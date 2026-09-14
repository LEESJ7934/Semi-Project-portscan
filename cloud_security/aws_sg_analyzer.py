"""Pure AWS Security Group configuration checks for the portfolio lab.

These checks identify overly broad ingress rules. They do not prove end-to-end
Internet reachability because route tables, IGWs, NACLs and host firewalls are
outside this analyzer's current scope.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

SENSITIVE_RULES = (
    ("AWS-SG-001", 22, "Security Group allows Internet-wide SSH ingress"),
    ("AWS-SG-002", 3389, "Security Group allows Internet-wide RDP ingress"),
    ("AWS-SG-003", 3306, "Security Group allows Internet-wide MySQL ingress"),
    ("AWS-SG-004", 5432, "Security Group allows Internet-wide PostgreSQL ingress"),
    ("AWS-SG-005", 27017, "Security Group allows Internet-wide MongoDB ingress"),
    ("AWS-SG-007", 21, "Security Group allows Internet-wide FTP ingress"),
    ("AWS-SG-008", 23, "Security Group allows Internet-wide Telnet ingress"),
)
BROAD_V4 = "0.0.0.0/0"
BROAD_V6 = "::/0"


def _broad_sources(permission: dict[str, Any]) -> list[str]:
    sources: set[str] = set()
    for entry in permission.get("IpRanges") or []:
        cidr = entry.get("CidrIp") if isinstance(entry, dict) else None
        if cidr == BROAD_V4:
            sources.add(cidr)
    for entry in permission.get("Ipv6Ranges") or []:
        cidr = entry.get("CidrIpv6") if isinstance(entry, dict) else None
        if cidr == BROAD_V6:
            sources.add(cidr)
    return sorted(sources)


def _covers_port(permission: dict[str, Any], port: int) -> bool:
    protocol = str(permission.get("IpProtocol", "")).lower()
    if protocol == "-1":
        return True
    if protocol not in {"tcp", "6"}:
        return False
    try:
        return int(permission.get("FromPort")) <= port <= int(permission.get("ToPort"))
    except (TypeError, ValueError):
        return False


def _is_all_ports(permission: dict[str, Any]) -> bool:
    protocol = str(permission.get("IpProtocol", "")).lower()
    if protocol == "-1":
        return True
    if protocol not in {"tcp", "6", "udp", "17"}:
        return False
    try:
        return int(permission.get("FromPort")) <= 0 and int(permission.get("ToPort")) >= 65535
    except (TypeError, ValueError):
        return False


def _priority(severity: str, public_address_present: bool) -> str:
    if severity == "CRITICAL":
        return "P1" if public_address_present else "P2"
    return "P2" if public_address_present else "P3"


def _finding(resource: dict[str, Any], rule_id: str, title: str, severity: str, matches: list[dict[str, Any]]):
    public_address_present = bool(resource.get("public_ip"))
    evidence = {
        "resource_id": resource.get("resource_id"),
        "vpc_id": resource.get("vpc_id"),
        "private_ip": resource.get("private_ip"),
        "public_address_present": public_address_present,
        "matched_permissions": sorted(
            matches,
            key=lambda item: (
                item.get("security_group_id") or "",
                item.get("protocol") or "",
                item.get("from_port") if item.get("from_port") is not None else -1,
                ",".join(item.get("sources") or []),
            ),
        ),
        "reachability_limit": (
            "Broad Security Group ingress was observed. Public IP presence is only a context signal; "
            "route tables, Internet Gateway, NACLs and host firewall were not evaluated."
        ),
    }
    canonical = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "rule_id": rule_id,
        "category": "NETWORK_EXPOSURE",
        "title": title,
        "severity": severity,
        "priority": _priority(severity, public_address_present),
        "public_address_present": public_address_present,
        "evidence": evidence,
        "remediation": (
            "Remove Internet-wide ingress unless explicitly required. Prefer a trusted CIDR, "
            "Security Group reference, VPN/private path, or Systems Manager for administration."
        ),
        "input_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    }


def analyze_resource(resource: dict[str, Any]) -> list[dict[str, Any]]:
    all_permissions: list[tuple[str, dict[str, Any], list[str]]] = []
    for group in resource.get("security_groups") or []:
        if not isinstance(group, dict):
            continue
        group_id = group.get("group_id")
        for permission in group.get("ip_permissions") or []:
            if not isinstance(permission, dict):
                continue
            sources = _broad_sources(permission)
            if sources:
                all_permissions.append((group_id, permission, sources))

    all_port_matches = []
    for group_id, permission, sources in all_permissions:
        if _is_all_ports(permission):
            all_port_matches.append({
                "security_group_id": group_id,
                "protocol": permission.get("IpProtocol"),
                "from_port": permission.get("FromPort"),
                "to_port": permission.get("ToPort"),
                "sources": sources,
            })
    if all_port_matches:
        return [_finding(
            resource,
            "AWS-SG-006",
            "Security Group allows Internet-wide all ports/protocols",
            "CRITICAL",
            all_port_matches,
        )]

    findings = []
    for rule_id, port, title in SENSITIVE_RULES:
        matches = []
        for group_id, permission, sources in all_permissions:
            if _covers_port(permission, port):
                matches.append({
                    "security_group_id": group_id,
                    "protocol": permission.get("IpProtocol"),
                    "from_port": permission.get("FromPort"),
                    "to_port": permission.get("ToPort"),
                    "sources": sources,
                })
        if matches:
            findings.append(_finding(resource, rule_id, title, "HIGH", matches))
    return findings


def analyze_security_groups(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for resource in inventory.get("resources") or []:
        if not isinstance(resource, dict):
            continue
        for finding in analyze_resource(resource):
            findings.append({
                "resource_id": resource.get("resource_id"),
                "private_ip": resource.get("private_ip"),
                **finding,
            })
    findings.sort(key=lambda item: (item.get("resource_id") or "", item["rule_id"]))
    return findings
