"""Persistence for AWS cloud context and configuration findings.

The repository accepts an existing transaction/connection and never commits on
its own. It intentionally has no mysql-connector import so pure unit tests can
use a fake DB connection.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from asset_management import normalize_ip_address


def _utc_naive_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))




def find_cloud_host_by_ip(conn: Any, host_ip: str) -> dict[str, Any] | None:
    """Return current cloud host mapping for a scanned private/public IP.

    Cloud inventory keeps one canonical host row on the instance private IP.
    A scanner may legitimately target the instance public IP, so persistence
    needs a read-only way to resolve that public address back to the canonical
    cloud host before storing ports.
    """
    canonical_ip = normalize_ip_address(host_ip)
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            """
            SELECT cr.host_id, cr.private_ip, cr.public_ip, cr.resource_id,
                   cr.provider, cr.region
            FROM cloud_resources AS cr
            WHERE cr.private_ip = %s OR cr.public_ip = %s
            ORDER BY cr.last_discovered_at DESC, cr.id DESC
            LIMIT 1;
            """,
            (canonical_ip, canonical_ip),
        )
        row = cursor.fetchone()
    if not isinstance(row, dict) or not row:
        return None
    if row.get("private_ip"):
        row["private_ip"] = normalize_ip_address(row["private_ip"])
    if row.get("public_ip"):
        row["public_ip"] = normalize_ip_address(row["public_ip"])
    return row

def upsert_cloud_resource(conn: Any, resource: dict[str, Any]) -> dict[str, int]:
    required = ("account_id", "region", "resource_id", "vpc_id", "private_ip")
    missing = [key for key in required if not resource.get(key)]
    if missing:
        raise ValueError("AWS 자산 필수 필드가 없습니다: " + ", ".join(missing))
    private_ip = normalize_ip_address(resource["private_ip"])
    now = _utc_naive_now()
    asset_uid = str(uuid4())

    with conn.cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO hosts (
                asset_uid, host_ip, asset_name, asset_type, internet_exposed,
                source, first_seen, last_seen
            ) VALUES (%s, %s, %s, 'CLOUD_RESOURCE', %s, 'IMPORTED', %s, %s)
            ON DUPLICATE KEY UPDATE
                id = LAST_INSERT_ID(id),
                asset_name = COALESCE(VALUES(asset_name), asset_name),
                asset_type = 'CLOUD_RESOURCE',
                internet_exposed = VALUES(internet_exposed),
                last_seen = VALUES(last_seen);
            """,
            (
                asset_uid,
                private_ip,
                resource.get("asset_name"),
                bool(resource.get("public_ip")),
                now,
                now,
            ),
        )
        host_id = cursor.lastrowid
        cursor.execute(
            """
            INSERT INTO cloud_resources (
                host_id, provider, account_id, region, resource_type, resource_id,
                vpc_id, subnet_id, private_ip, public_ip, instance_state,
                security_groups, tags, first_discovered_at, last_discovered_at
            ) VALUES (
                %s, 'AWS', %s, %s, 'EC2', %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            )
            ON DUPLICATE KEY UPDATE
                id = LAST_INSERT_ID(id),
                host_id = VALUES(host_id),
                vpc_id = VALUES(vpc_id),
                subnet_id = VALUES(subnet_id),
                private_ip = VALUES(private_ip),
                public_ip = VALUES(public_ip),
                instance_state = VALUES(instance_state),
                security_groups = VALUES(security_groups),
                tags = VALUES(tags),
                last_discovered_at = VALUES(last_discovered_at);
            """,
            (
                host_id,
                resource["account_id"],
                resource["region"],
                resource["resource_id"],
                resource["vpc_id"],
                resource.get("subnet_id"),
                private_ip,
                resource.get("public_ip"),
                resource.get("instance_state"),
                _json(resource.get("security_groups") or []),
                _json(resource.get("tags") or {}),
                now,
                now,
            ),
        )
        cloud_resource_id = cursor.lastrowid
    return {"host_id": host_id, "cloud_resource_id": cloud_resource_id}


def save_inventory(conn: Any, inventory: dict[str, Any]) -> dict[str, dict[str, int]]:
    vpc_filter = inventory.get("vpc_id_filter")
    if not vpc_filter:
        raise ValueError("Cloud inventory 저장에는 단일 vpc_id_filter가 필요합니다.")
    mapping: dict[str, dict[str, int]] = {}
    for resource in inventory.get("resources") or []:
        if resource.get("vpc_id") != vpc_filter:
            raise ValueError("Inventory resource가 승인된 단일 VPC filter와 일치하지 않습니다.")
        if not resource.get("private_ip"):
            continue
        enriched = {
            **resource,
            "account_id": inventory.get("account_id"),
            "region": inventory.get("region"),
        }
        ids = upsert_cloud_resource(conn, enriched)
        mapping[resource["resource_id"]] = ids
    return mapping


def sync_configuration_findings(
    conn: Any,
    resource_mapping: dict[str, dict[str, int]],
    findings: list[dict[str, Any]],
) -> int:
    now = _utc_naive_now()
    observed: dict[int, set[str]] = {}
    written = 0
    with conn.cursor() as cursor:
        for finding in findings:
            resource_id = finding.get("resource_id")
            ids = resource_mapping.get(resource_id)
            if not ids:
                continue
            cloud_id = ids["cloud_resource_id"]
            observed.setdefault(cloud_id, set()).add(finding["rule_id"])
            cursor.execute(
                """
                INSERT INTO cloud_configuration_findings (
                    cloud_resource_id, rule_id, category, title, severity,
                    priority, status, public_address_present, evidence,
                    remediation, input_sha256, first_detected_at,
                    last_detected_at, resolved_at, observations
                ) VALUES (
                    %s, %s, %s, %s, %s,
                    %s, 'OPEN', %s, %s,
                    %s, %s, %s, %s, NULL, 1
                )
                ON DUPLICATE KEY UPDATE
                    category = VALUES(category),
                    title = VALUES(title),
                    severity = VALUES(severity),
                    priority = VALUES(priority),
                    status = 'OPEN',
                    public_address_present = VALUES(public_address_present),
                    evidence = VALUES(evidence),
                    remediation = VALUES(remediation),
                    input_sha256 = VALUES(input_sha256),
                    last_detected_at = VALUES(last_detected_at),
                    resolved_at = NULL,
                    observations = observations + 1;
                """,
                (
                    cloud_id,
                    finding["rule_id"],
                    finding["category"],
                    finding["title"],
                    finding["severity"],
                    finding["priority"],
                    bool(finding.get("public_address_present")),
                    _json(finding.get("evidence") or {}),
                    finding["remediation"],
                    finding["input_sha256"],
                    now,
                    now,
                ),
            )
            written += 1

        # Only resources reviewed in this run are eligible for automatic resolve.
        for ids in resource_mapping.values():
            cloud_id = ids["cloud_resource_id"]
            current_rule_ids = sorted(observed.get(cloud_id, set()))
            if current_rule_ids:
                placeholders = ",".join(["%s"] * len(current_rule_ids))
                cursor.execute(
                    "UPDATE cloud_configuration_findings SET status='RESOLVED', resolved_at=%s "
                    "WHERE cloud_resource_id=%s AND status='OPEN' AND rule_id NOT IN (" + placeholders + ");",
                    (now, cloud_id, *current_rule_ids),
                )
            else:
                cursor.execute(
                    "UPDATE cloud_configuration_findings SET status='RESOLVED', resolved_at=%s "
                    "WHERE cloud_resource_id=%s AND status='OPEN';",
                    (now, cloud_id),
                )
    return written
