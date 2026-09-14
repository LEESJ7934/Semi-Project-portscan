"""Read-only AWS EC2 inventory collection.

The module is deliberately import-safe: boto3 is imported only when live AWS
clients are requested. Tests can inject fake STS/EC2 clients without AWS
credentials or network access.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

REGION_RE = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$")
VPC_RE = re.compile(r"^vpc-[0-9a-fA-F]+$")


class AwsInventoryError(RuntimeError):
    """Raised when a live AWS inventory cannot be collected safely."""


def validate_region(region: str) -> str:
    if not isinstance(region, str) or not REGION_RE.fullmatch(region.strip()):
        raise ValueError("AWS region 형식이 올바르지 않습니다.")
    return region.strip()


def validate_vpc_id(vpc_id: str | None) -> str | None:
    if vpc_id is None:
        return None
    if not isinstance(vpc_id, str) or not VPC_RE.fullmatch(vpc_id.strip()):
        raise ValueError("AWS VPC ID 형식이 올바르지 않습니다.")
    return vpc_id.strip().lower()


ALLOWED_TAG_KEYS = {"name", "environment", "owner", "businessunit", "data_classification"}


def _safe_tags(tags: Iterable[dict[str, Any]] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in tags or []:
        if not isinstance(item, dict):
            continue
        key, value = item.get("Key"), item.get("Value")
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        key = key.strip()
        if key.casefold() not in ALLOWED_TAG_KEYS or len(value) > 256:
            continue
        result[key] = value.strip()
    return result


def _name_tag(tags: dict[str, str]) -> str | None:
    value = tags.get("Name")
    return value or None


def _iter_instance_pages(ec2_client: Any, filters: list[dict[str, Any]]):
    if hasattr(ec2_client, "get_paginator"):
        paginator = ec2_client.get_paginator("describe_instances")
        yield from paginator.paginate(Filters=filters)
    else:
        yield ec2_client.describe_instances(Filters=filters)


def _chunked(values: list[str], size: int = 100):
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _fetch_security_groups(ec2_client: Any, group_ids: list[str]) -> dict[str, dict[str, Any]]:
    groups: dict[str, dict[str, Any]] = {}
    for batch in _chunked(sorted(set(group_ids))):
        if not batch:
            continue
        response = ec2_client.describe_security_groups(GroupIds=batch)
        for group in response.get("SecurityGroups", []):
            group_id = group.get("GroupId")
            if isinstance(group_id, str):
                groups[group_id] = group
    return groups


def _normalize_permission(permission: dict[str, Any]) -> dict[str, Any]:
    return {
        "IpProtocol": permission.get("IpProtocol"),
        "FromPort": permission.get("FromPort"),
        "ToPort": permission.get("ToPort"),
        "IpRanges": [
            {"CidrIp": entry.get("CidrIp")} for entry in permission.get("IpRanges") or []
            if isinstance(entry, dict) and isinstance(entry.get("CidrIp"), str)
        ],
        "Ipv6Ranges": [
            {"CidrIpv6": entry.get("CidrIpv6")} for entry in permission.get("Ipv6Ranges") or []
            if isinstance(entry, dict) and isinstance(entry.get("CidrIpv6"), str)
        ],
        "UserIdGroupPairs": [
            {"GroupId": entry.get("GroupId")} for entry in permission.get("UserIdGroupPairs") or []
            if isinstance(entry, dict) and isinstance(entry.get("GroupId"), str)
        ],
    }


def _normalize_sg(group: dict[str, Any]) -> dict[str, Any]:
    return {
        "group_id": group.get("GroupId"),
        "group_name": group.get("GroupName"),
        "vpc_id": group.get("VpcId"),
        "ip_permissions": [
            _normalize_permission(permission) for permission in group.get("IpPermissions") or []
            if isinstance(permission, dict)
        ],
    }


def create_live_clients(region: str):
    """Return live STS/EC2 clients without accepting static credentials."""
    region = validate_region(region)
    try:
        import boto3  # lazy on purpose
    except ImportError as exc:
        raise AwsInventoryError(
            "boto3가 설치되어 있지 않습니다. requirements.txt를 설치하세요."
        ) from exc
    session = boto3.session.Session(region_name=region)
    return session.client("sts"), session.client("ec2")


def collect_inventory(
    *,
    region: str,
    vpc_id: str | None = None,
    sts_client: Any | None = None,
    ec2_client: Any | None = None,
) -> dict[str, Any]:
    """Collect EC2 + Security Group metadata using read-only AWS API calls.

    No scan is triggered. The output intentionally excludes credentials,
    user-data and arbitrary API response bodies.
    """
    region = validate_region(region)
    vpc_id = validate_vpc_id(vpc_id)
    if (sts_client is None) != (ec2_client is None):
        raise ValueError("STS와 EC2 client는 둘 다 주입하거나 둘 다 생략해야 합니다.")
    if sts_client is None:
        sts_client, ec2_client = create_live_clients(region)

    try:
        identity = sts_client.get_caller_identity()
        account_id = str(identity.get("Account") or "").strip()
        if not account_id.isdigit() or len(account_id) != 12:
            raise AwsInventoryError("AWS Account ID를 확인할 수 없습니다.")

        filters = [{"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}]
        if vpc_id:
            filters.append({"Name": "vpc-id", "Values": [vpc_id]})

        raw_instances: list[dict[str, Any]] = []
        group_ids: list[str] = []
        for page in _iter_instance_pages(ec2_client, filters):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    raw_instances.append(instance)
                    for group in instance.get("SecurityGroups", []):
                        group_id = group.get("GroupId")
                        if isinstance(group_id, str):
                            group_ids.append(group_id)
        groups = _fetch_security_groups(ec2_client, group_ids)
    except AwsInventoryError:
        raise
    except Exception as exc:
        raise AwsInventoryError(
            "AWS read-only inventory API 호출에 실패했습니다 "
            f"({type(exc).__name__})."
        ) from exc

    resources: list[dict[str, Any]] = []
    for instance in raw_instances:
        private_ip = instance.get("PrivateIpAddress")
        instance_id = instance.get("InstanceId")
        instance_vpc = instance.get("VpcId")
        if not all(isinstance(value, str) and value for value in (private_ip, instance_id, instance_vpc)):
            # Current scanner inventory requires one primary private IP.
            continue
        tags = _safe_tags(instance.get("Tags"))
        sg_items = []
        for ref in instance.get("SecurityGroups", []):
            group_id = ref.get("GroupId")
            if group_id in groups:
                sg_items.append(_normalize_sg(groups[group_id]))
        sg_items.sort(key=lambda item: item.get("group_id") or "")
        resources.append({
            "provider": "AWS",
            "account_id": account_id,
            "region": region,
            "resource_type": "EC2",
            "resource_id": instance_id,
            "asset_name": _name_tag(tags),
            "vpc_id": instance_vpc,
            "subnet_id": instance.get("SubnetId"),
            "private_ip": private_ip,
            "public_ip": instance.get("PublicIpAddress"),
            "instance_state": (instance.get("State") or {}).get("Name"),
            "security_groups": sg_items,
            "tags": tags,
        })
    resources.sort(key=lambda item: (item["vpc_id"], item["private_ip"], item["resource_id"]))
    return {
        "provider": "AWS",
        "account_id": account_id,
        "region": region,
        "vpc_id_filter": vpc_id,
        "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "resources": resources,
    }
