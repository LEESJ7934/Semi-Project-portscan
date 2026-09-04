from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Any, Mapping


class AssetType(str, Enum):
    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    CONTAINER = "CONTAINER"
    UNKNOWN = "UNKNOWN"


class AssetEnvironment(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    UNKNOWN = "UNKNOWN"


class AssetCriticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNASSIGNED = "UNASSIGNED"


class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    UNKNOWN = "UNKNOWN"


class AssetLifecycleStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    RETIRED = "RETIRED"


class AssetSource(str, Enum):
    DISCOVERED = "DISCOVERED"
    MANUAL = "MANUAL"
    IMPORTED = "IMPORTED"


ENUM_FIELDS = {
    "asset_type": AssetType,
    "environment": AssetEnvironment,
    "criticality": AssetCriticality,
    "data_classification": DataClassification,
    "lifecycle_status": AssetLifecycleStatus,
    "source": AssetSource,
}

TEXT_FIELDS = {
    "asset_name": 255,
    "owner": 255,
    "business_unit": 255,
    "notes": 2000,
}

BOOLEAN_FIELDS = {
    "handles_personal_data",
    "internet_exposed",
}

ASSET_UPDATE_FIELDS = frozenset(
    set(ENUM_FIELDS)
    | set(TEXT_FIELDS)
    | BOOLEAN_FIELDS
)


def normalize_ip_address(value: str) -> str:
    """Return a canonical IPv4 or IPv6 string."""

    if not isinstance(value, str):
        raise ValueError("자산 IP는 문자열이어야 합니다.")

    candidate = value.strip()

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError(
            f"올바르지 않은 자산 IP입니다: {value}"
        ) from exc

    if address.is_unspecified or address.is_multicast:
        raise ValueError(
            f"자산으로 등록할 수 없는 IP입니다: {value}"
        )

    return str(address)


def _normalize_enum(
    field_name: str,
    value: Any,
) -> str:
    enum_class = ENUM_FIELDS[field_name]

    if isinstance(value, enum_class):
        return value.value

    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} 값은 문자열이어야 합니다."
        )

    normalized = value.strip().upper()

    try:
        return enum_class(normalized).value
    except ValueError as exc:
        allowed = ", ".join(
            item.value for item in enum_class
        )
        raise ValueError(
            f"지원하지 않는 {field_name} 값입니다: "
            f"{value}. 허용값: {allowed}"
        ) from exc


def _normalize_text(
    field_name: str,
    value: Any,
) -> str | None:
    if value is None:
        return None

    if not isinstance(value, str):
        raise ValueError(
            f"{field_name} 값은 문자열이어야 합니다."
        )

    normalized = value.strip()

    if not normalized:
        return None

    max_length = TEXT_FIELDS[field_name]

    if len(normalized) > max_length:
        raise ValueError(
            f"{field_name} 값은 {max_length}자를 "
            "초과할 수 없습니다."
        )

    return normalized


def normalize_asset_updates(
    updates: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and normalize a metadata update allowlist."""

    unknown_fields = sorted(
        set(updates) - ASSET_UPDATE_FIELDS
    )

    if unknown_fields:
        raise ValueError(
            "수정할 수 없는 자산 필드입니다: "
            + ", ".join(unknown_fields)
        )

    normalized: dict[str, Any] = {}

    for field_name, value in updates.items():
        if field_name in ENUM_FIELDS:
            normalized[field_name] = (
                _normalize_enum(field_name, value)
            )
        elif field_name in TEXT_FIELDS:
            normalized[field_name] = (
                _normalize_text(field_name, value)
            )
        elif field_name in BOOLEAN_FIELDS:
            if not isinstance(value, bool):
                raise ValueError(
                    f"{field_name} 값은 bool이어야 합니다."
                )
            normalized[field_name] = value

    return normalized
