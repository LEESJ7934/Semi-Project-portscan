from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Mapping

from asset_management import (
    AssetCriticality,
    AssetLifecycleStatus,
    normalize_asset_updates,
    normalize_ip_address,
)
from scanner.scope import ScopePolicy


VALID_RESOLUTION_TYPES = {
    "IP",
    "CIDR",
    "HOSTNAME",
}

VALID_SCAN_ASSET_RESULTS = {
    "SCANNED",
    "ERROR",
}

ASSET_UPDATE_SQL = {
    "asset_name": (
        "UPDATE hosts SET asset_name = %s WHERE id = %s;"
    ),
    "asset_type": (
        "UPDATE hosts SET asset_type = %s WHERE id = %s;"
    ),
    "environment": (
        "UPDATE hosts SET environment = %s WHERE id = %s;"
    ),
    "criticality": (
        "UPDATE hosts SET criticality = %s WHERE id = %s;"
    ),
    "owner": "UPDATE hosts SET owner = %s WHERE id = %s;",
    "business_unit": (
        "UPDATE hosts SET business_unit = %s WHERE id = %s;"
    ),
    "data_classification": (
        "UPDATE hosts SET data_classification = %s "
        "WHERE id = %s;"
    ),
    "handles_personal_data": (
        "UPDATE hosts SET handles_personal_data = %s "
        "WHERE id = %s;"
    ),
    "internet_exposed": (
        "UPDATE hosts SET internet_exposed = %s "
        "WHERE id = %s;"
    ),
    "lifecycle_status": (
        "UPDATE hosts SET lifecycle_status = %s "
        "WHERE id = %s;"
    ),
    "source": "UPDATE hosts SET source = %s WHERE id = %s;",
    "notes": "UPDATE hosts SET notes = %s WHERE id = %s;",
}


def _utc_naive(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError(
            "시간대가 있는 datetime 값이 필요합니다."
        )

    return value.astimezone(timezone.utc).replace(
        tzinfo=None
    )


def _required_audit_text(
    value: str,
    field_name: str,
    max_length: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{field_name} 값이 필요합니다."
        )

    normalized = value.strip()

    if len(normalized) > max_length:
        raise ValueError(
            f"{field_name} 값은 {max_length}자를 "
            "초과할 수 없습니다."
        )

    return normalized


def upsert_scan_scope(
    conn: Any,
    scope_data: Mapping[str, Any],
) -> int:
    policy = ScopePolicy.from_dict(scope_data)
    supplied_fingerprint = scope_data.get(
        "policy_sha256"
    )

    if (
        supplied_fingerprint is not None
        and supplied_fingerprint != policy.fingerprint
    ):
        raise ValueError(
            "스캔 스코프 해시가 실제 정책 내용과 다릅니다."
        )

    sql = """
    INSERT INTO scan_scopes (
        scope_uid,
        name,
        authorization_ref,
        approved_by,
        valid_from,
        valid_until,
        allowed_targets,
        max_targets,
        max_workers,
        max_ports_per_target,
        policy_sha256
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s,
        %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        name = VALUES(name),
        authorization_ref = VALUES(
            authorization_ref
        ),
        approved_by = VALUES(approved_by),
        valid_from = VALUES(valid_from),
        valid_until = VALUES(valid_until),
        allowed_targets = VALUES(allowed_targets),
        max_targets = VALUES(max_targets),
        max_workers = VALUES(max_workers),
        max_ports_per_target = VALUES(
            max_ports_per_target
        ),
        policy_sha256 = VALUES(policy_sha256);
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                policy.scope_uid,
                policy.name,
                policy.authorization_ref,
                policy.approved_by,
                _utc_naive(policy.valid_from),
                _utc_naive(policy.valid_until),
                json.dumps(
                    list(policy.allowed_targets),
                    ensure_ascii=False,
                ),
                policy.max_targets,
                policy.max_workers,
                policy.max_ports_per_target,
                policy.fingerprint,
            ),
        )
        return cursor.lastrowid


def record_scan_asset(
    conn: Any,
    scan_id: int,
    host_id: int,
    input_target: str,
    resolution_type: str,
    result_status: str,
    open_port_count: int,
    error_code: str | None = None,
) -> int:
    resolution_value = resolution_type.strip().upper()
    result_value = result_status.strip().upper()

    if resolution_value not in VALID_RESOLUTION_TYPES:
        raise ValueError(
            "지원하지 않는 대상 해석 유형입니다: "
            f"{resolution_type}"
        )

    if result_value not in VALID_SCAN_ASSET_RESULTS:
        raise ValueError(
            "지원하지 않는 자산 스캔 결과입니다: "
            f"{result_status}"
        )

    if open_port_count < 0:
        raise ValueError(
            "open_port_count는 0 이상이어야 합니다."
        )

    sql = """
    INSERT INTO scan_assets (
        scan_id,
        host_id,
        input_target,
        resolution_type,
        result_status,
        open_port_count,
        error_code
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        input_target = VALUES(input_target),
        resolution_type = VALUES(resolution_type),
        result_status = VALUES(result_status),
        open_port_count = VALUES(open_port_count),
        error_code = VALUES(error_code),
        observed_at = CURRENT_TIMESTAMP;
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                scan_id,
                host_id,
                input_target,
                resolution_value,
                result_value,
                open_port_count,
                error_code,
            ),
        )
        return cursor.lastrowid


def get_asset_by_id(
    conn: Any,
    host_id: int,
) -> dict[str, Any] | None:
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM hosts WHERE id = %s;",
            (host_id,),
        )
        return cursor.fetchone()


def get_asset_by_uid(
    conn: Any,
    asset_uid: str,
) -> dict[str, Any] | None:
    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM hosts WHERE asset_uid = %s;",
            (asset_uid,),
        )
        return cursor.fetchone()


def get_asset_by_ip(
    conn: Any,
    host_ip: str,
) -> dict[str, Any] | None:
    canonical_ip = normalize_ip_address(host_ip)

    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM hosts WHERE host_ip = %s;",
            (canonical_ip,),
        )
        return cursor.fetchone()


def list_assets(
    conn: Any,
    lifecycle_status: str | None = None,
    criticality: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise ValueError("limit은 1~1000 범위여야 합니다.")

    if lifecycle_status is not None:
        status_value = AssetLifecycleStatus(
            lifecycle_status.strip().upper()
        ).value
    else:
        status_value = None

    if criticality is not None:
        criticality_value = AssetCriticality(
            criticality.strip().upper()
        ).value
    else:
        criticality_value = None

    sql = """
    SELECT
        h.*,
        COUNT(DISTINCT CASE
            WHEN p.state = 'open' THEN p.id
            ELSE NULL
        END) AS open_port_count,
        COUNT(DISTINCT sa.scan_id) AS scan_count
    FROM hosts AS h
    LEFT JOIN ports AS p
        ON p.host_id = h.id
    LEFT JOIN scan_assets AS sa
        ON sa.host_id = h.id
    WHERE (%s IS NULL OR h.lifecycle_status = %s)
        AND (%s IS NULL OR h.criticality = %s)
    GROUP BY h.id
    ORDER BY
        FIELD(
            h.criticality,
            'CRITICAL',
            'HIGH',
            'MEDIUM',
            'LOW',
            'UNASSIGNED'
        ),
        h.host_ip
    LIMIT %s;
    """

    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            sql,
            (
                status_value,
                status_value,
                criticality_value,
                criticality_value,
                limit,
            ),
        )
        return cursor.fetchall()


def update_asset_metadata(
    conn: Any,
    asset_uid: str,
    updates: Mapping[str, Any],
    changed_by: str,
    reason: str,
) -> dict[str, Any]:
    normalized = normalize_asset_updates(updates)

    if not normalized:
        raise ValueError("변경할 자산 정보가 없습니다.")

    actor = _required_audit_text(
        changed_by,
        "changed_by",
        100,
    )
    audit_reason = _required_audit_text(
        reason,
        "reason",
        500,
    )

    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(
            "SELECT * FROM hosts "
            "WHERE asset_uid = %s FOR UPDATE;",
            (asset_uid,),
        )
        current = cursor.fetchone()

        if not current:
            raise LookupError(
                f"자산을 찾을 수 없습니다: {asset_uid}"
            )

        changed = {
            field_name: value
            for field_name, value in normalized.items()
            if current.get(field_name) != value
        }

        if not changed:
            return current

        for field_name, new_value in changed.items():
            cursor.execute(
                ASSET_UPDATE_SQL[field_name],
                (new_value, current["id"]),
            )
            cursor.execute(
                """
                INSERT INTO asset_change_history (
                    host_id,
                    field_name,
                    old_value,
                    new_value,
                    reason,
                    changed_by
                )
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                (
                    current["id"],
                    field_name,
                    (
                        None
                        if current.get(field_name) is None
                        else str(current[field_name])
                    ),
                    (
                        None
                        if new_value is None
                        else str(new_value)
                    ),
                    audit_reason,
                    actor,
                ),
            )

        cursor.execute(
            "SELECT * FROM hosts WHERE id = %s;",
            (current["id"],),
        )
        return cursor.fetchone()


def get_asset_history(
    conn: Any,
    asset_uid: str,
    limit: int = 100,
) -> list[dict[str, Any]]:
    if not 1 <= limit <= 1000:
        raise ValueError("limit은 1~1000 범위여야 합니다.")

    sql = """
    SELECT
        history.id,
        history.field_name,
        history.old_value,
        history.new_value,
        history.reason,
        history.changed_by,
        history.changed_at
    FROM asset_change_history AS history
    JOIN hosts AS host
        ON history.host_id = host.id
    WHERE host.asset_uid = %s
    ORDER BY history.changed_at DESC, history.id DESC
    LIMIT %s;
    """

    with conn.cursor(dictionary=True) as cursor:
        cursor.execute(sql, (asset_uid, limit))
        return cursor.fetchall()
