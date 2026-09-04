import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from mysql.connector import MySQLConnection

from asset_management import normalize_ip_address
from .db_client import get_connection
from .statuses import (
    ScanStatus,
    VulnStatus,
    normalize_scan_status,
    normalize_vuln_status,
    validate_vuln_transition,
)


VALID_SEVERITIES = {
    "INFO",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
}

VALID_EVIDENCE_TYPES = {
    "HTTP_RESPONSE",
    "SCREENSHOT",
    "NUCLEI",
    "BANNER",
    "MANUAL",
    "ERROR_LOG",
}


def utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    ).replace(tzinfo=None)


def upsert_host(
    conn: MySQLConnection,
    host_ip: str,
    host_name: Optional[str] = None,
    last_scan_id: Optional[int] = None,
) -> int:
    now = utc_now()
    canonical_ip = normalize_ip_address(host_ip)
    new_asset_uid = str(uuid4())

    sql = """
    INSERT INTO hosts (
        asset_uid,
        host_ip,
        host_name,
        first_seen,
        last_seen,
        last_scan_id
    )
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        host_name = COALESCE(
            VALUES(host_name),
            host_name
        ),
        last_seen = VALUES(last_seen),
        last_scan_id = COALESCE(
            VALUES(last_scan_id),
            last_scan_id
        );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                new_asset_uid,
                canonical_ip,
                host_name,
                now,
                now,
                last_scan_id,
            ),
        )
        return cursor.lastrowid


def get_all_ports() -> List[Dict[str, Any]]:
    conn = get_connection()

    sql = """
    SELECT
        p.id AS port_id,
        h.host_ip,
        p.port,
        p.protocol,
        p.service,
        p.version,
        p.banner,
        p.state
    FROM ports AS p
    JOIN hosts AS h
        ON p.host_id = h.id;
    """

    try:
        with conn.cursor(
            dictionary=True
        ) as cursor:
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()


def upsert_port(
    conn: MySQLConnection,
    host_id: int,
    port: int,
    protocol: str,
    service: Optional[str] = None,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    last_scan_id: Optional[int] = None,
    state: str = "closed",
) -> int:
    normalized_protocol = (
        protocol
        .strip()
        .lower()
    )
    normalized_state = (
        state
        .strip()
        .lower()
    )

    if normalized_state == "open|filtered":
        normalized_state = "open_or_filtered"

    if normalized_protocol not in {
        "tcp",
        "udp",
    }:
        raise ValueError(
            "지원하지 않는 프로토콜입니다: "
            f"{protocol}"
        )

    if normalized_state not in {
        "open",
        "closed",
        "filtered",
        "open_or_filtered",
    }:
        raise ValueError(
            "지원하지 않는 포트 상태입니다: "
            f"{state}"
        )

    now = utc_now()

    sql = """
    INSERT INTO ports (
        host_id,
        port,
        protocol,
        service,
        version,
        banner,
        state,
        first_seen,
        last_seen,
        last_scan_id
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        service = COALESCE(
            VALUES(service),
            service
        ),
        version = COALESCE(
            VALUES(version),
            version
        ),
        banner = COALESCE(
            VALUES(banner),
            banner
        ),
        state = VALUES(state),
        last_seen = VALUES(last_seen),
        last_scan_id = VALUES(last_scan_id);
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                host_id,
                port,
                normalized_protocol,
                service,
                version,
                banner,
                normalized_state,
                now,
                now,
                last_scan_id,
            ),
        )
        return cursor.lastrowid


def insert_scan(
    conn: MySQLConnection,
    scan_uid: str,
    target: str,
    scan_type: str,
    port_range: str,
    started_at: datetime,
    finished_at: Optional[datetime],
    status: str | ScanStatus,
    scope_id: Optional[int] = None,
    requested_targets: Optional[List[str]] = None,
    config_snapshot: Optional[
        Dict[str, Any]
    ] = None,
) -> int:
    normalized_status = (
        normalize_scan_status(status)
    )

    snapshot_json = (
        json.dumps(
            config_snapshot,
            ensure_ascii=False,
            default=str,
        )
        if config_snapshot
        else None
    )
    requested_targets_json = (
        json.dumps(
            requested_targets,
            ensure_ascii=False,
        )
        if requested_targets is not None
        else None
    )

    sql = """
    INSERT INTO scans (
        scan_uid,
        scope_id,
        target,
        requested_targets,
        scan_type,
        port_range,
        started_at,
        finished_at,
        status,
        config_snapshot
    )
    VALUES (
        %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        scope_id = VALUES(scope_id),
        requested_targets = VALUES(
            requested_targets
        ),
        finished_at = VALUES(finished_at),
        status = VALUES(status),
        config_snapshot = VALUES(
            config_snapshot
        );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                scan_uid,
                scope_id,
                target,
                requested_targets_json,
                scan_type,
                port_range,
                started_at,
                finished_at,
                normalized_status,
                snapshot_json,
            ),
        )
        return cursor.lastrowid


def upsert_vuln(
    conn: MySQLConnection,
    port_id: int,
    cve_id: str,
    title: str,
    severity: str,
    epss: Optional[float] = None,
    cvss: Optional[float] = None,
    risk: Optional[float] = None,
    source: Optional[str] = None,
    status: str | VulnStatus = VulnStatus.POTENTIAL,
) -> int:
    severity_value = (
        severity
        .strip()
        .upper()
    )
    status_value = (
        normalize_vuln_status(status)
    )
    cve_value = (
        cve_id or "NONE"
    ).strip().upper()
    source_value = (
        source or "unknown"
    ).strip()

    if severity_value not in VALID_SEVERITIES:
        raise ValueError(
            "지원하지 않는 심각도입니다: "
            f"{severity}"
        )

    now = utc_now()

    sql = """
    INSERT INTO vulns (
        port_id,
        cve_id,
        title,
        severity,
        epss,
        cvss,
        risk,
        status,
        source,
        first_detected_at,
        last_detected_at,
        created_at,
        updated_at
    )
    VALUES (
        %s, %s, %s, %s, %s,
        %s, %s, %s, %s,
        %s, %s, %s, %s
    )
    ON DUPLICATE KEY UPDATE
        id = LAST_INSERT_ID(id),
        title = VALUES(title),
        severity = VALUES(severity),
        epss = VALUES(epss),
        cvss = VALUES(cvss),
        risk = VALUES(risk),
        status = CASE
            WHEN vulns.status IN (
                'CONFIRMED',
                'NOT_APPLICABLE',
                'FALSE_POSITIVE',
                'RETEST_REQUIRED',
                'CLOSED'
            )
            THEN vulns.status
            ELSE VALUES(status)
        END,
        last_detected_at = VALUES(
            last_detected_at
        ),
        updated_at = VALUES(
            updated_at
        );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                port_id,
                cve_value,
                title,
                severity_value,
                epss,
                cvss,
                risk,
                status_value,
                source_value,
                now,
                now,
                now,
                now,
            ),
        )

        vuln_id = cursor.lastrowid

        if cursor.rowcount == 1:
            cursor.execute(
                """
                INSERT INTO
                    remediation_history (
                        vuln_id,
                        from_status,
                        to_status,
                        action_type,
                        reason,
                        changed_by
                    )
                VALUES (
                    %s,
                    NULL,
                    %s,
                    'STATUS_CHANGE',
                    '최초 탐지',
                    'analysis'
                );
                """,
                (
                    vuln_id,
                    status_value,
                ),
            )

        return vuln_id


def insert_vuln(
    conn: MySQLConnection,
    port_id: int,
    cve_id: str,
    title: str,
    severity: str,
    epss: Optional[float] = None,
    source: Optional[str] = None,
    status: str | VulnStatus = VulnStatus.POTENTIAL,
) -> int:
    return upsert_vuln(
        conn=conn,
        port_id=port_id,
        cve_id=cve_id,
        title=title,
        severity=severity,
        epss=epss,
        source=source,
        status=status,
    )


def insert_vuln_evidence(
    conn: MySQLConnection,
    vuln_id: int,
    checker: str,
    evidence_type: str,
    details: Optional[str] = None,
    evidence_path: Optional[str] = None,
    sha256: Optional[str] = None,
) -> int:
    type_value = (
        evidence_type
        .strip()
        .upper()
    )

    if type_value not in VALID_EVIDENCE_TYPES:
        raise ValueError(
            "지원하지 않는 증적 유형입니다: "
            f"{evidence_type}"
        )

    sql = """
    INSERT INTO vuln_evidence (
        vuln_id,
        checker,
        evidence_type,
        details,
        evidence_path,
        sha256
    )
    VALUES (
        %s, %s, %s,
        %s, %s, %s
    );
    """

    with conn.cursor() as cursor:
        cursor.execute(
            sql,
            (
                vuln_id,
                checker,
                type_value,
                details,
                evidence_path,
                sha256,
            ),
        )
        return cursor.lastrowid


def transition_vuln_status(
    conn: MySQLConnection,
    vuln_id: int,
    new_status: str | VulnStatus,
    reason: Optional[str] = None,
    changed_by: str = "system",
) -> None:
    with conn.cursor(
        dictionary=True
    ) as cursor:
        cursor.execute(
            """
            SELECT status
            FROM vulns
            WHERE id = %s
            FOR UPDATE;
            """,
            (vuln_id,),
        )

        row = cursor.fetchone()

        if not row:
            raise LookupError(
                "취약점 레코드를 "
                "찾을 수 없습니다: "
                f"{vuln_id}"
            )

        current, new = (
            validate_vuln_transition(
                row["status"],
                new_status,
            )
        )

        if current == new:
            return

        now = utc_now()

        verified_at = (
            now
            if new in {
                VulnStatus.CONFIRMED.value,
                VulnStatus.NOT_APPLICABLE.value,
                VulnStatus.FALSE_POSITIVE.value,
            }
            else None
        )

        closed_at = (
            now
            if new == VulnStatus.CLOSED.value
            else None
        )

        cursor.execute(
            """
            UPDATE vulns
            SET
                status = %s,
                verified_at = COALESCE(
                    %s,
                    verified_at
                ),
                closed_at = %s,
                updated_at = %s
            WHERE id = %s;
            """,
            (
                new,
                verified_at,
                closed_at,
                now,
                vuln_id,
            ),
        )

        if new == VulnStatus.RETEST_REQUIRED.value:
            action_type = "RETEST_REQUEST"
        elif new == VulnStatus.CLOSED.value:
            action_type = "CLOSURE"
        elif current == VulnStatus.CLOSED.value:
            action_type = "REOPEN"
        else:
            action_type = "STATUS_CHANGE"

        cursor.execute(
            """
            INSERT INTO
                remediation_history (
                    vuln_id,
                    from_status,
                    to_status,
                    action_type,
                    reason,
                    changed_by
                )
            VALUES (
                %s, %s, %s,
                %s, %s, %s
            );
            """,
            (
                vuln_id,
                current,
                new,
                action_type,
                reason,
                changed_by,
            ),
        )


def update_vuln_verification(
    conn: MySQLConnection,
    vuln_id: int,
    status: str | VulnStatus,
    reason: Optional[str] = None,
) -> None:
    transition_vuln_status(
        conn=conn,
        vuln_id=vuln_id,
        new_status=status,
        reason=reason,
        changed_by="verification",
    )


def get_ports_with_vuln_candidates(
    conn: Optional[
        MySQLConnection
    ] = None,
) -> List[
    Tuple[
        Dict[str, Any],
        Dict[str, Any],
    ]
]:
    owns_connection = conn is None
    active_connection = (
        conn or get_connection()
    )

    sql = """
    SELECT
        p.id AS port_id,
        h.host_ip,
        p.port,
        p.protocol,
        p.service,
        v.id AS vuln_id,
        v.cve_id,
        v.title,
        v.source,
        v.status
    FROM vulns AS v
    JOIN ports AS p
        ON v.port_id = p.id
    JOIN hosts AS h
        ON p.host_id = h.id
    WHERE v.status IN (
        'POTENTIAL',
        'RETEST_REQUIRED'
    );
    """

    try:
        with active_connection.cursor(
            dictionary=True
        ) as cursor:
            cursor.execute(sql)
            rows = cursor.fetchall()

        results = []

        for row in rows:
            port_record = {
                "id": row["port_id"],
                "host_ip": row["host_ip"],
                "port": row["port"],
                "protocol": row["protocol"],
                "service": row["service"],
            }

            vuln_record = {
                "id": row["vuln_id"],
                "cve": row["cve_id"],
                "title": row["title"],
                "source": row["source"],
                "status": row["status"],
            }

            results.append(
                (
                    port_record,
                    vuln_record,
                )
            )

        return results

    finally:
        if owns_connection:
            active_connection.close()
