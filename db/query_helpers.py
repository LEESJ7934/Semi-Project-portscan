# 모든 모듈에서 공통으로 호출하는 DB 저장/조회 API 역할
import json
from datetime import datetime
from typing import Optional, Dict, Any
from mysql.connector import MySQLConnection
from .db_client import get_connection


def upsert_host(
    conn: MySQLConnection,
    host_ip: str,
    host_name: Optional[str] = None,
    last_scan_id: Optional[int] = None,
) -> int:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    INSERT INTO hosts (host_ip, host_name,first_seen, last_seen, last_scan_id)
    VALUES (%s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        host_name = COALESCE(VALUES(host_name), host_name),
        last_seen = VALUES(last_seen),
        last_scan_id = VALUES(last_scan_id);
    """

    with conn.cursor() as cur:
        cur.execute(
            sql,
            (host_ip, host_name,now, now, last_scan_id),
        )
        if cur.lastrowid:
            host_id = cur.lastrowid
        else:
            cur.execute("SELECT id FROM hosts WHERE host_ip = %s", (host_ip,))
            row = cur.fetchone()
            host_id = row[0]
    return host_id



def upsert_port(
    conn: MySQLConnection,
    host_id: int,
    port: int,
    protocol: str,
    service: Optional[str] = None,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    last_scan_id: Optional[str] = None,
    state: str = "closed",
) -> int:

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # open / closed 정규화
    state = "open" if state == "open" else "closed"

    sql = """
    INSERT INTO ports (
        host_id, port, protocol, service, version,
        banner, state, first_seen, last_seen, last_scan_id
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        service = COALESCE(VALUES(service), service),
        version = COALESCE(VALUES(version), version),
        banner = COALESCE(VALUES(banner), banner),
        state = VALUES(state),
        last_seen = VALUES(last_seen),
        last_scan_id = VALUES(last_scan_id);
    """

    with conn.cursor() as cur:
        cur.execute(
            sql,
            (
                host_id,
                port,
                protocol,
                service,
                version,
                banner,
                state,
                now,
                now,
                last_scan_id,
            ),
        )

        if cur.lastrowid:
            port_id = cur.lastrowid
        else:
            cur.execute(
                "SELECT id FROM ports WHERE host_id = %s AND port = %s AND protocol = %s",
                (host_id, port, protocol),
            )
            row = cur.fetchone()
            port_id = row[0]

    return port_id



def insert_scan(
    conn: MySQLConnection,
    target: str,
    scan_type: str,
    port_range: str,
    started_at: datetime,
    finished_at: Optional[datetime],
    status: str,
    config_snapshot: Optional[Dict[str, Any]] = None,
) -> int:

    sql = """
    INSERT INTO scans (
        target, scan_type, port_range,
        started_at, finished_at, status, config_snapshot
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s);
    """
    snapshot_json = json.dumps(config_snapshot) if config_snapshot is not None else None

    with conn.cursor() as cur:
        cur.execute(
            sql,
            (
                target,
                scan_type,
                port_range,
                started_at,
                finished_at,
                status,
                snapshot_json,
            ),
        )
        scan_db_id = cur.lastrowid
    return scan_db_id



def insert_vuln(
    conn: MySQLConnection,
    port_id: int,
    cve_id: str,
    title: str,
    severity: str,
    epss: Optional[float] = None,
    source: Optional[str] = None,
    status: str = "POTENTIAL",
) -> int:

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    INSERT INTO vulns (
        port_id, cve_id, title, severity, epss, status, source,
        created_at, updated_at
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
    """

    with conn.cursor() as cur:
        cur.execute(
            sql,
            (port_id, cve_id, title, severity, epss, status, source, now, now),
        )
        vuln_id = cur.lastrowid
    return vuln_id



def update_vuln_status(
    conn: MySQLConnection,
    vuln_id: int,
    status: str,
) -> None:

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    UPDATE vulns
    SET status = %s,
        updated_at = %s
    WHERE id = %s;
    """

    with conn.cursor() as cur:
        cur.execute(sql, (status, now, vuln_id))
