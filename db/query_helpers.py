# 모든 모듈(scanner, analysis, verification, api)에서 공통으로 호출하는 DB 저장/조회 API 역할
from datetime import datetime
from typing import Optional, Dict, Any

from mysql.connector import MySQLConnection

from .db_client import get_connection


def upsert_host(
    conn: MySQLConnection,
    host_ip: str,
    host_name: Optional[str] = None,
    os_name: Optional[str] = None,
    last_scan_id: Optional[int] = None,
) -> int:
    """
    host_ip 기준으로 hosts 테이블 upsert.
    - 없으면 INSERT
    - 있으면 last_seen, host_name, os_name, last_scan_id 업데이트
    반환값: host_id
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    INSERT INTO hosts (host_ip, host_name, os_name, first_seen, last_seen, last_scan_id)
    VALUES (%s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        host_name = COALESCE(VALUES(host_name), host_name),
        os_name = COALESCE(VALUES(os_name), os_name),
        last_seen = VALUES(last_seen),
        last_scan_id = VALUES(last_scan_id);
    """
    with conn.cursor() as cur:
        cur.execute(
            sql,
            (host_ip, host_name, os_name, now, now, last_scan_id),
        )
        # 새로 INSERT면 lastrowid, 아니면 기존 id를 다시 조회
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
    product: Optional[str] = None,
    version: Optional[str] = None,
    banner: Optional[str] = None,
    last_scan_id: Optional[int] = None,
    is_open: bool = True,
) -> int:
    """
    (host_id, port, protocol) 기준으로 ports 테이블 upsert.
    - 없으면 INSERT
    - 있으면 last_seen, service/product/version/banner, is_open, last_scan_id 업데이트
    반환값: port_id
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    INSERT INTO ports (
        host_id, port, protocol, service, product, version,
        banner, is_open, first_seen, last_seen, last_scan_id
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        service = COALESCE(VALUES(service), service),
        product = COALESCE(VALUES(product), product),
        version = COALESCE(VALUES(version), version),
        banner = COALESCE(VALUES(banner), banner),
        is_open = VALUES(is_open),
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
                product,
                version,
                banner,
                1 if is_open else 0,
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
    """
    새 취약점 후보 추가.
    - port_id + cve_id 조합으로 중복 체크할지 여부는 이후 필요 시 확장.
    """
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
    """
    취약점 상태 변경(POTENTIAL -> CONFIRMED/REJECTED 등).
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    sql = """
    UPDATE vulns
    SET status = %s,
        updated_at = %s
    WHERE id = %s;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (status, now, vuln_id))
