# 모든 모듈에서 공통으로 호출하는 DB 저장/조회 API 역할
import json
from datetime import datetime
from typing import Optional, Dict, Any, List
from mysql.connector import MySQLConnection
from .db_client import get_connection



# -----------------------------
# 1) HOST UPSERT
# -----------------------------
def upsert_host(
    conn: MySQLConnection,
    host_ip: str,
    host_name: Optional[str] = None,
    last_scan_id: Optional[int] = None,
) -> int:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    INSERT INTO hosts (host_ip, host_name, first_seen, last_seen, last_scan_id)
    VALUES (%s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE
        host_name = COALESCE(VALUES(host_name), host_name),
        last_seen = VALUES(last_seen),
        last_scan_id = VALUES(last_scan_id);
    """

    with conn.cursor() as cur:
        cur.execute(sql, (host_ip, host_name, now, now, last_scan_id))

        if cur.lastrowid:
            host_id = cur.lastrowid
        else:
            cur.execute("SELECT id FROM hosts WHERE host_ip = %s", (host_ip,))
            row = cur.fetchone()
            host_id = row[0]

    return host_id

def get_all_ports() -> List[Dict[str, Any]]:
    """
    analysis/run_analysis.py에서 사용하는 함수.
    ports + hosts 테이블을 JOIN하여, 포트 정보와 IP를 함께 가져온다.
    """

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
    FROM ports p
    JOIN hosts h ON p.host_id = h.id;
    """

    results = []

    with conn.cursor(dictionary=True) as cur:
        cur.execute(sql)
        rows = cur.fetchall()

        for r in rows:
            # run_analysis → vuln_mapper.map_vulns() 에 필요한 필드만 담아 전달
            results.append({
                "id": r["port_id"],
                "host_ip": r["host_ip"],
                "port": r["port"],
                "protocol": r["protocol"],
                "service": r["service"],
                "version": r["version"],
                "banner": r["banner"],
                "state": r["state"],
            })

    conn.close()
    return results

# -----------------------------
# 2) PORT UPSERT
# -----------------------------
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
            (host_id, port, protocol, service, version,
             banner, state, now, now, last_scan_id)
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



# -----------------------------
# 3) SCAN 삽입
# -----------------------------
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

    snapshot_json = json.dumps(config_snapshot) if config_snapshot else None

    with conn.cursor() as cur:
        cur.execute(
            sql,
            (target, scan_type, port_range, started_at,
             finished_at, status, snapshot_json),
        )
        scan_db_id = cur.lastrowid

    return scan_db_id



# -----------------------------
# 4) 취약점 INSERT
# -----------------------------
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



# -----------------------------
# 5) 취약점 상태 UPDATE  (verification용)
# -----------------------------
def update_vuln_verification(
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



# -----------------------------
# ⭐ 6) 취약점 검증 대상 조회 (verification 전용)
# -----------------------------
def get_ports_with_vuln_candidates() -> List[Dict[str, Any]]:
    """
    hosts → ports → vulns JOIN하여
    status = 'POTENTIAL' 인 취약점만 가져온다.
    verification/run_verification.py 에서 사용됨.
    """

    conn = get_connection()

    sql = """
    SELECT
        p.id          AS port_id,
        h.host_ip     AS host_ip,
        p.port        AS port,
        p.service     AS service,
        v.id          AS vuln_id,
        v.cve_id,
        v.title,
        v.source
    FROM vulns v
    JOIN ports p  ON v.port_id = p.id
    JOIN hosts h  ON p.host_id = h.id
    WHERE v.status = 'POTENTIAL';
    """

    results = []

    with conn.cursor(dictionary=True) as cur:
        cur.execute(sql)
        rows = cur.fetchall()

        for r in rows:
            port_record = {
                "id": r["port_id"],
                "host_ip": r["host_ip"],
                "port": r["port"],
                "service": r["service"]
            }
            vuln_record = {
                "id": r["vuln_id"],
                "cve": r["cve_id"],
                "title": r["title"],
                "source": r["source"]
            }
            results.append((port_record, vuln_record))

    conn.close()
    return results
