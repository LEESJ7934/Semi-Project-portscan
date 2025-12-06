# analysis/save_vulns.py
from datetime import datetime
from db.db_client import get_connection


def save_vulns(vulns):
    """
    DB vulns 테이블에 취약점 저장.
    EPSS + CVSS + Risk 모두 저장.
    """
    sql = """
    INSERT INTO vulns 
    (port_id, cve_id, title, severity, epss, cvss, risk, status, source, created_at, updated_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    conn = get_connection()
    with conn.cursor() as cur:
        for v in vulns:
            port_id = v["port_id"]
            cve_id = v.get("cve_id", "NONE")
            title = v.get("title", "Unknown Vulnerability")
            severity = v.get("severity", "LOW")
            epss = float(v.get("epss", 0.0))
            cvss = float(v.get("cvss", 0.0))
            risk = float(v.get("risk", 0.0))
            status = v.get("status", "POTENTIAL")
            source = v.get("source", "auto_rule")

            now = datetime.utcnow()

            cur.execute(sql, (
                port_id, cve_id, title, severity,
                epss, cvss, risk, status, source,
                now, now
            ))

    conn.commit()
    conn.close()

    print("[+] Vulnerabilities saved with CVSS and Risk")
