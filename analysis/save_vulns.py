# analysis/save_vulns.py

from db.db_client import get_connection
from datetime import datetime

def save_vulns(vuln_list):

    if not vuln_list:
        return

    conn = get_connection()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    sql = """
    INSERT INTO vulns (
        port_id, cve_id, title, severity, epss, status, source, created_at, updated_at
    )
    VALUES (
        %s, %s, %s, %s, %s, 'POTENTIAL', %s, %s, %s
    )
    """

    with conn.cursor() as cur:
        for v in vuln_list:

            # severity를 ENUM 형식에 맞게 대문자로 변환
            sev = v["severity"].upper()

            cur.execute(sql, (
                v["port_id"],
                v["cve_id"],
                v["title"],
                sev,
                v["epss"],        # nullable OK
                v["rule_id"],     # source = rule_id
                now,              # created_at
                now               # updated_at
            ))

    conn.commit()
    conn.close()
