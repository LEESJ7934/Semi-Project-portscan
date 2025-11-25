# scripts/db_connect_test.py

from db.db_client import get_connection
from db.query_helpers import upsert_host, upsert_port, insert_vuln


def main():
    conn = get_connection()
    try:
        # 임시 scan_id 없음
        host_id = upsert_host(conn, host_ip="127.0.0.1")
        port_id = upsert_port(conn, host_id=host_id, port=22, protocol="tcp", service="ssh")
        vuln_id = insert_vuln(
            conn,
            port_id=port_id,
            cve_id="CVE-TEST-0001",
            title="Test vuln",
            severity="LOW",
            epss=0.1234,
            source="manual",
        )
        conn.commit()
        print("host_id:", host_id, "port_id:", port_id, "vuln_id:", vuln_id)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
