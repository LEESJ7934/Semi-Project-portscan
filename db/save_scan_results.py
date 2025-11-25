# db/save_scan_results.py

from db.db_client import get_connection
from db.query_helpers import upsert_host, upsert_port
from datetime import datetime


def save_scan_results(scan_result: dict):
    """
    scan_runner.py 가 반환한 결과(dict)를 받아 DB에 저장.
    
    scan_result 구조:
    {
      "scan_id": "...",
      "started_at": "...",
      "finished_at": "...",
      "targets": [
        {
          "ip": "127.0.0.1",
          "results": [
             {"port": 22, "status": "open", "service": "...", "banner": "..."},
             ...
          ]
        },
        ...
      ]
    }
    """

    scan_id = scan_result["scan_id"]
    targets = scan_result["targets"]

    conn = get_connection()

    for t in targets:
        ip = t["ip"]

        # 1) hosts 테이블 upsert
        host_id = upsert_host(
            conn,
            host_ip=ip,
            host_name=None,
            os_name=None,
            last_scan_id=scan_id,
        )

        # 2) 각 포트 결과 upsert
        for r in t["results"]:
            port = r["port"]
            state = r["state"]
            service = r.get("service")
            banner = r.get("banner")
            
            upsert_port(
                conn,
                host_id=host_id,
                port=port,
                protocol="tcp",
                service=service,
                product=None,
                version=None,
                banner=banner,
                last_scan_id=scan_id,
                is_open=(state == "open"),
            )

    conn.commit()
    conn.close()
    return True

