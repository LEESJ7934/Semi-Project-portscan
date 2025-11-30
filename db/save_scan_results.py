# db/save_scan_results.py

from db.db_client import get_connection
from db.query_helpers import upsert_host, upsert_port, insert_scan
from scanner.service_fingerprints import PORT_SERVICE_MAP, guess_service
from datetime import datetime
from scanner.utils import resolve_hostname


def save_scan_results(scan_result: dict):
    scan_id = scan_result["scan_id"]
    targets = scan_result["targets"]

    conn = get_connection()

    target_str = ",".join(t["ip"] for t in targets)
    started_at = datetime.fromisoformat(scan_result["started_at"])
    finished_at = datetime.fromisoformat(scan_result["finished_at"])

    insert_scan(
        conn=conn,
        target=target_str,
        scan_type=scan_result.get("scan_type", "tcp+udp"),
        port_range=scan_result.get("port_range", "1-1024"),
        started_at=started_at,
        finished_at=finished_at,
        status=scan_result.get("status", "DONE"),
        config_snapshot=scan_result.get("config"),
    )

    for t in targets:
        ip = t["ip"]
        host_name = resolve_hostname(ip)
        host_id = upsert_host(
            conn,
            host_ip=ip,
            host_name=host_name,
            last_scan_id=scan_id,
        )

        for r in t["results"]: 
            port = r["port"]

            # 🔥🔥🔥 여기서 필터링: PORT_SERVICE_MAP 에 없는 포트는 저장 안 함
            if r["state"] != "open":
                continue

            protocol = r["protocol"]
            state = r["state"]
            service = r.get("service")
            banner = r.get("banner")
            version = r.get("version")
            upsert_port(
                conn,
                host_id=host_id,
                port=port,
                protocol=protocol,
                service=service,
                version=version,
                banner=banner,
                last_scan_id=scan_id,
                state=state,    # open / closed / open|filtered
            )

    conn.commit()
    conn.close()
    return True
