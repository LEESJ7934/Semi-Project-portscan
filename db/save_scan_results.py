from db.db_client import get_connection
from db.query_helpers import upsert_host, upsert_port, insert_scan, insert_vuln
from datetime import datetime
from scanner.utils import resolve_hostname


def save_scan_results(scan_result: dict):
    scan_id = scan_result["scan_id"]
    targets = scan_result["targets"]

    conn = get_connection()

    # 타겟 문자열 생성 (여러 개일 경우 콤마로 구분)
    target_str = ",".join(t.get("ip", "unknown") for t in targets)
    started_at = datetime.fromisoformat(scan_result["started_at"])
    finished_at = datetime.fromisoformat(scan_result["finished_at"])

    # 1. 스캔 이력 저장
    insert_scan(
        conn=conn,
        target=target_str,
        scan_type=scan_result.get("scan_type", "tcp+udp"),
        port_range=scan_result.get("port_range", "1-1024"),
        started_at=started_at,
        finished_at=finished_at,
        status="DONE",
        scan_id=scan_id,
        config_snapshot=None,  # 필요시 추가
    )

    for t in targets:
        ip = t["ip"]
        # hostname이 결과에 있으면 쓰고, 없으면 조회
        host_name = t.get("hostname") or resolve_hostname(ip)

        # 2. 호스트 저장
        host_id = upsert_host(
            conn,
            host_ip=ip,
            host_name=host_name,
            last_scan_id=scan_id,
        )

        for r in t["results"]:
            port = r["port"]
            protocol = r["protocol"]
            state = r["state"]
            service = r.get("service", "unknown")
            banner = r.get("banner")
            product = r.get("product")
            version = r.get("version")
            screenshot = r.get("screenshot")  # [NEW] 스크린샷 경로

            # 3. 포트 저장
            port_id = upsert_port(
                conn,
                host_id=host_id,
                port=port,
                protocol=protocol,
                state=state,
                service=service,
                banner=banner,
                product=product,
                version=version,
                screenshot_path=screenshot,  # [NEW] 전달
                last_scan_id=scan_id,
            )

            # 4. 취약점(Nuclei) 저장 [NEW]
            vulns = r.get("vulnerabilities", [])
            if vulns and port_id:
                for v in vulns:
                    insert_vuln(
                        conn=conn,
                        port_id=port_id,
                        cve_id=v.get("cve_id") or "N/A",
                        title=v.get("name") or "Unknown Vuln",
                        severity=v.get("severity", "LOW").upper(),
                        epss=v.get("epss"),
                        source="Nuclei",
                        status="POTENTIAL",
                    )

    conn.commit()
    conn.close()
