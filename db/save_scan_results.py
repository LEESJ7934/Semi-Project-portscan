from datetime import datetime

from db.db_client import get_connection
from db.query_helpers import (
    insert_scan,
    upsert_host,
    upsert_port,
)
from db.statuses import ScanStatus
from scanner.utils import resolve_hostname


def determine_scan_status(
    targets: list[dict],
) -> str:
    failed_count = sum(
        1
        for target in targets
        if target.get("error")
    )

    if failed_count == 0:
        return ScanStatus.COMPLETED.value

    if failed_count == len(targets):
        return ScanStatus.FAILED.value

    return ScanStatus.PARTIAL.value


def save_scan_results(
    scan_result: dict,
) -> int:
    scan_uid = scan_result["scan_id"]
    targets = scan_result["targets"]

    target_text = ",".join(
        str(target.get("ip", "unknown"))
        for target in targets
    )

    started_at = datetime.fromisoformat(
        scan_result["started_at"]
    )
    finished_at = datetime.fromisoformat(
        scan_result["finished_at"]
    )

    scan_status = determine_scan_status(
        targets
    )

    conn = get_connection()

    try:
        scan_db_id = insert_scan(
            conn=conn,
            scan_uid=scan_uid,
            target=target_text,
            scan_type=scan_result.get(
                "scan_type",
                "tcp",
            ),
            port_range=str(
                scan_result.get(
                    "port_range",
                    "1-1024",
                )
            ),
            started_at=started_at,
            finished_at=finished_at,
            status=scan_status,
            config_snapshot=scan_result.get(
                "config"
            ),
        )

        for target in targets:
            if target.get("error"):
                continue

            host_ip = target["ip"]
            host_name = resolve_hostname(
                host_ip
            )

            host_id = upsert_host(
                conn=conn,
                host_ip=host_ip,
                host_name=host_name,
                last_scan_id=scan_db_id,
            )

            for result in target.get(
                "results",
                [],
            ):
                if result.get("state") != "open":
                    continue

                upsert_port(
                    conn=conn,
                    host_id=host_id,
                    port=result["port"],
                    protocol=result["protocol"],
                    service=result.get(
                        "service"
                    ),
                    version=result.get(
                        "version"
                    ),
                    banner=result.get(
                        "banner"
                    ),
                    last_scan_id=scan_db_id,
                    state=result["state"],
                )

        conn.commit()
        return scan_db_id

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()