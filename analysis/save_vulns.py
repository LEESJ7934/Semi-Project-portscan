from db.db_client import get_connection
from db.query_helpers import upsert_vuln
from db.statuses import VulnStatus


def as_float(
    value,
    default: float = 0.0,
) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def save_vulns(
    vulns: list[dict],
) -> list[int]:
    """
    동일한 포트/CVE/출처는
    중복 생성하지 않고 갱신합니다.
    """
    conn = get_connection()
    saved_ids = []

    try:
        for vuln in vulns:
            vuln_id = upsert_vuln(
                conn=conn,
                port_id=vuln["port_id"],
                cve_id=vuln.get(
                    "cve_id",
                    "NONE",
                ),
                title=vuln.get(
                    "title",
                    "Unknown Vulnerability",
                ),
                severity=vuln.get(
                    "severity",
                    "INFO",
                ),
                epss=as_float(
                    vuln.get("epss")
                ),
                cvss=as_float(
                    vuln.get("cvss")
                ),
                risk=as_float(
                    vuln.get("risk")
                ),
                status=vuln.get(
                    "status",
                    VulnStatus.POTENTIAL.value,
                ),
                source=vuln.get(
                    "source",
                    "auto_rule",
                ),
            )

            saved_ids.append(vuln_id)

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()

    print(
        "[+] 취약점 저장 완료: "
        f"{len(saved_ids)}건 처리"
    )

    return saved_ids