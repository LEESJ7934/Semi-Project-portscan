from analysis.vuln_mapper import RETIRED_RULE_IDS
import hashlib
from pathlib import Path

from colorama import Fore, Style, init

from db.db_client import DBClient
from db.query_helpers import (
    get_ports_with_vuln_candidates,
    insert_vuln_evidence,
    update_vuln_verification,
)
from db.statuses import (
    VulnStatus,
    normalize_vuln_status,
)
from verification.checker_ftp import FTPChecker
from verification.checker_http import HTTPChecker
from verification.nuclei_runner import NucleiRunner
from verification.screenshot import (
    ScreenshotChecker,
)


init(autoreset=True)

CHECKER_RESULT_STATUSES = {
    "POTENTIAL",
    "CONFIRMED",
    "INVALID",
    "ERROR",
    "SKIP",
}


def colorize_status(
    status: str,
) -> str:
    status = status.upper()

    colors = {
        VulnStatus.CONFIRMED.value:
            Fore.GREEN,
        VulnStatus.POTENTIAL.value:
            Fore.YELLOW,
        VulnStatus.FALSE_POSITIVE.value:
            Fore.RED,
        VulnStatus.NOT_APPLICABLE.value:
            Fore.LIGHTBLACK_EX,
        VulnStatus.RETEST_REQUIRED.value:
            Fore.CYAN,
        VulnStatus.CLOSED.value:
            Fore.BLUE,
        VulnStatus.ERROR.value:
            Fore.MAGENTA,
    }

    color = colors.get(status, "")

    return (
        color
        + status
        + Style.RESET_ALL
    )


def get_checkers_for_candidate(
    service: str,
    vuln_candidate: dict,
) -> list:
    cve_id = (
        vuln_candidate.get("cve")
        or vuln_candidate.get("cve_id")
        or ""
    ).upper()

    if service == "ftp":
        return [FTPChecker()]

    if service in {
        "http",
        "https",
    }:
        checkers = [
            HTTPChecker(),
            ScreenshotChecker(),
        ]

        if cve_id in {
            "CVE-2012-1823",
            "CVE-2020-2551",
        }:
            checkers.append(
                NucleiRunner()
            )

        return checkers

    return []


def summarize_results(
    results: list[dict],
) -> str:
    statuses = {
        str(
            result.get(
                "status",
                "ERROR",
            )
        ).strip().upper()
        for result in results
    }

    if "CONFIRMED" in statuses:
        return VulnStatus.CONFIRMED.value

    if "POTENTIAL" in statuses:
        return VulnStatus.POTENTIAL.value

    if "ERROR" in statuses:
        return VulnStatus.ERROR.value

    if "INVALID" in statuses:
        return (
            VulnStatus.FALSE_POSITIVE.value
        )

    return (
        VulnStatus.NOT_APPLICABLE.value
    )


def evidence_type_for(
    checker_name: str,
    status: str,
) -> str:
    if status == "ERROR":
        return "ERROR_LOG"

    if checker_name == "ScreenshotChecker":
        return "SCREENSHOT"

    if checker_name == "NucleiRunner":
        return "NUCLEI"

    if checker_name == "HTTPChecker":
        return "HTTP_RESPONSE"

    if checker_name == "FTPChecker":
        return "BANNER"

    return "MANUAL"


def file_sha256(
    file_path: str | None,
) -> str | None:
    if not file_path:
        return None

    path = Path(file_path)

    if not path.is_file():
        return None

    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(
            lambda: file.read(65536),
            b"",
        ):
            digest.update(chunk)

    return digest.hexdigest()


def run_checker(
    checker,
    port_record: dict,
    vuln_candidate: dict,
) -> dict:
    try:
        result = checker.run_check(
            port_record,
            vuln_candidate,
        )

    except Exception as error:
        result = {
            "status": "ERROR",
            "details": (
                f"{type(error).__name__}: "
                f"{error}"
            ),
        }

    raw_status = str(
        result.get(
            "status",
            "ERROR",
        )
    ).strip().upper()

    if (
        raw_status
        not in CHECKER_RESULT_STATUSES
    ):
        raw_status = "ERROR"
        result["details"] = (
            "검증기가 지원하지 않는 "
            "상태값을 반환했습니다."
        )

    result["status"] = raw_status
    return result


def run_verifications() -> None:
    db = DBClient()

    try:
        targets = (
            get_ports_with_vuln_candidates(
                db.conn
            )
        )

        for (
            port_record,
            vuln_candidate,
        ) in targets:
            source = vuln_candidate.get("source", "")
            if source in RETIRED_RULE_IDS or source.startswith("day4:"):
                print(f"[REVIEW] vuln_id={vuln_candidate['id']}: "
                      "requires a CVE-specific verifier; status preserved.")
                continue
            service = str(
                port_record.get(
                    "service"
                )
                or ""
            ).lower()

            port = port_record["port"]
            protocol = port_record.get(
                "protocol",
                "tcp",
            )
            vuln_id = vuln_candidate["id"]

            checkers = (
                get_checkers_for_candidate(
                    service,
                    vuln_candidate,
                )
            )

            if not checkers:
                update_vuln_verification(
                    conn=db.conn,
                    vuln_id=vuln_id,
                    status=(
                        VulnStatus
                        .NOT_APPLICABLE
                    ),
                    reason=(
                        "등록된 검증기가 없는 "
                        "서비스입니다: "
                        f"{service or 'unknown'}"
                    ),
                )

                db.conn.commit()
                continue

            results = []

            try:
                for checker in checkers:
                    checker_name = (
                        checker
                        .__class__
                        .__name__
                    )

                    result = run_checker(
                        checker,
                        port_record,
                        vuln_candidate,
                    )

                    raw_status = (
                        result["status"]
                    )

                    details = str(
                        result.get("details")
                        or ""
                    )[:60000]

                    evidence_path = (
                        result.get(
                            "evidence_path"
                        )
                    )

                    insert_vuln_evidence(
                        conn=db.conn,
                        vuln_id=vuln_id,
                        checker=checker_name,
                        evidence_type=(
                            evidence_type_for(
                                checker_name,
                                raw_status,
                            )
                        ),
                        details=details,
                        evidence_path=(
                            evidence_path
                        ),
                        sha256=file_sha256(
                            evidence_path
                        ),
                    )

                    results.append(result)

                    tag = (
                        f"[{service.upper()}] "
                        f"{port}/{protocol}"
                    )

                    print(
                        f"{tag} -> "
                        f"{checker_name}: "
                        f"{colorize_status(raw_status)}"
                    )

                final_status = (
                    summarize_results(
                        results
                    )
                )

                if (
                    vuln_candidate.get(
                        "status"
                    )
                    == VulnStatus
                    .RETEST_REQUIRED
                    .value
                    and final_status
                    == VulnStatus
                    .POTENTIAL
                    .value
                ):
                    final_status = (
                        VulnStatus
                        .RETEST_REQUIRED
                        .value
                    )

                result_summary = ", ".join(
                    result["status"]
                    for result in results
                )

                update_vuln_verification(
                    conn=db.conn,
                    vuln_id=vuln_id,
                    status=(
                        normalize_vuln_status(
                            final_status
                        )
                    ),
                    reason=(
                        "자동 검증 결과: "
                        f"{result_summary}"
                    ),
                )

                db.conn.commit()

                print(
                    "    final: "
                    f"{colorize_status(final_status)}"
                )

            except Exception:
                db.conn.rollback()
                raise

    finally:
        db.close()


if __name__ == "__main__":
    run_verifications()