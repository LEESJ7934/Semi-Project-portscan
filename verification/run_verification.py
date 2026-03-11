from colorama import Fore, Style, init
init(autoreset=True)

from verification.checker_http import HTTPChecker
from verification.checker_ftp import FTPChecker
from verification.screenshot import ScreenshotChecker
from verification.nuclei_runner import NucleiRunner

from db.db_client import DBClient
from db.query_helpers import get_ports_with_vuln_candidates, update_vuln_verification


def colorize_status(status: str):
    status = status.upper()

    if status == "CONFIRMED":
        return Fore.GREEN + status + Style.RESET_ALL

    if status == "POTENTIAL":
        return Fore.YELLOW + status + Style.RESET_ALL

    if status == "INVALID":
        return Fore.RED + status + Style.RESET_ALL

    if status == "ERROR":
        return Fore.MAGENTA + status + Style.RESET_ALL

    if status in ("SKIP", "NONE"):
        return Fore.LIGHTBLACK_EX + status + Style.RESET_ALL

    return status


def get_checkers_for_candidate(service: str, vuln_candidate: dict):
    cve_id = (vuln_candidate.get("cve") or vuln_candidate.get("cve_id") or "").upper()
    title = (vuln_candidate.get("title") or "").lower()
    source = (vuln_candidate.get("source") or "").lower()

    if service == "ftp":
        # FTP는 지금 anonymous/writable 전용 checker만 사용
        return [FTPChecker()]

    if service in ("http", "https"):
        checkers = [HTTPChecker(), ScreenshotChecker()]

        # 실제 HTTP 취약점용 CVE일 때만 nuclei 추가
        if cve_id in ("CVE-2012-1823", "CVE-2020-2551"):
            checkers.append(NucleiRunner())

        return checkers

    return []


def summarize_results(results):
    """
    우선순위:
    CONFIRMED > POTENTIAL > INVALID > SKIP
    ERROR는 실행 오류이므로 INVALID처럼 덮지 않고 우선 보존
    """
    statuses = [str(r["status"]).upper() for r in results]

    if "CONFIRMED" in statuses:
        return "CONFIRMED"
    if "POTENTIAL" in statuses:
        return "POTENTIAL"
    if "ERROR" in statuses:
        return "ERROR"
    if "INVALID" in statuses:
        return "INVALID"
    return "SKIP"


def run_verifications():
    db = DBClient()
    targets = get_ports_with_vuln_candidates()

    for port_record, vuln_candidate in targets:
        service = port_record.get("service", "").lower()
        ip = port_record["host_ip"]
        port = port_record["port"]

        checkers = get_checkers_for_candidate(service, vuln_candidate)
        if not checkers:
            continue

        results = []

        for checker in checkers:
            result = checker.run_check(port_record, vuln_candidate)
            raw_status = str(result.get("status", "ERROR")).strip().upper()

            if raw_status not in ("POTENTIAL", "CONFIRMED", "INVALID", "ERROR", "SKIP"):
                raw_status = "ERROR"

            result["status"] = raw_status
            results.append(result)

            checker_name = checker.__class__.__name__
            short_name = (
                checker_name
                .replace("Checker", "")
                .replace("Runner", "")
            )

            if short_name == "Nuclei":
                short_name = f"Nuclei-{(vuln_candidate.get('source') or '').replace('rule_','')}"

            tag = f"[{service.upper()}] {port}/tcp"
            colored_status = colorize_status(raw_status)

            print(f"{tag} → {short_name}: {colored_status}")

        final_status = summarize_results(results)

        update_vuln_verification(
            db.conn,
            vuln_candidate["id"],
            final_status
        )

        print(f"    └─ final: {colorize_status(final_status)}")


if __name__ == "__main__":
    run_verifications()