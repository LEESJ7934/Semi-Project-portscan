from colorama import Fore, Style, init
init(autoreset=True)

# === 필수 체크 모듈 가져오기 ===
from verification.checker_http import HTTPChecker
from verification.checker_ftp import FTPChecker
from verification.screenshot import ScreenshotChecker
from verification.nuclei_runner import NucleiRunner

from db.db_client import DBClient
from db.query_helpers import get_ports_with_vuln_candidates, update_vuln_verification

from colorama import Fore, Style, init
init(autoreset=True)

CHECKER_MAP = {
    "http": [HTTPChecker(), ScreenshotChecker(), NucleiRunner()],
    "ftp":  [FTPChecker(), NucleiRunner()]
}

def colorize_status(status: str):
    status = status.upper()

    if status == "CONFIRMED":
        return Fore.GREEN + status + Style.RESET_ALL

    if status == "INVALID":
        return Fore.RED + status + Style.RESET_ALL

    if status in ("SKIP", "NONE"):
        return Fore.LIGHTBLACK_EX + status + Style.RESET_ALL

    return status  # fallback

def run_verifications():
    db = DBClient()

    targets = get_ports_with_vuln_candidates()

    for port_record, vuln_candidate in targets:
        service = port_record.get("service")
        ip = port_record["host_ip"]
        port = port_record["port"]

        if service not in CHECKER_MAP:
            continue

        for checker in CHECKER_MAP[service]:
            result = checker.run_check(port_record, vuln_candidate)

            # 상태 정규화
            raw_status = str(result["status"]).strip().upper()
            if raw_status not in ("POTENTIAL", "CONFIRMED", "INVALID"):
                raw_status = "INVALID"

            # DB 업데이트
            update_vuln_verification(
                db.conn,
                vuln_candidate["id"],
                raw_status
            )

            # 출력 형식
            checker_name = checker.__class__.__name__
            short_name = (
                checker_name
                .replace("Checker", "")
                .replace("Runner", "")
            )

            # nuclei는 취약점 종류까지 구분해주면 이해가 쉬움
            if short_name == "Nuclei":
                short_name = f"Nuclei-{vuln_candidate['source'].replace('rule_','')}"

            tag = f"[{service.upper()}] {port}/tcp"

            colored_status = colorize_status(raw_status)

            print(f"{tag} → {short_name}: {colored_status}")


if __name__ == "__main__":
    run_verifications()
