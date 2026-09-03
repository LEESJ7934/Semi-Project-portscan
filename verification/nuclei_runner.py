import os
import shutil
import subprocess
from pathlib import Path

from dotenv import load_dotenv

from .base_checker import BaseChecker
from .dvwa_auth import get_dvwa_cookie_header


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")


CVE_TEMPLATE_MAP = {
    "CVE-2012-1823": os.path.join(
        "http",
        "cves",
        "2012",
        "dvwa_sqli_cve_2012_1823.yaml",
    ),
    "CVE-2020-2551": os.path.join(
        "http",
        "cves",
        "2020",
        "dvwa_fileupload_cve_2020_2551.yaml",
    ),
}


class NucleiRunner(BaseChecker):
    def __init__(
        self,
        nuclei_path=None,
        templates_root=None,
        dvwa_host=None,
        debug=False,
    ):
        self.nuclei_path = (
            nuclei_path
            or os.getenv("NUCLEI_PATH")
            or shutil.which("nuclei")
        )
        self.templates_root = (
            templates_root
            or os.getenv("NUCLEI_TEMPLATES_PATH")
        )
        self.dvwa_host = (
            dvwa_host
            or os.getenv("DVWA_HOST", "127.0.0.1")
        )
        self.debug = debug

    def _log(self, *args):
        if self.debug:
            print("[NucleiRunner]", *args)

    def _resolve_template_path(self, cve_id: str) -> str:
        if not self.templates_root:
            raise FileNotFoundError(
                "NUCLEI_TEMPLATES_PATH가 설정되지 않았습니다."
            )

        relative_path = CVE_TEMPLATE_MAP.get(cve_id)

        if not relative_path:
            raise FileNotFoundError(
                f"CVE 템플릿 매핑이 없습니다: {cve_id}"
            )

        return os.path.join(
            self.templates_root,
            relative_path,
        )

    def run_check(self, port_record, vuln_candidate):
        ip = port_record["host_ip"]
        port = port_record["port"]
        service = port_record.get("service", "")

        if service not in ("http", "https"):
            return {
                "status": "SKIP",
                "details": "HTTP/HTTPS 서비스가 아닙니다.",
            }

        protocol = "https" if service == "https" else "http"
        target = f"{protocol}://{ip}:{port}"

        cve_id = (
            vuln_candidate.get("cve")
            or vuln_candidate.get("cve_id")
        )

        if not cve_id or cve_id == "NONE":
            return {
                "status": "SKIP",
                "details": "CVE 정보가 없습니다.",
            }

        try:
            template_path = self._resolve_template_path(cve_id)
        except FileNotFoundError as error:
            return {
                "status": "SKIP",
                "details": str(error),
            }

        if not os.path.exists(template_path):
            return {
                "status": "ERROR",
                "details": f"템플릿을 찾을 수 없습니다: {template_path}",
            }

        cookie_header = None

        if ip == self.dvwa_host:
            try:
                cookie_header = get_dvwa_cookie_header()
            except Exception as error:
                return {
                    "status": "ERROR",
                    "details": f"DVWA 로그인 실패: {error}",
                }

        if not self.nuclei_path:
            return {
                "status": "ERROR",
                "details": (
                    "Nuclei 실행 파일을 찾지 못했습니다. "
                    "NUCLEI_PATH를 설정하거나 PATH에 추가하세요."
                ),
            }

        command = [
            self.nuclei_path,
            "-u",
            target,
            "-t",
            template_path,
            "-vv",
        ]

        if cookie_header:
            command.extend([
                "-H",
                f"Cookie: {cookie_header}",
            ])

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=25,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return {
                "status": "ERROR",
                "details": str(error),
            }

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            return {
                "status": "ERROR",
                "details": stderr or stdout or "Nuclei 실행 실패",
            }

        output_lower = stdout.lower()

        if (
            "0 matches" in output_lower
            or "no results" in output_lower
        ):
            return {
                "status": "INVALID",
                "details": "취약점이 확인되지 않았습니다.",
            }

        if stdout:
            return {
                "status": "CONFIRMED",
                "details": stdout,
            }

        return {
            "status": "INVALID",
            "details": "Nuclei 출력 결과가 없습니다.",
        }