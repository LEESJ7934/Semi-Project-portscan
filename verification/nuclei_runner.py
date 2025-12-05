import os
import subprocess
from .base_checker import BaseChecker
from .dvwa_auth import get_dvwa_cookie_header


CVE_TEMPLATE_MAP = {
    "CVE-2012-1823": os.path.join("http", "cves", "2012", "dvwa_sqli_cve_2012_1823.yaml"),
    "CVE-2020-2551": os.path.join("http", "cves", "2020", "dvwa_fileupload_cve_2020_2551.yaml"),
}


class NucleiRunner(BaseChecker):
    def __init__(
        self,
        nuclei_path=r"C:\Users\Seung Jun\AppData\Local\Programs\nuclei\nuclei.exe",
        templates_root=r"C:\Users\Seung Jun\nuclei-templates",
        dvwa_host="3.35.37.54",
        debug=False,
    ):
        self.nuclei_path = nuclei_path
        self.templates_root = templates_root
        self.dvwa_host = dvwa_host
        self.debug = debug

    def _log(self, *args):
        if self.debug:
            print("[NucleiRunner]", *args)

    def _resolve_template_path(self, cve_id: str) -> str:
        rel = CVE_TEMPLATE_MAP.get(cve_id)
        if not rel:
            raise FileNotFoundError(f"No template mapping for CVE: {cve_id}")
        return os.path.join(self.templates_root, rel)

    def run_check(self, port_record, vuln_candidate):
        ip = port_record["host_ip"]
        port = port_record["port"]
        service = port_record.get("service", "")

        if service == "http":
            target = f"http://{ip}:{port}"
        else:
            target = f"{ip}:{port}"

        cve_id = vuln_candidate.get("cve")
        if not cve_id or cve_id == "NONE":
            return {"status": "INVALID", "details": "No CVE provided"}

        try:
            template_path = self._resolve_template_path(cve_id)
        except FileNotFoundError as e:
            return {"status": "INVALID", "details": str(e)}

        if not os.path.exists(template_path):
            return {"status": "INVALID", "details": f"Template not found: {template_path}"}

        cookie_header = None
        if ip == self.dvwa_host and service == "http":
            try:
                cookie_header = get_dvwa_cookie_header()
            except Exception as e:
                return {"status": "INVALID", "details": f"DVWA login failed: {e}"}

        try:
            cmd = [
                self.nuclei_path,
                "-u", target,
                "-t", template_path,
                "-vv",
            ]

            if cookie_header:
                cmd.extend(["-H", f"Cookie: {cookie_header}"])

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if stderr and "error" in stderr.lower():
                return {"status": "INVALID", "details": stderr}

            if "0 matches" in stdout.lower() or "no results" in stdout.lower():
                return {"status": "INVALID", "details": "No matches"}

            if stdout:
                return {"status": "CONFIRMED", "details": stdout}

            return {"status": "INVALID", "details": "Empty output"}

        except Exception as e:
            return {"status": "INVALID", "details": str(e)}
