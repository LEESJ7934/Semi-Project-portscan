import requests
from .base_checker import BaseChecker


class HTTPChecker(BaseChecker):
    def __init__(self, timeout=4):
        self.timeout = timeout

    def run_check(self, port_record, vuln_candidate):
        ip = port_record["host_ip"]
        port = port_record["port"]

        url = f"http://{ip}:{port}"

        try:
            resp = requests.get(url, timeout=self.timeout)

            if 200 <= resp.status_code < 400:
                title = self._extract_title(resp.text)
                return {
                    "status": "POTENTIAL",
                    "details": f"HTTP {resp.status_code}, title='{title}'"
                }

            return {
                "status": "INVALID",
                "details": f"HTTP {resp.status_code}"
            }

        except Exception as e:
            return {
                "status": "ERROR",
                "details": f"HTTP request failed: {e}"
            }

    def _extract_title(self, html: str):
        html_lower = html.lower()
        if "<title>" in html_lower and "</title>" in html_lower:
            start = html_lower.index("<title>") + len("<title>")
            end = html_lower.index("</title>")
            return html[start:end].strip()
        return "No Title"
