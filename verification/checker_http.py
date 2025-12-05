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

            # HTTP 응답 코드 검사
            if resp.status_code >= 200 and resp.status_code < 400:
                title = self._extract_title(resp.text)
                return {
                    "status": "CONFIRMED",
                    "details": f"HTTP {resp.status_code}, title='{title}'"
                }
            else:
                return {
                    "status": "INVALID",
                    "details": f"HTTP {resp.status_code}"
                }

        except Exception as e:
            return {
                "status": "INVALID",
                "details": f"HTTP request failed: {e}"
            }

    # HTML title 추출용 간단 파서
    def _extract_title(self, html: str):
        html_lower = html.lower()
        if "<title>" in html_lower and "</title>" in html_lower:
            start = html_lower.index("<title>") + len("<title>")
            end = html_lower.index("</title>")
            return html[start:end].strip()
        return "No Title"
