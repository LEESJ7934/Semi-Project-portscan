"""Compatibility entry point; the former DVWA/CVE templates have been retired."""
from .base_checker import BaseChecker, check_result


# No reviewed, nonintrusive CVE-specific templates are configured for Day 5.
CVE_TEMPLATE_MAP: dict[str, str] = {}


class NucleiRunner(BaseChecker):
    def __init__(self, nuclei_path=None, templates_root=None, dvwa_host=None, debug=False):
        self.nuclei_path = nuclei_path
        self.templates_root = templates_root
        self.dvwa_host = dvwa_host
        self.debug = debug

    def _resolve_template_path(self, cve_id: str) -> str:
        raise FileNotFoundError(f"No reviewed nonintrusive Nuclei template for {cve_id}")

    def run_check(self, port_record, vuln_candidate):
        cve_id = vuln_candidate.get("cve_id") or vuln_candidate.get("cve")
        return check_result(
            "ERROR", "No reviewed nonintrusive Nuclei template is configured; no process or login was started.",
            checker=type(self).__name__, evidence_type="ERROR_LOG", error_code="UNSUPPORTED_VERIFIER",
            details={"cve_id": cve_id, "safe_checks": []},
            additional_checks=["Use the CVE-specific dispatcher or review the official advisory manually."],
        )
