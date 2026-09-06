"""Legacy FTP helper: greeting inspection only, with no login or file operations."""
from ftplib import FTP, error_perm, error_proto, error_reply, error_temp

from .base_checker import BaseChecker, check_result


class FTPChecker(BaseChecker):
    def __init__(self, timeout=5):
        self.timeout = timeout

    def run_check(self, port_record, vuln_candidate):
        ftp = FTP()
        try:
            ftp.connect(port_record["host_ip"], port_record["port"], timeout=self.timeout)
            return check_result(
                "POTENTIAL", "FTP greeting received; authentication and CVE conditions remain unverified.",
                checker=type(self).__name__, evidence_type="BANNER",
                details={"safe_checks": ["ftp_greeting_only"], "banner": ftp.getwelcome()[:512]},
                additional_checks=["Review FTP configuration and the specific CVE; no file-write test was performed."],
            )
        except TimeoutError:
            code = "TIMEOUT"
        except (error_perm, error_proto, error_reply, error_temp):
            code = "FTP_PROTOCOL_ERROR"
        except OSError:
            code = "CONNECTION_ERROR"
        finally:
            ftp.close()
        return check_result("ERROR", "FTP greeting inspection failed; no vulnerability verdict is available.",
                            checker=type(self).__name__, evidence_type="ERROR_LOG", error_code=code,
                            details={"safe_checks": ["ftp_greeting_only"]})
