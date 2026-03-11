from ftplib import FTP, error_perm
from io import BytesIO
from .base_checker import BaseChecker


class FTPChecker(BaseChecker):
    def __init__(self, timeout=5):
        self.timeout = timeout

    def run_check(self, port_record, vuln_candidate):
        ip = port_record["host_ip"]
        port = port_record["port"]
        title = (vuln_candidate.get("title") or "").lower()
        source = (vuln_candidate.get("source") or "").lower()

        ftp = FTP()
        test_filename = "chatgpt_ftp_write_test.txt"

        try:
            ftp.set_pasv(False)
            ftp.connect(ip, port, timeout=self.timeout)
            banner = ftp.getwelcome()

            # anonymous login
            login_resp = ftp.login()
            files_before = []
            try:
                files_before = ftp.nlst()
            except Exception:
                files_before = []

            result = {
                "anonymous": True,
                "banner": banner,
                "login_response": login_resp,
                "file_list_before": files_before,
                "login": False
            }

            # "writable" 후보일 때만 업로드/삭제 시도
            needs_write_test = ("login" in title) or ("login" in source)

            if needs_write_test:
                payload = BytesIO(b"ftp write test")
                ftp.storbinary(f"STOR {test_filename}", payload)

                try:
                    files_after = ftp.nlst()
                except Exception:
                    files_after = []

                result["file_list_after"] = files_after
                result["login"] = True

                try:
                    ftp.delete(test_filename)
                    result["cleanup_deleted"] = True
                except Exception as e:
                    result["cleanup_deleted"] = False
                    result["cleanup_error"] = str(e)

                ftp.quit()
                return {
                    "status": "CONFIRMED",
                    "details": result
                }

            ftp.quit()
            return {
                "status": "CONFIRMED",
                "details": result
            }

        except error_perm as e:
            return {
                "status": "INVALID",
                "details": f"Permission denied or anonymous login disabled: {e}"
            }
        except Exception as e:
            return {
                "status": "ERROR",
                "details": str(e)
            }