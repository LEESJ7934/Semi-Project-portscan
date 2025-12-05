# verification/checker_ftp.py

from ftplib import FTP
from .base_checker import BaseChecker

class FTPChecker(BaseChecker):

    def run_check(self, port_record, vuln_candidate):
        ip = port_record["host_ip"]
        port = port_record["port"]

        try:
            ftp = FTP()
            ftp.set_pasv(False)
            ftp.connect(ip, port, timeout=5)
            ftp.login()   # anonymous login
            files = ftp.nlst()
            ftp.quit()

            return {
                "status": "CONFIRMED",
                "details": {
                    "anonymous": True,
                    "file_list": files
                }
            }
        except Exception as e:
            return {"status": "INVALID", "details": str(e)}
