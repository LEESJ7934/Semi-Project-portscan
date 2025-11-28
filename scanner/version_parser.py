# scanner/version_parser.py

import re

def parse_version(service: str, banner: str | None) -> str | None:
    if not banner:
        return None

    b = banner.lower()

    # SSH
    if service == "ssh":
        m = re.search(r"openssh[_/ ]([\d\.p]+)", b)
        if m:
            return f"OpenSSH {m.group(1)}"
        return banner.strip()

    # FTP
    if service == "ftp":
        m = re.search(r"vsftpd ([\d\.]+)", b)
        if m:
            return f"vsftpd {m.group(1)}"
        return banner.strip()

    # HTTP
    if service == "http":
        m = re.search(r"server: ([^\r\n]+)", banner, re.IGNORECASE)
        if m:
            return m.group(1)
        return banner.strip()

    # Telnet은 배너 파싱 실패해도 raw로 출력
    if service == "telnet":
        return banner.strip()

    return banner.strip()
