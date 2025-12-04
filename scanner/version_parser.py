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
            return m.group(1)
        return banner.strip()

    # FTP
    if service == "ftp":
        m = re.search(r"vsftpd ([\d\.]+)", b)
        if m:
            return m.group(1)
        return banner.strip()

    # HTTP
    if service == "http":
    # Server: Apache/2.4.25 (Debian)
        m = re.search(r"Apache/([\d\.]+)", banner, re.IGNORECASE)
        if m:
            return m.group(1)   # ← 버전만 저장됨
        return None
    # Telnet은 배너 파싱 실패해도 raw로 출력
    if service == "telnet":
        return banner.strip()

    return banner.strip()
