# scanner/version_parser.py

import re


def parse_version(service: str, banner: str | None) -> str | None:
    if not banner:
        return None

    b = banner.lower()

    # 1. SSH
    if service == "ssh":
        m = re.search(r"openssh[_/ ]([\d\.p]+)", b)
        if m:
            return f"OpenSSH {m.group(1)}"
        return banner.strip()[:100]  # 안전장치: 100자 넘으면 자름

    # 2. FTP
    if service == "ftp":
        m = re.search(r"vsftpd ([\d\.]+)", b)
        if m:
            return f"vsftpd {m.group(1)}"
        return banner.strip()[:100]

    # 3. HTTP (여기가 문제였음!)
    if service == "http":
        m = re.search(r"server: ([^\r\n]+)", banner, re.IGNORECASE)
        if m:
            return m.group(1)[:100]

        # Server 헤더가 없으면 HTML 전체를 버전이라고 우기지 말고, None 반환
        return None

    # 4. 기타 서비스 (Telnet 등)
    # 무엇이든 DB에 넣기 전에는 100자로 잘라야 안전함
    return banner.strip()[:100]
