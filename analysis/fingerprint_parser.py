# analysis/fingerprint_parser.py
import re

def parse_banner(banner: str, service: str):
    """
    banner 문자열에서 '버전'만 추출한다.
    product는 더 이상 사용하지 않으므로 항상 None 반환.
    """
    if not banner:
        return None, None

    # 서비스별 배너 기반 버전 추출 패턴
    patterns = {
        # SSH → OpenSSH_8.9p1 → 8.9p1
        "ssh": r"OpenSSH[_/ ](?P<version>[0-9\.p]+)",

        # FTP → vsftpd 3.0.5 → 3.0.5
        "ftp": r"vsftpd[ ](?P<version>[0-9\.]+)",

        # HTTP → Server: Apache/2.4.25 (Debian) → 2.4.25
        "http": r"Apache/(?P<version>[0-9\.]+)"
    }

    regex = patterns.get(service)
    if not regex:
        return None, None

    match = re.search(regex, banner, re.IGNORECASE | re.MULTILINE)
    if not match:
        return None, None

    version = match.group("version")

    # product는 더 이상 DB에도 rule 매핑에도 사용하지 않음
    return None, version
