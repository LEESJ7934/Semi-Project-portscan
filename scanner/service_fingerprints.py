# scanner/service_fingerprints.py

# 단순 포트 → 기본 서비스 매핑
PORT_SERVICE_MAP: dict[int, str] = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    8080: "http-alt",
    # 필요시 계속 추가
}


def guess_service(port: int) -> str | None:
    """포트 번호로 기본 서비스 이름 추정."""
    return PORT_SERVICE_MAP.get(port)
