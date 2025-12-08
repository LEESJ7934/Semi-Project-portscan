import socket
import time

# 1. 시그니처 데이터베이스 (포트 번호가 아닌 '내용'으로 판단)
SIGNATURES = {
    "ftp": [b"220", b"FTP", b"vsFTPd"],
    "ssh": [b"SSH-", b"OpenSSH"],
    "smtp": [b"220", b"SMTP", b"ESMTP"],
    "mysql": [b"mysql_native_password"],
    "http": [b"HTTP/1.1", b"Server:", b"<html>", b"<head>"],
}

# 2. 말을 안 할 때 찔러볼 질문들 (Probes)
PROBES = [
    # HTTP Probe
    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    # Generic Line Feed (일부 서버는 엔터 치면 반응함)
    b"\r\n\r\n",
]


def grab_banner(host: str, port: int, timeout: float = 2.0) -> tuple[str, str]:
    """
    포트의 배너를 가져오고, 내용을 분석해 서비스 이름을 반환합니다.
    Returns: (banner_content, service_name)
    """
    banner_content = ""
    service_name = "unknown"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # [전략 1] 수동적 대기 (Passive): 서버가 먼저 말하는지 듣는다 (FTP, SSH)
        try:
            data = sock.recv(1024)
            if data:
                banner_content = data.decode(errors="ignore").strip()
                # 배너를 얻었으니 바로 분석 시도
                service_name = identify_service(data)
        except socket.timeout:
            pass  # 말이 없으면 다음 단계로

        # [전략 2] 능동적 찌르기 (Active): 말이 없으면 질문을 던진다 (HTTP)
        if service_name == "unknown":
            for probe in PROBES:
                try:
                    sock.sendall(probe)
                    # 질문 후 응답 대기
                    data = sock.recv(2048)
                    if data:
                        response = data.decode(errors="ignore").strip()
                        banner_content += (
                            f"\n[Probe Response]: {response[:50]}..."  # 로그용
                        )

                        # 응답 분석
                        detected = identify_service(data)
                        if detected != "unknown":
                            service_name = detected
                            break  # 찾았으면 중단
                except Exception:
                    continue

        sock.close()
        return banner_content, service_name

    except Exception as e:
        return None, None


def identify_service(raw_data: bytes) -> str:
    """받은 데이터(Byte) 안에 시그니처가 있는지 검사"""
    for service, patterns in SIGNATURES.items():
        for pattern in patterns:
            if (
                pattern in raw_data
            ):  # 대소문자 구분 없이 하려면 raw_data.lower() 사용 가능
                return service
    return "unknown"
