# scanner/utils.py
import ipaddress
from typing import List, Iterable
import socket


def is_valid_ip(ip: str) -> bool:
    """IPv4/IPv6 형식 검증."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_hostname(ip: str) -> str | None:
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        return host              # 문자열만 반환
    except socket.herror:
        return None              # 역방향 DNS 없으면 None

def parse_ports(ports: str | Iterable[int]) -> List[int]:
    """
    포트 범위 파싱.
    - "80" / "22,80,443" / "20-25,80,443" 형식 지원
    - 이미 리스트[int]를 넣으면 그대로 정렬해서 반환
    """
    if isinstance(ports, (list, tuple, set)):
        return sorted({int(p) for p in ports if 0 < int(p) <= 65535})

    result: set[int] = set()
    for token in ports.split(","):
        token = token.strip()
        if not token:
            continue

        if "-" in token:
            start_str, end_str = token.split("-", 1)
            start = int(start_str)
            end = int(end_str)
            if start > end:
                start, end = end, start
            for p in range(start, end + 1):
                if 0 < p <= 65535:
                    result.add(p)
        else:
            p = int(token)
            if 0 < p <= 65535:
                result.add(p)

    return sorted(result)


def tcp_connect(host: str, port: int, timeout: float = 1.0) -> socket.socket | None:
    """
    단순 TCP connect 함수.
    - 성공: 연결된 socket 반환
    - 실패: None
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        return sock
    except OSError:
        return None


def udp_connect(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # UDP는 연결 개념이 없어 바로 sendto()로 패킷 전송
        sock.sendto(b"", (host, port))

        try:
            data, addr = sock.recvfrom(1024)
            # 응답 패킷 수신 → open
            return "open"
        except socket.timeout:
            # 응답 없음 → open|filtered
            return "open|filtered"
        except OSError as e:
            # ICMP Port Unreachable (Win/Linux 에러 코드 다름)
            if e.errno in (111, 113, 10061):
                return "closed"
            return "open|filtered"

    except Exception:
        return "closed"
    finally:
        try:
            sock.close()
        except:
            pass