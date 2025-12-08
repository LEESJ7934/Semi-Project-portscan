# scanner/domain_resolver.py

import socket
from typing import Tuple, Optional
from .utils import is_valid_ip


def resolve_target(target: str) -> Tuple[str, str, Optional[str]]:
    """
    타겟(IP 또는 도메인)을 받아서 (IP, 도메인, 추가정보) 튜플을 반환합니다.

    1. IP가 들어오면 -> 도메인을 찾음 (Reverse DNS / PTR)
    2. 도메인이 들어오면 -> IP를 찾음 (Forward DNS / A)

    Returns: (ip_address, hostname, resolution_type)
    """
    ip_address = ""
    hostname = ""
    res_type = ""

    try:
        if is_valid_ip(target):
            # Case A: 사용자가 IP를 입력함 (예: 127.0.0.1)
            ip_address = target
            res_type = "Reverse DNS (PTR)"
            try:
                # gethostbyaddr: IP -> 도메인 (역방향 조회)
                # 반환값: (hostname, aliaslist, ipaddrlist)
                host_info = socket.gethostbyaddr(ip_address)
                hostname = host_info[0]
            except socket.herror:
                # 역방향 도메인이 없는 경우 (대부분의 개인 PC나 보안 설정된 서버)
                hostname = "unknown_host"
        else:
            # Case B: 사용자가 도메인을 입력함 (예: google.com)
            hostname = target
            res_type = "Forward DNS (A)"
            try:
                # gethostbyname: 도메인 -> IP (정방향 조회)
                ip_address = socket.gethostbyname(hostname)
            except socket.gaierror:
                return (target, "unresolved", "error")

        return (ip_address, hostname, res_type)

    except Exception as e:
        # 치명적 오류 시 원본 그대로 반환
        return (target, "error", str(e))
