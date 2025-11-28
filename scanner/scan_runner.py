# scanner/scan_runner.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Dict, Iterable

from .tcp_scanner import sequential_scan, threaded_scan          # TCP scanner
from .udp_scanner import sequential_udp_scan, threaded_udp_scan  # UDP scanner
from .utils import is_valid_ip, parse_ports
from .service_fingerprints import TCP_PORTS, UDP_PORTS
# 자동 포트 분리 로직 import
from .service_fingerprints import TCP_PORTS, UDP_PORTS


def generate_scan_id() -> str:
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    u = uuid.uuid4().hex[:8]
    return f"scan-{ts}-{u}"


def run_scan(
    targets: Iterable[str],
    ports: Iterable[int] | str = "20-1024",
    timeout: float = 1.0,
    threaded: bool = True,
    max_workers: int = 100,
    enable_udp: bool = False,   # TCP + UDP
    udp_only: bool = False, 
    scan_type: str = "tcp",     # UDP only
) -> Dict:

    scan_id = generate_scan_id()
    started_at = datetime.utcnow().isoformat()

    # 사용자 포트 범위
    port_list = parse_ports(ports)

    # 자동 TCP/UDP 필터링
    tcp_port_list = [p for p in port_list if p in TCP_PORTS]
    udp_port_list = [p for p in port_list if p in UDP_PORTS]

    targets_results: List[Dict] = []

    for ip in targets:
        if not is_valid_ip(ip):
            targets_results.append({
                "ip": ip,
                "error": "invalid_ip",
                "results": [],
            })
            continue

        # =====================================================
        # TCP 스캔
        # =====================================================
        if udp_only:
            tcp_results = []
        else:
            if threaded:
                tcp_results = threaded_scan(
                    ip, tcp_port_list, timeout=timeout, max_workers=max_workers
                )
            else:
                tcp_results = sequential_scan(
                    ip, tcp_port_list, timeout=timeout
                )

        # =====================================================
        # UDP 스캔
        # =====================================================
        if enable_udp or udp_only:
            if threaded:
                udp_results = threaded_udp_scan(
                    ip, udp_port_list, timeout=timeout, max_workers=max_workers
                )
            else:
                udp_results = sequential_udp_scan(
                    ip, udp_port_list, timeout=timeout
                )
        else:
            udp_results = []

        # TCP + UDP 결과 병합
        merged = tcp_results + udp_results

        targets_results.append({
            "ip": ip,
            "results": merged,
        })

    finished_at = datetime.utcnow().isoformat()

    return {
        "scan_id": scan_id,
        "scan_type": scan_type, 
        "started_at": started_at,
        "finished_at": finished_at,
        "targets": targets_results,
    }
