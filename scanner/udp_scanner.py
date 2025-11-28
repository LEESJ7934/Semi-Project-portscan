# scanner/udp_scanner.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Dict, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import udp_connect, parse_ports
from .service_fingerprints import guess_service


@dataclass
class UDPPortScanResult:
    port: int
    protocol: str   # "udp"
    state: str      # "open" / "closed" / "open|filtered"
    banner: str | None = None   # UDP는 일반적으로 배너 없음
    service: str | None = None

    def to_dict(self) -> Dict:
        return asdict(self)


def scan_single_udp_port(host: str, port: int, timeout: float = 1.0) -> UDPPortScanResult:
    """
    단일 UDP 포트 스캔.
    - 응답 수신       → open
    - ICMP unreachable → closed
    - 응답 없음       → open|filtered
    """
    state = udp_connect(host, port, timeout)
    service = guess_service(port)

    return UDPPortScanResult(
        port=port,
        protocol="udp",
        state=state,
        banner=None,
        service=service,
    )


def sequential_udp_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0) -> List[Dict]:
    """
    단일 IP에 대해 순차 UDP 스캔.
    - 출력: [{port, protocol, state, banner, service}, ...]
    """
    port_list = parse_ports(ports)
    results: List[Dict] = []

    for p in port_list:
        res = scan_single_udp_port(host, p, timeout=timeout)
        results.append(res.to_dict())

    return results


def threaded_udp_scan(
    host: str,
    ports: Iterable[int] | str,
    timeout: float = 1.0,
    max_workers: int = 100,
) -> List[Dict]:
    """
    단일 IP에 대해 멀티스레드 UDP 스캔.
    - ThreadPoolExecutor 사용
    - 결과는 포트 번호 기준 정렬
    """
    port_list = parse_ports(ports)
    results: List[UDPPortScanResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_single_udp_port, host, p, timeout): p for p in port_list
        }

        for future in as_completed(future_to_port):
            res = future.result()
            results.append(res)

    results.sort(key=lambda r: r.port)
    return [r.to_dict() for r in results]
