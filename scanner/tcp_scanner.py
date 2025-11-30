from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Dict, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import tcp_connect, parse_ports
from .banner_grabber import grab_banner
from .version_parser import parse_version
from .service_fingerprints import guess_service


@dataclass
class PortScanResult:
    port: int
    protocol: str  # "tcp" / "udp"
    state: str     # "open" / "closed" / "open|filtered"
    banner: str | None = None
    service: str | None = None
    version: str | None = None

    def to_dict(self) -> Dict:
        return asdict(self)


def scan_single_port(host: str, port: int, timeout: float = 1.0) -> PortScanResult:
    # 1) TCP 연결 시도
    sock = tcp_connect(host, port, timeout=timeout)

    if sock is None:
        return PortScanResult(
            port=port,
            protocol="tcp",
            state="closed",
            banner=None,
            service=guess_service(port),
            version=None
        )

    # 연결 성공 → 바로 소켓 닫기
    try:
        sock.close()
    except:
        pass

    service = guess_service(port)

    # 2) 프로토콜별 banner grab
    banner = grab_banner(host, port, service, timeout)

    # 3) 배너 기반 버전 파싱
    version = parse_version(service, banner)

    return PortScanResult(
        port=port,
        protocol="tcp",
        state="open",
        banner=banner,
        service=service,
        version=version
    )

from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import parse_ports

def sequential_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0) -> List[Dict]:
    """
    단일 IP에 대해 순차 TCP 스캔.
    """
    port_list = parse_ports(ports)
    results: List[Dict] = []

    for p in port_list:
        res = scan_single_port(host, p, timeout=timeout)
        results.append(res.to_dict())

    return results


def threaded_scan(
    host: str,
    ports: Iterable[int] | str,
    timeout: float = 1.0,
    max_workers: int = 100,
) -> List[Dict]:
    """
    단일 IP에 대해 멀티스레드 TCP 스캔.
    """
    port_list = parse_ports(ports)
    results: List[PortScanResult] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_single_port, host, p, timeout): p for p in port_list
        }

        for future in as_completed(future_to_port):
            res = future.result()
            results.append(res)

    results.sort(key=lambda r: r.port)
    return [r.to_dict() for r in results]
