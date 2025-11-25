# scanner/scanner.py
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import List, Dict, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import tcp_connect, parse_ports
from .banner_grabber import grab_banner
from .service_fingerprints import guess_service


@dataclass
class PortScanResult:
    port: int
    protocol: str  # "tcp"
    state: str     # "open" / "closed"
    banner: str | None = None
    service: str | None = None

    def to_dict(self) -> Dict:
        return asdict(self)


def scan_single_port(host: str, port: int, timeout: float = 1.0) -> PortScanResult:
    """
    단일 포트 스캔.
    - connect 성공: open, 배너 및 서비스 추정
    - 실패: closed
    """
    sock = tcp_connect(host, port, timeout=timeout)
    if sock is None:
        return PortScanResult(
            port=port,
            protocol="tcp",
            state="closed",
            banner=None,
            service=guess_service(port),
        )

    # 연결 성공했다면 배너 그랩 시도
    try:
        sock.close()
    except OSError:
        pass

    banner = grab_banner(host, port, timeout=timeout)
    service = guess_service(port)

    return PortScanResult(
        port=port,
        protocol="tcp",
        state="open",
        banner=banner,
        service=service,
    )


def sequential_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0) -> List[Dict]:
    """
    단일 IP에 대해 순차 스캔.
    - 입력: 포트 리스트 또는 포트 범위 문자열 ("20-1024")
    - 출력: [{port, protocol, state, banner, service}, ...]
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
    단일 IP에 대해 멀티스레드 스캔.
    - ThreadPoolExecutor 사용
    - 결과는 포트 번호 기준 정렬
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

    # 포트 번호 기준 정렬 후 dict 리스트로 반환
    results.sort(key=lambda r: r.port)
    return [r.to_dict() for r in results]
