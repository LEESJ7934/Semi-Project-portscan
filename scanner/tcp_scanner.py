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
    state: str  # "open" / "closed" / "open|filtered"
    banner: str | None = None
    service: str | None = None
    product: str | None = None
    version: str | None = None

    def to_dict(self) -> Dict:
        return asdict(self)


def scan_single_port(host: str, port: int, timeout: float = 1.0) -> PortScanResult:
    # 1) TCP 연결 시도 (포트가 열려있는지 1차 확인)
    sock = tcp_connect(host, port, timeout=timeout)

    # 연결 실패(Closed) 처리
    if sock is None:
        return PortScanResult(
            port=port,
            protocol="tcp",
            state="closed",
            banner=None,
            service=guess_service(
                port
            ),  # 닫혀있으면 그냥 포트 번호 기반으로 추측값 넣음 (참고용)
            product=None,
            version=None,
        )

    # 연결 성공! -> 일단 닫습니다.
    # 이유: grab_banner 함수가 내부적으로 새로운 소켓을 열어서
    #      깨끗한 상태에서 대화(Active Probing)를 시도하기 위함입니다.
    try:
        sock.close()
    except:
        pass

    # ================= [수정된 핵심 로직] =================
    # 2) 스마트 배너 그래빙 (서비스 이름까지 알아옴)
    # 기존 코드: banner = grab_banner(host, port, service, timeout)
    # 변경 코드: service 인자 삭제 -> (banner, detected_service) 튜플 반환 받기
    banner, detected_service = grab_banner(host, port, timeout)

    # 3) 최종 서비스 이름 결정
    # 만약 배너로 정체를 못 밝히면('unknown'), 그때 가서 포트 번호로 추측(guess)
    if detected_service != "unknown":
        final_service = detected_service
    else:
        final_service = guess_service(port) or "unknown"

    # 4) 배너 기반 버전 파싱
    version = parse_version(final_service, banner)
    # ====================================================

    return PortScanResult(
        port=port,
        protocol="tcp",
        state="open",
        banner=banner,
        service=final_service,  # 이제 정확한 서비스 이름이 들어갑니다!
        product=final_service,
        version=version,
    )


from concurrent.futures import ThreadPoolExecutor, as_completed
from .utils import parse_ports


def sequential_scan(
    host: str, ports: Iterable[int] | str, timeout: float = 1.0
) -> List[Dict]:
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
