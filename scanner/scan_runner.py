from __future__ import annotations

from .screenshot import take_screenshot  # 상단에 추가
from .nuclei_runner import run_nuclei  # 상단에 추가
from .domain_resolver import resolve_target  # 추가
import uuid
from datetime import datetime
from typing import List, Dict, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed  # 멀티스레딩용

from .tcp_scanner import sequential_scan, threaded_scan  # TCP scanner (Connect)
from .udp_scanner import sequential_udp_scan, threaded_udp_scan  # UDP scanner
from .syn_scanner import syn_scan_port  # [New] SYN scanner (Stealth)
from .utils import is_valid_ip, parse_ports

# [삭제됨] 과도한 필터링을 유발하는 import 제거
# from .service_fingerprints import TCP_PORTS, UDP_PORTS


def generate_scan_id() -> str:
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    u = uuid.uuid4().hex[:8]
    return f"scan-{ts}-{u}"


# [New] 스텔스 스캔을 병렬로 처리하기 위한 내부 헬퍼 함수
def threaded_syn_scan(
    target: str, ports: List[int], timeout: float, max_workers: int
) -> List[Dict]:
    results = []
    # Scapy는 I/O 작업이므로 스레딩 효과가 큽니다.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # {Future객체: 포트번호} 딕셔너리 생성
        future_to_port = {
            executor.submit(syn_scan_port, target, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                # syn_scan_port는 "open", "closed", "filtered" 문자열 반환
                status = future.result()

                if status == "open":
                    # DB 형식에 맞는 딕셔너리 생성
                    # 주의: SYN 스캔은 연결을 안 맺으므로 배너(Banner)를 못 가져옵니다.
                    results.append(
                        {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "unknown",  # 나중에 HTTP 등으로 추가 확인 가능
                            "version": None,
                            "banner": None,
                        }
                    )
                # 닫힌 포트는 결과에 안 담음 (DB 용량 절약)
            except Exception as e:
                # 에러 발생 시 로그 (필요하다면 print)
                pass

    return results


def run_scan(
    targets: Iterable[str],
    ports: Iterable[int] | str = "20-1024",
    timeout: float = 1.0,
    threaded: bool = True,
    max_workers: int = 100,
    enable_udp: bool = False,  # TCP + UDP
    udp_only: bool = False,
    scan_type: str = "tcp",  # UDP only
    stealth: bool = False,  # [New] 스텔스 모드 인자 추가
) -> Dict:

    scan_id = generate_scan_id()
    started_at = datetime.utcnow().isoformat()

    # 사용자 포트 범위 파싱
    port_list = parse_ports(ports)

    # [수정] 과도한 필터링 로직 제거!
    # 사용자가 입력한 포트 리스트를 그대로 사용합니다.
    # 이전 코드: tcp_port_list = [p for p in port_list if p in TCP_PORTS] (문제의 원인)
    tcp_port_list = port_list

    # UDP는 특성상 스캔 속도가 느리므로, 명시된 포트가 아니면 필터링 할 수도 있지만,
    # 여기서는 사용자 의도를 존중해 그대로 넣습니다.
    udp_port_list = port_list

    targets_results: List[Dict] = []

    for target_input in targets:
        # [Phase 5] 1. 도메인 분석 (nslookup) 수행
        real_ip, hostname, res_type = resolve_target(target_input)

        # IP 변환에 실패했으면 에러 처리
        if real_ip == target_input and hostname == "unresolved":
            targets_results.append(
                {
                    "ip": target_input,
                    "error": "dns_resolution_failed",
                    "results": [],
                }
            )
            continue

        if not is_valid_ip(real_ip):
            targets_results.append(
                {
                    "ip": real_ip,
                    "error": "invalid_ip",
                    "results": [],
                }
            )
            continue

        print(
            f"[*] Target Identified: {target_input} -> IP: {real_ip} | Host: {hostname} ({res_type})"
        )

        # 이후 로직에서는 찾아낸 실제 IP(real_ip)를 사용합니다.
        ip = real_ip

        # =====================================================
        # TCP 스캔 (Stealth vs Normal)
        # =====================================================
        if udp_only:
            tcp_results = []
        else:
            if stealth:
                # [New] 스텔스 모드 작동 (SYN Scan)
                # print(f"[*] Running Stealth SYN Scan on {ip}...") # 디버깅용
                tcp_results = threaded_syn_scan(
                    ip, tcp_port_list, timeout=timeout, max_workers=max_workers
                )
            else:
                # [Old] 일반 모드 작동 (Connect Scan + Smart Banner Grabber)
                if threaded:
                    tcp_results = threaded_scan(
                        ip, tcp_port_list, timeout=timeout, max_workers=max_workers
                    )
                else:
                    tcp_results = sequential_scan(ip, tcp_port_list, timeout=timeout)

        # =====================================================
        # UDP 스캔
        # =====================================================
        if enable_udp or udp_only:
            if threaded:
                udp_results = threaded_udp_scan(
                    ip, udp_port_list, timeout=timeout, max_workers=max_workers
                )
            else:
                udp_results = sequential_udp_scan(ip, udp_port_list, timeout=timeout)
        else:
            udp_results = []

        # TCP + UDP 결과 병합
        merged = tcp_results + udp_results

        # =====================================================
        # [Phase 4] Post-Scan Intelligence (Nuclei + Screenshot)
        # =====================================================
        # 발견된 포트 중 웹 서비스에 대해 Nuclei 실행
        for result in merged:
            if result["state"] == "open":
                port = result["port"]
                # 서비스 이름을 모르면(Unknown) 일단 웹이라고 가정하고 찔러보거나(80, 443, 8080 등),
                # Phase 2에서 알아낸 service 정보를 활용합니다.

                # 예: 서비스가 http, https거나, 포트가 웹 포트 대역이면 실행
                # (일단 테스트를 위해 8088, 3330은 무조건 실행하도록 로직 작성)
                is_web_port = port in [80, 443, 8080, 8088, 3330]
                service_name = result.get("service", "unknown")

                if "http" in service_name or is_web_port:
                    # 1. Nuclei 실행!
                    vulns = run_nuclei(ip, port, "http")  # 일단 http로 가정

                    if vulns:
                        result["vulnerabilities"] = vulns

                    # [Phase 4-2] 2. 웹 스크린샷 캡처
                    screenshot_path = take_screenshot(ip, port, service_name)
                    if screenshot_path:
                        result["screenshot"] = screenshot_path  # 결과에 경로 저장
        # =====================================================

        targets_results.append(
            {
                "ip": ip,
                "hostname": hostname,  # <--- 추가됨! (나중에 보고서에 씀)
                "results": merged,
            }
        )

    finished_at = datetime.utcnow().isoformat()

    return {
        "scan_id": scan_id,
        "scan_type": "stealth_syn" if stealth else scan_type,  # 스캔 타입 기록
        "started_at": started_at,
        "finished_at": finished_at,
        "targets": targets_results,
    }
