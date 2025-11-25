# scanner/scan_runner.py
from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Dict, Iterable

from .scanner import sequential_scan, threaded_scan
from .utils import is_valid_ip, parse_ports


def generate_scan_id() -> str:
    """간단한 scan_id 생성: timestamp + uuid4"""
    ts = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    u = uuid.uuid4().hex[:8]
    return f"scan-{ts}-{u}"


def run_scan(
    targets: Iterable[str],
    ports: Iterable[int] | str = "20-1024",
    timeout: float = 1.0,
    threaded: bool = True,
    max_workers: int = 100,
) -> Dict:
    """
    여러 IP 대상 스캔 실행.
    - DB 저장 X, 결과만 반환.
    - 반환 구조 예:
      {
        "scan_id": "...",
        "started_at": "...",
        "finished_at": "...",
        "targets": [
          {"ip": "1.2.3.4", "results": [...]},
          {"ip": "5.6.7.8", "results": [...]},
        ]
      }
    """
    scan_id = generate_scan_id()
    started_at = datetime.utcnow().isoformat()

    port_list = parse_ports(ports)
    target_list = list(targets)

    targets_results: List[Dict] = []

    for ip in target_list:
        if not is_valid_ip(ip):
            targets_results.append(
                {
                    "ip": ip,
                    "error": "invalid_ip",
                    "results": [],
                }
            )
            continue

        if threaded:
            res = threaded_scan(ip, port_list, timeout=timeout, max_workers=max_workers)
        else:
            res = sequential_scan(ip, port_list, timeout=timeout)

        targets_results.append(
            {
                "ip": ip,
                "results": res,
            }
        )

    finished_at = datetime.utcnow().isoformat()

    return {
        "scan_id": scan_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "targets": targets_results,
    }
