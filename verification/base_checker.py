# verification/base_checker.py

from abc import ABC, abstractmethod

class BaseChecker(ABC):
    """모든 검증 모듈이 따라야 할 공통 인터페이스"""

    @abstractmethod
    def run_check(self, port_record: dict, vuln_candidate: dict) -> dict:
        """
        port_record 예시:
            { "host_ip": "1.2.3.4", "port": 80, "service": "http", ... }

        vuln_candidate:
            { "cve": "CVE-2021-1234", "source": "fingerprint", ... }

        return 구조:
            {
              "status": "confirmed" | "failed" | "error",
              "details": "...",
              "evidence_path": "...optional screenshot path..."
            }
        """
        pass
