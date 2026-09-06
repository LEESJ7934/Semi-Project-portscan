"""Shared checker interface and the Day 5 verification result contract."""
from abc import ABC, abstractmethod
from typing import Any


RESULT_STATUSES = frozenset({"POTENTIAL", "CONFIRMED", "NOT_APPLICABLE", "ERROR"})
RESULT_EVIDENCE_TYPES = frozenset({"HTTP_RESPONSE", "BANNER", "MANUAL", "ERROR_LOG"})


def check_result(status: str, reason: str, *, checker: str,
                 evidence_type: str = "MANUAL", details: dict[str, Any] | None = None,
                 additional_checks: list[str] | None = None,
                 error_code: str | None = None) -> dict:
    """Return DB-compatible values; ERROR is never an inapplicability verdict."""
    if status not in RESULT_STATUSES or evidence_type not in RESULT_EVIDENCE_TYPES:
        raise ValueError("Unsupported verification result status or evidence type")
    return {"status": status, "reason": reason, "checker": checker,
            "evidence_type": evidence_type, "details": details or {},
            "additional_checks": additional_checks or [], "error_code": error_code}


class BaseChecker(ABC):
    """Keep the existing run_check(port_record, vuln_candidate) -> dict API.

    Day 5 results contain status, reason, checker, evidence_type, details,
    additional_checks and error_code. A CONFIRMED result additionally requires
    positive_evidence describing proof beyond a banner/version/HTTP status.
    Legacy checkers are not selected by the automatic CVE dispatcher.
    """

    @abstractmethod
    def run_check(self, port_record: dict, vuln_candidate: dict) -> dict:
        raise NotImplementedError
