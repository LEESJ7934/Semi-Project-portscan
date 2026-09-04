from enum import Enum


class ScanStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class VulnStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    POTENTIAL = "POTENTIAL"
    CONFIRMED = "CONFIRMED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RETEST_REQUIRED = "RETEST_REQUIRED"
    CLOSED = "CLOSED"
    ERROR = "ERROR"


SCAN_STATUS_ALIASES = {
    "DONE": ScanStatus.COMPLETED.value,
    "SUCCESS": ScanStatus.COMPLETED.value,
    "ERROR": ScanStatus.FAILED.value,
}

VULN_STATUS_ALIASES = {
    "INVALID": VulnStatus.FALSE_POSITIVE.value,
    "REJECTED": VulnStatus.FALSE_POSITIVE.value,
    "SKIP": VulnStatus.NOT_APPLICABLE.value,
    "NONE": VulnStatus.NOT_APPLICABLE.value,
}

ALLOWED_VULN_TRANSITIONS = {
    VulnStatus.CANDIDATE.value: {
        VulnStatus.POTENTIAL.value,
        VulnStatus.NOT_APPLICABLE.value,
        VulnStatus.ERROR.value,
    },
    VulnStatus.POTENTIAL.value: {
        VulnStatus.CONFIRMED.value,
        VulnStatus.NOT_APPLICABLE.value,
        VulnStatus.FALSE_POSITIVE.value,
        VulnStatus.ERROR.value,
    },
    VulnStatus.CONFIRMED.value: {
        VulnStatus.RETEST_REQUIRED.value,
        VulnStatus.CLOSED.value,
    },
    VulnStatus.NOT_APPLICABLE.value: {
        VulnStatus.RETEST_REQUIRED.value,
    },
    VulnStatus.FALSE_POSITIVE.value: {
        VulnStatus.RETEST_REQUIRED.value,
    },
    VulnStatus.RETEST_REQUIRED.value: {
        VulnStatus.CONFIRMED.value,
        VulnStatus.NOT_APPLICABLE.value,
        VulnStatus.FALSE_POSITIVE.value,
        VulnStatus.CLOSED.value,
        VulnStatus.ERROR.value,
    },
    VulnStatus.CLOSED.value: {
        VulnStatus.RETEST_REQUIRED.value,
    },
    VulnStatus.ERROR.value: {
        VulnStatus.POTENTIAL.value,
        VulnStatus.RETEST_REQUIRED.value,
        VulnStatus.NOT_APPLICABLE.value,
    },
}


def normalize_scan_status(
    value: str | ScanStatus,
) -> str:
    if isinstance(value, ScanStatus):
        return value.value

    normalized = str(value).strip().upper()
    normalized = SCAN_STATUS_ALIASES.get(
        normalized,
        normalized,
    )

    try:
        return ScanStatus(normalized).value
    except ValueError as error:
        raise ValueError(
            f"지원하지 않는 스캔 상태입니다: {value}"
        ) from error


def normalize_vuln_status(
    value: str | VulnStatus,
) -> str:
    if isinstance(value, VulnStatus):
        return value.value

    normalized = str(value).strip().upper()
    normalized = VULN_STATUS_ALIASES.get(
        normalized,
        normalized,
    )

    try:
        return VulnStatus(normalized).value
    except ValueError as error:
        raise ValueError(
            f"지원하지 않는 취약점 상태입니다: {value}"
        ) from error


def validate_vuln_transition(
    current_status: str | VulnStatus,
    new_status: str | VulnStatus,
) -> tuple[str, str]:
    current = normalize_vuln_status(
        current_status
    )
    new = normalize_vuln_status(
        new_status
    )

    if current == new:
        return current, new

    allowed = ALLOWED_VULN_TRANSITIONS[
        current
    ]

    if new not in allowed:
        raise ValueError(
            "허용되지 않는 취약점 상태 변경입니다: "
            f"{current} -> {new}"
        )

    return current, new