from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .targets import (
    HARD_MAX_TARGETS,
    ResolvedTarget,
    normalize_hostname,
)


class ScopeValidationError(ValueError):
    """Raised when a scan is outside the approved scope."""


def _required_text(
    data: Mapping[str, Any],
    key: str,
    max_length: int,
) -> str:
    value = data.get(key)

    if not isinstance(value, str) or not value.strip():
        raise ScopeValidationError(
            f"스코프 파일의 {key} 값이 필요합니다."
        )

    normalized = value.strip()

    if len(normalized) > max_length:
        raise ScopeValidationError(
            f"스코프 파일의 {key} 값은 {max_length}자를 "
            "초과할 수 없습니다."
        )

    return normalized


def _parse_datetime(value: Any, key: str) -> datetime:
    if not isinstance(value, str):
        raise ScopeValidationError(
            f"스코프 파일의 {key} 값은 ISO 8601 "
            "문자열이어야 합니다."
        )

    normalized = value.strip().replace("Z", "+00:00")

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ScopeValidationError(
            f"스코프 파일의 {key} 날짜 형식이 "
            "올바르지 않습니다: {value}"
        ) from exc

    if parsed.tzinfo is None:
        raise ScopeValidationError(
            f"스코프 파일의 {key}에는 시간대가 필요합니다."
        )

    return parsed.astimezone(timezone.utc)


def _bounded_integer(
    data: Mapping[str, Any],
    key: str,
    minimum: int,
    maximum: int,
) -> int:
    value = data.get(key)

    if isinstance(value, bool) or not isinstance(value, int):
        raise ScopeValidationError(
            f"스코프 파일의 {key} 값은 정수여야 합니다."
        )

    if not minimum <= value <= maximum:
        raise ScopeValidationError(
            f"스코프 파일의 {key} 값은 "
            f"{minimum}~{maximum} 범위여야 합니다."
        )

    return value


@dataclass(frozen=True)
class ScopePolicy:
    scope_uid: str
    name: str
    authorization_ref: str
    approved_by: str
    valid_from: datetime
    valid_until: datetime
    allowed_targets: tuple[str, ...]
    max_targets: int
    max_workers: int
    max_ports_per_target: int

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
    ) -> "ScopePolicy":
        if not isinstance(data, Mapping):
            raise ScopeValidationError(
                "스코프 파일 최상위 값은 객체여야 합니다."
            )

        raw_targets = data.get("allowed_targets")

        if (
            not isinstance(raw_targets, list)
            or not raw_targets
            or any(
                not isinstance(item, str)
                or not item.strip()
                for item in raw_targets
            )
        ):
            raise ScopeValidationError(
                "allowed_targets에는 하나 이상의 대상이 "
                "필요합니다."
            )

        allowed_targets = tuple(
            item.strip() for item in raw_targets
        )
        valid_from = _parse_datetime(
            data.get("valid_from"),
            "valid_from",
        )
        valid_until = _parse_datetime(
            data.get("valid_until"),
            "valid_until",
        )

        if valid_from >= valid_until:
            raise ScopeValidationError(
                "valid_until은 valid_from보다 늦어야 합니다."
            )

        policy = cls(
            scope_uid=_required_text(
                data,
                "scope_uid",
                64,
            ),
            name=_required_text(data, "name", 255),
            authorization_ref=_required_text(
                data,
                "authorization_ref",
                255,
            ),
            approved_by=_required_text(
                data,
                "approved_by",
                255,
            ),
            valid_from=valid_from,
            valid_until=valid_until,
            allowed_targets=allowed_targets,
            max_targets=_bounded_integer(
                data,
                "max_targets",
                1,
                HARD_MAX_TARGETS,
            ),
            max_workers=_bounded_integer(
                data,
                "max_workers",
                1,
                512,
            ),
            max_ports_per_target=_bounded_integer(
                data,
                "max_ports_per_target",
                1,
                65535,
            ),
        )
        policy._compiled_allowlist()
        return policy

    @classmethod
    def load(cls, path: str | Path) -> "ScopePolicy":
        scope_path = Path(path)

        try:
            raw_text = scope_path.read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise ScopeValidationError(
                f"스코프 파일을 읽을 수 없습니다: {scope_path}"
            ) from exc

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ScopeValidationError(
                f"스코프 JSON 형식이 올바르지 않습니다: "
                f"{scope_path}"
            ) from exc

        return cls.from_dict(data)

    def _compiled_allowlist(
        self,
    ) -> tuple[
        tuple[
            ipaddress.IPv4Network
            | ipaddress.IPv6Network,
            ...,
        ],
        frozenset[str],
    ]:
        networks = []
        hostnames = set()

        for entry in self.allowed_targets:
            try:
                if "/" in entry:
                    network = ipaddress.ip_network(
                        entry,
                        strict=False,
                    )
                else:
                    address = ipaddress.ip_address(entry)
                    network = ipaddress.ip_network(
                        f"{address}/{address.max_prefixlen}"
                    )
            except ValueError:
                try:
                    hostname = normalize_hostname(entry)
                except ValueError as exc:
                    raise ScopeValidationError(
                        "allowed_targets에 올바르지 않은 "
                        f"값이 있습니다: {entry}"
                    ) from exc
                hostnames.add(hostname)
            else:
                networks.append(network)

        return tuple(networks), frozenset(hostnames)

    @property
    def fingerprint(self) -> str:
        canonical = json.dumps(
            self._canonical_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _canonical_dict(self) -> dict[str, Any]:
        return {
            "scope_uid": self.scope_uid,
            "name": self.name,
            "authorization_ref": self.authorization_ref,
            "approved_by": self.approved_by,
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "allowed_targets": list(self.allowed_targets),
            "max_targets": self.max_targets,
            "max_workers": self.max_workers,
            "max_ports_per_target": (
                self.max_ports_per_target
            ),
        }

    def to_snapshot(self) -> dict[str, Any]:
        snapshot = self._canonical_dict()
        snapshot["policy_sha256"] = self.fingerprint
        return snapshot

    def validate_time(
        self,
        now: datetime | None = None,
    ) -> None:
        reference = now or datetime.now(timezone.utc)

        if reference.tzinfo is None:
            raise ScopeValidationError(
                "현재 시각에는 시간대 정보가 필요합니다."
            )

        reference = reference.astimezone(timezone.utc)

        if reference < self.valid_from:
            raise ScopeValidationError(
                "아직 유효하지 않은 스캔 허가입니다."
            )

        if reference > self.valid_until:
            raise ScopeValidationError(
                "만료된 스캔 허가입니다."
            )

    def authorize(
        self,
        targets: Iterable[ResolvedTarget],
        worker_count: int,
        port_count: int,
        now: datetime | None = None,
    ) -> None:
        self.validate_time(now)
        target_list = list(targets)

        if not target_list:
            raise ScopeValidationError(
                "승인할 스캔 대상이 없습니다."
            )

        if len(target_list) > self.max_targets:
            raise ScopeValidationError(
                f"대상 수 {len(target_list)}개가 승인 한도 "
                f"{self.max_targets}개를 초과합니다."
            )

        if not 1 <= worker_count <= self.max_workers:
            raise ScopeValidationError(
                f"작업자 수 {worker_count}개가 승인 한도 "
                f"{self.max_workers}개를 초과합니다."
            )

        if not 1 <= port_count <= self.max_ports_per_target:
            raise ScopeValidationError(
                f"대상별 포트 수 {port_count}개가 승인 한도 "
                f"{self.max_ports_per_target}개를 초과합니다."
            )

        networks, hostnames = self._compiled_allowlist()
        denied = []

        for target in target_list:
            address = ipaddress.ip_address(target.ip)
            input_hostname_allowed = (
                target.resolution_type == "HOSTNAME"
                and target.input_target in hostnames
            )
            address_allowed = any(
                address.version == network.version
                and address in network
                for network in networks
            )

            if not input_hostname_allowed and not address_allowed:
                denied.append(
                    f"{target.input_target} -> {target.ip}"
                )

        if denied:
            raise ScopeValidationError(
                "승인 범위를 벗어난 대상입니다: "
                + ", ".join(denied)
            )
