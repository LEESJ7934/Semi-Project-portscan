from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence


HARD_MAX_TARGETS = 4096
HOST_LABEL_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)


@dataclass(frozen=True)
class ResolvedTarget:
    ip: str
    input_target: str
    resolution_type: str


def normalize_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".")

    if not candidate:
        raise ValueError("호스트 이름이 비어 있습니다.")

    try:
        ascii_name = candidate.encode("idna").decode(
            "ascii"
        )
    except UnicodeError as exc:
        raise ValueError(
            f"올바르지 않은 호스트 이름입니다: {value}"
        ) from exc

    ascii_name = ascii_name.lower()

    if len(ascii_name) > 253:
        raise ValueError(
            "호스트 이름은 253자를 초과할 수 없습니다."
        )

    labels = ascii_name.split(".")

    if any(
        not HOST_LABEL_PATTERN.fullmatch(label)
        for label in labels
    ):
        raise ValueError(
            f"올바르지 않은 호스트 이름입니다: {value}"
        )

    return ascii_name


def _validate_scannable_address(
    address: ipaddress.IPv4Address
    | ipaddress.IPv6Address,
) -> None:
    if (
        address.is_unspecified
        or address.is_multicast
        or (
            address.is_reserved
            and not address.is_loopback
        )
    ):
        raise ValueError(
            f"스캔 대상으로 사용할 수 없는 IP입니다: "
            f"{address}"
        )


def _expand_network(
    candidate: str,
    remaining: int,
) -> list[ResolvedTarget]:
    try:
        network = ipaddress.ip_network(
            candidate,
            strict=False,
        )
    except ValueError as exc:
        raise ValueError(
            f"올바르지 않은 CIDR입니다: {candidate}"
        ) from exc

    if network.num_addresses > remaining + 2:
        raise ValueError(
            f"CIDR 대상 수가 허용 한도 {remaining}개를 "
            f"초과합니다: {candidate}"
        )

    addresses = list(network.hosts())

    if len(addresses) > remaining:
        raise ValueError(
            f"CIDR 대상 수가 허용 한도 {remaining}개를 "
            f"초과합니다: {candidate}"
        )

    results = []

    for address in addresses:
        _validate_scannable_address(address)
        results.append(
            ResolvedTarget(
                ip=str(address),
                input_target=str(network),
                resolution_type="CIDR",
            )
        )

    return results


def _resolve_hostname(
    candidate: str,
    resolver: Callable[..., Sequence[tuple]],
) -> list[ResolvedTarget]:
    hostname = normalize_hostname(candidate)

    try:
        records = resolver(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(
            f"호스트 이름을 확인할 수 없습니다: {candidate}"
        ) from exc

    addresses = set()

    for record in records:
        sockaddr = record[4]
        address = ipaddress.ip_address(sockaddr[0])
        _validate_scannable_address(address)
        addresses.add(address)

    if not addresses:
        raise ValueError(
            f"호스트 이름의 IP 결과가 없습니다: {candidate}"
        )

    ordered = sorted(
        addresses,
        key=lambda address: (
            address.version,
            int(address),
        ),
    )

    return [
        ResolvedTarget(
            ip=str(address),
            input_target=hostname,
            resolution_type="HOSTNAME",
        )
        for address in ordered
    ]


def resolve_target_specs(
    target_specs: Iterable[str],
    max_targets: int = 256,
    resolver: Callable[..., Sequence[tuple]] = (
        socket.getaddrinfo
    ),
) -> list[ResolvedTarget]:
    """Expand IP, CIDR and hostnames into unique IP targets."""

    if not 1 <= max_targets <= HARD_MAX_TARGETS:
        raise ValueError(
            f"max_targets는 1~{HARD_MAX_TARGETS} 범위여야 "
            "합니다."
        )

    resolved: list[ResolvedTarget] = []
    seen_ips: set[str] = set()

    for raw_spec in target_specs:
        if not isinstance(raw_spec, str):
            raise ValueError(
                "스캔 대상은 문자열이어야 합니다."
            )

        candidate = raw_spec.strip()

        if not candidate:
            raise ValueError("빈 스캔 대상은 허용되지 않습니다.")

        remaining = max_targets - len(seen_ips)

        if remaining <= 0:
            raise ValueError(
                f"전체 대상 수가 허용 한도 {max_targets}개를 "
                "초과합니다."
            )

        if "/" in candidate:
            candidates = _expand_network(
                candidate,
                remaining,
            )
        else:
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                candidates = _resolve_hostname(
                    candidate,
                    resolver,
                )
            else:
                _validate_scannable_address(address)
                candidates = [
                    ResolvedTarget(
                        ip=str(address),
                        input_target=str(address),
                        resolution_type="IP",
                    )
                ]

        for target in candidates:
            if target.ip in seen_ips:
                continue

            if len(seen_ips) >= max_targets:
                raise ValueError(
                    f"전체 대상 수가 허용 한도 "
                    f"{max_targets}개를 초과합니다."
                )

            seen_ips.add(target.ip)
            resolved.append(target)

    if not resolved:
        raise ValueError("스캔 대상이 하나도 없습니다.")

    return resolved
