from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Iterable

from .banner_grabber import collect_banner
from .fingerprints import identify_service
from .service_fingerprints import guess_service
from .utils import parse_ports, tcp_connect


@dataclass
class PortScanResult:
    port: int
    protocol: str
    state: str
    banner: str | None = None
    service: str | None = None
    version: str | None = None
    product: str | None = None
    fingerprint: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def scan_single_port(host: str, port: int, timeout: float = 1.0,
                     detect_versions: bool = False,
                     server_name: str | None = None) -> PortScanResult:
    hint = guess_service(port)
    sock = tcp_connect(host, port, timeout=timeout)
    if sock is None:
        return PortScanResult(port, "tcp", "closed", service=hint)
    sock.close()
    fingerprint = identify_service(None, hint)
    banner = None
    if detect_versions:
        observation = collect_banner(host, port, hint, timeout, server_name)
        fingerprint = identify_service(observation.data, hint)
        fingerprint.update(probe_error=observation.error, tls=observation.tls)
        if observation.data:
            banner = observation.data.decode("latin1")
    else:
        fingerprint["probe_error"] = "not_requested"
    return PortScanResult(port, "tcp", "open", banner=banner,
                          service=fingerprint["service"], version=fingerprint["version"],
                          product=fingerprint["product"], fingerprint=fingerprint)


def sequential_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0,
                    detect_versions: bool = False, server_name: str | None = None) -> list[dict]:
    return [scan_single_port(host, port, timeout, detect_versions, server_name).to_dict()
            for port in parse_ports(ports)]


def threaded_scan(host: str, ports: Iterable[int] | str, timeout: float = 1.0,
                  max_workers: int = 100, detect_versions: bool = False,
                  server_name: str | None = None) -> list[dict]:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(scan_single_port, host, port, timeout,
                                   detect_versions, server_name) for port in parse_ports(ports)]
        results = [future.result().to_dict() for future in as_completed(futures)]
    return sorted(results, key=lambda result: result["port"])
