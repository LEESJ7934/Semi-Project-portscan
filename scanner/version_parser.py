"""Compatibility wrapper for callers that only need the advertised version."""
from .fingerprints import identify_service


def parse_version(service: str, banner: str | None) -> str | None:
    return identify_service(banner, service)["version"]
