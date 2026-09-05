"""Use the same product parser during scanning and offline analysis."""
from scanner.fingerprints import identify_service


def parse_banner(banner: str, service: str):
    fingerprint = identify_service(banner, service)
    return fingerprint["product"], fingerprint["version"]
