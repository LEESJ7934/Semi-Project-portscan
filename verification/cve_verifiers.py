"""CVE-specific, read-only verification for the unchanged Day 4 catalog."""
from __future__ import annotations

import re

from analysis.vuln_mapper import load_catalog, normalized_version
from scanner.banner_grabber import collect_banner
from scanner.fingerprints import identify_service
from .base_checker import BaseChecker, check_result


VERIFIER_VERSION = "day5.1"


class CVEVerifier(BaseChecker):
    cve_id = ""
    expected_product = ""
    expected_service = "http"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def run_check(self, port_record: dict, vuln_candidate: dict) -> dict:
        checker = type(self).__name__
        candidate_cve = str(vuln_candidate.get("cve_id") or vuln_candidate.get("cve") or "").upper()
        details = {"verifier_version": VERIFIER_VERSION, "cve_id": self.cve_id,
                   "safe_checks": [], "expected_product": self.expected_product}

        def error(code, reason):
            return check_result("ERROR", reason, checker=checker, evidence_type="ERROR_LOG",
                                details=details, error_code=code)

        if candidate_cve != self.cve_id:
            return error("CVE_MISMATCH", "The candidate CVE does not match this verifier.")
        protocol = str(port_record.get("protocol", "")).lower()
        if protocol == "udp":
            return check_result(
                "NOT_APPLICABLE", "This CVE concerns a TCP service; the selected record is a UDP endpoint.",
                checker=checker, details={**details, "condition": "transport_not_applicable"},
            )
        if protocol != "tcp":
            return error("INVALID_TARGET", "A valid endpoint transport is required.")
        try:
            catalog, catalog_hash = load_catalog()
            rule = next(rule for rule in catalog["rules"] if rule["cve"] == self.cve_id)
        except (OSError, ValueError, KeyError, StopIteration):
            return error("CATALOG_ERROR", "The reviewed CVE rule could not be loaded.")
        details.update(catalog_sha256=catalog_hash, affected=rule["affected"], references=rule["references"])
        service = self.expected_service
        if service == "http" and port_record.get("service") == "https":
            service = "https"
        details["safe_checks"] = (["tcp_connect", "ssh_greeting_only"] if service == "ssh"
                                  else ["tcp_connect", "http_head_root_no_redirects"])
        # Reuse Day 4's bounded transport and TLS support; connect only to the scoped numeric IP.
        try:
            observation = collect_banner(port_record["host_ip"], port_record["port"], service,
                                         timeout=self.timeout, server_name=port_record.get("server_name"))
        except TimeoutError:
            return error("TIMEOUT", "The read-only probe timed out; vulnerability conditions were not evaluated.")
        except OSError:
            return error("CONNECTION_ERROR", "The endpoint could not be reached; this is not a negative CVE verdict.")
        except (ValueError, KeyError, TypeError):
            return error("INVALID_TARGET", "The endpoint or probe arguments are invalid.")
        details["tls"] = observation.tls
        if observation.error:
            details["probe_error"] = observation.error
            code = {"TimeoutError": "TIMEOUT", "timeout": "TIMEOUT",
                    "no_response": "NO_RESPONSE", "SSLError": "TLS_ERROR",
                    "SSLCertVerificationError": "TLS_ERROR", "ValueError": "INVALID_TARGET"}.get(
                        observation.error, "CONNECTION_ERROR")
            return error(code, "The read-only probe failed; no non-vulnerable conclusion can be drawn.")
        if not observation.data:
            return error("NO_RESPONSE", "The endpoint returned no usable response.")
        fingerprint = identify_service(observation.data, service)
        if fingerprint["source"] in {"port_hint", "http_incomplete_headers"}:
            return error("PARSING_ERROR", "The response is malformed, truncated or not a supported greeting.")
        details["observed_fingerprint"] = fingerprint
        # Keep stable, relevant evidence: do not hash Date headers, cookies or response bodies.
        if observation.data.startswith(b"HTTP/"):
            status = re.match(rb"HTTP/1\.[01] ([0-9]{3})", observation.data)
            if status:
                details["http_status"] = int(status[1])
        version = normalized_version(self.expected_product, fingerprint["version"])
        if fingerprint["product"] != self.expected_product:
            condition = "product_unidentified" if not fingerprint["product"] else "product_mismatch_needs_review"
        elif version is None:
            condition = "version_unavailable_or_unsupported"
        elif (normalized_version(self.expected_product, rule["affected"]["introduced"]) <= version
              < normalized_version(self.expected_product, rule["affected"]["fixed"])):
            condition = "advertised_version_in_affected_range"
        else:
            condition = "advertised_version_outside_range_needs_review"
        details["condition"] = condition
        return check_result(
            "POTENTIAL", "Read-only observation completed; installed package, patches and CVE-specific conditions need verification.",
            checker=checker, evidence_type="BANNER" if self.expected_service == "ssh" else "HTTP_RESPONSE",
            details=details, additional_checks=list(rule["conditions"]),
        )


class Apache41773Verifier(CVEVerifier):
    cve_id = "CVE-2021-41773"
    expected_product = "apache_http_server"


class Apache42013Verifier(CVEVerifier):
    cve_id = "CVE-2021-42013"
    expected_product = "apache_http_server"


class OpenSSH25136Verifier(CVEVerifier):
    cve_id = "CVE-2023-25136"
    expected_product = "openssh"
    expected_service = "ssh"


class Nginx23017Verifier(CVEVerifier):
    cve_id = "CVE-2021-23017"
    expected_product = "nginx"


class UnsupportedCVEVerifier(BaseChecker):
    def __init__(self, cve_id: str):
        self.cve_id = cve_id

    def run_check(self, port_record, vuln_candidate):
        return check_result(
            "ERROR", "No CVE-specific verifier is registered; no network probe was attempted.",
            checker=type(self).__name__, evidence_type="ERROR_LOG", error_code="UNSUPPORTED_CVE",
            details={"verifier_version": VERIFIER_VERSION, "cve_id": self.cve_id, "safe_checks": []},
            additional_checks=["Review the official advisory and add a reviewed CVE-specific verifier."],
        )


VERIFIER_REGISTRY = {
    "CVE-2021-41773": Apache41773Verifier,
    "CVE-2021-42013": Apache42013Verifier,
    "CVE-2023-25136": OpenSSH25136Verifier,
    "CVE-2021-23017": Nginx23017Verifier,
}


def get_verifier(cve_id: str, timeout: float = 5.0) -> BaseChecker:
    normalized = str(cve_id or "").strip().upper()
    verifier = VERIFIER_REGISTRY.get(normalized)
    return verifier(timeout=timeout) if verifier else UnsupportedCVEVerifier(normalized)
