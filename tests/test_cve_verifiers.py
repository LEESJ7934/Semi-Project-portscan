import json
import socket
import unittest
from unittest.mock import MagicMock, patch

from scanner.banner_grabber import BannerObservation
from verification.base_checker import RESULT_STATUSES
from verification.checker_ftp import FTPChecker
from verification.cve_verifiers import (Apache41773Verifier, Apache42013Verifier,
                                        Nginx23017Verifier, OpenSSH25136Verifier,
                                        UnsupportedCVEVerifier, get_verifier)
from verification.nuclei_runner import CVE_TEMPLATE_MAP, NucleiRunner


PORT = {"host_ip": "127.0.0.1", "port": 8081, "protocol": "tcp", "service": "http",
        "product": "apache_http_server", "version": "2.4.50"}


def response(server="Apache/2.4.50", status=200):
    return BannerObservation(f"HTTP/1.1 {status} Response\r\nServer: {server}\r\n\r\n".encode())


class CVEVerifierTests(unittest.TestCase):
    def verify(self, cve="CVE-2021-42013", observation=None, port=None):
        with patch("verification.cve_verifiers.collect_banner", return_value=observation or response()) as probe:
            result = get_verifier(cve).run_check(port or PORT, {"cve_id": cve})
        self.assertIn(result["status"], RESULT_STATUSES)
        return result, probe

    def test_registry_selects_by_cve_id(self):
        for cve, cls in (("CVE-2021-41773", Apache41773Verifier), ("CVE-2021-42013", Apache42013Verifier),
                         ("CVE-2023-25136", OpenSSH25136Verifier), ("CVE-2021-23017", Nginx23017Verifier)):
            self.assertIsInstance(get_verifier(cve.lower()), cls)

    def test_unknown_cve_does_not_fall_back_to_generic_http(self):
        result, probe = self.verify("CVE-2099-12345")
        self.assertIsInstance(get_verifier("CVE-2099-12345"), UnsupportedCVEVerifier)
        self.assertEqual((result["status"], result["error_code"]), ("ERROR", "UNSUPPORTED_CVE"))
        probe.assert_not_called()

    def test_all_catalog_matches_remain_potential(self):
        cases = (("CVE-2021-41773", response("Apache/2.4.49")),
                 ("CVE-2021-42013", response()),
                 ("CVE-2021-23017", response("nginx/1.20.0")),
                 ("CVE-2023-25136", BannerObservation(b"SSH-2.0-OpenSSH_9.1p1\r\n")))
        for cve, observation in cases:
            with self.subTest(cve=cve):
                result, _ = self.verify(cve, observation)
                self.assertEqual(result["status"], "POTENTIAL")
                self.assertEqual(result["details"]["condition"], "advertised_version_in_affected_range")
                self.assertTrue(result["additional_checks"])
                self.assertTrue(result["details"]["references"])

    def test_http_200_without_product_is_not_confirmation(self):
        result, _ = self.verify(observation=response("hidden"))
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertEqual(result["details"]["condition"], "product_unidentified")

    def test_http_denial_redirect_or_server_error_is_not_a_negative_verdict(self):
        for status in (302, 401, 403, 404, 500):
            result, probe = self.verify(observation=response(status=status))
            self.assertEqual(result["status"], "POTENTIAL")
            self.assertEqual(result["details"]["http_status"], status)
            probe.assert_called_once()

    def test_banner_change_requires_package_review(self):
        for server, condition in (("nginx/1.24.0", "product_mismatch_needs_review"),
                                  ("Apache/2.4.51", "advertised_version_outside_range_needs_review"),
                                  ("Apache", "version_unavailable_or_unsupported")):
            result, _ = self.verify(observation=response(server))
            self.assertEqual(result["status"], "POTENTIAL")
            self.assertEqual(result["details"]["condition"], condition)

    def test_udp_endpoint_is_explicitly_not_applicable_without_tcp_probe(self):
        result, probe = self.verify(port={**PORT, "protocol": "udp"})
        self.assertEqual(result["status"], "NOT_APPLICABLE")
        probe.assert_not_called()

    def test_unknown_transport_is_an_error(self):
        result, probe = self.verify(port={**PORT, "protocol": "invalid"})
        self.assertEqual(result["error_code"], "INVALID_TARGET")
        probe.assert_not_called()

    def test_connection_failure_timeout_and_empty_response_are_errors(self):
        for error, expected in (("ConnectionRefusedError", "CONNECTION_ERROR"),
                                ("TimeoutError", "TIMEOUT"), ("no_response", "NO_RESPONSE"),
                                ("SSLError", "TLS_ERROR")):
            result, _ = self.verify(observation=BannerObservation(error=error))
            self.assertEqual((result["status"], result["error_code"]), ("ERROR", expected))

    def test_raised_network_exceptions_are_errors(self):
        for error, expected in ((TimeoutError(), "TIMEOUT"), (ConnectionError(), "CONNECTION_ERROR")):
            with patch("verification.cve_verifiers.collect_banner", side_effect=error):
                result = get_verifier("CVE-2021-42013").run_check(PORT, {"cve_id": "CVE-2021-42013"})
            self.assertEqual((result["status"], result["error_code"]), ("ERROR", expected))

    def test_empty_or_malformed_and_truncated_responses_are_not_safe(self):
        for data, code in ((b"", "NO_RESPONSE"), (b"garbage\n", "PARSING_ERROR"),
                            (b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.50", "PARSING_ERROR")):
            result, _ = self.verify(observation=BannerObservation(data))
            self.assertEqual((result["status"], result["error_code"]), ("ERROR", code))

    def test_http_probe_uses_only_head_on_root(self):
        sock = MagicMock()
        sock.recv.return_value = response().data
        with patch("scanner.banner_grabber.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value = sock
            result = get_verifier("CVE-2021-42013").run_check(PORT, {"cve_id": "CVE-2021-42013"})
        request = sock.sendall.call_args.args[0]
        self.assertTrue(request.startswith(b"HEAD / HTTP/1.1\r\n"))
        self.assertEqual(request.split(b"\r\n\r\n", 1)[1], b"")
        self.assertEqual(sock.sendall.call_count, 1)
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertEqual(connect.call_args.args[0], ("127.0.0.1", 8081))

    def test_ssh_probe_never_sends_a_payload(self):
        sock = MagicMock()
        sock.recv.return_value = b"SSH-2.0-OpenSSH_9.1p1\r\n"
        with patch("scanner.banner_grabber.socket.create_connection") as connect:
            connect.return_value.__enter__.return_value = sock
            result = get_verifier("CVE-2023-25136").run_check(PORT, {"cve_id": "CVE-2023-25136"})
        sock.sendall.assert_not_called()
        self.assertEqual(result["status"], "POTENTIAL")

    def test_legacy_ftp_never_authenticates_uploads_lists_or_deletes(self):
        with patch("verification.checker_ftp.FTP") as factory:
            ftp = factory.return_value
            ftp.getwelcome.return_value = "220 FTP ready"
            result = FTPChecker().run_check({**PORT, "port": 21}, {"title": "anonymous writable login"})
        self.assertEqual(result["status"], "POTENTIAL")
        self.assertEqual([call[0] for call in ftp.method_calls], ["connect", "getwelcome", "close"])

    def test_ftp_timeout_is_error_and_connection_is_closed(self):
        with patch("verification.checker_ftp.FTP") as factory:
            factory.return_value.connect.side_effect = socket.timeout()
            result = FTPChecker().run_check(PORT, {})
            factory.return_value.close.assert_called_once()
        self.assertEqual((result["status"], result["error_code"]), ("ERROR", "TIMEOUT"))

    def test_retired_nuclei_mappings_cannot_start_processes(self):
        self.assertEqual(CVE_TEMPLATE_MAP, {})
        with patch("subprocess.run") as process, patch("socket.create_connection") as network:
            for cve in ("CVE-2012-1823", "CVE-2020-2551", "CVE-2021-42013"):
                result = NucleiRunner().run_check(PORT, {"cve_id": cve})
                self.assertEqual(result["error_code"], "UNSUPPORTED_VERIFIER")
                json.dumps(result)
        process.assert_not_called()
        network.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
