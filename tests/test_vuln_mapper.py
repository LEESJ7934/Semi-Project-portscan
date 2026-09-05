import json
import os
import tempfile
import unittest
from pathlib import Path

from analysis.vuln_mapper import DEFAULT_RULES, analyze_ports, load_catalog, map_vulns, normalized_version


def http_port(token, **overrides):
    return {"port_id": 7, "scan_id": 5, "protocol": "tcp", "state": "open",
            "service": "http", "banner": f"HTTP/1.1 200 OK\r\nServer: {token}\r\n\r\n", **overrides}


class VulnMapperTests(unittest.TestCase):
    def cves(self, record):
        return {item["cve_id"] for item in map_vulns([record])}

    def test_apache_release_boundaries(self):
        expected = {"2.4.48": set(), "2.4.49": {"CVE-2021-41773", "CVE-2021-42013"},
                    "2.4.50": {"CVE-2021-42013"}, "2.4.51": set(), "2.4.100": set()}
        for version, cves in expected.items():
            with self.subTest(version=version):
                self.assertEqual(self.cves(http_port("Apache/" + version)), cves)

    def test_openssh_89_regression_and_91_boundary(self):
        for version in ("8.9p1", "9.0p1", "9.1", "9.1p1", "9.2p1", "9.10p1"):
            record = http_port("ignored", service="ssh", banner="SSH-2.0-OpenSSH_" + version + "\r\n")
            self.assertEqual(bool(self.cves(record)), version in {"9.1", "9.1p1"})

    def test_nginx_lower_and_fixed_boundaries(self):
        for version, matched in (("0.6.17", False), ("0.6.18", True), ("1.20.0", True),
                                 ("1.20.1", False), ("1.21.0", False)):
            self.assertEqual(bool(self.cves(http_port("nginx/" + version))), matched)

    def test_same_version_from_wrong_product_does_not_match(self):
        self.assertFalse(self.cves(http_port("nginx/2.4.50")))
        self.assertFalse(self.cves(http_port("Microsoft-IIS/2.4.50")))

    def test_generic_http_or_dvwa_does_not_create_unrelated_cves(self):
        record = http_port("hidden", version="2.4.50", product="apache_http_server")
        record["banner"] += "DVWA SQL injection and file upload Server: Apache/2.4.50"
        self.assertFalse(self.cves(record))

    def test_closed_or_udp_record_is_excluded(self):
        self.assertFalse(self.cves(http_port("Apache/2.4.50", state="closed")))
        self.assertFalse(self.cves(http_port("Apache/2.4.50", protocol="udp")))

    def test_prerelease_unknown_or_partial_versions_are_not_truncated(self):
        for version in ("2.4", "2.4.50rc1", "2.4.50-dev", "2.4.50.1", "unknown"):
            self.assertFalse(self.cves(http_port("Apache/" + version)))

    def test_distribution_suffix_remains_candidate_with_backport_warning(self):
        candidate = map_vulns([http_port("Apache/2.4.50-ubuntu1")])[0]
        self.assertEqual(candidate["status"], "CANDIDATE")
        self.assertTrue(any("backport" in condition for condition in candidate["conditions_to_verify"]))

    def test_candidates_preserve_reason_sources_and_null_scores(self):
        candidate = map_vulns([http_port("Apache/2.4.50")])[0]
        self.assertEqual(candidate["port_id"], 7)
        self.assertEqual(candidate["scan_id"], 5)
        self.assertEqual(candidate["status"], "CANDIDATE")
        self.assertIn("2.4.51", candidate["match_reason"])
        self.assertEqual(len(candidate["catalog_sha256"]), 64)
        self.assertTrue(candidate["references"])
        self.assertTrue(all(candidate[key] is None for key in ("epss", "cvss", "risk")))

    def test_port_id_and_legacy_id_alias_both_work(self):
        record = http_port("Apache/2.4.50")
        record["id"] = record.pop("port_id")
        self.assertEqual(map_vulns([record])[0]["port_id"], 7)

    def test_https_can_match_http_product_catalog(self):
        self.assertEqual(self.cves(http_port("Apache/2.4.50", service="https")), {"CVE-2021-42013"})

    def test_not_identified_and_not_in_catalog_are_explained(self):
        report = analyze_ports([http_port("hidden"), http_port("Apache"), http_port("Microsoft-IIS/10.0")])
        self.assertEqual([item["reason"] for item in report["observations"]],
                         ["product_not_identified", "version_not_identified", "product_not_in_catalog"])
        self.assertIn("No match does not mean secure", report["limitation"])

    def test_catalog_path_is_independent_of_working_directory(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as directory:
            try:
                os.chdir(directory)
                self.assertTrue(self.cves(http_port("Apache/2.4.50")))
            finally:
                os.chdir(previous)

    def test_legacy_and_invalid_catalogs_fail_instead_of_guessing(self):
        catalog, _ = load_catalog()
        bad = json.loads(json.dumps(catalog))
        bad["rules"][0]["affected"]["fixed"] = "2.4.48"
        duplicate = json.loads(json.dumps(catalog))
        duplicate["rules"].append(duplicate["rules"][0])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rules.json"
            for value in ([{"version_regex": ".*"}], bad, duplicate):
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    load_catalog(path)

    def test_version_comparison_is_numeric(self):
        self.assertGreater(normalized_version("openssh", "9.10p1"), normalized_version("openssh", "9.2p1"))
        self.assertGreater(normalized_version("nginx", "1.20.0"), normalized_version("nginx", "1.9.9"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
