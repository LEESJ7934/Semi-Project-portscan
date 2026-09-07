"""External source contracts, mocked at requests; never calls the live Internet."""
import copy
import json
import os
import unittest
from unittest.mock import MagicMock, patch

import requests

from analysis.kev_catalog import fetch_kev_catalog, lookup_kev
from analysis.nvd_cvss import (INTEL_URLS, KEV_URL, KEV_MIRROR_URL, NVD_BASE_URL, cvss_result,
                               fetch_cvss, fetch_cvss_score, fetch_cvss_scores, request_json)
from api.shodan_epss_report import EPSS_BASE_URL, MAX_CVE_PARAMETER, fetch_epss_scores

CVE = "CVE-2021-42013"
OTHER = "CVE-2021-41773"


def response(data=None, status=200):
    result = MagicMock(status_code=status, headers={})
    result.json.return_value = data
    return result


def metric(version="4.0", score=9.3, source="nvd@nist.gov", kind="Primary"):
    return {"source": source, "type": kind, "cvssData": {"version": version, "baseScore": score,
            "baseSeverity": "CRITICAL", "vectorString": f"CVSS:{version}/AV:N/AC:L"}}


def nvd(metrics):
    return {"totalResults": 1, "vulnerabilities": [{"cve": {"id": CVE, "metrics": metrics}}]}


def epss_row(cve=CVE, score="0.123456789", percentile="0.987654321", date="2026-09-07"):
    return {"cve": cve, "epss": score, "percentile": percentile, "date": date}


def epss_payload(rows):
    return {"status": "OK", "status-code": 200, "total": len(rows), "offset": 0, "data": rows}


def kev_payload():
    return {"catalogVersion": "2026.09.07", "dateReleased": "2026-09-07T12:00:00.000Z", "count": 1,
            "vulnerabilities": [{"cveID": CVE, "dateAdded": "2021-10-07", "dueDate": "2021-11-01",
            "vendorProject": "Apache", "product": "HTTP Server", "requiredAction": "Apply vendor updates.",
            "knownRansomwareCampaignUse": "Unknown"}]}


class RiskSourceTests(unittest.TestCase):
    def setUp(self):
        self.get = patch("requests.get").start()
        self.sleep = patch("analysis.nvd_cvss.time.sleep").start()
        self.addCleanup(patch.stopall)

    def test_nvd_v4_precedes_v31_and_retains_provenance(self):
        self.get.return_value = response(nvd({"cvssMetricV31": [metric("3.1", 9.8)], "cvssMetricV40": [metric()]}))
        result = fetch_cvss(CVE)
        self.assertEqual((result["score"], result["version"], result["source"], result["metric_type"]),
                         (9.3, "4.0", "nvd@nist.gov", "Primary"))
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertTrue(result["vector"].startswith("CVSS:4.0"))

    def test_nvd_version_fallbacks_include_v2_severity(self):
        for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
            item = metric(version)
            if version == "2.0":
                item["baseSeverity"] = item["cvssData"].pop("baseSeverity")
                item["cvssData"]["vectorString"] = "AV:N/AC:L/Au:N/C:C/I:C/A:C"
            self.get.return_value = response(nvd({key: [item]}))
            with self.subTest(version=version):
                self.assertEqual(fetch_cvss(CVE)["version"], version)
                self.assertEqual(fetch_cvss(CVE)["severity"], "CRITICAL")

    def test_nvd_primary_metric_preference_and_valid_fallback(self):
        secondary = metric(source="cna@example.org", kind="Secondary", score=7.1)
        primary = metric(source="cna@example.org", score=8.2)
        for entries, expected_source, score in (([secondary, primary, metric()], "nvd@nist.gov", 9.3),
                                                ([secondary, primary], "cna@example.org", 8.2),
                                                ([secondary], "cna@example.org", 7.1),
                                                ([{"cvssData": {}}, secondary], "cna@example.org", 7.1)):
            self.get.return_value = response(nvd({"cvssMetricV40": entries}))
            result = fetch_cvss(CVE)
            self.assertEqual((result["source"], result["score"]), (expected_source, score))

    def test_nvd_no_cve_no_score_and_real_zero_are_distinct(self):
        for data, state, score in (({"totalResults": 0, "vulnerabilities": []}, "NOT_FOUND", None),
                                   (nvd({}), "NO_SCORE", None),
                                   (nvd({"cvssMetricV40": [metric(score=0)]}), "OK", 0.0)):
            self.get.return_value = response(data)
            result = fetch_cvss(CVE)
            self.assertEqual((result["state"], result["score"]), (state, score))
            self.assertIsNone(result["error_code"])

    def test_nvd_timeout_and_json_errors_never_become_zero(self):
        self.get.side_effect = requests.Timeout("a sensitive request description")
        self.assertEqual(fetch_cvss(CVE)["error_code"], "TIMEOUT")
        self.assertIsNone(fetch_cvss_score(CVE))
        self.get.side_effect = None
        self.get.return_value = response()
        self.get.return_value.json.side_effect = ValueError("invalid JSON")
        self.assertEqual(fetch_cvss(CVE)["error_code"], "JSON_PARSE_ERROR")

    def test_nvd_malformed_score_is_error_not_absence(self):
        for score in (None, True, -1, 11, "NaN", "Infinity", {}):
            self.get.return_value = response(nvd({"cvssMetricV40": [metric(score=score)]}))
            result = fetch_cvss(CVE)
            self.assertEqual(result["state"], "ERROR")
            self.assertIsNone(result["score"])
        self.get.return_value = response({})
        self.assertEqual(fetch_cvss(CVE)["state"], "ERROR")

    def test_nvd_api_key_sent_only_in_header_and_not_result(self):
        secret = "unit-test-only-key"
        self.get.return_value = response(nvd({"cvssMetricV40": [metric()]}))
        with patch.dict(os.environ, {"NVD_API_KEY": secret}):
            result = fetch_cvss(CVE)
        self.assertEqual(self.get.call_args.kwargs["headers"], {"apiKey": secret})
        self.assertNotIn(secret, json.dumps(result))
        self.assertNotIn("apiKey", self.get.call_args.kwargs["params"])

    def test_nvd_unique_cve_fetched_once_per_execution(self):
        def get(_url, **kwargs):
            data = nvd({})
            data["vulnerabilities"][0]["cve"]["id"] = kwargs["params"]["cveId"]
            return response(data)
        self.get.side_effect = get
        results = fetch_cvss_scores([CVE, OTHER, CVE])
        self.assertEqual(set(results), {CVE, OTHER})
        self.assertEqual(self.get.call_count, 2)

    def test_http_retries_are_bounded_and_redirects_are_not_followed(self):
        for status in (429, 500, 502, 503, 504):
            self.get.reset_mock()
            self.get.return_value = response(status=status)
            self.get.return_value.headers = {"Retry-After": "99999"}
            result = fetch_cvss(CVE, timeout=2)
            self.assertEqual(result["error_code"], f"HTTP_{status}")
            self.assertEqual(self.get.call_count, 3)
            self.assertEqual(self.get.call_args.kwargs["timeout"], 2)
            self.assertFalse(self.get.call_args.kwargs["allow_redirects"])
        self.assertTrue(all(call.args[0] <= 2 for call in self.sleep.call_args_list))
        self.get.reset_mock()
        self.get.return_value = response(status=302)
        self.assertEqual(fetch_cvss(CVE)["error_code"], "HTTP_302")
        self.get.assert_called_once()

    def test_retry_then_success_and_no_retry_for_403(self):
        self.get.side_effect = [response(status=503), response(nvd({}))]
        self.assertEqual(fetch_cvss(CVE)["state"], "NO_SCORE")
        self.assertEqual(self.get.call_count, 2)
        self.get.reset_mock()
        self.get.side_effect = None
        self.get.return_value = response(status=403)
        self.assertEqual(fetch_cvss(CVE)["error_code"], "HTTP_403")
        self.get.assert_called_once()

    def test_invalid_cve_timeout_and_arbitrary_urls_do_not_request(self):
        for value in (None, "NONE", "http://127.0.0.1", "CVE-2021-42013&other=value"):
            self.assertEqual(fetch_cvss(value)["error_code"], "INVALID_CVE")
        for timeout in (0, -1, 31, float("nan"), float("inf"), True):
            with self.assertRaises(ValueError):
                fetch_cvss(CVE, timeout=timeout)
        with self.assertRaises(ValueError):
            request_json("http://127.0.0.1")
        self.get.assert_not_called()

    def test_epss_score_percentile_date_and_legacy_alias(self):
        self.get.return_value = response(epss_payload([epss_row()]))
        result = fetch_epss_scores([CVE])[CVE]
        self.assertEqual(result["state"], "OK")
        self.assertEqual(result["score"], 0.123456789)
        self.assertEqual(result["epss"], result["score"])
        self.assertEqual(result["percentile"], 0.987654321)
        self.assertEqual(result["date"], "2026-09-07")

    def test_epss_batch_dedup_character_and_record_limits(self):
        cves = [f"CVE-2026-{i:019d}" for i in range(250)]
        def get(url, **kwargs):
            self.assertEqual(url, EPSS_BASE_URL)
            param = kwargs["params"]["cve"]
            ids = param.split(",")
            self.assertLessEqual(len(param), MAX_CVE_PARAMETER)
            self.assertLessEqual(len(ids), 100)
            self.assertEqual(kwargs["params"]["limit"], len(ids))
            return response(epss_payload([epss_row(cve=cve) for cve in ids]))
        self.get.side_effect = get
        result = fetch_epss_scores(cves + cves)
        requested = [cve for call in self.get.call_args_list for cve in call.kwargs["params"]["cve"].split(",")]
        self.assertEqual(sorted(requested), sorted(cves))
        self.assertEqual(set(result), set(cves))
        self.assertGreater(self.get.call_count, 1)

    def test_epss_absence_zero_and_connection_error_are_distinct(self):
        self.get.return_value = response(epss_payload([epss_row(score="0", percentile="0")]))
        result = fetch_epss_scores([CVE, OTHER])
        self.assertEqual((result[CVE]["score"], result[CVE]["state"]), (0, "OK"))
        self.assertEqual(result[OTHER]["state"], "NOT_FOUND")
        self.assertIsNone(result[OTHER]["score"])
        self.get.side_effect = requests.ConnectionError("network")
        result = fetch_epss_scores([CVE])[CVE]
        self.assertEqual(result["error_code"], "CONNECTION_ERROR")
        self.assertIsNone(result["score"])
        self.assertIsNone(result["percentile"])

    def test_epss_malformed_rows_do_not_invent_zero_or_discard_other_valid_rows(self):
        for field, value in (("epss", "NaN"), ("epss", None), ("percentile", "1.1"),
                              ("date", "2026-02-30"), ("date", None)):
            bad = {**epss_row(), field: value}
            self.get.return_value = response(epss_payload([bad, epss_row(OTHER)]))
            result = fetch_epss_scores([CVE, OTHER])
            self.assertEqual(result[CVE]["state"], "ERROR")
            self.assertIsNone(result[CVE]["score"])
            self.assertEqual(result[OTHER]["state"], "OK")

    def test_epss_incomplete_or_invalid_envelope_is_error_not_missing(self):
        for data in ({}, {**epss_payload([]), "status": "ERROR"},
                     {**epss_payload([epss_row()]), "total": 2},
                     epss_payload([epss_row(), epss_row()]), {**epss_payload([]), "offset": 1}):
            self.get.return_value = response(data)
            self.assertEqual(fetch_epss_scores([CVE])[CVE]["state"], "ERROR")

    def test_empty_epss_selection_never_requests(self):
        self.assertEqual(fetch_epss_scores([]), {})
        self.get.assert_not_called()

    def test_kev_known_and_not_listed_from_one_valid_catalog(self):
        self.get.return_value = response(kev_payload())
        catalog = fetch_kev_catalog()
        known, absent = lookup_kev(catalog, CVE), lookup_kev(catalog, OTHER)
        self.assertEqual(known["status"], "KNOWN_EXPLOITED")
        self.assertEqual(absent["status"], "NOT_LISTED")
        self.assertEqual(known["source"], KEV_URL)
        self.assertEqual(known["catalog_version"], "2026.09.07")
        self.assertEqual(known["due_date"], "2021-11-01")
        self.assertEqual(known["known_ransomware_campaign_use"], "Unknown")
        self.assertEqual(known["required_action"], "Apply vendor updates.")
        self.get.assert_called_once()

    def test_kev_canonical_failure_uses_only_official_mirror(self):
        self.get.side_effect = [response(status=403), response(kev_payload())]
        catalog = fetch_kev_catalog()
        result = lookup_kev(catalog, CVE)
        self.assertEqual(result["status"], "KNOWN_EXPLOITED")
        self.assertEqual(result["source"], KEV_MIRROR_URL)
        self.assertEqual(result["errors"], [{"source": KEV_URL, "error_code": "HTTP_403"}])
        self.assertEqual([call.args[0] for call in self.get.call_args_list], [KEV_URL, KEV_MIRROR_URL])

    def test_kev_both_fail_is_unknown_for_every_cve(self):
        self.get.side_effect = requests.Timeout("offline")
        catalog = fetch_kev_catalog()
        for cve in (CVE, OTHER):
            result = lookup_kev(catalog, cve)
            self.assertEqual((result["status"], result["state"]), ("UNKNOWN", "ERROR"))
            self.assertIsNone(result["date_added"])
        self.assertEqual(self.get.call_count, 2)

    def test_malformed_kev_catalog_cannot_assert_not_listed(self):
        invalid = kev_payload()
        invalid["count"] = 2
        for bad in ({}, invalid, {**kev_payload(), "vulnerabilities": []}):
            self.get.return_value = response(bad)
            result = lookup_kev(fetch_kev_catalog(), OTHER)
            self.assertEqual(result["status"], "UNKNOWN")
            self.assertEqual(result["error_code"], "KEV_UNAVAILABLE")

    def test_kev_json_failure_can_fallback(self):
        broken = response()
        broken.json.side_effect = ValueError("not JSON")
        self.get.side_effect = [broken, response(kev_payload())]
        self.assertEqual(lookup_kev(fetch_kev_catalog(), OTHER)["status"], "NOT_LISTED")

    def test_all_http_reads_are_fixed_sources_with_no_payload_or_redirects(self):
        self.get.return_value = response(status=403)
        fetch_cvss(CVE)
        fetch_epss_scores([CVE])
        fetch_kev_catalog()
        for call in self.get.call_args_list:
            self.assertIn(call.args[0], INTEL_URLS)
            self.assertNotIn("data", call.kwargs)
            self.assertNotIn("json", call.kwargs)
            self.assertFalse(call.kwargs["allow_redirects"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
