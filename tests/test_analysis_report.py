"""Read-only report data tests against a V5 DB-API fixture; no MySQL or external I/O."""
import contextlib
import copy
import json
import unittest
from datetime import datetime
from decimal import Decimal
from unittest.mock import patch

from api.analysis_report import (ReportDatabaseError, ReportSelectionError, build_report_snapshot,
                                  snapshot_sha256, validate_selection)

ASSET = "9cd48a9c-bc17-4bbb-81ce-419f2bef8306"
OTHER_ASSET = "0561e307-a8b3-11f1-bb09-9a1fea705640"
CVE = "CVE-2021-42013"
NOW = datetime(2026, 9, 9, 10, 0, 0)


def fixture_data():
    host = {"id": 1, "asset_uid": ASSET, "host_ip": "127.0.0.1", "host_name": "localhost",
            "asset_name": "로컬 실습 서버", "asset_type": "SERVER", "environment": "TEST", "criticality": "LOW",
            "owner": "보안 담당자", "business_unit": "실습팀", "data_classification": "INTERNAL",
            "handles_personal_data": 0, "internet_exposed": 0, "lifecycle_status": "ACTIVE",
            "first_seen": NOW, "last_seen": NOW, "last_scan_id": 4}
    port = {"port_id": 11, "host_id": 1, "port": 18080, "protocol": "tcp", "service": "http",
            "product": "apache_http_server", "version": "2.4.50", "state": "open", "last_scan_id": 4,
            "fingerprint": json.dumps({"product": "apache_http_server", "version": "2.4.50", "source": "http_server_header"})}
    finding = {"vuln_id": 101, "port_id": 11, "cve_id": CVE, "title": "Apache candidate / 확인 필요",
               "source": "day4:apache:cve-2021-42013", "status": "POTENTIAL", "severity": "CRITICAL",
               "first_detected_at": NOW, "last_detected_at": NOW, "verified_at": NOW, "closed_at": None,
               "risk": Decimal("0.969"), "cvss": Decimal("1.0"), "epss": Decimal("0.001")}
    assessment = {"assessment_id": 1, "vuln_id": 101, "methodology_id": "day6-priority-v1",
                  "methodology_sha256": "a" * 64, "vuln_status": "POTENTIAL", "action": "VERIFY", "priority": "P3",
                  "cvss_score": Decimal("9.80"), "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                  "cvss_source": "nvd@nist.gov", "epss_score": Decimal("0.123456789"),
                  "epss_percentile": Decimal("0.810000000"), "epss_date": NOW.date(), "kev_status": "NOT_LISTED",
                  "kev_date_added": None, "asset_criticality": "LOW", "internet_exposed": 0, "handles_personal_data": 0,
                  "input_sha256": "b" * 64, "first_assessed_at": datetime(2026, 9, 7), "last_assessed_at": NOW, "observations": 3,
                  "details": json.dumps({"matched_rules": ["P3_CVSS_HIGH"], "missing_inputs": [], "reason": "설정 및 설치 패키지 확인이 필요합니다.",
                         "incomplete": False, "source_errors": [], "cve_id": CVE, "source": finding["source"],
                         "asset_context": {"asset_uid": ASSET, "owner": host["owner"]},
                         "endpoint": {"port_id": 11, "scan_id": 4, "port": 18080, "protocol": "tcp"},
                         "cvss": {"state": "OK", "source": "nvd@nist.gov", "metric_type": "Primary", "score": 9.8},
                         "epss": {"state": "OK", "score": 0.123456789, "percentile": 0.81, "date": "2026-09-09"},
                         "kev": {"state": "OK", "status": "NOT_LISTED", "source": "https://www.cisa.gov/",
                                  "catalog_version": "2026.09.09", "due_date": None}})}
    scan = {"scan_id": 4, "scan_uid": "scan-local-4", "status": "COMPLETED", "scan_type": "TCP", "target": "localhost",
            "requested_targets": '["localhost"]', "port_range": "18080", "started_at": NOW, "finished_at": NOW,
            "scope_uid": "local-lab-v1", "authorization_ref": "LAB-APPROVAL", "approved_by": "실습 담당자",
            "valid_from": datetime(2026, 1, 1), "valid_until": datetime(2027, 1, 1), "policy_sha256": "c" * 64}
    return {"hosts": [host, {**host, "id": 2, "asset_uid": OTHER_ASSET, "host_ip": "127.0.0.2", "last_scan_id": 5}],
            "scans": [scan, {**scan, "scan_id": 3}, {**scan, "scan_id": 5}],
            "scan_assets": [{"host_id": 1, "scan_id": 4}, {"host_id": 2, "scan_id": 4}],
            "ports": [port, {**port, "port_id": 12, "last_scan_id": 3, "port": 22},
                      {**port, "port_id": 13, "port": 443, "state": "closed"},
                      {**port, "port_id": 21, "host_id": 2, "port": 8080}],
            "findings": [finding, {**finding, "vuln_id": 102, "source": "rule_dvwa_sqli"},
                         {**finding, "vuln_id": 103, "port_id": 12}],
            "assessments": [assessment],
            "evidence": [
                {"evidence_id": 2, "vuln_id": 101, "checker": "day5:apache", "evidence_type": "BANNER", "sha256": "d" * 64,
                 "collected_at": NOW, "details": json.dumps({"content": {"result": "POTENTIAL", "reason": "추가 설정 확인",
                     "error_code": None, "additional_checks": ["설정 파일 확인"], "details": {"safe_checks": ["http_head_root_no_redirects"]}},
                     "first_checked_at": "2026-09-07T10:00:00Z", "last_checked_at": "2026-09-09T10:00:00Z", "observations": 2})},
                {"evidence_id": 1, "vuln_id": 101, "checker": "day4_mapper", "evidence_type": "BANNER", "sha256": "e" * 64,
                 "collected_at": datetime(2026, 9, 7), "details": json.dumps({"status": "CANDIDATE", "match_reason": "공식 영향 범위 일치",
                     "conditions_to_verify": ["패치 여부 확인"], "references": ["https://httpd.apache.org/security/"], "catalog_sha256": "f" * 64})}],
            "history": [{"history_id": 2, "vuln_id": 101, "from_status": "CANDIDATE", "to_status": "POTENTIAL", "action_type": "STATUS_CHANGE",
                         "reason": "추가 확인 필요", "changed_by": "verifier", "changed_at": NOW},
                        {"history_id": 1, "vuln_id": 101, "from_status": None, "to_status": "CANDIDATE", "action_type": "STATUS_CHANGE",
                         "reason": "후보 생성", "changed_by": "mapper", "changed_at": datetime(2026, 9, 7)}]}


class FixtureDB:
    def __init__(self):
        self.data = fixture_data()
        self.connections = []
        self.fail_on = None
        self.on_first_read = None

    def connect(self):
        conn = FixtureConnection(self)
        self.connections.append(conn)
        return conn


class FixtureConnection:
    def __init__(self, db):
        self.db = db
        self.transaction = None
        self.closed = False
        self.rollbacks = self.commits = 0
        self.log = []

    def start_transaction(self, **kwargs):
        self.transaction = kwargs
        self.snapshot = copy.deepcopy(self.db.data)
        if self.db.fail_on == "start":
            raise RuntimeError("start failed")

    def cursor(self, **_kwargs):
        return FixtureCursor(self)

    def commit(self):
        self.commits += 1
        raise AssertionError("Report cannot commit")

    def rollback(self):
        self.rollbacks += 1

    def close(self):
        self.closed = True


class FixtureCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        text = " ".join(sql.split())
        conn, data = self.conn, self.conn.snapshot
        conn.log.append((text, params))
        assert text.startswith("SELECT"), "Report SQL must only SELECT"
        assert "FOR UPDATE" not in text, "Report must not take write locks"
        assert conn.transaction == {"isolation_level": "REPEATABLE READ", "consistent_snapshot": True, "readonly": True}
        if conn.db.fail_on and conn.db.fail_on in text:
            raise RuntimeError("injected read failure")
        if conn.db.on_first_read and len(conn.log) == 1:
            conn.db.on_first_read()
        if text.startswith("SELECT h.id"):
            if "h.asset_uid = %s" in text:
                self.rows = [row for row in data["hosts"] if row["asset_uid"] == params[0]]
            else:
                ids = {row["host_id"] for row in data["scan_assets"] if row["scan_id"] == params[0]}
                ids.update(row["host_id"] for row in data["ports"] if row["last_scan_id"] == params[1])
                self.rows = [row for row in data["hosts"] if row["id"] in ids]
        elif text.startswith("SELECT s.id AS scan_id"):
            self.rows = [row for row in data["scans"] if row["scan_id"] in params]
        elif text.startswith("SELECT p.id AS port_id"):
            if "p.last_scan_id = h.last_scan_id" in text:
                hosts = {row["id"]: row for row in data["hosts"] if row["asset_uid"] == params[0]}
                self.rows = [row for row in data["ports"] if row["host_id"] in hosts
                             and row["last_scan_id"] is not None and row["last_scan_id"] == hosts[row["host_id"]]["last_scan_id"]]
            else:
                self.rows = [row for row in data["ports"] if row["last_scan_id"] == params[0]]
        elif text.startswith("SELECT v.id AS vuln_id"):
            assert "v.source LIKE 'day4:%'" in text
            self.rows = [row for row in data["findings"] if row["port_id"] in params and row["source"].startswith("day4:")]
        elif text.startswith("SELECT r.id AS assessment_id"):
            assert "newer.last_assessed_at > r.last_assessed_at" in text and "newer.id > r.id" in text
            groups = {}
            for row in data["assessments"]:
                if row["vuln_id"] in params:
                    key = row["vuln_id"]
                    if key not in groups or (row["last_assessed_at"], row["assessment_id"]) > (groups[key]["last_assessed_at"], groups[key]["assessment_id"]):
                        groups[key] = row
            self.rows = list(groups.values())
        elif text.startswith("SELECT e.id AS evidence_id"):
            self.rows = [row for row in data["evidence"] if row["vuln_id"] in params]
        elif text.startswith("SELECT rh.id AS history_id"):
            self.rows = [row for row in data["history"] if row["vuln_id"] in params]
        else:
            raise AssertionError("Unexpected SELECT: " + text)

    def fetchall(self):
        return copy.deepcopy(self.rows)


class AnalysisReportTests(unittest.TestCase):
    def setUp(self):
        self.db = FixtureDB()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("api.analysis_report.get_connection", side_effect=lambda: self.db.connect()))
        self.network = self.stack.enter_context(patch("requests.sessions.Session.request", side_effect=AssertionError("No HTTP allowed")))
        self.dns = self.stack.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("No target DNS allowed")))
        self.probe = self.stack.enter_context(patch("socket.create_connection", side_effect=AssertionError("No target probe allowed")))

    def build(self):
        return build_report_snapshot(asset_uid=ASSET)

    def finding(self, snapshot=None):
        return (snapshot or self.build())["assets"][0]["findings"][0]

    def test_asset_selection_current_observations_and_scopes(self):
        report = self.build()
        self.assertEqual(report["selection"]["asset_uid"], ASSET)
        self.assertEqual(report["summary"]["asset_count"], 1)
        self.assertEqual(report["summary"]["open_port_count"], 1)
        self.assertEqual([p["port_id"] for p in report["assets"][0]["ports"]], [13, 11])
        self.assertEqual(report["scans"][0]["scope"]["authorization_ref"], "LAB-APPROVAL")
        self.assertEqual(report["scans"][0]["requested_targets"], ["localhost"])

    def test_scan_selection_current_ports_even_when_host_has_newer_scan(self):
        report = build_report_snapshot(scan_id=4)
        self.assertEqual(report["summary"]["asset_count"], 2)
        self.assertEqual(report["summary"]["open_port_count"], 2)
        self.assertEqual([p["port_id"] for p in report["assets"][1]["ports"]], [21])
        self.assertIn("not historical replay", report["selection"]["selection_note"])

    def test_invalid_selection_is_rejected_before_database(self):
        for args in ({}, {"asset_uid": ASSET, "scan_id": 4}, {"asset_uid": "127.0.0.1"},
                     {"scan_id": 0}, {"scan_id": -1}, {"scan_id": True}, {"scan_id": "4 OR 1=1"}):
            with self.assertRaises(ReportSelectionError):
                build_report_snapshot(**args)
        self.assertEqual(self.db.connections, [])

    def test_missing_asset_or_scan_closes_read_connection(self):
        for args in ({"asset_uid": "00000000-0000-0000-0000-000000000001"}, {"scan_id": 999}):
            with self.assertRaises(ReportSelectionError):
                build_report_snapshot(**args)
        self.assertTrue(all(conn.closed and conn.commits == 0 for conn in self.db.connections))

    def test_only_reviewed_current_findings_not_legacy_or_invented_day4_sources(self):
        self.db.data["findings"].append({**self.db.data["findings"][0], "vuln_id": 199, "source": "day4:invented"})
        report = self.build()
        self.assertEqual([f["vuln_id"] for f in report["assets"][0]["findings"]], [101])
        self.assertEqual(report["summary"]["finding_count"], 1)

    def test_latest_assessment_uses_last_observation_not_max_id(self):
        original = self.db.data["assessments"][0]
        self.db.data["assessments"].append({**original, "assessment_id": 9, "last_assessed_at": datetime(2026, 9, 6), "priority": "P1"})
        self.assertEqual(self.finding()["assessment"]["assessment_id"], 1)
        self.db.data["assessments"].append({**original, "assessment_id": 10, "priority": "P2"})
        self.assertEqual(self.finding()["assessment"]["assessment_id"], 10)

    def test_current_assessment_values_come_from_v5_not_vulns_summaries(self):
        finding = self.finding()
        self.assertEqual(finding["assessment_freshness"], "CURRENT")
        self.assertEqual((finding["effective_priority"], finding["effective_action"]), ("P3", "VERIFY"))
        self.assertEqual(finding["assessment"]["cvss_score"], 9.8)
        self.assertEqual(finding["assessment"]["epss_score"], 0.123456789)
        self.assertEqual(finding["assessment"]["provenance"]["cvss"]["metric_type"], "Primary")

    def test_status_mismatch_is_stale_and_does_not_reuse_priority(self):
        self.db.data["findings"][0]["status"] = "CONFIRMED"
        report = self.build()
        finding = self.finding(report)
        self.assertEqual(finding["assessment_freshness"], "STALE")
        self.assertEqual(finding["effective_priority"], "UNASSESSED")
        self.assertIsNone(finding["effective_action"])
        self.assertEqual(finding["assessment"]["priority"], "P3")
        self.assertEqual(report["summary"]["priority_counts"]["UNASSESSED"], 1)
        self.assertEqual(report["summary"]["highest_priority"], "UNASSESSED")

    def test_each_asset_context_change_marks_stale(self):
        for key, value in (("criticality", "HIGH"), ("internet_exposed", 1), ("handles_personal_data", 1), ("owner", "변경 담당자")):
            self.db.data = fixture_data()
            self.db.data["hosts"][0][key] = value
            with self.subTest(field=key):
                self.assertEqual(self.finding()["assessment_freshness"], "STALE")

    def test_missing_assessment_is_unassessed(self):
        self.db.data["assessments"] = []
        report = self.build()
        self.assertIsNone(self.finding(report)["assessment"])
        self.assertEqual(self.finding(report)["assessment_freshness"], "MISSING")
        self.assertEqual(report["summary"]["assessment_freshness_counts"]["MISSING"], 1)
        self.assertEqual(report["summary"]["priority_counts"]["UNASSESSED"], 1)

    def test_priority_ordering_and_stale_p1_exclusion(self):
        finding, assessment = self.db.data["findings"][0], self.db.data["assessments"][0]
        self.db.data["findings"] = []
        self.db.data["assessments"] = []
        for index, priority in enumerate(("P4", "P2", "P1", "P3", "P1"), start=1):
            self.db.data["findings"].append({**finding, "vuln_id": index})
            self.db.data["assessments"].append({**assessment, "vuln_id": index, "assessment_id": index,
                                                "priority": priority, "vuln_status": "ERROR" if index == 5 else "POTENTIAL"})
        report = self.build()
        self.assertEqual([f["effective_priority"] for f in report["assets"][0]["findings"]], ["P1", "P2", "P3", "P4", "UNASSESSED"])
        self.assertEqual(report["summary"]["priority_counts"], dict.fromkeys(("P1", "P2", "P3", "P4", "UNASSESSED"), 1))
        self.assertEqual(report["summary"]["highest_priority"], "P1")

    def test_legacy_weighted_risk_is_never_selected_or_serialized(self):
        report = self.build()
        self.assertNotIn('"risk"', json.dumps(report))
        self.assertNotIn("0.969", json.dumps(report))
        self.assertTrue(all("v.risk" not in sql for sql, _ in self.db.connections[0].log))

    def test_day4_day5_evidence_parsing_and_order(self):
        evidence = self.finding()["evidence"]
        self.assertEqual([row["evidence_id"] for row in evidence], [1, 2])
        self.assertEqual(evidence[0]["details"]["reason"], "공식 영향 범위 일치")
        self.assertEqual(evidence[1]["details"]["result"], "POTENTIAL")
        self.assertEqual(evidence[1]["details"]["observations"], 2)
        self.assertEqual(evidence[1]["details"]["safe_checks"], ["http_head_root_no_redirects"])

    def test_malformed_or_legacy_evidence_does_not_break_report_or_expose_raw(self):
        for bad in ("not-json secret=value", "[]", '{"content": []}', '{"value": NaN}'):
            self.db.data["evidence"][0]["details"] = bad
            evidence = self.finding()["evidence"][1]
            self.assertEqual(evidence["details_status"], "PARSE_ERROR")
            self.assertNotIn("secret=value", json.dumps(evidence))
            self.assertEqual(evidence["details"], {})

    def test_malformed_assessment_details_retains_columns_with_parse_error(self):
        self.db.data["assessments"][0]["details"] = "legacy-not-json"
        result = self.finding()["assessment"]
        self.assertEqual(result["details_status"], "PARSE_ERROR")
        self.assertEqual(result["cvss_score"], 9.8)
        self.assertIsNone(result["details"]["matched_rules"])

    def test_history_is_chronological_with_id_tiebreak(self):
        self.assertEqual([event["history_id"] for event in self.finding()["history"]], [1, 2])

    def test_no_findings_and_no_ports_are_not_secure_conclusions(self):
        self.db.data["ports"] = []
        report = self.build()
        self.assertEqual(report["summary"]["finding_count"], 0)
        self.assertEqual(report["summary"]["highest_priority"], "UNASSESSED")
        self.assertIn("does not establish security", report["summary"]["coverage_note"])
        self.assertEqual(set(report["summary"]["status_counts"]), {"CANDIDATE", "POTENTIAL", "CONFIRMED", "NOT_APPLICABLE",
                                                                "FALSE_POSITIVE", "RETEST_REQUIRED", "CLOSED", "ERROR"})

    def test_closed_current_port_finding_is_preserved_but_not_counted_open(self):
        self.db.data["ports"][0]["state"] = "closed"
        report = self.build()
        self.assertEqual(report["summary"]["open_port_count"], 0)
        self.assertEqual(report["summary"]["finding_count"], 1)
        self.assertEqual(self.finding(report)["status"], "POTENTIAL")

    def test_stable_hash_excludes_generation_time_and_hash_itself(self):
        first, second = self.build(), self.build()
        self.assertEqual(first["integrity"]["snapshot_sha256"], second["integrity"]["snapshot_sha256"])
        digest = snapshot_sha256(first)
        first["generated_at"] = "2030-01-01T00:00:00Z"
        first["integrity"]["snapshot_sha256"] = "changed"
        self.assertEqual(snapshot_sha256(first), digest)
        first["assets"][0]["owner"] = "changed owner"
        self.assertNotEqual(snapshot_sha256(first), digest)

    def test_read_only_consistent_transaction_no_writes_no_network(self):
        before = copy.deepcopy(self.db.data)
        self.build()
        conn = self.db.connections[0]
        self.assertEqual(conn.transaction, {"isolation_level": "REPEATABLE READ", "consistent_snapshot": True, "readonly": True})
        self.assertEqual(conn.commits, 0)
        self.assertEqual(conn.rollbacks, 1)
        self.assertTrue(conn.closed)
        self.assertEqual(self.db.data, before)
        self.network.assert_not_called()
        self.dns.assert_not_called()
        self.probe.assert_not_called()

    def test_concurrent_writer_is_outside_consistent_snapshot(self):
        self.db.on_first_read = lambda: self.db.data["hosts"][0].update(criticality="CRITICAL")
        report = self.build()
        self.assertEqual(report["assets"][0]["criticality"], "LOW")
        self.assertEqual(self.finding(report)["assessment_freshness"], "CURRENT")
        self.assertEqual(self.db.data["hosts"][0]["criticality"], "CRITICAL")

    def test_query_and_transaction_start_failure_close_connection(self):
        for failure in ("vuln_risk_assessments", "start"):
            self.db.fail_on = failure
            with self.assertRaises(ReportDatabaseError):
                self.build()
            self.assertTrue(self.db.connections[-1].closed)
            self.assertEqual(self.db.connections[-1].commits, 0)

    def test_asset_without_last_scan_and_scan_without_remaining_observations(self):
        self.db.data["hosts"][0]["last_scan_id"] = None
        report = self.build()
        self.assertEqual(report["scans"], [])
        self.assertEqual(report["assets"][0]["ports"], [])
        self.db.data["ports"] = []
        report = build_report_snapshot(scan_id=4)
        self.assertEqual(report["summary"]["asset_count"], 2)
        self.assertEqual(report["summary"]["finding_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
