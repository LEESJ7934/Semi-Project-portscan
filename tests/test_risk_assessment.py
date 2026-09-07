"""Policy, CLI and transaction tests; DB-API doubles and mocked public sources only."""
import contextlib
import copy
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis.nvd_cvss import cvss_result, NVD_BASE_URL, EPSS_URL, KEV_URL
from analysis.risk_assessment import run_risk_assessments, RiskSelectionError
from analysis.risk_engine import METHODOLOGY, assess_priority, sha256_json
from api.shodan_epss_report import epss_result
from db.query_helpers import get_risk_assessment_targets
from scripts.run_risk_assessment import main

CVE = "CVE-2021-42013"
OTHER = "CVE-2021-41773"
ASSET = "9cd48a9c-bc17-4bbb-81ce-419f2bef8306"
ASSET2 = "0561e307-a8b3-11f1-bb09-9a1fea705640"


def cvss(score=5.0):
    if score is None:
        return cvss_result("NO_SCORE")
    return cvss_result("OK", score=score, version="3.1", source="nvd@nist.gov",
                       vector="CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:L", metric_type="Primary", severity="MEDIUM")


def epss(score=0.01, percentile=0.2, date="2026-09-07"):
    return epss_result("NOT_FOUND") if score is None else epss_result("OK", score=score, percentile=percentile, date=date)


def kev(status="NOT_LISTED"):
    return {"state": "ERROR" if status == "UNKNOWN" else "OK", "status": status,
            "error_code": "KEV_UNAVAILABLE" if status == "UNKNOWN" else None}


def catalog():
    return {"state": "OK", "source": KEV_URL, "catalog_version": "2026.09.07",
            "date_released": "2026-09-07T12:00:00Z", "entries": {}, "error_code": None, "errors": []}


def asset(**updates):
    return {"criticality": "LOW", "internet_exposed": False, "handles_personal_data": False, **updates}


def stored_row(vuln_id=1, **updates):
    return {"vuln_id": vuln_id, "cve_id": CVE, "source": "day4:apache:cve-2021-42013", "status": "CANDIDATE",
            "cvss": 8.4, "epss": 0.65432, "risk": 0.71, "severity": "HIGH", "verified_at": "2026-09-01",
            "closed_at": None, "port_id": 10, "port": 8081, "protocol": "tcp", "scan_id": 4,
            "host_id": 2, "asset_uid": ASSET, "host_ip": "127.0.0.1", "asset_name": "local-lab",
            "asset_type": "SERVER", "environment": "TEST", "criticality": "LOW", "owner": "security-team",
            "business_unit": None, "data_classification": "INTERNAL", "internet_exposed": 0,
            "handles_personal_data": 0, "lifecycle_status": "ACTIVE", **updates}


class RiskEngineTests(unittest.TestCase):
    def evaluate(self, status="CANDIDATE", *, context=None, cvss_info=None, epss_info=None, kev_info=None, **kwargs):
        return assess_priority(status, asset() if context is None else context,
                               cvss() if cvss_info is None else cvss_info,
                               epss() if epss_info is None else epss_info,
                               kev() if kev_info is None else kev_info, **kwargs)

    def test_status_to_action_mapping(self):
        for status, action in {"CANDIDATE": "VERIFY", "POTENTIAL": "VERIFY", "ERROR": "VERIFY",
                               "CONFIRMED": "REMEDIATE", "RETEST_REQUIRED": "RETEST"}.items():
            self.assertEqual(self.evaluate(status)["action"], action)

    def test_terminal_states_are_not_assessable(self):
        for status in ("NOT_APPLICABLE", "FALSE_POSITIVE", "CLOSED", "INVALID"):
            with self.assertRaises(ValueError):
                self.evaluate(status)

    def test_p1_kev_plus_exposure_does_not_confirm_candidate(self):
        result = self.evaluate(context=asset(internet_exposed=True), kev_info=kev("KNOWN_EXPLOITED"))
        self.assertEqual((result["priority"], result["action"]), ("P1", "VERIFY"))
        self.assertEqual(result["matched_rules"], ["P1_KEV_EXPOSED"])
        self.assertNotIn("status", result)

    def test_p1_confirmed_critical_exposed(self):
        result = self.evaluate("CONFIRMED", context=asset(criticality="CRITICAL", internet_exposed=True))
        self.assertEqual(result["priority"], "P1")
        self.assertIn("P1_CONFIRMED_CRITICAL_EXPOSED", result["matched_rules"])

    def test_p2_kev_without_exposure(self):
        self.assertEqual(self.evaluate(kev_info=kev("KNOWN_EXPLOITED"))["priority"], "P2")

    def test_p2_very_high_percentile_with_exposure_boundary(self):
        for percentile, expected in ((0.949999999, "P3"), (0.95, "P2"), (1.0, "P2")):
            self.assertEqual(self.evaluate(context=asset(internet_exposed=True),
                                           epss_info=epss(percentile=percentile))["priority"], expected)
        self.assertEqual(self.evaluate(epss_info=epss(percentile=0.99))["priority"], "P3")

    def test_p2_confirmed_important_asset(self):
        for criticality in ("HIGH", "CRITICAL"):
            self.assertEqual(self.evaluate("CONFIRMED", context=asset(criticality=criticality))["priority"], "P2")
        self.assertEqual(self.evaluate("POTENTIAL", context=asset(criticality="HIGH"))["priority"], "P3")

    def test_p2_cvss_critical_important_asset_boundary(self):
        for score, expected in ((8.99, "P3"), (9.0, "P2"), (10.0, "P2")):
            self.assertEqual(self.evaluate(context=asset(criticality="HIGH"), cvss_info=cvss(score))["priority"], expected)
        self.assertEqual(self.evaluate(cvss_info=cvss(9.8))["priority"], "P3")

    def test_p3_rules_individually(self):
        cases = [(dict(epss_info=epss(percentile=0.8)), "P3_EPSS_HIGH"),
                 (dict(cvss_info=cvss(7.0)), "P3_CVSS_HIGH"),
                 (dict(context=asset(criticality="HIGH")), "P3_IMPORTANT_ASSET"),
                 (dict(context=asset(internet_exposed=True)), "P3_EXPOSED")]
        for arguments, rule in cases:
            result = self.evaluate(**arguments)
            self.assertEqual(result["priority"], "P3")
            self.assertIn(rule, result["matched_rules"])
        self.assertEqual(self.evaluate(cvss_info=cvss(6.99), epss_info=epss(percentile=0.799999999))["priority"], "P4")

    def test_pii_promotes_one_level_only(self):
        for score, base, final in ((5.0, "P4", "P3"), (7.0, "P3", "P2")):
            result = self.evaluate(context=asset(handles_personal_data=True), cvss_info=cvss(score))
            self.assertEqual((result["base_priority"], result["priority"]), (base, final))
            self.assertIn("PII_ONE_LEVEL", result["matched_rules"])

    def test_pii_cannot_promote_p2_to_p1_or_create_a_priority_from_no_data(self):
        result = self.evaluate(context=asset(handles_personal_data=True), kev_info=kev("KNOWN_EXPLOITED"))
        self.assertEqual(result["priority"], "P2")
        self.assertNotIn("PII_ONE_LEVEL", result["matched_rules"])
        result = self.evaluate(context=asset(criticality="UNASSIGNED", handles_personal_data=True),
                               cvss_info=cvss(None), epss_info=epss(None), kev_info=kev("UNKNOWN"))
        self.assertEqual(result["priority"], "UNASSESSED")

    def test_p4_real_zero_is_available_but_unknown_is_not_zero(self):
        self.assertEqual(self.evaluate(cvss_info=cvss(0), epss_info=epss(None))["priority"], "P4")
        result = self.evaluate(cvss_info=cvss(None), epss_info=epss(None), kev_info=kev("UNKNOWN"))
        self.assertEqual(result["priority"], "UNASSESSED")
        self.assertTrue({"cvss.score", "epss.score", "epss.percentile", "epss.date", "kev.status"} <= set(result["missing_inputs"]))

    def test_unassigned_criticality_blocks_p4(self):
        result = self.evaluate(context=asset(criticality="UNASSIGNED"))
        self.assertEqual(result["priority"], "UNASSESSED")
        self.assertIn("asset.criticality", result["missing_inputs"])

    def test_winning_tier_can_record_multiple_rules(self):
        result = self.evaluate("CONFIRMED", context=asset(criticality="CRITICAL", internet_exposed=True),
                               kev_info=kev("KNOWN_EXPLOITED"))
        self.assertEqual(result["matched_rules"], ["P1_KEV_EXPOSED", "P1_CONFIRMED_CRITICAL_EXPOSED"])

    def test_engine_determinism_input_immutability_and_methodology_hash(self):
        inputs = [asset(), cvss(), epss(), kev()]
        original = copy.deepcopy(inputs)
        first = assess_priority("POTENTIAL", *inputs)
        self.assertEqual(first, assess_priority("POTENTIAL", *inputs))
        self.assertEqual(inputs, original)
        self.assertEqual(first["methodology_sha256"], sha256_json(METHODOLOGY))
        changed = copy.deepcopy(METHODOLOGY)
        changed["thresholds"]["cvss_high"] = 6.0
        other = self.evaluate(cvss_info=cvss(6.0), methodology=changed)
        self.assertEqual(other["priority"], "P3")
        self.assertNotEqual(first["methodology_sha256"], other["methodology_sha256"])

    def test_bad_normalized_inputs_do_not_silently_drive_priority(self):
        with self.assertRaises(ValueError):
            self.evaluate(context=asset(internet_exposed="false"))
        with self.assertRaises(ValueError):
            self.evaluate(cvss_info={**cvss(), "score": float("nan")})


class MemoryDB:
    def __init__(self, rows=None):
        self.state = {"rows": [stored_row()] if rows is None else rows,
                      "assessments": [], "history": [("existing review",)]}
        self.connections = []
        self.fail_on = None
        self.fail_vuln = None

    def connect(self):
        conn = MemoryConnection(self)
        self.connections.append(conn)
        return conn


class MemoryConnection:
    def __init__(self, db):
        self.db = db
        self.state = copy.deepcopy(db.state)
        self.log = []
        self.closed = self.locked = self.started = False
        self.commits = self.rollbacks = 0
        self.selected_vuln = None

    def start_transaction(self):
        self.started = True

    def cursor(self, **_kwargs):
        return MemoryCursor(self)

    def commit(self):
        self.db.state = copy.deepcopy(self.state)
        self.commits += 1

    def rollback(self):
        self.state = copy.deepcopy(self.db.state)
        self.rollbacks += 1

    def close(self):
        self.closed = True


class MemoryCursor:
    def __init__(self, conn):
        self.conn = conn
        self.rows = []
        self.lastrowid = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        sql = " ".join(sql.split()).rstrip(";")
        conn, state = self.conn, self.conn.state
        conn.log.append((sql, params))
        if conn.db.fail_on and conn.db.fail_on in sql and (conn.db.fail_vuln is None or conn.db.fail_vuln == conn.selected_vuln):
            raise RuntimeError("injected write failure")
        if sql.startswith(("INSERT", "UPDATE")):
            assert conn.started and conn.locked, "Writes need a locked parent and transaction"
        if sql.startswith("SELECT v.id AS vuln_id"):
            rows = state["rows"]
            if "v.source LIKE 'day4:%'" in sql:
                rows = [row for row in rows if row["source"].startswith("day4:")]
            if "v.status IN" in sql:
                statuses = re.findall(r"'([A-Z_]+)'", re.search(r"v.status IN \(([^)]+)\)", sql)[1])
                rows = [row for row in rows if row["status"] in statuses]
            values = iter(params)
            for condition, key in (("AND v.id = %s", "vuln_id"), ("AND p.last_scan_id = %s", "scan_id"),
                                    ("AND h.asset_uid = %s", "asset_uid")):
                if condition in sql:
                    value = next(values)
                    rows = [row for row in rows if row[key] == value]
                    if key == "vuln_id":
                        conn.selected_vuln = value
            self.rows = copy.deepcopy(rows)
            conn.locked = sql.endswith("FOR UPDATE")
        elif sql.startswith("SELECT id FROM vuln_risk_assessments"):
            self.rows = [row for row in state["assessments"]
                         if (row["vuln_id"], row["methodology_id"], row["input_sha256"]) == params]
        elif sql.startswith("INSERT INTO vuln_risk_assessments"):
            columns = re.search(r"vuln_risk_assessments \((.*?)\) VALUES", sql)[1].split(",")
            assert len(columns) == len(params)
            row = dict(zip((column.strip() for column in columns), params))
            key = tuple(row[name] for name in ("vuln_id", "methodology_id", "input_sha256"))
            assert not any(tuple(item[name] for name in ("vuln_id", "methodology_id", "input_sha256")) == key
                           for item in state["assessments"]), "unique assessment key"
            self.lastrowid = len(state["assessments"]) + 1
            state["assessments"].append({**row, "id": self.lastrowid, "observations": 1})
        elif sql.startswith("UPDATE vuln_risk_assessments"):
            row = next(row for row in state["assessments"] if row["id"] == params[1])
            row["observations"] += 1
            row["last_assessed_at"] = max(row["last_assessed_at"], params[0])
        elif sql.startswith("UPDATE vulns SET"):
            columns = [item.split("=")[0].strip() for item in re.search(r"SET (.*?) WHERE", sql)[1].split(",")]
            assert set(columns) <= {"cvss", "epss"}, "Day 6 must never change review/legacy fields"
            row = next(row for row in state["rows"] if row["vuln_id"] == params[-1])
            row.update(zip(columns, params[:-1]))
        else:
            raise AssertionError("Unexpected Day 6 SQL: " + sql)

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class RiskAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.db = MemoryDB()
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch("db.query_helpers.get_connection", side_effect=lambda: self.db.connect()))
        self.stack.enter_context(patch("analysis.risk_assessment.get_connection", side_effect=lambda: self.db.connect()))
        self.cvss_values = {CVE: cvss(), OTHER: cvss()}
        self.epss_values = {CVE: epss(), OTHER: epss()}
        self.catalog = catalog()
        self.before_fetch = None
        self.nvd = self.stack.enter_context(patch("analysis.risk_assessment.fetch_cvss_scores", side_effect=self.fetch_nvd))
        self.first = self.stack.enter_context(patch("analysis.risk_assessment.fetch_epss_scores", side_effect=self.fetch_first))
        self.cisa = self.stack.enter_context(patch("analysis.risk_assessment.fetch_kev_catalog", side_effect=self.fetch_cisa))
        self.target_connect = self.stack.enter_context(patch("socket.create_connection", side_effect=AssertionError("Target connection forbidden")))
        self.target_dns = self.stack.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("Target DNS forbidden")))
        self.http = self.stack.enter_context(patch("requests.sessions.Session.request", side_effect=AssertionError("Unmocked HTTP forbidden")))

    def assert_no_locks_during_fetch(self):
        self.assertTrue(all(conn.closed and not conn.started and not conn.locked for conn in self.db.connections))

    def fetch_nvd(self, cves, **_kwargs):
        self.assert_no_locks_during_fetch()
        if self.before_fetch:
            self.before_fetch()
        return {cve: self.cvss_values[cve] for cve in cves}

    def fetch_first(self, cves, **_kwargs):
        self.assert_no_locks_during_fetch()
        return {cve: self.epss_values[cve] for cve in cves}

    def fetch_cisa(self, **_kwargs):
        self.assert_no_locks_during_fetch()
        return copy.deepcopy(self.catalog)

    def run_one(self, **kwargs):
        return run_risk_assessments(vuln_id=1, **kwargs)

    def assert_no_review_writes(self):
        for conn in self.db.connections:
            for sql, _params in conn.log:
                self.assertNotIn("INSERT INTO remediation_history", sql)
                if sql.startswith("UPDATE vulns"):
                    self.assertNotRegex(sql, r"\b(status|risk|severity|verified_at|closed_at)\s*=")

    def test_query_selection_statuses_source_and_parameterized_filters(self):
        self.db.state["rows"] = [stored_row(i + 1, status=status) for i, status in enumerate(
            ["CANDIDATE", "POTENTIAL", "CONFIRMED", "RETEST_REQUIRED", "ERROR", "CLOSED", "NOT_APPLICABLE", "FALSE_POSITIVE"])]
        self.db.state["rows"].append(stored_row(9, source="rule_dvwa_sqli"))
        rows = get_risk_assessment_targets(asset_uid=ASSET)
        self.assertEqual([row["vuln_id"] for row in rows], [1, 2, 3, 4, 5])
        self.assertTrue(self.db.connections[-1].closed)
        sql, params = self.db.connections[-1].log[0]
        self.assertEqual(params, (ASSET,))
        self.assertIn("h.internet_exposed", sql)
        self.assertIn("h.handles_personal_data", sql)
        self.assertFalse(self.db.connections[-1].locked)
        with self.assertRaises(ValueError):
            get_risk_assessment_targets(vuln_id=1, for_update=True)

    def test_unreviewed_or_legacy_sources_never_reach_network(self):
        for source in ("rule_dvwa_sqli", "rule_dvwa_fileupload", "unknown", "day4:invented"):
            self.db.state["rows"][0]["source"] = source
            with self.assertRaises(RiskSelectionError):
                self.run_one()
        self.nvd.assert_not_called()
        self.first.assert_not_called()
        self.cisa.assert_not_called()

    def test_no_eligible_rows_is_selection_error(self):
        self.db.state["rows"][0]["status"] = "CLOSED"
        with self.assertRaises(RiskSelectionError):
            self.run_one()
        self.nvd.assert_not_called()

    def test_preview_is_default_and_never_writes_or_probes(self):
        original = copy.deepcopy(self.db.state)
        result = self.run_one()
        self.assertEqual(result["mode"], "PREVIEW")
        self.assertEqual(self.db.state, original)
        self.assertEqual(len(self.db.connections), 1)
        self.assertFalse(self.db.connections[0].started)
        self.assertIsNone(result["results"][0]["assessment_id"])
        self.target_connect.assert_not_called()
        self.target_dns.assert_not_called()
        self.http.assert_not_called()

    def test_unique_cve_sources_and_one_catalog_fetch_for_many_findings(self):
        self.db.state["rows"] = [stored_row(), stored_row(2),
            stored_row(3, cve_id=OTHER, source="day4:apache:cve-2021-41773")]
        result = run_risk_assessments(scan_id=4)
        self.assertEqual(len(result["results"]), 3)
        self.nvd.assert_called_once_with(sorted([CVE, OTHER]), timeout=10)
        self.first.assert_called_once_with(sorted([CVE, OTHER]), timeout=10)
        self.cisa.assert_called_once_with(timeout=10)

    def test_save_stores_snapshot_and_updates_only_score_summaries(self):
        before = copy.deepcopy(self.db.state["rows"][0])
        result = self.run_one(save=True)["results"][0]
        self.assertEqual(result["outcome"], "SAVED")
        self.assertFalse(result["assessment_reused"])
        stored = self.db.state["assessments"][0]
        details = json.loads(stored["details"])
        self.assertEqual(details["current_status"], "CANDIDATE")
        self.assertEqual(details["action"], "VERIFY")
        self.assertEqual(details["cvss"]["source"], "nvd@nist.gov")
        self.assertEqual(stored["input_sha256"], sha256_json(details))
        self.assertEqual(self.db.state["rows"][0]["cvss"], 5.0)
        self.assertEqual(self.db.state["rows"][0]["epss"], 0.01)
        for key in ("status", "risk", "severity", "verified_at", "closed_at"):
            self.assertEqual(self.db.state["rows"][0][key], before[key])
        self.assertEqual(self.db.state["history"], [("existing review",)])
        self.assertEqual(self.db.connections[-1].commits, 1)
        self.assert_no_review_writes()

    def test_same_assessment_reuses_row_and_increments_observations(self):
        self.run_one(save=True)
        first = copy.deepcopy(self.db.state["assessments"][0])
        self.db.connections.clear()
        result = self.run_one(save=True)["results"][0]
        self.assertTrue(result["assessment_reused"])
        self.assertEqual(len(self.db.state["assessments"]), 1)
        stored = self.db.state["assessments"][0]
        self.assertEqual(stored["observations"], 2)
        self.assertEqual(stored["first_assessed_at"], first["first_assessed_at"])
        self.assertGreaterEqual(stored["last_assessed_at"], first["last_assessed_at"])
        self.assertEqual(stored["input_sha256"], first["input_sha256"])

    def test_asset_changes_create_new_assessments(self):
        self.run_one(save=True)
        for field, value in (("criticality", "HIGH"), ("internet_exposed", 1),
                              ("handles_personal_data", 1), ("owner", "new-owner")):
            self.db.connections.clear()
            self.db.state["rows"][0][field] = value
            outcome = self.run_one(save=True)["results"][0]
            self.assertFalse(outcome["assessment_reused"])
        self.assertEqual(len(self.db.state["assessments"]), 5)

    def test_epss_value_and_date_changes_create_new_assessments(self):
        self.run_one(save=True)
        for update in ({"score": 0.012345678, "epss": 0.012345678}, {"date": "2026-09-08"}, {"percentile": 0.95}):
            self.db.connections.clear()
            self.epss_values[CVE].update(update)
            self.assertFalse(self.run_one(save=True)["results"][0]["assessment_reused"])
        self.assertEqual(len(self.db.state["assessments"]), 4)

    def test_kev_catalog_and_status_changes_create_new_assessments(self):
        self.run_one(save=True)
        self.db.connections.clear()
        self.catalog["catalog_version"] = "2026.09.08"
        self.assertFalse(self.run_one(save=True)["results"][0]["assessment_reused"])
        self.db.connections.clear()
        self.catalog["entries"][CVE] = {"date_added": "2026-09-08"}
        self.assertFalse(self.run_one(save=True)["results"][0]["assessment_reused"])
        self.assertEqual(self.db.state["assessments"][-1]["kev_status"], "KNOWN_EXPLOITED")

    def test_status_and_methodology_changes_create_new_assessments(self):
        self.run_one(save=True)
        self.db.connections.clear()
        self.db.state["rows"][0]["status"] = "CONFIRMED"
        self.assertEqual(self.run_one(save=True)["results"][0]["action"], "REMEDIATE")
        self.db.connections.clear()
        with patch.dict(METHODOLOGY["thresholds"], {"cvss_high": 6.5}):
            self.assertFalse(self.run_one(save=True)["results"][0]["assessment_reused"])
        self.assertEqual(len(self.db.state["assessments"]), 3)
        self.assert_no_review_writes()

    def test_candidate_and_potential_stay_unconfirmed_at_p1(self):
        self.catalog["entries"][CVE] = {"date_added": "2026-09-07"}
        for status in ("CANDIDATE", "POTENTIAL"):
            self.db.connections.clear()
            self.db.state["rows"][0].update(status=status, internet_exposed=1)
            result = self.run_one(save=True)["results"][0]
            self.assertEqual((result["priority"], result["action"]), ("P1", "VERIFY"))
            self.assertEqual(self.db.state["rows"][0]["status"], status)
        self.assert_no_review_writes()

    def test_network_error_preserves_existing_scores_but_records_missing_data(self):
        self.cvss_values[CVE] = cvss_result("ERROR", error_code="TIMEOUT")
        self.epss_values[CVE] = epss_result("ERROR", error_code="HTTP_503")
        result = self.run_one(save=True)
        self.assertTrue(result["incomplete"])
        self.assertEqual(self.db.state["rows"][0]["cvss"], 8.4)
        self.assertEqual(self.db.state["rows"][0]["epss"], 0.65432)
        self.assertIsNone(self.db.state["assessments"][0]["cvss_score"])
        self.assertIsNone(self.db.state["assessments"][0]["epss_score"])
        self.assertEqual(result["results"][0]["priority"], "UNASSESSED")
        self.assertEqual({e["error_code"] for e in result["source_errors"]}, {"TIMEOUT", "HTTP_503"})

    def test_official_absence_clears_summaries_to_null_without_external_error(self):
        self.cvss_values[CVE] = cvss(None)
        self.epss_values[CVE] = epss(None)
        result = self.run_one(save=True)
        self.assertFalse(result["incomplete"])
        self.assertIsNone(self.db.state["rows"][0]["cvss"])
        self.assertIsNone(self.db.state["rows"][0]["epss"])

    def test_actual_zero_scores_are_saved(self):
        self.cvss_values[CVE] = cvss(0)
        self.epss_values[CVE] = epss(0, 0)
        result = self.run_one(save=True)
        self.assertFalse(result["incomplete"])
        self.assertEqual(self.db.state["rows"][0]["cvss"], 0)
        self.assertEqual(self.db.state["rows"][0]["epss"], 0)

    def test_failed_assessment_or_summary_write_rolls_back_all_changes(self):
        for failure in ("INSERT INTO vuln_risk_assessments", "UPDATE vulns"):
            self.db = MemoryDB()
            original = copy.deepcopy(self.db.state)
            self.db.fail_on = failure
            result = self.run_one(save=True)
            self.assertTrue(result["incomplete"])
            self.assertEqual(result["results"][0]["error_code"], "DB_SAVE_FAILED")
            self.assertEqual(self.db.state, original)
            self.assertEqual(self.db.connections[-1].rollbacks, 1)
            self.assertEqual(self.db.connections[-1].commits, 0)

    def test_failure_after_duplicate_update_rolls_back_observation_increment(self):
        self.run_one(save=True)
        original = copy.deepcopy(self.db.state)
        self.db.connections.clear()
        self.db.fail_on = "UPDATE vulns"
        self.assertTrue(self.run_one(save=True)["incomplete"])
        self.assertEqual(self.db.state, original)

    def test_terminal_state_during_fetch_is_skipped_without_writes(self):
        self.before_fetch = lambda: self.db.state["rows"][0].update(status="CLOSED")
        result = self.run_one(save=True)["results"][0]
        self.assertEqual(result["outcome"], "SKIPPED")
        self.assertEqual(result["current_status"], "CLOSED")
        self.assertEqual(self.db.state["assessments"], [])
        self.assertEqual(self.db.state["rows"][0]["cvss"], 8.4)
        self.assertEqual(self.db.connections[-1].commits, 0)
        self.assert_no_review_writes()

    def test_concurrent_status_and_asset_change_are_reassessed_under_lock(self):
        self.before_fetch = lambda: self.db.state["rows"][0].update(status="CONFIRMED", criticality="CRITICAL", internet_exposed=1)
        result = self.run_one(save=True)["results"][0]
        self.assertEqual((result["current_status"], result["action"], result["priority"]), ("CONFIRMED", "REMEDIATE", "P1"))
        self.assertTrue(self.db.connections[-1].locked)
        self.assert_no_review_writes()

    def test_concurrent_source_or_cve_change_cannot_use_stale_intel(self):
        for changes in ({"source": "rule_dvwa_sqli"}, {"cve_id": OTHER, "source": "day4:apache:cve-2021-41773"}):
            self.db = MemoryDB()
            self.before_fetch = lambda: self.db.state["rows"][0].update(changes)
            result = self.run_one(save=True)["results"][0]
            self.assertEqual(result["outcome"], "SKIPPED")
            self.assertEqual(self.db.state["assessments"], [])

    def test_changed_scan_membership_is_skipped(self):
        self.before_fetch = lambda: self.db.state["rows"][0].update(scan_id=5)
        result = run_risk_assessments(scan_id=4, save=True)["results"][0]
        self.assertEqual(result["outcome"], "SKIPPED")
        self.assertEqual(self.db.state["assessments"], [])

    def test_independent_vuln_transactions_keep_prior_success_when_next_fails(self):
        self.db.state["rows"].append(stored_row(2))
        self.db.fail_on, self.db.fail_vuln = "UPDATE vulns", 2
        result = run_risk_assessments(scan_id=4, save=True)
        self.assertEqual([row["outcome"] for row in result["results"]], ["SAVED", "ERROR"])
        self.assertEqual(len(self.db.state["assessments"]), 1)
        self.assertEqual(self.db.state["rows"][0]["cvss"], 5.0)
        self.assertEqual(self.db.state["rows"][1]["cvss"], 8.4)

    def test_fallback_failure_is_visible_even_when_mirror_recovers_membership(self):
        self.catalog["errors"] = [{"source": KEV_URL, "error_code": "HTTP_403"}]
        result = self.run_one()
        self.assertEqual(result["results"][0]["kev"]["status"], "NOT_LISTED")
        self.assertTrue(result["source_errors"][0]["recovered"])
        self.assertTrue(result["incomplete"])

    def test_asset_id_selection(self):
        self.db.state["rows"].append(stored_row(2, asset_uid=ASSET2))
        result = run_risk_assessments(asset_uid=ASSET)
        self.assertEqual([row["vuln_id"] for row in result["results"]], [1])

    def test_cli_preview_save_and_output_file(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()) as stdout:
            output = Path(directory) / "risk.json"
            self.assertEqual(main(["--vuln-id", "1", "--output", str(output)]), 0)
            rendered = json.loads(stdout.getvalue())
            self.assertEqual(rendered["mode"], "PREVIEW")
            self.assertEqual(rendered, json.loads(output.read_text(encoding="utf-8")))
            self.assertEqual(self.db.state["assessments"], [])
        self.db.connections.clear()
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["--asset-id", ASSET, "--save"]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["mode"], "SAVE")
        self.assertEqual(len(self.db.state["assessments"]), 1)

    def test_cli_external_error_emits_json_and_exit_one(self):
        self.cvss_values[CVE] = cvss_result("ERROR", error_code="TIMEOUT")
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(main(["--scan-id", "4"]), 1)
        result = json.loads(stdout.getvalue())
        self.assertTrue(result["incomplete"])
        self.assertEqual(result["results"][0]["epss"]["state"], "OK")
        self.assertEqual(self.db.state["assessments"], [])

    def test_cli_invalid_selections_timeouts_and_missing_rows_exit_one(self):
        cases = [[], ["--vuln-id", "0"], ["--vuln-id", "-1"], ["--asset-id", "not-a-uuid"],
                 ["--scan-id", "4", "--vuln-id", "1"], ["--vuln-id", "1", "--timeout", "nan"],
                 ["--vuln-id", "1", "--timeout", "inf"], ["--vuln-id", "1", "--timeout", "31"],
                 ["--vuln-id", "1", "--timeout", "0"], ["--vuln-id", "999"]]
        for args in cases:
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(main(args), 1)
                self.assertEqual(json.loads(stderr.getvalue())["error_code"], "SELECTION_ERROR")
        self.nvd.assert_not_called()

    def test_cli_db_and_catalog_errors_exit_one_without_request(self):
        with patch("analysis.risk_assessment.get_risk_assessment_targets", side_effect=RuntimeError("secret")), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(main(["--vuln-id", "1"]), 1)
            self.assertEqual(json.loads(stderr.getvalue())["error_code"], "DB_ERROR")
            self.assertNotIn("secret", stderr.getvalue())
        with patch("analysis.risk_assessment.load_catalog", side_effect=ValueError("invalid")), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(main(["--vuln-id", "1"]), 1)
            self.assertEqual(json.loads(stderr.getvalue())["error_code"], "POLICY_ERROR")
        self.nvd.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
