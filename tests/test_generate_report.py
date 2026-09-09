"""Real fixture PDFs and CLI outputs, with no optional PDF parser dependency."""
import base64
import contextlib
import copy
import io
import json
import re
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from api.analysis_report import build_report_snapshot, generate_report, snapshot_sha256
from api.generate_final_report import generate_final_report
from api.report_pdf import render_report_pdf
from scripts.generate_report import build_parser, main
from test_analysis_report import ASSET, CVE, FixtureDB


def pdf_drawn_text(raw):
    """Read ReportLab's Tj text operands for ASCII/CID value checks using stdlib.

    This limited test reader is not shipped in production and is not a general PDF parser.
    PDF layout is additionally rendered and visually inspected in Work.
    """
    pieces = []
    for header, stream in re.findall(rb"<<(.*?)>>\s*stream\r?\n(.*?)endstream", raw, re.S):
        try:
            if b"/ASCII85Decode" in header:
                stream = base64.a85decode(stream.strip(), adobe=True)
            if b"/FlateDecode" in header:
                stream = zlib.decompress(stream)
        except (ValueError, zlib.error):
            continue
        for literal in re.findall(rb"\(((?:\\[0-7]{1,3}|\\.|[^\\)])*)\)\s*Tj\b", stream):
            decoded = re.sub(rb"\\([0-7]{1,3}|.)", lambda m: bytes([int(m[1], 8)]) if m[1].isdigit()
                             else {b"n": b"\n", b"r": b"\r", b"t": b"\t"}.get(m[1], m[1]), literal)
            pieces.append(decoded.decode("latin1"))
            if b"\x00" in decoded and len(decoded) % 2 == 0:
                pieces.append(decoded.decode("utf-16-be", errors="replace"))
    return "".join(pieces)


class GenerateReportTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.db = FixtureDB()
        self.stack.enter_context(patch("api.analysis_report.get_connection", side_effect=self.db.connect))
        self.network = self.stack.enter_context(patch("requests.sessions.Session.request", side_effect=AssertionError("No external requests")))
        self.urlopen = self.stack.enter_context(patch("urllib.request.urlopen", side_effect=AssertionError("No external resources")))
        self.probe = self.stack.enter_context(patch("socket.create_connection", side_effect=AssertionError("No target connection")))
        self.dns = self.stack.enter_context(patch("socket.getaddrinfo", side_effect=AssertionError("No target DNS")))

    def test_fixture_pdf_has_pages_and_renders_summary_and_finding_values(self):
        snapshot = build_report_snapshot(asset_uid=ASSET)
        path = self.directory / "fixture.pdf"
        render_report_pdf(snapshot, path)
        raw = path.read_bytes()
        self.assertTrue(raw.startswith(b"%PDF-"))
        self.assertGreater(len(raw), 1000)
        self.assertGreaterEqual(len(re.findall(rb"/Type\s*/Page\b", raw)), 1)
        drawn = pdf_drawn_text(raw)
        for text in (CVE, "Executive Summary", "POTENTIAL", "P3", "VERIFY", "CURRENT", "9.8", "0.123456789",
                     "NOT_LISTED", "Remediation History", "Report Integrity"):
            self.assertIn(text, drawn)
        self.assertIn(snapshot["integrity"]["snapshot_sha256"], drawn)

    def test_korean_values_and_missing_optional_fields_do_not_crash(self):
        self.db.data["hosts"][0].update(host_name=None, business_unit=None, owner="한글 담당자")
        self.db.data["assessments"] = []
        self.db.data["evidence"] = []
        self.db.data["history"] = []
        snapshot = build_report_snapshot(asset_uid=ASSET)
        render_report_pdf(snapshot, self.directory / "korean_missing.pdf")
        text = pdf_drawn_text((self.directory / "korean_missing.pdf").read_bytes())
        self.assertIn("UNASSESSED", text)
        self.assertIn("MISSING", text)
        self.assertIn("N/A", text)

    def test_long_korean_evidence_and_host_values_paginate(self):
        self.db.data["hosts"][0]["asset_name"] = "매우 긴 한글 자산명 " * 40
        doc = json.loads(self.db.data["evidence"][0]["details"])
        doc["content"]["reason"] = "추가 수동 설정 확인이 필요한 증적입니다. " * 300
        self.db.data["evidence"][0]["details"] = json.dumps(doc)
        snapshot = build_report_snapshot(asset_uid=ASSET)
        render_report_pdf(snapshot, self.directory / "long.pdf")
        raw = (self.directory / "long.pdf").read_bytes()
        self.assertGreater(len(re.findall(rb"/Type\s*/Page\b", raw)), 1)
        self.assertIn("Report Integrity", pdf_drawn_text(raw))

    def test_untrusted_markup_is_plain_text_without_external_resource_reads(self):
        self.db.data["findings"][0]["title"] = '<img src="https://example.invalid/secret.png"/><b>DATA</b>&'
        self.db.data["history"][0]["reason"] = '<img src="file:///not-authorized"/>\x00literal'
        snapshot = build_report_snapshot(asset_uid=ASSET)
        render_report_pdf(snapshot, self.directory / "escaped.pdf")
        self.network.assert_not_called()
        self.urlopen.assert_not_called()
        self.assertIn("DATA", pdf_drawn_text((self.directory / "escaped.pdf").read_bytes()))

    def test_renderer_uses_snapshot_without_database_or_mutating_it(self):
        snapshot = build_report_snapshot(asset_uid=ASSET)
        before = copy.deepcopy(snapshot)
        with patch("api.analysis_report.get_connection", side_effect=AssertionError("No renderer DB lookup")):
            render_report_pdf(snapshot, self.directory / "snapshot_only.pdf")
        self.assertEqual(snapshot, before)
        self.assertEqual(len(self.db.connections), 1)

    def test_empty_snapshot_renders_sections_without_safe_verdict(self):
        self.db.data["ports"] = []
        snapshot = build_report_snapshot(asset_uid=ASSET)
        render_report_pdf(snapshot, self.directory / "empty.pdf")
        text = pdf_drawn_text((self.directory / "empty.pdf").read_bytes())
        self.assertIn("does not establish security", text)
        self.assertIn("UNASSESSED", text)

    def test_stale_priority_is_explicitly_historical_in_pdf(self):
        self.db.data["assessments"][0]["priority"] = "P1"
        self.db.data["hosts"][0]["criticality"] = "HIGH"
        snapshot = build_report_snapshot(asset_uid=ASSET)
        render_report_pdf(snapshot, self.directory / "stale.pdf")
        text = pdf_drawn_text((self.directory / "stale.pdf").read_bytes())
        self.assertIn("UNASSESSED", text)
        self.assertIn("Historical assessment below is STALE", text)

    def call_cli(self, args):
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = main(args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_cli_json_creates_nested_directory_and_correct_snapshot(self):
        directory = self.directory / "new" / "reports"
        code, stdout, stderr = self.call_cli(["--asset-id", ASSET, "--format", "json", "--output-dir", str(directory)])
        self.assertEqual((code, stderr), (0, ""))
        output = json.loads(stdout)
        self.assertTrue(Path(output["json_path"]).is_file())
        self.assertIsNone(output["pdf_path"])
        saved = json.loads(Path(output["json_path"]).read_text(encoding="utf-8"))
        self.assertEqual(saved["integrity"]["snapshot_sha256"], output["snapshot_sha256"])
        self.assertEqual(snapshot_sha256(saved), output["snapshot_sha256"])
        self.assertEqual(saved["assets"][0]["asset_name"], "로컬 실습 서버")

    def test_cli_pdf_only_and_scan_selection(self):
        code, stdout, stderr = self.call_cli(["--scan-id", "4", "--format", "pdf", "--output-dir", str(self.directory)])
        self.assertEqual((code, stderr), (0, ""))
        output = json.loads(stdout)
        self.assertIsNone(output["json_path"])
        self.assertTrue(Path(output["pdf_path"]).read_bytes().startswith(b"%PDF-"))
        self.assertEqual(output["selection"]["scan_id"], 4)

    def test_default_both_exports_share_one_snapshot_and_one_db_read(self):
        code, stdout, stderr = self.call_cli(["--asset-id", ASSET, "--output-dir", str(self.directory)])
        self.assertEqual((code, stderr), (0, ""))
        output = json.loads(stdout)
        snapshot = json.loads(Path(output["json_path"]).read_text(encoding="utf-8"))
        pdf_text = pdf_drawn_text(Path(output["pdf_path"]).read_bytes())
        self.assertIn(snapshot["integrity"]["snapshot_sha256"], pdf_text)
        self.assertEqual(len(self.db.connections), 1)
        self.assertEqual(list(self.directory.glob(".report-*")), [])
        args = build_parser().parse_args(["--asset-id", ASSET])
        self.assertEqual((args.output_dir, args.format), (Path("reports"), "both"))

    def test_cli_invalid_selection_and_format_fail_without_database(self):
        for args in ([], ["--asset-id", ASSET, "--scan-id", "4"], ["--scan-id", "0"], ["--scan-id", "abc"],
                     ["--asset-id", "127.0.0.1"], ["--asset-id", ASSET, "--format", "html"]):
            code, stdout, stderr = self.call_cli(args)
            self.assertEqual(code, 1)
            self.assertEqual(stdout, "")
            self.assertEqual(json.loads(stderr)["error_code"], "SELECTION_ERROR")
        self.assertEqual(self.db.connections, [])

    def test_cli_database_and_missing_selection_errors_exit_one(self):
        self.db.fail_on = "vuln_risk_assessments"
        code, stdout, stderr = self.call_cli(["--asset-id", ASSET, "--output-dir", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stderr)["error_code"], "DB_ERROR")
        self.assertEqual(list(self.directory.iterdir()), [])
        self.db.fail_on = None
        code, stdout, stderr = self.call_cli(["--scan-id", "999"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stderr)["error_code"], "SELECTION_ERROR")

    def test_render_failure_leaves_no_partial_json_or_pdf(self):
        with patch("api.report_pdf.render_report_pdf", side_effect=RuntimeError("synthetic render failure")):
            code, stdout, stderr = self.call_cli(["--asset-id", ASSET, "--output-dir", str(self.directory)])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stderr)["error_code"], "REPORT_ERROR")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_report_generation_has_no_external_fetch_or_target_probe(self):
        before = copy.deepcopy(self.db.data)
        code, _, _ = self.call_cli(["--asset-id", ASSET, "--output-dir", str(self.directory)])
        self.assertEqual(code, 0)
        self.assertEqual(before, self.db.data)
        self.network.assert_not_called()
        self.urlopen.assert_not_called()
        self.dns.assert_not_called()
        self.probe.assert_not_called()
        self.assertTrue(all(conn.commits == 0 and conn.closed for conn in self.db.connections))

    def test_compatibility_entry_point_is_same_engine(self):
        self.assertIs(generate_final_report, generate_report)
        output = generate_final_report(asset_uid=ASSET, output_dir=self.directory, format="json")
        self.assertTrue(Path(output["json_path"]).is_file())
        with self.assertRaises(TypeError):
            generate_final_report("127.0.0.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
