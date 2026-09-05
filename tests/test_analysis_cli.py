import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analysis.run_analysis import main

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "day4_ports.json"


class AnalysisCliTests(unittest.TestCase):
    def test_offline_example_neither_connects_nor_saves(self):
        output = io.StringIO()
        with patch("socket.create_connection") as connect, \
             patch("db.query_helpers.get_connection") as database, \
             patch("analysis.save_vulns.save_vulns") as save, \
             contextlib.redirect_stdout(output):
            code = main(["--input", str(EXAMPLE)])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["candidate_count"], 3)
        self.assertEqual(report["mode"], "PREVIEW")
        connect.assert_not_called()
        database.assert_not_called()
        save.assert_not_called()

    def test_input_cannot_be_written_to_real_database(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["--input", str(EXAMPLE), "--save"])
        self.assertEqual(raised.exception.code, 2)

    def test_database_preview_is_read_only(self):
        with patch("db.query_helpers.get_all_ports", return_value=[]) as query, \
             patch("analysis.save_vulns.save_vulns") as save, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            code = main(["--scan-id", "3"])
        self.assertEqual(code, 0)
        query.assert_called_once_with(scan_id=3, asset_uid=None)
        save.assert_not_called()
        self.assertIn("No current open TCP", json.loads(output.getvalue())["selection_note"])

    def test_explicit_save_and_output_file(self):
        records = json.loads(EXAMPLE.read_text())[:1]
        with tempfile.TemporaryDirectory() as directory, \
             patch("db.query_helpers.get_all_ports", return_value=records), \
             patch("analysis.save_vulns.save_vulns", return_value=[17]) as save, \
             contextlib.redirect_stdout(io.StringIO()):
            path = Path(directory) / "report.json"
            self.assertEqual(main(["--scan-id", "4", "--save", "--output", str(path)]), 0)
            report = json.loads(path.read_text())
        self.assertEqual(report["saved_vuln_ids"], [17])
        self.assertEqual(save.call_args.args[0][0]["status"], "CANDIDATE")

    def test_invalid_input_has_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            path = Path(directory) / "bad.json"
            path.write_text('{"wrong":"shape"}')
            self.assertEqual(main(["--input", str(path)]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
