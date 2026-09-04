import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.run_scan import (  # noqa: E402
    determine_scan_mode,
    main,
)
from scanner.utils import parse_ports  # noqa: E402


class ScanCliTests(unittest.TestCase):
    def _saved_port_range(self, expression=None):
        args = ["scan", "--target", "127.0.0.1"]
        if expression is not None:
            args.extend(["--ports", expression])

        with (
            patch(
                "scanner.scan_runner.threaded_scan",
                return_value=[],
            ),
            patch("db.save_scan_results.get_connection") as get_connection,
            patch(
                "db.save_scan_results.resolve_hostname",
                return_value=None,
            ),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            connection = get_connection.return_value
            cursor = connection.cursor.return_value.__enter__.return_value
            cursor.lastrowid = 1
            self.assertEqual(main(args), 0)

        scan_insert = next(
            call for call in cursor.execute.call_args_list
            if "INSERT INTO scans (" in call.args[0]
        )
        return scan_insert.args[1][5]

    def test_default_port_range_reaches_database_as_compact_text(self):
        self.assertEqual(self._saved_port_range(), "1-1024")

    def test_mixed_port_ranges_preserve_exact_selection(self):
        stored = self._saved_port_range("443,22,80-82,80")
        self.assertEqual(stored, "22,80-82,443")
        self.assertEqual(parse_ports(stored), [22, 80, 81, 82, 443])

    def test_long_sparse_port_list_is_saved_without_truncation(self):
        selected = list(range(1, 2048, 2))
        expression = ",".join(map(str, selected))
        self.assertGreater(len(expression), 100)
        stored = self._saved_port_range(expression)
        self.assertEqual(stored, expression)
        self.assertEqual(parse_ports(stored), selected)

    def test_default_mode_is_tcp(self):
        self.assertEqual(
            determine_scan_mode(False, False),
            ("tcp", False, False),
        )

    def test_both_flags_enable_tcp_and_udp(self):
        self.assertEqual(
            determine_scan_mode(True, True),
            ("tcp+udp", True, False),
        )

    @patch("scripts.run_scan.run_scan")
    def test_dry_run_does_not_start_scanner(
        self,
        run_scan,
    ):
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "scan",
                    "--target",
                    "127.0.0.1",
                    "--ports",
                    "22,80",
                    "--dry-run",
                ]
            )

        self.assertEqual(exit_code, 0)
        run_scan.assert_not_called()
        self.assertIn("[DRY-RUN]", output.getvalue())

    @patch("scripts.run_scan.run_scan")
    def test_out_of_scope_target_is_blocked(
        self,
        run_scan,
    ):
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                main(
                    [
                        "scan",
                        "--target",
                        "192.0.2.10",
                        "--ports",
                        "53",
                        "--dry-run",
                    ]
                )

        self.assertEqual(raised.exception.code, 2)
        run_scan.assert_not_called()
        self.assertIn(
            "승인 범위를 벗어난 대상",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
