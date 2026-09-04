import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from db.save_scan_results import save_scan_results  # noqa: E402


class SaveScanResultsTests(unittest.TestCase):
    @patch("db.save_scan_results.record_scan_asset")
    @patch("db.save_scan_results.upsert_port")
    @patch("db.save_scan_results.upsert_host")
    @patch("db.save_scan_results.insert_scan")
    @patch("db.save_scan_results.upsert_scan_scope")
    @patch("db.save_scan_results.get_connection")
    def test_scope_asset_and_open_port_are_saved(
        self,
        get_connection,
        upsert_scan_scope,
        insert_scan,
        upsert_host,
        upsert_port,
        record_scan_asset,
    ):
        connection = MagicMock()
        get_connection.return_value = connection
        upsert_scan_scope.return_value = 3
        insert_scan.return_value = 10
        upsert_host.return_value = 20
        upsert_port.return_value = 30
        scope = {
            "scope_uid": "test-scope",
            "name": "Test scope",
            "authorization_ref": "AUTH-1",
            "approved_by": "tester",
            "valid_from": "2026-01-01T00:00:00+00:00",
            "valid_until": "2027-01-01T00:00:00+00:00",
            "allowed_targets": ["127.0.0.1"],
            "max_targets": 1,
            "max_workers": 10,
            "max_ports_per_target": 100,
        }
        result = {
            "scan_id": "scan-test",
            "scan_type": "tcp",
            "port_range": "22,80",
            "started_at": "2026-06-01 10:00:00",
            "finished_at": "2026-06-01 10:00:01",
            "requested_targets": ["localhost"],
            "scope": scope,
            "config": {"max_workers": 10},
            "targets": [
                {
                    "ip": "127.0.0.1",
                    "input_target": "localhost",
                    "resolution_type": "HOSTNAME",
                    "results": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": None,
                            "banner": None,
                        },
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "closed",
                            "service": "http",
                            "version": None,
                            "banner": None,
                        },
                    ],
                }
            ],
        }

        scan_id = save_scan_results(result)

        self.assertEqual(scan_id, 10)
        upsert_scan_scope.assert_called_once_with(
            connection,
            scope,
        )
        self.assertEqual(
            insert_scan.call_args.kwargs["scope_id"],
            3,
        )
        self.assertEqual(
            insert_scan.call_args.kwargs[
                "requested_targets"
            ],
            ["localhost"],
        )
        upsert_host.assert_called_once()
        upsert_port.assert_called_once()
        record_scan_asset.assert_called_once_with(
            conn=connection,
            scan_id=10,
            host_id=20,
            input_target="localhost",
            resolution_type="HOSTNAME",
            result_status="SCANNED",
            open_port_count=1,
        )
        connection.commit.assert_called_once()
        connection.rollback.assert_not_called()
        connection.close.assert_called_once()

    @patch("db.save_scan_results.insert_scan")
    @patch("db.save_scan_results.get_connection")
    def test_database_error_rolls_back(
        self,
        get_connection,
        insert_scan,
    ):
        connection = MagicMock()
        get_connection.return_value = connection
        insert_scan.side_effect = RuntimeError("db failed")
        result = {
            "scan_id": "scan-test",
            "started_at": "2026-06-01 10:00:00",
            "finished_at": "2026-06-01 10:00:01",
            "targets": [],
        }

        with self.assertRaises(RuntimeError):
            save_scan_results(result)

        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()
        connection.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
