import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from db.asset_repository import (  # noqa: E402
    record_scan_asset,
    update_asset_metadata,
    upsert_scan_scope,
)


class FakeCursor:
    def __init__(self, responses=None, lastrowid=1):
        self.responses = list(responses or [])
        self.lastrowid = lastrowid
        self.executions = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.executions.append((sql, params))

    def fetchone(self):
        if not self.responses:
            return None
        return self.responses.pop(0)

    def fetchall(self):
        if not self.responses:
            return []
        return self.responses.pop(0)


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self, **_kwargs):
        return self._cursor


def scope_data():
    return {
        "scope_uid": "scope-test",
        "name": "Test scope",
        "authorization_ref": "AUTH-TEST",
        "approved_by": "tester",
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_until": "2027-01-01T00:00:00+00:00",
        "allowed_targets": ["127.0.0.1"],
        "max_targets": 1,
        "max_workers": 10,
        "max_ports_per_target": 100,
    }


class AssetRepositoryTests(unittest.TestCase):
    def test_scan_scope_is_upserted(self):
        cursor = FakeCursor(lastrowid=7)
        connection = FakeConnection(cursor)

        result = upsert_scan_scope(
            connection,
            scope_data(),
        )

        self.assertEqual(result, 7)
        self.assertEqual(len(cursor.executions), 1)
        _sql, params = cursor.executions[0]
        self.assertEqual(params[0], "scope-test")
        self.assertEqual(len(params[-1]), 64)

    def test_tampered_scope_hash_is_rejected(self):
        data = scope_data()
        data["policy_sha256"] = "0" * 64

        with self.assertRaises(ValueError):
            upsert_scan_scope(
                FakeConnection(FakeCursor()),
                data,
            )

    def test_scan_asset_values_are_normalized(self):
        cursor = FakeCursor(lastrowid=11)
        result = record_scan_asset(
            FakeConnection(cursor),
            scan_id=2,
            host_id=3,
            input_target="127.0.0.1",
            resolution_type="ip",
            result_status="scanned",
            open_port_count=2,
        )

        self.assertEqual(result, 11)
        _sql, params = cursor.executions[0]
        self.assertEqual(params[3], "IP")
        self.assertEqual(params[4], "SCANNED")

    def test_metadata_update_writes_audit_history(self):
        current = {
            "id": 5,
            "asset_uid": "asset-1",
            "criticality": "UNASSIGNED",
            "owner": None,
        }
        updated = {
            **current,
            "criticality": "HIGH",
            "owner": "security-team",
        }
        cursor = FakeCursor(
            responses=[current, updated]
        )

        result = update_asset_metadata(
            FakeConnection(cursor),
            asset_uid="asset-1",
            updates={
                "criticality": "high",
                "owner": "security-team",
            },
            changed_by="tester",
            reason="initial classification",
        )

        self.assertEqual(result, updated)
        self.assertEqual(len(cursor.executions), 6)
        update_sql = cursor.executions[1][0]
        self.assertIn("criticality = %s", update_sql)
        history_params = cursor.executions[2][1]
        self.assertEqual(history_params[1], "criticality")
        self.assertEqual(history_params[2], "UNASSIGNED")
        self.assertEqual(history_params[3], "HIGH")
        owner_update_sql = cursor.executions[3][0]
        self.assertIn("owner = %s", owner_update_sql)

    def test_unchanged_metadata_does_not_write_history(self):
        current = {
            "id": 5,
            "asset_uid": "asset-1",
            "criticality": "HIGH",
        }
        cursor = FakeCursor(responses=[current])

        result = update_asset_metadata(
            FakeConnection(cursor),
            asset_uid="asset-1",
            updates={"criticality": "HIGH"},
            changed_by="tester",
            reason="no change",
        )

        self.assertEqual(result, current)
        self.assertEqual(len(cursor.executions), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
