import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from db.cloud_repository import save_inventory, sync_configuration_findings


class FakeCursor:
    def __init__(self):
        self.executions = []
        self.lastrowid = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.executions.append((" ".join(sql.split()), params))
        if "INSERT INTO hosts" in sql:
            self.lastrowid = 10
        elif "INSERT INTO cloud_resources" in sql:
            self.lastrowid = 20


class FakeConnection:
    def __init__(self):
        self.cursor_object = FakeCursor()

    def cursor(self, **_kwargs):
        return self.cursor_object


class CloudRepositoryTests(unittest.TestCase):
    def test_inventory_upserts_host_and_cloud_resource_without_commit(self):
        conn = FakeConnection()
        mapping = save_inventory(conn, {
            "account_id": "123456789012",
            "region": "ap-northeast-2",
            "vpc_id_filter": "vpc-demo",
            "resources": [{
                "resource_id": "i-demo", "vpc_id": "vpc-demo", "subnet_id": "subnet-demo",
                "private_ip": "10.20.2.10", "public_ip": None, "asset_name": "target",
                "instance_state": "running", "security_groups": [], "tags": {"Name": "target"},
            }],
        })
        self.assertEqual(mapping["i-demo"], {"host_id": 10, "cloud_resource_id": 20})
        sql = " ".join(item[0] for item in conn.cursor_object.executions)
        self.assertIn("asset_type", sql)
        self.assertIn("cloud_resources", sql)
        self.assertNotIn("COMMIT", sql.upper())

    def test_inventory_save_requires_one_vpc_filter(self):
        with self.assertRaises(ValueError):
            save_inventory(FakeConnection(), {
                "account_id": "123456789012",
                "region": "ap-northeast-2",
                "resources": [],
            })

    def test_findings_upsert_and_resolve_unobserved_rules(self):
        conn = FakeConnection()
        count = sync_configuration_findings(
            conn,
            {"i-demo": {"host_id": 10, "cloud_resource_id": 20}},
            [{
                "resource_id": "i-demo", "rule_id": "AWS-SG-001", "category": "NETWORK_EXPOSURE",
                "title": "SSH broad", "severity": "HIGH", "priority": "P3",
                "public_address_present": False, "evidence": {"safe": True},
                "remediation": "restrict", "input_sha256": "a" * 64,
            }],
        )
        self.assertEqual(count, 1)
        texts = [sql for sql, _ in conn.cursor_object.executions]
        self.assertTrue(any("INSERT INTO cloud_configuration_findings" in sql for sql in texts))
        self.assertTrue(any("status='RESOLVED'" in sql and "NOT IN" in sql for sql in texts))

    def test_no_findings_resolves_existing_open_findings_for_reviewed_resource(self):
        conn = FakeConnection()
        count = sync_configuration_findings(
            conn,
            {"i-demo": {"host_id": 10, "cloud_resource_id": 20}},
            [],
        )
        self.assertEqual(count, 0)
        self.assertTrue(any("status='RESOLVED'" in sql for sql, _ in conn.cursor_object.executions))


if __name__ == "__main__":
    unittest.main()
