import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.scope import (  # noqa: E402
    ScopePolicy,
    ScopeValidationError,
)
from scanner.targets import ResolvedTarget  # noqa: E402


def make_policy(**overrides):
    data = {
        "scope_uid": "test-scope-v1",
        "name": "Unit test scope",
        "authorization_ref": "AUTH-001",
        "approved_by": "security-owner",
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_until": "2027-01-01T00:00:00+00:00",
        "allowed_targets": [
            "10.0.0.0/24",
            "lab.example.com",
        ],
        "max_targets": 16,
        "max_workers": 50,
        "max_ports_per_target": 100,
    }
    data.update(overrides)
    return ScopePolicy.from_dict(data)


class ScopePolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(
            2026,
            6,
            1,
            tzinfo=timezone.utc,
        )

    def test_ip_inside_network_is_allowed(self):
        policy = make_policy()
        target = ResolvedTarget(
            ip="10.0.0.25",
            input_target="10.0.0.25",
            resolution_type="IP",
        )
        policy.authorize(
            [target],
            worker_count=10,
            port_count=20,
            now=self.now,
        )

    def test_exact_hostname_is_allowed(self):
        policy = make_policy()
        target = ResolvedTarget(
            ip="203.0.113.10",
            input_target="lab.example.com",
            resolution_type="HOSTNAME",
        )
        policy.authorize(
            [target],
            worker_count=10,
            port_count=20,
            now=self.now,
        )

    def test_out_of_scope_ip_is_rejected(self):
        policy = make_policy()
        target = ResolvedTarget(
            ip="10.1.0.1",
            input_target="10.1.0.1",
            resolution_type="IP",
        )

        with self.assertRaises(ScopeValidationError):
            policy.authorize(
                [target],
                worker_count=10,
                port_count=20,
                now=self.now,
            )

    def test_expired_scope_is_rejected(self):
        policy = make_policy(
            valid_until="2026-05-01T00:00:00+00:00"
        )
        target = ResolvedTarget(
            ip="10.0.0.1",
            input_target="10.0.0.1",
            resolution_type="IP",
        )

        with self.assertRaises(ScopeValidationError):
            policy.authorize(
                [target],
                worker_count=10,
                port_count=20,
                now=self.now,
            )

    def test_worker_limit_is_enforced(self):
        policy = make_policy(max_workers=10)
        target = ResolvedTarget(
            ip="10.0.0.1",
            input_target="10.0.0.1",
            resolution_type="IP",
        )

        with self.assertRaises(ScopeValidationError):
            policy.authorize(
                [target],
                worker_count=11,
                port_count=20,
                now=self.now,
            )

    def test_policy_fingerprint_is_stable(self):
        first = make_policy()
        second = make_policy()
        self.assertEqual(
            first.fingerprint,
            second.fingerprint,
        )
        self.assertEqual(len(first.fingerprint), 64)

    def test_naive_validity_time_is_rejected(self):
        with self.assertRaises(ScopeValidationError):
            make_policy(
                valid_from="2026-01-01T00:00:00"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
