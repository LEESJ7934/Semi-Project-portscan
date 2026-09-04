import socket
import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scanner.targets import (  # noqa: E402
    normalize_hostname,
    resolve_target_specs,
)


def fake_resolver(hostname, *_args, **_kwargs):
    if hostname != "lab.example.com":
        raise socket.gaierror("not found")

    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("10.20.30.40", 0),
        ),
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("10.20.30.40", 0),
        ),
    ]


class TargetResolutionTests(unittest.TestCase):
    def test_single_ip(self):
        targets = resolve_target_specs(["127.0.0.1"])
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ip, "127.0.0.1")
        self.assertEqual(
            targets[0].resolution_type,
            "IP",
        )

    def test_cidr_expands_usable_hosts(self):
        targets = resolve_target_specs(
            ["192.168.10.0/30"],
            max_targets=4,
        )
        self.assertEqual(
            [target.ip for target in targets],
            ["192.168.10.1", "192.168.10.2"],
        )
        self.assertTrue(
            all(
                target.resolution_type == "CIDR"
                for target in targets
            )
        )

    def test_hostname_is_resolved_and_deduplicated(self):
        targets = resolve_target_specs(
            ["LAB.example.com."],
            resolver=fake_resolver,
        )
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ip, "10.20.30.40")
        self.assertEqual(
            targets[0].input_target,
            "lab.example.com",
        )
        self.assertEqual(
            targets[0].resolution_type,
            "HOSTNAME",
        )

    def test_duplicates_across_inputs_are_removed(self):
        targets = resolve_target_specs(
            ["192.168.10.1", "192.168.10.0/30"]
        )
        self.assertEqual(
            [target.ip for target in targets],
            ["192.168.10.1", "192.168.10.2"],
        )

    def test_large_cidr_is_rejected_before_expansion(self):
        with self.assertRaises(ValueError):
            resolve_target_specs(
                ["10.0.0.0/8"],
                max_targets=16,
            )

    def test_invalid_hostname_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_hostname("bad_host.example.com")

    def test_unresolved_hostname_is_rejected(self):
        with self.assertRaises(ValueError):
            resolve_target_specs(
                ["missing.example.com"],
                resolver=fake_resolver,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
