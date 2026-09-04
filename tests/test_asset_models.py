import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from asset_management import (  # noqa: E402
    normalize_asset_updates,
    normalize_ip_address,
)


class AssetModelTests(unittest.TestCase):
    def test_ipv6_is_canonicalized(self):
        self.assertEqual(
            normalize_ip_address(
                "2001:0db8:0000:0000:0000:0000:0000:0001"
            ),
            "2001:db8::1",
        )

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_ip_address("not-an-ip")

    def test_metadata_is_normalized(self):
        result = normalize_asset_updates(
            {
                "criticality": "high",
                "asset_name": "  Payment API  ",
                "handles_personal_data": True,
            }
        )

        self.assertEqual(result["criticality"], "HIGH")
        self.assertEqual(result["asset_name"], "Payment API")
        self.assertIs(
            result["handles_personal_data"],
            True,
        )

    def test_unknown_field_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_asset_updates(
                {"database_password": "secret"}
            )

    def test_non_boolean_flag_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_asset_updates(
                {"internet_exposed": "yes"}
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
