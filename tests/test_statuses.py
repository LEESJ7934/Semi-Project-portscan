import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(
    0,
    str(PROJECT_ROOT),
)

from db.statuses import (  # noqa: E402
    ScanStatus,
    VulnStatus,
    normalize_scan_status,
    normalize_vuln_status,
    validate_vuln_transition,
)


class StatusNormalizationTests(
    unittest.TestCase
):
    def test_done_becomes_completed(self):
        self.assertEqual(
            normalize_scan_status("DONE"),
            ScanStatus.COMPLETED.value,
        )

    def test_invalid_becomes_false_positive(
        self,
    ):
        self.assertEqual(
            normalize_vuln_status("INVALID"),
            VulnStatus.FALSE_POSITIVE.value,
        )

    def test_rejected_becomes_false_positive(
        self,
    ):
        self.assertEqual(
            normalize_vuln_status("REJECTED"),
            VulnStatus.FALSE_POSITIVE.value,
        )

    def test_skip_becomes_not_applicable(
        self,
    ):
        self.assertEqual(
            normalize_vuln_status("SKIP"),
            VulnStatus.NOT_APPLICABLE.value,
        )

    def test_unknown_status_is_rejected(
        self,
    ):
        with self.assertRaises(ValueError):
            normalize_vuln_status(
                "UNKNOWN_STATUS"
            )


class StatusTransitionTests(
    unittest.TestCase
):
    def test_candidate_can_become_potential(
        self,
    ):
        self.assertEqual(
            validate_vuln_transition(
                VulnStatus.CANDIDATE,
                VulnStatus.POTENTIAL,
            ),
            (
                VulnStatus.CANDIDATE.value,
                VulnStatus.POTENTIAL.value,
            ),
        )

    def test_confirmed_can_be_closed(self):
        self.assertEqual(
            validate_vuln_transition(
                VulnStatus.CONFIRMED,
                VulnStatus.CLOSED,
            ),
            (
                VulnStatus.CONFIRMED.value,
                VulnStatus.CLOSED.value,
            ),
        )

    def test_retest_can_be_not_applicable(
        self,
    ):
        self.assertEqual(
            validate_vuln_transition(
                VulnStatus.RETEST_REQUIRED,
                VulnStatus.NOT_APPLICABLE,
            ),
            (
                VulnStatus.RETEST_REQUIRED.value,
                VulnStatus.NOT_APPLICABLE.value,
            ),
        )

    def test_potential_cannot_close_directly(
        self,
    ):
        with self.assertRaises(ValueError):
            validate_vuln_transition(
                VulnStatus.POTENTIAL,
                VulnStatus.CLOSED,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)