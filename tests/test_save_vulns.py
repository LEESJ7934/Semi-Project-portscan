import unittest
from unittest.mock import MagicMock, patch

from analysis.save_vulns import save_vulns
from analysis.vuln_mapper import map_vulns


def candidate():
    return map_vulns([{"port_id": 8, "scan_id": 4, "port": 8081, "protocol": "tcp", "state": "open",
                       "service": "http", "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.50\r\n\r\n"}])[0]


class SaveCandidateTests(unittest.TestCase):
    def setUp(self):
        self.connection = MagicMock()
        self.cursor = self.connection.cursor.return_value.__enter__.return_value
        self.cursor.fetchone.return_value = None

    def test_unknown_scores_stay_null_and_reason_is_saved(self):
        with patch("analysis.save_vulns.get_connection", return_value=self.connection), \
             patch("analysis.save_vulns.upsert_vuln", return_value=20) as upsert, \
             patch("analysis.save_vulns.insert_vuln_evidence") as evidence:
            self.assertEqual(save_vulns([candidate()]), [20])
        self.assertIsNone(upsert.call_args.kwargs["cvss"])
        self.assertIsNone(upsert.call_args.kwargs["epss"])
        self.assertIsNone(upsert.call_args.kwargs["risk"])
        self.assertIn("match_reason", evidence.call_args.kwargs["details"])
        self.assertEqual(len(evidence.call_args.kwargs["sha256"]), 64)
        self.connection.commit.assert_called_once()
        self.connection.close.assert_called_once()

    def test_same_evidence_is_not_inserted_twice(self):
        self.cursor.fetchone.return_value = (50,)
        with patch("analysis.save_vulns.get_connection", return_value=self.connection), \
             patch("analysis.save_vulns.upsert_vuln", return_value=20), \
             patch("analysis.save_vulns.insert_vuln_evidence") as evidence:
            save_vulns([candidate()])
        evidence.assert_not_called()

    def test_evidence_failure_rolls_back_candidate_too(self):
        with patch("analysis.save_vulns.get_connection", return_value=self.connection), \
             patch("analysis.save_vulns.upsert_vuln", return_value=20), \
             patch("analysis.save_vulns.insert_vuln_evidence", side_effect=RuntimeError("test failure")):
            with self.assertRaises(RuntimeError):
                save_vulns([candidate()])
        self.connection.rollback.assert_called_once()
        self.connection.commit.assert_not_called()
        self.connection.close.assert_called_once()

    def test_invalid_status_scores_or_ids_do_not_open_database(self):
        for change in ({"status": "CONFIRMED"}, {"port_id": None}, {"port_id": True},
                       {"cvss": float("nan")}, {"epss": 2}, {"risk": -1}):
            item = {**candidate(), **change}
            with self.subTest(change=change), patch("analysis.save_vulns.get_connection") as connect:
                with self.assertRaises(ValueError):
                    save_vulns([item])
                connect.assert_not_called()

    def test_empty_candidates_do_not_connect(self):
        with patch("analysis.save_vulns.get_connection") as connect:
            self.assertEqual(save_vulns([]), [])
        connect.assert_not_called()



if __name__ == "__main__":
    unittest.main(verbosity=2)
