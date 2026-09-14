import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cloud_security.aws_sg_analyzer import analyze_security_groups


def inventory(permission, public_ip=None):
    return {"resources": [{
        "resource_id": "i-demo",
        "private_ip": "10.20.2.10",
        "public_ip": public_ip,
        "vpc_id": "vpc-demo",
        "security_groups": [{"group_id": "sg-demo", "ip_permissions": [permission]}],
    }]}


class AwsSecurityGroupAnalyzerTests(unittest.TestCase):
    def test_ssh_world_open_is_high_and_private_only_is_p3(self):
        findings = analyze_security_groups(inventory({
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
        }))
        self.assertEqual([(f["rule_id"], f["severity"], f["priority"]) for f in findings],
                         [("AWS-SG-001", "HIGH", "P3")])
        self.assertFalse(findings[0]["public_address_present"])
        self.assertIn("not evaluated", findings[0]["evidence"]["reachability_limit"])

    def test_public_address_raises_context_priority_but_not_reachability_claim(self):
        finding = analyze_security_groups(inventory({
            "IpProtocol": "tcp", "FromPort": 3306, "ToPort": 3306,
            "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }, public_ip="203.0.113.10"))[0]
        self.assertEqual((finding["rule_id"], finding["priority"]), ("AWS-SG-003", "P2"))
        self.assertTrue(finding["public_address_present"])

    def test_public_web_port_alone_is_not_a_finding(self):
        findings = analyze_security_groups(inventory({
            "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
        }, public_ip="203.0.113.10"))
        self.assertEqual(findings, [])

    def test_all_protocol_world_open_is_single_critical_rule(self):
        findings = analyze_security_groups(inventory({
            "IpProtocol": "-1",
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": [],
        }, public_ip="203.0.113.10"))
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0]["rule_id"], findings[0]["severity"], findings[0]["priority"]),
                         ("AWS-SG-006", "CRITICAL", "P1"))

    def test_security_group_reference_is_not_internet_wide(self):
        findings = analyze_security_groups(inventory({
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "UserIdGroupPairs": [{"GroupId": "sg-scanner"}],
            "IpRanges": [], "Ipv6Ranges": [],
        }))
        self.assertEqual(findings, [])

    def test_duplicate_permissions_aggregate_into_one_stable_finding(self):
        inv = {"resources": [{
            "resource_id": "i-demo", "private_ip": "10.20.2.10", "public_ip": None, "vpc_id": "vpc-demo",
            "security_groups": [
                {"group_id": "sg-b", "ip_permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                           "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
                {"group_id": "sg-a", "ip_permissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                                                           "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]},
            ],
        }]}
        first = analyze_security_groups(inv)
        second = analyze_security_groups(inv)
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["input_sha256"], second[0]["input_sha256"])
        self.assertEqual([m["security_group_id"] for m in first[0]["evidence"]["matched_permissions"]], ["sg-a", "sg-b"])


    def test_legacy_lab_ftp_and_telnet_world_open_are_findings(self):
        inv = {"resources": [{
            "resource_id": "i-legacy", "private_ip": "172.31.36.74",
            "public_ip": "203.0.113.10", "vpc_id": "vpc-legacy",
            "security_groups": [{"group_id": "sg-legacy", "ip_permissions": [
                {"IpProtocol": "tcp", "FromPort": 21, "ToPort": 21,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
                {"IpProtocol": "tcp", "FromPort": 23, "ToPort": 23,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []},
            ]}],
        }]}
        findings = analyze_security_groups(inv)
        self.assertEqual(
            [(f["rule_id"], f["severity"], f["priority"]) for f in findings],
            [("AWS-SG-007", "HIGH", "P2"), ("AWS-SG-008", "HIGH", "P2")],
        )


if __name__ == "__main__":
    unittest.main()
