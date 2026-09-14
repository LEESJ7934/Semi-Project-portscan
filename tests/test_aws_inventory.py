import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from cloud_security.aws_inventory import collect_inventory, validate_region, validate_vpc_id


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": "123456789012", "Arn": "ignored", "UserId": "ignored"}


class FakePaginator:
    def paginate(self, **kwargs):
        self.filters = kwargs["Filters"]
        return [{"Reservations": [{"Instances": [{
            "InstanceId": "i-0123456789abcdef0",
            "VpcId": "vpc-0123abcd",
            "SubnetId": "subnet-0123abcd",
            "PrivateIpAddress": "10.20.2.10",
            "PublicIpAddress": None,
            "State": {"Name": "running"},
            "SecurityGroups": [{"GroupId": "sg-0123abcd", "GroupName": "target"}],
            "Tags": [
                {"Key": "Name", "Value": "portscan-target"},
                {"Key": "api_token", "Value": "must-not-be-copied"},
            ],
        }]}]}]


class FakeEC2:
    def __init__(self):
        self.paginator = FakePaginator()
        self.group_calls = []

    def get_paginator(self, name):
        assert name == "describe_instances"
        return self.paginator

    def describe_security_groups(self, GroupIds):
        self.group_calls.append(GroupIds)
        return {"SecurityGroups": [{
            "GroupId": "sg-0123abcd",
            "GroupName": "target",
            "VpcId": "vpc-0123abcd",
            "IpPermissions": [{
                "IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
                "UserIdGroupPairs": [{"GroupId": "sg-scanner"}],
                "IpRanges": [], "Ipv6Ranges": [],
            }],
        }]}


class AwsInventoryTests(unittest.TestCase):
    def test_collect_inventory_is_normalized_and_filters_one_vpc(self):
        ec2 = FakeEC2()
        result = collect_inventory(
            region="ap-northeast-2",
            vpc_id="vpc-0123abcd",
            sts_client=FakeSTS(),
            ec2_client=ec2,
        )
        self.assertEqual(result["account_id"], "123456789012")
        self.assertEqual(len(result["resources"]), 1)
        resource = result["resources"][0]
        self.assertEqual(resource["private_ip"], "10.20.2.10")
        self.assertEqual(resource["asset_name"], "portscan-target")
        self.assertNotIn("api_token", resource["tags"])
        self.assertEqual(resource["security_groups"][0]["group_id"], "sg-0123abcd")
        self.assertIn({"Name": "vpc-id", "Values": ["vpc-0123abcd"]}, ec2.paginator.filters)

    def test_invalid_region_and_vpc_rejected_before_clients(self):
        for region in ("", "seoul", "ap-northeast", "../../x"):
            with self.subTest(region=region), self.assertRaises(ValueError):
                validate_region(region)
        for vpc in ("vpc-", "not-vpc", "vpc-xyz"):
            with self.subTest(vpc=vpc), self.assertRaises(ValueError):
                validate_vpc_id(vpc)

    def test_one_missing_injected_client_is_rejected(self):
        with self.assertRaises(ValueError):
            collect_inventory(region="ap-northeast-2", sts_client=FakeSTS())


if __name__ == "__main__":
    unittest.main()
