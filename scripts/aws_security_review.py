from __future__ import annotations

import argparse
import os
from typing import Sequence

from cloud_security.aws_inventory import AwsInventoryError, collect_inventory
from cloud_security.aws_sg_analyzer import analyze_security_groups


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only AWS Security Group review")
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--vpc-id", help="limit review to one VPC; required with --save")
    parser.add_argument("--save", action="store_true", help="persist inventory and configuration findings")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.save and not args.vpc_id:
        raise SystemExit("--save 사용 시 --vpc-id가 필요합니다.")
    try:
        inventory = collect_inventory(region=args.region, vpc_id=args.vpc_id)
        findings = analyze_security_groups(inventory)
    except (ValueError, AwsInventoryError) as exc:
        print(f"[ERROR] {exc}")
        return 2

    print(f"Reviewed resources: {len(inventory['resources'])}")
    print(f"Configuration findings: {len(findings)}")
    for finding in findings:
        print(
            f"  {finding['rule_id']} {finding['severity']} {finding['priority']} "
            f"{finding['resource_id']} - {finding['title']}"
        )

    if args.save:
        from db.cloud_repository import save_inventory, sync_configuration_findings
        from db.db_client import get_connection
        conn = get_connection()
        try:
            mapping = save_inventory(conn, inventory)
            count = sync_configuration_findings(conn, mapping, findings)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        print(f"Saved/updated findings: {count}")
    else:
        print("[DRY-RUN] AWS API was read-only; no database write was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
