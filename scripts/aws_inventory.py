from __future__ import annotations

import argparse
import os
from typing import Sequence

from cloud_security.aws_inventory import AwsInventoryError, collect_inventory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only AWS EC2 inventory")
    parser.add_argument("--region", default=os.getenv("AWS_REGION", "ap-northeast-2"))
    parser.add_argument("--vpc-id", help="limit inventory to one VPC; required with --save")
    parser.add_argument("--save", action="store_true", help="persist inventory to MySQL V6 tables")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.save and not args.vpc_id:
        raise SystemExit("--save 사용 시 --vpc-id가 필요합니다. Private IP 충돌 방지를 위해 한 VPC만 저장합니다.")
    try:
        inventory = collect_inventory(region=args.region, vpc_id=args.vpc_id)
    except (ValueError, AwsInventoryError) as exc:
        print(f"[ERROR] {exc}")
        return 2

    print(f"Provider: {inventory['provider']}")
    print(f"Region: {inventory['region']}")
    print(f"Account: {inventory['account_id']}")
    print(f"Resources: {len(inventory['resources'])}")
    for resource in inventory["resources"]:
        print(
            f"  {resource['resource_id']}  {resource['private_ip']}  "
            f"public={resource.get('public_ip') or '-'}  vpc={resource['vpc_id']}"
        )

    if args.save:
        from db.cloud_repository import save_inventory
        from db.db_client import get_connection
        conn = get_connection()
        try:
            mapping = save_inventory(conn, inventory)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
        print(f"Saved cloud resources: {len(mapping)}")
    else:
        print("[DRY-RUN] AWS API was read-only; no database write was performed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
