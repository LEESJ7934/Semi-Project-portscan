from __future__ import annotations

import argparse
import json
from typing import Any, Sequence

from asset_management import (
    AssetCriticality,
    AssetEnvironment,
    AssetLifecycleStatus,
    AssetType,
    DataClassification,
)
from db.asset_repository import (
    get_asset_by_id,
    get_asset_by_uid,
    get_asset_history,
    list_assets,
    update_asset_metadata,
)
from db.db_client import get_connection
from db.query_helpers import upsert_host


def _enum_choices(enum_class: type) -> list[str]:
    return [item.value for item in enum_class]


def _add_metadata_arguments(
    parser: argparse.ArgumentParser,
) -> None:
    parser.add_argument("--name", dest="asset_name")
    parser.add_argument(
        "--type",
        dest="asset_type",
        choices=_enum_choices(AssetType),
    )
    parser.add_argument(
        "--environment",
        choices=_enum_choices(AssetEnvironment),
    )
    parser.add_argument(
        "--criticality",
        choices=_enum_choices(AssetCriticality),
    )
    parser.add_argument("--owner")
    parser.add_argument("--business-unit")
    parser.add_argument(
        "--data-classification",
        choices=_enum_choices(DataClassification),
    )
    parser.add_argument(
        "--personal-data",
        dest="handles_personal_data",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument(
        "--internet-exposed",
        action=argparse.BooleanOptionalAction,
        default=None,
    )
    parser.add_argument("--notes")


def _metadata_from_args(args: argparse.Namespace) -> dict:
    field_names = (
        "asset_name",
        "asset_type",
        "environment",
        "criticality",
        "owner",
        "business_unit",
        "data_classification",
        "handles_personal_data",
        "internet_exposed",
        "lifecycle_status",
        "notes",
    )
    return {
        field_name: getattr(args, field_name)
        for field_name in field_names
        if hasattr(args, field_name)
        and getattr(args, field_name) is not None
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Asset inventory management"
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    list_parser = subparsers.add_parser(
        "list",
        help="list assets",
    )
    list_parser.add_argument(
        "--status",
        choices=_enum_choices(AssetLifecycleStatus),
    )
    list_parser.add_argument(
        "--criticality",
        choices=_enum_choices(AssetCriticality),
    )
    list_parser.add_argument(
        "--limit",
        type=int,
        default=200,
    )

    show_parser = subparsers.add_parser(
        "show",
        help="show one asset",
    )
    show_parser.add_argument("--asset-id", required=True)

    register_parser = subparsers.add_parser(
        "register",
        help="register or enrich an asset",
    )
    register_parser.add_argument("--ip", required=True)
    register_parser.add_argument("--hostname")
    register_parser.add_argument(
        "--changed-by",
        required=True,
    )
    register_parser.add_argument(
        "--reason",
        required=True,
    )
    _add_metadata_arguments(register_parser)

    update_parser = subparsers.add_parser(
        "update",
        help="update asset metadata",
    )
    update_parser.add_argument("--asset-id", required=True)
    update_parser.add_argument(
        "--status",
        dest="lifecycle_status",
        choices=_enum_choices(AssetLifecycleStatus),
    )
    update_parser.add_argument(
        "--changed-by",
        required=True,
    )
    update_parser.add_argument(
        "--reason",
        required=True,
    )
    _add_metadata_arguments(update_parser)

    history_parser = subparsers.add_parser(
        "history",
        help="show asset metadata changes",
    )
    history_parser.add_argument("--asset-id", required=True)
    history_parser.add_argument(
        "--limit",
        type=int,
        default=100,
    )
    return parser


def _print_json(value: Any) -> None:
    print(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            default=str,
        )
    )


def _print_asset_table(
    assets: list[dict[str, Any]],
) -> None:
    headers = (
        "ASSET_ID",
        "IP",
        "NAME",
        "CRITICALITY",
        "ENVIRONMENT",
        "STATUS",
        "OPEN_PORTS",
        "SCANS",
    )
    print("\t".join(headers))

    for asset in assets:
        print(
            "\t".join(
                str(value if value is not None else "-")
                for value in (
                    asset["asset_uid"],
                    asset["host_ip"],
                    asset["asset_name"],
                    asset["criticality"],
                    asset["environment"],
                    asset["lifecycle_status"],
                    asset["open_port_count"],
                    asset["scan_count"],
                )
            )
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    conn = get_connection()

    try:
        if args.command == "list":
            assets = list_assets(
                conn,
                lifecycle_status=args.status,
                criticality=args.criticality,
                limit=args.limit,
            )
            _print_asset_table(assets)
            return 0

        if args.command == "show":
            asset = get_asset_by_uid(
                conn,
                args.asset_id,
            )

            if not asset:
                raise LookupError(
                    f"자산을 찾을 수 없습니다: "
                    f"{args.asset_id}"
                )

            _print_json(asset)
            return 0

        if args.command == "history":
            history = get_asset_history(
                conn,
                args.asset_id,
                limit=args.limit,
            )
            _print_json(history)
            return 0

        if args.command == "register":
            host_id = upsert_host(
                conn,
                host_ip=args.ip,
                host_name=args.hostname,
            )
            asset = get_asset_by_id(conn, host_id)

            if not asset:
                raise RuntimeError(
                    "등록 직후 자산을 조회하지 못했습니다."
                )

            updates = _metadata_from_args(args)
            updates["source"] = "MANUAL"
            updated = update_asset_metadata(
                conn,
                asset_uid=asset["asset_uid"],
                updates=updates,
                changed_by=args.changed_by,
                reason=args.reason,
            )
            conn.commit()
            _print_json(updated)
            return 0

        if args.command == "update":
            updated = update_asset_metadata(
                conn,
                asset_uid=args.asset_id,
                updates=_metadata_from_args(args),
                changed_by=args.changed_by,
                reason=args.reason,
            )
            conn.commit()
            _print_json(updated)
            return 0

        parser.error("지원하지 않는 명령입니다.")
    except (ValueError, LookupError) as exc:
        conn.rollback()
        parser.error(str(exc))
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
