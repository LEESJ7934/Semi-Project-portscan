"""Preview or save CVE candidates without scanning or contacting external APIs."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from analysis.vuln_mapper import DEFAULT_RULES, analyze_ports


def positive_id(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("ID must be positive.")
    return number


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--scan-id", type=positive_id, help="DB scan ID; only still-current port observations")
    selection.add_argument("--asset-id", type=UUID, help="asset UUID; latest stored observation")
    selection.add_argument("--all", action="store_true", help="all assets' latest stored open TCP observations")
    selection.add_argument("--input", type=Path, help="offline JSON port records; preview only")
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--save", action="store_true", help="save DB candidates and evidence (default: preview)")
    parser.add_argument("--output", type=Path, help="also write the JSON report to this file")
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.input and args.save:
        parser.error("--input is preview-only; use --scan-id or --asset-id to save database observations.")
    try:
        if args.input:
            if args.input.stat().st_size > 10 * 1024 * 1024:
                raise ValueError("Input exceeds 10 MiB.")
            records = json.loads(args.input.read_text(encoding="utf-8-sig"))
            if not isinstance(records, list):
                raise ValueError("Input must be a JSON list of port observations.")
        else:
            from db.query_helpers import get_all_ports
            records = get_all_ports(scan_id=args.scan_id,
                                    asset_uid=str(args.asset_id) if args.asset_id else None)
        report = analyze_ports(records, args.rules)
        report["mode"] = "SAVE" if args.save else "PREVIEW"
        report["selected_port_count"] = len(records)
        report["candidate_count"] = len(report["candidates"])
        if not records:
            report["selection_note"] = ("No current open TCP observations selected. Verify the scan ID "
                                        "and rerun an approved scan with -sV; historical port replay is not supported.")
        if args.save:
            from analysis.save_vulns import save_vulns
            report["saved_vuln_ids"] = save_vulns(report["candidates"])
        encoded = json.dumps(report, ensure_ascii=False, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(encoded + "\n", encoding="utf-8")
        print(encoded)
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


def run_analysis():
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
