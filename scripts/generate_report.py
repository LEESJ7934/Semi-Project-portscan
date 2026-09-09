"""Export a stored V5 asset/scan report as JSON, PDF or both. No external fetches."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from api.analysis_report import (ReportDataError, ReportDatabaseError, ReportSelectionError,
                                  generate_report)


class ReportArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise ReportSelectionError(message)


def positive_id(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("scan-id must be an integer") from exc
    if number <= 0:
        raise argparse.ArgumentTypeError("scan-id must be positive")
    return number


def build_parser():
    parser = ReportArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--asset-id", help="asset UUID; IP selection is not supported")
    selection.add_argument("--scan-id", type=positive_id, help="current observations of this scan; not historical replay")
    parser.add_argument("--output-dir", type=Path, default=Path("reports"))
    parser.add_argument("--format", choices=("json", "pdf", "both"), default="both")
    return parser


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        result = generate_report(asset_uid=args.asset_id, scan_id=args.scan_id,
                                 output_dir=args.output_dir, format=args.format)
        print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
        return 0
    except ReportSelectionError as exc:
        code, message = "SELECTION_ERROR", str(exc)
    except ReportDatabaseError as exc:
        code, message = "DB_ERROR", str(exc)
    except ReportDataError as exc:
        code, message = "DATA_ERROR", str(exc)
    except Exception as exc:
        code, message = "REPORT_ERROR", type(exc).__name__
    print(json.dumps({"error_code": code, "message": message}, ensure_ascii=False), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
