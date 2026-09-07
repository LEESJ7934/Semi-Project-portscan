"""Preview Day 6 CVE priorities; persist V5 assessments only with --save."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from uuid import UUID

from analysis.nvd_cvss import validate_timeout
from analysis.risk_assessment import (RiskDatabaseError, RiskPolicyError, RiskSelectionError,
                                      run_risk_assessments)


class RiskArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        raise RiskSelectionError(message)


def positive_id(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("ID must be an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("ID must be positive")
    return number


def asset_uuid(value):
    try:
        return str(UUID(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("asset-id must be a UUID") from exc


def build_parser():
    parser = RiskArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--vuln-id", type=positive_id)
    selection.add_argument("--scan-id", type=positive_id, help="current port observation scan; not historical replay")
    selection.add_argument("--asset-id", type=asset_uuid)
    parser.add_argument("--save", action="store_true", help="save V5 assessment and eligible score summaries")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-request timeout: 0 < seconds <= 30")
    parser.add_argument("--output", type=Path, help="optional JSON output file (UTF-8)")
    return parser


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
        try:
            validate_timeout(args.timeout)
        except ValueError as exc:
            raise RiskSelectionError(str(exc)) from exc
        result = run_risk_assessments(vuln_id=args.vuln_id, scan_id=args.scan_id, asset_uid=args.asset_id,
                                      save=args.save, timeout=args.timeout)
        rendered = json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False)
        print(rendered)
        if args.output:
            args.output.write_text(rendered + "\n", encoding="utf-8")
        return 1 if result["incomplete"] else 0
    except RiskSelectionError as exc:
        code, message = "SELECTION_ERROR", str(exc)
    except RiskPolicyError as exc:
        code, message = "POLICY_ERROR", str(exc)
    except RiskDatabaseError as exc:
        code, message = "DB_ERROR", str(exc)
    except OSError:
        code, message = "OUTPUT_ERROR", "Could not write JSON output; any earlier SAVE commits remain stored."
    except Exception as exc:
        code, message = "ASSESSMENT_ERROR", type(exc).__name__
    print(json.dumps({"error_code": code, "message": message}, ensure_ascii=False), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
