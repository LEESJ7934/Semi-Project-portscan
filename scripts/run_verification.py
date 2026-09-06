"""Run explicitly selected, approved-scope CVE verification."""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from scanner.scope import ScopePolicy, ScopeValidationError
from verification.run_verification import (VerificationConflictError, VerificationDatabaseError,
                                           run_verifications)


def positive_id(value):
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("ID must be an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("ID must be positive")
    return number


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--vuln-id", type=positive_id, help="verify one eligible vulnerability ID")
    selection.add_argument("--scan-id", type=positive_id, help="verify candidates attached to current port observations of a scan")
    parser.add_argument("--scope-file", type=Path, required=True, help="existing approved scope JSON")
    parser.add_argument("--dry-run", action="store_true", help="read DB targets only; no DNS, endpoint requests or DB writes")
    parser.add_argument("--timeout", type=float, default=5.0, help="existing read-only probe timeout (0 < seconds <= 30)")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not math.isfinite(args.timeout) or not 0 < args.timeout <= 30:
        parser.error("timeout must be greater than 0 and at most 30 seconds")
    try:
        policy = ScopePolicy.load(args.scope_file)
        outcomes = run_verifications(policy=policy, vuln_id=args.vuln_id, scan_id=args.scan_id,
                                     dry_run=args.dry_run, timeout=args.timeout)
        print(json.dumps({"mode": "DRY_RUN" if args.dry_run else "VERIFY", "results": outcomes},
                         ensure_ascii=False, indent=2))
        return 1 if any(row.get("result", {}).get("status") == "ERROR" for row in outcomes) else 0
    except ScopeValidationError as exc:
        code, message = "SCOPE_DENIED", str(exc)
    except VerificationConflictError as exc:
        code, message = "VERIFICATION_CONFLICT", str(exc)
    except VerificationDatabaseError as exc:
        code, message = "DB_SAVE_FAILED", str(exc)
    except Exception as exc:
        code, message = "VERIFICATION_FAILED", type(exc).__name__
    print(json.dumps({"error_code": code, "message": message}, ensure_ascii=False), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
