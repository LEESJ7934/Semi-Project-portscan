"""Compatibility entry point for the single Day 7 generator (asset UUID / scan ID).

The former positional IP API and automatic Shodan/PDF-merger flow are retired.
"""
from api.analysis_report import generate_report as generate_final_report
from scripts.generate_report import main


if __name__ == "__main__":
    raise SystemExit(main())
