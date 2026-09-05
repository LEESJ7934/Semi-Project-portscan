from __future__ import annotations

import argparse
from datetime import datetime
from pathlib import Path
from typing import Sequence

from scanner.scan_runner import run_scan
from scanner.scope import ScopePolicy, ScopeValidationError
from scanner.service_fingerprints import guess_service
from scanner.targets import ResolvedTarget, resolve_target_specs
from scanner.utils import parse_ports


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOPE_FILE = (
    PROJECT_ROOT / "config" / "scope.example.json"
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Approved-scope infrastructure port scanner"
        )
    )
    subparsers = parser.add_subparsers(dest="command")
    scan_parser = subparsers.add_parser(
        "scan",
        help="run an approved scan",
    )
    scan_parser.add_argument(
        "--target",
        action="append",
        required=True,
        help=(
            "IP, CIDR or hostname. Repeat the option for "
            "multiple inputs."
        ),
    )
    scan_parser.add_argument(
        "--scope-file",
        type=Path,
        default=DEFAULT_SCOPE_FILE,
        help=(
            "JSON file containing the approved scan scope "
            f"(default: {DEFAULT_SCOPE_FILE})"
        ),
    )
    scan_parser.add_argument(
        "--ports",
        default="1-1024",
        help="port expression such as 22,80,443 or 1-1024",
    )
    scan_parser.add_argument(
        "-sT",
        action="store_true",
        help="TCP scan",
    )
    scan_parser.add_argument(
        "-sU",
        action="store_true",
        help="UDP scan",
    )
    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
    )
    scan_parser.add_argument(
        "--max-workers",
        type=int,
        default=100,
    )
    scan_parser.add_argument(
        "-sV",
        action="store_true",
        help="collect TCP banners and identify advertised products/versions",
    )
    scan_parser.add_argument(
        "-oN",
        "--output-normal",
        type=Path,
        metavar="FILE",
        help="save text output",
    )
    scan_parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "validate and display the approved expansion "
            "without scanning or using the database"
        ),
    )
    return parser


def determine_scan_mode(
    tcp_flag: bool,
    udp_flag: bool,
) -> tuple[str, bool, bool]:
    if not tcp_flag and not udp_flag:
        return "tcp", False, False

    if tcp_flag and udp_flag:
        return "tcp+udp", True, False

    if tcp_flag:
        return "tcp", False, False

    return "udp", False, True


def attach_target_metadata(
    results: dict,
    targets: Sequence[ResolvedTarget],
) -> None:
    metadata_by_ip = {
        target.ip: target for target in targets
    }

    for target_result in results["targets"]:
        metadata = metadata_by_ip[target_result["ip"]]
        target_result["input_target"] = (
            metadata.input_target
        )
        target_result["resolution_type"] = (
            metadata.resolution_type
        )


def print_scan_plan(
    policy: ScopePolicy,
    targets: Sequence[ResolvedTarget],
    port_count: int,
    worker_count: int,
) -> None:
    print(f"Authorization: {policy.authorization_ref}")
    print(f"Scope: {policy.scope_uid} ({policy.name})")
    print(f"Resolved targets: {len(targets)}")
    print(f"Ports per target: {port_count}")
    print(f"Max workers: {worker_count}")

    for target in targets:
        print(
            f"  {target.input_target} -> {target.ip} "
            f"[{target.resolution_type}]"
        )


def render_results(
    results: dict,
    show_versions: bool,
) -> list[str]:
    lines = [f"Starting Scan at {results['started_at']}"]

    for target_info in results["targets"]:
        ip = target_info["ip"]
        lines.append("")
        lines.append(f"Scan report for {ip}")

        if target_info.get("error"):
            lines.append(
                f"[!] Error: {target_info['error']}"
            )
            continue

        port_results = target_info["results"]
        closed_count = sum(
            1
            for result in port_results
            if result["state"] == "closed"
        )
        lines.append("Target scan completed")
        lines.append(f"closed ports: {closed_count}")
        header = (
            "PORT\tSTATE\tSERVICE\tPRODUCT\tVERSION"
            if show_versions
            else "PORT\tSTATE\tSERVICE"
        )
        lines.append(header)

        for result in sorted(
            port_results,
            key=lambda item: (
                item["protocol"],
                item["port"],
            ),
        ):
            if result["state"] != "open":
                continue

            port = result["port"]
            protocol = result["protocol"]
            state = result["state"]
            service = (
                result.get("service")
                or guess_service(port, protocol)
                or "-"
            )
            version = result.get("version") or "-"
            product = result.get("product") or "-"

            if show_versions:
                lines.append(
                    f"{port}/{protocol}\t{state}\t"
                    f"{service:<15}\t{product}\t{version}"
                )
            else:
                lines.append(
                    f"{port}/{protocol}\t{state}\t{service}"
                )

    started_at = datetime.fromisoformat(
        results["started_at"]
    )
    finished_at = datetime.fromisoformat(
        results["finished_at"]
    )
    duration = (
        finished_at - started_at
    ).total_seconds()
    lines.append("")
    lines.append(
        "Scan done: "
        f"{len(results['targets'])} target(s) in "
        f"{duration:.3f} seconds"
    )
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_help()
        return 2

    try:
        if not 0 < args.timeout <= 30:
            raise ValueError(
                "timeout은 0초 초과 30초 이하여야 합니다."
            )

        policy = ScopePolicy.load(args.scope_file)
        port_list = parse_ports(args.ports)

        if not port_list:
            raise ValueError(
                "유효한 스캔 포트가 하나도 없습니다."
            )

        resolved_targets = resolve_target_specs(
            args.target,
            max_targets=policy.max_targets,
        )
        policy.authorize(
            resolved_targets,
            worker_count=args.max_workers,
            port_count=len(port_list),
        )
    except (ValueError, ScopeValidationError) as exc:
        parser.error(str(exc))

    print_scan_plan(
        policy,
        resolved_targets,
        len(port_list),
        args.max_workers,
    )

    if args.dry_run:
        print("[DRY-RUN] No scan or database write was performed.")
        return 0

    scan_type, enable_udp, udp_only = determine_scan_mode(
        args.sT,
        args.sU,
    )
    results = run_scan(
        targets=[
            target.ip for target in resolved_targets
        ],
        ports=port_list,
        timeout=args.timeout,
        threaded=True,
        max_workers=args.max_workers,
        enable_udp=enable_udp,
        udp_only=udp_only,
        scan_type=scan_type,
        detect_versions=args.sV,
        server_names={target.ip: target.input_target for target in resolved_targets
                      if target.resolution_type == "HOSTNAME"},
    )
    attach_target_metadata(results, resolved_targets)
    results["requested_targets"] = list(args.target)
    scope_snapshot = policy.to_snapshot()
    results["scope"] = scope_snapshot
    results["config"] = {
        "ports": args.ports,
        "timeout": args.timeout,
        "max_workers": args.max_workers,
        "service_version_requested": args.sV,
        "scope": scope_snapshot,
    }

    output_lines = render_results(
        results,
        show_versions=args.sV,
    )

    for line in output_lines:
        print(line)

    if args.output_normal:
        args.output_normal.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        args.output_normal.write_text(
            "\n".join(output_lines) + "\n",
            encoding="utf-8",
        )
        print(f"[+] Saved output to {args.output_normal}")

    from db.save_scan_results import save_scan_results

    scan_db_id = save_scan_results(results)
    print(f"[+] DB save completed (scan_id={scan_db_id})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
