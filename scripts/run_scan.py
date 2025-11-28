# scripts/run_scan.py
import argparse
from scanner.scan_runner import run_scan
from db.save_scan_results import save_scan_results
from scanner.service_fingerprints import PORT_SERVICE_MAP, guess_service
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="Custom Nmap-like Scanner")
    sub = parser.add_subparsers(dest="command")
    scan_parser = sub.add_parser("scan", help="run scanner")
    # 포트 범위는 고정 (원하면 변경)
    scan_parser.add_argument("--ports", default="1-1024", help="Port range (fixed)")
    scan_parser.add_argument("--target", required=True,
                             help="IP or domain to scan")
    scan_parser.add_argument("-sT", action="store_true",
                             help="TCP scan")
    scan_parser.add_argument("-sU", action="store_true",
                             help="UDP scan")
    scan_parser.add_argument("--timeout", type=float, default=1.0)
    scan_parser.add_argument("--max-workers", type=int, default=100)

    args = parser.parse_args()
    if args.command != "scan":
        print("Usage: python -m scripts.run_scan scan -sT -sU --target <IP>")
        return

    # ------------------------------
    # Nmap 스타일 옵션 해석
    # ------------------------------

    # 아무것도 안 넣으면 기본 TCP(-sT)
    if not args.sT and not args.sU:
        # 아무 옵션 없으면 기본 TCP만 스캔
        scan_type = "tcp"
        tcp_enabled = True
        udp_enabled = False
    else:
        if args.sT and args.sU:
            scan_type = "tcp+udp"
        elif args.sT:
            scan_type = "tcp"
        elif args.sU:
            scan_type = "udp"
        tcp_enabled = args.sT
        udp_enabled = args.sU

    # run_scan용 파라미터로 변환
    enable_udp = udp_enabled and tcp_enabled  # TCP+UDP
    udp_only = (udp_enabled and not tcp_enabled)

    # ------------------------------
    # 실행
    # ------------------------------
    results = run_scan(
        targets=[args.target],
        ports=args.ports,
        timeout=args.timeout,
        threaded=True,
        max_workers=args.max_workers,
        enable_udp=enable_udp,
        udp_only=udp_only,
        scan_type=scan_type,
    )

    # ------------------------------
    # 출력
    # ------------------------------
    scan_id = results["scan_id"]
    started_at = results["started_at"]
    finished_at = results["finished_at"]
    target_info = results["targets"][0]
    ip = target_info["ip"]

    if "error" in target_info:
        print(f"[!] Error: {target_info['error']} (invalid IP: {ip})")
        return

    port_results = target_info["results"]

    print(f"Starting Scan at {started_at}")
    print(f"Scan report for {ip}")
    print("Host is up")

    closed = [r for r in port_results if r["state"] == "closed"]
    print(f"Not shown: {len(closed)} closed ports")

    print("PORT\tSTATE\tSERVICE\tversion")

    for r in sorted(port_results, key=lambda x: (x["protocol"], x["port"])):
        port = r["port"]
        if port not in PORT_SERVICE_MAP:
            continue

        proto = r["protocol"]
        state = r["state"]
        service = r.get("service") or guess_service(port) or "-"
        version = r.get("version") or "-"

        print(f"{port}/{proto}\t{state}\t{service}\t{version}")

    save_scan_results(results)
    print("\n[+] DB 저장 완료")


if __name__ == "__main__":
    main()
