# scripts/run_scan.py
import argparse
from scanner.scan_runner import run_scan
from db.save_scan_results import save_scan_results
from scanner.service_fingerprints import guess_service
from datetime import datetime


def main():
    parser = argparse.ArgumentParser(description="Custom Scanner")
    sub = parser.add_subparsers(dest="command")
    scan_parser = sub.add_parser("scan", help="run scanner")

    # 포트 범위
    scan_parser.add_argument("--ports", default="1-1024", help="Port range (fixed)")
    scan_parser.add_argument("--target", required=True, help="IP or domain to scan")

    # 스캔 타입
    scan_parser.add_argument("-sT", action="store_true", help="TCP scan")
    scan_parser.add_argument("-sU", action="store_true", help="UDP scan")

    # 성능 옵션
    scan_parser.add_argument("--timeout", type=float, default=1.0)
    scan_parser.add_argument("--max-workers", type=int, default=100)

    # 서비스/버전 탐지
    scan_parser.add_argument(
        "-sV",
        action="store_true",
        help="Detect service versions (banner/metadata)",
    )

    # 텍스트 출력 파일(-oN)
    scan_parser.add_argument(
        "-oN",
        "--output-normal",
        metavar="FILE",
        help="Save normal text output to a text file",
    )

    args = parser.parse_args()

    # 스캐너 사용 방법
    if args.command != "scan":
        print("Usage: python -m scripts.run_scan scan -sT -sU --target <IP>")
        return

    # ------------------------------
    # Nmap 스타일 옵션 해석
    # ------------------------------
    if not args.sT and not args.sU:
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
    # 출력 준비 (콘솔 + 파일 공통)
    # ------------------------------
    file_lines = []  # -oN 파일에 쓸 라인들

    scan_id = results["scan_id"]
    started_at = results["started_at"]
    finished_at = results["finished_at"]
    target_info = results["targets"][0]
    ip = target_info["ip"]

    if "error" in target_info:
        msg = f"[!] Error: {target_info['error']} (invalid IP: {ip})"
        print(msg)
        file_lines.append(msg)
        return

    port_results = target_info["results"]

    line = f"Starting Scan at {started_at}"
    print(line)
    file_lines.append(line)

    line = f"Scan report for {ip}"
    print(line)
    file_lines.append(line)

    print("Host is up")
    file_lines.append("Host is up")

    closed = [r for r in port_results if r["state"] == "closed"]
    line = f"closed ports: {len(closed)}"
    print(line)
    file_lines.append(line)

    # 헤더
    header = "PORT\tSTATE\tSERVICE\tVERSION" if args.sV else "PORT\tSTATE\tSERVICE"
    print(header)
    file_lines.append(header)

    # ------------------------------
    # 포트 출력
    # ------------------------------
    for r in sorted(port_results, key=lambda x: (x["protocol"], x["port"])):

        # open 포트만 출력
        if r["state"] != "open":
            continue

        port = r["port"]
        proto = r["protocol"]
        state = r["state"]

        service = r.get("service") or guess_service(port) or "-"
        version = r.get("version") or "-"

        if args.sV:
            line = f"{port}/{proto}\t{state}\t{service:<15}\t{version}"
        else:
            line = f"{port}/{proto}\t{state}\t{service}"

        print(line)
        file_lines.append(line)

    # ------------------------------
    # -oN 파일 저장
    # ------------------------------
    if args.output_normal:
        with open(args.output_normal, "w", encoding="utf-8") as f:
            f.write("\n".join(file_lines))
        print(f"\n[+] Saved output to {args.output_normal}")

    # ------------------------------
    # DB 저장
    # ------------------------------
    save_scan_results(results)
    print("\n[+] DB 저장 완료")


if __name__ == "__main__":
    main()
