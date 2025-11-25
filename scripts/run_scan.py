# scripts/run_scan.py
import argparse
from scanner.scan_runner import run_scan
from db.save_scan_results import save_scan_results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="IP or domain to scan")
    parser.add_argument("--ports", default="1-1024", help="Port range")
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--max-workers", type=int, default=100)

    args = parser.parse_args()

    # 1) 스캔 실행
    results = run_scan(
        targets=[args.target],
        ports=args.ports,
        timeout=args.timeout,
        threaded=True,
        max_workers=args.max_workers,
    )

    # 2) 콘솔 출력
    print("\n=== Scan Result ===")
    for r in results:
        print(r)

    # 3) DB 저장
    save_scan_results(results)
    print("\n[+] DB 저장 완료")


if __name__ == "__main__":
    main()
