# test_scan.py
from scanner.scan_runner import run_scan

if __name__ == "__main__":
    result = run_scan(
        targets=["127.0.0.1"],
        ports="20-1024",
        timeout=0.5,
        threaded=True,
        max_workers=200,
    )
    print(result)
