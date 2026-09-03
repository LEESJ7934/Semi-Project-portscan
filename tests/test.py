import os
import sys
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from verification.screenshot import ScreenshotChecker


def test_screenshot():
    target = os.getenv("LAB_TARGET")

    if not target:
        print("[SKIP] LAB_TARGET is not configured.")
        return

    checker = ScreenshotChecker()

    port_record = {
        "id": 999,
        "host_ip": target,
        "port": 80,
        "service": "http",
    }

    vuln_candidate = {
        "id": 999,
        "cve": "NONE",
        "title": "Screenshot test",
        "source": "test",
    }

    print("=== Screenshot Test Start ===")

    result = checker.run_check(
        port_record,
        vuln_candidate,
    )

    print("=== Result ===")
    print(result)

    screenshot_dir = PROJECT_ROOT / "logs" / "screenshots"

    if not screenshot_dir.exists():
        print("No screenshots were saved.")
        return

    print("=== Saved Screenshots ===")

    for file_path in screenshot_dir.iterdir():
        if file_path.is_file():
            print(file_path.name)


if __name__ == "__main__":
    test_screenshot()