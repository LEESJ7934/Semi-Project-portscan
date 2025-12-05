import os
import sys
import time

# 프로젝트 루트 경로 추가
sys.path.append(os.path.dirname(__file__))

from verification.screenshot import ScreenshotChecker


def test_screenshot():
    checker = ScreenshotChecker()

    # 테스트용 포트 레코드 (DVWA 80포트 예시)
    port_record = {
        "id": 999,
        "host_ip": "3.35.37.54",
        "port": 80,
        "service": "http"
    }

    vuln_candidate = {
        "id": 999,
        "cve": "NONE",
        "title": "Dummy",
        "source": "test"
    }

    print("=== Screenshot Test Start ===")

    result = checker.run_check(port_record, vuln_candidate)

    print("=== RESULT ===")
    print(result)

    # 캡처 파일 확인
    screenshot_dir = "logs/screenshots"
    files = os.listdir(screenshot_dir)
    print("\n=== Saved Files in logs/screenshots ===")
    for f in files:
        print(f)


if __name__ == "__main__":
    test_screenshot()
