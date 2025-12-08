# scanner/screenshot.py

import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


def take_screenshot(target_ip: str, port: int, service: str) -> str | None:
    """
    웹 서비스인 경우 브라우저를 띄워 스크린샷을 찍고 파일 경로를 반환합니다.
    """
    # 1. 웹 서비스가 아니면 스킵
    # (포트 번호 기반 체크는 호출하는 쪽에서 이미 했으므로 여기선 서비스명 위주로)
    # 하지만 안전을 위해 한 번 더 체크
    if "http" not in service and "https" not in service:
        # 주요 웹 포트가 아니면 굳이 안 찍음
        if port not in [80, 443, 8080, 8088, 3000, 3330]:
            return None

    # 2. URL 구성
    protocol = "https" if "https" in service else "http"
    target_url = f"{protocol}://{target_ip}:{port}"

    # 저장 경로 설정 (reports/screenshots 폴더)
    base_dir = os.path.join(os.getcwd(), "reports", "screenshots")
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    filename = f"{target_ip}_{port}.png"
    filepath = os.path.join(base_dir, filename)

    print(f"[*] 📸 Taking screenshot of {target_url}...")

    # 3. 크롬 옵션 설정 (Headless & 보안 무시)
    chrome_options = Options()
    chrome_options.add_argument("--headless")  # 창 띄우지 않음
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--ignore-certificate-errors")  # SSL 에러 무시
    chrome_options.add_argument("--window-size=1920,1080")  # FHD 해상도로 캡처

    driver = None
    try:
        # 4. 브라우저 실행
        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=chrome_options)

        # 페이지 로딩 (타임아웃 10초)
        driver.set_page_load_timeout(10)
        driver.get(target_url)

        # 렌더링 대기 (잠깐 쉬어야 화면이 다 그려짐)
        time.sleep(2)

        # 5. 찰칵!
        driver.save_screenshot(filepath)
        print(f"    -> Saved to {filepath}")

        return filepath

    except Exception as e:
        print(f"    [!] Screenshot failed: {e}")
        return None

    finally:
        if driver:
            driver.quit()  # 브라우저 종료 (메모리 누수 방지)
