import os
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager

from .base_checker import BaseChecker


class ScreenshotChecker(BaseChecker):
    def __init__(self, screenshot_dir="logs/screenshots"):
        self.screenshot_dir = screenshot_dir
        os.makedirs(self.screenshot_dir, exist_ok=True)

    def _create_browser(self):
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1366,768")

        service = Service(ChromeDriverManager().install())
        driver = webdriver.Chrome(service=service, options=options)
        return driver

    def run_check(self, port_record, vuln_candidate):
        ip = port_record["host_ip"]
        port = port_record["port"]
        service_name = port_record.get("service", "")

        if service_name not in ("http", "https"):
            return {"status": "SKIP", "details": "Not a web service"}

        protocol = "https" if service_name == "https" else "http"
        url = f"{protocol}://{ip}:{port}"

        browser = None
        try:
            browser = self._create_browser()
            browser.get(url)
            time.sleep(2)

            filename = f"{ip}_{port}.png"
            save_path = os.path.join(self.screenshot_dir, filename)

            browser.save_screenshot(save_path)

            return {
                "status": "POTENTIAL",
                "details": f"Screenshot saved: {save_path}",
                "evidence_path": save_path
            }

        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

        finally:
            if browser:
                try:
                    browser.quit()
                except Exception:
                    pass