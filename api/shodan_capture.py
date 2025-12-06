# analysis/shodan_capture.py
from playwright.sync_api import sync_playwright

def capture_shodan_page(ip: str, output_path: str = "reports/shodan_page.pdf"):
    url = f"https://www.shodan.io/host/{ip}"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        print(f"[+] Loading Shodan page for {ip} ...")
        page.goto(url, timeout=60000)
        page.wait_for_timeout(4000)

        page.pdf(
            path=output_path,
            format="A4",
            print_background=True
        )

        browser.close()

    print(f"[+] Shodan PDF saved to {output_path}")
    return output_path
