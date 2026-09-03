import os
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

DVWA_BASE_URL = os.getenv(
    "DVWA_BASE_URL",
    "http://127.0.0.1:8080",
).rstrip("/")

LOGIN_CANDIDATES = [
    "/login.php",
    "/dvwa/login.php",
]


def _find_login_page(session: requests.Session) -> str:
    """여러 후보 URL 중 실제 DVWA 로그인 페이지를 찾습니다."""

    for path in LOGIN_CANDIDATES:
        url = DVWA_BASE_URL + path

        try:
            response = session.get(url, timeout=10)
        except requests.RequestException:
            continue

        if response.status_code == 200 and "DVWA" in response.text:
            return url

    raise RuntimeError(
        "DVWA 로그인 페이지를 찾지 못했습니다. "
        "DVWA_BASE_URL과 DVWA 실행 상태를 확인하세요."
    )


def get_dvwa_cookie_header(
    username: str | None = None,
    password: str | None = None,
) -> str:
    """DVWA에 로그인하고 Nuclei에서 사용할 Cookie 헤더를 반환합니다."""

    username = username or os.getenv("DVWA_USERNAME")
    password = password or os.getenv("DVWA_PASSWORD")

    if not username or not password:
        raise RuntimeError(
            "DVWA_USERNAME과 DVWA_PASSWORD를 "
            "프로젝트 루트의 .env에 설정하세요."
        )

    session = requests.Session()
    login_url = _find_login_page(session)

    response = session.get(login_url, timeout=10)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "user_token"})

    user_token = None
    if token_input and token_input.has_attr("value"):
        user_token = token_input["value"]

    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
    }

    if user_token:
        payload["user_token"] = user_token

    login_response = session.post(
        login_url,
        data=payload,
        timeout=10,
    )
    login_response.raise_for_status()

    response_text = login_response.text.lower()

    if (
        "logout" not in response_text
        and "dvwa security" not in response_text
    ):
        raise RuntimeError("DVWA 로그인에 실패했습니다.")

    cookies = session.cookies.get_dict()

    if not cookies:
        raise RuntimeError("DVWA 로그인 후 쿠키가 생성되지 않았습니다.")

    return "; ".join(
        f"{name}={value}"
        for name, value in cookies.items()
    )