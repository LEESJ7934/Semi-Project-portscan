# scanner/auth.py

import requests
from bs4 import BeautifulSoup


def get_dvwa_cookie(target_ip: str, port: int) -> str | None:
    """
    DVWA에 자동으로 로그인하고, Nuclei가 사용할 수 있는 쿠키 문자열을 반환합니다.
    Format: "PHPSESSID=...; security=low"
    """
    base_url = f"http://{target_ip}:{port}"
    login_url = f"{base_url}/login.php"
    security_url = f"{base_url}/security.php"

    # 세션 객체 생성 (쿠키를 유지하기 위함)
    session = requests.Session()

    try:
        print(f"[*] 🔐 Authenticating to DVWA at {login_url}...")

        # 1. 로그인 페이지 접속 (CSRF 토큰 획득)
        response = session.get(login_url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        # input 태그 중 name='user_token'인 것의 value를 찾음
        token_input = soup.find("input", {"name": "user_token"})
        if not token_input:
            print("[!] Failed to find CSRF token. Is the service up?")
            return None

        user_token = token_input.get("value")

        # 2. 로그인 요청 전송
        login_data = {
            "username": "admin",  # DVWA 기본 ID
            "password": "password",  # DVWA 기본 PW
            "Login": "Login",
            "user_token": user_token,
        }

        # 리다이렉트 허용 (로그인 후 index.php로 이동)
        response = session.post(login_url, data=login_data, allow_redirects=True)

        if "Welcome to Damn Vulnerable Web App" not in response.text:
            print("[!] Login Failed! (Default credentials might have changed)")
            return None

        # 3. 보안 레벨 'Low'로 변경 (취약점 탐지를 위해 필수)
        # 보안 레벨 변경 페이지에서 다시 토큰을 얻어야 함
        response = session.get(security_url)
        soup = BeautifulSoup(response.text, "html.parser")
        user_token = soup.find("input", {"name": "user_token"}).get("value")

        sec_data = {
            "security": "low",
            "seclev_submit": "Submit",
            "user_token": user_token,
        }
        session.post(security_url, data=sec_data)

        # 4. 쿠키 추출 및 포맷팅
        cookies = session.cookies.get_dict()
        phpsessid = cookies.get("PHPSESSID")

        if phpsessid:
            # Nuclei에 전달할 쿠키 문자열 완성
            cookie_str = f"PHPSESSID={phpsessid}; security=low"
            print(f"[+] Authentication Successful! Cookie: {cookie_str}")
            return cookie_str

        return None

    except Exception as e:
        print(f"[!] Auth Error: {e}")
        return None
