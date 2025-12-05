import requests
from bs4 import BeautifulSoup


DVWA_BASE_URL = "http://3.35.37.54"  # 필요하면 나중에 env로 뺄 것
LOGIN_CANDIDATES = [
    "/login.php",
    "/dvwa/login.php",
]


def _find_login_page(session: requests.Session) -> str:
    """
    여러 후보 URL 중 실제 DVWA 로그인 페이지를 찾아서 전체 URL 반환.
    """
    for path in LOGIN_CANDIDATES:
        url = DVWA_BASE_URL + path
        resp = session.get(url, timeout=10)
        if resp.status_code == 200 and "DVWA" in resp.text:
            return url
    raise RuntimeError("DVWA login page not found (tried /login.php, /dvwa/login.php)")


def get_dvwa_cookie_header(
    username: str = "admin",
    password: str = "password",
) -> str:
    """
    DVWA에 로그인해서 nuclei에 넘길 Cookie 헤더 문자열을 반환.
    user_token(hidden input)이 없으면 없음대로 로그인 시도한다.
    로그인 실패 시 예외 발생.
    """
    s = requests.Session()

    # 1) 로그인 페이지 찾기
    login_url = _find_login_page(s)

    # 2) 로그인 페이지 GET
    resp = s.get(login_url, timeout=10)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")

    # 3) CSRF 토큰(user_token) 추출 (없어도 에러 내지 않고 진행)
    token_input = soup.find("input", {"name": "user_token"})
    user_token = token_input["value"] if token_input and token_input.has_attr("value") else None

    # 4) 로그인 폼 payload 구성
    payload = {
        "username": username,
        "password": password,
        "Login": "Login",
    }
    if user_token:
        payload["user_token"] = user_token

    # 5) POST 로그인 요청
    login_resp = s.post(login_url, data=payload, timeout=10)
    login_resp.raise_for_status()

    # 6) 로그인 성공 여부 대충 체크 (Logout 텍스트 / login 실패 문구 등)
    text_lower = login_resp.text.lower()
    if "logout" not in text_lower and "dvwa security" not in text_lower:
        # 실패로 간주
        raise RuntimeError("DVWA login seems to have failed (no 'logout' text)")

    # 7) 세션 쿠키들을 Cookie 헤더 형태로 변환
    cookies = s.cookies.get_dict()
    if not cookies:
        raise RuntimeError("No cookies set after DVWA login")

    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
    return cookie_header
