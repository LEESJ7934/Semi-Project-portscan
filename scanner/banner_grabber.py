# scanner/banner_grabber.py
from typing import Optional
from .utils import tcp_connect


def grab_banner(host: str, port: int, timeout: float = 1.0, bufsize: int = 1024) -> Optional[str]:
    """
    단순 배너 그랩:
    - connect
    - 짧은 timeout 설정
    - recv() 호출 후 문자열로 반환
    - 실패 시 None
    """
    sock = tcp_connect(host, port, timeout=timeout)
    if sock is None:
        return None

    try:
        sock.settimeout(timeout)
        # 일부 서비스는 연결 직후 배너를 보내지 않을 수도 있음.
        # 일단 아무것도 보내지 않고 recv만 시도.
        data = sock.recv(bufsize)
        if not data:
            return None
        try:
            return data.decode(errors="ignore").strip()
        except UnicodeDecodeError:
            return None
    except OSError:
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass
