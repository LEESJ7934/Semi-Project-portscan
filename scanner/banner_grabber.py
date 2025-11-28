# scanner/banner_grabber_versioned.py

import socket
from .probes import PROBES

def grab_banner(host: str, port: int, service: str, timeout: float = 1.0) -> str | None:
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))

        probe = PROBES.get(service)

        # SSH는 접속 시 서버가 먼저 배너를 보냄
        if probe:
            sock.sendall(probe)

        data = sock.recv(4096)
        sock.close()
        return data.decode(errors="ignore")

    except Exception:
        return None
