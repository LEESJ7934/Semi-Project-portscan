# scanner/probes.py

PROBES = {
    "ftp": b"\r\n",
    "ssh": b"",  # SSH는 접속하면 서버가 먼저 banner 전송
    "telnet": b"\r\n",
    "http": b"GET / HTTP/1.0\r\n\r\n",
}
