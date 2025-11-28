# scanner/service_fingerprints.py

# (protocol, service_name)
# protocol: "tcp", "udp", "both"
PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {

    # -------- TCP 서비스 --------
    20: ("tcp", "ftp-data"),
    21: ("tcp", "ftp"),
    22: ("tcp", "ssh"),
    23: ("tcp", "telnet"),
    25: ("tcp", "smtp"),
    80: ("tcp", "http"),
    110: ("tcp", "pop3"),
    143: ("tcp", "imap"),
    443: ("tcp", "https"),
    3306: ("tcp", "mysql"),

    # -------- BOTH (TCP+UDP) --------
    53: ("both", "dns"),  # DNS는 TCP/UDP 둘 다 사용

    # -------- UDP 서비스 --------
    67: ("udp", "dhcp-server"),
    68: ("udp", "dhcp-client"),
    69: ("udp", "tftp"),
    123: ("udp", "ntp"),
    137: ("udp", "netbios-ns"),
    138: ("udp", "netbios-dgm"),
    161: ("udp", "snmp"),
    162: ("udp", "snmp-trap"),
    500: ("udp", "ike"),
    514: ("udp", "syslog"),
    520: ("udp", "rip"),
    1900: ("udp", "ssdp"),
    4500: ("udp", "ipsec-natt"),
    5353: ("udp", "mdns"),
    11211: ("udp", "memcached"),
}


def guess_service(port: int) -> str | None:
    """포트 번호로 기본 서비스 이름 추정."""
    entry = PORT_SERVICE_MAP.get(port)
    if entry is None:
        return None
    return entry[1]   # 서비스 이름


# ---------- 자동 TCP/UDP 포트 리스트 생성 ----------
TCP_PORTS = [
    port for port, (proto, _) in PORT_SERVICE_MAP.items()
    if proto in ("tcp", "both")
]

UDP_PORTS = [
    port for port, (proto, _) in PORT_SERVICE_MAP.items()
    if proto in ("udp", "both")
]
