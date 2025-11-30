# scanner/service_fingerprints.py

# (protocol, service_name)
# protocol: "tcp", "udp", "both"
PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {

    # TCP 
    20: ("tcp", "ftp-data"),
    21: ("tcp", "ftp"),
    22: ("tcp", "ssh"),
    23: ("tcp", "telnet"),
    25: ("tcp", "smtp"),
    80: ("tcp", "http"),
    110: ("tcp", "pop3"),
    135: ("tcp", "msrpc"),
    143: ("tcp", "imap"),
    443: ("tcp", "https"),
    445: ("tcp", "microsoft-ds"),
    902: ("tcp", "iss-realsecure"),
    912: ("tcp", "apex-mesh"),
    1042: ("tcp", "afrog"),
    1043: ("tcp", "boinc"),
    2179: ("tcp", "vmrdp"),
    3306: ("tcp", "mysql"),
    9010: ("tcp", "sdr"),
    9200: ("tcp", "wap-wsp"),

    # -------- BOTH --------
    53: ("both", "dns"),

    # -------- UDP (기본 + Nmap 열린 포트) --------
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
    1900: ("udp", "upnp"),          # ← Nmap 결과 반영
    4500: ("udp", "nat-t-ike"),     # ← Nmap 결과 반영
    5050: ("udp", "mmcc"),          # ← Nmap 결과 반영
    5353: ("udp", "zeroconf"),      # ← Nmap 결과 반영
    5355: ("udp", "llmnr"),         # ← Nmap 결과 반영
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
