# scanner/syn_scanner.py

from scapy.all import IP, TCP, sr1, conf
import logging

# Scapy가 쓸데없이 출력하는 경고 메시지 끄기
conf.verb = 0


def syn_scan_port(host: str, port: int, timeout: float = 1.0) -> str:
    """
    TCP SYN 스캔 (Half-open Scan) 수행
    Returns: "open", "closed", "filtered"
    """
    try:
        # 1. 패킷 조립 (Crafting Packet)
        # IP 헤더: 목적지 IP
        # TCP 헤더: 목적지 포트, 플래그="S" (SYN)
        # sport(출발지 포트)는 랜덤으로 설정됨
        packet = IP(dst=host) / TCP(dport=port, flags="S")

        # 2. 패킷 발사 및 응답 대기 (Send and Receive 1 packet)
        response = sr1(packet, timeout=timeout, verbose=0)

        # 3. 응답 분석 (Analysis)
        if response is None:
            return "filtered"  # 응답 없음 (방화벽이 드롭했을 가능성)

        # TCP 레이어가 있는지 확인
        if response.haslayer(TCP):
            flags = response.getlayer(TCP).flags

            # 0x12는 SYN(0x02) + ACK(0x10)를 의미함
            if flags == 0x12:
                # [중요] 연결을 맺지 않고 바로 RST(Reset)를 날려서 도망감
                rst_packet = IP(dst=host) / TCP(
                    dport=port, sport=response.sport, flags="R"
                )
                sr1(rst_packet, timeout=0.1, verbose=0)
                return "open"

            # 0x14는 RST(0x04) + ACK(0x10) -> 닫혀있음
            elif flags == 0x14:
                return "closed"

        return "filtered"

    except Exception as e:
        logging.error(f"SYN Scan Error on {host}:{port} -> {e}")
        return "error"
