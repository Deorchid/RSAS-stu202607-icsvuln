import struct
import time
from scapy.all import IP, TCP, Raw, send

# 虚拟机环境参数
LOOPBACK_DST = "127.0.0.1"
IEC104_TCP_PORT = 2404

# 分级日志（与前面所有协议格式完全统一）
class IECLog:
    @staticmethod
    def info(msg):
        print(f"[IEC104-正常流量] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def warn(msg):
        print(f"[IEC104-漏洞探测] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def exploit(msg):
        print(f"[IEC104-攻击POC] {time.strftime('%H:%M:%S')} | {msg}")

# IEC104固定APCI头构造（标准6字节头部）
def build_iec_apci(apci_type: int, tx_seq: int, rx_seq: int, data_len: int) -> bytes:
    start = 0x68
    header = struct.pack("<BBHHH", start, data_len, apci_type, tx_seq, rx_seq)
    return header

# 封装完整IEC104 APCI+ASDU报文
def build_iec_frame(apci_type: int, tx_seq: int, rx_seq: int, asdu_payload: bytes) -> bytes:
    data_len = 4 + len(asdu_payload)
    apci_header = build_iec_apci(apci_type, tx_seq, rx_seq, data_len)
    return apci_header + asdu_payload

# 统一发包函数，Windows无需手动绑定源IP，避免丢包
def send_iec_tcp_pkt(dst_ip: str, sport: int, full_frame: bytes):
    pkt = IP(dst=dst_ip)/TCP(sport=sport, dport=IEC104_TCP_PORT, flags="PA")/Raw(load=full_frame)
    send(pkt, verbose=0)
    return pkt