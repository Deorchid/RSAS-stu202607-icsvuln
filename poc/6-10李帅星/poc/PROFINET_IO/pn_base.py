import struct
import time
from scapy.all import IP, UDP, Raw, send

# 虚拟机环境参数
VM_IP = "192.168.250.128"
LOOPBACK_DST = "127.0.0.1"
PROFINET_UDP_PORT = 34964  # PROFINET RT标准端口

# 分级日志
class PNLog:
    @staticmethod
    def info(msg):
        print(f"[PROFINET-正常流量] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def warn(msg):
        print(f"[PROFINET-漏洞探测] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def exploit(msg):
        print(f"[PROFINET-攻击POC] {time.strftime('%H:%M:%S')} | {msg}")

# 构建标准PROFINET IO实时帧头
def build_pn_rt_frame(cycle_id: int, io_len: int, payload: bytes) -> bytes:
    # PROFINET RT 固定头部格式
    pn_header = struct.pack(">HHHH", 0x8100, cycle_id, io_len, 0x0000)
    return pn_header + payload

# 发包函数，Windows自动适配网卡，不会丢包
def send_pn_pkt(dst_ip: str, sport: int, full_frame: bytes):
    pkt = IP(dst=dst_ip)/UDP(sport=sport, dport=PROFINET_UDP_PORT)/Raw(load=full_frame)
    send(pkt, verbose=0)
    return pkt