import struct
import time
from scapy.all import IP, UDP, Raw, send

# 虚拟机固定环境参数
LOOPBACK_DST = "127.0.0.1"
ECAT_UDP_PORT = 8899  # EtherCAT over UDP标准端口

# 分级标准化日志（和S7、PROFINET格式完全统一）
class ECLog:
    @staticmethod
    def info(msg):
        print(f"[EtherCAT-正常流量] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def warn(msg):
        print(f"[EtherCAT-漏洞探测] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def exploit(msg):
        print(f"[EtherCAT-攻击POC] {time.strftime('%H:%M:%S')} | {msg}")

# 构造标准EtherCAT报文头（遵循IEC61158-4）
def build_ecat_frame(slave_cnt: int, wkc: int, payload: bytes) -> bytes:
    """
    slave_cnt：从站数量
    wkc：工作计数器
    payload：IO过程数据载荷
    """
    ec_header = struct.pack("<HH", slave_cnt, wkc)
    return ec_header + payload

# 统一发包函数，自动适配Windows网卡，无手动绑定源IP
def send_ec_pkt(dst_ip: str, sport: int, full_frame: bytes):
    pkt = IP(dst=dst_ip)/UDP(sport=sport, dport=ECAT_UDP_PORT)/Raw(load=full_frame)
    send(pkt, verbose=0)
    return pkt