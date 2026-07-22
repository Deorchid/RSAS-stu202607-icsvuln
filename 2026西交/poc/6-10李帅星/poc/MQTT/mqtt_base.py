import struct
import time
from scapy.all import IP, TCP, Raw, send

# 虚拟机环境参数
LOOPBACK_DST = "127.0.0.1"
MQTT_TCP_PORT = 1883

# 分级日志（与前面S7/PROFINET/EtherCAT格式统一）
class MQTTLog:
    @staticmethod
    def info(msg):
        print(f"[MQTT-正常流量] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def warn(msg):
        print(f"[MQTT-漏洞探测] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def exploit(msg):
        print(f"[MQTT-攻击POC] {time.strftime('%H:%M:%S')} | {msg}")

# MQTT固定头构造：报文类型+标志位+剩余长度
def build_mqtt_fixed_header(msg_type: int, flag: int, remain_len: int) -> bytes:
    byte1 = (msg_type << 4) | flag
    # MQTT可变剩余长度编码
    len_buf = b""
    val = remain_len
    while True:
        digit = val % 128
        val = val // 128
        if val > 0:
            digit |= 0x80
        len_buf += bytes([digit])
        if val == 0:
            break
    return bytes([byte1]) + len_buf

# 封装完整MQTT报文
def build_mqtt_pkt(msg_type: int, flag: int, payload: bytes) -> bytes:
    remain_len = len(payload)
    header = build_mqtt_fixed_header(msg_type, flag, remain_len)
    return header + payload

# 发包函数，不强制绑定源IP，Windows无丢包
def send_mqtt_tcp_pkt(dst_ip: str, sport: int, full_mqtt_frame: bytes):
    pkt = IP(dst=dst_ip)/TCP(sport=sport, dport=MQTT_TCP_PORT, flags="PA")/Raw(load=full_mqtt_frame)
    send(pkt, verbose=0)
    return pkt