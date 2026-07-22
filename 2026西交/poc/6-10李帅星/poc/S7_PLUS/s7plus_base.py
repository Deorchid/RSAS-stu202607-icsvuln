import struct
import socket
import time
from scapy.all import IP, TCP, Raw, send, sr1

# 适配你虚拟机固定环境参数
S7_TCP_PORT = 102
VM_LOCAL_IP = "192.168.250.128"  # 本机虚拟机网卡IP（本地连接*8）
TARGET_LOOPBACK = "127.0.0.1"    # 无PLC，本地回环发包抓包

# S7Plus PDU 标准消息类型
JOB_REQ = 0x01
ACK_ONLY = 0x02
ACK_DATA = 0x03
# TPKT/COTP 西门子官方固定头部
TPKT_VER = 0x03
COTP_FIX_HEAD = b"\x02\xf0\x80"
# S7-1200/1500 合法会话ID
VALID_SESS_ID = 0x00A8C29F

# 分级标准化日志
class S7Log:
    @staticmethod
    def info(msg):
        print(f"[S7-正常流量] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def warn(msg):
        print(f"[S7-漏洞探测] {time.strftime('%H:%M:%S')} | {msg}")
    @staticmethod
    def exploit(msg):
        print(f"[S7-攻击POC] {time.strftime('%H:%M:%S')} | {msg}")

# 构建标准12字节S7Plus PDU（1200/1500独有4字节会话ID字段）
def build_s7_pdu(msg_type: int, seq: int, sess_id: int, param_buf: bytes, data_buf: bytes) -> bytes:
    param_len = len(param_buf)
    data_len = len(data_buf)
    # 格式 >BBHHHHI 对应7个参数：B,B,H,H,H,H,I
    s7_header = struct.pack(
        ">BBHHHHI",
        msg_type,
        0x00,
        seq,
        param_len,
        data_len,
        0x0000,  # 补上缺失的第6个H字段（PDU预留子序号）
        sess_id
    )
    return s7_header + param_buf + data_buf

# TPKT+COTP外层封装，自动计算总长度，无畸形报文
def wrap_tpkt_cotp(pdu_payload: bytes) -> bytes:
    cotp_combined = COTP_FIX_HEAD + pdu_payload
    tpkt_total_len = len(cotp_combined)
    tpkt_head = struct.pack(">BBH", TPKT_VER, 0x00, tpkt_total_len)
    return tpkt_head + cotp_combined

# Scapy发包，源IP固定为本机虚拟机网卡192.168.250.128，流量出现在【本地连接*8】
def send_s7_standard_pkt(dst_ip: str, sport: int, full_payload: bytes):
    pkt = IP(src=VM_LOCAL_IP, dst=dst_ip)/TCP(sport=sport, dport=S7_TCP_PORT, flags="PA")/Raw(load=full_payload)
    send(pkt, verbose=0)
    return pkt

# TCP同步查询（用于资产探测，需要接收应答）
def s7_tcp_query(dst_ip: str, payload: bytes, timeout=2) -> bytes:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((dst_ip, S7_TCP_PORT))
        sock.sendall(payload)
        resp = sock.recv(4096)
        sock.close()
        return resp
    except Exception as e:
        S7Log.warn(f"TCP连接失败 {dst_ip}:{S7_TCP_PORT} -> {str(e)}")
        return b""