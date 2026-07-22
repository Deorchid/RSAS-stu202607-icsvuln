from iec_base import *

DEST = LOOPBACK_DST

# 遥测数据周期上报（电压、电流、有功功率浮点值）
def sim_normal_telemetry(cycle: int, volt: float, curr: float, power: float):
    # ASDU载荷：地址+三遥测浮点数据
    asdu_data = struct.pack("<Hfff", cycle, volt, curr, power)
    full_frame = build_iec_frame(apci_type=0x00, tx_seq=cycle, rx_seq=0, asdu_payload=asdu_data)
    send_iec_tcp_pkt(DEST, sport=52000 + cycle, full_frame=full_frame)
    IECLog.info(f"周期{cycle}正常遥测报文：电压={volt:.2f}kV 电流={curr:.1f}A 有功={power:.2f}MW")

if __name__ == "__main__":
    print("===== 启动IEC104变电站正常遥测流量模拟器 =====")
    sim_normal_telemetry(1, volt=10.52, curr=225.6, power=2120.35)
    sim_normal_telemetry(2, volt=10.48, curr=223.1, power=2095.72)
    sim_normal_telemetry(3, volt=10.55, curr=228.3, power=2156.10)
    print("===== 流量发送完成，Wireshark过滤 tcp.port == 2404 抓包 =====\n")