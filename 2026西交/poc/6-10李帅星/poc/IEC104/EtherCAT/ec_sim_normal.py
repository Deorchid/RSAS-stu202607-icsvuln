from ec_base import *

DEST_ADDR = LOOPBACK_DST

# 标准周期IO报文：伺服位置、转速、扭矩浮点数据
def sim_normal_cycle(cycle_id: int, pos: float, speed: float, torque: float):
    io_payload = struct.pack("<fff", pos, speed, torque)
    full_frame = build_ecat_frame(slave_cnt=4, wkc=12, payload=io_payload)
    send_ec_pkt(DEST_ADDR, sport=55100 + cycle_id, full_frame=full_frame)
    ECLog.info(f"周期{cycle_id}正常IO帧：位置={pos:.2f} 转速={speed:.1f} 扭矩={torque:.1f}")

if __name__ == "__main__":
    print("===== 启动EtherCAT机器人伺服正常流量模拟器 =====")
    sim_normal_cycle(1, pos=1320.0, speed=60.5, torque=12.3)
    sim_normal_cycle(2, pos=1580.2, speed=42.1, torque=9.8)
    sim_normal_cycle(3, pos=890.5, speed=33.6, torque=15.2)
    print("===== 流量发送完成，Wireshark过滤 udp.port == 8899 抓包 =====\n")