from pn_base import *

DEST = LOOPBACK_DST

# 周期IO输出：伺服速度、位置正常控制数据
def sim_normal_io_cycle(cycle_num: int, pos: float, speed: float):
    # 标准IO载荷：位置+速度浮点参数
    io_data = struct.pack(">ff", pos, speed)
    full_frame = build_pn_rt_frame(cycle_id=cycle_num, io_len=len(io_data), payload=io_data)
    send_pn_pkt(DEST, sport=51000+cycle_num, full_frame=full_frame)
    PNLog.info(f"周期{cycle_num}正常IO报文：伺服位置{pos},转速{speed}")

if __name__ == "__main__":
    print("===== 启动PROFINET_IO运动控制正常流量模拟器 =====")
    sim_normal_io_cycle(1, pos=1250.0, speed=45.2)
    sim_normal_io_cycle(2, pos=1680.5, speed=62.8)
    sim_normal_io_cycle(3, pos=920.0, speed=30.1)
    print("===== 正常流量发送完毕，Wireshark过滤 udp.port == 34964 抓包 =====\n")