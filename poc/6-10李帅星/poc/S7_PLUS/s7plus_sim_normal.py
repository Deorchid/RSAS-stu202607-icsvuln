from s7plus_base import *

DEST_IP = TARGET_LOOPBACK

# 仿真读取生产工艺DB块（合规标准读报文）
def sim_normal_read_db(db_id: int, offset: int, read_len: int):
    read_param = struct.pack(">BBHHHB", 0x04, 0x01, 0x84, db_id, offset, read_len)
    pdu = build_s7_pdu(JOB_REQ, seq=0x0001, sess_id=VALID_SESS_ID, param_buf=read_param, data_buf=b"")
    full_packet = wrap_tpkt_cotp(pdu)
    send_s7_standard_pkt(DEST_IP, sport=51234, full_payload=full_packet)
    S7Log.info(f"仿真正常流量：读取DB{db_id}，偏移{offset}，读取长度{read_len}字节")

# 仿真写入设备控制参数（合规标准写报文）
def sim_normal_write_db(db_id: int, offset: int, ctrl_data: bytes):
    write_param = struct.pack(">BBHHHB", 0x05, 0x01, 0x84, db_id, offset, len(ctrl_data))
    pdu = build_s7_pdu(JOB_REQ, seq=0x0002, sess_id=VALID_SESS_ID, param_buf=write_param, data_buf=ctrl_data)
    full_packet = wrap_tpkt_cotp(pdu)
    send_s7_standard_pkt(DEST_IP, sport=51235, full_payload=full_packet)
    S7Log.info(f"仿真正常流量：写入DB{db_id}控制参数，载荷长度 {len(ctrl_data)} 字节")

if __name__ == "__main__":
    print("===== 启动S7-Plus正常业务流量模拟器 =====")
    sim_normal_read_db(db_id=1, offset=0, read_len=32)
    # 写入温度控制浮点值
    temp_ctrl = struct.pack(">f", 58.2)
    sim_normal_write_db(db_id=1, offset=32, ctrl_data=temp_ctrl)
    print("===== 正常流量发送完毕，Wireshark选中【本地连接*8】过滤 tcp.port == 102 抓包 =====\n")