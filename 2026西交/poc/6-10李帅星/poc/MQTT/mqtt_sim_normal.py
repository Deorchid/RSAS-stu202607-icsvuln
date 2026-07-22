from mqtt_base import *

DEST = LOOPBACK_DST

# 传感器周期上报正常PUBLISH报文
def sim_normal_publish(cycle: int, temp: float, press: float, dev_status: int):
    # 主题长度+主题名 + 报文ID + 传感器数据
    topic = b"factory/line1/sensor"
    topic_head = struct.pack(">H", len(topic))
    msg_id = struct.pack(">H", cycle)
    sensor_data = struct.pack(">ffB", temp, press, dev_status)
    full_payload = topic_head + topic + msg_id + sensor_data
    mqtt_frame = build_mqtt_pkt(msg_type=3, flag=0, payload=full_payload)
    send_mqtt_tcp_pkt(DEST, sport=62000 + cycle, full_mqtt_frame=mqtt_frame)
    MQTTLog.info(f"周期{cycle}正常上报：温度={temp:.1f} 压力={press:.2f} 设备状态={dev_status}")

if __name__ == "__main__":
    print("===== 启动工业MQTT传感器正常上报流量模拟器 =====")
    sim_normal_publish(1, temp=26.3, press=0.62, dev_status=1)
    sim_normal_publish(2, temp=27.1, press=0.65, dev_status=1)
    sim_normal_publish(3, temp=25.8, press=0.60, dev_status=0)
    print("===== 流量发送完成，Wireshark过滤 tcp.port == 1883 抓包 =====\n")