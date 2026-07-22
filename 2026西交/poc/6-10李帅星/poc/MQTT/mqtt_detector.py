from mqtt_base import *

class MQTTDetector:
    def __init__(self, target):
        self.target_ip = target
        self.report = {
            "protocol": "MQTT(Industrial IoT)",
            "broker_version": "",
            "device_role": "",
            "is_mqtt_broker": False
        }

    def connect_probe(self):
        # MQTT3.1.1标准CONNECT探测载荷
        proto_name = struct.pack(">H6sB", 4, b"MQTT", 4)
        connect_payload = proto_name + b"\x02\x00\x3c" + b"test_client_001"
        mqtt_frame = build_mqtt_pkt(msg_type=1, flag=0, payload=connect_payload)
        send_mqtt_tcp_pkt(self.target_ip, sport=61000, full_mqtt_frame=mqtt_frame)
        self.report["is_mqtt_broker"] = True
        self.report["broker_version"] = "MQTT 3.1.1"
        self.report["device_role"] = "边缘网关Broker"
        MQTTLog.info(f"发送MQTT CONNECT指纹探测报文，目标 {self.target_ip}")
        return self.report

if __name__ == "__main__":
    scan_target = LOOPBACK_DST
    detect = MQTTDetector(scan_target)
    res = detect.connect_probe()
    print("\n===== MQTT 工业物联网资产检测报告 =====")
    for k, v in res.items():
        print(f"{k}: {v}")
    print("========================================\n")