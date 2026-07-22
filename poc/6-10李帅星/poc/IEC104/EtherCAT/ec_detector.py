from ec_base import *

class EtherCATDetector:
    def __init__(self, target_ip):
        self.target = target_ip
        self.asset_report = {
            "protocol": "EtherCAT",
            "device_model": "",
            "vendor": "",
            "is_ecat_device": False
        }

    def al_state_probe(self):
        # AL状态读取标准探测帧（EtherCAT原生设备发现指令）
        probe_payload = struct.pack("<B", 0x01)  # AL状态读指令
        frame = build_ecat_frame(slave_cnt=1, wkc=0, payload=probe_payload)
        send_ec_pkt(self.target, sport=55001, full_frame=frame)
        # 模拟识别结果
        self.asset_report["is_ecat_device"] = True
        self.asset_report["vendor"] = "Beckhoff"
        self.asset_report["device_model"] = "EK1100 IO耦合器+伺服从站"
        ECLog.info(f"发送EtherCAT AL状态探测报文，目标 {self.target}")
        return self.asset_report

if __name__ == "__main__":
    scan_target = LOOPBACK_DST
    detect = EtherCATDetector(scan_target)
    res = detect.al_state_probe()
    print("\n===== EtherCAT 资产检测报告 =====")
    for key, val in res.items():
        print(f"{key}: {val}")
    print("==================================\n")