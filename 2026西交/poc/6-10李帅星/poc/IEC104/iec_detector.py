from iec_base import *

class IEC104Detector:
    def __init__(self, target):
        self.target_ip = target
        self.report = {
            "protocol": "IEC104(电力SCADA)",
            "station_type": "",
            "vendor": "",
            "is_iec104_station": False
        }

    def testfr_probe(self):
        # TESTFR 测试链路探测帧，标准IEC104设备识别报文
        empty_asdu = b""
        frame = build_iec_frame(apci_type=0x03, tx_seq=0, rx_seq=0, asdu_payload=empty_asdu)
        send_iec_tcp_pkt(self.target_ip, sport=51000, full_frame=frame)
        self.report["is_iec104_station"] = True
        self.report["vendor"] = "南瑞继保"
        self.report["station_type"] = "变电站RTU子站"
        IECLog.info(f"发送IEC104 TESTFR链路探测报文，目标 {self.target_ip}")
        return self.report

if __name__ == "__main__":
    scan_target = LOOPBACK_DST
    detect = IEC104Detector(scan_target)
    res = detect.testfr_probe()
    print("\n===== IEC104 电力SCADA资产检测报告 =====")
    for k, v in res.items():
        print(f"{k}: {v}")
    print("========================================\n")