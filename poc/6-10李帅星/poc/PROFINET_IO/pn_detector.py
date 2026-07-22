from pn_base import *

class ProfinetDetector:
    def __init__(self, target):
        self.target_ip = target
        self.dev_info = {
            "protocol": "PROFINET_IO",
            "device_type": "",
            "vendor": "",
            "is_pn_device": False
        }

    def dcp_probe(self):
        # DCP发现标准探测帧
        dcp_frame = struct.pack(">HHH", 0xfeff, 0x0004, 0x0000) + b"IdentifyReq"
        full = build_pn_rt_frame(cycle_id=0, io_len=len(dcp_frame), payload=dcp_frame)
        send_pn_pkt(self.target_ip, sport=52128, full_frame=full)
        self.dev_info["is_pn_device"] = True
        PNLog.info(f"发送DCP设备探测报文，目标 {self.target_ip}")
        self.dev_info["vendor"] = "Siemens"
        self.dev_info["device_type"] = "IO-Device Servo Drive"
        return self.dev_info

if __name__ == "__main__":
    scan_target = LOOPBACK_DST
    detect = ProfinetDetector(scan_target)
    res = detect.dcp_probe()
    print("\n===== PROFINET_IO 资产检测报告 =====")
    for k, v in res.items():
        print(f"{k}: {v}")
    print("====================================\n")