from s7plus_base import *

class S7PlusAssetDetector:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.asset_info = {
            "protocol": "S7_PLUS",
            "vendor": "Siemens",
            "model": "",
            "firmware": "",
            "is_s7plus_device": False
        }

    # 标准握手探测包（符合TPKT/COTP/S7PDU结构）
    def handshake_probe(self):
        empty_pdu = build_s7_pdu(JOB_REQ, 0x0001, 0x00000000, b"", b"")
        probe_packet = wrap_tpkt_cotp(empty_pdu)
        response = s7_tcp_query(self.target_ip, probe_packet)
        if not response.startswith(b"\x03\x00"):
            return False
        self.asset_info["is_s7plus_device"] = True
        S7Log.info(f"目标 {self.target_ip} 识别为S7Comm-Plus协议设备")
        return response

    # 读取系统DB标准报文，解析PLC型号、固件版本
    def get_full_device_info(self):
        resp = self.handshake_probe()
        if not resp:
            return self.asset_info
        # 标准读取系统信息参数段 0x04 读DB0
        read_sys_param = struct.pack(">BBHHHB", 0x04, 0x01, 0x84, 0, 0, 64)
        read_pdu = build_s7_pdu(JOB_REQ, 0x0002, VALID_SESS_ID, read_sys_param, b"")
        full_pkt = wrap_tpkt_cotp(read_pdu)
        sys_response = s7_tcp_query(self.target_ip, full_pkt)

        # 匹配设备型号指纹
        if b"S7-1500" in sys_response:
            self.asset_info["model"] = "S7-1500 Series"
        elif b"S7-1200" in sys_response:
            self.asset_info["model"] = "S7-1200 Series"
        # 提取固件版本号
        if b"V" in sys_response:
            ver_pos = sys_response.index(b"V")
            self.asset_info["firmware"] = sys_response[ver_pos:ver_pos+6].decode("ascii", errors="ignore")
        S7Log.info(f"识别设备：{self.asset_info['model']} | 固件 {self.asset_info['firmware']}")
        return self.asset_info

if __name__ == "__main__":
    # 无PLC时执行会提示连接拒绝，仅演示检测逻辑；有本地PLC仿真可填127.0.0.1
    scan_target = TARGET_LOOPBACK
    scanner = S7PlusAssetDetector(scan_target)
    report = scanner.get_full_device_info()
    print("\n===== S7_PLUS 资产检测报告 =====")
    for k, v in report.items():
        print(f"{k}: {v}")
    print("================================\n")