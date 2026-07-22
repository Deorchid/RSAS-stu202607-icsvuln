"""
CIP 协议信息检测逻辑 — 全维度威胁检测:
  会话跟踪, 服务代码评分, 路径分析, 路由深度, 序列号校验,
  连接滥用, 电子键验证, 符号段滥用, UCMM 洪水检测。
"""

import struct
import time
import logging
from collections import defaultdict
from typing import Dict, Any, Optional, List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CIPDetect")

# ── 服务代码名称 ──
SVC_NAMES = {
    0x01: "GetAttributeAll",       0x02: "SetAttributeAll",
    0x03: "GetAttributesList",     0x04: "SetAttributesList",
    0x0E: "GetAttributeSingle",    0x10: "SetAttributeSingle",
    0x4E: "ForwardOpen",           0x4F: "ForwardClose",
    0x52: "Reset",                 0x53: "Start",
    0x54: "Stop",                  0x55: "Create",
    0x56: "Delete",                0x57: "MultipleService",
}

# ── 威胁评分权重 ──
SVC_THREAT_SCORES = {
    0x52: 40,  # Reset
    0x54: 40,  # Stop
    0x56: 35,  # Delete
    0x10: 25,  # SetAttributeSingle
    0x02: 30,  # SetAttributeAll
    0x55: 20,  # Create
    0x57: 30,  # MultipleService
    0x4E: 15,  # ForwardOpen
    0x4F: 10,  # ForwardClose
    0x01: 5,   # GetAttributeAll (enumeration)
    0x0E: 5,   # GetAttributeSingle
}

# ── 关键对象类 ──
CRITICAL_CLASSES = {1: "Identity", 4: "Assembly", 5: "Connection",
                    6: "ConnectionManager", 0xF6: "TCP/IP"}
PATH_CLASSES = {1: "Identity", 2: "MessageRouter", 4: "Assembly", 5: "Connection",
                6: "ConnectionManager", 7: "Register", 8: "DiscreteInputPoint",
                9: "DiscreteOutputPoint", 10: "AnalogInputPoint",
                11: "AnalogOutputPoint", 15: "ParameterObject",
                0xF6: "TCP/IP", 0xF7: "EthernetLink"}

# ── 路径段类型 ──
SEG_EKEY       = 0x34
SEG_SYM_ANSI   = 0x71
SEG_PORT       = 0x00
SEG_LOGICAL_20 = 0x20
SEG_LOGICAL_24 = 0x24
SEG_LOGICAL_30 = 0x30

# ── 异常码名称 ──
STATUS_NAMES = {
    0x00: "Success",         0x08: "Service Not Supported",
    0x09: "Invalid Attribute", 0x0F: "Privilege Violation",
    0x05: "Path Destination Unknown", 0x04: "Path Segment Error",
    0x0C: "Object State Conflict",     0x0E: "Attribute Not Settable",
    0x13: "Not Enough Data",          0x01: "Connection Failure",
    0x20: "Invalid Parameter",        0x15: "Embedded Service Error",
}


# ── 检测结果 ──
class DetectionResult:
    def __init__(self, protocol="CIP", alert=False, severity="info",
                 message="", details=None, threat_score=0):
        self.protocol = protocol
        self.alert = alert
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.threat_score = threat_score

    def __repr__(self):
        return (f"[{self.severity.upper()}] "
                f"{'ALERT' if self.alert else 'INFO'} "
                f"[{self.protocol}] {self.message} "
                f"(score={self.threat_score})")


# ── 会话跟踪 ──
class CIPSession:
    __slots__ = ("src_ip", "last_seq", "expected_seq", "last_activity",
                 "open_count", "close_count", "msg_count", "write_count",
                 "reset_count", "stop_count", "ucmm_count", "established",
                 "first_seen")

    def __init__(self, src_ip: str):
        self.src_ip = src_ip
        self.last_seq = -1
        self.expected_seq = 1
        self.last_activity = time.time()
        self.open_count = 0
        self.close_count = 0
        self.msg_count = 0
        self.write_count = 0
        self.reset_count = 0
        self.stop_count = 0
        self.ucmm_count = 0
        self.established = False
        self.first_seen = time.time()

    def bump(self):
        self.last_activity = time.time()
        self.msg_count += 1


# ── 路径段解析器 ──
def parse_path_segments(raw_path: bytes) -> List[Dict[str, Any]]:
    segments = []
    offset = 0
    while offset < len(raw_path):
        if offset >= len(raw_path):
            break
        b = raw_path[offset]
        seg = {"type": b, "type_name": f"0x{b:02X}"}

        if (b & 0xE0) == 0x20:
            seg["type_name"] = "LogicalClass" if (b & 0x10) else "LogicalInstance"
            if b & 0x02:
                if offset + 2 >= len(raw_path):
                    break
                seg["value"] = struct.unpack_from("<H", raw_path, offset + 1)[0]
                seg["size"] = 16
                offset += 3
            else:
                seg["value"] = raw_path[offset + 1] if offset + 1 < len(raw_path) else 0
                seg["size"] = 8
                offset += 2
        elif (b & 0xF0) == 0x30:
            seg["type_name"] = "LogicalAttribute"
            if b & 0x02:
                if offset + 2 >= len(raw_path):
                    break
                seg["value"] = struct.unpack_from("<H", raw_path, offset + 1)[0]
                seg["size"] = 16
                offset += 3
            else:
                seg["value"] = raw_path[offset + 1] if offset + 1 < len(raw_path) else 0
                seg["size"] = 8
                offset += 2
        elif b == 0x34:
            seg["type_name"] = "ElectronicKey"
            if offset + 10 <= len(raw_path):
                seg["vendor"] = struct.unpack_from("<H", raw_path, offset + 2)[0]
                seg["device_type"] = struct.unpack_from("<H", raw_path, offset + 4)[0]
                seg["product_code"] = struct.unpack_from("<H", raw_path, offset + 6)[0]
                seg["major"] = raw_path[offset + 8]
                seg["minor"] = raw_path[offset + 9]
            offset += 10
        elif (b & 0xF0) == 0x70:
            seg["type_name"] = "Symbolic"
            if b == 0x71:
                if offset + 1 < len(raw_path):
                    sym_len = raw_path[offset + 1]
                    start = offset + 2
                    end = start + sym_len
                    if end <= len(raw_path):
                        seg["symbol"] = raw_path[start:end].decode("ascii", errors="replace")
                    pad = (sym_len + 2) % 2
                    offset = end + pad
                    segments.append(seg)
                    continue
            offset += 1
        else:
            port = (b & 0xF0) >> 4
            link_len = b & 0x0F
            seg["type_name"] = "Port"
            seg["port"] = port
            seg["link_size"] = link_len
            offset += 1 + link_len

        segments.append(seg)

    return segments


# ── 主检测器 ──
class CIPDetector:
    def __init__(self):
        self.name = "CIPDetector"
        self.sessions: Dict[str, CIPSession] = {}
        self._conn_rate_tracker: Dict[str, List[float]] = defaultdict(list)
        self._ucmm_tracker: Dict[str, List[float]] = defaultdict(list)

    def _get_session(self, src_ip: str) -> CIPSession:
        if src_ip not in self.sessions:
            self.sessions[src_ip] = CIPSession(src_ip)
        return self.sessions[src_ip]

    def _cleanup_stale(self, max_age=300):
        now = time.time()
        stale = [k for k, s in self.sessions.items()
                 if now - s.last_activity > max_age]
        for k in stale:
            del self.sessions[k]

    # ── 数据包解析 ──
    def parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 2:
            return None

        offset = 0
        info: Dict[str, Any] = {"protocol": "cip"}

        # 检测前缀
        if len(data) >= 8 and data[0] == 0xFF and data[1] == 0xFE:
            info["mode"] = "connected"
            info["connection_id"] = struct.unpack_from("<H", data, 2)[0]
            info["sequence_num"] = struct.unpack_from("<H", data, 4)[0]
            offset = 6
        elif len(data) >= 6 and data[0] == 0xFF and data[1] == 0xFD:
            info["mode"] = "ucmm"
            info["tick_time"] = struct.unpack_from("<H", data, 2)[0]
            info["timeout"] = struct.unpack_from("<H", data, 4)[0]
            offset = 6
        else:
            info["mode"] = "unconnected"

        try:
            svc_raw = data[offset] if offset < len(data) else 0
            is_resp = bool(svc_raw & 0x80)
            actual_svc = svc_raw & 0x7F

            info["service_code_raw"] = svc_raw
            info["service_code"] = actual_svc
            info["service_name"] = SVC_NAMES.get(actual_svc, f"Unknown(0x{actual_svc:02X})")
            info["is_response"] = is_resp

            plen = data[offset + 1] if offset + 1 < len(data) else 0
            info["path_len"] = plen

            if is_resp and len(data) > offset + 4:
                info["general_status"] = struct.unpack_from("<H", data, offset + 2)[0]
                info["status_name"] = STATUS_NAMES.get(
                    info["general_status"],
                    f"Error(0x{info['general_status']:04X})"
                )

            if plen > 0 and len(data) >= offset + 2 + plen * 2:
                raw_path = data[offset + 2 : offset + 2 + plen * 2]
                info["path_hex"] = raw_path.hex()
                segments = parse_path_segments(raw_path)
                info["path_segments"] = segments
                info["segment_count"] = len(segments)

                for seg in segments:
                    if seg["type_name"] == "LogicalClass":
                        info["class_id"] = seg.get("value", 0)
                        info["class_name"] = PATH_CLASSES.get(
                            info["class_id"],
                            f"0x{info['class_id']:04X}"
                        )
                    elif seg["type_name"] == "LogicalInstance":
                        info["instance_id"] = seg.get("value", 0)
                    elif seg["type_name"] == "LogicalAttribute":
                        info["attribute_id"] = seg.get("value", 0)
                    elif seg["type_name"] == "ElectronicKey":
                        info["electronic_key"] = {
                            "vendor": seg.get("vendor"),
                            "device_type": seg.get("device_type"),
                            "product_code": seg.get("product_code"),
                            "major": seg.get("major"),
                            "minor": seg.get("minor"),
                        }
                    elif seg["type_name"] == "Symbolic" and "symbol" in seg:
                        info["symbol_segment"] = seg["symbol"]
        except Exception:
            return None

        return info

    # ── 主检测逻辑 ──
    def detect(self, data: bytes, src_addr=None, dst_addr=None) -> DetectionResult:
        info = self.parse_packet(data)
        if not info:
            return DetectionResult("CIP", False, "low", "Invalid CIP packet")

        src_ip = src_addr[0] if src_addr else "0.0.0.0"
        session = self._get_session(src_ip)
        session.bump()

        details = info.copy()
        svc = info.get("service_code", 0)
        svc_name = info.get("service_name", "")
        cls_id = info.get("class_id", 0)
        cls_name = info.get("class_name", "")
        is_resp = info.get("is_response", False)
        mode = info.get("mode", "unconnected")

        threat_score = 0
        alerts: List[str] = []
        sev = "info"

        # ── 响应分析 ──
        if is_resp:
            status = info.get("general_status", 0)
            if status != 0:
                st_name = info.get("status_name", f"0x{status:04X}")
                return DetectionResult("CIP", True, "medium",
                    f"CIP error response: {st_name} (service={svc_name})", details, 5)
            return DetectionResult("CIP", False, "info",
                f"CIP response: {svc_name}", details, 0)

        # ── UCMM 洪水检测 ──
        if mode == "ucmm":
            now = time.time()
            self._ucmm_tracker[src_ip] = [
                t for t in self._ucmm_tracker[src_ip] if now - t < 10
            ]
            self._ucmm_tracker[src_ip].append(now)
            session.ucmm_count += 1
            if len(self._ucmm_tracker[src_ip]) > 50:
                sev = "high"
                threat_score += 20
                alerts.append(f"UCMM flood: {len(self._ucmm_tracker[src_ip])} msgs/10s")

        # ── 序列号跟踪 (connected) ──
        if mode == "connected":
            seq = info.get("sequence_num", 0)
            if seq != 0:
                if seq <= session.last_seq and session.last_seq >= 0:
                    alerts.append(f"Out-of-order/replayed seq_num={seq} (last={session.last_seq})")
                    threat_score += 15
                    sev = max(sev, "high")
                if seq != session.expected_seq and session.expected_seq > 1:
                    alerts.append(f"Unexpected seq_num={seq} (expected={session.expected_seq})")
                    threat_score += 10
                    sev = max(sev, "medium")
                session.expected_seq = seq + 1
            session.last_seq = max(session.last_seq, seq)
            session.established = True

        # ── 连接滥用检测 ──
        if svc == 0x4E:
            session.open_count += 1
            now = time.time()
            self._conn_rate_tracker[src_ip] = [
                t for t in self._conn_rate_tracker[src_ip] if now - t < 10
            ]
            self._conn_rate_tracker[src_ip].append(now)
            rate = len(self._conn_rate_tracker[src_ip])
            if rate > 10:
                sev = max(sev, "high")
                alerts.append(f"Rapid ForwardOpen: {rate} in 10s")
                threat_score += 25
        if svc == 0x4F:
            session.close_count += 1
            if session.close_count > 0:
                ratio = session.close_count / max(session.open_count, 1)
                if ratio > 3:
                    alerts.append(f"ForwardOpen/Close imbalance: O={session.open_count} C={session.close_count}")
                    threat_score += 10
                    sev = max(sev, "medium")

        # ── 威胁评分基础分 ──
        base_score = SVC_THREAT_SCORES.get(svc, 5)
        threat_score += base_score

        # ── CRITICAL 服务 ──
        if svc == 0x52:
            session.reset_count += 1
            alerts.append(f"Reset on {cls_name}({cls_id}) — device deactivation")
            sev = "critical"
        if svc == 0x54:
            session.stop_count += 1
            alerts.append(f"Stop on {cls_name}({cls_id}) — device deactivation")
            sev = "critical"
        if svc == 0x56:
            alerts.append(f"Delete on {cls_name}({cls_id}) inst={info.get('instance_id',0)}")
            sev = max(sev, "high")

        # ── 路径分析: 关键对象 + 写操作 ──
        if cls_id in CRITICAL_CLASSES:
            crit_name = CRITICAL_CLASSES[cls_id]
            if svc in (0x02, 0x10, 0x04):
                threat_score += 15
                sev = max(sev, "high")
                alerts.append(f"Write to critical class {crit_name}({cls_id}) via {svc_name}")
            if svc == 0x4E and cls_id == 6:
                sev = max(sev, "high")
                alerts.append("ForwardOpen targeting ConnectionManager")

        # ── SetAttributeSingle 特殊分析 ──
        if svc == 0x10 or svc == 0x02:
            session.write_count += 1
            attr_id = info.get("attribute_id", 0)
            if cls_id == 4 and attr_id == 3:
                threat_score += 15
                sev = max(sev, "critical")
                alerts.append("Assembly data write — possible payload modification")
            if cls_id == 6:
                threat_score += 10
                sev = max(sev, "critical")
                alerts.append("ConnectionManager attribute write — connection manipulation")

        # ── 路径深度检测 ──
        seg_count = info.get("segment_count", 0)
        if seg_count > 3:
            threat_score += (seg_count - 3) * 5
            sev = max(sev, "medium")
            alerts.append(f"Deep routing: {seg_count} path segments — potential routing attack")

        # ── 电子键校验失败 ──
        if "electronic_key" in info:
            ek = info["electronic_key"]
            if ek.get("vendor") != 0x0001:
                alerts.append(f"Electronic key mismatch: vendor={ek.get('vendor')}")
                threat_score += 10
                sev = max(sev, "medium")

        # ── 符号段滥用 ──
        if "symbol_segment" in info:
            sym = info["symbol_segment"]
            alerts.append(f"Symbolic segment: '{sym}' — potential path traversal")
            threat_score += 12
            sev = max(sev, "high")
            if ".." in sym or "/" in sym:
                threat_score += 20
                sev = "critical"
                alerts.append(f"Path traversal via symbolic segment: '{sym}'")

        # ── Enumeration 检测 ──
        if svc == 0x01:
            if cls_id == 1:
                alerts.append("Identity enumeration via GetAttributeAll — fingerprinting")
                threat_score += 5

        # ── MultipleService ──
        if svc == 0x57:
            alerts.append("MultipleService — potential compound attack")
            sev = max(sev, "high")

        # ── 构建消息 ──
        if alerts:
            message = "; ".join(alerts)
            alert_flag = True
        else:
            message = f"CIP {svc_name} on {cls_name}({cls_id})"
            alert_flag = (threat_score >= 25)

        return DetectionResult("CIP", alert_flag, sev, message, details, threat_score)


if __name__ == "__main__":
    d = CIPDetector()
    tests = [
        (b"\x0E\x03\x20\x01\x24\x01\x30\x01", "GetAttributeSingle (Identity attr1)"),
        (b"\x54\x02\x20\x06\x24\x01", "Stop on ConnectionManager"),
        (b"\x10\x03\x20\x04\x24\x01\x30\x03\x00\x00\x00\x01",
         "SetAttributeSingle on Assembly data"),
        (b"\x52\x02\x20\x04\x24\x01", "Reset"),
        (b"\x01\x02\x20\x01\x24\x01", "GetAttributeAll on Identity"),
        (b"\xFF\xFE\x01\x00\x05\x00\x0E\x03\x20\x10\x24\x01\x30\x03",
         "Connected GetAttributeSingle"),
        (b"\x57\x02\x20\x04\x24\x01", "MultipleService"),
        (b"\x4E\x02\x20\x06\x24\x01", "ForwardOpen"),
    ]
    for data, desc in tests:
        result = d.detect(data, src_addr=("192.168.1.100", 12345))
        log.info("  [%s] %s", desc, result)
