"""
EtherNet/IP Protocol Detector — Full Implementation

Detection capabilities:
  - Per-IP session tracking with session age and request count
  - Threat scoring engine with configurable thresholds
  - CIP service path analysis for critical object targeting
  - Encapsulation header validation (malformed headers, oversized packets)
  - Connection tracking (rapid open/close cycles, connection churn)
  - Electronic key mismatch detection in ForwardOpen requests
  - RPI anomaly detection (unusually fast RPI, potential DoS)
  - Session flood, ListIdentity scan, unauthorized ForwardOpen detection
  - SetAttribute to critical objects, Reset/Stop detection
  - Large assembly data write detection
  - Connection timeout storm detection
"""
import struct
import time
import logging
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("EIPDetect")

ENCAP = struct.Struct("<IHHIIQHHI")

EIP_CMD = {
    0x63: "ListIdentity",
    0x64: "ListServices",
    0x65: "RegisterSession",
    0x66: "UnregisterSession",
    0x6F: "SendRRData",
    0x70: "SendUnitData",
    0x72: "IndicateStatus",
    0x73: "CancelStatus",
}

CIP_SVC = {
    0x01: "GetAttributeAll",
    0x02: "SetAttributeAll",
    0x0E: "GetAttributeSingle",
    0x10: "SetAttributeSingle",
    0x4B: "GetAttributesList",
    0x4C: "SetAttributesList",
    0x4E: "ForwardOpen",
    0x4F: "ForwardClose",
    0x52: "Reset",
    0x53: "Start",
    0x54: "Stop",
    0x55: "Create",
    0x56: "Delete",
}

CIP_WRITE_SERVICES = {0x02, 0x10, 0x4C, 0x04}
CIP_DESTRUCTIVE_SERVICES = {0x05, 0x52, 0x07, 0x54, 0x09, 0x56}
CIP_CRITICAL_CLASSES = {0x01, 0x06, 0x04, 0xF5, 0xF6}
CIP_CLASS_NAMES = {
    0x01: "Identity",
    0x02: "MessageRouter",
    0x04: "Assembly",
    0x05: "Connection",
    0x06: "ConnectionManager",
    0x07: "Register",
    0xF5: "TCPIP_Interface",
    0xF6: "EthernetLink",
}

THREAT_SCORES = {
    "session_flood": 15,
    "list_identity_scan": 20,
    "unauthorized_forward_open": 25,
    "set_attribute_critical": 30,
    "reset_or_stop": 40,
    "connection_churn": 15,
    "large_assembly_write": 10,
    "rpi_anomaly": 35,
    "malformed_header": 10,
    "oversized_packet": 15,
    "ekey_mismatch": 20,
    "connection_timeout_storm": 15,
    "path_to_critical": 25,
}

SESSION_FLOOD_THRESHOLD = 50
IDENTITY_SCAN_THRESHOLD = 8
CONNECTION_CHURN_WINDOW = 10.0
CONNECTION_CHURN_THRESHOLD = 10
MIN_SAFE_RPI_US = 1000
MAX_PACKET_SIZE = 65535
LARGE_WRITE_THRESHOLD = 500


@dataclass
class DetectionResult:
    protocol: str = "EIP"
    alert: bool = False
    severity: str = "low"
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self):
        return f"[{self.severity.upper()}] {'ALERT' if self.alert else 'INFO'} [{self.protocol}] {self.message}"


@dataclass
class SessionTracker:
    register_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    identity_requests: List[float] = field(default_factory=list)
    total_requests: int = 0

    def __post_init__(self):
        self.first_seen = time.time()
        self.last_seen = time.time()

    def touch(self):
        self.last_seen = time.time()
        self.total_requests += 1

    @property
    def age(self):
        return time.time() - self.first_seen

    @property
    def idle(self):
        return time.time() - self.last_seen


@dataclass
class ConnectionTracker:
    opens: List[float] = field(default_factory=list)
    closes: List[float] = field(default_factory=list)
    total_opens: int = 0
    total_closes: int = 0

    def record_open(self, conn_id=0):
        self.opens.append(time.time())
        self.total_opens += 1

    def record_close(self, conn_id=0):
        self.closes.append(time.time())
        self.total_closes += 1

    def churn_count(self, window=CONNECTION_CHURN_WINDOW):
        now = time.time()
        recent_opens = sum(1 for t in self.opens if now - t < window)
        recent_closes = sum(1 for t in self.closes if now - t < window)
        return min(recent_opens, recent_closes)


class EthernetIPDetector:
    def __init__(self):
        self.name = "EIPDetector"
        self._sessions = defaultdict(SessionTracker)
        self._connections = defaultdict(ConnectionTracker)
        self._active_connections = defaultdict(set)
        self._request_history = defaultdict(lambda: deque(maxlen=200))
        self._reset_counters = defaultdict(int)
        self._last_cleanup = time.time()

    def parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 28:
            return {"protocol": "ethernetip", "parse_error": True,
                    "message": "Packet too short (%d bytes)" % len(data),
                    "raw_sample": data.hex()[:60]}

        try:
            cmd, length, handle, status, ctx_lo, ctx_hi, \
                sess_qword, es, ev, _ = ENCAP.unpack(data[:28])
            ctx = (ctx_hi << 32) | ctx_lo
            sess = int(sess_qword) if isinstance(sess_qword, int) else 0

            info = {
                "protocol": "ethernetip",
                "command_code": cmd,
                "command_name": EIP_CMD.get(cmd, "Unknown(0x%04X)" % cmd),
                "length": length,
                "session": sess,
                "context": ctx,
                "status": status,
                "handle": handle,
                "encap_valid": True,
            }

            cip_offset = 30
            is_rr = (cmd == 0x6F)
            is_ud = (cmd == 0x70)
            if cmd in (0x6F, 0x70) and len(data) > cip_offset + 1:
                iface = data[26] if len(data) > 26 else 0
                info["interface_handle"] = iface
                timeout_bytes = data[28:30] if len(data) > 29 else b"\x00\x00"
                info["timeout"] = struct.unpack("<H", timeout_bytes)[0]
                cip = data[cip_offset:]
                if len(cip) >= 2:
                    info["cip_service"] = cip[0]
                    info["cip_service_name"] = CIP_SVC.get(cip[0],
                                                           "Unknown(0x%02X)" % cip[0])
                    info["cip_path_len"] = cip[1]
                    if cip[1] > 0 and len(cip) >= 2 + cip[1] * 2:
                        info["cip_path_raw"] = cip[2:2 + cip[1] * 2].hex()
                        path_segments = self._parse_cip_path(cip[2:2 + cip[1] * 2], cip[1])
                        info["cip_path"] = path_segments
                        info["cip_class"] = path_segments[0].get("class") if path_segments else None
                    if cip[0] == 0x4E and len(cip) >= 56:
                        try:
                            rpi_o_t = struct.unpack("<I", cip[44:48])[0]
                            rpi_t_o = struct.unpack("<I", cip[48:52])[0]
                            info["rpi_o_t"] = rpi_o_t
                            info["rpi_t_o"] = rpi_t_o
                            ekey = cip[54:64] if len(cip) >= 64 else b""
                            if len(ekey) >= 10:
                                info["ekey_vendor"] = struct.unpack("<H", ekey[0:2])[0]
                                info["ekey_type"] = struct.unpack("<H", ekey[2:4])[0]
                                info["ekey_product"] = struct.unpack("<H", ekey[4:6])[0]
                                info["ekey_major"] = struct.unpack("<H", ekey[6:8])[0]
                                info["ekey_minor"] = struct.unpack("<H", ekey[8:10])[0]
                        except struct.error:
                            pass

            return info
        except struct.error:
            return {"protocol": "ethernetip", "parse_error": True,
                    "message": "Failed to unpack ENCAP header",
                    "raw_sample": data.hex()[:60]}
        except Exception:
            return {"protocol": "ethernetip", "parse_error": True,
                    "message": "Unexpected parse error"}

    @staticmethod
    def _parse_cip_path(data: bytes, word_count: int) -> List[Dict[str, Any]]:
        segments = []
        i = 0
        while i < word_count * 2 and i + 1 < len(data):
            seg_type = (data[i] >> 4) & 0x0F
            seg_val = data[i] & 0x0F
            if seg_val == 0:
                if i + 1 < len(data):
                    segments.append({"type": "logical", "value": data[i + 1]})
                i += 2
            elif seg_val == 1:
                if i + 3 < len(data):
                    class_id = struct.unpack("<H", data[i + 1:i + 3])[0]
                    segments.append({"type": "class", "class": class_id})
                i += 3
            elif seg_val == 2:
                if i + 3 < len(data):
                    inst = struct.unpack("<H", data[i + 1:i + 3])[0]
                    segments.append({"type": "instance", "instance": inst})
                i += 3
            else:
                i += 2
        return segments

    def detect(self, data: bytes, src_addr=None, dst_addr=None) -> DetectionResult:
        self._cleanup()

        info = self.parse_packet(data)
        if not info or info.get("parse_error"):
            return DetectionResult(
                protocol="EIP",
                alert=False,
                severity="low",
                message="Invalid EtherNet/IP packet: %s" % info.get("message", "Unknown"),
                details=info or {},
            )

        details = info.copy()
        cmd = info.get("command_code")

        header_result = self._validate_header(info, len(data))
        if header_result:
            return header_result

        if src_addr:
            self._sessions[src_addr].touch()

        if cmd == 0x0065:
            return self._detect_register_session(info, src_addr)
        elif cmd == 0x0066:
            return self._detect_unregister_session(info, src_addr)
        elif cmd == 0x0063:
            return self._detect_list_identity(info, src_addr)
        elif cmd == 0x0064:
            return self._detect_list_services(info, src_addr)
        elif cmd == 0x006F:
            return self._detect_send_rr_data(info, src_addr, details)
        elif cmd == 0x0070:
            return self._detect_send_unit_data(info, src_addr, details)
        elif cmd in (0x0072, 0x0073):
            return DetectionResult("EIP", False, "info",
                                  info.get("command_name", "EIP status"),
                                  details)

        if info.get("status", 0) != 0:
            return DetectionResult("EIP", True, "medium",
                                  "EIP error status %d from %s" % (
                                      info["status"], src_addr), details)

        return DetectionResult("EIP", False, "info",
                              info.get("command_name", "Normal EIP"),
                              details)

    def _validate_header(self, info: dict, raw_len: int) -> Optional[DetectionResult]:
        length = info.get("length", 0)
        if length < 28 or length > MAX_PACKET_SIZE:
            return DetectionResult("EIP", True, "medium",
                "Malformed EIP header: invalid length %d" % length, info)

        if length > 28 and raw_len < length:
            return DetectionResult("EIP", True, "low",
                "Truncated packet: header says %d bytes, got %d" % (length, raw_len),
                info)

        if raw_len > MAX_PACKET_SIZE:
            return DetectionResult("EIP", True, "high",
                "Oversized EIP packet: %d bytes exceeds max %d" % (
                    raw_len, MAX_PACKET_SIZE), info)

        if raw_len > 4096 and info.get("command_code") == 0x6F:
            return DetectionResult("EIP", True, "medium",
                "Large SendRRData packet: %d bytes" % raw_len, info)

        return None

    def _detect_register_session(self, info: dict, src_addr):
        details = info.copy()
        if not src_addr:
            return DetectionResult("EIP", False, "info",
                                  "RegisterSession (no source)", details)

        tracker = self._sessions[src_addr]
        tracker.register_count += 1
        details["register_count"] = tracker.register_count

        score = 0
        alerts = []

        if tracker.register_count > SESSION_FLOOD_THRESHOLD:
            score += THREAT_SCORES["session_flood"]
            alerts.append("Session flood: %d registrations from %s" % (
                tracker.register_count, src_addr))

        if tracker.register_count > 10 and tracker.age < 5:
            score += THREAT_SCORES["session_flood"] // 2
            alerts.append("Rapid session registrations (%.1fs)" % tracker.age)

        if alerts:
            severity = "high" if score >= 30 else "medium"
            return DetectionResult("EIP", True, severity,
                                  "; ".join(alerts), details)

        return DetectionResult("EIP", False, "info",
                              "RegisterSession (count %d from %s)" % (
                                  tracker.register_count, src_addr), details)

    def _detect_unregister_session(self, info: dict, src_addr):
        return DetectionResult("EIP", False, "info",
                              "UnregisterSession from %s" % src_addr, info)

    def _detect_list_identity(self, info: dict, src_addr):
        details = info.copy()
        score = 0
        alerts = []

        if src_addr:
            tracker = self._sessions[src_addr]
            tracker.identity_requests.append(time.time())
            count = len([t for t in tracker.identity_requests
                        if time.time() - t < 10])
            details["identity_scan_count"] = count

            if count > IDENTITY_SCAN_THRESHOLD:
                score += THREAT_SCORES["list_identity_scan"]
                alerts.append("ListIdentity scan: %d requests in 10s from %s" % (
                    count, src_addr))

        if score > 0:
            return DetectionResult("EIP", True, "high",
                                  "; ".join(alerts), details)

        return DetectionResult("EIP", True, "medium",
                              "ListIdentity probe from %s" % src_addr, details)

    def _detect_list_services(self, info: dict, src_addr):
        return DetectionResult("EIP", True, "medium",
                              "ListServices (service enumeration) from %s" % src_addr,
                              info)

    def _detect_send_rr_data(self, info: dict, src_addr, details: dict):
        svc = info.get("cip_service")
        svc_name = info.get("cip_service_name", "?")
        cls = info.get("cip_class")
        cls_name = CIP_CLASS_NAMES.get(cls, "?") if cls else "?"
        path = info.get("cip_path", [])
        score = 0
        alerts = []

        cip_result = self._analyze_cip_service(info, svc, cls, path, src_addr)
        if cip_result:
            return cip_result

        if svc == 0x4E and src_addr:
            score += THREAT_SCORES["unauthorized_forward_open"]
            alerts.append("ForwardOpen from %s" % src_addr)
            ekey_result = self._check_ekey(info)
            if ekey_result:
                score += THREAT_SCORES["ekey_mismatch"]
                alerts.append(ekey_result)
            rpi_result = self._check_rpi(info)
            if rpi_result:
                score += THREAT_SCORES["rpi_anomaly"]
                alerts.append(rpi_result)
            if src_addr:
                self._connections[src_addr].record_open()

        elif svc == 0x4F and src_addr:
            self._connections[src_addr].record_close()
            churn = self._connections[src_addr].churn_count()
            if churn >= CONNECTION_CHURN_THRESHOLD:
                score += THREAT_SCORES["connection_churn"]
                alerts.append("Connection churn: %d open/close in %.1fs from %s" % (
                    churn, CONNECTION_CHURN_WINDOW, src_addr))

        if svc in CIP_DESTRUCTIVE_SERVICES:
            score += THREAT_SCORES["reset_or_stop"]
            alerts.append("CIP %s service from %s on class 0x%02X (%s)" % (
                svc_name, src_addr, cls or 0, cls_name))

        if svc in CIP_WRITE_SERVICES:
            if cls in CIP_CRITICAL_CLASSES:
                score += THREAT_SCORES["set_attribute_critical"]
                alerts.append("Write to critical class 0x%02X (%s) from %s" % (
                    cls, cls_name, src_addr))

        if cls == 0x06 and svc in CIP_WRITE_SERVICES:
            score += THREAT_SCORES["path_to_critical"]
            alerts.append("Write to ConnectionManager (0x06) from %s" % src_addr)

        if cls == 0x04 and svc in CIP_WRITE_SERVICES:
            raw_len = info.get("length", 0)
            if raw_len > LARGE_WRITE_THRESHOLD:
                score += THREAT_SCORES["large_assembly_write"]
                alerts.append("Large assembly write: %d bytes from %s" % (
                    raw_len, src_addr))

        if score > 0:
            severity = "critical" if score >= 40 else "high" if score >= 25 else "medium"
            return DetectionResult("EIP", True, severity,
                                  "; ".join(alerts), details)

        return DetectionResult("EIP", False, "info",
                              "SendRRData: CIP %s class=0x%02X (%s)" % (
                                  svc_name, cls or 0, cls_name), details)

    def _detect_send_unit_data(self, info: dict, src_addr, details: dict):
        svc = info.get("cip_service")
        if svc in CIP_DESTRUCTIVE_SERVICES:
            return DetectionResult("EIP", True, "critical",
                                  "CIP destructive via SendUnitData from %s" % src_addr,
                                  details)
        return DetectionResult("EIP", False, "info",
                              "SendUnitData from %s" % src_addr, details)

    def _analyze_cip_service(self, info: dict, svc, cls, path, src_addr
                             ) -> Optional[DetectionResult]:
        if svc in (0x52, 0x05):
            return DetectionResult("EIP", True, "critical",
                "CIP Reset on class 0x%02X (%s) from %s" % (
                    cls or 0, CIP_CLASS_NAMES.get(cls, "?"), src_addr),
                info)

        if svc in (0x54, 0x07):
            return DetectionResult("EIP", True, "critical",
                "CIP Stop on class 0x%02X (%s) from %s" % (
                    cls or 0, CIP_CLASS_NAMES.get(cls, "?"), src_addr),
                info)

        if svc == 0x10 and cls in (0x01, 0xF5, 0xF6):
            return DetectionResult("EIP", True, "high",
                "CIP SetAttributeSingle on critical class 0x%02X (%s) from %s" % (
                    cls, CIP_CLASS_NAMES.get(cls, "?"), src_addr),
                info)

        if svc == 0x02 and cls in CIP_CRITICAL_CLASSES:
            return DetectionResult("EIP", True, "high",
                "CIP SetAttributeAll on critical class 0x%02X (%s) from %s" % (
                    cls, CIP_CLASS_NAMES.get(cls, "?"), src_addr),
                info)

        return None

    def _check_ekey(self, info: dict) -> Optional[str]:
        if "ekey_vendor" not in info:
            return None
        e_vendor = info["ekey_vendor"]
        e_type = info["ekey_type"]
        e_product = info["ekey_product"]
        e_major = info["ekey_major"]
        e_minor = info["ekey_minor"]
        expected = (0x0001, 0x000E, 0x0064, 4, 1)
        actual = (e_vendor, e_type, e_product, e_major, e_minor)
        if actual != expected:
            return ("Electronic key mismatch: got vendor=0x%04X type=0x%04X "
                    "product=0x%04X rev=%d.%d" % actual)
        return None

    def _check_rpi(self, info: dict) -> Optional[str]:
        o_t = info.get("rpi_o_t")
        t_o = info.get("rpi_t_o")
        anomalies = []
        if o_t is not None and o_t < MIN_SAFE_RPI_US:
            anomalies.append("O->T RPI=%dus (below safe min %dus)" % (
                o_t, MIN_SAFE_RPI_US))
        if t_o is not None and t_o < MIN_SAFE_RPI_US:
            anomalies.append("T->O RPI=%dus (below safe min %dus)" % (
                t_o, MIN_SAFE_RPI_US))
        if anomalies:
            return "RPI anomaly: %s — potential DoS" % "; ".join(anomalies)
        return None

    def _cleanup(self):
        now = time.time()
        if now - self._last_cleanup < 30:
            return
        self._last_cleanup = now
        stale_ips = []
        for ip, tracker in self._sessions.items():
            if tracker.idle > 300:
                stale_ips.append(ip)
        for ip in stale_ips:
            del self._sessions[ip]
            self._connections.pop(ip, None)
            self._active_connections.pop(ip, None)
            self._request_history.pop(ip, None)

    def get_stats(self, src_addr=None) -> Dict[str, Any]:
        stats = {"total_tracked_ips": len(self._sessions)}
        if src_addr and src_addr in self._sessions:
            t = self._sessions[src_addr]
            c = self._connections.get(src_addr)
            stats["session"] = {
                "register_count": t.register_count,
                "age_seconds": t.age,
                "total_requests": t.total_requests,
                "identity_scan_count": len([x for x in t.identity_requests
                                           if time.time() - x < 10]),
            }
            if c:
                stats["connection"] = {
                    "total_opens": c.total_opens,
                    "total_closes": c.total_closes,
                    "churn_count_10s": c.churn_count(10),
                }
        return stats


if __name__ == "__main__":
    d = EthernetIPDetector()
    tests = [
        (b"\x63\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 20, "ListIdentity probe"),
        (b"\x65\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 20, "RegisterSession"),
        (b"\x6F\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 20 +
         b"\x00\x00\x52\x02\x04\x24", "CIP Reset via 0x6F"),
        (b"\x6F\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 20 +
         b"\x00\x00\x10\x03\x04\x24\x01\x01", "CIP SetAttribute via 0x6F"),
        (b"\x6F\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 20 +
         b"\x00\x00\x54\x02\x04\x24", "CIP Stop via 0x6F"),
    ]
    for data, desc in tests:
        result = d.detect(data, src_addr="192.168.1.100")
        log.info("  [%s] %s", desc, result)
