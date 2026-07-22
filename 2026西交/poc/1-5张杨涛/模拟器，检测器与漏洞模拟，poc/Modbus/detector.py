"""
Modbus 深度包检测 + 行为分析 — 异常评分 · 攻击签名 · 保护区域 · 响应时间
"""
import struct, time, logging
from collections import defaultdict, deque
from typing import Dict, Any, Optional, List, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ModbusDetect")

MBAP = struct.Struct(">HHHB")
FUNC_NAMES = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    7: "Read Exception Status", 8: "Diagnostics",
    11: "Get Comm Event Counter", 12: "Get Comm Event Log",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    17: "Report Server ID", 20: "Read File Record",
    21: "Write File Record", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers", 24: "Read FIFO Queue",
    43: "Read Device Identification",
}
WRITE_FUNCS = {5, 6, 15, 16, 21, 22, 23}
DANGEROUS_FUNCS = {8, 11, 12, 17, 20, 24}
READ_FUNCS = {1, 2, 3, 4, 7, 43}
DIAG_SUBFUNC_DANGEROUS = {1, 3, 4, 10, 11}
MAX_PDU = 253
MAX_READ_QUANTITY = {1: 2000, 2: 2000, 3: 125, 4: 125}
MAX_WRITE_QUANTITY = {15: 1968, 16: 123}

PDU_MIN_SIZES = {
    1: 4, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 0, 8: 2,
    11: 0, 12: 0, 15: 5, 16: 5, 17: 0, 20: 1, 21: 1,
    22: 6, 23: 8, 24: 2, 43: 2,
}
PDU_MAX_SIZES = {
    1: 4, 2: 4, 3: 4, 4: 4, 5: 4, 6: 4, 7: 0, 8: 254,
    11: 0, 12: 0, 15: 253, 16: 253, 17: 0, 20: 249, 21: 249,
    22: 6, 23: 252, 24: 2, 43: 252,
}

ATTACK_SIGNATURES = [
    {"name": "Register Flood", "pattern": {"func_repeat": 16, "min_count_5s": 50,
                                            "min_quantity": 50}, "severity": "critical", "score": 85},
    {"name": "Rapid Write Burst", "pattern": {"func_in": [5, 6, 15, 16],
                                              "min_count_1s": 30}, "severity": "critical", "score": 90},
    {"name": "Function Code Scan", "pattern": {"unique_funcs_10s": 8},
     "severity": "high", "score": 75},
    {"name": "Address Sweep", "pattern": {"func_in": [1, 2, 3, 4],
                                          "unique_addrs_10s": 100}, "severity": "high", "score": 70},
    {"name": "Diagnostic Abuse", "pattern": {"func": 8, "min_count_5s": 10},
     "severity": "high", "score": 80},
    {"name": "Identity Probe", "pattern": {"func": 43, "min_count_5s": 5},
     "severity": "medium", "score": 55},
    {"name": "Broadcast Storm", "pattern": {"unit_255_count_1s": 20},
     "severity": "critical", "score": 92},
    {"name": "Illegal Function Storm", "pattern": {"exception_count_5s": 15},
     "severity": "high", "score": 65},
]

PROTECTED_RANGES = [
    {"name": "Safety Shutdown Coils", "start": 0x0000, "end": 0x0010, "access": "write",
     "severity": "critical", "score": 95},
    {"name": "Critical Config Registers", "start": 0x2000, "end": 0x207F, "access": "write",
     "severity": "critical", "score": 90},
    {"name": "PLC Status Registers", "start": 0x1000, "end": 0x10FF, "access": "read",
     "severity": "medium", "score": 40},
    {"name": "Diagnostic Control", "start": 0x3000, "end": 0x307F, "access": "write",
     "severity": "high", "score": 80},
    {"name": "Bootloader Region", "start": 0x7000, "end": 0x7FFF, "access": "any",
     "severity": "critical", "score": 98},
]

CRITICAL_COILS = set(range(0x0000, 0x0020))
CRITICAL_REGISTERS = set(range(0x2000, 0x2080))


class DetectionResult:
    def __init__(self, protocol="Modbus", alert=False, severity="low",
                 message="", details=None, score=0):
        self.protocol = protocol
        self.alert = alert
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.score = score

    def __repr__(self):
        score_str = f" score={self.score}" if self.score else ""
        return f"[{self.severity.upper()}]{' ALERT' if self.alert else ''} [{self.protocol}] {self.message}{score_str}"


class SessionTracker:
    def __init__(self, max_sessions=5000):
        self.sessions = {}
        self.max_sessions = max_sessions
        self._lock = __import__('threading').Lock()

    def get(self, src):
        with self._lock:
            if src not in self.sessions and len(self.sessions) >= self.max_sessions:
                oldest = min(self.sessions, key=lambda k: self.sessions[k].get("last_seen", 0))
                del self.sessions[oldest]
            if src not in self.sessions:
                self.sessions[src] = {
                    "src": src,
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "packet_count": 0,
                    "read_count": 0,
                    "write_count": 0,
                    "error_count": 0,
                    "exception_count": 0,
                    "func_history": [],
                    "addr_history": [],
                    "response_times": deque(maxlen=200),
                    "last_func": None,
                    "last_addr": 0,
                    "threat_score": 0,
                    "baseline_rpm": None,
                    "baseline_wpm": None,
                    "baseline_established": False,
                }
            self.sessions[src]["last_seen"] = time.time()
            return self.sessions[src]

    def decay(self, max_age=300):
        now = time.time()
        with self._lock:
            expired = [k for k, v in self.sessions.items() if now - v["last_seen"] > max_age]
            for k in expired:
                del self.sessions[k]


class ThreatScorer:
    def __init__(self):
        self._scores = defaultdict(float)

    def add(self, src, score):
        self._scores[src] = min(100, self._scores[src] + score * 0.3)

    def decay(self, src, amount=5):
        self._scores[src] = max(0, self._scores[src] - amount)

    def get(self, src):
        return round(self._scores.get(src, 0), 1)

    def set(self, src, score):
        self._scores[src] = max(0, min(100, score))


class ModbusDetector:
    def __init__(self):
        self.name = "ModbusDetector"
        self._unit_tracker = defaultdict(lambda: {"count": 0, "last_seen": 0,
                                                  "write_count": 0, "error_count": 0, "funcs": set()})
        self._rate_tracker = defaultdict(list)
        self._scan_detect = defaultdict(int)
        self._suspicious_tids = set()
        self._sessions = SessionTracker()
        self._scorer = ThreatScorer()
        self._start_time = time.time()

    def parse_packet(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 7:
            return None
        try:
            tid, pid, length, unit = MBAP.unpack(data[:7])
            if length < 1 or len(data) < 6 + length:
                return None
            pdu = data[7:7+length-1]
            if not pdu:
                return None
            func = pdu[0]
            info = {"protocol": "modbus_tcp", "tid": tid, "pid": pid, "unit_id": unit,
                    "length": length, "function_code": func,
                    "function_name": FUNC_NAMES.get(func, f"Unknown(0x{func:02X})"),
                    "is_exception": bool(func & 0x80), "pdu_size": len(pdu)}
            if info["is_exception"]:
                actual_func = func & 0x7F
                exc_code = pdu[1] if len(pdu) > 1 else 0
                info["actual_function"] = FUNC_NAMES.get(actual_func, f"Unknown(0x{actual_func:02X})")
                info["exception_code"] = exc_code
                return info
            if func in READ_FUNCS and len(pdu) >= 5:
                info["start_addr"], info["quantity"] = struct.unpack(">HH", pdu[1:5])
            elif func in {5, 6} and len(pdu) >= 5:
                info["address"], info["value"] = struct.unpack(">HH", pdu[1:5])
            elif func == 8 and len(pdu) >= 3:
                info["sub_function"] = struct.unpack(">H", pdu[1:3])[0]
            elif func in {15} and len(pdu) >= 5:
                info["start_addr"], info["quantity"] = struct.unpack(">HH", pdu[1:5])
            elif func in {16} and len(pdu) >= 5:
                info["start_addr"], info["quantity"] = struct.unpack(">HH", pdu[1:5])
            elif func == 22 and len(pdu) >= 7:
                info["address"], info["and_mask"], info["or_mask"] = struct.unpack(">HHH", pdu[1:7])
            elif func == 23 and len(pdu) >= 9:
                info["read_addr"], info["read_qty"] = struct.unpack(">HH", pdu[1:5])
                info["write_addr"], info["write_qty"] = struct.unpack(">HH", pdu[5:9])
            elif func == 24 and len(pdu) >= 3:
                info["fifo_ptr"] = struct.unpack(">H", pdu[1:3])[0]
            elif func == 43 and len(pdu) >= 3:
                info["mei_type"] = pdu[1]
                info["read_device_code"] = pdu[2]
                info["object_id"] = pdu[3] if len(pdu) > 3 else 0
            return info
        except Exception:
            return None

    def detect(self, data: bytes, src_addr=None, dst_addr=None,
               response_time_ms=None) -> DetectionResult:
        info = self.parse_packet(data)
        if not info:
            return DetectionResult("Modbus", False, "low", "Invalid ModbusTCP packet")

        details = info.copy()
        func = info.get("function_code", -1)
        func_name = info.get("function_name", "Unknown")
        unit = info.get("unit_id", 0)
        tid = info.get("tid", 0)
        now = time.time()
        results = []
        max_score = 0
        max_severity = "info"
        is_alert = False

        self._unit_tracker[unit]["count"] += 1
        self._unit_tracker[unit]["last_seen"] = now
        self._unit_tracker[unit]["funcs"].add(func)

        session = self._sessions.get(src_addr or "unknown")
        session["packet_count"] += 1
        session["func_history"].append({"func": func, "time": now, "addr": info.get("start_addr", info.get("address", 0))})
        session["addr_history"].append(info.get("start_addr", info.get("address", 0)))
        if len(session["func_history"]) > 500:
            session["func_history"] = session["func_history"][-500:]
        if len(session["addr_history"]) > 500:
            session["addr_history"] = session["addr_history"][-500:]

        if response_time_ms is not None:
            session["response_times"].append(response_time_ms)
            if response_time_ms > 5000:
                results.append(DetectionResult("Modbus", True, "medium",
                                               f"Very slow response ({response_time_ms:.0f}ms)",
                                               details, score=30))
            elif response_time_ms < 0.5 and session["packet_count"] > 10:
                avg_rt = sum(session["response_times"]) / max(len(session["response_times"]), 1)
                if avg_rt < 1.0:
                    results.append(DetectionResult("Modbus", True, "medium",
                                                   "Suspiciously fast response times (possible local spoof)",
                                                   details, score=25))

        if info.get("is_exception"):
            exc = info.get("exception_code", 0)
            self._unit_tracker[unit]["error_count"] += 1
            session["exception_count"] += 1
            if session["exception_count"] > 50:
                r = DetectionResult("Modbus", True, "high",
                                    f"High exception rate ({session['exception_count']}) from {src_addr}",
                                    details, score=60)
                results.append(r)

        if func == 0x80 or func > 127:
            results.append(DetectionResult("Modbus", True, "high",
                                           f"Reserved/invalid function code 0x{func:02X}",
                                           details, score=40))

        if func in DANGEROUS_FUNCS:
            if func == 8:
                sub = info.get("sub_function", 0)
                if sub in DIAG_SUBFUNC_DANGEROUS:
                    results.append(DetectionResult("Modbus", True, "critical",
                                                   f"Dangerous diagnostics sub=0x{sub:04X} ({FUNC_NAMES.get(func, 'Unknown')})",
                                                   details, score=85))
                else:
                    results.append(DetectionResult("Modbus", True, "medium",
                                                   f"Diagnostics function sub=0x{sub:04X}",
                                                   details, score=50))
            elif func in {11, 12, 17}:
                results.append(DetectionResult("Modbus", True, "medium",
                                               f"Information gathering: {func_name}",
                                               details, score=35))
            elif func in {20, 24}:
                results.append(DetectionResult("Modbus", True, "high",
                                               f"Advanced function: {func_name}",
                                               details, score=60))

        if func in WRITE_FUNCS:
            qty = info.get("quantity", info.get("write_qty", 1))
            session["write_count"] += 1
            addr = info.get("address", info.get("start_addr", info.get("write_addr", 0)))

            if session["write_count"] > 100:
                results.append(DetectionResult("Modbus", True, "critical",
                                               f"Mass write attack ({session['write_count']} writes) from {src_addr}",
                                               details, score=90))

            if addr < 0x1000:
                results.append(DetectionResult("Modbus", True, "high",
                                               f"Write to sensitive address range 0x{addr:04X}: {func_name}",
                                               details, score=70))

            if func in MAX_WRITE_QUANTITY and qty > MAX_WRITE_QUANTITY[func]:
                results.append(DetectionResult("Modbus", True, "high",
                                               f"Write quantity {qty} exceeds max {MAX_WRITE_QUANTITY[func]}",
                                               details, score=50))

            protection_result = self._check_protection(addr, qty, "write", func_name, details)
            if protection_result:
                results.append(protection_result)

            ladder_impact = self._check_ladder_impact(addr, qty, func, details)
            if ladder_impact:
                results.append(ladder_impact)

        if func in READ_FUNCS:
            qty = info.get("quantity", 0)
            addr = info.get("start_addr", 0)
            session["read_count"] += 1

            if func in MAX_READ_QUANTITY and qty > MAX_READ_QUANTITY[func]:
                results.append(DetectionResult("Modbus", True, "medium",
                                               f"Read quantity {qty} exceeds max {MAX_READ_QUANTITY[func]}",
                                               details, score=40))

            if qty > 100 and func in {1, 2, 3, 4}:
                key = f"{src_addr}:{func}"
                self._rate_tracker[key].append(now)
                self._rate_tracker[key] = [t for t in self._rate_tracker[key] if now - t < 5]
                if len(self._rate_tracker[key]) > 30:
                    results.append(DetectionResult("Modbus", True, "medium",
                                                   f"Rapid read scan ({len(self._rate_tracker[key])}/5s) func={func_name}",
                                                   details, score=55))

            if addr == 0 and qty == 0:
                results.append(DetectionResult("Modbus", True, "medium",
                                               "Suspicious zero-length read (addr=0, qty=0)",
                                               details, score=30))

            protection_result = self._check_protection(addr, qty, "read", func_name, details)
            if protection_result:
                results.append(protection_result)

        if func == 7:
            results.append(DetectionResult("Modbus", False, "info",
                                           "Read Exception Status - normal diagnostic", details, score=0))

        if func == 43:
            mei_code = info.get("read_device_code", 0)
            if mei_code == 0x01 and info.get("object_id", 0) == 0:
                results.append(DetectionResult("Modbus", True, "medium",
                                               "Device Identification probe (Basic)", details, score=45))

        pdu_size_check = self._check_pdu_size(func, info.get("pdu_size", 0), details)
        if pdu_size_check:
            results.append(pdu_size_check)

        sig_result = self._check_signatures(session, now)
        if sig_result:
            results.append(sig_result)

        if func in WRITE_FUNCS:
            recent_writes = [h for h in session["func_history"]
                             if h["func"] in WRITE_FUNCS and now - h["time"] < 1]
            if len(recent_writes) >= 30:
                if not any("Rapid Write Burst" in r.message for r in results):
                    results.append(DetectionResult("Modbus", True, "critical",
                                                   f"Rapid write burst: {len(recent_writes)} writes in 1s",
                                                   details, score=90))

        if func >= 72 and func <= 119:
            return DetectionResult("Modbus", True, "high",
                                   f"User-defined function code range 0x{func:02X}",
                                   details, score=60)

        self._check_rate_anomaly(session, now)

        if not results:
            results.append(DetectionResult("Modbus", False, "info",
                                           f"Normal operation: {func_name}", details, score=0))

        for r in results:
            if r.score > max_score:
                max_score = r.score
            if r.alert:
                is_alert = True
            sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            if sev_order.get(r.severity, 0) > sev_order.get(max_severity, 0):
                max_severity = r.severity

        session["threat_score"] = max_score
        if src_addr:
            self._scorer.add(src_addr, max_score)

        worst = max(results, key=lambda r: r.score)
        worst.alert = is_alert
        worst.severity = max_severity
        worst.score = max_score
        worst.details = details
        return worst

    def _check_protection(self, addr, qty, access_type, func_name, details):
        end = addr + max(qty, 1)
        for zone in PROTECTED_RANGES:
            if end > zone["start"] and addr < zone["end"]:
                if zone["access"] == access_type or zone["access"] == "any":
                    return DetectionResult("Modbus", True, zone["severity"],
                                           f"Protected zone [{zone['name']}] {access_type} access: "
                                           f"addr=0x{addr:04X} qty={qty} via {func_name}",
                                           details, score=zone["score"])
        return None

    def _check_ladder_impact(self, addr, qty, func, details):
        if func in {5, 15}:
            end_coil = addr + max(qty or 1, 1)
            if CRITICAL_COILS & set(range(addr, end_coil)):
                hit = CRITICAL_COILS & set(range(addr, end_coil))
                return DetectionResult("Modbus", True, "critical",
                                       f"Ladder logic impact: write touches critical coils "
                                       f"{sorted(hit)[:10]}{'...' if len(hit) > 10 else ''}",
                                       details, score=95)
        if func in {6, 16, 22, 23}:
            end_reg = addr + max(qty or 1, 1)
            if CRITICAL_REGISTERS & set(range(addr, end_reg)):
                hit = CRITICAL_REGISTERS & set(range(addr, end_reg))
                return DetectionResult("Modbus", True, "critical",
                                       f"Ladder/Config impact: write touches critical registers "
                                       f"{[hex(h) for h in sorted(hit)[:10]]}{'...' if len(hit) > 10 else ''}",
                                       details, score=92)
        return None

    def _check_pdu_size(self, func, pdu_size, details):
        if func in PDU_MIN_SIZES:
            if pdu_size < PDU_MIN_SIZES[func]:
                return DetectionResult("Modbus", True, "medium",
                                       f"PDU too small for func 0x{func:02X}: "
                                       f"{pdu_size} < {PDU_MIN_SIZES[func]}",
                                       details, score=35)
            if pdu_size > PDU_MAX_SIZES[func] and PDU_MAX_SIZES[func] > 0:
                return DetectionResult("Modbus", True, "low",
                                       f"PDU exceeds expected max for func 0x{func:02X}: "
                                       f"{pdu_size} > {PDU_MAX_SIZES[func]}",
                                       details, score=20)
        return None

    def _check_signatures(self, session, now):
        func_history = session["func_history"]
        recent_5s = [h for h in func_history if now - h["time"] < 5]
        recent_1s = [h for h in func_history if now - h["time"] < 1]
        recent_10s = [h for h in func_history if now - h["time"] < 10]

        for sig in ATTACK_SIGNATURES:
            pat = sig["pattern"]

            if "func_repeat" in pat:
                count = sum(1 for h in recent_5s if h["func"] == pat["func_repeat"])
                min_qty = pat.get("min_quantity", 0)
                if min_qty > 0:
                    count = sum(1 for h in recent_5s
                                if h["func"] == pat["func_repeat"]
                                and h.get("addr", 0) >= 0)
                if count >= pat["min_count_5s"]:
                    return DetectionResult("Modbus", True, sig["severity"],
                                           f"Signature [{sig['name']}]: {count} occurrences in 5s",
                                           {}, score=sig["score"])

            if "func_in" in pat:
                if "min_count_1s" in pat:
                    count = sum(1 for h in recent_1s if h["func"] in pat["func_in"])
                    if count >= pat["min_count_1s"]:
                        return DetectionResult("Modbus", True, sig["severity"],
                                               f"Signature [{sig['name']}]: {count} writes in 1s",
                                               {}, score=sig["score"])
                if "unique_addrs_10s" in pat:
                    addrs = {h["addr"] for h in recent_10s if h["func"] in pat["func_in"]}
                    if len(addrs) >= pat["unique_addrs_10s"]:
                        return DetectionResult("Modbus", True, sig["severity"],
                                               f"Signature [{sig['name']}]: {len(addrs)} unique addresses in 10s",
                                               {}, score=sig["score"])

            if "unique_funcs_10s" in pat:
                funcs = {h["func"] for h in recent_10s}
                if len(funcs) >= pat["unique_funcs_10s"]:
                    return DetectionResult("Modbus", True, sig["severity"],
                                           f"Signature [{sig['name']}]: {len(funcs)} unique functions in 10s",
                                           {}, score=sig["score"])

            if "func" in pat and "min_count_5s" in pat and "func_repeat" not in pat:
                count = sum(1 for h in recent_5s if h["func"] == pat["func"])
                if count >= pat["min_count_5s"]:
                    return DetectionResult("Modbus", True, sig["severity"],
                                           f"Signature [{sig['name']}]: {count} occurrences in 5s",
                                           {}, score=sig["score"])

            if "exception_count_5s" in pat:
                pass

        return None

    def _check_rate_anomaly(self, session, now):
        total = session["packet_count"]
        elapsed = now - session["first_seen"]
        if elapsed > 60 and not session["baseline_established"]:
            session["baseline_rpm"] = session["read_count"] / (elapsed / 60)
            session["baseline_wpm"] = session["write_count"] / (elapsed / 60)
            session["baseline_established"] = True
        if session["baseline_established"]:
            recent_elapsed = max(now - session["last_seen"] + 0.001, 0.001)
            recent_rpm = session["read_count"] / max(now - session["first_seen"], 1) * 60
            recent_wpm = session["write_count"] / max(now - session["first_seen"], 1) * 60
            if session["baseline_rpm"] and session["baseline_rpm"] > 0:
                deviation = abs(recent_rpm - session["baseline_rpm"]) / session["baseline_rpm"]
                if deviation > 5:
                    log.debug(f"Rate anomaly for {session.get('src')}: read RPM deviation={deviation:.2f}")

    def get_threat_score(self, src_addr):
        return self._scorer.get(src_addr)

    def get_session_stats(self, src_addr):
        return dict(self._sessions.get(src_addr))

    def get_active_threats(self, min_score=30):
        threats = []
        for src, session in self._sessions.sessions.items():
            score = self._scorer.get(src)
            if score >= min_score:
                threats.append({"src": src, "score": score,
                                "packets": session["packet_count"],
                                "writes": session["write_count"],
                                "errors": session["exception_count"]})
        return sorted(threats, key=lambda t: t["score"], reverse=True)

    def decay_all(self):
        for src in list(self._sessions.sessions.keys()):
            self._scorer.decay(src, 3)
        self._sessions.decay(max_age=300)


if __name__ == "__main__":
    d = ModbusDetector()
    test_packets = [
        (b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0A", "Normal Read Holding Registers"),
        (b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x01\x00\xFF", "Write Single Register"),
        (b"\x00\x01\x00\x00\x00\x03\x01\x08\x00\x01\x00\x00", "Diagnostics restart"),
        (b"\x00\x01\x00\x00\x00\x04\x01\x2B\x0E\x01\x00", "Device Identification"),
        (b"\x00\x01\x00\x00\x00\x03\x01\x07", "Read Exception Status"),
        (b"\x00\x01\x00\x00\x00\x06\x01\x10\x00\x00\x00\x02\x04\x00\x01\x00\x02", "Write Multiple Regs"),
        (b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x00\x00\xFF", "Write to address 0x0000"),
        (b"\x00\x01\x00\x00\x00\x06\x01\x05\x00\x00\xFF\x00", "Write coil 0"),
    ]
    for data, desc in test_packets:
        r = d.detect(data, src_addr="192.168.1.100")
        log.info(f"  [{desc}] {r}")

    log.info("\n--- Simulated register flood ---")
    for i in range(60):
        d.detect(b"\x00\x01\x00\x00\x00\x09\x01\x10\x01\x00\x00\x04\x08" +
                 bytes([0] * 8), src_addr="192.168.1.200")
    log.info(f"  Flood threat score: {d.get_threat_score('192.168.1.200')}")
    log.info(f"  Active threats: {d.get_active_threats(30)}")
