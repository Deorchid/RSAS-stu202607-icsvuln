"""
S7COMM 协议信息检测逻辑 — COTP/S7 双层分析 + 行为指纹 + 威胁评分
"""
import struct
import time
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("S7Detect")

FUNC_NAMES = {
    0x00: "CPU Services", 0x01: "Setup Communication", 0x04: "Read",
    0x05: "Write", 0x07: "BSEND", 0x08: "BRCV", 0x09: "Start Download",
    0x0A: "Download", 0x0B: "End Download", 0x0C: "Start Upload",
    0x0D: "Upload", 0x0E: "End Upload", 0x1A: "Control",
    0x1C: "Block Functions", 0x1D: "Block Info",
    0x1E: "Time Functions", 0x1F: "Time Functions",
    0x21: "PASSWORD", 0x22: "Force Stop",
    0x28: "SZL Read", 0x29: "SZL Read",
    0x30: "Protection", 0x32: "Security",
}

CPU_CMDS = {
    0x01: "PING", 0x04: "STOP", 0x05: "HOT_START",
    0x07: "COLD_START", 0x08: "RUN", 0x10: "PASSWORD",
}

AREA_NAMES = {
    0x81: "PE(Input)", 0x82: "PA(Output)", 0x83: "MK(Merker)",
    0x84: "DB", 0x85: "DI", 0x86: "LB", 0x87: "LD",
}

TRANSPORT_MAP = {3: "Byte", 4: "Word", 5: "DWord", 6: "Counter", 7: "Timer"}
TSAP_PROFILES = {
    0x0100: "PG", 0x0101: "OP", 0x0102: "PG",
    0x0110: "OP", 0x0200: "S7", 0x0300: "Other",
}

BLOCK_FUNCS = {
    0x01: "ListBlocks", 0x02: "BlockInfo", 0x03: "StartUpload",
    0x04: "Upload", 0x05: "EndUpload", 0x06: "StartDownload",
    0x07: "Download", 0x08: "EndDownload", 0x09: "DeleteBlock",
}


class DetectionResult:
    def __init__(self, protocol, alert=False, severity="low", message="",
                 details=None, score=0):
        self.protocol = protocol
        self.alert = alert
        self.severity = severity
        self.message = message
        self.details = details or {}
        self.score = score

    def __repr__(self):
        prefix = "[ALERT]" if self.alert else "[INFO ]"
        return f"{prefix} [{self.severity.upper():8s}] [{self.protocol}] score={self.score:3d} {self.message}"


class SessionTracker:
    def __init__(self):
        self.sessions = {}

    def get(self, src):
        if src not in self.sessions:
            self.sessions[src] = SessionFingerprint(src)
        self._purge_old()
        return self.sessions[src]

    def _purge_old(self):
        now = time.time()
        stale = [k for k, v in self.sessions.items() if now - v.last_seen > 3600]
        for k in stale:
            del self.sessions[k]

    def all_sessions(self):
        self._purge_old()
        return list(self.sessions.values())


class SessionFingerprint:
    def __init__(self, src):
        self.src = src
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.packet_count = 0
        self.tsap_profile = None
        self.func_counts = defaultdict(int)
        self.write_events = []
        self.read_events = []
        self.control_commands = []
        self.password_attempts = 0
        self.block_operations = []
        self.plc_state_observed = None

    def record(self, info):
        self.last_seen = time.time()
        self.packet_count += 1

        if info.get("cotp_type") == 0x11 and self.tsap_profile is None:
            self.tsap_profile = info.get("src_tsap_profile")

        func = info.get("function_code")
        if func is not None:
            self.func_counts[func] += 1

        if func == 0x05:
            self.write_events.append({
                "time": time.time(),
                "items": info.get("write_items", []),
            })

        if func == 0x04:
            self.read_events.append({
                "time": time.time(),
                "items": info.get("read_items", []),
            })

        if func == 0x00 or func == 0x1A:
            cmd = info.get("cpu_command", "")
            self.control_commands.append({
                "time": time.time(),
                "command": cmd,
            })

        if func == 0x21:
            self.password_attempts += 1

        if func == 0x1C:
            sub = info.get("block_sub_func")
            self.block_operations.append({
                "time": time.time(),
                "operation": sub,
            })

    def write_burst_detected(self, window=5, threshold=10):
        now = time.time()
        recent = [e for e in self.write_events if now - e["time"] <= window]
        if len(recent) < threshold:
            return False, 0

        area_counts = defaultdict(int)
        for e in recent:
            for item in e.get("items", []):
                key = f"{item.get('area','')}-{item.get('db',0)}"
                area_counts[key] += 1

        max_count = max(area_counts.values()) if area_counts else 0
        return max_count >= threshold, max_count

    def sequential_db_read_detected(self, window=10, threshold=5):
        now = time.time()
        recent = [e for e in self.read_events if now - e["time"] <= window]
        if len(recent) < threshold:
            return False, 0

        db_reads = defaultdict(list)
        for e in recent:
            for item in e.get("items", []):
                if item.get("area") == "DB":
                    db_reads[item["db"]].append(item.get("address", 0))

        for db, addrs in db_reads.items():
            if len(addrs) < threshold:
                continue
            sorted_addrs = sorted(addrs)
            gaps = [sorted_addrs[i + 1] - sorted_addrs[i]
                    for i in range(len(sorted_addrs) - 1)]
            avg_gap = sum(gaps) / len(gaps) if gaps else 0
            if avg_gap < 512 and len(addrs) >= threshold:
                return True, len(addrs)

        return False, 0

    def stop_command_count(self):
        return sum(1 for c in self.control_commands if c["command"] == "STOP")


class ThreatScorer:
    WEIGHTS = {
        "stop_command": 30,
        "start_command": 20,
        "unauthorized_write": 20,
        "password_attempt": 25,
        "rapid_scan": 15,
        "data_exfil": 25,
        "write_burst": 25,
        "block_upload": 20,
        "block_download": 30,
        "pg_connection": 10,
        "unusual_time_func": 10,
        "force_stop": 35,
        "szl_diag_read": 8,
    }

    def __init__(self):
        self.global_alerts = []

    def score_session(self, fingerprint):
        score = 0
        reasons = []

        f = fingerprint

        if f.tsap_profile == "PG":
            score += self.WEIGHTS["pg_connection"]
            reasons.append("PG connection profile")

        stop_count = f.stop_command_count()
        if stop_count > 0:
            score += self.WEIGHTS["stop_command"] * min(stop_count, 3)
            reasons.append(f"STOP command x{stop_count}")

        start_ops = sum(1 for c in f.control_commands
                        if c["command"] in ("HOT_START", "COLD_START", "RUN"))
        if start_ops > 0:
            score += self.WEIGHTS["start_command"]
            reasons.append(f"Unauthorized start/run ({start_ops})")

        if f.password_attempts > 0:
            score += self.WEIGHTS["password_attempt"] * min(f.password_attempts, 4)
            reasons.append(f"Password attempt x{f.password_attempts}")

        is_burst, burst_count = f.write_burst_detected()
        if is_burst:
            score += self.WEIGHTS["write_burst"]
            reasons.append(f"Write burst ({burst_count} in 5s)")

        is_seq, seq_count = f.sequential_db_read_detected()
        if is_seq:
            score += self.WEIGHTS["data_exfil"]
            reasons.append(f"Sequential DB read ({seq_count} reads) – data exfiltration")

        if len(f.write_events) > 20:
            score += self.WEIGHTS["unauthorized_write"]
            reasons.append(f"Excessive writes ({len(f.write_events)})")

        force_stops = sum(1 for c in f.control_commands if c["command"] == "FORCE_STOP")
        if force_stops > 0:
            score += self.WEIGHTS["force_stop"]
            reasons.append("Force STOP detected")

        block_uploads = sum(1 for b in f.block_operations if b["operation"] == "StartUpload")
        block_downloads = sum(1 for b in f.block_operations if b["operation"] == "StartDownload")
        if block_uploads > 0:
            score += self.WEIGHTS["block_upload"]
            reasons.append(f"Block upload ({block_uploads})")
        if block_downloads > 0:
            score += self.WEIGHTS["block_download"]
            reasons.append(f"Block download ({block_downloads})")

        score = min(score, 100)
        return score, reasons


class S7CommDetector:
    def __init__(self):
        self.name = "S7COMMDetector"
        self.session_tracker = SessionTracker()
        self.scorer = ThreatScorer()
        self._plc_state = None
        self._state_change_log = []

    def parse_packet(self, data):
        if len(data) < 4 or data[0] != 3:
            return None
        try:
            tpkt_len = struct.unpack(">H", data[2:4])[0]
            if len(data) < tpkt_len or tpkt_len < 7:
                return None
            cotp = data[4]
            info = {"protocol": "s7comm", "tpkt_length": tpkt_len, "cotp_type": cotp}

            if cotp == 0x11:
                info["description"] = "COTP Connection Request"
                info["cotp_ptype"] = "CR"
                if len(data) > 17:
                    src_tsap = data[16:18]
                    dst_tsap = data[19:21]
                    info["src_tsap"] = src_tsap.hex()
                    info["dst_tsap"] = dst_tsap.hex()
                    src_val = struct.unpack(">H", src_tsap)[0]
                    info["src_tsap_profile"] = TSAP_PROFILES.get(
                        src_val, f"Custom({hex(src_val)})"
                    )
                    dst_val = struct.unpack(">H", dst_tsap)[0]
                    info["dst_tsap_profile"] = TSAP_PROFILES.get(
                        dst_val, f"Custom({hex(dst_val)})"
                    )

            elif cotp == 0x10:
                info["description"] = "COTP Data Transfer"
                info["cotp_ptype"] = "DT"
                if len(data) > 6:
                    s7 = data[6:]
                    self._parse_s7_info(s7, info)

            elif cotp == 0xD0:
                info["description"] = "COTP Connection Confirm"
                info["cotp_ptype"] = "CC"
            elif cotp == 0xF0:
                info["description"] = "COTP Data (nested)"
                if len(data) > 5:
                    s7 = data[5:]
                    self._parse_s7_info(s7, info)

            return info
        except Exception:
            return None

    def _parse_s7_info(self, s7, info):
        if len(s7) <= 1:
            return
        func = s7[1]
        info["function_code"] = func
        info["function_name"] = FUNC_NAMES.get(func, f"Unknown(0x{func:02X})")
        info["description"] = f"S7 {info['function_name']}"

        if len(s7) > 5:
            info["request_id"] = struct.unpack(">H", s7[4:6])[0]

        if func in (0x00, 0x1A) and len(s7) > 6:
            sub = s7[6]
            info["cpu_command"] = CPU_CMDS.get(sub, f"Unknown(0x{sub:02X})")
            info["description"] = f"PLC {info['cpu_command']}"

        elif func == 0x04 and len(s7) > 12:
            count = s7[10] if len(s7) > 10 else 1
            info["read_count"] = count
            items = []
            off = 12
            for _ in range(count):
                if off + 10 > len(s7):
                    break
                area = s7[off + 5]
                db = struct.unpack(">H", s7[off + 4:off + 6])[0]
                addr = struct.unpack(">H", s7[off + 6:off + 8])[0]
                length = struct.unpack(">H", s7[off + 2:off + 4])[0]
                items.append({
                    "area": AREA_NAMES.get(area, hex(area)),
                    "db": db, "address": addr, "length": length,
                })
                off += 10
            info["read_items"] = items

        elif func == 0x05 and len(s7) > 12:
            count = s7[10] if len(s7) > 10 else 1
            info["write_count"] = count
            items = []
            off = 12
            for _ in range(count):
                if off + 10 > len(s7):
                    break
                area = s7[off + 5]
                db = struct.unpack(">H", s7[off + 4:off + 6])[0]
                addr = struct.unpack(">H", s7[off + 6:off + 8])[0]
                length = struct.unpack(">H", s7[off + 2:off + 4])[0]
                items.append({
                    "area": AREA_NAMES.get(area, hex(area)),
                    "db": db, "address": addr, "length": length,
                })
                off += 10
            info["write_items"] = items

        elif func == 0x1C and len(s7) >= 8:
            sub = s7[6] if len(s7) > 6 else 0
            info["block_sub_func"] = BLOCK_FUNCS.get(sub, f"Unknown(0x{sub:02X})")
            info["description"] = f"Block {info['block_sub_func']}"

        elif func == 0x21:
            info["description"] = "PASSWORD attempt"
        elif func == 0x22:
            info["description"] = "Force STOP"

    def detect(self, data, src_addr=None, dst_addr=None):
        info = self.parse_packet(data)
        if not info:
            return DetectionResult("S7COMM", False, "low", "Invalid S7COMM packet")

        details = info.copy()
        desc = info.get("description", "")

        if src_addr:
            session = self.session_tracker.get(src_addr)
            session.record(info)

        if info.get("cotp_type") == 0x11:
            profile = info.get("src_tsap_profile", "")
            if profile == "PG":
                return DetectionResult("S7COMM", True, "medium",
                                       f"PG connection ({desc}) – engineering access",
                                       details, score=10)

        func = info.get("function_code")

        if func in (0x00, 0x1A):
            cmd = info.get("cpu_command", "")
            if cmd == "STOP":
                self._log_state_change("RUN" if self._plc_state is None else self._plc_state, "STOP")
                self._plc_state = "STOP"
                return DetectionResult("S7COMM", True, "critical",
                                       "PLC STOP command detected!", details, score=30)
            if cmd in ("HOT_START", "COLD_START"):
                self._log_state_change(self._plc_state or "STOP", "STARTUP")
                self._plc_state = "STARTUP"
                return DetectionResult("S7COMM", True, "critical",
                                       f"PLC {cmd} – unexpected restart or control",
                                       details, score=20)
            if cmd == "RUN":
                self._log_state_change(self._plc_state or "STOP", "RUN")
                self._plc_state = "RUN"

        if func == 0x05:
            items = info.get("write_items", [])
            for item in items:
                if item.get("area") == "DB" and item.get("address", 0) < 100:
                    return DetectionResult("S7COMM", True, "high",
                                           f"Write to DB{item['db']} sensitive area "
                                           f"addr={item['address']}", details, score=20)
            return DetectionResult("S7COMM", True, "high",
                                   f"S7 Write ({len(items)} items) – possible "
                                   f"unauthorized modification", details, score=20)

        if func == 0x04:
            items = info.get("read_items", [])
            for item in items:
                if item.get("area") == "DB" and item.get("length", 0) > 500:
                    return DetectionResult("S7COMM", True, "medium",
                                           f"Large DB{item['db']} read ({item['length']}B) – "
                                           f"possible data exfiltration", details, score=15)

        if func == 0x21:
            attempts = 1
            if src_addr:
                session = self.session_tracker.get(src_addr)
                attempts = session.password_attempts
            if attempts > 5:
                return DetectionResult("S7COMM", True, "critical",
                                       f"Password brute-force ({attempts} attempts from "
                                       f"{src_addr})", details, score=25)
            return DetectionResult("S7COMM", True, "high",
                                   "S7 Password attempt – unauthorized access",
                                   details, score=25)

        if func == 0x22:
            return DetectionResult("S7COMM", True, "critical",
                                   "Force STOP – immediate PLC halt!", details, score=35)

        if func == 0x1C:
            sub = info.get("block_sub_func", "")
            if sub in ("StartUpload", "Upload"):
                return DetectionResult("S7COMM", True, "high",
                                       f"Block upload ({sub}) – possible IP theft",
                                       details, score=20)
            if sub in ("StartDownload", "Download"):
                return DetectionResult("S7COMM", True, "high",
                                       f"Block download ({sub}) – possible firmware "
                                       f"tampering", details, score=30)
            if sub == "DeleteBlock":
                return DetectionResult("S7COMM", True, "critical",
                                       "Block delete – sabotage attempt", details, score=35)

        if func in (0x28, 0x29):
            if info.get("szl_id") == 0x001C:
                return DetectionResult("S7COMM", True, "low",
                                       "Diagnostic buffer read – reconnaissance",
                                       details, score=8)

        if func in (0x1E, 0x1F):
            return DetectionResult("S7COMM", False, "info",
                                   "Time function – possible anti-forensic", details, score=10)

        return DetectionResult("S7COMM", False, "info", desc, details)

    def _log_state_change(self, from_state, to_state):
        entry = {
            "time": time.time(),
            "from": from_state,
            "to": to_state,
        }
        self._state_change_log.append(entry)
        self._state_change_log = [
            e for e in self._state_change_log
            if time.time() - e["time"] < 3600
        ]
        log.warning(f"PLC state transition: {from_state} -> {to_state}")

    def get_plc_state_history(self):
        return list(self._state_change_log)

    def get_session_score(self, src):
        session = self.session_tracker.get(src)
        score, reasons = self.scorer.score_session(session)
        return {
            "src": src,
            "score": score,
            "reasons": reasons,
            "packet_count": session.packet_count,
            "first_seen": session.first_seen,
            "last_seen": session.last_seen,
            "tsap_profile": session.tsap_profile,
        }

    def get_all_threats(self):
        threats = []
        for session in self.session_tracker.all_sessions():
            score, reasons = self.scorer.score_session(session)
            if score > 0:
                threats.append({
                    "src": session.src,
                    "score": score,
                    "reasons": reasons,
                })
        return sorted(threats, key=lambda x: x["score"], reverse=True)


if __name__ == "__main__":
    d = S7CommDetector()
    tests = [
        (b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc0\x01\x0a\xc1\x02"
         b"\x01\x02\xc2\x02\x01\x00", "COTP CR PG"),
        (b"\x03\x00\x00\x1a\x11\x10\x00\x00\x00\x01\x00\xc0\x01\x0a"
         b"\x32\x00\x00\x00\x00\x00\x00\x00\x04", "CPU STOP"),
        (b"\x03\x00\x00\x1c\x11\x10\x00\x00\x00\x01\x00\xc0\x01\x0a"
         b"\x32\x01\x00\x00\x00\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00",
         "Setup"),
        (b"\x03\x00\x00\x1a\x11\x10\x00\x00\x00\x01\x00\xc0\x01\x0a"
         b"\x32\x21\x00\x00\x00\x00\x00\x00", "Password"),
        (b"\x03\x00\x00\x1a\x11\x10\x00\x00\x00\x01\x00\xc0\x01\x0a"
         b"\x32\x09\x00\x00\x00\x00\x00\x00", "Start Download"),
        (b"\x03\x00\x00\x1a\x11\x10\x00\x00\x00\x01\x00\xc0\x01\x0a"
         b"\x32\x22\x00\x00\x00\x00\x00\x00", "Force Stop"),
    ]
    for data, desc in tests:
        result = d.detect(data, src_addr="192.168.1.100")
        log.info(f"  [{desc}] {result}")

    log.info("\n--- Threat Summary ---")
    for t in d.get_all_threats():
        log.info(f"  {t['src']}: score={t['score']} reasons={t['reasons']}")
