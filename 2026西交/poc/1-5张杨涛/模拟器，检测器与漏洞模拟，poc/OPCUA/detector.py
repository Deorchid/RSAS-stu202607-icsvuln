"""
OPC UA Protocol Detector — behavioral tracking, threat scoring,
anomaly detection, and security policy monitoring.
Self-contained; Python stdlib only.
"""
import struct
import time
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("OPCUADetect")

MSG_TYPES = {b"HEL": "Hello", b"ACK": "Acknowledge", b"ERR": "Error",
             b"OPN": "OpenSecureChannel", b"CLO": "CloseSecureChannel",
             b"MSG": "MessageChunk"}

SERVICE_NAMES = {
    428: "GetEndpoints", 461: "CreateSession", 466: "ActivateSession",
    525: "Browse", 526: "BrowseNext", 629: "Read", 669: "Write",
    781: "CreateSubscription", 745: "CreateMonitoredItems", 822: "Publish",
}

THREAT_LOW    = 1
THREAT_MEDIUM = 3
THREAT_HIGH   = 6
THREAT_CRITICAL = 10

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
        return "[%s] %sALERT [%s] %s (score=%d)" % (
            self.severity.upper(), "" if self.alert else "INFO ",
            self.protocol, self.message, self.score)


class SessionTracker:
    def __init__(self, addr):
        self.addr = addr
        self.created = time.time()
        self.last_seen = time.time()
        self.hello_count = 0
        self.opn_count = 0
        self.msg_count = 0
        self.error_count = 0
        self.browse_count = 0
        self.read_count = 0
        self.write_count = 0
        self.sub_count = 0
        self.mon_count = 0
        self.channels_opened = []
        self.tokens_seen = set()
        self.browse_targets = set()
        self.write_targets = []
        self.service_history = []
        self.msg_sizes = []
        self.security_policies = set()
        self.threat_score = 0
        self.alert_history = []
        self.session_id = None

    def touch(self):
        self.last_seen = time.time()

    def add_alert(self, severity, msg):
        self.alert_history.append((time.time(), severity, msg))


class OpcUaDetector:
    def __init__(self):
        self.name = "OPCUADetector"
        self._sessions = {}
        self._session_timeout = 3600
        self._hello_tracker = defaultdict(list)
        self._channel_tracker = defaultdict(lambda: {"open_count": 0, "msg_count": 0,
                                                      "last_seen": 0})
        self._browse_window = defaultdict(list)
        self._write_window = defaultdict(list)
        self._subscription_window = defaultdict(list)
        self._protected_nodes = {
            "i=2256", "i=2257", "i=2268", "i=2259", "i=2274", "i=2275",
        }
        self._known_token_sets = defaultdict(set)

    def _get_or_create_session(self, addr):
        key = addr if isinstance(addr, str) else "unknown"
        now = time.time()
        if key in self._sessions and now - self._sessions[key].last_seen < self._session_timeout:
            self._sessions[key].touch()
            return self._sessions[key]
        st = SessionTracker(key)
        self._sessions[key] = st
        self._cleanup_sessions()
        return st

    def _cleanup_sessions(self):
        now = time.time()
        expired = [k for k, v in self._sessions.items()
                   if now - v.last_seen > self._session_timeout]
        for k in expired:
            del self._sessions[k]

    def parse_packet(self, data):
        if len(data) < 8:
            return None
        try:
            msg_len = struct.unpack(">I", data[:4])[0]
            msg_type = data[4:7]
            chunk_type = data[7]
            info = {
                "protocol": "opcua",
                "message_type": msg_type.decode(errors="replace"),
                "message_name": MSG_TYPES.get(msg_type, "Unknown(%s)" % msg_type.decode(errors="replace")),
                "length": msg_len,
                "chunk_type": chunk_type,
                "is_final": chunk_type in (70, 65, 99),
            }

            if msg_type == b"HEL" and len(data) >= 24:
                info["recv_buf"] = struct.unpack(">I", data[8:12])[0]
                info["send_buf"] = struct.unpack(">I", data[12:16])[0]
                info["max_msg_size"] = struct.unpack(">I", data[16:20])[0]
                info["max_chunk_count"] = struct.unpack(">I", data[20:24])[0] if len(data) >= 24 else 0
                if len(data) > 24:
                    raw = data[24:].rstrip(b"\x00").decode(errors="replace")
                    info["endpoint_url"] = raw

            elif msg_type == b"ACK" and len(data) >= 24:
                info["recv_buf"] = struct.unpack(">I", data[8:12])[0]
                info["send_buf"] = struct.unpack(">I", data[12:16])[0]

            elif msg_type == b"ERR" and len(data) >= 12:
                info["error_code"] = struct.unpack(">I", data[8:12])[0]
                if len(data) > 12:
                    info["error_reason"] = data[12:].rstrip(b"\x00").decode(errors="replace")

            elif msg_type == b"OPN" and len(data) >= 24:
                info["client_protocol"] = struct.unpack(">I", data[8:12])[0]
                info["security_policy"] = data[12:16].hex()
                info["certificate_length"] = struct.unpack(">I", data[16:20])[0]
                info["token_id"] = struct.unpack(">I", data[20:24])[0]
                info["has_certificate"] = info["certificate_length"] > 0

            elif msg_type == b"CLO" and len(data) >= 12:
                info["channel_id"] = struct.unpack(">I", data[8:12])[0]

            elif msg_type == b"MSG" and len(data) >= 28:
                info["channel_id"] = struct.unpack(">I", data[8:12])[0]
                info["token_id"] = struct.unpack(">I", data[12:16])[0]
                info["sequence_number"] = struct.unpack(">I", data[16:20])[0]
                info["request_id"] = struct.unpack(">I", data[20:24])[0]
                if len(data) > 30:
                    info["service_id"] = struct.unpack("<H", data[24:26])[0]
                    info["service_name"] = SERVICE_NAMES.get(info["service_id"], "Unknown(%d)" % info["service_id"])
                    info["request_handle"] = struct.unpack("<I", data[26:30])[0]

            return info
        except Exception:
            return None

    def detect(self, data, src_addr=None, dst_addr=None):
        info = self.parse_packet(data)
        if not info:
            return DetectionResult("OPCUA", False, "low", "Invalid OPC UA packet", score=0)

        addr = src_addr if isinstance(src_addr, str) else (
            str(src_addr) if src_addr else "unknown")
        now = time.time()
        session = self._get_or_create_session(addr)
        details = info.copy()

        results = []
        msg_len = info.get("length", 0)
        mt = info.get("message_type", "")
        mn = info.get("message_name", "")

        # ---- Rule: Oversized / zero-length messages ----
        if msg_len > 10_000_000:
            session.threat_score += THREAT_HIGH
            results.append(DetectionResult("OPCUA", True, "high",
                "Oversized message (%d bytes) — possible DoS" % msg_len, details,
                score=THREAT_HIGH))
        elif msg_len == 0:
            session.threat_score += THREAT_MEDIUM
            results.append(DetectionResult("OPCUA", True, "medium",
                "Zero-length message — possible fuzzing", details, score=THREAT_MEDIUM))
        elif msg_len > 100_000:
            session.threat_score += THREAT_LOW
            results.append(DetectionResult("OPCUA", True, "low",
                "Large message (%d bytes)" % msg_len, details, score=THREAT_LOW))

        session.msg_sizes.append(msg_len)
        if len(session.msg_sizes) > 100:
            session.msg_sizes = session.msg_sizes[-100:]

        # ---- Hello flood detection ----
        if mt == "HEL":
            session.hello_count += 1
            recv_b = info.get("recv_buf", 0)
            send_b = info.get("send_buf", 0)
            max_m = info.get("max_msg_size", 0)

            if recv_b == 0 or send_b == 0:
                session.threat_score += THREAT_MEDIUM
                results.append(DetectionResult("OPCUA", True, "medium",
                    "Hello with zero buffer size — possible fuzzing", details, score=THREAT_MEDIUM))
            if max_m == 0:
                results.append(DetectionResult("OPCUA", True, "low",
                    "Zero max message size in Hello", details, score=THREAT_LOW))

            self._hello_tracker[addr].append(now)
            self._hello_tracker[addr] = [t for t in self._hello_tracker[addr] if now - t < 10]
            hc = len(self._hello_tracker[addr])
            if hc > 20:
                session.threat_score += THREAT_HIGH
                results.append(DetectionResult("OPCUA", True, "high",
                    "Hello flood — %d Hellos in 10 seconds" % hc, details, score=THREAT_HIGH))
            elif hc > 5:
                session.threat_score += THREAT_LOW
                results.append(DetectionResult("OPCUA", True, "low",
                    "Elevated Hello rate — %d/10s" % hc, details, score=THREAT_LOW))

        # ---- Error messages ----
        if mt == "ERR":
            session.error_count += 1
            err_code = info.get("error_code", 0)
            err_reason = info.get("error_reason", "")
            sev = "critical" if err_code == 0x80000000 else "high"
            score = THREAT_CRITICAL if sev == "critical" else THREAT_HIGH
            session.threat_score += score
            results.append(DetectionResult("OPCUA", True, sev,
                "OPC UA Error 0x%08X: %s" % (err_code, err_reason), details, score=score))

        # ---- OPN: Channel opening analysis ----
        if mt == "OPN":
            session.opn_count += 1
            sec_policy = info.get("security_policy", "")
            has_cert = info.get("has_certificate", False)

            session.security_policies.add(sec_policy)
            session.channels_opened.append(now)
            session.channels_opened = [t for t in session.channels_opened if now - t < 60]

            # Security policy violation: using None when others are available
            if sec_policy == "00000000" and not has_cert:
                session.threat_score += THREAT_LOW
                results.append(DetectionResult("OPCUA", True, "low",
                    "Security policy: None (no encryption/signing)", details, score=THREAT_LOW))

            # Certificate missing
            if not has_cert:
                results.append(DetectionResult("OPCUA", True, "low",
                    "No client certificate provided", details, score=THREAT_LOW))

            # Rapid channel openings
            ch_count = len(session.channels_opened)
            if ch_count > 50:
                session.threat_score += THREAT_HIGH
                results.append(DetectionResult("OPCUA", True, "high",
                    "Excessive channel openings — %d in 60s" % ch_count, details, score=THREAT_HIGH))
            elif ch_count > 10:
                session.threat_score += THREAT_MEDIUM
                results.append(DetectionResult("OPCUA", True, "medium",
                    "Rapid channel openings — %d in 60s" % ch_count, details, score=THREAT_MEDIUM))

        # ---- MSG: Service-layer analysis ----
        if mt == "MSG":
            session.msg_count += 1
            seq = info.get("sequence_number", 0)
            rid = info.get("request_id", 0)
            token = info.get("token_id", 0)
            ch_id = info.get("channel_id", 0)
            svc_id = info.get("service_id")
            svc_name = info.get("service_name", "")

            # Zero seq/req id
            if seq == 0 or rid == 0:
                session.threat_score += THREAT_MEDIUM
                results.append(DetectionResult("OPCUA", True, "medium",
                    "Message with zero seq/request id — possible fuzzing", details, score=THREAT_MEDIUM))

            # Token mismatch / session hijacking
            session.tokens_seen.add(token)
            if len(session.tokens_seen) > 5:
                session.threat_score += THREAT_HIGH
                results.append(DetectionResult("OPCUA", True, "high",
                    "Token proliferation — %d distinct tokens (possible hijacking)" % len(session.tokens_seen),
                    details, score=THREAT_HIGH))

            # Service-specific tracking
            if svc_id is not None:
                session.service_history.append((now, svc_id))
                if len(session.service_history) > 200:
                    session.service_history = session.service_history[-200:]

            # ---- Browse pattern detection (reconnaissance) ----
            if svc_id == 525:  # Browse
                session.browse_count += 1
                self._browse_window[addr].append(now)
                self._browse_window[addr] = [t for t in self._browse_window[addr] if now - t < 60]

                # Detect full tree enumeration (many Browses without Reads)
                bc = len(self._browse_window[addr])
                if bc > 100:
                    session.threat_score += THREAT_HIGH
                    results.append(DetectionResult("OPCUA", True, "high",
                        "Full tree enumeration — %d Browse ops in 60s (reconnaissance)" % bc,
                        details, score=THREAT_HIGH))
                elif bc > 30:
                    session.threat_score += THREAT_MEDIUM
                    results.append(DetectionResult("OPCUA", True, "medium",
                        "Suspicious browse pattern — %d Browse ops in 60s" % bc,
                        details, score=THREAT_MEDIUM))

                if bc > 20:
                    read_ratio = session.read_count / max(bc, 1)
                    if read_ratio < 0.1:
                        session.threat_score += THREAT_MEDIUM
                        results.append(DetectionResult("OPCUA", True, "medium",
                            "Browse-heavy pattern (Browse:%d Read:%d) — possible enumeration" % (bc, session.read_count),
                            details, score=THREAT_MEDIUM))

            elif svc_id == 526:  # BrowseNext
                session.browse_count += 1

            elif svc_id == 629:  # Read
                session.read_count += 1

            # ---- Write monitoring ----
            elif svc_id == 669:  # Write
                session.write_count += 1
                self._write_window[addr].append(now)
                self._write_window[addr] = [t for t in self._write_window[addr] if now - t < 60]
                wc = len(self._write_window[addr])

                if wc > 30:
                    session.threat_score += THREAT_HIGH
                    results.append(DetectionResult("OPCUA", True, "high",
                        "Excessive writes — %d writes in 60s" % wc, details, score=THREAT_HIGH))
                elif wc > 10:
                    session.threat_score += THREAT_MEDIUM
                    results.append(DetectionResult("OPCUA", True, "medium",
                        "Elevated write rate — %d writes in 60s" % wc, details, score=THREAT_MEDIUM))

            # ---- Subscription abuse ----
            elif svc_id == 781:  # CreateSubscription
                session.sub_count += 1
                self._subscription_window[addr].append(now)
                self._subscription_window[addr] = [t for t in self._subscription_window[addr] if now - t < 60]
                sc = len(self._subscription_window[addr])
                if sc > 20:
                    session.threat_score += THREAT_HIGH
                    results.append(DetectionResult("OPCUA", True, "high",
                        "Subscription DoS — %d subscriptions in 60s" % sc, details, score=THREAT_HIGH))
                elif sc > 5:
                    session.threat_score += THREAT_MEDIUM
                    results.append(DetectionResult("OPCUA", True, "medium",
                        "Excessive subscriptions — %d in 60s" % sc, details, score=THREAT_MEDIUM))

            elif svc_id == 745:  # CreateMonitoredItems
                session.mon_count += 1

        # ---- Write-to-protected target detection (deferred analysis) ----
        if mt == "MSG" and info.get("service_id") == 669:
            body = data[30:] if len(data) > 30 else b""
            self._analyze_write_targets(body, addr, session, results)

        # ---- Aggregate threat score check ----
        if session.threat_score >= THREAT_CRITICAL:
            results.append(DetectionResult("OPCUA", True, "critical",
                "Aggregate threat score CRITICAL (%d)" % session.threat_score,
                {"session": str(addr), "score": session.threat_score,
                 "alerts": session.alert_history[-5:]}, score=session.threat_score))
        elif session.threat_score >= THREAT_HIGH:
            results.append(DetectionResult("OPCUA", True, "high",
                "Aggregate threat score HIGH (%d)" % session.threat_score,
                {"session": str(addr), "score": session.threat_score}, score=session.threat_score))

        # ---- Default: informational ----
        if not results:
            return DetectionResult("OPCUA", False, "info", mn, details, score=0)

        if len(results) == 1:
            return results[0]

        highest = max(results, key=lambda r: r.score)
        highest.details["related_alerts"] = [r.message for r in results if r is not highest]
        return highest

    def _analyze_write_targets(self, body, addr, session, results):
        """Try to extract node IDs from write request body."""
        try:
            if len(body) < 2:
                return
            node_count = struct.unpack("<H", body[0:2])[0]
            pos = 2
            for _ in range(min(node_count, 10)):
                node_info, pos = self._decode_node_id(body, pos)
                fid = node_info.get("full_id", "")
                if fid and pos < len(body):
                    if pos + 5 > len(body):
                        break
                    val_type = body[pos]; pos += 1
                    val_len = struct.unpack("<I", body[pos:pos+4])[0]; pos += 4
                    pos += val_len
                    if fid in self._protected_nodes:
                        session.threat_score += THREAT_CRITICAL
                        results.append(DetectionResult("OPCUA", True, "critical",
                            "Write to protected node: %s by %s" % (fid, addr),
                            {"node": fid, "src": addr}, score=THREAT_CRITICAL))
                    session.write_targets.append((fid, time.time()))
                    if len(session.write_targets) > 50:
                        session.write_targets = session.write_targets[-50:]
        except Exception:
            pass

    def _decode_node_id(self, data, pos):
        if pos >= len(data):
            return {"full_id": ""}, pos
        enc = data[pos]; pos += 1
        full_id = ""
        ns, val = 0, 0
        if enc == 0:
            if pos + 2 <= len(data):
                val = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
                full_id = "i=%d" % val
        elif enc == 1:
            if pos + 4 <= len(data):
                ns, val = struct.unpack("<HH", data[pos:pos+4]); pos += 4
                full_id = "ns=%d;i=%d" % (ns, val)
        elif enc == 2:
            if pos + 3 <= len(data):
                ns = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
                slen = data[pos]; pos += 1
                if pos + slen <= len(data):
                    sval = data[pos:pos+slen].decode(errors="replace"); pos += slen
                    full_id = "ns=%d;s=%s" % (ns, sval)
        elif enc == 4:
            if pos + 3 <= len(data):
                ns = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
                blen = data[pos]; pos += 1
                if pos + blen <= len(data):
                    pos += blen
                    full_id = "ns=%d;b=..." % ns
        return {"full_id": full_id, "ns": ns, "id": val}, pos

    def get_session_summary(self, addr):
        key = str(addr) if addr else "unknown"
        s = self._sessions.get(key)
        if not s:
            return {"status": "no_session", "addr": key}
        return {
            "addr": key,
            "hello_count": s.hello_count,
            "opn_count": s.opn_count,
            "msg_count": s.msg_count,
            "browse_count": s.browse_count,
            "read_count": s.read_count,
            "write_count": s.write_count,
            "threat_score": s.threat_score,
            "active_seconds": time.time() - s.created,
            "recent_alerts": s.alert_history[-5:],
        }

    def get_all_sessions(self):
        self._cleanup_sessions()
        return {k: self.get_session_summary(k) for k in self._sessions}


if __name__ == "__main__":
    d = OpcUaDetector()
    test_cases = [
        (b"\x00\x00\x00\x10HELL\x00\x00\x00\x00\x00\x00\x00\x00", "Hello zero buf"),
        (b"\x00\x00\x00\x18HELL\x00\x01\x00\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00opc.tcp://x", "Hello normal"),
        (b"\x00\x00\x00\x10ERRR\x80\x00\x00\x00\x00\x00\x00\x00", "Error critical"),
        (b"\x00\x00\x00\x18OPN\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "OPN no cert"),
        (b"\x00\x00\x00\x20MSG\x00" + b"\x00" * 4 + b"\x00\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x0d\x02" + b"\x00" * 8, "MSG browse"),
    ]
    for data, desc in test_cases:
        result = d.detect(data, src_addr="192.168.1.100")
        log.info("  [%s] %s", desc, result)
