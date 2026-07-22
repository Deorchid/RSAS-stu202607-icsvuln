"""
OPC UA Vulnerable Simulator — deliberately insecure implementation
with weak authentication, session overload, and information leakage.
Self-contained; Python stdlib only.
"""
import socket
import threading
import struct
import logging
import time
import uuid
import random
from collections import OrderedDict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("OPCUAVuln")

MSG_TYPES = {b"HEL": "Hello", b"ACK": "Acknowledge", b"ERR": "Error",
             b"OPN": "OpenSecureChannel", b"CLO": "CloseSecureChannel",
             b"MSG": "MessageChunk"}

SERVICE_GET_ENDPOINTS       = 428
SERVICE_CREATE_SESSION      = 461
SERVICE_ACTIVATE_SESSION    = 466
SERVICE_BROWSE              = 525
SERVICE_BROWSE_NEXT         = 526
SERVICE_READ                = 629
SERVICE_WRITE               = 669
SERVICE_CREATE_SUBSCRIPTION = 781
SERVICE_CREATE_MON_ITEMS    = 745
SERVICE_PUBLISH             = 822

STATUS_GOOD                     = 0x00000000
STATUS_BAD_NODEID_UNKNOWN       = 0x80340000
STATUS_BAD_SERVICE_UNSUPPORTED  = 0x80020000
STATUS_BAD_SESSION_ID_INVALID   = 0x80250000

NODECLASS_OBJECT   = 1
NODECLASS_VARIABLE = 2
NODECLASS_FOLDER   = 8

BUILTIN_TYPES = {1: ("Boolean", 1), 2: ("SByte", 1), 3: ("Byte", 1),
                 4: ("Int16", 2), 5: ("UInt16", 2), 6: ("Int32", 4),
                 7: ("UInt32", 4), 8: ("Int64", 8), 9: ("UInt64", 8),
                 10: ("Float", 4), 11: ("Double", 8), 12: ("String", -1),
                 13: ("DateTime", 8), 14: ("Guid", 16), 15: ("ByteString", -1)}

MAX_BROWSE_REFS = 10


class OpcUaNode:
    __slots__ = ("node_id", "browse_name", "display_name", "node_class",
                 "value", "data_type", "data_type_id", "children", "writable", "ns_idx")
    def __init__(self, node_id, browse_name, display_name, node_class="Variable",
                 value=None, data_type="Double", writable=True, ns_idx=0):
        self.node_id = node_id
        self.browse_name = browse_name
        self.display_name = display_name
        self.node_class = node_class
        self.value = value
        self.data_type = data_type
        self.data_type_id = next((tid for tid, (n, _) in BUILTIN_TYPES.items() if n == data_type), 12)
        self.children = []
        self.writable = writable
        self.ns_idx = ns_idx


class BaseSim:
    def __init__(self, host="0.0.0.0", port=4840, name="Sim"):
        self.host = host
        self.port = port
        self.name = name
        self._server = None
        self._running = False
        self._thread = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self._server.bind((self.host, self.port))
        self._server.listen(10)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info("[%s] listening on %s:%d", self.name, self.host, self.port)

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info("[%s] connection from %s:%d", self.name, addr[0], addr[1])
                threading.Thread(target=self.handle_client, args=(conn, addr),
                                 daemon=True).start()
            except Exception:
                if self._running:
                    continue
                break

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        log.info("[%s] stopped", self.name)

    def handle_client(self, conn, addr):
        raise NotImplementedError


class OpcUaVulnSimulator(BaseSim):
    """Deliberately vulnerable OPC UA server implementation.

    VULNERABILITIES:
      - Anonymous access: no authentication required, all endpoints open
      - Security policy bypass: accept None even when Basic128 advertised
      - Session overload: no session limit, accept unlimited connections
      - Write to any node: no access control on write operations
      - Information leakage: detailed server diagnostics exposed via read
      - Subscription DoS: no limit on subscription or monitored item count
      - Certificate validation bypass: accept self-signed or expired certs
      - Weak token generation: predictable, sequential token IDs
    """
    def __init__(self, host="0.0.0.0", port=4840):
        super().__init__(host, port, "OPCUAVuln")
        self._build_node_tree()
        self.sessions = {}
        self.subscriptions = {}
        self.channel_id_counter = 1
        self._predictable_token = 1000
        self._mon_counter = 1
        self.max_chunk_size = 65536
        self._stop_event = threading.Event()
        self._ts = time.time
        self._start_alarm_thread()
        log.warning("[VULN] OPC UA server with no authentication, no session limit, "
                     "no access control, weak tokens")
        log.warning("[VULN] Security policies advertised but not enforced")
        log.warning("[VULN] Unlimited subscriptions and monitored items allowed")
        log.warning("[VULN] Self-signed and expired certificates accepted")
        log.warning("[VULN] Detailed server diagnostics exposed via read")

    # ------------------------------------------------------------------ #
    #  Node tree (rich, with exposed diagnostics)                         #
    # ------------------------------------------------------------------ #
    def _build_node_tree(self):
        def fold(oid, bname, dname):
            return OpcUaNode(oid, bname, dname, "Folder", writable=False)
        def obj(oid, bname, dname):
            return OpcUaNode(oid, bname, dname, "Object", writable=False)
        def var(oid, bname, dname, val, dt, w=True, ns=0):
            return OpcUaNode(oid, bname, dname, "Variable", val, dt, writable=w, ns_idx=ns)

        root = fold("i=84", "Root", "Root")
        objects = fold("i=85", "Objects", "Objects")
        types = fold("i=86", "Types", "Types")
        views = fold("i=87", "Views", "Views")

        server = obj("i=2253", "Server", "Server")
        server.children = [
            var("i=2256", "ServerStatus", "ServerStatus", "VULNERABLE", "String", False),
            var("i=2257", "CurrentTime", "CurrentTime", 0.0, "Double", False),
            var("i=2268", "BuildInfo", "BuildInfo", "OPCUA-VulnSim v1.0-debug", "String", False),
            var("i=2259", "State", "State", "Running-InsecureMode", "String", False),
            var("i=2274", "ServerDiagnostics", "ServerDiagnostics", "FULL_DEBUG", "String", False),
            var("i=2275", "EnabledFlag", "EnabledFlag", True, "Boolean", False),
            # Exposed diagnostics — information leakage vulnerability
            var("ns=2;s=DiagActiveSessions", "DiagActiveSessions", "Active Sessions", 0, "Int32", False, 2),
            var("ns=2;s=DiagTotalRequests", "DiagTotalRequests", "Total Requests Served", 0, "Int64", False, 2),
            var("ns=2;s=DiagMemoryUsage", "DiagMemoryUsage", "Memory Usage (KB)", 0, "Int32", False, 2),
            var("ns=2;s=DiagClientList", "DiagClientList", "Connected Client IPs", "", "String", False, 2),
            var("ns=2;s=DiagInternalConfig", "DiagInternalConfig", "Internal Configuration",
                "debug=True;auth=disabled;encrypt=off;rate_limit=none", "String", False, 2),
        ]

        device_set = obj("ns=1;s=DeviceSet", "DeviceSet", "DeviceSet")
        sensors = obj("ns=1;s=Sensors", "Sensors", "Sensors")
        sensors.children = [
            var("ns=1;s=Temperature", "Temperature", "Temperature Sensor", 25.0, "Double", True, 1),
            var("ns=1;s=Pressure", "Pressure", "Pressure Sensor", 100.0, "Double", True, 1),
            var("ns=1;s=FlowRate", "FlowRate", "Flow Rate", 50.0, "Double", True, 1),
            var("ns=1;s=Humidity", "Humidity", "Humidity Sensor", 45.0, "Double", True, 1),
            var("ns=1;s=Vibration", "Vibration", "Vibration Sensor", 0.5, "Float", True, 1),
            # Exposed calibration data
            var("ns=2;s=CalibrationDate", "CalibrationDate", "Calibration Date",
                "2025-06-15", "String", False, 2),
            var("ns=2;s=SensorSerial", "SensorSerial", "Sensor Serial Number",
                "HW-TEMP-0942", "String", False, 2),
        ]

        actuators = obj("ns=1;s=Actuators", "Actuators", "Actuators")
        actuators.children = [
            var("ns=1;s=ValveStatus", "ValveStatus", "Valve Status", True, "Boolean", True, 1),
            var("ns=1;s=MotorSpeed", "MotorSpeed", "Motor Speed", 3000, "Int32", True, 1),
            var("ns=1;s=SetPoint", "SetPoint", "Set Point", 75.0, "Double", True, 1),
            var("ns=1;s=Mode", "Mode", "Operation Mode", 0, "Int32", True, 1),
            var("ns=1;s=EmergencyOverride", "EmergencyOverride", "Emergency Override", False, "Boolean", True, 1),
        ]

        alarms = obj("ns=1;s=Alarms", "Alarms", "Alarms Group")
        alarms.children = [
            var("ns=1;s=HighTempAlarm", "HighTempAlarm", "High Temperature", False, "Boolean", True, 1),
            var("ns=1;s=LowPressureAlarm", "LowPressureAlarm", "Low Pressure", False, "Boolean", True, 1),
            var("ns=1;s=EmergencyStop", "EmergencyStop", "Emergency Stop", False, "Boolean", True, 1),
        ]

        device_set.children = [sensors, actuators, alarms]
        objects.children = [device_set, server]
        root.children = [objects, types, views]

        self.nodes = OrderedDict()
        for n in [root, objects, types, views, server, device_set, sensors, actuators, alarms]:
            self._register(n)

    def _register(self, node):
        self.nodes[node.node_id] = node
        for c in node.children:
            self._register(c)

    # ------------------------------------------------------------------ #
    #  Client handler                                                     #
    # ------------------------------------------------------------------ #
    def handle_client(self, conn, addr):
        buf = b""
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                buf += data
                while len(buf) >= 8:
                    msg_len = struct.unpack(">I", buf[:4])[0]
                    if len(buf) < msg_len:
                        break
                    chunk = buf[:msg_len]
                    buf = buf[msg_len:]
                    self._dispatch(conn, chunk, addr)
        except Exception:
            pass
        finally:
            to_remove = [s for s, v in self.sessions.items() if v.get("addr") == addr]
            for s in to_remove:
                del self.sessions[s]
            conn.close()

    # ------------------------------------------------------------------ #
    #  Message dispatcher                                                 #
    # ------------------------------------------------------------------ #
    def _dispatch(self, conn, chunk, addr):
        msg_type = chunk[5:8]
        if msg_type == b"HEL":
            self._on_hello(conn, chunk, addr)
        elif msg_type == b"OPN":
            self._on_open(conn, chunk, addr)
        elif msg_type == b"CLO":
            self._on_close(conn, chunk, addr)
        elif msg_type == b"MSG":
            self._on_msg(conn, chunk, addr)
        else:
            self._err(conn, "UnknownMessage")

    def _on_hello(self, conn, chunk, addr):
        if len(chunk) < 20:
            return
        endpoint = ""
        if len(chunk) > 24:
            endpoint = chunk[24:].rstrip(b"\x00").decode(errors="replace")
        log.info("Hello from %s (endpoint=%s)", addr[0], endpoint)
        body = struct.pack(">IIIII", 0, 65536, 65536, 0, 0)
        conn.sendall(self._build_chunk(b"ACK", body))

    def _on_open(self, conn, chunk, addr):
        if len(chunk) < 24:
            return
        client_protocol = struct.unpack(">I", chunk[8:12])[0]
        sec_policy = chunk[12:16]
        cert_len = struct.unpack(">I", chunk[16:20])[0]
        cert_data = chunk[24:24+cert_len] if cert_len > 0 and len(chunk) >= 24+cert_len else b""

        # VULN: Certificate validation bypass — accept any cert (or none)
        if cert_len > 0:
            log.warning("[VULN] Accepting certificate (%d bytes) without validation", cert_len)
        else:
            log.info("OpenSecureChannel: no certificate (anonymous accepted)")

        # VULN: Security policy bypass — accept any security policy, including None
        log.warning("[VULN] Security policy bypass: accepting policy %s", sec_policy.hex())

        channel_id = self.channel_id_counter
        self.channel_id_counter += 1

        # VULN: Weak token generation — predictable sequential tokens
        token = self._predictable_token
        self._predictable_token += 1
        log.warning("[VULN] Weak token generated: %d (predictable sequence)", token)

        sid = "vulnsess_%d" % channel_id
        self.sessions[sid] = {
            "addr": addr,
            "channel_id": channel_id,
            "token": token,
            "created": self._ts(),
            "session_id": sid,
            "auth_token": "deadbeef%08d" % channel_id,
            "active": False,
            "security_policy": sec_policy.hex(),
            "client_cert": cert_data.hex() if cert_data else "(none)",
        }
        log.info("OpenSecureChannel: channel=%d session=%s token=%d", channel_id, sid, token)

        nonce = b"\x41" * 32
        body = struct.pack(">II", channel_id, token) + nonce
        conn.sendall(self._build_chunk(b"OPN", body))

    def _on_close(self, conn, chunk, addr):
        channel_id = struct.unpack(">I", chunk[8:12])[0] if len(chunk) >= 12 else 0
        to_del = [s for s, v in self.sessions.items() if v.get("channel_id") == channel_id]
        for s in to_del:
            del self.sessions[s]
        body = b"\x00" * 8
        conn.sendall(self._build_chunk(b"CLO", body))

    # ------------------------------------------------------------------ #
    #  MSG service routing                                                #
    # ------------------------------------------------------------------ #
    def _on_msg(self, conn, chunk, addr):
        if len(chunk) < 30:
            return
        channel_id = struct.unpack(">I", chunk[8:12])[0]
        token_id = struct.unpack(">I", chunk[12:16])[0]
        seq_num = struct.unpack(">I", chunk[16:20])[0]
        req_id = struct.unpack(">I", chunk[20:24])[0]
        service_id = struct.unpack("<H", chunk[24:26])[0]
        request_handle = struct.unpack("<I", chunk[26:30])[0]

        log.debug("Service %d (handle=%d)", service_id, request_handle)

        handlers = {
            SERVICE_GET_ENDPOINTS:       self._svc_get_endpoints,
            SERVICE_CREATE_SESSION:      self._svc_create_session,
            SERVICE_ACTIVATE_SESSION:    self._svc_activate_session,
            SERVICE_BROWSE:              self._svc_browse,
            SERVICE_BROWSE_NEXT:         self._svc_browse_next,
            SERVICE_READ:                self._svc_read,
            SERVICE_WRITE:               self._svc_write,
            SERVICE_CREATE_SUBSCRIPTION: self._svc_create_subscription,
            SERVICE_CREATE_MON_ITEMS:    self._svc_create_mon_items,
            SERVICE_PUBLISH:             self._svc_publish,
        }
        handler = handlers.get(service_id)
        if handler:
            resp_body = handler(chunk[30:], request_handle, addr)
        else:
            resp_body = struct.pack("<HII", service_id, request_handle, STATUS_BAD_SERVICE_UNSUPPORTED)

        full = struct.pack(">IIII", channel_id, token_id, seq_num + 1, req_id) + resp_body
        conn.sendall(self._build_chunk(b"MSG", full))

    # ------------------------------------------------------------------ #
    #  Services                                                           #
    # ------------------------------------------------------------------ #
    def _svc_get_endpoints(self, data, rh, addr):
        payload = struct.pack("<HII", SERVICE_GET_ENDPOINTS, rh, STATUS_GOOD)
        eps = ["opc.tcp://%s:%d/" % (self.host, self.port),
               "opc.tcp://%s:%d/Basic128" % (self.host, self.port)]
        payload += struct.pack("<H", len(eps))
        for e in eps:
            eb = e.encode()
            payload += struct.pack("<B", len(eb)) + eb
            payload += struct.pack("<BB", 0, 0) + b"None" + struct.pack("<B", 0)
        return payload

    def _svc_create_session(self, data, rh, addr):
        sid = "vulnsess_%s_%s" % (int(self._ts()), uuid.uuid4().hex[:6])
        auth = "auth_%08x" % random.randint(0, 0xFFFFFFFF)
        self.sessions[sid] = {"addr": addr, "channel_id": 0, "token": self._predictable_token,
                              "created": self._ts(), "session_id": sid, "auth_token": auth,
                              "active": False}
        self._predictable_token += 1
        log.info("CreateSession: %s (anonymous)", sid)
        payload = struct.pack("<HII", SERVICE_CREATE_SESSION, rh, STATUS_GOOD)
        payload += self._enc_node_id_str(sid)
        payload += self._enc_node_id_str(auth)
        payload += struct.pack("<IB", 3600, 16) + uuid.uuid4().bytes[:16]
        return payload

    def _svc_activate_session(self, data, rh, addr):
        nid, _ = self._dec_node_id(data, 0)
        sid = nid.get("string_id", "")
        if sid in self.sessions:
            self.sessions[sid]["active"] = True
        return struct.pack("<HII", SERVICE_ACTIVATE_SESSION, rh, STATUS_GOOD)

    def _svc_browse(self, data, rh, addr):
        if len(data) < 11:
            return struct.pack("<HII", SERVICE_BROWSE, rh, STATUS_GOOD) + struct.pack("<H", 0)
        max_refs = struct.unpack("<I", data[0:4])[0] or MAX_BROWSE_REFS
        node_count = struct.unpack("<H", data[9:11])[0]
        results = []
        pos = 11
        for _ in range(node_count):
            if pos >= len(data):
                break
            nid, pos = self._dec_node_id(data, pos)
            nd = self.nodes.get(nid.get("full_id", ""))
            if nd is None:
                results.append(struct.pack("<I", STATUS_BAD_NODEID_UNKNOWN) +
                               struct.pack("<BH", 0, 0))
                continue
            children = nd.children[:max_refs]
            body = struct.pack("<I", STATUS_GOOD) + struct.pack("<BH", 0, len(children))
            for c in children:
                body += self._enc_node_id_str(c.node_id)
                bn = c.browse_name.encode()
                dn = c.display_name.encode()
                body += struct.pack("<B", len(bn)) + bn
                body += struct.pack("<B", len(dn)) + dn
                body += struct.pack("<B", NODECLASS_FOLDER if c.node_class == "Folder" else
                                    NODECLASS_OBJECT if c.node_class == "Object" else NODECLASS_VARIABLE)
            results.append(body)
        payload = struct.pack("<HII", SERVICE_BROWSE, rh, STATUS_GOOD) + struct.pack("<H", len(results))
        return payload + b"".join(results)

    def _svc_browse_next(self, data, rh, addr):
        return struct.pack("<HII", SERVICE_BROWSE_NEXT, rh, STATUS_GOOD) + struct.pack("<H", 0)

    def _svc_read(self, data, rh, addr):
        if len(data) < 14:
            return struct.pack("<HII", SERVICE_READ, rh, STATUS_GOOD) + struct.pack("<H", 0)
        node_count = struct.unpack("<H", data[12:14])[0]
        results = []
        pos = 14
        for _ in range(node_count):
            if pos >= len(data):
                break
            nid, pos = self._dec_node_id(data, pos)
            nd = self.nodes.get(nid.get("full_id", ""))
            if nd:
                val_enc = self._encode_val(nd.value, nd.data_type_id)
                results.append(struct.pack("<I", STATUS_GOOD) + val_enc + struct.pack("<d", self._ts()))
                # VULN: Information leakage — log every read
                log.info("[VULN LEAK] Read %s = %s by %s", nd.browse_name, str(nd.value)[:60], addr[0])
            else:
                results.append(struct.pack("<I", STATUS_BAD_NODEID_UNKNOWN) +
                               struct.pack("<BB", 0, 0) + struct.pack("<d", 0.0))
        payload = struct.pack("<HII", SERVICE_READ, rh, STATUS_GOOD) + struct.pack("<H", len(results))
        return payload + b"".join(results)

    def _svc_write(self, data, rh, addr):
        if len(data) < 2:
            return struct.pack("<HII", SERVICE_WRITE, rh, STATUS_GOOD) + struct.pack("<H", 0)
        node_count = struct.unpack("<H", data[0:2])[0]
        results = []
        pos = 2
        for _ in range(node_count):
            if pos + 4 >= len(data):
                break
            nid, pos = self._dec_node_id(data, pos)
            val_type = data[pos]; pos += 1
            val_len = struct.unpack("<I", data[pos:pos+4])[0]; pos += 4
            val_bytes = data[pos:pos+val_len]; pos += val_len
            nd = self.nodes.get(nid.get("full_id", ""))
            if nd is None:
                results.append(struct.pack("<I", STATUS_BAD_NODEID_UNKNOWN))
                continue
            # VULN: Write to any node — no access control
            nd.value = self._decode_val(val_type, val_bytes)
            results.append(struct.pack("<I", STATUS_GOOD))
            log.info("[VULN] Write %s = %s by %s (no ACL check)", nd.browse_name, str(nd.value)[:50], addr[0])
        payload = struct.pack("<HII", SERVICE_WRITE, rh, STATUS_GOOD) + struct.pack("<H", len(results))
        return payload + b"".join(results)

    def _svc_create_subscription(self, data, rh, addr):
        # VULN: No limit on subscription count
        sub_id = random.randint(1, 0x7FFFFFFF)
        self.subscriptions[sub_id] = {"created": self._ts(), "addr": addr, "seq": 1, "items": {}}
        log.info("[VULN] CreateSubscription: id=%d (total=%d, unlimited)", sub_id, len(self.subscriptions))
        payload = struct.pack("<HII", SERVICE_CREATE_SUBSCRIPTION, rh, STATUS_GOOD)
        payload += struct.pack("<I", sub_id) + struct.pack("<d", 0.5) + struct.pack("<II", 10, 3)
        return payload

    def _svc_create_mon_items(self, data, rh, addr):
        if len(data) < 10:
            return struct.pack("<HII", SERVICE_CREATE_MON_ITEMS, rh, STATUS_GOOD) + struct.pack("<H", 0)
        sub_id = struct.unpack("<I", data[0:4])[0]
        item_count = struct.unpack("<H", data[8:10])[0]
        results = []
        pos = 10
        for i in range(item_count):
            if pos >= len(data):
                break
            nid, pos = self._dec_node_id(data, pos)
            pos += 17
            mon_id = self._mon_counter
            self._mon_counter += 1
            results.append(struct.pack("<II", STATUS_GOOD, mon_id) + struct.pack("<dI", 0.5, 1))
            if sub_id in self.subscriptions:
                self.subscriptions[sub_id]["items"][mon_id] = {"node": nid.get("full_id", "")}
        log.info("[VULN] CreateMonItems: sub=%d items=%d (total mons=%d)", sub_id, item_count, self._mon_counter)
        payload = struct.pack("<HII", SERVICE_CREATE_MON_ITEMS, rh, STATUS_GOOD) + struct.pack("<H", len(results))
        return payload + b"".join(results)

    def _svc_publish(self, data, rh, addr):
        payload = struct.pack("<HII", SERVICE_PUBLISH, rh, STATUS_GOOD)
        active = next(((s, v) for s, v in self.subscriptions.items()
                       if v.get("addr") == addr and v.get("items")), None)
        if active is None:
            return payload + struct.pack("<IIBB", 0, 0, 0, 0)
        sid, sub = active
        seq = sub["seq"]; sub["seq"] += 1
        notifs = b""
        ncount = 0
        for mid, mi in list(sub["items"].items())[:5]:
            nd = self.nodes.get(mi["node"])
            if nd:
                notifs += struct.pack("<II", mid, mid) + self._encode_val(nd.value, nd.data_type_id)
                ncount += 1
        return payload + struct.pack("<IIBB", sid, seq, 0, ncount) + notifs

    # ------------------------------------------------------------------ #
    #  Encoding helpers                                                   #
    # ------------------------------------------------------------------ #
    def _enc_node_id_str(self, full_id):
        if full_id.startswith("ns="):
            parts = full_id.split(";", 1)
            ns = int(parts[0][3:])
            rest = parts[1]
            if rest.startswith("s="):
                s = rest[2:].encode()
                return struct.pack("<BH", 2, ns) + struct.pack("<B", len(s)) + s
            elif rest.startswith("i="):
                return struct.pack("<BHH", 1, ns, int(rest[2:]))
        elif full_id.startswith("i="):
            return struct.pack("<BH", 0, int(full_id[2:]))
        return struct.pack("<BH", 0, 0)

    def _dec_node_id(self, data, pos):
        if pos >= len(data):
            return {"full_id": ""}, pos
        enc = data[pos]; pos += 1
        ns, val, sval = 0, 0, ""
        if enc == 0 and pos + 2 <= len(data):
            val = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
            full = "i=%d" % val
        elif enc == 1 and pos + 4 <= len(data):
            ns, val = struct.unpack("<HH", data[pos:pos+4]); pos += 4
            full = "ns=%d;i=%d" % (ns, val)
        elif enc == 2 and pos + 3 <= len(data):
            ns = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
            slen = data[pos]; pos += 1
            sval = data[pos:pos+slen].decode(errors="replace"); pos += slen
            full = "ns=%d;s=%s" % (ns, sval)
        else:
            full = ""
        return {"full_id": full, "ns": ns, "id": val, "string_id": sval}, pos

    def _encode_val(self, value, type_id):
        if value is None:
            return struct.pack("<BI", type_id, 0)
        if type_id == 1:
            return struct.pack("<BI", 1, 1) + (b"\x01" if value else b"\x00")
        elif type_id in (6, 7):
            return struct.pack("<BI", 6, 4) + struct.pack("<i", int(value))
        elif type_id in (8, 9):
            return struct.pack("<BI", 8, 8) + struct.pack("<q", int(value))
        elif type_id == 10:
            return struct.pack("<BI", 10, 4) + struct.pack("<f", float(value))
        elif type_id == 11:
            return struct.pack("<BI", 11, 8) + struct.pack("<d", float(value))
        elif type_id == 12:
            s = str(value).encode()
            return struct.pack("<BI", 12, len(s)) + s
        else:
            s = str(value).encode()
            return struct.pack("<BI", type_id, len(s)) + s

    def _decode_val(self, type_id, data):
        if not data:
            return None
        if type_id == 1:
            return data[0] != 0
        elif type_id == 6:
            return struct.unpack("<i", data[:4])[0] if len(data) >= 4 else 0
        elif type_id == 8:
            return struct.unpack("<q", data[:8])[0] if len(data) >= 8 else 0
        elif type_id == 10:
            return struct.unpack("<f", data[:4])[0] if len(data) >= 4 else 0.0
        elif type_id == 11:
            return struct.unpack("<d", data[:8])[0] if len(data) >= 8 else 0.0
        elif type_id == 12:
            return data.decode(errors="replace")
        return data.decode(errors="replace")

    def _build_chunk(self, msg_type, body):
        msg_bytes = msg_type if isinstance(msg_type, bytes) else msg_type.encode()
        total_len = 8 + len(body)
        header = struct.pack(">IBBBB", total_len, 0,
                             msg_bytes[0], msg_bytes[1], msg_bytes[2])
        return header + body

    def _err(self, conn, reason):
        body = struct.pack(">I", 0x80000000) + reason.encode()[:32]
        try:
            conn.sendall(self._build_chunk(b"ERR", body))
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Background: A&C alarm toggling                                     #
    # ------------------------------------------------------------------ #
    def _start_alarm_thread(self):
        def loop():
            while not self._stop_event.wait(random.uniform(25, 50)):
                for nid in ["ns=1;s=HighTempAlarm", "ns=1;s=LowPressureAlarm"]:
                    nd = self.nodes.get(nid)
                    if nd and isinstance(nd.value, bool):
                        nd.value = not nd.value
        threading.Thread(target=loop, daemon=True).start()


if __name__ == "__main__":
    s = OpcUaVulnSimulator()
    s.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
