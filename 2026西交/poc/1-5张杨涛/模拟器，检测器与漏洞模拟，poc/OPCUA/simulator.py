"""
OPC UA Protocol Simulator — full TCP binary layer, secure channels,
Browse/Read/Write services, subscriptions, A&C simulation.
Self-contained; Python stdlib only.
"""
import socket
import threading
import struct
import logging
import time
import uuid
import random
import datetime
from collections import OrderedDict, defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("OPCUASim")

MSG_TYPES = {b"HEL": "Hello", b"ACK": "Acknowledge", b"ERR": "Error",
             b"OPN": "OpenSecureChannel", b"CLO": "CloseSecureChannel",
             b"MSG": "MessageChunk"}

SECURITY_POLICIES = {
    "None":     b"http://opcfoundation.org/UA/SecurityPolicy#None",
    "Basic128": b"http://opcfoundation.org/UA/SecurityPolicy#Basic128Rsa15",
    "Basic256": b"http://opcfoundation.org/UA/SecurityPolicy#Basic256",
}

NAMESPACE_ARRAY = [
    "http://opcfoundation.org/UA/",       # ns=0
    "urn:opcua:device:sensors",           # ns=1
    "urn:opcua:simulation:config",        # ns=2
]

BUILTIN_TYPES = {1: ("Boolean", 1), 2: ("SByte", 1), 3: ("Byte", 1),
                 4: ("Int16", 2), 5: ("UInt16", 2), 6: ("Int32", 4),
                 7: ("UInt32", 4), 8: ("Int64", 8), 9: ("UInt64", 8),
                 10: ("Float", 4), 11: ("Double", 8), 12: ("String", -1),
                 13: ("DateTime", 8), 14: ("Guid", 16), 15: ("ByteString", -1)}

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

NODECLASS_OBJECT   = 1
NODECLASS_VARIABLE = 2
NODECLASS_METHOD   = 3
NODECLASS_FOLDER   = 8

STATUS_GOOD              = 0x00000000
STATUS_BAD_NODEID_UNKNOWN = 0x80340000
STATUS_BAD_WRITE_NOT_SUPPORTED = 0x80730000
STATUS_BAD_SESSION_ID_INVALID  = 0x80250000
STATUS_BAD_TOO_MANY_SESSIONS   = 0x80290000
STATUS_BAD_NOT_WRITABLE        = 0x80730000
STATUS_BAD_SERVICE_UNSUPPORTED = 0x80020000

MAX_SESSIONS = 50
SESSION_TIMEOUT = 3600
MAX_BROWSE_REFS = 10

class OpcUaNode:
    __slots__ = ("node_id", "browse_name", "display_name", "node_class",
                 "value", "data_type", "data_type_id", "children",
                 "writable", "ns_idx")
    def __init__(self, node_id, browse_name, display_name, node_class="Variable",
                 value=None, data_type="Double", writable=True, ns_idx=0):
        self.node_id = node_id
        self.browse_name = browse_name
        self.display_name = display_name
        self.node_class = node_class
        self.value = value
        self.data_type = data_type
        self.data_type_id = self._resolve_type(data_type)
        self.children = []
        self.writable = writable
        self.ns_idx = ns_idx

    @staticmethod
    def _resolve_type(dt_name):
        for tid, (name, _) in BUILTIN_TYPES.items():
            if name == dt_name:
                return tid
        return 12

    def to_dict(self):
        return {"node_id": self.node_id, "browse_name": self.browse_name,
                "display_name": self.display_name, "node_class": self.node_class,
                "value": str(self.value), "data_type": self.data_type}


class BaseSim:
    """Minimal TCP server acceptor."""
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


class OpcUaSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=4840):
        super().__init__(host, port, "OPCUA")
        self._build_node_tree()
        self.sessions = {}
        self.subscriptions = {}
        self.channel_id_counter = 1
        self.token_id_counter = 1
        self.max_chunk_size = 65536
        self.max_msg_size = 0
        self._monitored_item_counter = 1
        self._publish_responses = defaultdict(list)
        self._cleanup_event = threading.Event()
        self._ts = time.time
        self._start_cleanup_thread()
        self._start_alarm_thread()
        log.info("OPC UA simulator initialized with %d nodes", len(self.nodes))

    # ------------------------------------------------------------------ #
    #  Node tree                                                          #
    # ------------------------------------------------------------------ #
    def _build_node_tree(self):
        def folder(oid, bname, dname):
            return OpcUaNode(oid, bname, dname, "Folder", writable=False)
        def obj(oid, bname, dname):
            return OpcUaNode(oid, bname, dname, "Object", writable=False)
        def var(oid, bname, dname, val, dt, w=True, ns=0):
            return OpcUaNode(oid, bname, dname, "Variable", val, dt, writable=w, ns_idx=ns)

        root = folder("i=84", "Root", "Root")
        objects = folder("i=85", "Objects", "Objects")
        types = folder("i=86", "Types", "Types")
        views = folder("i=87", "Views", "Views")

        server = obj("i=2253", "Server", "Server")
        server.children = [
            var("i=2256", "ServerStatus", "ServerStatus", "Running", "String", False),
            var("i=2257", "CurrentTime", "CurrentTime", 0.0, "Double", False),
            var("i=2268", "BuildInfo", "BuildInfo", "OPCUA-Sim v3.0", "String", False),
            var("i=2259", "State", "State", "Running", "String", False),
            obj("i=2269", "ServerCapabilities", "ServerCapabilities"),
            var("i=2274", "ServerDiagnostics", "ServerDiagnostics", "Enabled", "String", False),
            var("i=2275", "EnabledFlag", "EnabledFlag", True, "Boolean", False),
        ]

        device_set = obj("ns=1;s=DeviceSet", "DeviceSet", "DeviceSet")
        sensors = obj("ns=1;s=Sensors", "Sensors", "Sensors")
        sensors.children = [
            var("ns=1;s=Temperature", "Temperature", "Temperature Sensor", 25.0, "Double", True, 1),
            var("ns=1;s=Pressure", "Pressure", "Pressure Sensor", 100.0, "Double", True, 1),
            var("ns=1;s=FlowRate", "FlowRate", "Flow Rate", 50.0, "Double", True, 1),
            var("ns=1;s=Humidity", "Humidity", "Humidity Sensor", 45.0, "Double", True, 1),
            var("ns=1;s=Vibration", "Vibration", "Vibration Sensor", 0.5, "Float", True, 1),
        ]

        actuators = obj("ns=1;s=Actuators", "Actuators", "Actuators")
        actuators.children = [
            var("ns=1;s=ValveStatus", "ValveStatus", "Valve Status", True, "Boolean", True, 1),
            var("ns=1;s=MotorSpeed", "MotorSpeed", "Motor Speed (RPM)", 3000, "Int32", True, 1),
            var("ns=1;s=SetPoint", "SetPoint", "Set Point", 75.0, "Double", True, 1),
            var("ns=1;s=Mode", "Mode", "Operation Mode", 0, "Int32", True, 1),
        ]

        alarms = obj("ns=1;s=Alarms", "Alarms", "Alarms Group")
        alarms.children = [
            var("ns=1;s=HighTempAlarm", "HighTempAlarm", "High Temperature Alarm", False, "Boolean", True, 1),
            var("ns=1;s=LowPressureAlarm", "LowPressureAlarm", "Low Pressure Alarm", False, "Boolean", True, 1),
            var("ns=1;s=VibrationAlarm", "VibrationAlarm", "Vibration Alarm", False, "Boolean", True, 1),
            var("ns=1;s=EmergencyStop", "EmergencyStop", "Emergency Stop", False, "Boolean", True, 1),
        ]

        diagnostics = obj("ns=2;s=Diagnostics", "Diagnostics", "Diagnostics")
        diagnostics.children = [
            var("ns=2;s=ErrorCount", "ErrorCount", "Error Count", 0, "Int32", True, 2),
            var("ns=2;s=LastError", "LastError", "Last Error", "None", "String", True, 2),
            var("ns=2;s=Uptime", "Uptime", "Uptime (seconds)", 0, "Int64", True, 2),
        ]

        config = obj("ns=2;s=Config", "Config", "Configuration")
        config.children = [
            var("ns=2;s=DeviceName", "DeviceName", "Device Name", "SimulatedPLC-v2", "String", True, 2),
            var("ns=2;s=FirmwareVersion", "FirmwareVersion", "Firmware Version", "v2.5.1", "String", True, 2),
            var("ns=2;s=SerialNumber", "SerialNumber", "Serial Number", "SN-2026-001", "String", True, 2),
            var("ns=2;s=MaintenanceMode", "MaintenanceMode", "Maintenance Mode", False, "Boolean", True, 2),
        ]

        static = obj("ns=2;s=StaticData", "StaticData", "Static Data")
        static.children = [
            var("ns=2;s=VendorName", "VendorName", "Vendor Name", "SimCorp Industries", "String", False, 2),
            var("ns=2;s=Location", "Location", "Location", "Building A, Floor 3", "String", False, 2),
        ]

        device_set.children = [sensors, actuators, alarms, diagnostics, config, static]
        objects.children = [device_set, server]
        root.children = [objects, types, views]

        self.nodes = OrderedDict()
        for n in [root, objects, types, views, server, device_set, sensors,
                  actuators, alarms, diagnostics, config, static]:
            self._register_node(n)

    def _register_node(self, node):
        self.nodes[node.node_id] = node
        for c in node.children:
            self._register_node(c)

    # ------------------------------------------------------------------ #
    #  Client connection                                                  #
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
                    if msg_len < 8 or len(buf) < msg_len:
                        break
                    chunk = buf[:msg_len]
                    buf = buf[msg_len:]
                    self._handle_chunk(conn, chunk, addr)
        except Exception:
            pass
        finally:
            to_remove = [sid for sid, s in self.sessions.items()
                         if s.get("addr") == addr]
            for sid in to_remove:
                del self.sessions[sid]
                log.info("Session %s cleaned on disconnect", sid[:12])
            conn.close()

    # ------------------------------------------------------------------ #
    #  Chunk dispatcher                                                   #
    # ------------------------------------------------------------------ #
    def _handle_chunk(self, conn, chunk, addr):
        msg_type = chunk[5:8]
        msg_name = MSG_TYPES.get(msg_type, "Unknown(%s)" % msg_type.decode(errors="replace"))
        log.debug("OPC UA msg: %s (%d bytes)", msg_name, len(chunk))

        if msg_type == b"HEL":
            self._handle_hello(conn, chunk, addr)
        elif msg_type == b"OPN":
            self._handle_open(conn, chunk, addr)
        elif msg_type == b"CLO":
            self._handle_close(conn, chunk, addr)
        elif msg_type == b"MSG":
            self._handle_message(conn, chunk, addr)
        else:
            log.warning("Unknown message type from %s: %s", addr[0], msg_name)
            self._send_error(conn, chunk, "BadMessageType")

    # ------------------------------------------------------------------ #
    #  Hello / ACK                                                        #
    # ------------------------------------------------------------------ #
    def _handle_hello(self, conn, chunk, addr):
        if len(chunk) < 20:
            return
        recv_buf = struct.unpack(">I", chunk[8:12])[0]
        send_buf = struct.unpack(">I", chunk[12:16])[0]
        max_msg = struct.unpack(">I", chunk[16:20])[0]
        max_chunk = struct.unpack(">I", chunk[20:24])[0] if len(chunk) >= 24 else 0
        endpoint = ""
        if len(chunk) > 24:
            endpoint = chunk[24:].rstrip(b"\x00").decode(errors="replace")

        log.info("Hello: recv_buf=%d send_buf=%d endpoint='%s' from %s",
                 recv_buf, send_buf, endpoint, addr[0])
        self.max_chunk_size = min(recv_buf, 65536)
        self.max_msg_size = max_msg or 0

        body = struct.pack(">IIIII", self.protocol_version if hasattr(self, "protocol_version") else 0,
                           65536, 65536, self.max_msg_size or 0, 0)
        ack = self._build_chunk(b"ACK", body)
        conn.sendall(ack)
        log.debug("ACK sent to %s", addr[0])

    # ------------------------------------------------------------------ #
    #  Open / Close SecureChannel                                         #
    # ------------------------------------------------------------------ #
    def _handle_open(self, conn, chunk, addr):
        if len(chunk) < 24:
            return
        client_protocol = struct.unpack(">I", chunk[8:12])[0]
        sec_policy_raw = chunk[12:16]
        cert_len = struct.unpack(">I", chunk[16:20])[0]
        token_id = struct.unpack(">I", chunk[20:24])[0]

        if len(self.sessions) >= MAX_SESSIONS:
            log.warning("Max sessions (%d) reached, rejecting OPN from %s", MAX_SESSIONS, addr[0])
            body = struct.pack(">I", STATUS_BAD_TOO_MANY_SESSIONS)
            self._send_err_chunk(conn, chunk, body)
            return

        channel_id = self.channel_id_counter
        self.channel_id_counter += 1
        token = self.token_id_counter
        self.token_id_counter += 1
        session_id = "session_%d_%s" % (channel_id, uuid.uuid4().hex[:8])

        self.sessions[session_id] = {
            "addr": addr,
            "channel_id": channel_id,
            "token": token,
            "created": self._ts(),
            "last_activity": self._ts(),
            "client_protocol": client_protocol,
            "active": False,
            "session_id": session_id,
            "auth_token": uuid.uuid4().hex[:16],
        }

        log.info("OpenSecureChannel: channel=%d, session=%s, protocol=%d",
                 channel_id, session_id, client_protocol)

        nonce = uuid.uuid4().bytes + uuid.uuid4().bytes  # 32 bytes
        body = struct.pack(">II", channel_id, token) + nonce
        resp = self._build_chunk(b"OPN", body)
        conn.sendall(resp)

    def _handle_close(self, conn, chunk, addr):
        channel_id = struct.unpack(">I", chunk[8:12])[0] if len(chunk) >= 12 else 0
        to_delete = [sid for sid, s in self.sessions.items()
                     if s.get("channel_id") == channel_id]
        for sid in to_delete:
            del self.sessions[sid]
            log.info("CloseSecureChannel: channel=%d, session=%s", channel_id, sid)

        body = b"\x00" * 8
        resp = self._build_chunk(b"CLO", body)
        conn.sendall(resp)

    # ------------------------------------------------------------------ #
    #  MSG — service dispatcher                                           #
    # ------------------------------------------------------------------ #
    def _handle_message(self, conn, chunk, addr):
        if len(chunk) < 24:
            return
        channel_id = struct.unpack(">I", chunk[8:12])[0]
        token_id = struct.unpack(">I", chunk[12:16])[0]
        seq_num = struct.unpack(">I", chunk[16:20])[0]
        req_id = struct.unpack(">I", chunk[20:24])[0]

        log.debug("MSG: channel=%d token=%d seq=%d req=%d", channel_id, token_id, seq_num, req_id)

        body = chunk[24:]
        if len(body) < 6:
            log.warning("MSG body too short from %s", addr[0])
            return

        service_id = struct.unpack("<H", body[0:2])[0]
        request_handle = struct.unpack("<I", body[2:6])[0]

        log.info("Service call: %d (handle=%d) from %s", service_id, request_handle, addr[0])

        if service_id == SERVICE_GET_ENDPOINTS:
            resp_body = self._svc_get_endpoints(request_handle)
        elif service_id == SERVICE_CREATE_SESSION:
            resp_body = self._svc_create_session(body[6:], request_handle, addr)
        elif service_id == SERVICE_ACTIVATE_SESSION:
            resp_body = self._svc_activate_session(body[6:], request_handle, addr)
        elif service_id == SERVICE_BROWSE:
            resp_body = self._svc_browse(body[6:], request_handle, addr)
        elif service_id == SERVICE_BROWSE_NEXT:
            resp_body = self._svc_browse_next(body[6:], request_handle, addr)
        elif service_id == SERVICE_READ:
            resp_body = self._svc_read(body[6:], request_handle, addr)
        elif service_id == SERVICE_WRITE:
            resp_body = self._svc_write(body[6:], request_handle, addr)
        elif service_id == SERVICE_CREATE_SUBSCRIPTION:
            resp_body = self._svc_create_subscription(body[6:], request_handle, addr)
        elif service_id == SERVICE_CREATE_MON_ITEMS:
            resp_body = self._svc_create_mon_items(body[6:], request_handle, addr)
        elif service_id == SERVICE_PUBLISH:
            resp_body = self._svc_publish(body[6:], request_handle, addr)
        else:
            log.warning("Unknown service: %d", service_id)
            resp_body = struct.pack("<HI", service_id, request_handle) + \
                        struct.pack("<I", STATUS_BAD_SERVICE_UNSUPPORTED)

        full_body = struct.pack(">IIII", channel_id, token_id, seq_num + 1, req_id) + resp_body
        resp = self._build_chunk(b"MSG", full_body)
        conn.sendall(resp)

    # ------------------------------------------------------------------ #
    #  Service: GetEndpoints                                              #
    # ------------------------------------------------------------------ #
    def _svc_get_endpoints(self, request_handle):
        payload = struct.pack("<HII", SERVICE_GET_ENDPOINTS, request_handle, STATUS_GOOD)
        eps = [
            {"url": "opc.tcp://%s:%d/" % (self.host if self.host != "0.0.0.0" else "127.0.0.1", self.port),
             "policy": "None", "mode": 0, "level": 0},
            {"url": "opc.tcp://%s:%d/Basic128" % (self.host if self.host != "0.0.0.0" else "127.0.0.1", self.port),
             "policy": "Basic128", "mode": 1, "level": 1},
        ]
        payload += struct.pack("<H", len(eps))
        for ep in eps:
            eu = ep["url"].encode()
            pu = ep["policy"].encode()
            payload += struct.pack("<B", len(eu)) + eu
            payload += struct.pack("<B", len(pu)) + pu
            payload += struct.pack("<BB", ep["mode"], ep["level"])
        return payload

    # ------------------------------------------------------------------ #
    #  Service: CreateSession / ActivateSession                           #
    # ------------------------------------------------------------------ #
    def _svc_create_session(self, data, request_handle, addr):
        pos = 0
        sname = self._read_string_be(data, pos); pos += 1 + len(sname)
        aname = self._read_string_be(data, pos); pos += 1 + len(aname)
        req_timeout = struct.unpack("<I", data[pos:pos+4])[0] if pos+4 <= len(data) else 3600

        sid = "session_%s_%s" % (int(self._ts()), uuid.uuid4().hex[:8])
        auth = uuid.uuid4().hex[:16]
        actual_timeout = min(req_timeout, SESSION_TIMEOUT)

        self.sessions[sid] = {
            "addr": addr,
            "channel_id": 0,
            "token": self.token_id_counter,
            "created": self._ts(),
            "last_activity": self._ts(),
            "active": False,
            "session_id": sid,
            "auth_token": auth,
            "session_name": sname,
            "app_name": aname,
            "timeout": actual_timeout,
        }
        self.token_id_counter += 1
        log.info("CreateSession: id=%s name='%s' app='%s'", sid, sname, aname)

        payload = struct.pack("<HII", SERVICE_CREATE_SESSION, request_handle, STATUS_GOOD)
        payload += self._encode_node_id_str(sid)
        payload += self._encode_node_id_str(auth)
        payload += struct.pack("<I", actual_timeout)
        nonce = uuid.uuid4().bytes[:16]
        payload += struct.pack("<B", len(nonce)) + nonce
        return payload

    def _svc_activate_session(self, data, request_handle, addr):
        node_id = self._decode_node_id_all(data, 0)
        sid = node_id.get("id", "")
        if sid in self.sessions:
            self.sessions[sid]["active"] = True
            self.sessions[sid]["last_activity"] = self._ts()
            log.info("ActivateSession: %s activated", sid)
            return struct.pack("<HII", SERVICE_ACTIVATE_SESSION, request_handle, STATUS_GOOD)
        return struct.pack("<HII", SERVICE_ACTIVATE_SESSION, request_handle, STATUS_BAD_SESSION_ID_INVALID)

    # ------------------------------------------------------------------ #
    #  Service: Browse / BrowseNext                                       #
    # ------------------------------------------------------------------ #
    def _svc_browse(self, data, request_handle, addr):
        if len(data) < 11:
            return struct.pack("<HII", SERVICE_BROWSE, request_handle, STATUS_GOOD) + struct.pack("<H", 0)
        max_refs = struct.unpack("<I", data[0:4])[0]
        direction = struct.unpack("<I", data[4:8])[0]
        include_subtypes = data[8]
        node_count = struct.unpack("<H", data[9:11])[0]
        if max_refs == 0:
            max_refs = MAX_BROWSE_REFS

        results = []
        pos = 11
        for _ in range(node_count):
            if pos >= len(data):
                break
            result, pos = self._browse_single_node(data, pos, max_refs)
            results.append(result)

        payload = struct.pack("<HII", SERVICE_BROWSE, request_handle, STATUS_GOOD)
        payload += struct.pack("<H", len(results))
        for res in results:
            payload += res
        return payload

    def _browse_single_node(self, data, pos, max_refs):
        node_id_info, npos = self._decode_node_id(data, pos)
        nd = self.nodes.get(node_id_info.get("full_id", ""))
        if nd is None:
            body = struct.pack("<I", STATUS_BAD_NODEID_UNKNOWN)
            body += struct.pack("<B", 0)  # no continuation point
            body += struct.pack("<H", 0)  # zero references
            return body, npos

        children = nd.children
        total = len(children)
        if total <= max_refs:
            refs = children
            cp = b""
        else:
            refs = children[:max_refs]
            cp = ("cp|%s|%d" % (nd.node_id, max_refs)).encode()

        body = struct.pack("<I", STATUS_GOOD)
        body += struct.pack("<B", len(cp)) + cp
        body += struct.pack("<H", len(refs))
        for c in refs:
            nid_enc = self._encode_node_id_str(c.node_id)
            body += nid_enc
            bname = c.browse_name.encode()
            dname = c.display_name.encode()
            body += struct.pack("<B", len(bname)) + bname
            body += struct.pack("<B", len(dname)) + dname
            nc = NODECLASS_FOLDER if c.node_class == "Folder" else \
                 NODECLASS_OBJECT if c.node_class == "Object" else \
                 NODECLASS_VARIABLE
            body += struct.pack("<B", nc)
        return body, npos

    def _svc_browse_next(self, data, request_handle, addr):
        if len(data) < 2:
            return struct.pack("<HII", SERVICE_BROWSE_NEXT, request_handle, STATUS_GOOD) + struct.pack("<H", 0)
        release = data[0]
        cp_count = data[1]
        results = []
        pos = 2
        for _ in range(cp_count):
            if pos >= len(data):
                break
            cp_len = data[pos]; pos += 1
            cp = data[pos:pos+cp_len]; pos += cp_len
            cp_str = cp.decode(errors="replace")
            if cp_str.startswith("cp|"):
                parts = cp_str.split("|")
                if len(parts) >= 3:
                    node_id = parts[1]
                    offset = int(parts[2])
                    nd = self.nodes.get(node_id)
                    if nd:
                        remaining = nd.children[offset:]
                        refs = remaining[:MAX_BROWSE_REFS]
                        new_cp = ""
                        if len(remaining) > MAX_BROWSE_REFS:
                            new_cp = ("cp|%s|%d" % (node_id, offset + MAX_BROWSE_REFS)).encode()
                        body = struct.pack("<I", STATUS_GOOD)
                        body += struct.pack("<B", len(new_cp)) + new_cp
                        body += struct.pack("<H", len(refs))
                        for c in refs:
                            body += self._encode_node_id_str(c.node_id)
                            bname = c.browse_name.encode()
                            dname = c.display_name.encode()
                            body += struct.pack("<B", len(bname)) + bname
                            body += struct.pack("<B", len(dname)) + dname
                            body += struct.pack("<B", NODECLASS_VARIABLE)
                        results.append(body)
                        continue
            results.append(struct.pack("<I", STATUS_GOOD) +
                           struct.pack("<B", 0) + struct.pack("<H", 0))

        payload = struct.pack("<HII", SERVICE_BROWSE_NEXT, request_handle, STATUS_GOOD)
        payload += struct.pack("<H", len(results))
        for r in results:
            payload += r
        return payload

    # ------------------------------------------------------------------ #
    #  Service: Read                                                      #
    # ------------------------------------------------------------------ #
    def _svc_read(self, data, request_handle, addr):
        if len(data) < 14:
            return struct.pack("<HII", SERVICE_READ, request_handle, STATUS_GOOD) + struct.pack("<H", 0)
        max_age = struct.unpack("<d", data[0:8])[0]
        attr_id = struct.unpack("<I", data[8:12])[0]
        node_count = struct.unpack("<H", data[12:14])[0]

        results = []
        pos = 14
        for _ in range(node_count):
            if pos >= len(data):
                break
            node_id_info, pos = self._decode_node_id(data, pos)
            nd = self.nodes.get(node_id_info.get("full_id", ""))
            if nd:
                status = STATUS_GOOD
                val_enc = self._encode_value(nd.value, nd.data_type_id)
                ts = struct.pack("<d", self._ts())
                results.append(struct.pack("<I", status) + val_enc + ts)
                log.info("Read: %s = %s", nd.browse_name, str(nd.value)[:50])
            else:
                results.append(struct.pack("<I", STATUS_BAD_NODEID_UNKNOWN) +
                               struct.pack("<BB", 0, 0) + struct.pack("<d", 0.0))

        payload = struct.pack("<HII", SERVICE_READ, request_handle, STATUS_GOOD)
        payload += struct.pack("<H", len(results))
        for r in results:
            payload += r
        return payload

    # ------------------------------------------------------------------ #
    #  Service: Write                                                     #
    # ------------------------------------------------------------------ #
    def _svc_write(self, data, request_handle, addr):
        if len(data) < 2:
            return struct.pack("<HII", SERVICE_WRITE, request_handle, STATUS_GOOD) + struct.pack("<H", 0)
        node_count = struct.unpack("<H", data[0:2])[0]
        results = []
        pos = 2
        for _ in range(node_count):
            if pos + 4 >= len(data):
                break
            node_id_info, pos = self._decode_node_id(data, pos)
            val_type = data[pos] if pos < len(data) else 0
            pos += 1
            val_len = struct.unpack("<I", data[pos:pos+4])[0] if pos+4 <= len(data) else 0
            pos += 4
            val_bytes = data[pos:pos+val_len] if pos+val_len <= len(data) else b""
            pos += val_len

            nd = self.nodes.get(node_id_info.get("full_id", ""))
            if nd is None:
                results.append(struct.pack("<I", STATUS_BAD_NODEID_UNKNOWN))
                continue
            if not nd.writable:
                results.append(struct.pack("<I", STATUS_BAD_NOT_WRITABLE))
                log.warning("Write denied (read-only): %s by %s", nd.browse_name, addr[0])
                continue

            nd.value = self._decode_value(val_type, val_bytes)
            nd.last_write_time = self._ts()
            nd.last_write_addr = addr[0]
            results.append(struct.pack("<I", STATUS_GOOD))
            log.info("Write: %s = %s by %s", nd.browse_name, str(nd.value)[:50], addr[0])

        payload = struct.pack("<HII", SERVICE_WRITE, request_handle, STATUS_GOOD)
        payload += struct.pack("<H", len(results))
        for r in results:
            payload += r
        return payload

    # ------------------------------------------------------------------ #
    #  Service: Subscription / MonitoredItems / Publish                   #
    # ------------------------------------------------------------------ #
    def _svc_create_subscription(self, data, request_handle, addr):
        if len(data) < 25:
            return struct.pack("<HII", SERVICE_CREATE_SUBSCRIPTION, request_handle, STATUS_GOOD) + \
                   struct.pack("<I", 0) + struct.pack("<d", 0.5) + struct.pack("<II", 10, 3)
        pub_interval = struct.unpack("<d", data[0:8])[0]
        lifetime = struct.unpack("<I", data[8:12])[0]
        max_keep = struct.unpack("<I", data[12:16])[0]
        max_notif = struct.unpack("<I", data[16:20])[0]
        priority = data[20] if len(data) > 20 else 0

        sub_id = int(self._ts() * 1000) % 0x7FFFFFFF
        self.subscriptions[sub_id] = {
            "pub_interval": pub_interval,
            "lifetime": lifetime,
            "max_keep_alive": max_keep,
            "max_notif": max_notif,
            "priority": priority,
            "monitored_items": {},
            "created": self._ts(),
            "addr": addr,
            "seq": 1,
        }
        log.info("CreateSubscription: id=%d interval=%.3f", sub_id, pub_interval)

        payload = struct.pack("<HII", SERVICE_CREATE_SUBSCRIPTION, request_handle, STATUS_GOOD)
        payload += struct.pack("<I", sub_id)
        payload += struct.pack("<d", pub_interval)
        payload += struct.pack("<II", lifetime, max_keep)
        return payload

    def _svc_create_mon_items(self, data, request_handle, addr):
        if len(data) < 10:
            return struct.pack("<HII", SERVICE_CREATE_MON_ITEMS, request_handle, STATUS_GOOD) + \
                   struct.pack("<H", 0)
        sub_id = struct.unpack("<I", data[0:4])[0]
        timestamps = struct.unpack("<I", data[4:8])[0]
        item_count = struct.unpack("<H", data[8:10])[0]

        results = []
        pos = 10
        for _ in range(item_count):
            if pos >= len(data):
                break
            node_id_info, pos = self._decode_node_id(data, pos)
            if pos + 17 > len(data):
                break
            sampling = struct.unpack("<d", data[pos:pos+8])[0]
            pos += 8
            queue_size = struct.unpack("<I", data[pos:pos+4])[0]
            pos += 4
            discard = data[pos]
            pos += 1

            mon_id = self._monitored_item_counter
            self._monitored_item_counter += 1
            results.append(struct.pack("<II", STATUS_GOOD, mon_id) +
                           struct.pack("<d", sampling) +
                           struct.pack("<I", queue_size))

            if sub_id in self.subscriptions:
                self.subscriptions[sub_id]["monitored_items"][mon_id] = {
                    "node_id": node_id_info.get("full_id", ""),
                    "mon_id": mon_id,
                    "sampling": sampling,
                    "queue": queue_size,
                }
                log.info("MonitoredItem: sub=%d mon=%d node=%s", sub_id, mon_id,
                         node_id_info.get("full_id", "?"))

        payload = struct.pack("<HII", SERVICE_CREATE_MON_ITEMS, request_handle, STATUS_GOOD)
        payload += struct.pack("<H", len(results))
        for r in results:
            payload += r
        return payload

    def _svc_publish(self, data, request_handle, addr):
        ack_count = struct.unpack("<H", data[0:2])[0] if len(data) >= 2 else 0
        payload = struct.pack("<HII", SERVICE_PUBLISH, request_handle, STATUS_GOOD)

        active_sub = None
        for sid, sub in self.subscriptions.items():
            if sub.get("addr") == addr and sub.get("monitored_items"):
                active_sub = (sid, sub)
                break

        if active_sub is None:
            payload += struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<BB", 0, 0)
            return payload

        sid, sub = active_sub
        seq = sub["seq"]
        sub["seq"] += 1
        notifications = []
        for mon_id, mi in sub["monitored_items"].items():
            nd = self.nodes.get(mi["node_id"])
            if nd:
                val_enc = self._encode_value(nd.value, nd.data_type_id)
                notifications.append(struct.pack("<II", mon_id, mon_id) + val_enc)

        payload += struct.pack("<II", sid, seq)
        payload += struct.pack("<BB", 0 if len(notifications) == 0 else 0, len(notifications) & 0xFF)
        for n in notifications:
            payload += n
        return payload

    # ------------------------------------------------------------------ #
    #  NodeId encoding / decoding helpers                                 #
    # ------------------------------------------------------------------ #
    def _encode_node_id_str(self, full_id):
        """Encode 'ns=1;s=XXX' or 'i=2253' into binary.
           Encoding byte: 0=numeric-ns0, 1=numeric+ns, 2=string+ns."""
        if full_id.startswith("ns="):
            parts = full_id.split(";", 1)
            ns = int(parts[0][3:])
            rest = parts[1]
            if rest.startswith("s="):
                s = rest[2:].encode()
                return struct.pack("<BH", 2, ns) + struct.pack("<B", len(s)) + s
            elif rest.startswith("i="):
                val = int(rest[2:])
                return struct.pack("<BHH", 1, ns, val)
            elif rest.startswith("b="):
                b = bytes.fromhex(rest[2:])
                return struct.pack("<BH", 4, ns) + struct.pack("<B", len(b)) + b
        elif full_id.startswith("i="):
            val = int(full_id[2:])
            return struct.pack("<BH", 0, val)
        return struct.pack("<BH", 0, 0)

    def _decode_node_id(self, data, pos):
        """Parse encoded node id starting at pos.  Returns (dict, new_pos)."""
        if pos >= len(data):
            return {"full_id": ""}, pos
        enc = data[pos]
        pos += 1
        ns = 0
        val = 0
        sval = ""
        full_id = ""

        if enc == 0:
            if pos + 2 > len(data):
                return {"full_id": ""}, pos
            val = struct.unpack("<H", data[pos:pos+2])[0]
            pos += 2
            full_id = "i=%d" % val
        elif enc == 1:
            if pos + 4 > len(data):
                return {"full_id": ""}, pos
            ns, val = struct.unpack("<HH", data[pos:pos+4])
            pos += 4
            full_id = "ns=%d;i=%d" % (ns, val)
        elif enc == 2:
            if pos + 3 > len(data):
                return {"full_id": ""}, pos
            ns = struct.unpack("<H", data[pos:pos+2])[0]
            pos += 2
            slen = data[pos]; pos += 1
            if pos + slen > len(data):
                return {"full_id": ""}, pos
            sval = data[pos:pos+slen].decode(errors="replace")
            pos += slen
            full_id = "ns=%d;s=%s" % (ns, sval)
        elif enc == 3:
            if pos + 18 > len(data):
                return {"full_id": ""}, pos
            ns = struct.unpack("<H", data[pos:pos+2])[0]
            pos += 2
            guid = uuid.UUID(bytes_le=data[pos:pos+16])
            pos += 16
            full_id = "ns=%d;g=%s" % (ns, str(guid))
        elif enc == 4:
            if pos + 3 > len(data):
                return {"full_id": ""}, pos
            ns = struct.unpack("<H", data[pos:pos+2])[0]
            pos += 2
            blen = data[pos]; pos += 1
            if pos + blen > len(data):
                return {"full_id": ""}, pos
            bdata = data[pos:pos+blen].hex()
            pos += blen
            full_id = "ns=%d;b=%s" % (ns, bdata)

        return {"full_id": full_id, "ns": ns, "id": val, "string_id": sval}, pos

    def _decode_node_id_all(self, data, pos):
        return self._decode_node_id(data, pos)[0]

    def _encode_value(self, value, type_id):
        """Encode a Python value into [type_id:1][value_len:4][value:N]."""
        if value is None:
            return struct.pack("<BI", type_id, 0)
        if type_id == 1:   # Boolean
            b = b"\x01" if value else b"\x00"
            return struct.pack("<BI", type_id, 1) + b
        elif type_id in (2, 3):  # SByte, Byte
            return struct.pack("<BI", type_id, 1) + struct.pack("<b", int(value))
        elif type_id in (4, 5):  # Int16, UInt16
            return struct.pack("<BI", type_id, 2) + struct.pack("<h", int(value))
        elif type_id in (6, 7):  # Int32, UInt32
            return struct.pack("<BI", type_id, 4) + struct.pack("<i", int(value))
        elif type_id in (8, 9):  # Int64, UInt64
            return struct.pack("<BI", type_id, 8) + struct.pack("<q", int(value))
        elif type_id == 10:  # Float
            return struct.pack("<BI", type_id, 4) + struct.pack("<f", float(value))
        elif type_id == 11:  # Double
            return struct.pack("<BI", type_id, 8) + struct.pack("<d", float(value))
        elif type_id == 12:  # String
            s = str(value).encode()
            return struct.pack("<BI", type_id, len(s)) + s
        elif type_id == 13:  # DateTime
            return struct.pack("<BI", type_id, 8) + struct.pack("<d", float(value))
        elif type_id == 14:  # Guid
            g = uuid.UUID(str(value)).bytes_le if isinstance(value, str) else b"\x00" * 16
            return struct.pack("<BI", type_id, 16) + g
        elif type_id == 15:  # ByteString
            b = value if isinstance(value, bytes) else str(value).encode()
            return struct.pack("<BI", type_id, len(b)) + b
        else:
            s = str(value).encode()
            return struct.pack("<BI", type_id, len(s)) + s

    def _decode_value(self, type_id, data):
        """Decode binary value of given type_id."""
        if not data:
            return None
        if type_id == 1:
            return data[0] != 0
        elif type_id == 2:
            return struct.unpack("<b", data[:1])[0]
        elif type_id == 3:
            return data[0]
        elif type_id == 4:
            return struct.unpack("<h", data[:2])[0] if len(data) >= 2 else 0
        elif type_id == 5:
            return struct.unpack("<H", data[:2])[0] if len(data) >= 2 else 0
        elif type_id == 6:
            return struct.unpack("<i", data[:4])[0] if len(data) >= 4 else 0
        elif type_id == 7:
            return struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0
        elif type_id == 8:
            return struct.unpack("<q", data[:8])[0] if len(data) >= 8 else 0
        elif type_id == 9:
            return struct.unpack("<Q", data[:8])[0] if len(data) >= 8 else 0
        elif type_id == 10:
            return struct.unpack("<f", data[:4])[0] if len(data) >= 4 else 0.0
        elif type_id == 11:
            return struct.unpack("<d", data[:8])[0] if len(data) >= 8 else 0.0
        elif type_id == 12:
            return data.decode(errors="replace")
        elif type_id == 13:
            return struct.unpack("<d", data[:8])[0] if len(data) >= 8 else 0.0
        elif type_id == 14:
            return str(uuid.UUID(bytes_le=data[:16]))
        elif type_id == 15:
            return data
        return data.decode(errors="replace")

    # ------------------------------------------------------------------ #
    #  Chunk framing utilities                                            #
    # ------------------------------------------------------------------ #
    def _build_chunk(self, msg_type, body):
        msg_type_bytes = msg_type if isinstance(msg_type, bytes) else msg_type.encode()
        if len(msg_type_bytes) != 3:
            msg_type_bytes = msg_type_bytes[:3].ljust(3, b" ")
        total_len = 8 + len(body)
        header = struct.pack(">IBBBB", total_len, 0,
                             msg_type_bytes[0], msg_type_bytes[1], msg_type_bytes[2])
        return header + body

    def _send_error(self, conn, chunk, reason):
        body = struct.pack(">I", 0x80000000) + reason.encode()[:32]
        err = self._build_chunk(b"ERR", body)
        try:
            conn.sendall(err)
        except Exception:
            pass
        log.warning("Sent Error: %s", reason)

    def _send_err_chunk(self, conn, chunk, body):
        err = self._build_chunk(b"ERR", body)
        try:
            conn.sendall(err)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Background threads                                                 #
    # ------------------------------------------------------------------ #
    def _start_cleanup_thread(self):
        def cleanup():
            while not self._cleanup_event.wait(60):
                now = self._ts()
                expired = [sid for sid, s in self.sessions.items()
                           if now - s.get("last_activity", s.get("created", 0)) > SESSION_TIMEOUT]
                for sid in expired:
                    del self.sessions[sid]
                expired_subs = [sid for sid, s in self.subscriptions.items()
                                if now - s.get("created", 0) > SESSION_TIMEOUT * 2]
                for sid in expired_subs:
                    del self.subscriptions[sid]
                if expired:
                    log.info("Session cleanup: removed %d expired sessions", len(expired))
        t = threading.Thread(target=cleanup, daemon=True)
        t.start()

    def _start_alarm_thread(self):
        def alarm_loop():
            alarm_nodes = [
                "ns=1;s=HighTempAlarm", "ns=1;s=LowPressureAlarm",
                "ns=1;s=VibrationAlarm", "ns=1;s=EmergencyStop",
            ]
            while not self._cleanup_event.wait(random.uniform(20, 45)):
                node_id = random.choice(alarm_nodes)
                nd = self.nodes.get(node_id)
                if nd and isinstance(nd.value, bool):
                    nd.value = not nd.value
                    log.info("A&C: %s toggled → %s", nd.browse_name, nd.value)
                temp = self.nodes.get("ns=1;s=Temperature")
                if temp and isinstance(temp.value, (int, float)):
                    temp.value = round(temp.value + random.uniform(-2.0, 2.0), 1)
                pres = self.nodes.get("ns=1;s=Pressure")
                if pres and isinstance(pres.value, (int, float)):
                    pres.value = round(pres.value + random.uniform(-5.0, 5.0), 1)
        t = threading.Thread(target=alarm_loop, daemon=True)
        t.start()

    # ------------------------------------------------------------------ #
    #  Helpers                                                            #
    # ------------------------------------------------------------------ #
    @staticmethod
    def _read_string_be(data, pos):
        if pos >= len(data):
            return ""
        slen = data[pos]
        if pos + 1 + slen > len(data):
            return ""
        return data[pos+1:pos+1+slen].decode(errors="replace")

    @property
    def protocol_version(self):
        return 0


if __name__ == "__main__":
    s = OpcUaSimulator()
    s.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
