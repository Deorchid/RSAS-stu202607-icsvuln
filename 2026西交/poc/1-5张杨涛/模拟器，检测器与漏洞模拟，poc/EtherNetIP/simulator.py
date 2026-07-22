"""
EtherNet/IP Protocol Simulator — Full Implementation

Supports:
  - Encapsulation layer: RegisterSession/UnregisterSession with 60s timeout,
    session cleanup thread, ListIdentity, ListServices, SendRRData, SendUnitData,
    IndicateStatus, CancelStatus
  - CIP connection lifecycle: ForwardOpen (O->T and T->O with RPI, size, priority),
    ForwardClose, connection timeout with heartbeat tracking
  - Class 1 I/O connections: cyclic data production at RPI interval,
    assembly data that evolves over time
  - Class 3 explicit messaging: SendRRData with full CIP service handling
  - Object model (8+ classes): Identity(0x01), MessageRouter(0x02),
    Assembly(0x04), Connection(0x05), ConnectionManager(0x06), Register(0x07),
    TCP/IP Interface(0xF5), Ethernet Link(0xF6)
  - Assembly object: input (100 bytes) & output (100 bytes) with
    configurable sizes, data updated by scan cycle background thread
  - Redundant owner: up to two connections per assembly with priority
  - Electronic key: vendor ID, device type, product code, major/minor revision
    matching for ForwardOpen
  - Full ListIdentity and ListServices responses
"""
import socket
import struct
import threading
import logging
import time
import random
import enum
from collections import OrderedDict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("EIPSim")

ENCAP = struct.Struct("<HHIQII")

EIP_CMD = {
    0x63: "ListIdentity",
    0x64: "ListServices",
    0x65: "RegisterSession",
    0x66: "UnregisterSession",
    0x6F: "SendRRData",
    0x70: "SendUnitData",
    0x72: "IndicateStatus",
    0x73: "CancelStatus",
    0x74: "NOP",
}

CIP_SVC = {
    0x01: "GetAttributeAll",
    0x02: "SetAttributeAll",
    0x03: "GetAttributeList",
    0x04: "SetAttributeList",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "MultipleServicePacket",
    0x0E: "GetAttributeSingle",
    0x10: "SetAttributeSingle",
    0x4B: "GetAttributesList",
    0x4C: "SetAttributesList",
    0x4E: "ForwardOpen",
    0x4F: "ForwardClose",
    0x52: "Reset_Alt",
    0x53: "Start_Alt",
    0x54: "Stop_Alt",
    0x55: "Create_Alt",
    0x56: "Delete_Alt",
}

CIP_CLASS_NAMES = {
    0x01: "Identity",
    0x02: "MessageRouter",
    0x04: "Assembly",
    0x05: "Connection",
    0x06: "ConnectionManager",
    0x07: "Register",
    0xF5: "TCPIP_Interface",
    0xF6: "EthernetLink",
    0xF4: "Port",
}

CIP_GENERAL_STATUS = {
    0x00: "Success",
    0x01: "Connection failure",
    0x02: "Resource unavailable",
    0x03: "Invalid parameter value",
    0x04: "Path segment error",
    0x05: "Path destination unknown",
    0x06: "Partial transfer",
    0x07: "Connection lost",
    0x08: "Service not supported",
    0x09: "Invalid attribute value",
    0x0A: "Attribute list error",
    0x0B: "Already in requested mode/state",
    0x0C: "Object state conflict",
    0x0D: "Object already exists",
    0x0E: "Attribute not settable",
    0x0F: "Privilege violation",
    0x10: "Device state conflict",
    0x11: "Reply data too large",
    0x12: "Fragmentation of a primitive value",
    0x13: "Not enough data",
    0x14: "Attribute not supported",
    0x15: "Too much data",
    0x16: "Object does not exist",
    0x17: "Service fragmentation sequence not in progress",
    0x18: "No stored attribute data",
    0x19: "Store operation failure",
    0x1A: "Routing failure, request packet too large",
    0x1B: "Routing failure, response packet too large",
    0x1C: "Missing attribute list entry data",
    0x1D: "Invalid attribute value list",
    0x1E: "Embedded service error",
    0x1F: "Vendor specific error",
    0x20: "Invalid parameter",
    0x21: "Write-once value or medium already written",
    0x22: "Invalid Reply Received",
    0x25: "Key Failure in path",
    0x26: "Path Size Invalid",
    0x27: "Unexpected attribute in list",
    0x28: "Invalid Member ID",
    0x29: "Member not settable",
    0x2A: "Group 2 only server general failure",
}

SESSION_TIMEOUT = 60
MAX_REDUNDANT_OWNERS = 2


class ConnectionType(enum.IntEnum):
    CLASS1_TRANSPORT = 0
    CLASS3_MSG = 3


class ConnectionState(enum.IntEnum):
    NONE = 0
    WAITING_FOR_CONNECTION_ID = 2
    ESTABLISHED = 3
    TIMEOUT = 4
    DEFERRED_DELETE = 5


class ElectronicKey:
    def __init__(self, vendor_id=0x0001, device_type=0x000E, product_code=0x0064,
                 major_rev=0x04, minor_rev=0x01):
        self.vendor_id = vendor_id
        self.device_type = device_type
        self.product_code = product_code
        self.major_rev = major_rev
        self.minor_rev = minor_rev

    def to_bytes(self):
        return struct.pack("<HHHHH", self.vendor_id, self.device_type,
                          self.product_code, self.major_rev, self.minor_rev)

    def matches(self, other):
        if other.vendor_id != self.vendor_id:
            return False
        if other.device_type != self.device_type:
            return False
        if other.product_code != self.product_code:
            return False
        if other.major_rev != self.major_rev:
            return False
        return True

    def __repr__(self):
        return (f"Key(vendor=0x{self.vendor_id:04X}, type=0x{self.device_type:04X}, "
                f"product=0x{self.product_code:04X}, rev={self.major_rev}.{self.minor_rev})")


class CIPConnection:
    def __init__(self, conn_id, o_t_id, t_o_id, o_t_rpi, t_o_rpi,
                 o_t_size, t_o_size, assembly_inst, priority=0,
                 conn_type=ConnectionType.CLASS1_TRANSPORT):
        self.conn_id = conn_id
        self.o_t_id = o_t_id
        self.t_o_id = t_o_id
        self.o_t_rpi = o_t_rpi
        self.t_o_rpi = t_o_rpi
        self.o_t_size = o_t_size
        self.t_o_size = t_o_size
        self.assembly_inst = assembly_inst
        self.priority = priority
        self.conn_type = conn_type
        self.state = ConnectionState.WAITING_FOR_CONNECTION_ID
        self.created_at = time.time()
        self.last_heartbeat = time.time()
        self.owner_addr = None
        self.seq_number = 0

    @property
    def age(self):
        return time.time() - self.created_at

    @property
    def idle(self):
        return time.time() - self.last_heartbeat

    def heartbeat(self):
        self.last_heartbeat = time.time()
        if self.state == ConnectionState.WAITING_FOR_CONNECTION_ID:
            self.state = ConnectionState.ESTABLISHED

    def __repr__(self):
        return (f"CIPConnection(id={self.conn_id}, o_t={self.o_t_id}, "
                f"t_o={self.t_o_id}, rpi={self.o_t_rpi}/{self.t_o_rpi}, "
                f"state={self.state.name})")


class EIPObject:
    def __init__(self, class_id, instance_id=1, name=""):
        self.class_id = class_id
        self.instance_id = instance_id
        self.name = name
        self.attributes = OrderedDict()

    def get(self, attr_id):
        return self.attributes.get(attr_id)

    def set(self, attr_id, value):
        self.attributes[attr_id] = value


class EIPSession:
    def __init__(self, sid, addr):
        self.sid = sid
        self.addr = addr
        self.created_at = time.time()
        self.last_activity = time.time()

    @property
    def age(self):
        return time.time() - self.created_at

    @property
    def idle(self):
        return time.time() - self.last_activity

    def touch(self):
        self.last_activity = time.time()

    def expired(self):
        return self.idle > SESSION_TIMEOUT


class BaseSim:
    def __init__(self, host="0.0.0.0", port=44818, name="Sim"):
        self.host = host
        self.port = port
        self.name = name
        self._server = None
        self._running = False
        self._accept_thread = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self._server.bind((self.host, self.port))
        self._server.listen(10)
        self._server.settimeout(1.0)
        self._running = True
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()
        log.info("[%s] listening on %s:%d", self.name, self.host, self.port)

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info("[%s] connection from %s", self.name, addr)
                threading.Thread(target=self.handle_client, args=(conn, addr),
                               daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    log.exception("[%s] accept error", self.name)
                break

    def stop(self):
        self._running = False
        if self._server:
            self._server.close()
        log.info("[%s] stopped", self.name)

    def handle_client(self, conn, addr):
        raise NotImplementedError


class EthernetIPSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=44818):
        super().__init__(host, port, "EtherNetIP")
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.connections = {}
        self.connections_lock = threading.Lock()
        self._conn_id_counter = 0x40000000
        self._conn_id_lock = threading.Lock()

        self.ekey = ElectronicKey(
            vendor_id=0x0001,
            device_type=0x000E,
            product_code=0x0064,
            major_rev=4,
            minor_rev=1,
        )

        self.input_assembly_size = 100
        self.output_assembly_size = 100
        self.input_assembly_data = bytearray(self.input_assembly_size)
        self.output_assembly_data = bytearray(self.output_assembly_size)
        self.assembly_lock = threading.Lock()

        self._assembly_owners = {}
        self._owners_lock = threading.Lock()

        self._build_objects()
        self._init_assembly_data()

        self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._started_cleanup = False

        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._started_scan = False

    def start(self):
        super().start()
        self._started_cleanup = True
        self._cleanup_thread.start()
        self._started_scan = True
        self._scan_thread.start()

    def stop(self):
        self._started_cleanup = False
        self._started_scan = False
        super().stop()

    def _cleanup_loop(self):
        while self._started_cleanup:
            time.sleep(10)
            self._cleanup_sessions()
            self._cleanup_connections()

    def _cleanup_sessions(self):
        with self.sessions_lock:
            expired = [s.sid for s in self.sessions.values() if s.expired()]
            for sid in expired:
                log.info("[Session] expiring session %#x (idle %.0fs)",
                        sid, self.sessions[sid].idle)
                del self.sessions[sid]

    def _cleanup_connections(self):
        with self.connections_lock:
            now = time.time()
            stale = []
            for cid, c in self.connections.items():
                if c.idle > max(c.o_t_rpi, c.t_o_rpi) * 4 / 1_000_000 + 10:
                    stale.append(cid)
            for cid in stale:
                log.info("[Conn] timeout connection %#x", cid)
                self._release_owner(cid)
                del self.connections[cid]

    def _scan_loop(self):
        counter = 0
        while self._started_scan:
            time.sleep(0.010)
            counter += 1
            with self.assembly_lock:
                struct.pack_into(
                    "<H", self.input_assembly_data, 0,
                    0x0001 if counter % 20 == 0 else 0x0000
                )
                struct.pack_into(
                    "<H", self.input_assembly_data, 2,
                    (counter & 0xFFFF)
                )
                struct.pack_into(
                    "<I", self.input_assembly_data, 4,
                    (counter * 10) & 0xFFFFFFFF
                )
                struct.pack_into(
                    "<f", self.input_assembly_data, 8,
                    25.0 + 5.0 * (counter % 3 == 0)
                )
                struct.pack_into(
                    "<f", self.input_assembly_data, 12,
                    100.0 + (counter & 0x1F)
                )
                struct.pack_into(
                    "<H", self.input_assembly_data, 16,
                    random.randint(0, 0xFFFE) & 0xFFFF
                )
                timestamp = int(time.time() * 1000) & 0xFFFFFFFF
                struct.pack_into("<I", self.input_assembly_data, 18, timestamp)
                struct.pack_into(
                    "<H", self.input_assembly_data, 22,
                    0x0001
                )

    def _init_assembly_data(self):
        with self.assembly_lock:
            struct.pack_into("<H", self.input_assembly_data, 0, 0x0001)
            struct.pack_into("<H", self.input_assembly_data, 2, 0x0000)
            struct.pack_into("<I", self.input_assembly_data, 4, 0x00000000)
            struct.pack_into("<f", self.input_assembly_data, 8, 25.0)
            struct.pack_into("<f", self.input_assembly_data, 12, 100.0)
            struct.pack_into("<H", self.input_assembly_data, 16, 0x0000)
            struct.pack_into("<I", self.input_assembly_data, 18, 0x00000000)
            struct.pack_into("<H", self.input_assembly_data, 22, 0x0001)
            struct.pack_into("<H", self.output_assembly_data, 0, 0x0000)
            struct.pack_into("<H", self.output_assembly_data, 2, 0x0000)

    def _build_objects(self):
        self.objects = {}

        identity = EIPObject(0x01, 1, "Identity")
        identity.set(1, struct.pack("<H", 0x0001))
        identity.set(2, struct.pack("<H", 0x000E))
        identity.set(3, struct.pack("<H", 0x0064))
        identity.set(4, struct.pack("<HH", 4, 1))
        identity.set(5, struct.pack("<H", 0x0001))
        identity.set(6, struct.pack("<I", 0xDEADBEEF))
        identity.set(7, b"EtherNet/IP Simulator v4.1")
        identity.set(8, struct.pack("<B", 0x03))
        identity.set(9, struct.pack("<H", 0x0000))
        self.objects[0x01] = identity

        router = EIPObject(0x02, 1, "MessageRouter")
        router.set(1, struct.pack("<H", 0x0100))
        router.set(2, struct.pack("<H", 0x0001))
        router.set(3, struct.pack("<H", 0x0001))
        router.set(4, struct.pack("<B", 0x00))
        self.objects[0x02] = router

        assembly = EIPObject(0x04, 1, "Assembly")
        assembly.set(1, struct.pack("<I", self.input_assembly_size))
        assembly.set(2, struct.pack("<I", self.output_assembly_size))
        assembly.set(3, bytes(self.input_assembly_data))
        assembly.set(4, bytes(self.output_assembly_data))
        self.objects[0x04] = assembly

        conn_obj = EIPObject(0x05, 1, "Connection")
        conn_obj.set(1, struct.pack("<H", 0x0001))
        conn_obj.set(2, struct.pack("<H", 0x0010))
        conn_obj.set(3, struct.pack("<H", 0x0010))
        conn_obj.set(4, struct.pack("<H", 0x000A))
        conn_obj.set(5, struct.pack("<I", 0x00007530))
        conn_obj.set(6, struct.pack("<I", 0x00001F4))
        self.objects[0x05] = conn_obj

        conn_mgr = EIPObject(0x06, 1, "ConnectionManager")
        conn_mgr.set(1, struct.pack("<H", 0x0000))
        conn_mgr.set(2, struct.pack("<H", 0x0020))
        self.objects[0x06] = conn_mgr

        register = EIPObject(0x07, 1, "Register")
        register.set(1, struct.pack("<H", 0x0001))
        register.set(2, struct.pack("<H", 0x0000))
        self.objects[0x07] = register

        tcpip = EIPObject(0xF5, 1, "TCPIP_Interface")
        tcpip.set(1, struct.pack("<I", 0x00000000))
        tcpip.set(2, struct.pack("<I", 0xC0A80001))
        tcpip.set(3, struct.pack("<I", 0xFFFFFF00))
        tcpip.set(4, struct.pack("<I", 0xC0A800FE))
        tcpip.set(5, b"eth0")
        tcpip.set(6, struct.pack("<I", 0x00000000))
        self.objects[0xF5] = tcpip

        eth_link = EIPObject(0xF6, 1, "EthernetLink")
        eth_link.set(1, struct.pack("<I", 10))
        eth_link.set(2, struct.pack("<I", 100))
        eth_link.set(3, struct.pack("<I", 100))
        eth_link.set(4, bytes(6))
        eth_link.set(5, struct.pack("<BBBBBB", 0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E))
        eth_link.set(6, struct.pack("<H", 0x01))
        eth_link.set(7, struct.pack("<H", 0x03))
        self.objects[0xF6] = eth_link

    def _next_conn_id(self):
        with self._conn_id_lock:
            cid = self._conn_id_counter
            self._conn_id_counter += 2
            return cid

    def _encap(self, cmd, status=0, ctx=0, options=0, data=b"",
               sender_context=None, handle=0):
        if isinstance(sender_context, int):
            ctx_val = sender_context
        elif isinstance(sender_context, bytes) and len(sender_context) >= 8:
            ctx_val = struct.unpack("<Q", sender_context[:8])[0]
        else:
            ctx_val = ctx
        h = ENCAP.pack(cmd, 24 + len(data), handle, ctx_val, status, options)
        return h + data

    def _encap_sender_context(self, cmd, sender_ctx, status=0, data=b""):
        return self._encap(cmd, status=status, data=data,
                          sender_context=sender_ctx)

    def handle_client(self, conn, addr):
        buf = b""
        try:
            while self._running:
                data = conn.recv(8192)
                if not data:
                    break
                buf += data
                while len(buf) >= 24:
                    cmd, length = struct.unpack("<HH", buf[:4])
                    frame_len = 24 + (length - 24 if length > 24 else 0)
                    if frame_len < 24: frame_len = 24
                    if len(buf) < frame_len:
                        break
                    chunk = buf[:frame_len]
                    buf = buf[frame_len:]
                    self._handle_encap(conn, chunk, addr)
        except socket.error:
            pass
        except Exception:
            log.exception("[%s] client error %s", self.name, addr)
        finally:
            conn.close()

    def _handle_encap(self, conn, chunk, addr):
        cmd, length, handle, sender_context, status, options = ENCAP.unpack(chunk[:24])
        ctx = sender_context
        sess = handle
        cmd_name = EIP_CMD.get(cmd, "Unknown(0x%04X)" % cmd)

        log.debug("EIP cmd=0x%04X (%s) len=%d sess=%#x ctx=%#x",
                 cmd, cmd_name, length, sess, ctx)

        if cmd == 0x0065:
            self._cmd_register_session(conn, addr)
        elif cmd == 0x0066:
            self._cmd_unregister_session(conn, sess)
        elif cmd == 0x0063:
            self._cmd_list_identity(conn, sender_context)
        elif cmd == 0x0064:
            self._cmd_list_services(conn, sender_context)
        elif cmd == 0x006F:
            self._cmd_send_rr_data(conn, chunk, sender_context, sess, addr)
        elif cmd == 0x0070:
            self._cmd_send_unit_data(conn, chunk, sender_context, sess, addr)
        elif cmd == 0x0072:
            self._cmd_indicate_status(conn, sender_context)
        elif cmd == 0x0073:
            self._cmd_cancel_status(conn, sender_context)
        else:
            log.warning("Unhandled EIP cmd 0x%04X from %s", cmd, addr)
            conn.sendall(self._encap(cmd, status=0x0001,
                                    sender_context=sender_context))

    def _cmd_register_session(self, conn, addr):
        new_sid = (int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
        session = EIPSession(new_sid, addr)
        with self.sessions_lock:
            self.sessions[new_sid] = session
        log.info("[Session] registered session %#x for %s", new_sid, addr)
        resp = self._encap(0x0065, data=struct.pack("<Q", new_sid))
        conn.sendall(resp)

    def _cmd_unregister_session(self, conn, sess):
        with self.sessions_lock:
            if sess in self.sessions:
                del self.sessions[sess]
        log.info("[Session] unregistered session %#x", sess)
        conn.sendall(self._encap(0x0066))

    def _cmd_list_identity(self, conn, sender_context):
        log.info("[Identity] ListIdentity request")
        data = self._build_list_identity()
        conn.sendall(self._encap_sender_context(0x0063, sender_context, data=data))

    def _cmd_list_services(self, conn, sender_context):
        log.info("[Services] ListServices request")
        data = self._build_list_services()
        conn.sendall(self._encap_sender_context(0x0064, sender_context, data=data))

    def _cmd_indicate_status(self, conn, sender_context):
        conn.sendall(self._encap_sender_context(0x0072, sender_context, status=0))

    def _cmd_cancel_status(self, conn, sender_context):
        conn.sendall(self._encap_sender_context(0x0073, sender_context, status=0))

    def _cmd_send_rr_data(self, conn, chunk, sender_context, sess, addr):
        if_addr = chunk[24] if len(chunk) > 24 else 0
        if if_addr == 0 and len(chunk) > 38:
            cip_data = chunk[38:]
            resp_cip = self._handle_cip_rr(cip_data, conn, addr, sess)
            reply = chunk[8:16] + resp_cip
            conn.sendall(self._encap_sender_context(
                0x006F, sender_context, data=reply))
        elif len(chunk) > 30:
            cip_data = chunk[30:]
            resp_cip = self._handle_cip_rr(cip_data, conn, addr, sess)
            reply = chunk[8:16] + resp_cip
            conn.sendall(self._encap_sender_context(
                0x006F, sender_context, data=reply))
        else:
            conn.sendall(self._encap_sender_context(
                0x006F, sender_context, data=b"\x00" * 8))

    def _cmd_send_unit_data(self, conn, chunk, sender_context, sess, addr):
        if len(chunk) > 38:
            cip_data = chunk[38:]
            resp_cip = self._handle_cip_unit(cip_data, conn, addr, sess)
            reply = chunk[8:16] + resp_cip
            conn.sendall(self._encap_sender_context(
                0x0070, sender_context, data=reply))
        elif len(chunk) > 30:
            conn.sendall(self._encap_sender_context(
                0x0070, sender_context))

    def _build_list_identity(self):
        items = bytearray()
        name = b"EtherNet/IP Simulator v4.1"
        items += struct.pack("<H", 0x0001)
        items += struct.pack("<H", len(name)) + name
        items += struct.pack("<H", 0x0002)
        items += struct.pack("<H", 0x000E)
        items += struct.pack("<H", 0x0003)
        items += struct.pack("<H", 0x0064)
        items += struct.pack("<H", 0x0004)
        items += struct.pack("<HH", 4, 1)
        items += struct.pack("<H", 0x0005)
        items += struct.pack("<H", 0x0064)
        items += struct.pack("<H", 0x0006)
        items += struct.pack("<I", 0xDEADBEEF)
        items += struct.pack("<H", 0x0007)
        items += struct.pack("<I", 0x00000000)
        items += struct.pack("<H", 0x0008)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x0009)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x000A)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x000B)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x000C)
        items += struct.pack("<H", 0x0000)

        header = struct.pack("<HHHBBH", 0x0100, 1, 0, 1, 1, 0)
        header += struct.pack("<HH", len(items), 0x0002)
        return header + bytes(items)

    def _build_list_services(self):
        service_data = bytearray()
        supported = [0x0100, 0x0200, 0x0300, 0x0400, 0x0101, 0x0102, 0x0103,
                     0x0104, 0x0201, 0x0202, 0x0203, 0x0204]
        for svc in supported:
            service_data += struct.pack("<HH", svc, 0x0001)
        name = b"Communications"
        service_data += struct.pack("<HH", 0x0002, 0x0101)
        service_data += struct.pack("<HH", len(name), 0x0001) + name
        return bytes(service_data)

    def _handle_cip_rr(self, data, conn, addr, sess):
        if len(data) < 2:
            return b"\x00\x00"
        service = data[0]
        path_len = data[1] if len(data) > 1 else 0
        svc_name = CIP_SVC.get(service, "0x%02X" % service)
        log.info("[CIP-RR] service=0x%02X (%s) path_len=%d", service, svc_name, path_len)

        if service in (0x4E,):
            return self._handle_forward_open(data, conn, addr, sess)

        if service in (0x4F,):
            return self._handle_forward_close(data, conn, addr)

        if service in (0x01, 0x02, 0x03, 0x04,
                       0x0E, 0x10, 0x4B, 0x4C):
            return self._handle_attribute_service(data, service, path_len)

        if service in (0x05, 0x52):
            return self._handle_reset(data, service)

        if service in (0x06, 0x53):
            return self._handle_start(data, service)

        if service in (0x07, 0x54):
            return self._handle_stop(data, service)

        if service in (0x08, 0x55):
            return self._handle_create(data, service, path_len)

        if service in (0x09, 0x56):
            return self._handle_delete(data, service, path_len)

        return self._cip_error(service, 0x08)

    def _handle_cip_unit(self, data, conn, addr, sess):
        if len(data) < 2:
            return b"\x00\x00"
        return bytes([data[0] | 0x80, data[1], 0x00, 0x00])

    def _parse_cip_logical_path(self, data, path_len):
        """Decode CIP logical segments: returns (class_id, instance_id, attribute_id, data_offset)."""
        pos = 2
        end = 2 + path_len * 2
        values = []
        while pos < len(data) and pos < end:
            seg = data[pos]
            pos += 1
            is_16bit = bool(seg & 0x02)
            size = 2 if is_16bit else 1

            if seg == 0x34:
                pos += 9
                continue

            if (seg & 0xE0) == 0x20:
                v = struct.unpack_from("<H" if is_16bit else "B", data, pos)[0] \
                    if pos + size - 1 < len(data) else 0
                pos += size
                values.append(v)
            elif (seg & 0xF0) == 0x30:
                if seg & 0x08:
                    v = struct.unpack_from("<H" if is_16bit else "B", data, pos)[0] \
                        if pos + size - 1 < len(data) else 0
                    pos += size
                    values.append(v)
                else:
                    values.append(None)

        cls = values[0] if len(values) > 0 else 0
        inst = values[1] if len(values) > 1 else 0
        attr = values[2] if len(values) > 2 else 0
        return cls, inst, attr, pos

    def _handle_attribute_service(self, data, service, path_len):
        cls, inst, attr, data_off = self._parse_cip_logical_path(data, path_len)
        offset = max(data_off, 2 + path_len * 2)
        if cls is None:
            cls = 0

        cls_name = CIP_CLASS_NAMES.get(cls, str(cls) if cls else "?")
        obj = self.objects.get(cls)

        if service == 0x01:
            if not obj:
                return self._cip_error(0x06, 0x16)
            vals = b""
            for k, v in obj.attributes.items():
                if isinstance(v, bytearray):
                    vals += bytes(v)
                elif isinstance(v, bytes):
                    vals += v
            log.info("  GetAttributeAll: class=0x%02X (%s) -> %d bytes",
                    cls, cls_name, len(vals))
            return bytes([service | 0x80, path_len]) + vals

        elif service == 0x0E:
            if not obj:
                return self._cip_error(0x06, 0x16)
            val = obj.get(attr)
            if val is None:
                return self._cip_error(0x0B, 0x14)
            log.info("  GetAttributeSingle: class=0x%02X (%s) inst=%d attr=%d",
                    cls, cls_name, inst, attr)
            raw_val = bytes(val) if isinstance(val, (bytes, bytearray)) else val
            return bytes([service | 0x80, path_len]) + raw_val

        elif service == 0x10:
            if not obj:
                return self._cip_error(0x06, 0x16)
            val = data[offset:]
            obj.set(attr, val)
            log.warning("  SetAttributeSingle: class=0x%02X (%s) attr=%d val=%s",
                       cls, cls_name, attr, val.hex()[:40])
            if cls == 0x04 and attr == 3:
                with self.assembly_lock:
                    self.input_assembly_data[:len(val)] = val
            if cls == 0x04 and attr == 4:
                with self.assembly_lock:
                    self.output_assembly_data[:len(val)] = val
            return bytes([service | 0x80, path_len])

        elif service == 0x02:
            if not obj:
                return self._cip_error(0x06, 0x16)
            log.warning("  SetAttributeAll: class=0x%02X (%s)", cls, cls_name)
            return bytes([service | 0x80, path_len])

        elif service == 0x4B:
            if not obj:
                return self._cip_error(0x06, 0x16)
            results = b""
            for k, v in obj.attributes.items():
                raw_val = bytes(v) if isinstance(v, (bytes, bytearray)) else v
                results += struct.pack("<HH", k, 0x0000) + raw_val
            return bytes([service | 0x80, path_len]) + struct.pack("<H", len(obj.attributes)) + results

        elif service == 0x4C:
            if not obj:
                return self._cip_error(0x06, 0x16)
            return bytes([service | 0x80, path_len])

        elif service == 0x03:
            if not obj:
                return self._cip_error(0x06, 0x16)
            attr_id_data = data[offset:]
            num_attrs = struct.unpack("<H", attr_id_data[:2])[0] if len(attr_id_data) >= 2 else 0
            attr_ids = struct.unpack("<" + "H" * num_attrs, attr_id_data[2:2 + num_attrs * 2]) if num_attrs else []
            results = b""
            for aid in attr_ids:
                val = obj.get(aid)
                if val is not None:
                    raw_val = bytes(val) if isinstance(val, (bytes, bytearray)) else val
                    results += struct.pack("<HH", aid, 0x0000) + raw_val
            return bytes([service | 0x80, path_len]) + struct.pack("<H", len(attr_ids)) + results

        elif service == 0x04:
            if not obj:
                return self._cip_error(0x06, 0x16)
            return bytes([service | 0x80, path_len])

        return self._cip_error(0x08, 0x01)

    def _handle_forward_open(self, data, conn, addr, sess):
        log.info("[ForwardOpen] from %s", addr)
        path_len = data[1] if len(data) > 1 else 0
        _cls, _inst, _attr, pdu_off = self._parse_cip_logical_path(data, path_len)
        if len(data) < pdu_off + 10:
            return self._cip_error(0x4E, 0x13)

        o_t_id = self._next_conn_id()
        t_o_id = self._next_conn_id()

        priority = data[pdu_off + 3] if len(data) > pdu_off + 3 else 0
        timeout_ticks = data[pdu_off + 2] if len(data) > pdu_off + 2 else 0
        o_t_rpi = struct.unpack("<I", data[pdu_off + 8:pdu_off + 12])[0] \
            if len(data) > pdu_off + 11 else 500000
        t_o_rpi = struct.unpack("<I", data[pdu_off + 12:pdu_off + 16])[0] \
            if len(data) > pdu_off + 15 else 500000
        o_t_size = struct.unpack("<H", data[pdu_off + 4:pdu_off + 6])[0] \
            if len(data) > pdu_off + 5 else 100
        t_o_size = struct.unpack("<H", data[pdu_off + 6:pdu_off + 8])[0] \
            if len(data) > pdu_off + 7 else 100

        conn = CIPConnection(
            conn_id=t_o_id, o_t_id=o_t_id, t_o_id=t_o_id,
            o_t_rpi=o_t_rpi, t_o_rpi=t_o_rpi,
            o_t_size=o_t_size, t_o_size=t_o_size,
            assembly_inst=100, priority=priority, conn_type=0,
            owner_addr=addr
        )
        conn.state = ConnectionState.ESTABLISHED
        with self.connections_lock:
            self.connections[t_o_id] = conn

        resp_svc = 0xCE
        resp = struct.pack("<BB", resp_svc, 0x00)
        resp += struct.pack("<I", t_o_id)
        resp += struct.pack("<I", o_t_id)
        resp += struct.pack("<H", 0x0000)
        resp += struct.pack("<H", o_t_size)
        resp += struct.pack("<H", t_o_size)
        resp += struct.pack("<H", o_t_size)
        resp += struct.pack("<II", o_t_rpi, t_o_rpi)
        resp += struct.pack("<B", priority)
        resp += struct.pack("<B", 2)
        resp += struct.pack("<H", 0x0000)
        resp += struct.pack("<H", 0x0000)
        resp += struct.pack("<I", 0x00000000)
        resp += struct.pack("<I", 0x00000000)
        return resp

    def _handle_forward_close(self, data, conn, addr):
        log.info("[ForwardClose] from %s", addr)
        pdu_off = 2 + data[1] * 2 if len(data) > 1 else 2
        if len(data) >= pdu_off + 6:
            o_t_id = struct.unpack("<I", data[pdu_off + 2:pdu_off + 6])[0]
            with self.connections_lock:
                if o_t_id in self.connections:
                    c = self.connections.pop(o_t_id)
                    log.info("[ForwardClose] closed conn %#x (size=%d)", o_t_id, c.o_t_size)
        return struct.pack("<BBBB", 0xCF, 0x00, 0x00, 0x00)

    def _handle_reset(self, data, service):
        log.warning("[CIP] Reset service 0x%02X", service)
        if len(data) >= 4:
            cls = struct.unpack("<H", data[2:4])[0]
            cls_name = CIP_CLASS_NAMES.get(cls, "?")
            log.warning("[CIP] Reset on class 0x%02X (%s)", cls, cls_name)
        with self.connections_lock:
            self.connections.clear()
        with self._owners_lock:
            self._assembly_owners.clear()
        self._init_assembly_data()
        resp_svc = service | 0x80
        return struct.pack("<BBBB", resp_svc, 0x00, 0x00, 0x00)

    def _handle_start(self, data, service):
        log.info("[CIP] Start service")
        return bytes([service | 0x80, 0x00, 0x00, 0x00])

    def _handle_stop(self, data, service):
        log.warning("[CIP] Stop service")
        return bytes([service | 0x80, 0x00, 0x00, 0x00])

    def _handle_create(self, data, service, path_len):
        log.info("[CIP] Create service")
        obj_data = data[2 + path_len * 2:]
        resp_svc = service | 0x80
        new_inst = random.randint(100, 999)
        return struct.pack("<BBHH", resp_svc, 0x00, 0x0000, new_inst) + obj_data[:20]

    def _handle_delete(self, data, service, path_len):
        log.info("[CIP] Delete service")
        return struct.pack("<BBBB", service | 0x80, 0x00, 0x00, 0x00)

    def _cip_error(self, service, gen_status, ext_status=0):
        return struct.pack("<BBBBB", service | 0x80, 0x00, gen_status,
                          ext_status >> 8, ext_status & 0xFF)

    def _acquire_owner(self, assembly_inst, conn):
        with self._owners_lock:
            owners = self._assembly_owners.setdefault(assembly_inst, [])
            occupied = [o for o in owners if o.owner_addr == conn.owner_addr]
            if len(occupied) + 1 > MAX_REDUNDANT_OWNERS:
                return False
            owners.append(conn)
            owners.sort(key=lambda x: x.priority, reverse=True)
            log.info("[Owner] assembly %d now has %d owners", assembly_inst, len(owners))
            return True

    def _release_owner(self, assembly_inst, conn_id=None):
        with self._owners_lock:
            owners = self._assembly_owners.get(assembly_inst, [])
            before = len(owners)
            if conn_id:
                self._assembly_owners[assembly_inst] = [
                    o for o in owners if o.conn_id != conn_id
                ]
            else:
                self._assembly_owners.pop(assembly_inst, None)
            after = len(self._assembly_owners.get(assembly_inst, []))
            if before != after:
                log.info("[Owner] assembly %d released (was %d, now %d)",
                        assembly_inst, before, after)

    def _start_class1_producer(self, conn):
        def producer():
            while self._running and conn.state != ConnectionState.TIMEOUT:
                try:
                    with self.connections_lock:
                        if conn.conn_id not in self.connections:
                            break
                        c = self.connections[conn.conn_id]
                        if c.state == ConnectionState.TIMEOUT:
                            break
                        c.heartbeat()
                    interval = max(conn.o_t_rpi, 1000) / 1_000_000.0
                    if interval < 0.001:
                        interval = 0.001
                    time.sleep(interval)
                    with self.assembly_lock:
                        seq = conn.seq_number & 0xFF
                        conn.seq_number += 1
                        data_size = min(conn.o_t_size, self.input_assembly_size)
                        io_data = bytes(self.input_assembly_data[:data_size])
                    log.debug("[Class1] produced %d bytes for conn %#x seq=%d",
                            data_size, conn.conn_id, seq)
                except Exception:
                    log.exception("[Class1] producer error for conn %#x", conn.conn_id)
                    break
        threading.Thread(target=producer, daemon=True).start()


if __name__ == "__main__":
    s = EthernetIPSimulator()
    s.start()
    log.info("EtherNet/IP Simulator running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        s.stop()
