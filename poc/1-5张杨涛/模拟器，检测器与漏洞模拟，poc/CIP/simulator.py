"""
CIP (Common Industrial Protocol) 协议模拟器 — 完整版
支持: 全部标准服务代码, 多段路径解析(端口/逻辑/电子键/符号段),
  Connected/Unconnected(UCMM) 双模通信, 连接状态机,
  10+ 对象类, 电子键校验, 扫描周期, 序列号跟踪。
"""

import socket
import threading
import struct
import logging
import time
import math
from collections import OrderedDict, defaultdict

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CIPSim")

# ── 服务代码 ──
CIP_SVC_NAMES = {
    0x01: "GetAttributeAll",        0x02: "SetAttributeAll",
    0x03: "GetAttributesList",      0x04: "SetAttributesList",
    0x0E: "GetAttributeSingle",     0x10: "SetAttributeSingle",
    0x4E: "ForwardOpen",            0x4F: "ForwardClose",
    0x52: "Reset",                  0x53: "Start",
    0x54: "Stop",                   0x55: "Create",
    0x56: "Delete",                 0x57: "MultipleService",
}

# ── 对象类 ──
CIP_CLASS_NAMES = {
    1: "Identity",          2: "MessageRouter",      4: "Assembly",
    5: "Connection",        6: "ConnectionManager",   7: "Register",
    8: "DiscreteInputPoint", 9: "DiscreteOutputPoint", 10: "AnalogInputPoint",
    11: "AnalogOutputPoint", 15: "ParameterObject",
}

# ── 通用状态/异常码 ──
EXCEPTION_CODES = {
    0x00: "Success",                   0x01: "Connection Failure",
    0x02: "Resource Unavailable",      0x03: "Invalid Parameter",
    0x04: "Path Segment Error",        0x05: "Path Destination Unknown",
    0x06: "Partial Transfer",          0x07: "Connection Lost",
    0x08: "Service Not Supported",     0x09: "Invalid Attribute",
    0x0A: "Attribute List Error",      0x0B: "Already in Requested Mode",
    0x0C: "Object State Conflict",     0x0D: "Object Already Exists",
    0x0E: "Attribute Not Settable",    0x0F: "Privilege Violation",
    0x10: "Device State Conflict",     0x11: "Reply Data Too Large",
    0x13: "Not Enough Data",           0x14: "Attribute Not Supported",
    0x15: "Embedded Service Error",
}

# ── 路径段类型 ──
SEG_PORT            = 0x00   # 高4位=端口, 低4位=链路地址长度
SEG_LOGICAL_CLASS   = 0x20   # 逻辑段-类 (8/16位)
SEG_LOGICAL_INST    = 0x24   # 逻辑段-实例 (8/16位)
SEG_LOGICAL_ATTR    = 0x30   # 逻辑段-属性 (8/16位)
SEG_EKEY            = 0x34   # 电子键段
SEG_SYM_ANSI_EXT    = 0x71   # ANSI 扩展符号段

# ── 连接状态机 ──
CONN_STATE_NONEXISTENT  = 0
CONN_STATE_CONFIGURING  = 1
CONN_STATE_WAITING      = 2
CONN_STATE_ESTABLISHED  = 3
CONN_STATE_TIMED_OUT    = 4
CONN_TIMEOUT_SEC        = 30

CONN_STATE_NAMES = {
    0: "non-existent", 1: "configuring", 2: "waiting",
    3: "established", 4: "timed-out",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  BaseSim — TCP 服务器基类 (self-contained)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class BaseSim:
    def __init__(self, host="0.0.0.0", port=44819, name="Sim"):
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
        self._server.listen(20)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info("[%s] listening on %s:%d", self.name, self.host, self.port)

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info("[%s] connection from %s:%d", self.name, *addr)
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
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


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CIPPathSegment — 路径段解析辅助
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CIPPathSegment:
    __slots__ = ("seg_type", "value", "extra")

    def __init__(self, seg_type, value=None, extra=None):
        self.seg_type = seg_type
        self.value = value
        self.extra = extra

    def __repr__(self):
        return f"Seg({self.seg_type:#04x}, {self.value}, {self.extra})"


def parse_path_segments(data, offset=0):
    segments = []
    while offset < len(data):
        b = data[offset]
        seg_type = b

        if (b & 0xE0) == 0x20:          # Logical segment (class 0x20, inst 0x24)
            if b & 0x10:
                if b & 0x02:
                    if offset + 2 >= len(data):
                        break
                    value = struct.unpack_from("<H", data, offset + 1)[0]
                    segments.append(CIPPathSegment(b, value))
                    offset += 3
                else:
                    value = data[offset + 1] if offset + 1 < len(data) else 0
                    segments.append(CIPPathSegment(b, value))
                    offset += 2
            else:
                if b & 0x02:
                    if offset + 2 >= len(data):
                        break
                    value = struct.unpack_from("<H", data, offset + 1)[0]
                    segments.append(CIPPathSegment(b, value))
                    offset += 3
                else:
                    value = data[offset + 1] if offset + 1 < len(data) else 0
                    segments.append(CIPPathSegment(b, value))
                    offset += 2
            continue

        if (b & 0xF0) == 0x30:          # Logical segment (attribute 0x30)
            if b & 0x08:
                if b & 0x02:
                    if offset + 2 >= len(data):
                        break
                    value = struct.unpack_from("<H", data, offset + 1)[0]
                    segments.append(CIPPathSegment(b, value))
                    offset += 3
                else:
                    value = data[offset + 1] if offset + 1 < len(data) else 0
                    segments.append(CIPPathSegment(b, value))
                    offset += 2
            else:
                value = None
                segments.append(CIPPathSegment(b, value))
                offset += 1
            continue

        if b == 0x34:                   # Electronic key
            if offset + 10 >= len(data):
                break
            fmt_byte = data[offset + 1]
            vendor = struct.unpack_from("<H", data, offset + 2)[0]
            dev_type = struct.unpack_from("<H", data, offset + 4)[0]
            prod_code = struct.unpack_from("<H", data, offset + 6)[0]
            major = data[offset + 8]
            minor = data[offset + 9]
            key = {"format": fmt_byte, "vendor": vendor, "device_type": dev_type,
                   "product_code": prod_code, "major": major, "minor": minor}
            segments.append(CIPPathSegment(b, key, key))
            offset += 10
            continue

        if (b & 0xF0) == 0x70:          # Symbolic segment
            if b == 0x71:
                if offset + 1 >= len(data):
                    break
                sym_len = data[offset + 1]
                start = offset + 2
                end = start + sym_len
                if end > len(data):
                    break
                symbol = data[start:end].decode("ascii", errors="replace")
                segments.append(CIPPathSegment(b, symbol))
                pad = (sym_len + 2) % 2
                offset = end + pad
            else:
                segments.append(CIPPathSegment(b))
                offset += 1
            continue

        # Port segment (高4位=端口, 低4位=链路地址长度)
        port = (b & 0xF0) >> 4
        link_len = b & 0x0F
        link_data = None
        if link_len > 0:
            if offset + 1 + link_len >= len(data):
                break
            link_data = data[offset + 1 : offset + 1 + link_len]
            offset += 1 + link_len
        else:
            offset += 1
        segments.append(CIPPathSegment(SEG_PORT, port, link_data))

    return segments, offset


def simplify_segments(segments):
    """从段列表中提取 class_id / instance_id / attribute_id (尽力而为)"""
    result = {"class_id": 0, "instance_id": 1, "attribute_id": 0}
    for seg in segments:
        t = seg.seg_type
        if (t & 0xE0) == 0x20:
            result["class_id"] = seg.value
        elif (t & 0xE0) == 0x24:
            result["instance_id"] = seg.value
        elif (t & 0xF0) == 0x30:
            result["attribute_id"] = seg.value or 0
    return result


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CIPObject — 对象表示
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CIPObject:
    def __init__(self, class_id, instance_id=1):
        self.class_id = class_id
        self.instance_id = instance_id
        self.attributes = OrderedDict()
        self.state = 0
        self.created_at = time.time()

    def get(self, attr_id):
        return self.attributes.get(attr_id)

    def set(self, attr_id, value):
        self.attributes[attr_id] = value

    def get_all(self):
        return b"".join(self.attributes.values())


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CIPConnection — 连接对象 (含状态机)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CIPConnection:
    def __init__(self, o_t_id, t_o_id, rpi=4000):
        self.o_t_connection_id = o_t_id
        self.t_o_connection_id = t_o_id
        self.rpi = rpi
        self.state = CONN_STATE_CONFIGURING
        self.created_at = time.time()
        self.last_activity = time.time()
        self.seq_num = 0
        self.src_addr = None

    def transit(self, new_state):
        old = CONN_STATE_NAMES.get(self.state, str(self.state))
        new = CONN_STATE_NAMES.get(new_state, str(new_state))
        log.info("  Connection %d: %s → %s", self.o_t_connection_id, old, new)
        self.state = new_state
        self.last_activity = time.time()

    def is_timed_out(self):
        if self.state == CONN_STATE_ESTABLISHED:
            return (time.time() - self.last_activity) > CONN_TIMEOUT_SEC
        return False

    def bump(self):
        self.last_activity = time.time()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CIPSimulator — CIP 主模拟器
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class CIPSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=44819):
        super().__init__(host, port, "CIP")
        self._build_objects()
        self._connections = {}          # conn_id → CIPConnection
        self._connection_id_counter = 1
        self._sessions = defaultdict(lambda: {"seq": 0, "last_activity": time.time()})
        self._ucmm_count = defaultdict(int)
        self._scan_running = False
        self._scan_thread = None
        self.device_state = 0x1000      # Running
        self._electronic_key = {"vendor": 0x0001, "device_type": 0x000E,
                                "product_code": 0x0064, "major": 4, "minor": 1}

    # ── 对象库构建 ──
    def _build_objects(self):
        self.objects = {}

        # 1. Identity (class 1)
        ident = CIPObject(1)
        ident.set(1, b"Rockwell Automation/Allen-Bradley\x00")
        ident.set(2, b"PLC-5/80 Series Z\x00")
        ident.set(3, b"4.001.00\x00")
        ident.set(4, struct.pack("<H", 0x0001))
        ident.set(5, struct.pack("<H", 0x000E))
        ident.set(6, struct.pack("<I", 0xDEADBEEF))
        ident.set(7, struct.pack("<H", 0x0064))
        ident.set(8, struct.pack("<H", 0x1000))
        self.objects[(1, 1)] = ident

        # 2. MessageRouter (class 2)
        router = CIPObject(2)
        router.set(1, struct.pack("<H", 0x0100))
        router.set(2, struct.pack("<H", 0x0003))
        router.set(3, struct.pack("<H", 15))
        router.set(4, struct.pack("<H", 120))
        self.objects[(2, 1)] = router

        # 4. Assembly (class 4) — instance 1=output, 100=configurable, 101=heartbeat, 102=listener
        # Instance 1: output data
        self.assembly_data_1 = bytearray(1024)
        struct.pack_into("<H", self.assembly_data_1, 0, 0x0001)
        struct.pack_into("<I", self.assembly_data_1, 2, 0x00000064)
        struct.pack_into("<f", self.assembly_data_1, 6, 25.0)
        struct.pack_into("<f", self.assembly_data_1, 10, 100.0)
        struct.pack_into("<f", self.assembly_data_1, 14, 50.0)
        a1 = CIPObject(4, 1)
        a1.set(3, bytes(self.assembly_data_1))
        self.objects[(4, 1)] = a1

        # Instance 100: configurable size
        a100 = CIPObject(4, 100)
        a100.set(3, b"\x00" * 512)
        a100.set(4, struct.pack("<I", 512))
        self.objects[(4, 100)] = a100

        # Instance 101: heartbeat (32 bytes)
        hb = CIPObject(4, 101)
        hb_data = bytearray(32)
        struct.pack_into("<I", hb_data, 0, int(time.time()))
        struct.pack_into("<I", hb_data, 4, 0x01)
        hb.set(3, bytes(hb_data))
        hb.set(4, struct.pack("<I", 32))
        self.objects[(4, 101)] = hb

        # Instance 102: listener data
        ls = CIPObject(4, 102)
        ls.set(3, b"\x00" * 128)
        ls.set(4, struct.pack("<I", 128))
        self.objects[(4, 102)] = ls

        # 5. Connection objects — created dynamically on ForwardOpen

        # 6. ConnectionManager
        cm = CIPObject(6)
        cm.set(1, struct.pack("<I", 16))
        cm.set(2, struct.pack("<I", 128))
        cm.set(3, struct.pack("<I", 0))
        cm.set(4, struct.pack("<I", 0))
        cm.set(5, struct.pack("<I", 0))
        cm.set(6, struct.pack("<H", 0x0001))
        self.objects[(6, 1)] = cm

        # 7. Register
        reg = CIPObject(7)
        reg.set(1, struct.pack("<H", 1))
        reg.set(2, struct.pack("<H", 1))
        self.objects[(7, 1)] = reg

        # 8. DiscreteInputPoint, 9. DiscreteOutputPoint
        dip = CIPObject(8)
        dip.set(3, struct.pack("<?", False))
        dip.set(4, struct.pack("<?", False))   # forced state
        self.objects[(8, 1)] = dip
        dop = CIPObject(9)
        dop.set(3, struct.pack("<?", False))
        dop.set(4, struct.pack("<?", False))
        self.objects[(9, 1)] = dop

        # 10. AnalogInputPoint, 11. AnalogOutputPoint
        aip = CIPObject(10)
        aip.set(3, struct.pack("<f", 0.0))
        aip.set(6, struct.pack("<f", 0.0))   # engineering units
        aip.set(7, struct.pack("<f", 0.0))   # raw value
        self.objects[(10, 1)] = aip
        aop = CIPObject(11)
        aop.set(3, struct.pack("<f", 0.0))
        aop.set(6, struct.pack("<f", 0.0))
        aop.set(7, struct.pack("<f", 0.0))
        self.objects[(11, 1)] = aop

        # 15. ParameterObject
        param = CIPObject(15)
        param.set(1, struct.pack("<H", 0x0001))
        param.set(2, b"LoopGain\x00")
        param.set(3, struct.pack("<f", 1.5))
        param.set(4, struct.pack("<f", 0.0))
        param.set(5, struct.pack("<f", 100.0))
        self.objects[(15, 1)] = param

    def start(self):
        super().start()
        self._start_scan_cycle()

    def _start_scan_cycle(self):
        self._scan_running = True
        self._tick = 0.0
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scan_thread.start()
        log.info("[CIP] scan cycle started")

    def _scan_loop(self):
        while self._scan_running:
            self._tick += 0.1
            t = self._tick

            # AnalogInputPoint: sinusoidal pattern
            aip = self.objects.get((10, 1))
            if aip:
                val = 50.0 + 45.0 * math.sin(t * 0.5)
                aip.set(3, struct.pack("<f", val))
                aip.set(7, struct.pack("<f", val * 327.67))

            # Discrete points: toggle every 3 seconds
            toggle = (int(t) % 6) < 3
            dip = self.objects.get((8, 1))
            if dip:
                dip.set(3, struct.pack("<?", toggle))

            # Heartbeat update
            hb = self.objects.get((4, 101))
            if hb:
                hb_data = bytearray(32)
                struct.pack_into("<I", hb_data, 0, int(time.time()))
                struct.pack_into("<I", hb_data, 4, 0x01 if self.device_state == 0x1000 else 0x00)
                hb.set(3, bytes(hb_data))

            # Connection timeout check
            now = time.time()
            to_remove = []
            for cid, conn in self._connections.items():
                if conn.is_timed_out():
                    conn.transit(CONN_STATE_TIMED_OUT)
                    to_remove.append(cid)
            for cid in to_remove:
                log.warning("  Connection %d timed out after %ds", cid, CONN_TIMEOUT_SEC)
                del self._connections[cid]

            time.sleep(0.1)

    def stop(self):
        self._scan_running = False
        super().stop()

    # ── 电子键校验 ──
    def _validate_electronic_key(self, key):
        ek = self._electronic_key
        return (key["vendor"] == ek["vendor"] and
                key["device_type"] == ek["device_type"] and
                key["product_code"] == ek["product_code"] and
                key["major"] == ek["major"] and
                key["minor"] == ek["minor"])

    # ── 符号名查找 ──
    def _lookup_symbol(self, symbol):
        for (cid, iid), obj in self.objects.items():
            try:
                name = obj.get(2)
                if name and symbol.encode("ascii") in name:
                    return (cid, iid)
            except Exception:
                continue
        return None

    # ── 客户端处理 ──
    def handle_client(self, conn, addr):
        buf = b""
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                buf += data

                while len(buf) >= 2:
                    consumed, resp = self._dispatch(buf, addr)
                    if consumed == 0:
                        break
                    buf = buf[consumed:]
                    if resp:
                        try:
                            conn.sendall(resp)
                        except Exception:
                            return
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _dispatch(self, buf, addr):
        first = buf[0]

        # ── Connected message: header 0xFF 0xFE ──
        if len(buf) >= 8 and buf[0] == 0xFF and buf[1] == 0xFE:
            conn_id, seq_num = struct.unpack_from("<HH", buf, 2)
            inner = buf[6:]
            consumed, inner_resp = self._process_cip_connected(inner, addr, conn_id, seq_num)
            if consumed == 0:
                return 0, b""
            header = struct.pack("<B B H H", 0xFF, 0xFE, conn_id, seq_num)
            return 6 + consumed, header + inner_resp

        # ── UCMM message: header 0xFF 0xFD ──
        if len(buf) >= 6 and buf[0] == 0xFF and buf[1] == 0xFD:
            tick_time = struct.unpack_from("<H", buf, 2)[0]
            timeout_ticks = struct.unpack_from("<H", buf, 4)[0]
            inner = buf[6:]
            src_ip = addr[0] if addr else "0.0.0.0"
            self._ucmm_count[src_ip] += 1
            log.debug("  UCMM tick=%d timeout=%d src=%s count=%d",
                      tick_time, timeout_ticks, src_ip, self._ucmm_count[src_ip])
            consumed, inner_resp = self._process_cip(inner, addr)
            if consumed == 0:
                return 0, b""
            header = struct.pack("<B B H H", 0xFF, 0xFD, tick_time, timeout_ticks)
            return 6 + consumed, header + inner_resp

        # ── Simple unconnected (bare CIP) ──
        consumed, resp = self._process_cip(buf, addr)
        return consumed, resp

    # ── Connected 消息处理 ──
    def _process_cip_connected(self, data, addr, conn_id, seq_num):
        if len(data) < 2:
            return 0, b""
        conn = self._connections.get(conn_id)
        if not conn:
            log.warning("  Connected msg on unknown conn_id=%d", conn_id)
            return 0, b""
        if conn.state != CONN_STATE_ESTABLISHED:
            log.warning("  Connected msg on non-established conn=%d state=%d",
                        conn_id, conn.state)
            return 0, b""

        # Sequence number check
        session = self._sessions[addr[0]]
        if seq_num != 0 and seq_num <= session["seq"]:
            log.warning("  Out-of-order seq_num=%d (expected >%d)", seq_num, session["seq"])
        session["seq"] = max(session["seq"], seq_num)
        session["last_activity"] = time.time()
        conn.bump()

        return self._process_cip(data, addr)

    # ── 核心 CIP 服务处理 ──
    def _process_cip(self, data, addr=None):
        if len(data) < 2:
            return 0, b""

        service = data[0]
        path_len = data[1]
        if service & 0x80:
            return len(data), b""

        # 路径解析
        raw_path = data[2:2 + path_len * 2] if path_len > 0 else b""
        segments, _ = parse_path_segments(raw_path)
        pinfo = simplify_segments(segments)

        # 电子键校验
        for seg in segments:
            if seg.seg_type == 0x34 and seg.extra:
                if not self._validate_electronic_key(seg.extra):
                    log.warning("  Electronic key validation FAILED")
                    return len(data), struct.pack("<BBH", service | 0x80, path_len,
                                                  0x000F)

        # 符号段解析
        for seg in segments:
            if seg.seg_type == 0x71 and isinstance(seg.value, str):
                resolved = self._lookup_symbol(seg.value)
                if resolved:
                    pinfo["class_id"], pinfo["instance_id"] = resolved
                    log.info("  Symbol '%s' resolved to class=%d inst=%d",
                             seg.value, *resolved)

        class_id = pinfo.get("class_id", 0)
        instance_id = pinfo.get("instance_id", 1)
        attr_id = pinfo.get("attribute_id", 0)

        svc_name = CIP_SVC_NAMES.get(service, f"Unknown(0x{service:02X})")
        cls_name = CIP_CLASS_NAMES.get(class_id, f"0x{class_id:04X}")
        log.info("  CIP svc=0x%02X (%s) class=%d(%s) inst=%d attr=%d segs=%d",
                 service, svc_name, class_id, cls_name, instance_id, attr_id, len(segments))

        # 路径深度告警
        if len(segments) > 3:
            log.warning("  Deep path routing: %d segments", len(segments))

        # ── 服务分发 ──
        handler = self._SERVICE_MAP.get(service, self._unsupported)
        consumed, resp = handler(self, data, raw_path, pinfo, segments, addr)
        return consumed if consumed > 0 else len(data), resp

    # ──────────────────────────
    #  服务处理方法
    # ──────────────────────────

    def _svc_get_attr_all(self, data, raw_path, pinfo, segments, addr):
        obj = self.objects.get((pinfo["class_id"], pinfo["instance_id"]))
        if not obj:
            obj = self.objects.get((pinfo["class_id"], 1))
        vals = obj.get_all() if obj else b""
        return len(data), bytes([data[0] | 0x80, data[1]]) + vals

    def _svc_set_attr_all(self, data, raw_path, pinfo, segments, addr):
        val = data[2 + data[1] * 2:]
        obj = self.objects.get((pinfo["class_id"], pinfo["instance_id"]))
        if not obj:
            obj = CIPObject(pinfo["class_id"], pinfo["instance_id"])
            self.objects[(pinfo["class_id"], pinfo["instance_id"])] = obj
        idx = 0
        while idx < len(val):
            if idx + 1 > len(val):
                break
            aid = val[idx]
            aval = val[idx + 1:idx + 5] if idx + 5 <= len(val) else val[idx + 1:]
            obj.set(aid, aval)
            idx += 5 if idx + 5 <= len(val) else idx + 1 + len(aval)
        log.warning("  SetAttributeAll: class=%d inst=%d (%dB)",
                     pinfo["class_id"], pinfo["instance_id"], len(val))
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_get_attr_single(self, data, raw_path, pinfo, segments, addr):
        obj = self.objects.get((pinfo["class_id"], pinfo["instance_id"]))
        if not obj:
            obj = self.objects.get((pinfo["class_id"], 1))
        val = obj.get(pinfo["attribute_id"]) if obj else b""
        if not val:
            val = b"\x00" * 4
        return len(data), bytes([data[0] | 0x80, data[1]]) + val

    def _svc_set_attr_single(self, data, raw_path, pinfo, segments, addr):
        val = data[2 + data[1] * 2:]
        obj = self.objects.get((pinfo["class_id"], pinfo["instance_id"]))
        if not obj:
            obj = CIPObject(pinfo["class_id"], pinfo["instance_id"])
            self.objects[(pinfo["class_id"], pinfo["instance_id"])] = obj
        obj.set(pinfo["attribute_id"], val)
        log.warning("  SetAttributeSingle: class=%d inst=%d attr=%d val=%s",
                     pinfo["class_id"], pinfo["instance_id"], pinfo["attribute_id"],
                     val[:16].hex())
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_get_attrs_list(self, data, raw_path, pinfo, segments, addr):
        obj = self.objects.get((pinfo["class_id"], pinfo["instance_id"]))
        if not obj:
            obj = self.objects.get((pinfo["class_id"], 1))
        payload = data[2 + data[1] * 2:]
        resp_data = b""
        if obj and len(payload) >= 2:
            count = struct.unpack_from("<H", payload, 0)[0]
            attrs = list(struct.unpack_from(f"<{count}H", payload, 2)) if len(payload) >= 2 + count * 2 else []
            resp_data = struct.pack("<H", count)
            for aid in attrs:
                v = obj.get(aid) or b"\x00" * 4
                resp_data += struct.pack("<H", aid) + v
        return len(data), bytes([data[0] | 0x80, data[1]]) + resp_data

    def _svc_set_attrs_list(self, data, raw_path, pinfo, segments, addr):
        obj = self.objects.get((pinfo["class_id"], pinfo["instance_id"]))
        if not obj:
            obj = CIPObject(pinfo["class_id"], pinfo["instance_id"])
            self.objects[(pinfo["class_id"], pinfo["instance_id"])] = obj
        payload = data[2 + data[1] * 2:]
        if len(payload) >= 2:
            count = struct.unpack_from("<H", payload, 0)[0]
            offset = 2
            for _ in range(count):
                if offset + 2 > len(payload):
                    break
                aid = struct.unpack_from("<H", payload, offset)[0]
                offset += 2
                if offset + 4 <= len(payload):
                    val = payload[offset:offset + 4]
                    offset += 4
                    obj.set(aid, val)
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_forward_open(self, data, raw_path, pinfo, segments, addr):
        o_to = self._connection_id_counter
        self._connection_id_counter += 1
        t_to = self._connection_id_counter
        self._connection_id_counter += 1

        rpi = 4000
        payload = data[2 + data[1] * 2:]
        if len(payload) >= 4:
            rpi = struct.unpack_from("<I", payload, 0)[0]
        if len(payload) >= 8:
            rpi = struct.unpack_from("<I", payload, 4)[0]

        conn = CIPConnection(o_to, t_to, rpi)
        conn.src_addr = addr
        conn.transit(CONN_STATE_WAITING)
        conn.transit(CONN_STATE_ESTABLISHED)
        self._connections[o_to] = conn
        self._connections[t_to] = conn

        log.info("  ForwardOpen: O_T=%d T_O=%d RPI=%dms", o_to, t_to, rpi)
        resp = struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)
        resp += struct.pack("<II", o_to, t_to)
        resp += struct.pack("<II", rpi, rpi)
        resp += struct.pack("<I", 0)
        return len(data), resp

    def _svc_forward_close(self, data, raw_path, pinfo, segments, addr):
        payload = data[2 + data[1] * 2:]
        close_id = 0
        if len(payload) >= 2:
            close_id = struct.unpack_from("<H", payload, 0)[0]
        if close_id in self._connections:
            self._connections[close_id].transit(CONN_STATE_NONEXISTENT)
            del self._connections[close_id]
            log.info("  ForwardClose: conn_id=%d closed", close_id)
        else:
            for cid in list(self._connections.keys()):
                if cid == close_id:
                    del self._connections[cid]
                    log.info("  ForwardClose: conn_id=%d closed", close_id)
                    break
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_reset(self, data, raw_path, pinfo, segments, addr):
        log.warning("  [CRITICAL] Reset on class=%d inst=%d",
                     pinfo["class_id"], pinfo["instance_id"])
        self.device_state = 0x0000
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_start(self, data, raw_path, pinfo, segments, addr):
        log.info("  Start on class=%d inst=%d", pinfo["class_id"], pinfo["instance_id"])
        self.device_state = 0x1000
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_stop(self, data, raw_path, pinfo, segments, addr):
        log.warning("  [CRITICAL] Stop on class=%d inst=%d",
                     pinfo["class_id"], pinfo["instance_id"])
        self.device_state = 0x0000
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_create(self, data, raw_path, pinfo, segments, addr):
        log.info("  Create: class=%d inst=%d",
                 pinfo["class_id"], pinfo["instance_id"])
        key = (pinfo["class_id"], pinfo["instance_id"])
        if key not in self.objects:
            self.objects[key] = CIPObject(pinfo["class_id"], pinfo["instance_id"])
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)

    def _svc_delete(self, data, raw_path, pinfo, segments, addr):
        key = (pinfo["class_id"], pinfo["instance_id"])
        log.warning("  Delete: class=%d inst=%d",
                     pinfo["class_id"], pinfo["instance_id"])
        if key in self.objects:
            del self.objects[key]
            return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0005)

    def _svc_multiple_service(self, data, raw_path, pinfo, segments, addr):
        payload = data[2 + data[1] * 2:]
        if len(payload) < 2:
            return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0013)
        count = struct.unpack_from("<H", payload, 0)[0]
        log.info("  MultipleService: %d sub-services", count)
        offset = 2
        results = b""
        for _ in range(count):
            if offset + 2 > len(payload):
                break
            sub_len = struct.unpack_from("<H", payload, offset)[0]
            offset += 2
            sub_data = payload[offset:offset + sub_len]
            offset += sub_len
            consumed, sub_resp = self._process_cip(sub_data, addr)
            if sub_resp and len(sub_resp) >= 2:
                results += sub_resp
        full = struct.pack("<BBH", data[0] | 0x80, data[1], 0x0000)
        full += struct.pack("<H", count)
        for i in range(count):
            full += struct.pack("<H", 0x0000)
        full += results
        return len(data), full

    def _unsupported(self, data, raw_path, pinfo, segments, addr):
        log.warning("  Unsupported service 0x%02X", data[0])
        return len(data), struct.pack("<BBH", data[0] | 0x80, data[1], 0x0008)

    # ── 服务映射表 ──
    _SERVICE_MAP = {
        0x01: _svc_get_attr_all,
        0x02: _svc_set_attr_all,
        0x03: _svc_get_attrs_list,
        0x04: _svc_set_attrs_list,
        0x0E: _svc_get_attr_single,
        0x10: _svc_set_attr_single,
        0x4E: _svc_forward_open,
        0x4F: _svc_forward_close,
        0x52: _svc_reset,
        0x53: _svc_start,
        0x54: _svc_stop,
        0x55: _svc_create,
        0x56: _svc_delete,
        0x57: _svc_multiple_service,
    }


if __name__ == "__main__":
    s = CIPSimulator()
    s.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
