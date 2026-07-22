"""
Modbus TCP/RTU 协议模拟器 — 深度仿真版
PLC扫描周期 · 梯形图逻辑 · 交易追踪 · 诊断缓冲 · 速率限制 · 多单元支持
"""
import socket, threading, struct, logging, time, os, random
from collections import OrderedDict, defaultdict, deque
from enum import Enum

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ModbusSim")

MBAP_HDR = struct.Struct(">HHHB")
RTU_CRC_TABLE = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
]
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
EXC_CODES = {1: "Illegal Function", 2: "Illegal Data Address", 3: "Illegal Data Value",
             4: "Server Device Failure", 5: "Acknowledge", 6: "Server Device Busy",
             7: "Memory Parity Error", 8: "Gateway Path Unavailable", 10: "Gateway Target Failed"}
DIAG_SUBFUNC = {0: "Return Query Data", 1: "Restart Communications", 2: "Return Diagnostic Register",
                3: "Change ASCII Input Delimiter", 4: "Force Listen Only Mode",
                10: "Clear Counters & Diagnostic Register", 11: "Return Bus Message Count",
                12: "Return Bus Communication Error Count", 13: "Return Bus Exception Error Count",
                14: "Return Server Message Count", 15: "Return Server No Response Count",
                16: "Return Server NAK Count", 17: "Return Server Busy Count",
                18: "Return Bus Character Overrun Count", 20: "Clear Overrun Counter",
                21: "Get Clear Overrun Counter"}

EXC_STATUS_MEMFAULT = 0x01
EXC_STATUS_PLCFAULT = 0x02
EXC_STATUS_IOFAULT = 0x04
EXC_STATUS_COMMFAULT = 0x08
EXC_STATUS_WDTIMEOUT = 0x10
EXC_STATUS_POWERLOSS = 0x20
EXC_STATUS_CFGERR = 0x40
EXC_STATUS_DIAGACTIVE = 0x80

MAX_IDLE_SECONDS = 30
MAX_REQ_PER_SEC = 100
MAX_DIAG_BUFFER = 200
SCAN_CYCLE_MS = 50


class ContactType(Enum):
    NORMAL_OPEN = 0
    NORMAL_CLOSED = 1
    RISING_EDGE = 2
    FALLING_EDGE = 3


class CoilType(Enum):
    NORMAL = 0
    LATCH_SET = 1
    LATCH_RESET = 2


class TimerType(Enum):
    TON = 0
    TOFF = 1


class LadderRung:
    def __init__(self, rung_id, contacts, coil_addr, coil_type=CoilType.NORMAL,
                 timer=None):
        self.rung_id = rung_id
        self.contacts = contacts
        self.coil_addr = coil_addr
        self.coil_type = coil_type
        self.timer = timer

    def dependencies(self):
        return {c[0] for c in self.contacts}

    def __repr__(self):
        return (f"Rung({self.rung_id}, contacts={self.contacts}, "
                f"coil={self.coil_addr}, type={self.coil_type}, timer={self.timer})")


class LadderTimer:
    def __init__(self, timer_type, preset_ms, acc_ms=0):
        self.timer_type = timer_type
        self.preset_ms = preset_ms
        self.acc_ms = acc_ms
        self.done = False
        self.last_input = False

    def reset(self):
        self.acc_ms = 0
        self.done = False

    def update(self, input_state, dt_ms):
        if self.timer_type == TimerType.TON:
            if input_state:
                self.acc_ms += dt_ms
                if self.acc_ms >= self.preset_ms:
                    self.acc_ms = self.preset_ms
                    self.done = True
            else:
                self.acc_ms = 0
                self.done = False
            return self.done
        elif self.timer_type == TimerType.TOFF:
            if input_state:
                self.acc_ms = 0
                self.done = True
                return True
            else:
                if self.last_input:
                    self.acc_ms = 0
                self.acc_ms += dt_ms
                if self.acc_ms >= self.preset_ms:
                    self.acc_ms = self.preset_ms
                    self.done = False
                    return False
                return True
        return input_state


class LadderLogic:
    def __init__(self):
        self._rungs = []
        self._timers = {}
        self._dep_graph = defaultdict(set)
        self._prev_coils = {}
        self._rising_edges = set()
        self._falling_edges = set()
        self._latch_state = {}
        self._last_scan = time.time()
        self._lock = threading.Lock()

    def add_rung(self, rung):
        with self._lock:
            self._rungs.append(rung)
            dep_addrs = rung.dependencies()
            for da in dep_addrs:
                self._dep_graph[da].add(rung.coil_addr)
            if rung.timer is not None:
                self._timers[rung.coil_addr] = LadderTimer(
                    TimerType(rung.timer["type"]),
                    rung.timer.get("preset_ms", 1000)
                )
            log.debug(f"Ladder: added rung[{rung.rung_id}] coil={rung.coil_addr} deps={dep_addrs}")

    def remove_rung(self, rung_id):
        with self._lock:
            self._rungs = [r for r in self._rungs if r.rung_id != rung_id]
            self._rebuild_dep_graph()

    def _rebuild_dep_graph(self):
        self._dep_graph.clear()
        for r in self._rungs:
            for da in r.dependencies():
                self._dep_graph[da].add(r.coil_addr)

    def evaluate(self, coil_reader, input_reader, dt_ms):
        with self._lock:
            self._rising_edges.clear()
            self._falling_edges.clear()
            scan_start = time.time()

            for rung in self._rungs:
                result = self._eval_contacts(rung.contacts, coil_reader, input_reader)
                if rung.timer is not None:
                    timer = self._timers.get(rung.coil_addr)
                    if timer:
                        timer.last_input = result
                        result = timer.update(result, dt_ms)

                prev = self._prev_coils.get(rung.coil_addr, False)
                if result and not prev:
                    self._rising_edges.add(rung.coil_addr)
                elif not result and prev:
                    self._falling_edges.add(rung.coil_addr)
                self._prev_coils[rung.coil_addr] = result

                if rung.coil_type == CoilType.LATCH_SET and result:
                    self._latch_state[rung.coil_addr] = True
                elif rung.coil_type == CoilType.LATCH_RESET and result:
                    self._latch_state[rung.coil_addr] = False
                else:
                    self._latch_state[rung.coil_addr] = result

            self._last_scan = scan_start

    def _eval_contacts(self, contacts, coil_reader, input_reader):
        result = True
        for addr, ctype in contacts:
            if addr < 0x10000:
                raw_val = coil_reader(addr) or self._latch_state.get(addr, False)
            else:
                raw_val = input_reader(addr - 0x10000)
            if ctype == ContactType.NORMAL_OPEN:
                result = result and raw_val
            elif ctype == ContactType.NORMAL_CLOSED:
                result = result and (not raw_val)
            elif ctype == ContactType.RISING_EDGE:
                result = result and (addr in self._rising_edges)
            elif ctype == ContactType.FALLING_EDGE:
                result = result and (addr in self._falling_edges)
        return result

    @property
    def latch_state(self):
        return dict(self._latch_state)

    @property
    def dep_graph(self):
        return dict(self._dep_graph)

    @property
    def rung_count(self):
        return len(self._rungs)


class BaseSim:
    def __init__(self, host="0.0.0.0", port=502, name="Sim"):
        self.host = host; self.port = port; self.name = name
        self._server = None; self._running = False; self._thread = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self._server.bind((self.host, self.port)); self._server.listen(10)
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        log.info(f"[{self.name}] listening on {self.host}:{self.port}")

    def _accept_loop(self):
        self._server.settimeout(1.0)
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info(f"[{self.name}] new connection from {addr[0]}:{addr[1]}")
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self._running:
                    log.error(f"[{self.name}] accept error: {e}")
                break
        log.info(f"[{self.name}] accept loop terminated")

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        log.info(f"[{self.name}] stopped")

    def handle_client(self, conn, addr):
        raise NotImplementedError


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ RTU_CRC_TABLE[(crc ^ b) & 0xFF]
    return crc


class ModbusSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=502, use_rtu=False, tls_enabled=False):
        super().__init__(host, port, "ModbusRTU" if use_rtu else "ModbusTCP")
        self.use_rtu = use_rtu
        self.tls_enabled = tls_enabled

        self.coils = bytearray(65536)
        self.discrete_inputs = bytearray(65536)
        self.holding_registers = bytearray(65536 * 2)
        self.input_registers = bytearray(65536 * 2)
        self.fifo_buffer = [0] * 32
        self.file_records = OrderedDict()
        self._init_file_records()

        self.diag_counters = {k: 0 for k in range(11, 19)}
        self.diag_register = 0x0000
        self.broadcast_enabled = True

        self.server_id = b"ModbusSim v2.0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.device_id_data = {
            0x00: b"ModbusSim\x00\x00\x00\x00\x00\x00\x00\x00",
            0x01: b"PLC-2000 Simulator\x00\x00\x00\x00\x00\x00",
            0x02: b"2.0.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x03: b"https://example.com/modbus\x00\x00\x00\x00",
            0x04: b"ModbusSim-2026\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            0x05: b"2026-01-01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        }
        self.diag_counters[11] = 0

        self.exception_status = 0x00
        self.diagnostic_buffer = deque(maxlen=MAX_DIAG_BUFFER)
        self.diagnostic_buffer_lock = threading.Lock()

        self._bus_counters = defaultdict(lambda: {"total": 0, "errors": 0, "exceptions": 0})
        self._bus_counters_lock = threading.Lock()

        self._transactions = {}
        self._transactions_lock = threading.Lock()

        self._rate_windows = defaultdict(list)
        self._rate_lock = threading.Lock()

        self._conn_last_active = {}
        self._conn_last_lock = threading.Lock()

        self._unit_memory = {}
        for uid in range(256):
            self._unit_memory[uid] = {
                "coils": bytearray(1024),
                "holding": bytearray(4096 * 2),
                "discrete": bytearray(1024),
                "input": bytearray(4096 * 2),
            }

        self._ladder = LadderLogic()
        self._scan_thread = None
        self._scan_running = False
        self._scan_interval = SCAN_CYCLE_MS / 1000.0

        self._timeout_watcher_thread = threading.Thread(
            target=self._timeout_watcher, daemon=True
        )

        log.info(f"[{self.name}] initialized TLS={tls_enabled} scan_cycle={SCAN_CYCLE_MS}ms")

    def _init_file_records(self):
        for i in range(5):
            rec = bytearray(100 * 2)
            for j in range(100):
                struct.pack_into(">H", rec, j * 2, (i + 1) * 1000 + j)
            self.file_records[i + 1] = rec

    def start(self):
        super().start()
        self._scan_running = True
        self._scan_thread = threading.Thread(target=self._scan_cycle, daemon=True)
        self._scan_thread.start()
        self._timeout_watcher_thread.start()
        log.info(f"[{self.name}] scan cycle thread started, timeout watcher started")

    def stop(self):
        self._scan_running = False
        super().stop()

    def _scan_cycle(self):
        while self._scan_running:
            cycle_start = time.time()
            try:
                dt_ms = int(self._scan_interval * 1000)

                self._ladder.evaluate(
                    lambda a: self._read_coil_bit(a),
                    lambda a: self._read_discrete_bit(a),
                    dt_ms,
                )

                latch = self._ladder.latch_state
                for addr, state in latch.items():
                    if state:
                        self._write_coil_bit(addr, True)
                    else:
                        null_coils = set()
                        for r in self._ladder._rungs:
                            if r.coil_addr == addr and r.coil_type == CoilType.NORMAL:
                                break
                        else:
                            if addr not in self._ladder._rungs:
                                self._write_coil_bit(addr, False)

            except Exception as e:
                log.error(f"[{self.name}] scan cycle error: {e}")

            elapsed = time.time() - cycle_start
            sleep_time = self._scan_interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)

    def _read_coil_bit(self, addr):
        if addr < 0 or addr >= 65536 * 8:
            return False
        bi, bj = addr // 8, addr % 8
        bi = min(bi, len(self.coils) - 1)
        return bool(self.coils[bi] & (1 << bj))

    def _write_coil_bit(self, addr, val):
        if addr < 0 or addr >= 65536 * 8:
            return
        bi, bj = addr // 8, addr % 8
        bi = min(bi, len(self.coils) - 1)
        if val:
            self.coils[bi] |= 1 << bj
        else:
            self.coils[bi] &= ~(1 << bj)

    def _read_discrete_bit(self, addr):
        if addr < 0 or addr >= 65536 * 8:
            return False
        bi, bj = addr // 8, addr % 8
        bi = min(bi, len(self.discrete_inputs) - 1)
        return bool(self.discrete_inputs[bi] & (1 << bj))

    @property
    def ladder(self):
        return self._ladder

    def add_diag_event(self, event_type, details=""):
        with self.diagnostic_buffer_lock:
            self.diagnostic_buffer.append({
                "timestamp": time.time(),
                "event_type": event_type,
                "details": details,
            })

    def get_diag_events(self, count=None):
        with self.diagnostic_buffer_lock:
            events = list(self.diagnostic_buffer)
        if count is not None:
            events = events[-count:]
        return events

    def clear_diag_events(self):
        with self.diagnostic_buffer_lock:
            self.diagnostic_buffer.clear()
        self.add_diag_event("DIAG_CLEARED", "diagnostic buffer manually cleared")

    def _check_rate(self, conn_key):
        now = time.time()
        with self._rate_lock:
            window = self._rate_windows[conn_key]
            window = [t for t in window if now - t < 1.0]
            self._rate_windows[conn_key] = window
            if len(window) >= MAX_REQ_PER_SEC:
                return False
            window.append(now)
            return True

    def _track_transaction(self, tid):
        now = time.time()
        key = threading.get_ident()
        with self._transactions_lock:
            if tid in self._transactions:
                prev = self._transactions[tid]
                if now - prev["timestamp"] < 5.0:
                    log.warning(f"[Transaction] TID {tid} retry detected "
                                f"(prev={prev['tid']}, elapsed={now - prev['timestamp']:.3f}s)")
                self._transactions[tid]["retry_count"] = prev.get("retry_count", 0) + 1
            self._transactions[tid] = {
                "tid": tid,
                "timestamp": now,
                "thread": key,
                "retry_count": self._transactions[tid].get("retry_count", 0) if tid in self._transactions else 0,
            }

    def _touch_connection(self, conn_addr):
        with self._conn_last_lock:
            self._conn_last_active[conn_addr] = time.time()

    def _timeout_watcher(self):
        while self._running:
            now = time.time()
            with self._conn_last_lock:
                timed_out = [addr for addr, last in self._conn_last_active.items()
                             if now - last > MAX_IDLE_SECONDS]
                for addr in timed_out:
                    log.warning(f"[{self.name}] connection {addr} idle for "
                                f"{now - self._conn_last_active[addr]:.1f}s, marking timeout")
                    del self._conn_last_active[addr]
                    self.add_diag_event("CONN_TIMEOUT", f"connection={addr}")
            time.sleep(5)

    def _update_bus_counter(self, unit, counter_type):
        with self._bus_counters_lock:
            self._bus_counters[unit][counter_type] += 1

    def get_bus_counters(self):
        with self._bus_counters_lock:
            return dict(self._bus_counters)

    def get_unit_memory(self, unit):
        return self._unit_memory.get(unit, self._unit_memory.get(0))

    def _read_mem(self, mem, addr, count, width=1):
        max_addr = len(mem) // width
        if addr + count > max_addr:
            return self._exc(1, 2)
        if width == 1:
            data = bytearray()
            for i in range(count):
                byte_idx = (addr + i) // 8; bit_idx = (addr + i) % 8
                if i % 8 == 0:
                    data.append(0)
                data[-1] |= ((mem[byte_idx] >> bit_idx) & 1) << (i % 8)
            return bytes([(count + 7) // 8]) + bytes(data)
        data = bytearray()
        for i in range(count):
            off = (addr + i) * 2
            val = struct.unpack(">H", mem[off:off+2])[0] if off + 2 <= len(mem) else 0
            data.extend(struct.pack(">H", val))
        return bytes([count * 2]) + bytes(data)

    def _write_coil(self, addr, val):
        bi, bj = addr // 8, addr % 8
        old_bit = bool(self.coils[bi] & (1 << bj))
        if val:
            self.coils[bi] |= 1 << bj
        else:
            self.coils[bi] &= ~(1 << bj)
        new_bit = bool(self.coils[bi] & (1 << bj))
        if old_bit != new_bit:
            self.add_diag_event("COIL_CHANGE", f"addr={addr} old={int(old_bit)} new={int(new_bit)}")

    def _write_reg(self, addr, val):
        old_bytes = bytes(self.holding_registers[addr*2:addr*2+2])
        struct.pack_into(">H", self.holding_registers, addr * 2, val & 0xFFFF)
        new_bytes = bytes(self.holding_registers[addr*2:addr*2+2])
        if old_bytes != new_bytes:
            self.add_diag_event("REG_CHANGE", f"addr={addr} old={old_bytes.hex()} new={new_bytes.hex()}")

    def _exc(self, func, code):
        return bytes([func | 0x80, code])

    def handle_client(self, conn, addr):
        conn_key = f"{addr[0]}:{addr[1]}"
        self._touch_connection(conn_key)
        buf = b""
        try:
            while self._running:
                try:
                    conn.settimeout(1.0)
                    data = conn.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break

                self._touch_connection(conn_key)
                buf += data

                if self.use_rtu:
                    result = self._handle_rtu_frame(buf, conn, conn_key, addr)
                    if result is not None:
                        buf = result
                else:
                    result = self._handle_tcp_frame(buf, conn, conn_key, addr)
                    if result is not None:
                        buf = result
        except Exception as e:
            log.error(f"[{self.name}] client error {addr}: {e}")
        finally:
            with self._conn_last_lock:
                self._conn_last_active.pop(conn_key, None)
            with self._rate_lock:
                self._rate_windows.pop(conn_key, None)
            try:
                conn.close()
            except Exception:
                pass
            log.info(f"[{self.name}] connection closed {addr}")

    def _handle_tcp_frame(self, buf, conn, conn_key, addr):
        if len(buf) < 7:
            return None
        tid, pid, length, unit = MBAP_HDR.unpack(buf[:7])
        if len(buf) < 6 + length:
            return None

        pdu = buf[7:7+length-1]
        remaining = buf[6+length:]

        if not self._check_rate(conn_key):
            log.warning(f"[{self.name}] rate limit exceeded for {conn_key}")
            resp_pdu = self._exc(pdu[0] if pdu else 0, 6)
            resp = MBAP_HDR.pack(tid, pid, len(resp_pdu) + 1, unit) + resp_pdu
            conn.sendall(resp)
            self._update_bus_counter(unit, "errors")
            return remaining

        self._track_transaction(tid)
        self._update_bus_counter(unit, "total")
        func = pdu[0] if pdu else 0
        resp_pdu = self._process_pdu(func, pdu[1:] if len(pdu) > 1 else b"", unit)

        if (func | 0x80) == resp_pdu[0]:
            self._update_bus_counter(unit, "exceptions")

        if unit != 0:
            resp = MBAP_HDR.pack(tid, pid, len(resp_pdu) + 1, unit) + resp_pdu
            conn.sendall(resp)
        elif self.broadcast_enabled:
            self._update_bus_counter(255, "total")
            log.info(f"[{self.name}] Broadcast function 0x{func:02X} processed")
            self.add_diag_event("BROADCAST", f"func=0x{func:02X} unit={unit}")

        self.add_diag_event("REQUEST", f"func=0x{func:02X} unit={unit} tid={tid}")
        return remaining

    def _handle_rtu_frame(self, buf, conn, conn_key, addr):
        if len(buf) < 4:
            return None
        unit = buf[0]
        func = buf[1]
        if func in {1, 2, 3, 4} and len(buf) >= 8:
            length_expected = 2 + ((buf[4] * 256 + buf[5] + 7) // 8) + 2 if func in {1, 2} else 2 + buf[4] * 256 + buf[5] * 2 + 2
        elif func in {5, 6} and len(buf) >= 8:
            length_expected = 8
        elif func == 15 and len(buf) >= 8:
            length_expected = 7 + buf[6] + 2
        elif func == 16 and len(buf) >= 8:
            length_expected = 7 + buf[6] + 2
        else:
            length_expected = len(buf)
        if len(buf) < length_expected:
            return None

        full_frame = buf[:length_expected]
        pdu = full_frame[1:length_expected-2]
        remaining = buf[length_expected:]

        if not self._check_rate(conn_key):
            log.warning(f"[{self.name}] RTU rate limit exceeded for {conn_key}")
            resp_pdu = self._exc(pdu[0] if pdu else 0, 6)
            resp_frame = bytes([unit]) + resp_pdu
            crc = crc16(resp_frame)
            conn.sendall(resp_frame + struct.pack("<H", crc))
            self._update_bus_counter(unit, "errors")
            return remaining

        self._update_bus_counter(unit, "total")
        resp_pdu = self._process_pdu(func, pdu[1:] if len(pdu) > 1 else b"", unit)

        if (func | 0x80) == resp_pdu[0]:
            self._update_bus_counter(unit, "exceptions")

        resp_frame = bytes([unit]) + resp_pdu
        try:
            crc = crc16(resp_frame)
        except Exception:
            crc = 0
        conn.sendall(resp_frame + struct.pack("<H", crc))
        self.add_diag_event("REQUEST", f"RTU func=0x{func:02X} unit={unit}")
        return remaining

    def _process_pdu(self, func, data, unit=1):
        try:
            log.debug(f"Func 0x{func:02X} unit={unit} data={data.hex() if data else ''}")
            if func == 1:
                a, c = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                if c < 1 or c > 2000:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.coils, a, c, 1)
            elif func == 2:
                a, c = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                if c < 1 or c > 2000:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.discrete_inputs, a, c, 1)
            elif func == 3:
                a, c = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                if c < 1 or c > 125:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.holding_registers, a, c, 2)
            elif func == 4:
                a, c = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                if c < 1 or c > 125:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.input_registers, a, c, 2)
            elif func == 5:
                a, v = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                self._write_coil(a, v == 0xFF00)
                return bytes([func]) + struct.pack(">HH", a, v)
            elif func == 6:
                a, v = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                self._write_reg(a, v)
                return bytes([func]) + struct.pack(">HH", a, v)
            elif func == 7:
                status = self.exception_status
                return bytes([func, status])
            elif func == 8:
                sub = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else 0
                req_data = data[2:4] if len(data) >= 4 else b"\x00\x00"
                return self._handle_diagnostics(sub, req_data, unit)
            elif func == 11:
                status, events = 0x0000, self.diag_counters.get(11, 0)
                return bytes([func]) + struct.pack(">HH", status, events & 0xFFFF)
            elif func == 12:
                events = struct.pack(">HH", 0x0006, self.diag_counters.get(11, 0) & 0xFFFF)
                return bytes([func, len(events)]) + events + bytes([0, 0, 0, 0, 0, 0])
            elif func == 15:
                a, c = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                if c < 1 or c > 1968:
                    return self._exc(func, 3)
                for i in range(c):
                    byte_idx = (a + i) // 8; bit_idx = (a + i) % 8
                    byte_val = data[5 + i // 8] if 5 + i // 8 < len(data) else 0
                    if (byte_val >> (i % 8)) & 1:
                        self.coils[byte_idx] |= 1 << bit_idx
                    else:
                        self.coils[byte_idx] &= ~(1 << bit_idx)
                self.add_diag_event("MULTI_COIL_WRITE", f"addr={a} count={c}")
                return bytes([func]) + struct.pack(">HH", a, c)
            elif func == 16:
                a, c = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                if c < 1 or c > 123:
                    return self._exc(func, 3)
                for i in range(c):
                    off = 5 + i * 2
                    if off + 2 <= len(data):
                        self._write_reg(a + i, struct.unpack(">H", data[off:off+2])[0])
                self.add_diag_event("MULTI_REG_WRITE", f"addr={a} count={c}")
                return bytes([func]) + struct.pack(">HH", a, c)
            elif func == 17:
                server_id = self.server_id
                return bytes([func, len(server_id)]) + server_id + struct.pack(">H", 0x00FF)
            elif func == 20:
                return self._handle_read_file_record(data)
            elif func == 21:
                return self._handle_write_file_record(data)
            elif func == 22:
                a, and_mask, or_mask = struct.unpack(">HHH", data[:6]) if len(data) >= 6 else (0, 0, 0)
                cur = struct.unpack(">H", self.holding_registers[a*2:a*2+2])[0] if a * 2 + 2 <= len(self.holding_registers) else 0
                new_val = (cur & and_mask) | (or_mask & 0xFFFF)
                self._write_reg(a, new_val)
                return bytes([func]) + struct.pack(">HHH", a, and_mask, or_mask)
            elif func == 23:
                ra, rc = struct.unpack(">HH", data[:4]) if len(data) >= 4 else (0, 0)
                wa, wc = struct.unpack(">HH", data[4:8]) if len(data) >= 8 else (0, 0)
                for i in range(wc):
                    off = 9 + i * 2
                    if off + 2 <= len(data):
                        self._write_reg(wa + i, struct.unpack(">H", data[off:off+2])[0])
                read_data = self._read_mem(self.holding_registers, ra, rc, 2)
                return bytes([func]) + read_data[1:] if read_data else bytes([func])
            elif func == 24:
                count = self.fifo_buffer[0] if self.fifo_buffer[0] <= 31 else 0
                values = self.fifo_buffer[1:1+count] if count else []
                resp = struct.pack(">HH", 2 + count * 2, count)
                for v in values:
                    resp += struct.pack(">H", v)
                return bytes([func]) + resp
            elif func == 43:
                return self._handle_mei(data, unit)
            else:
                return self._exc(func, 1)
        except struct.error:
            return self._exc(func, 2)
        except Exception as e:
            log.error(f"Error processing func 0x{func:02X}: {e}")
            self.exception_status |= EXC_STATUS_PLCFAULT
            return self._exc(func, 4)

    def _handle_diagnostics(self, sub, data, unit):
        log.info(f"Diagnostics sub=0x{sub:04X} ({DIAG_SUBFUNC.get(sub, 'Unknown')}) unit={unit}")
        self.add_diag_event("DIAGNOSTICS", f"sub=0x{sub:04X} unit={unit}")
        if sub == 0:
            return bytes([8]) + struct.pack(">HH", sub, struct.unpack(">H", data)[0] if len(data) >= 2 else 0)
        elif sub == 1:
            log.warning("Restart Communications Option executed")
            self.diag_register = 0
            for k in self.diag_counters:
                self.diag_counters[k] = 0
            return bytes([8]) + struct.pack(">HH", sub, 0xFF00)
        elif sub == 2:
            return bytes([8]) + struct.pack(">HH", sub, self.diag_register)
        elif sub == 3:
            return bytes([8]) + struct.pack(">HH", sub, struct.unpack(">H", data)[0] if len(data) >= 2 else 0)
        elif sub == 4:
            log.warning("Force Listen Only Mode")
            self.exception_status |= EXC_STATUS_COMMFAULT
            return bytes([8]) + struct.pack(">HH", sub, struct.unpack(">H", data)[0] if len(data) >= 2 else 0)
        elif sub == 10:
            for k in self.diag_counters:
                self.diag_counters[k] = 0
            self.diag_register = 0
            return bytes([8]) + struct.pack(">HH", sub, 0x0000)
        elif sub in self.diag_counters:
            return bytes([8]) + struct.pack(">HH", sub, self.diag_counters[sub] & 0xFFFF)
        elif sub == 20:
            return bytes([8]) + struct.pack(">HH", sub, 0x0000)
        elif sub == 21:
            return bytes([8]) + struct.pack(">HH", sub, 0x0000)
        else:
            return self._exc(8, 3)

    def _handle_read_file_record(self, data):
        results = bytearray()
        off = 1
        while off + 7 <= len(data):
            ref_type = data[off]
            file_num = struct.unpack(">H", data[off+1:off+3])[0]
            rec_num = struct.unpack(">H", data[off+3:off+5])[0]
            rec_len = struct.unpack(">H", data[off+5:off+7])[0]
            off += 7
            if file_num in self.file_records:
                rec = self.file_records[file_num]
                start = rec_num * 2
                end = start + rec_len * 2
                if end <= len(rec):
                    results.append(ref_type)
                    results.append(rec_len)
                    results.extend(rec[start:end])
        return bytes([20]) + bytes([len(results)]) + bytes(results)

    def _handle_write_file_record(self, data):
        off = 1
        while off + 7 <= len(data):
            ref_type = data[off]
            file_num = struct.unpack(">H", data[off+1:off+3])[0]
            rec_num = struct.unpack(">H", data[off+3:off+5])[0]
            rec_len = struct.unpack(">H", data[off+5:off+7])[0]
            off += 7
            if file_num in self.file_records:
                rec = self.file_records[file_num]
                start = rec_num * 2
                end = start + rec_len * 2
                if end <= len(rec) and off + rec_len * 2 <= len(data):
                    rec[start:end] = data[off:off+rec_len*2]
                off += rec_len * 2
            else:
                off += rec_len * 2
        response_data = data[:1+min(off, len(data))]
        return bytes([21]) + response_data[:1] + response_data[1:min(len(response_data), 250)]

    def _handle_mei(self, data, unit):
        if len(data) < 2:
            return self._exc(43, 3)
        mei_type = data[0]
        if mei_type != 0x0E:
            return self._exc(43, 3)
        read_code = data[1]
        obj_id = data[2] if len(data) > 2 else 0
        if read_code == 0x01:
            more = 0 if obj_id >= max(self.device_id_data) else 0x01
            count = len([k for k in self.device_id_data if k <= obj_id])
        elif read_code == 0x02:
            more = 0
            count = 1 if obj_id in self.device_id_data else 0
        elif read_code == 0x03:
            more = 0
            count = len(self.device_id_data)
        elif read_code == 0x04:
            values = b"".join(self.device_id_data[k] for k in sorted(self.device_id_data))
            resp = bytes([0x0E, read_code, 0x01, 0x00]) + bytes([len(self.device_id_data)])
            resp += bytes([0x00, 0x00, len(values)]) + values
            return bytes([43]) + resp
        else:
            return self._exc(43, 3)
        resp = bytes([0x0E, read_code, 0x00, 0x00, count])
        for oid in sorted(self.device_id_data):
            val = self.device_id_data[oid]
            resp += bytes([oid, 0x00, len(val)]) + val
        return bytes([43]) + resp


class ModbusRtuSimulator(ModbusSimulator):
    def __init__(self, host="0.0.0.0", port=5021):
        super().__init__(host, port, use_rtu=True)


if __name__ == "__main__":
    sim = ModbusSimulator()
    sim._ladder.add_rung(LadderRung(1, [(0, ContactType.NORMAL_OPEN)], 100,
                                     CoilType.NORMAL))
    sim._ladder.add_rung(LadderRung(2, [(100, ContactType.NORMAL_OPEN)], 200,
                                     CoilType.NORMAL,
                                     timer={"type": 0, "preset_ms": 1000}))
    sim._ladder.add_rung(LadderRung(3, [(1, ContactType.RISING_EDGE)], 101,
                                     CoilType.LATCH_SET))
    sim._ladder.add_rung(LadderRung(4, [(2, ContactType.NORMAL_OPEN)], 101,
                                     CoilType.LATCH_RESET))
    sim.start()
    log.info("ModbusSimulator running with ladder logic (3 rungs + reset)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        sim.stop()
