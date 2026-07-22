"""
S7COMM (Siemens S7) 协议模拟器 — 完整版
支持: COTP连接管理, S7 Setup/Read/Write, PLC控制(STOP/START),
      扫描周期仿真(OB1/PII/PIQ), 块管理器, 定时器/计数器,
      诊断缓冲区, 保护级别, 多机架, CPU状态字, 循环数据更新
"""
import socket, threading, struct, logging, time, datetime, math, random, queue

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("S7Sim")

TPKT = struct.Struct(">BBH")
CPU_STATE = {0: "STOP", 1: "STOP", 4: "RUN", 0x10: "STARTUP", 0x20: "HOLD"}
AREA_NAMES = {0x81: "PE", 0x82: "PA", 0x83: "MK", 0x84: "DB", 0x85: "DI", 0x86: "LB", 0x87: "LD"}


class DiagnosticEntry:
    def __init__(self, event_class, ob_number, details=""):
        self.timestamp = datetime.datetime.now()
        self.event_class = event_class
        self.ob_number = ob_number
        self.details = details

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_class": self.event_class,
            "ob_number": self.ob_number,
            "details": self.details,
        }

    def __repr__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S.%f')[:-3]}] OB{self.ob_number} class={self.event_class} {self.details}"


class DiagnosticBuffer:
    def __init__(self, max_entries=100):
        self.max_entries = max_entries
        self.entries = []

    def add(self, event_class, ob_number, details=""):
        entry = DiagnosticEntry(event_class, ob_number, details)
        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]
        return entry

    def get_recent(self, count=10):
        return self.entries[-count:]

    def clear(self):
        self.entries = []


class Timer:
    def __init__(self, number):
        self.number = number
        self.sv = 0
        self.remaining = 0
        self.running = False
        self.enabled = False

    def tick(self, delta_ms=100):
        if self.running and self.remaining > 0:
            self.remaining = max(0, self.remaining - delta_ms)
            if self.remaining == 0:
                self.running = False
                return True
        return False

    def start(self, value_ms):
        self.sv = value_ms
        self.remaining = value_ms
        self.running = True
        self.enabled = True

    def reset(self):
        self.sv = 0
        self.remaining = 0
        self.running = False
        self.enabled = False

    def to_dict(self):
        return {
            "number": self.number,
            "sv": self.sv,
            "remaining": self.remaining,
            "running": self.running,
            "enabled": self.enabled,
        }


class Counter:
    def __init__(self, number):
        self.number = number
        self.preset = 0
        self.current = 0
        self.enabled = False
        self.overflow = False

    def set_preset(self, value):
        self.preset = value
        self.current = value

    def count_up(self):
        if not self.enabled:
            return
        self.current += 1
        if self.current > 999:
            self.current = 0
            self.overflow = True

    def count_down(self):
        if not self.enabled:
            return
        self.current -= 1
        if self.current < 0:
            self.current = 999
            self.overflow = True

    def reset(self):
        self.preset = 0
        self.current = 0
        self.enabled = False
        self.overflow = False

    def to_dict(self):
        return {
            "number": self.number,
            "preset": self.preset,
            "current": self.current,
            "enabled": self.enabled,
        }


class S7Block:
    def __init__(self, block_type, number, size=256):
        self.block_type = block_type
        self.number = number
        self.size = size
        self.data = bytearray(size)
        self.protected = False
        self.password = ""

    def read(self, offset, length):
        if offset + length > len(self.data):
            length = len(self.data) - offset
        if length <= 0:
            return b""
        return bytes(self.data[offset:offset + length])

    def write(self, offset, data):
        if offset + len(data) > len(self.data):
            return False
        self.data[offset:offset + len(data)] = data
        return True


class S7DataBlock:
    def __init__(self, number, size=1024):
        self.number = number
        self.size = size
        self.data = bytearray(size)
        self.protected = False
        self.password = ""
        self._init_defaults()

    def _init_defaults(self):
        for i in range(0, min(len(self.data), 256), 4):
            struct.pack_into(">f", self.data, i, random.uniform(0, 100))
        struct.pack_into(">f", self.data, 0, 25.0)
        struct.pack_into(">f", self.data, 4, 100.0)
        struct.pack_into(">f", self.data, 8, 50.0)
        struct.pack_into(">H", self.data, 12, 1)

    def read(self, offset, length):
        if offset + length > len(self.data):
            length = len(self.data) - offset
        if length <= 0:
            return b""
        return bytes(self.data[offset:offset + length])

    def write(self, offset, data):
        if offset + len(data) > len(self.data):
            return False
        self.data[offset:offset + len(data)] = data
        return True


class BaseSim:
    def __init__(self, host="0.0.0.0", port=102, name="Sim"):
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
        self._on_start()
        log.info(f"[{self.name}] listening on {self.host}:{self.port}")

    def _on_start(self):
        pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info(f"[{self.name}] connection from {addr}")
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                if self._running:
                    continue
                break

    def stop(self):
        self._running = False
        self._on_stop()
        if self._server:
            try:
                self._server.close()
            except Exception:
                pass
        log.info(f"[{self.name}] stopped")

    def _on_stop(self):
        pass

    def handle_client(self, conn, addr):
        raise NotImplementedError


class S7CommSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=102):
        super().__init__(host, port, "S7COMM")
        self._init_state()
        self._scan_thread = None
        self._scan_running = False
        self._scan_interval = 0.1
        self._sim_time = time.time()

    # ── state initialisation ──────────────────────────────────────────
    def _init_state(self):
        self.cpu_state = 0x04
        self.cpu_substate = 0x00
        self.cpu_status_word = 0x0200
        self.session_id = 0
        self.pdu_length = 480
        self.max_amq = 5
        self.max_amq_caller = 5
        self.partner = {}
        self.cotp_src_ref = 0
        self.cotp_dst_ref = 0
        self.connected = False
        self.setup_done = False
        self.password = ""
        self.protection_level = 0
        self._block_download_active = False
        self._block_download_buffer = b""

        self.data_blocks = {}
        for n, sz in [(1, 2048), (2, 1024), (3, 512), (4, 4096), (5, 256),
                       (6, 1024), (7, 512), (8, 256), (9, 128), (10, 8192)]:
            self.data_blocks[n] = S7DataBlock(n, sz)

        self.blocks = {}
        self.blocks["OB1"] = S7Block("OB", 1, 512)
        self.blocks["OB100"] = S7Block("OB", 100, 256)
        self.blocks["FB1"] = S7Block("FB", 1, 256)
        self.blocks["FC1"] = S7Block("FC", 1, 256)

        self.pii = bytearray(65536)
        self.piq = bytearray(65536)
        self.merker = bytearray(65536)
        self.inputs = bytearray(65536)
        self.outputs = bytearray(65536)

        self.timers = {i: Timer(i) for i in range(256)}
        self.counters = {i: Counter(i) for i in range(256)}

        self.diag_buffer = DiagnosticBuffer(100)

        self.racks = {
            0: {2: "CPU 1516-3 PN/DP"},
            1: {4: "DI 16x24VDC (16B input)"},
        }

        self._init_timers()
        self._init_diagnostics()

    def _init_timers(self):
        rng = random.Random(42)
        for i in range(10):
            t = self.timers[i]
            t.start(rng.randint(1000, 60000))
        for i in range(10):
            c = self.counters[i]
            c.set_preset(rng.randint(0, 500))
            c.enabled = True
            c.current = rng.randint(0, c.preset)

    def _init_diagnostics(self):
        self.diag_buffer.add(0x00, 100, "Cold restart")
        self.diag_buffer.add(0x02, 1, "OB1 started – cyclic program execution")
        self.diag_buffer.add(0x03, 80, "Time-of-day interrupt")
        for i in range(3):
            self.diag_buffer.add(0x07, 1, f"Cycle time: {random.randint(5, 25)}ms")

    # ── scan cycle ────────────────────────────────────────────────────
    def _on_start(self):
        self._scan_running = True
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scan_thread.start()
        log.info("[S7COMM] scan cycle started")

    def _on_stop(self):
        self._scan_running = False
        log.info("[S7COMM] scan cycle stopped")

    def _scan_loop(self):
        while self._scan_running:
            cycle_start = time.time()
            try:
                self._scan_cycle()
            except Exception as e:
                log.error(f"scan cycle error: {e}")
            elapsed = time.time() - cycle_start
            sleep_time = max(0, self._scan_interval - elapsed)
            time.sleep(sleep_time)

    def _scan_cycle(self):
        dt = time.time() - self._sim_time
        self._sim_time = time.time()

        self._update_pii()
        self._execute_ob1(dt)
        self._update_piq()
        self._update_timers(int(dt * 1000))
        self._cyclic_data_update(dt)

    def _update_pii(self):
        for rack, slots in self.racks.items():
            for slot, desc in slots.items():
                if "input" in desc.lower() or "DI" in desc:
                    base = rack * 256 + slot * 16
                    for i in range(16):
                        if base + i < len(self.pii):
                            self.pii[base + i] = random.randint(0, 255)

    def _execute_ob1(self, dt):
        translate_len = min(len(self.pii), len(self.piq), 1024)
        for i in range(0, translate_len, 2):
            val = struct.unpack_from(">H", self.pii, i)[0]
            struct.pack_into(">H", self.piq, i, val ^ 0xAAAA)

    def _update_piq(self):
        output_len = min(len(self.piq), len(self.outputs))
        self.outputs[:output_len] = self.piq[:output_len]

    def _update_timers(self, delta_ms):
        for i in range(256):
            expired = self.timers[i].tick(delta_ms)
            if expired and i < 10:
                pass

    def _cyclic_data_update(self, dt):
        now = time.time()
        for db_num in [1, 2, 3]:
            db = self.data_blocks.get(db_num)
            if db is None:
                continue
            for i in range(0, min(db.size, 64), 4):
                base_val = struct.unpack_from(">f", db.data, i)[0] if i + 4 <= db.size else 0
                phase = i * 0.3 + db_num * 1.7
                new_val = base_val + math.sin(now * 0.5 + phase) * 1.5
                struct.pack_into(">f", db.data, i, new_val)

    def _log_diag(self, event_class, ob_number, details=""):
        entry = self.diag_buffer.add(event_class, ob_number, details)
        log.debug(f"DIAG: {entry}")

    # ── TPKT / COTP ─────────────────────────────────────────────────
    def _tpkt(self, payload):
        return TPKT.pack(3, 0, 4 + len(payload)) + payload

    def handle_client(self, conn, addr):
        self._init_state()
        self._log_diag(0x01, 0, f"Connection from {addr[0]}:{addr[1]}")
        buf = b""
        try:
            while True:
                data = conn.recv(8192)
                if not data:
                    break
                buf += data
                while len(buf) >= 4:
                    tpkt_len = struct.unpack(">H", buf[2:4])[0]
                    if len(buf) < tpkt_len:
                        break
                    payload = buf[4:tpkt_len]
                    buf = buf[tpkt_len:]
                    self._handle_payload(conn, payload)
        except Exception:
            pass
        finally:
            conn.close()

    def _handle_payload(self, conn, payload):
        if len(payload) < 2:
            return
        if payload[0] == 0x03 and payload[1] == 0x00:
            log.warning("Nested TPKT, skipping")
            return

        cotp_type = payload[0]

        if cotp_type == 0x11:
            self._handle_cotp_cr(conn, payload)
        elif cotp_type == 0x10:
            self._handle_s7(conn, payload[2:] if len(payload) > 2 else b"")
        elif cotp_type in (0x01, 0x02):
            log.info("COTP ED/SR (expedited data)")
        elif cotp_type == 0xc0:
            log.info("COTP UD (unit data)")
        else:
            log.warning(f"Unknown COTP type 0x{cotp_type:02X}")

    def _handle_cotp_cr(self, conn, payload):
        if len(payload) < 6:
            return
        dst_ref = struct.unpack(">H", payload[2:4])[0]
        src_ref = struct.unpack(">H", payload[4:6])[0]
        self.cotp_dst_ref = dst_ref
        self.cotp_src_ref = src_ref

        tsap_src = payload[16:18] if len(payload) > 17 else b"\x01\x02"
        tsap_dst = payload[19:21] if len(payload) > 20 else b"\x01\x00"

        src_tsap = struct.unpack(">H", tsap_src)[0]
        dst_tsap = struct.unpack(">H", tsap_dst)[0]
        transport = {0x0100: "PG", 0x0102: "PG", 0x0101: "OP", 0x0110: "OP"}.get(
            src_tsap, f"0x{src_tsap:04X}"
        )

        log.info(
            f"COTP CR: src_ref={src_ref} dst_ref={dst_ref} "
            f"{transport} (src_tsap=0x{src_tsap:04X} dst_tsap=0x{dst_tsap:04X})"
        )

        cc_payload = bytes([
            0x11, 0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a,
            0xc1, 0x02, tsap_src[0], tsap_src[1],
            0xc2, 0x02, tsap_dst[0], tsap_dst[1],
        ])
        self.connected = True
        conn.sendall(self._tpkt(cc_payload))

    # ── S7 routing ───────────────────────────────────────────────────
    def _handle_s7(self, conn, data):
        if len(data) < 2:
            return
        func = data[1]
        handlers = {
            0x01: self._handle_s7_setup,
            0x04: self._handle_s7_read,
            0x05: self._handle_s7_write,
            0x00: self._handle_s7_control,
            0x1a: self._handle_s7_control,
            0x1c: self._handle_s7_block,
            0x1d: self._handle_s7_block_list,
            0x1f: self._handle_s7_time,
            0x21: self._handle_s7_password,
            0x22: self._handle_s7_force_stop,
            0x28: self._handle_s7_szl,
            0x29: self._handle_s7_szl,
        }
        handler = handlers.get(func)
        if handler:
            handler(conn, data)
        else:
            log.warning(f"Unknown S7 function 0x{func:02X}")

    # ── setup ────────────────────────────────────────────────────────
    def _handle_s7_setup(self, conn, data):
        request_id = data[4:6] if len(data) > 5 else b"\x00\x00"
        if len(data) > 9:
            self.max_amq_caller = struct.unpack(">H", data[6:8])[0]
        if len(data) > 11:
            pdu_len = struct.unpack(">H", data[10:12])[0]
            self.pdu_length = min(pdu_len, 480)

        log.info(f"S7 Setup: pdu_len={self.pdu_length} amq={self.max_amq_caller}")

        resp = bytearray([0x32, 0x01, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend(struct.pack(">H", 0x0000))
        resp.extend(struct.pack(">H", self.max_amq))
        resp.extend(struct.pack(">H", self.pdu_length))
        resp.extend(b"\x00" * 12)
        self.setup_done = True
        conn.sendall(self._tpkt(bytes(resp)))

    # ── read ─────────────────────────────────────────────────────────
    def _handle_s7_read(self, conn, data):
        request_id = data[4:6]
        count = data[7] if len(data) > 7 else 1
        log.info(f"S7 Read: {count} item(s)")

        results = bytearray()
        off = 12
        for _ in range(count):
            if off + 10 > len(data):
                break
            length = struct.unpack(">H", data[off + 2:off + 4])[0]
            db_num = struct.unpack(">H", data[off + 4:off + 6])[0]
            area = data[off + 5]
            address = struct.unpack(">H", data[off + 6:off + 8])[0]
            off += 10

            area_name = AREA_NAMES.get(area, f"0x{area:02X}")
            log.debug(f"  Read: area={area_name} db={db_num} addr={address} len={length}")

            results.append(0xff)
            val = self._read_area(area, db_num, address, length)
            results.extend(val)

        resp = bytearray([0x32, 0x04, 0x00, 0x00])
        resp.extend(request_id)
        resp.append(0x00)
        resp.append(count)
        resp.extend(results)
        conn.sendall(self._tpkt(bytes(resp)))

    def _read_area(self, area, db_num, address, length):
        if area == 0x84 and db_num in self.data_blocks:
            return self.data_blocks[db_num].read(address, length)
        if area == 0x83 and address + length <= len(self.merker):
            return bytes(self.merker[address:address + length])
        if area == 0x81 and address + length <= len(self.inputs):
            return bytes(self.inputs[address:address + length])
        if area == 0x82 and address + length <= len(self.outputs):
            return bytes(self.outputs[address:address + length])
        return b"\x00" * length

    # ── write ────────────────────────────────────────────────────────
    def _handle_s7_write(self, conn, data):
        request_id = data[4:6]
        count = data[7] if len(data) > 7 else 1
        log.info(f"S7 Write: {count} item(s)")

        if self.protection_level >= 2:
            log.warning(f"S7 Write blocked – protection level {self.protection_level}")
            self._send_error(conn, request_id, 0x05, 0x04)
            return

        off = 12
        for _ in range(count):
            if off + 10 > len(data):
                break
            length = struct.unpack(">H", data[off + 2:off + 4])[0]
            db_num = struct.unpack(">H", data[off + 4:off + 6])[0]
            area = data[off + 5]
            address = struct.unpack(">H", data[off + 6:off + 8])[0]
            val_len = data[off + 10] if off + 10 < len(data) else length
            val_start = off + 11
            off += 10
            val_data = data[val_start:val_start + val_len] if val_start + val_len <= len(data) else b""

            area_name = AREA_NAMES.get(area, f"0x{area:02X}")
            log.info(f"  Write: area={area_name} db={db_num} addr={address} len={val_len}")

            self._write_area(area, db_num, address, val_data)
            self._log_diag(0x04, 1, f"Write {area_name} DB{db_num} addr={address} len={val_len}")
            off += val_len - 1

        resp = bytearray([0x32, 0x05, 0x00, 0x00])
        resp.extend(request_id)
        resp.append(0x00)
        resp.append(count)
        resp.extend(bytes([0xff] * count))
        conn.sendall(self._tpkt(bytes(resp)))

    def _write_area(self, area, db_num, address, data):
        if area == 0x84 and db_num in self.data_blocks:
            self.data_blocks[db_num].write(address, data)
            return True
        if area == 0x83 and address + len(data) <= len(self.merker):
            self.merker[address:address + len(data)] = data
            return True
        if area == 0x82 and address + len(data) <= len(self.outputs):
            self.outputs[address:address + len(data)] = data
            return True
        return False

    def _send_error(self, conn, request_id, func, error_code):
        resp = bytearray([0x32, func, error_code, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    # ── control ──────────────────────────────────────────────────────
    def _handle_s7_control(self, conn, data):
        if len(data) < 8:
            return
        request_id = data[4:6]
        sub_type = data[6] if len(data) > 6 else 0

        ctrl_names = {0x01: "PING", 0x04: "STOP", 0x05: "HOT_START",
                      0x07: "COLD_START", 0x08: "RUN", 0x10: "PING"}
        name = ctrl_names.get(sub_type, f"0x{sub_type:02X}")
        log.info(f"S7 Control: {name}")

        prev_state = self.cpu_state

        if sub_type == 0x04:
            self.cpu_state = 0x00
            self.cpu_status_word = 0x0000
            self._log_diag(0x08, 1, "PLC STOP requested via S7")
            log.warning("PLC -> STOP")
        elif sub_type in {0x05, 0x07}:
            self.cpu_state = 0x10
            self._log_diag(0x08, 1, f"PLC {name} requested via S7")
            log.warning(f"PLC -> {name}")
            t = threading.Timer(2.0, self._transition_to_run)
            t.daemon = True
            t.start()
        elif sub_type == 0x08:
            self._transition_to_run()

        if self.cpu_state != prev_state:
            self._log_diag(0x09, 1,
                           f"CPU state transition: {CPU_STATE.get(prev_state, 'UNKNOWN')} -> "
                           f"{CPU_STATE.get(self.cpu_state, 'UNKNOWN')}")

        err_code = 0x80 if sub_type == 0x04 else 0x00
        resp = bytearray([0x32, 0x00, err_code, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    def _handle_s7_force_stop(self, conn, data):
        log.critical("S7 Force STOP received!")
        self.cpu_state = 0x00
        self.cpu_status_word = 0x0000
        request_id = data[4:6] if len(data) > 5 else b"\x00\x00"
        resp = bytearray([0x32, 0x22, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    def _transition_to_run(self):
        self.cpu_state = 0x04
        self.cpu_status_word = 0x0200
        log.warning("PLC -> RUN")

    # ── block ────────────────────────────────────────────────────────
    def _handle_s7_block(self, conn, data):
        if len(data) < 10:
            return
        request_id = data[4:6]
        sub_func = data[6] if len(data) > 6 else 0

        sub_names = {0x01: "List blocks", 0x02: "Block info", 0x03: "Start upload",
                     0x04: "Upload", 0x05: "End upload", 0x06: "Start download",
                     0x07: "Download", 0x08: "End download", 0x09: "Delete block"}
        name = sub_names.get(sub_func, f"0x{sub_func:02X}")
        log.info(f"S7 Block: {name}")
        self._log_diag(0x05, 1, f"Block {name} operation")

        resp = bytearray([0x32, 0x1c, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    def _handle_s7_block_list(self, conn, data):
        request_id = data[4:6] if len(data) > 5 else b"\x00\x00"
        log.info("S7 Block list request")
        resp = bytearray([0x32, 0x1d, 0x00, 0x00])
        resp.extend(request_id)
        block_list = bytearray()
        for name, blk in self.blocks.items():
            block_list.append(ord(name[0]))
            block_list.append(ord(name[1]) if len(name) > 1 else 0)
            block_list.append(blk.number)
            block_list.append(0x01)
            block_list.extend(struct.pack(">I", blk.size))
        resp.extend(struct.pack(">H", len(block_list) // 10))
        resp.extend(block_list)
        conn.sendall(self._tpkt(bytes(resp)))

    # ── time ─────────────────────────────────────────────────────────
    def _handle_s7_time(self, conn, data):
        now = datetime.datetime.now()
        resp = bytearray([0x32, 0x1f, 0x00, 0x00])
        resp.extend(data[4:6])
        resp.extend([0x00, 0x00, 0x00, 0x0a])
        resp.extend(struct.pack("<H", now.year))
        resp.extend([now.month, now.day, now.hour, now.minute, now.second, 0, 0])
        resp.extend(struct.pack("<H", 0x0000))
        conn.sendall(self._tpkt(bytes(resp)))

    # ── password ─────────────────────────────────────────────────────
    def _handle_s7_password(self, conn, data):
        log.warning("S7 Password attempt")
        resp = bytearray([0x32, 0x21, 0x00, 0x00])
        resp.extend(data[4:6])
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    # ── SZL ──────────────────────────────────────────────────────────
    def _handle_s7_szl(self, conn, data):
        request_id = data[4:6]
        szl_id = struct.unpack(">H", data[8:10])[0] if len(data) > 9 else 0
        szl_index = struct.unpack(">H", data[10:12])[0] if len(data) > 11 else 0
        log.info(f"S7 SZL Read: id=0x{szl_id:04X} idx=0x{szl_index:04X}")

        resp = bytearray([0x32, 0x28, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])

        if szl_id == 0x0011 and szl_index == 0x0001:
            resp.extend(self._szl_cpu_status())
        elif szl_id == 0x0013 and szl_index == 0x0000:
            resp.extend(self._szl_module_info())
        elif szl_id == 0x001C:
            resp.extend(self._szl_diag_buffer(szl_index))
        elif szl_id == 0x0232 and szl_index == 0x0004:
            resp.extend(self._szl_protection())
        else:
            resp.extend([0x10, 0x00, 0x04, 0x00, 0x00, 0x00])
            resp.extend(struct.pack(">f", 25.0))

        conn.sendall(self._tpkt(bytes(resp)))

    def _szl_cpu_status(self):
        buf = bytearray()
        buf.extend(struct.pack(">H", 0x0011))
        buf.extend(struct.pack(">H", 0x0001))
        buf.extend(struct.pack(">H", 4))
        buf.extend(struct.pack(">H", 4))
        buf.extend(struct.pack(">H", self.cpu_status_word))
        buf.extend(struct.pack(">H", 0x0000))
        return buf

    def _szl_module_info(self):
        buf = bytearray()
        buf.extend(struct.pack(">H", 0x0013))
        buf.extend(struct.pack(">H", 0x0000))
        buf.extend(struct.pack(">H", 6))
        buf.extend(struct.pack(">H", 6))
        buf.extend([0x00, 0x02])
        buf.extend([0x00, 0x00, 0x00, 0x00])
        return buf

    def _szl_diag_buffer(self, index):
        entries = self.diag_buffer.get_recent(10)
        buf = bytearray()
        buf.extend(struct.pack(">H", 0x001C))
        buf.extend(struct.pack(">H", index))
        buf.extend(struct.pack(">H", len(entries) * 16))
        buf.extend(struct.pack(">H", len(entries) * 16))
        for e in entries:
            buf.extend(struct.pack(">H", e.ob_number))
            buf.extend(struct.pack(">H", e.event_class))
            buf.extend(struct.pack(">I", 0))
            buf.extend(struct.pack(">Q", 0))
        return buf

    def _szl_protection(self):
        buf = bytearray()
        buf.extend(struct.pack(">H", 0x0232))
        buf.extend(struct.pack(">H", 0x0004))
        buf.extend(struct.pack(">H", 4))
        buf.extend(struct.pack(">H", 4))
        buf.extend(struct.pack(">H", self.protection_level))
        buf.extend([0x00, 0x00])
        return buf


if __name__ == "__main__":
    s = S7CommSimulator()
    s.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
