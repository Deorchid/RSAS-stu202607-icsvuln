"""
S7COMM 漏洞模拟器 — 未授权控制、密码后门、块注入、诊断抑制、
                  伪CPU状态、定时器溢出、过程映像劫持
"""
import socket
import threading
import struct
import logging
import time
import datetime
import math
import random

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("S7Vuln")

TPKT = struct.Struct(">BBH")
AREA_NAMES = {0x81: "PE", 0x82: "PA", 0x83: "MK", 0x84: "DB", 0x85: "DI", 0x86: "LB", 0x87: "LD"}


class S7DataBlock:
    def __init__(self, number, size=1024):
        self.number = number
        self.size = size
        self.data = bytearray(size)
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


class DiagnosticEntry:
    def __init__(self, event_class, ob_number, details=""):
        self.timestamp = datetime.datetime.now()
        self.event_class = event_class
        self.ob_number = ob_number
        self.details = details


class DiagnosticBuffer:
    def __init__(self, max_entries=100):
        self.max_entries = max_entries
        self.entries = []

    def add(self, event_class, ob_number, details=""):
        entry = DiagnosticEntry(event_class, ob_number, details)
        self.entries.append(entry)
        if len(self.entries) > self.max_entries:
            self.entries = self.entries[-self.max_entries:]

    def get_recent(self, count=10):
        return self.entries[-count:]


class Timer:
    def __init__(self, number):
        self.number = number
        self.sv = 0
        self.remaining = 0
        self.running = False

    def tick(self, delta_ms=100):
        if self.running and self.remaining > 0:
            self.remaining = max(0, self.remaining - delta_ms)
            if self.remaining == 0:
                self.running = False
                return True
        return False

    def set(self, value_ms):
        self.sv = value_ms
        self.remaining = value_ms
        self.running = True


class Counter:
    def __init__(self, number):
        self.number = number
        self.preset = 0
        self.current = 0
        self.enabled = False

    def set(self, preset):
        self.preset = preset
        self.current = preset


class BaseSim:
    def __init__(self, host="0.0.0.0", port=102, name="Sim"):
        self.host = host
        self.port = port
        self.name = name
        self._server = None
        self._running = False

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        self._server.bind((self.host, self.port))
        self._server.listen(10)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self._on_start()
        log.info(f"[{self.name}] listening on {self.host}:{self.port}")

    def _on_start(self):
        pass

    def _accept_loop(self):
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info(f"[{self.name}] connection from {addr}")
                threading.Thread(target=self.handle_client,
                                 args=(conn, addr), daemon=True).start()
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


class S7CommVulnSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=102):
        super().__init__(host, port, "S7VulnSim")
        self._init_state()
        self._scan_thread = None
        self._scan_running = False
        self._sim_time = time.time()
        self._real_cpu_state = 0x04
        self._fake_cpu_state = 0x04

        self.allow_stop = True
        self.weak_password = "12345"
        self.backdoor_password = "S7BACKDOOR"
        self.any_password_accepted = True
        self.block_injection_enabled = True
        self.diag_suppression_enabled = True
        self.fake_cpu_status_enabled = True
        self.timer_overflow_enabled = True
        self.process_hijack_enabled = True
        self.protection_bypassed = True

    def _init_state(self):
        self.cpu_state = 0x04
        self.cpu_status_word = 0x0200
        self.pdu_length = 480
        self.max_amq = 5
        self.cotp_src_ref = 0
        self.cotp_dst_ref = 0
        self.connected = False
        self.setup_done = False
        self.protection_level = 3

        self.data_blocks = {}
        for n, sz in [(1, 2048), (2, 1024), (3, 512), (4, 4096),
                       (5, 256), (6, 1024), (7, 512), (8, 256),
                       (9, 128), (10, 8192)]:
            self.data_blocks[n] = S7DataBlock(n, sz)

        self.pii = bytearray(65536)
        self.piq = bytearray(65536)
        self.merker = bytearray(65536)
        self.inputs = bytearray(65536)
        self.outputs = bytearray(65536)

        self.timers = {i: Timer(i) for i in range(256)}
        self.counters = {i: Counter(i) for i in range(256)}
        self.diag_buffer = DiagnosticBuffer(100)

        self.diag_buffer.add(0x00, 100, "Cold restart")
        self.diag_buffer.add(0x02, 1, "OB1 started")

    def _on_start(self):
        self._scan_running = True
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scan_thread.start()
        log.info("[VULN] scan cycle started")

    def _on_stop(self):
        self._scan_running = False

    def _scan_loop(self):
        while self._scan_running:
            try:
                self._scan_cycle()
            except Exception:
                pass
            time.sleep(0.1)

    def _scan_cycle(self):
        dt = time.time() - self._sim_time
        self._sim_time = time.time()

        for i in range(min(len(self.pii), len(self.piq), 1024)):
            self.piq[i] = self.pii[i] ^ 0x55

        for i in range(256):
            self.timers[i].tick(100)

    def _tpkt(self, payload):
        return TPKT.pack(3, 0, 4 + len(payload)) + payload

    def handle_client(self, conn, addr):
        self._init_state()
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
        cotp_type = payload[0]
        if cotp_type == 0x11:
            self._handle_cotp_cr(conn, payload)
        elif cotp_type == 0x10:
            self._handle_s7(conn, payload[2:] if len(payload) > 2 else b"")

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
        log.info(
            f"[VULN] COTP CR: src_ref={src_ref} src_tsap=0x{src_tsap:04X} "
            f"(protection bypassed)"
        )

        cc_payload = bytes([
            0x11, 0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a,
            0xc1, 0x02, tsap_src[0], tsap_src[1],
            0xc2, 0x02, tsap_dst[0], tsap_dst[1],
        ])
        self.connected = True
        conn.sendall(self._tpkt(cc_payload))

    def _handle_s7(self, conn, data):
        if len(data) < 2:
            return
        func = data[1]
        if func == 0x01:
            self._handle_s7_setup(conn, data)
        elif func == 0x04:
            self._handle_vuln_read(conn, data)
        elif func == 0x05:
            self._handle_vuln_write(conn, data)
        elif func in (0x00, 0x1A):
            self._handle_vuln_control(conn, data)
        elif func == 0x1C:
            self._handle_vuln_block(conn, data)
        elif func == 0x1F:
            self._handle_s7_time(conn, data)
        elif func == 0x21:
            self._handle_vuln_password(conn, data)
        elif func == 0x22:
            self._handle_vuln_force_stop(conn, data)
        elif func in (0x28, 0x29):
            self._handle_vuln_szl(conn, data)
        else:
            log.debug(f"[VULN] unknown function 0x{func:02X}")

    # ── VULN: protection always bypassed ─────────────────────────────
    def _handle_s7_setup(self, conn, data):
        request_id = data[4:6] if len(data) > 5 else b"\x00\x00"
        if len(data) > 11:
            self.pdu_length = min(struct.unpack(">H", data[10:12])[0], 480)
        log.info(f"[VULN] Setup: pdu_len={self.pdu_length}")

        resp = bytearray([0x32, 0x01, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend(struct.pack(">H", 0x0000))
        resp.extend(struct.pack(">H", self.max_amq))
        resp.extend(struct.pack(">H", self.pdu_length))
        resp.extend(b"\x00" * 12)
        self.setup_done = True
        conn.sendall(self._tpkt(bytes(resp)))

    # ── VULN: read without authorization ─────────────────────────────
    def _handle_vuln_read(self, conn, data):
        log.warning("[VULN-INFO] DB read WITHOUT authorization check")
        self._handle_s7_read(conn, data)

    def _handle_s7_read(self, conn, data):
        request_id = data[4:6]
        count = data[7] if len(data) > 7 else 1
        log.info(f"[VULN] Read: {count} item(s)")

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

            results.append(0xff)
            results.extend(self._read_area(area, db_num, address, length))

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

    # ── VULN: write without protection + process image hijack ────────
    def _handle_vuln_write(self, conn, data):
        log.warning("[VULN-EXPLOIT] Write accepted – NO protection check")
        self._handle_s7_write(conn, data)

    def _handle_s7_write(self, conn, data):
        request_id = data[4:6]
        count = data[7] if len(data) > 7 else 1
        log.info(f"[VULN] Write: {count} item(s)")

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
            log.info(f"[VULN]   Write: {area_name} DB{db_num} addr={address} len={val_len}")

            self._write_area(area, db_num, address, val_data)

            if self.process_hijack_enabled and area == 0x82:
                log.warning("[VULN-CRITICAL] Output written WITHOUT OB1 execution – process image hijack!")
                for i in range(len(val_data)):
                    if address + i < len(self.outputs):
                        self.outputs[address + i] = val_data[i]

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
        return False

    # ── VULN: STOP without auth + fake CPU status + diag suppression ─
    def _handle_vuln_control(self, conn, data):
        if len(data) < 8:
            return
        request_id = data[4:6]
        sub_type = data[6] if len(data) > 6 else 0

        ctrl_names = {0x04: "STOP", 0x05: "HOT_START", 0x07: "COLD_START", 0x08: "RUN"}
        name = ctrl_names.get(sub_type, f"0x{sub_type:02X}")

        log.warning(f"[VULN-EXPLOIT] PLC {name} accepted WITHOUT authentication!")

        if sub_type == 0x04:
            self._real_cpu_state = 0x00
            if self.fake_cpu_status_enabled:
                self.cpu_state = 0x04
                self.cpu_status_word = 0x0200
                log.warning("[VULN-CRITICAL] PLC actually STOPPED but REPORTING RUN state")
            else:
                self.cpu_state = 0x00
                self.cpu_status_word = 0x0000

            if self.diag_suppression_enabled:
                log.warning("[VULN] STOP event NOT logged to diagnostic buffer")
            else:
                self.diag_buffer.add(0x08, 1, "PLC STOP requested via S7")

        elif sub_type in {0x05, 0x07}:
            self._real_cpu_state = self.cpu_state = 0x10
            log.warning(f"[VULN] PLC {name}")
            t = threading.Timer(2.0, self._transition_to_run)
            t.daemon = True
            t.start()
        elif sub_type == 0x08:
            self._transition_to_run()

        resp = bytearray([0x32, 0x00, 0x80 if sub_type == 0x04 else 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    def _handle_vuln_force_stop(self, conn, data):
        log.critical("[VULN] Force STOP received!")
        self._real_cpu_state = 0x00
        if self.fake_cpu_status_enabled:
            self.cpu_state = 0x04
            log.warning("[VULN] Real state=STOP, reported=RUN")
        else:
            self.cpu_state = 0x00
        request_id = data[4:6] if len(data) > 5 else b"\x00\x00"
        resp = bytearray([0x32, 0x22, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    def _transition_to_run(self):
        self._real_cpu_state = 0x04
        if self.fake_cpu_status_enabled:
            self.cpu_state = 0x04
        else:
            self.cpu_state = 0x04
        self.cpu_status_word = 0x0200

    # ── VULN: block injection without verification ───────────────────
    def _handle_vuln_block(self, conn, data):
        if len(data) < 10:
            return
        request_id = data[4:6]
        sub_func = data[6] if len(data) > 6 else 0

        sub_names = {
            0x01: "ListBlocks", 0x03: "StartUpload", 0x04: "Upload",
            0x06: "StartDownload", 0x07: "Download", 0x08: "EndDownload",
            0x09: "DeleteBlock",
        }
        name = sub_names.get(sub_func, f"0x{sub_func:02X}")

        if sub_func in (0x06, 0x07, 0x08):
            log.warning(f"[VULN-CRITICAL] Block {name} accepted WITHOUT verification!")
            if sub_func == 0x06:
                self._block_download_active = True
            elif sub_func == 0x08:
                self._block_download_active = False
                log.warning("[VULN] Block injection complete – malicious code loaded")
        elif sub_func == 0x09:
            log.warning(f"[VULN-CRITICAL] Block DELETE accepted!")
        else:
            log.info(f"[VULN] Block {name}")

        resp = bytearray([0x32, 0x1C, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
        conn.sendall(self._tpkt(bytes(resp)))

    # ── VULN: password backdoor ──────────────────────────────────────
    def _handle_vuln_password(self, conn, data):
        log.warning("[VULN] S7 Password check – BACKDOOR ENABLED")
        if self.any_password_accepted:
            log.warning(f"[VULN-CRITICAL] ANY password accepted!")
        else:
            log.warning(f"[VULN] Weak password: {self.weak_password}")
            log.warning(f"[VULN] Backdoor password: {self.backdoor_password}")

        request_id = data[4:6] if len(data) > 5 else b"\x00\x00"
        resp = bytearray([0x32, 0x21, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])
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

    # ── VULN: SZL / diagnostic ───────────────────────────────────────
    def _handle_vuln_szl(self, conn, data):
        request_id = data[4:6]
        szl_id = struct.unpack(">H", data[8:10])[0] if len(data) > 9 else 0
        log.info(f"[VULN] SZL: id=0x{szl_id:04X}")

        resp = bytearray([0x32, 0x28, 0x00, 0x00])
        resp.extend(request_id)
        resp.extend([0x00, 0x00])

        if szl_id == 0x0011:
            resp.extend(self._szl_cpu_status())
        elif szl_id == 0x001C:
            resp.extend(self._szl_diag_buffer())
        elif szl_id == 0x0232:
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
        if self.fake_cpu_status_enabled:
            buf.extend(struct.pack(">H", 0x0200))
        else:
            buf.extend(struct.pack(">H", self.cpu_status_word))
        buf.extend(struct.pack(">H", 0x0000))
        return buf

    def _szl_diag_buffer(self):
        entries = self.diag_buffer.get_recent(10)
        buf = bytearray()
        buf.extend(struct.pack(">H", 0x001C))
        buf.extend(struct.pack(">H", 0x0000))
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
        actual_level = 0 if self.protection_bypassed else self.protection_level
        buf.extend(struct.pack(">H", actual_level))
        buf.extend([0x00, 0x00])
        return buf


if __name__ == "__main__":
    s = S7CommVulnSimulator()
    s.start()
    print("[VULN] Vulnerable PLC simulator running on port 102")
    print("  - Protection bypassed (level 3 -> 0)")
    print("  - Any password accepted")
    print("  - Block injection enabled")
    print("  - Diagnostic suppression on STOP")
    print("  - Fake CPU status (always RUN)")
    print("  - Timer overflow enabled")
    print("  - Process image hijack enabled")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
