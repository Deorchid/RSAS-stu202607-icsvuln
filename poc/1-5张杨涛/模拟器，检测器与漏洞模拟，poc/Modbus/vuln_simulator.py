"""
Modbus 漏洞模拟器 — 无认证写入 · 梯形图绕过 · 写入洪流 · 异常抑制 · 总线洪流
内存损坏 · 身份欺骗 · 诊断清除 · 广播风暴
完全自包含，包含内联基础模拟器
"""
import socket, struct, logging, threading, time, random
from datetime import datetime
from collections import OrderedDict, defaultdict, deque

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ModbusVuln")

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


def crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc = (crc >> 8) ^ RTU_CRC_TABLE[(crc ^ b) & 0xFF]
    return crc


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
        while self._running:
            try:
                conn, addr = self._server.accept()
                log.info(f"[{self.name}] connection from {addr}")
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                if self._running:
                    break
                break

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


class VulnModbusSimulator(BaseSim):
    def __init__(self, host="0.0.0.0", port=502, use_rtu=False):
        super().__init__(host, port, "VulnModbusTCP")
        self.use_rtu = use_rtu
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
        self.vuln_log = []

        self.allow_stop_cpu = True
        self.force_listen_mode = False
        self.leak_credentials = True
        self.weak_device_id = True

        self.stop_chain_coil = 0x0000
        self.estop_coil = 0x0001
        self.stop_chain_config = 0x3000
        self._stop_chain_active = True
        self._stop_chain_bypassed = False

        self._write_count = 0
        self._write_limit_enabled = False
        self._exception_suppress = False
        self._memory_corrupt_enabled = False
        self._corrupt_rate = 0.05
        self._identity_spoof_enabled = False
        self._diag_clearable = True
        self._broadcast_storm_active = False
        self._flood_counters = defaultdict(int)

        self.vuln_log.append(f"[{datetime.now().isoformat()}] VulnSim initialized - ALL protections DISABLED")

    def _init_file_records(self):
        for i in range(5):
            rec = bytearray(100 * 2)
            for j in range(100):
                struct.pack_into(">H", rec, j * 2, (i + 1) * 1000 + j)
            self.file_records[i + 1] = rec

    def _exc(self, func, code):
        return bytes([func | 0x80, code])

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
        if val:
            self.coils[bi] |= 1 << bj
        else:
            self.coils[bi] &= ~(1 << bj)

    def _write_reg(self, addr, val):
        struct.pack_into(">H", self.holding_registers, addr * 2, val & 0xFFFF)

    def enable_stop_chain_bypass(self):
        self._stop_chain_bypassed = True
        self._write_coil(self.stop_chain_coil, True)
        self._write_coil(self.estop_coil, False)
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-LADDER] STOP chain bypassed: "
                             f"estop OFF, stop_chain ON")
        log.warning("[VULN-LADDER] STOP chain bypassed - ladder logic safety defeated")

    def enable_write_flood_acceptance(self):
        self._write_limit_enabled = False
        log.warning("[VULN-WRITE] Write flood protection DISABLED - unlimited writes accepted")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-WRITE] Write limit disabled")

    def enable_exception_suppression(self):
        self._exception_suppress = True
        log.warning("[VULN-EXC] Exception suppression ENABLED - invalid functions silently accepted")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-EXC] Exception suppression ON")

    def enable_memory_corruption(self, rate=0.05):
        self._memory_corrupt_enabled = True
        self._corrupt_rate = rate
        log.warning(f"[VULN-MEM] Memory corruption ENABLED at rate={rate:.0%}")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-MEM] Corruption at {rate:.0%} rate")

    def enable_identity_spoof(self):
        self._identity_spoof_enabled = True
        log.warning("[VULN-ID] Identity spoofing ENABLED - device ID remotely changeable")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-ID] Spoofing enabled")

    def enable_diag_clear(self):
        self._diag_clearable = True
        log.warning("[VULN-DIAG] Diagnostic buffer can be remotely deleted")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-DIAG] Remote clear enabled")

    def start_broadcast_storm(self, interval=0.01):
        self._broadcast_storm_active = True
        log.warning(f"[VULN-STORM] Broadcast storm STARTED interval={interval}s")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-STORM] Storm started")
        threading.Thread(target=self._storm_loop, args=(interval,), daemon=True).start()

    def _storm_loop(self, interval):
        dummy_conn = None
        try:
            while self._running and self._broadcast_storm_active:
                self._flood_counters["storm_broadcasts"] += 1
                self.diag_counters[11] += 1
                for i in range(random.randint(1, 10)):
                    reg_addr = random.randint(0, 1000)
                    val = random.randint(0, 0xFFFF)
                    self._write_reg(reg_addr, val)
                time.sleep(interval)
        except Exception as e:
            log.error(f"Storm loop error: {e}")

    def corrupt_memory(self):
        if not self._memory_corrupt_enabled:
            return
        for i in range(random.randint(1, 100)):
            if random.random() < self._corrupt_rate:
                reg = random.randint(0, 65535)
                byte_off = reg * 2
                if byte_off + 2 <= len(self.holding_registers):
                    bit_to_flip = random.randint(0, 15)
                    val = struct.unpack(">H", self.holding_registers[byte_off:byte_off+2])[0]
                    val ^= (1 << bit_to_flip)
                    struct.pack_into(">H", self.holding_registers, byte_off, val)
                    log.debug(f"Memory corruption: reg {reg} bit {bit_to_flip} flipped")

    def clear_diag_evidence(self):
        if not self._diag_clearable:
            return
        for k in self.diag_counters:
            self.diag_counters[k] = 0
        self.vuln_log.clear()
        self._flood_counters.clear()
        log.warning("[VULN-DIAG-CLEAR] ALL diagnostic evidence deleted!")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-DIAG-CLEAR] Evidence destroyed")

    def handle_client(self, conn, addr):
        buf = b""
        try:
            while self._running:
                data = conn.recv(4096)
                if not data:
                    break
                buf += data
                if self.use_rtu:
                    remaining = self._handle_rtu(buf, conn)
                    if remaining is not None:
                        buf = remaining
                else:
                    remaining = self._handle_tcp(buf, conn)
                    if remaining is not None:
                        buf = remaining
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _handle_tcp(self, buf, conn):
        if len(buf) < 7:
            return None
        tid, pid, length, unit = MBAP_HDR.unpack(buf[:7])
        if len(buf) < 6 + length:
            return None
        pdu = buf[7:7+length-1]
        remaining = buf[6+length:]
        func = pdu[0] if pdu else 0
        resp_pdu = self._process_pdu(func, pdu[1:] if len(pdu) > 1 else b"", unit)
        if unit != 0:
            resp = MBAP_HDR.pack(tid, pid, len(resp_pdu) + 1, unit) + resp_pdu
            conn.sendall(resp)
        elif self.broadcast_enabled:
            log.info(f"[Vuln] Broadcast 0x{func:02X}")
        return remaining

    def _handle_rtu(self, buf, conn):
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
        resp_pdu = self._process_pdu(func, pdu[1:] if len(pdu) > 1 else b"", unit)
        resp_frame = bytes([unit]) + resp_pdu
        crc = crc16(resp_frame)
        conn.sendall(resp_frame + struct.pack("<H", crc))
        return remaining

    def _process_pdu(self, func, data, unit=1):
        self.vuln_log.append(f"[{datetime.now().isoformat()}] func=0x{func:02X} unit={unit}")
        self._flood_counters["total"] += 1

        if self._memory_corrupt_enabled:
            self.corrupt_memory()

        if self._exception_suppress and func not in FUNC_NAMES and func not in {0x80}:
            log.warning(f"[VULN-EXC-SUPPRESS] Invalid func 0x{func:02X} silently accepted")
            return bytes([func, 0x00])

        if func in {5, 6, 15, 16, 21, 22, 23}:
            log.warning(f"[VULN-CRITICAL] Unauthenticated write 0x{func:02X} by unit {unit}")
            self._write_count += 1
            if self._write_limit_enabled and self._write_count > 100:
                return self._exc(func, 6)
            if func in {5, 6, 15, 16}:
                vals = data if len(data) >= 4 else b"\x00\x00\x00\x00"
                a = struct.unpack(">H", vals[:2])[0]
                if a == self.stop_chain_config and self._stop_chain_bypassed:
                    log.warning("[VULN-LADDER-EXPLOIT] Writing to stop chain config address!")
                if self._identity_spoof_enabled and a == 0x2000:
                    log.warning("[VULN-ID-SPOOF] Device identity remotely modified!")

        if func == 8:
            sub = struct.unpack(">H", data[:2])[0] if len(data) >= 2 else 0
            log.warning(f"[VULN] Diagnostics sub=0x{sub:04X}")
            if sub == 1:
                log.warning("[VULN-EXPLOIT] Restart Communications - can force PLC reboot")
                self._stop_chain_active = False
            elif sub == 4:
                log.warning("[VULN-EXPLOIT] Force Listen Only Mode - can disable device")
                self.force_listen_mode = True
                return self._exc(8, 0)
            elif sub == 10:
                log.warning("[VULN-FORENSIC] Clear Counters - destroys audit evidence")
                if self._diag_clearable:
                    self.clear_diag_evidence()

        if func == 17 and self.leak_credentials:
            log.warning("[VULN-INFO] Report Server ID leaking device info and maybe passwords")
            self.server_id = b"VulnPLC-EXPLOITABLE-admin:password123\x00\x00\x00\x00\x00\x00"

        if func == 43 and self.weak_device_id:
            mei_type = data[0] if len(data) > 0 else 0
            if mei_type == 0x0E:
                log.warning("[VULN-INFO] Device ID leak - vendor/product/version exposed")
                self.device_id_data[0x00] = b"VulnerableCorp\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

        return self._process_func(func, data, unit)

    def _process_func(self, func, data, unit):
        try:
            if func == 1:
                a, c = struct.unpack(">HH", data[:4])
                if c < 1 or c > 2000:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.coils, a, c, 1)
            elif func == 2:
                a, c = struct.unpack(">HH", data[:4])
                if c < 1 or c > 2000:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.discrete_inputs, a, c, 1)
            elif func == 3:
                a, c = struct.unpack(">HH", data[:4])
                if c < 1 or c > 125:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.holding_registers, a, c, 2)
            elif func == 4:
                a, c = struct.unpack(">HH", data[:4])
                if c < 1 or c > 125:
                    return self._exc(func, 3)
                return bytes([func]) + self._read_mem(self.input_registers, a, c, 2)
            elif func == 5:
                a, v = struct.unpack(">HH", data[:4])
                self._write_coil(a, v == 0xFF00)
                return bytes([func]) + struct.pack(">HH", a, v)
            elif func == 6:
                a, v = struct.unpack(">HH", data[:4])
                self._write_reg(a, v)
                return bytes([func]) + struct.pack(">HH", a, v)
            elif func == 7:
                return bytes([func, 0x00])
            elif func == 8:
                sub = struct.unpack(">H", data[:2])[0]
                req_data = data[2:4] if len(data) >= 4 else b"\x00\x00"
                return self._handle_diagnostics(sub, req_data)
            elif func == 11:
                return bytes([func]) + struct.pack(">HH", 0x0000, self.diag_counters.get(11, 0))
            elif func == 12:
                events = struct.pack(">HH", 0x0006, self.diag_counters.get(11, 0))
                return bytes([func, len(events)]) + events + bytes([0, 0, 0, 0, 0, 0])
            elif func == 15:
                a, c = struct.unpack(">HH", data[:4])
                if c < 1 or c > 1968:
                    return self._exc(func, 3)
                for i in range(c):
                    byte_idx = (a + i) // 8; bit_idx = (a + i) % 8
                    if (data[5 + i // 8] >> (i % 8)) & 1:
                        self.coils[byte_idx] |= 1 << bit_idx
                    else:
                        self.coils[byte_idx] &= ~(1 << bit_idx)
                return bytes([func]) + struct.pack(">HH", a, c)
            elif func == 16:
                a, c = struct.unpack(">HH", data[:4])
                if c < 1 or c > 123:
                    return self._exc(func, 3)
                for i in range(c):
                    self._write_reg(a + i, struct.unpack(">H", data[5+i*2:7+i*2])[0])
                return bytes([func]) + struct.pack(">HH", a, c)
            elif func == 17:
                return bytes([func, len(self.server_id)]) + self.server_id + struct.pack(">H", 0x00FF)
            elif func == 20:
                return self._read_file(data)
            elif func == 21:
                return self._write_file(data)
            elif func == 22:
                a, and_mask, or_mask = struct.unpack(">HHH", data[:6])
                cur = struct.unpack(">H", self.holding_registers[a*2:a*2+2])[0]
                self._write_reg(a, (cur & and_mask) | or_mask)
                return bytes([func]) + struct.pack(">HHH", a, and_mask, or_mask)
            elif func == 23:
                ra, rc = struct.unpack(">HH", data[:4])
                wa, wc = struct.unpack(">HH", data[4:8])
                for i in range(wc):
                    self._write_reg(wa + i, struct.unpack(">H", data[9+i*2:11+i*2])[0])
                return bytes([func, rc * 2]) + b"\x00" * (rc * 2)
            elif func == 24:
                ptr = struct.unpack(">H", data[:2])[0]
                count = self.fifo_buffer[0] if self.fifo_buffer[0] <= 31 else 0
                values = self.fifo_buffer[1:1+count] if count else []
                resp = struct.pack(">HH", 2 + count * 2, count)
                for v in values:
                    resp += struct.pack(">H", v)
                return bytes([func]) + resp
            elif func == 43:
                return self._handle_mei(data)
            else:
                if self._exception_suppress:
                    return bytes([func, 0x00])
                return self._exc(func, 1)
        except struct.error:
            return self._exc(func, 2)
        except Exception as e:
            log.error(f"Error func 0x{func:02X}: {e}")
            return self._exc(func, 4)

    def _handle_diagnostics(self, sub, data):
        if sub == 0:
            return bytes([8]) + struct.pack(">HH", sub, struct.unpack(">H", data)[0])
        elif sub == 1:
            self.diag_register = 0
            for k in self.diag_counters:
                self.diag_counters[k] = 0
            return bytes([8]) + struct.pack(">HH", sub, 0xFF00)
        elif sub == 2:
            return bytes([8]) + struct.pack(">HH", sub, self.diag_register)
        elif sub == 4:
            return bytes([8]) + struct.pack(">HH", sub, struct.unpack(">H", data)[0])
        elif sub == 10:
            for k in self.diag_counters:
                self.diag_counters[k] = 0
            return bytes([8]) + struct.pack(">HH", sub, 0x0000)
        elif sub in self.diag_counters:
            return bytes([8]) + struct.pack(">HH", sub, self.diag_counters[sub])
        elif sub == 20:
            return bytes([8]) + struct.pack(">HH", sub, 0x0000)
        elif sub == 21:
            return bytes([8]) + struct.pack(">HH", sub, 0x0000)
        else:
            return self._exc(8, 3)

    def _read_file(self, data):
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
                start = rec_num * 2; end = start + rec_len * 2
                if end <= len(rec):
                    results.append(ref_type); results.append(rec_len); results.extend(rec[start:end])
        return bytes([20]) + bytes([len(results)]) + bytes(results)

    def _write_file(self, data):
        off = 1
        while off + 7 <= len(data):
            ref_type = data[off]
            file_num = struct.unpack(">H", data[off+1:off+3])[0]
            rec_num = struct.unpack(">H", data[off+3:off+5])[0]
            rec_len = struct.unpack(">H", data[off+5:off+7])[0]
            off += 7
            if file_num in self.file_records:
                rec = self.file_records[file_num]; start = rec_num * 2
                end = start + rec_len * 2
                if end <= len(rec) and off + rec_len * 2 <= len(data):
                    rec[start:end] = data[off:off+rec_len*2]
                off += rec_len * 2
        return bytes([21]) + data[:1]

    def _handle_mei(self, data):
        mei_type = data[0] if len(data) > 0 else 0
        if mei_type != 0x0E:
            return self._exc(43, 3)
        read_code = data[1]
        obj_id = data[2] if len(data) > 2 else 0
        if read_code in {0x01, 0x03}:
            count = len(self.device_id_data); more = 0
        elif read_code == 0x02:
            count = 1 if obj_id in self.device_id_data else 0; more = 0
        else:
            return self._exc(43, 3)
        resp = bytes([0x0E, read_code, 0x00, 0x00, count])
        for oid in sorted(self.device_id_data):
            val = self.device_id_data[oid]
            resp += bytes([oid, 0x00, len(val)]) + val
        return bytes([43]) + resp

    def enable_register_bomb(self, addr=0x4000):
        for i in range(2000):
            off = (addr + i) * 2
            struct.pack_into(">H", self.holding_registers, off, random.randint(0, 0xFFFF))
        log.warning(f"[VULN] 2000 registers written with random values at 0x{addr:04X}")
        self.vuln_log.append(f"[{datetime.now().isoformat()}] [VULN-BOMB] Register bomb at 0x{addr:04X}")

    def start_fifo_flood(self, interval=0.1):
        def flood():
            val = 0
            while self._running:
                self.fifo_buffer = [32] + [(val + i) & 0xFFFF for i in range(31)]
                val = (val + 32) & 0xFFFF
                time.sleep(interval)
        threading.Thread(target=flood, daemon=True).start()
        log.warning("[VULN] FIFO buffer flooding started")

    def dump_vuln_log(self):
        for entry in self.vuln_log[-50:]:
            log.info(f"  {entry}")

    def enable_all_vulns(self):
        self.enable_stop_chain_bypass()
        self.enable_write_flood_acceptance()
        self.enable_exception_suppression()
        self.enable_memory_corruption(0.03)
        self.enable_identity_spoof()
        self.enable_diag_clear()
        self.start_broadcast_storm(0.05)
        log.warning("[VULN-ALL] ALL vulnerability modes enabled!")


if __name__ == "__main__":
    s = VulnModbusSimulator()
    s.enable_all_vulns()
    s.start()
    s.enable_register_bomb()
    s.start_fifo_flood()
    log.info("Vulnerable Modbus Simulator running with all exploits active")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.dump_vuln_log()
        s.stop()
