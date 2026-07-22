"""
EtherNet/IP Vulnerability Simulator

Demonstrates critical ICS protocol weaknesses:
  - No session authentication: any RegisterSession accepted without credentials
  - Excessive connections: no limit on concurrent ForwardOpen connections
  - No electronic key validation: any device type accepted in ForwardOpen
  - Assembly data leakage: all assembly data readable without authorization
  - Identity information leakage: full device info exposed via ListIdentity
  - Connection flood vulnerability: no rate limiting on connection requests
  - CIP Stop/Reset without authentication: no privilege checks
  - Session hijacking: reuse any session handle regardless of origin

This simulator inherits and overrides EthernetIPSimulator to remove
security checks, demonstrating what a vulnerable device looks like.
"""
import struct
import time
import logging
import threading
from typing import Dict, Any

from simulator import (
    EthernetIPSimulator,
    ENCAP,
    EIP_CMD,
    CIP_SVC,
    CIP_CLASS_NAMES,
    EIPSession,
    CIPConnection,
    ConnectionType,
    ConnectionState,
    ElectronicKey,
    SESSION_TIMEOUT,
    log as sim_log,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("EIPVuln")


class EthernetIPVulnSimulator(EthernetIPSimulator):
    """Vulnerable EtherNet/IP simulator with all security checks removed."""

    def __init__(self, host="0.0.0.0", port=44818):
        super().__init__(host, port)
        self.name = "EIPVulnSim"
        self.leak_all_data = True
        self.allow_any_session = True
        self.max_connections = None
        self.validate_ekey = False
        self.require_auth = False
        self.rate_limit = None
        self._connection_counts = {}
        self._connection_counts_lock = threading.Lock()
        self._vuln_stats = {
            "unauth_registrations": 0,
            "total_connections": 0,
            "ekey_bypassed": 0,
            "assembly_leaks": 0,
            "identity_leaks": 0,
            "resets_without_auth": 0,
            "stops_without_auth": 0,
            "hijacked_sessions": 0,
            "connection_floods": 0,
            "writes_accepted": 0,
        }
        self._stats_lock = threading.Lock()
        self._leak_log: Dict[int, list] = {}

    def start(self):
        super().start()
        log.warning("=" * 62)
        log.warning(" VULNERABLE EtherNet/IP Simulator Started")
        log.warning(" No authentication required for any operation")
        log.warning(" No electronic key validation")
        log.warning(" No connection limits enforced")
        log.warning(" All assembly data exposed")
        log.warning("=" * 62)

    def stop(self):
        log.warning("=" * 62)
        log.warning(" Vulnerability Statistics:")
        with self._stats_lock:
            for key, val in sorted(self._vuln_stats.items()):
                log.warning("   %s: %d", key, val)
        log.warning("=" * 62)
        super().stop()

    def handle_client(self, conn, addr):
        buf = b""
        try:
            while self._running:
                data = conn.recv(8192)
                if not data:
                    break
                buf += data
                while len(buf) >= 24:
                    cmd, length = struct.unpack("<HH", buf[:4])
                    frame_len = 24 + (length - 24 if length > 24 else 0)
                    if len(buf) < frame_len:
                        break
                    chunk = buf[:frame_len]
                    buf = buf[frame_len:]
                    self._handle_encap_vuln(conn, chunk, addr)
        except Exception:
            pass
        finally:
            conn.close()

    def _handle_encap_vuln(self, conn, chunk, addr):
        """Overridden encapsulation handler that strips all security."""
        cmd, length, handle, sender_context, status, options = ENCAP.unpack(chunk[:24])
        ctx = sender_context
        s_qword = struct.pack("<Q", sender_context) if isinstance(sender_context, int) else \
            sender_context.to_bytes(8, 'little') if isinstance(sender_context, int) else b"\x00" * 8
        sess = struct.unpack("<Q", s_qword)[0]
        cmd_name = EIP_CMD.get(cmd, "Unknown(0x%04X)" % cmd)

        log.debug("VULN cmd=0x%04X (%s) sess=0x%016X from=%s",
                 cmd, cmd_name, sess, addr)

        if cmd == 0x0065:
            self._vuln_register_session(conn, addr)
        elif cmd == 0x0066:
            self._vuln_unregister_session(conn, sess, addr)
        elif cmd == 0x0063:
            self._vuln_list_identity(conn, sender_context, addr)
        elif cmd == 0x0064:
            self._vuln_list_services(conn, sender_context, addr)
        elif cmd == 0x006F:
            self._vuln_send_rr_data(conn, chunk, sender_context, sess, addr)
        elif cmd == 0x0070:
            self._vuln_send_unit_data(conn, chunk, sender_context, sess, addr)
        elif cmd == 0x0072:
            self._vuln_indicate_status(conn, sender_context)
        elif cmd == 0x0073:
            self._vuln_cancel_status(conn, sender_context)
        else:
            log.warning("[VULN] Unhandled cmd 0x%04X from %s (accepted anyway)", cmd, addr)
            conn.sendall(self._encap_sender_context(cmd, sender_context, 0))

    def _vuln_register_session(self, conn, addr):
        new_sid = (int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)
        sess = EIPSession(new_sid, addr)
        with self.sessions_lock:
            self.sessions[new_sid] = sess
        with self._stats_lock:
            self._vuln_stats["unauth_registrations"] += 1
        log.warning("[VULN-AUTH] RegisterSession #%d ACCEPTED without "
                    "authentication from %s (sid=0x%016X)",
                    self._vuln_stats["unauth_registrations"], addr, new_sid)
        resp = self._encap(0x0065, data=struct.pack("<Q", new_sid))
        conn.sendall(resp)

    def _vuln_unregister_session(self, conn, sess, addr):
        with self.sessions_lock:
            if sess in self.sessions:
                del self.sessions[sess]
        conn.sendall(self._encap(0x0066))

    def _vuln_list_identity(self, conn, sender_context, addr):
        with self._stats_lock:
            self._vuln_stats["identity_leaks"] += 1
        log.warning("[VULN-LEAK] ListIdentity responding with FULL device info "
                    "(leak #%d) to %s — vendor, serial, product, revision all exposed",
                    self._vuln_stats["identity_leaks"], addr)
        data = self._build_list_identity_full()
        conn.sendall(self._encap_sender_context(0x0063, sender_context, data=data))

    def _vuln_list_services(self, conn, sender_context, addr):
        data = self._build_list_services()
        conn.sendall(self._encap_sender_context(0x0064, sender_context, data=data))

    def _vuln_indicate_status(self, conn, sender_context):
        conn.sendall(self._encap_sender_context(0x0072, sender_context, 0))

    def _vuln_cancel_status(self, conn, sender_context):
        conn.sendall(self._encap_sender_context(0x0073, sender_context, 0))

    def _vuln_send_rr_data(self, conn, chunk, sender_context, sess, addr):
        if len(chunk) <= 24:
            conn.sendall(self._encap_sender_context(0x006F, sender_context, data=b"\x00" * 8))
            return

        cip_data = b""
        for off in (38, 34, 30, 24):
            if len(chunk) > off + 2:
                trial = chunk[off:]
                if trial[0] in (0x01,0x02,0x0E,0x10,0x4B,0x4C,0x4E,0x4F,0x52,0x54,0x03,0x04,0x05,0x06,0x07,0x08,0x09):
                    cip_data = trial
                    break
            if len(chunk) > off + 14:
                trial2 = chunk[off+14:]
                if trial2 and trial2[0] in (0x01,0x02,0x0E,0x10,0x4B,0x4C,0x4E,0x4F,0x52,0x54,0x03,0x04,0x05,0x06,0x07,0x08,0x09):
                    cip_data = trial2
                    break
        if not cip_data:
            cip_data = chunk[24:]
        if len(cip_data) < 2:
            conn.sendall(self._encap_sender_context(0x006F, sender_context,
                                                    data=chunk[8:16] + b"\x00\x00"))
            return

        service = cip_data[0]
        path_len = cip_data[1]
        svc_name = CIP_SVC.get(service, "0x%02X" % service)

        if service == 0x4E:
            with self._stats_lock:
                self._vuln_stats["total_connections"] += 1
            log.warning("[VULN-EXPLOIT] ForwardOpen #%d ACCEPTED with NO "
                        "connection limit from %s (max=none, ekey=bypassed)",
                        self._vuln_stats["total_connections"], addr)
        elif service == 0x4F:
            log.info("[VULN] ForwardClose from %s", addr)
        elif service in (0x10, 0x02, 0x4C, 0x04):
            with self._stats_lock:
                self._vuln_stats["writes_accepted"] += 1
            if path_len >= 2 and len(cip_data) >= 4:
                cls = struct.unpack("<H", cip_data[2:4])[0]
                cls_name = CIP_CLASS_NAMES.get(cls, "?")
                log.warning("[VULN-EXPLOIT] CIP %s ACCEPTED on class 0x%02X (%s) "
                            "from %s — NO write protection",
                            svc_name, cls, cls_name, addr)
            else:
                log.warning("[VULN-EXPLOIT] CIP %s ACCEPTED from %s — NO write "
                            "protection", svc_name, addr)
        elif service in (0x52, 0x05):
            with self._stats_lock:
                self._vuln_stats["resets_without_auth"] += 1
            log.warning("[VULN-EXPLOIT] CIP Reset ACCEPTED without auth! "
                        "(reset #%d from %s)",
                        self._vuln_stats["resets_without_auth"], addr)
        elif service in (0x54, 0x07):
            with self._stats_lock:
                self._vuln_stats["stops_without_auth"] += 1
            log.warning("[VULN-EXPLOIT] CIP Stop ACCEPTED without auth! "
                        "(stop #%d from %s)",
                        self._vuln_stats["stops_without_auth"], addr)
        elif service in (0x01, 0x0E, 0x4B, 0x03):
            with self._stats_lock:
                self._vuln_stats["assembly_leaks"] += 1
            if path_len >= 2 and len(cip_data) >= 4:
                cls = struct.unpack("<H", cip_data[2:4])[0]
                cls_name = CIP_CLASS_NAMES.get(cls, "?")
                log.warning("[VULN-LEAK] CIP %s on 0x%02X (%s) from %s — "
                            "full data exposed (leak #%d)",
                            svc_name, cls, cls_name, addr,
                            self._vuln_stats["assembly_leaks"])
            else:
                log.warning("[VULN-LEAK] CIP %s from %s — data exposed",
                            svc_name, addr)
        elif service == 0x53:
            log.warning("[VULN-EXPLOIT] CIP Start ACCEPTED from %s", addr)

        sess_hijacked = False
        if sess and sess != 0:
            with self.sessions_lock:
                if sess not in self.sessions:
                    log.warning("[VULN-HIJACK] Session 0x%016X from %s is not "
                                "registered — serving request ANYWAY (hijack)",
                                sess, addr)
                    hijacked_session = EIPSession(sess, addr)
                    self.sessions[sess] = hijacked_session
                    sess_hijacked = True
                    with self._stats_lock:
                        self._vuln_stats["hijacked_sessions"] += 1
                else:
                    self.sessions[sess].touch()

        resp_cip = self._handle_cip_rr(cip_data, conn, addr, sess)
        reply = chunk[8:16] + resp_cip
        conn.sendall(self._encap_sender_context(0x006F, sender_context, data=reply))

    def _vuln_send_unit_data(self, conn, chunk, sender_context, sess, addr):
        if len(chunk) > 38:
            cip_data = chunk[38:]
            if len(cip_data) >= 2:
                svc = cip_data[0]
                svc_name = CIP_SVC.get(svc, "0x%02X" % svc)
                log.warning("[VULN] SendUnitData CIP %s from %s", svc_name, addr)
            resp_cip = self._handle_cip_unit(cip_data, conn, addr, sess)
            reply = chunk[8:16] + resp_cip
            conn.sendall(self._encap_sender_context(0x0070, sender_context, data=reply))
        else:
            conn.sendall(self._encap_sender_context(0x0070, sender_context))

    def _build_list_identity_full(self):
        items = bytearray()
        name = b"VULNERABLE EtherNet/IP Simulator v4.1"
        items += struct.pack("<H", 0x0001)
        items += struct.pack("<H", len(name)) + name
        items += struct.pack("<H", 0x0002)
        items += struct.pack("<H", 0x000E)
        items += struct.pack("<H", 0x0003)
        items += struct.pack("<H", 0x0064)
        items += struct.pack("<H", 0x0004)
        items += struct.pack("<HH", 4, 1)
        items += struct.pack("<H", 0x0005)
        items += struct.pack("<H", 0x0064)
        items += struct.pack("<H", 0x0006)
        items += struct.pack("<I", 0xDEADBEEF)
        items += struct.pack("<H", 0x0007)
        items += struct.pack("<I", 0x00000000)
        items += struct.pack("<H", 0x0008)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x0009)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x000A)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x000B)
        items += struct.pack("<H", 0x0000)
        items += struct.pack("<H", 0x000C)
        items += struct.pack("<H", 0x0000)

        header = struct.pack("<HHHBBH", 0x0100, 1, 0, 1, 1, 0)
        header += struct.pack("<HH", len(items), 0x0002)
        return header + bytes(items)

    def _handle_cip_rr(self, data, conn, addr, sess):
        """Override to skip electronic key validation."""
        if len(data) < 2:
            return self._cip_error(0x08, 0x13)
        service = data[0]
        path_len = data[1]

        if service == 0x4E:
            return self._handle_forward_open_unrestricted(data, conn, addr, sess)

        return super()._handle_cip_rr(data, conn, addr, sess)

    def _handle_forward_open_unrestricted(self, data, conn, addr, sess):
        log.warning("[VULN-EXPLOIT] ForwardOpen UNRESTRICTED — no connection "
                    "limit, no ekey validation, any RPI accepted")
        priority = data[2] if len(data) > 2 else 0
        timeout_ticks = data[3] if len(data) > 3 else 0

        o_t_id = self._next_conn_id()
        t_o_id = self._next_conn_id()

        try:
            o_t_size = struct.unpack("<H", data[6:8])[0] if len(data) > 7 else 100
        except struct.error:
            o_t_size = 100
        try:
            t_o_size = struct.unpack("<H", data[8:10])[0] if len(data) > 9 else 100
        except struct.error:
            t_o_size = 100

        try:
            o_t_rpi = struct.unpack("<I", data[44:48])[0] if len(data) > 47 else 10000
            t_o_rpi = struct.unpack("<I", data[48:52])[0] if len(data) > 51 else 10000
        except struct.error:
            o_t_rpi = 10000
            t_o_rpi = 10000

        assembly_inst = 1
        if len(data) > 20:
            try:
                assembly_inst = struct.unpack("<H", data[4:6])[0]
            except struct.error:
                pass

        conn_obj = CIPConnection(
            conn_id=o_t_id,
            o_t_id=o_t_id,
            t_o_id=t_o_id,
            o_t_rpi=o_t_rpi,
            t_o_rpi=t_o_rpi,
            o_t_size=o_t_size,
            t_o_size=t_o_size,
            assembly_inst=assembly_inst,
            priority=priority,
        )
        conn_obj.owner_addr = addr
        conn_obj.heartbeat()

        with self._stats_lock:
            self._vuln_stats["ekey_bypassed"] += 1

        with self.connections_lock:
            self.connections[conn_obj.o_t_id] = conn_obj

        log.info("[VULN] connection established: o_t=%#x t_o=%#x rpi=%d/%d size=%d/%d",
                conn_obj.o_t_id, conn_obj.t_o_id,
                conn_obj.o_t_rpi, conn_obj.t_o_rpi,
                conn_obj.o_t_size, conn_obj.t_o_size)

        log.info("[VULN] connection established: o_t=%#x t_o=%#x",
                conn_obj.o_t_id, conn_obj.t_o_id)

        resp = bytes([0xCE, 0x00, 0x00, 0x00])
        resp += struct.pack("<II", o_t_id, t_o_id)
        resp += struct.pack("<I", 0)
        resp += struct.pack("<II", 500000, 500000)
        resp += struct.pack("<II", 100, 100)
        resp += struct.pack("<I", 0)
        return resp

    def get_vuln_report(self) -> Dict[str, Any]:
        with self._stats_lock:
            stats = dict(self._vuln_stats)
        with self.connections_lock:
            stats["active_connections"] = len(self.connections)
        with self.sessions_lock:
            stats["active_sessions"] = len(self.sessions)
        return {
            "simulator_type": "vulnerable",
            "security_features": {
                "session_authentication": "NONE — any RegisterSession accepted",
                "connection_limit": "NONE — unlimited ForwardOpen",
                "electronic_key_validation": "NONE — any device type accepted",
                "assembly_data_protection": "NONE — all data readable",
                "identity_protection": "NONE — full device info exposed",
                "rate_limiting": "NONE — no connection flood prevention",
                "cip_reset_stop_auth": "NONE — Reset/Stop accepted without auth",
                "session_hijacking": "VULNERABLE — any handle reused",
            },
            "stats": stats,
        }


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Vulnerable EtherNet/IP Simulator")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=44818, help="Bind port")
    parser.add_argument("--report-interval", type=int, default=0,
                        help="Print vulnerability report every N seconds (0=off)")
    args = parser.parse_args()

    s = EthernetIPVulnSimulator(args.host, args.port)
    s.start()

    def report_loop():
        while s._running:
            time.sleep(max(args.report_interval, 1))
            if args.report_interval:
                report = s.get_vuln_report()
                log.warning("--- Vulnerability Report ---")
                for key, val in sorted(report["stats"].items()):
                    log.warning("  %s: %s", key, val)

    if args.report_interval:
        threading.Thread(target=report_loop, daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        s.stop()
