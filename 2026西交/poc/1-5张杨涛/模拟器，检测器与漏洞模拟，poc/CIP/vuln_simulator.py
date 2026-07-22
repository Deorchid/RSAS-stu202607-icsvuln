"""
CIP 漏洞模拟器 — 模拟存在已知 CWE 的脆弱的 CIP 设备:
  - CWE-306: Missing Authentication (无服务授权)
  - CWE-862: Missing Authorization (电子键绕过)
  - CWE-22:  Path Traversal (任意路径访问)
  - CWE-400: Uncontrolled Resource Consumption (无限连接/对象)
  - CWE-20:  Improper Input Validation (弱序列号校验)
  - CWE-862: Missing Authorization (Assembly 覆写)
  - CWE-404: Improper Resource Shutdown (Reset/Stop 滥用)
  - CWE-416: Use After Free (对象删除后引用)
  - CWE-787: Out-of-bounds Write (内存耗尽)
"""

import struct
import logging
import threading
import time
from collections import defaultdict

from simulator import (
    CIPSimulator, CIPObject, CIPConnection,
    CONN_STATE_CONFIGURING, CONN_STATE_ESTABLISHED,
    SEG_EKEY, log as sim_log,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("CIPVuln")


class CIPVulnSimulator(CIPSimulator):
    """
    CIP 设备模拟器 — 故意暴露 9 类常见 OT 协议漏洞。
    """

    def __init__(self, host="0.0.0.0", port=44819):
        super().__init__(host, port)
        self.name = "CIPVulnSim"

        # ── 漏洞开关 (全部默认开启) ──
        self.vuln_no_auth           = True   # CWE-306
        self.vuln_ekey_bypass       = True   # CWE-862
        self.vuln_path_traversal    = True   # CWE-22
        self.vuln_no_conn_limit     = True   # CWE-400
        self.vuln_assembly_overwrite = True  # CWE-862
        self.vuln_reset_stop_abuse  = True   # CWE-404
        self.vuln_object_deletion   = True   # CWE-416
        self.vuln_memory_exhaustion = True   # CWE-787
        self.vuln_weak_seqnum       = True   # CWE-20

        self._auth_required = False          # 设置为 False 模拟无认证
        self._max_connections = -1           # -1 = 无限制

        self._created_object_count = 0
        self._deleted_object_log: list = []

    # ── 覆写: 电子键校验 — 绕过 ──
    def _validate_electronic_key(self, key):
        if self.vuln_ekey_bypass:
            log.warning("[VULN-CWE-862] Electronic key bypassed: "
                        "vendor=0x%04X type=0x%04X accepted without validation",
                        key.get("vendor", 0), key.get("device_type", 0))
            return True
        return super()._validate_electronic_key(key)

    # ── 覆写: 连接处理 — 无数量限制 ──
    def _process_cip(self, data, addr=None):
        return self._process_cip_vuln(data, addr)

    def _process_cip_vuln(self, data, addr=None):
        if len(data) < 2:
            return 0, b""

        service = data[0]
        path_len = data[1]
        if service & 0x80:
            return len(data), b""

        raw_path = data[2:2 + path_len * 2] if path_len > 0 else b""

        # 传入父类路径解析 (保留其 segment 解析能力)
        from simulator import parse_path_segments, simplify_segments
        segments, _ = parse_path_segments(raw_path)
        pinfo = simplify_segments(segments)

        # ── 电子键绕过 ──
        for seg in segments:
            if seg.seg_type == 0x34 and seg.extra:
                if not self._validate_electronic_key(seg.extra):
                    return len(data), struct.pack("<BBH", service | 0x80, path_len, 0x000F)

        class_id = pinfo.get("class_id", 0)
        instance_id = pinfo.get("instance_id", 1)
        attr_id = pinfo.get("attribute_id", 0)

        # ── 路径遍历: 接受任意路径 ──
        if self.vuln_path_traversal:
            for seg in segments:
                if seg.seg_type == 0x71 and isinstance(seg.value, str):
                    resolved = self._lookup_symbol(seg.value)
                    if resolved:
                        class_id, instance_id = resolved
                    log.warning("[VULN-CWE-22] Symbolic traversal: '%s' → class=%d inst=%d",
                                seg.value, class_id, instance_id)

        # ── CWE-306: 无认证服务接受 ──
        if self.vuln_no_auth and service in (0x52, 0x54, 0x55, 0x56):
            log.warning("[VULN-CWE-306] Service 0x%02X accepted "
                        "WITHOUT authentication!", service)

        # ── ForwardOpen: 无连接限制 ──
        if service == 0x4E:
            if self.vuln_no_conn_limit:
                log.warning("[VULN-CWE-400] ForwardOpen accepted — "
                            "no connection limit enforced (current: %d)",
                            len(self._connections))
            o_to = self._connection_id_counter
            self._connection_id_counter += 1
            t_to = self._connection_id_counter
            self._connection_id_counter += 1

            rpi = 4000
            payload = data[2 + path_len * 2:]
            if len(payload) >= 4:
                rpi = struct.unpack_from("<I", payload, 0)[0]
            if len(payload) >= 8:
                rpi = struct.unpack_from("<I", payload, 4)[0]

            conn = CIPConnection(o_to, t_to, rpi)
            conn.src_addr = addr
            conn.transit(CONN_STATE_CONFIGURING)
            conn.transit(CONN_STATE_ESTABLISHED)
            self._connections[o_to] = conn
            self._connections[t_to] = conn

            resp = struct.pack("<BBH", service | 0x80, path_len, 0x0000)
            resp += struct.pack("<II", o_to, t_to)
            resp += struct.pack("<II", rpi, rpi)
            resp += struct.pack("<I", 0)
            return len(data), resp

        # ── SetAttributeSingle: Assembly 覆写 ──
        if service == 0x10 or service == 0x02:
            val = data[2 + path_len * 2:]
            if self.vuln_assembly_overwrite and class_id == 4:
                log.warning("[VULN-CWE-862] Assembly(4) attr=%d overwritten "
                            "without authorization! val[:8]=%s",
                            attr_id, val[:8].hex())
            elif self.vuln_assembly_overwrite:
                log.warning("[VULN-CWE-862] Write to class=%d attr=%d "
                            "without authorization", class_id, attr_id)

        # ── Reset/Stop 滥用 ──
        if service == 0x52:
            if self.vuln_reset_stop_abuse:
                log.warning("[VULN-CWE-404] Reset accepted — "
                            "device deactivated WITHOUT authentication!")
            self.device_state = 0x0000
            return len(data), struct.pack("<BBH", service | 0x80, path_len, 0x0000)

        if service == 0x54:
            if self.vuln_reset_stop_abuse:
                log.warning("[VULN-CWE-404] Stop accepted — "
                            "device deactivated WITHOUT authentication!")
            self.device_state = 0x0000
            return len(data), struct.pack("<BBH", service | 0x80, path_len, 0x0000)

        # ── Delete: 任意对象删除 ──
        if service == 0x56:
            key = (class_id, instance_id)
            if self.vuln_object_deletion and key in self.objects:
                log.warning("[VULN-CWE-416] Object class=%d inst=%d deleted "
                            "— use-after-free possible!", class_id, instance_id)
                self._deleted_object_log.append(key)
                del self.objects[key]
                return len(data), struct.pack("<BBH", service | 0x80, path_len, 0x0000)

        # ── Create: 内存耗尽 ──
        if service == 0x55:
            self._created_object_count += 1
            if self.vuln_memory_exhaustion:
                log.warning("[VULN-CWE-787] Object class=%d inst=%d created "
                            "(total=%d) — no memory limit!",
                            class_id, instance_id, self._created_object_count)
            key = (class_id, instance_id)
            if key not in self.objects:
                self.objects[key] = CIPObject(class_id, instance_id)
            return len(data), struct.pack("<BBH", service | 0x80, path_len, 0x0000)

        # ── 弱序列号校验 (connected 消息) ──
        if self.vuln_weak_seqnum:
            # 在 _process_cip_connected 中体现
            pass

        return super()._process_cip(data, addr)

    # ── 覆写: connected 消息 — 弱序列号校验 ──
    def _process_cip_connected(self, data, addr, conn_id, seq_num):
        if len(data) < 2:
            return 0, b""
        conn = self._connections.get(conn_id)
        if not conn:
            if self.vuln_weak_seqnum:
                log.warning("[VULN-CWE-20] Connected msg on unknown conn_id=%d — "
                            "accepted (weak validation)", conn_id)
            else:
                log.warning("  Connected msg on unknown conn_id=%d", conn_id)
                return 0, b""

        if conn and conn.state != CONN_STATE_ESTABLISHED:
            if self.vuln_weak_seqnum:
                log.warning("[VULN-CWE-20] Connected msg on non-established conn=%d — "
                            "accepted (weak state check)", conn_id)
            else:
                return 0, b""

        # 弱序列号: 接受任意序列号
        session = self._sessions[addr[0]]
        if self.vuln_weak_seqnum:
            log.warning("[VULN-CWE-20] Weak sequence validation: "
                        "accepting seq_num=%d (prev=%d) without strict check",
                        seq_num, session["seq"])
            session["seq"] = seq_num
        else:
            if seq_num != 0 and seq_num <= session["seq"]:
                log.warning("  Out-of-order seq_num=%d (expected >%d)", seq_num, session["seq"])
            session["seq"] = max(session["seq"], seq_num)

        session["last_activity"] = time.time()
        if conn:
            conn.bump()

        return super()._process_cip(data, addr)

    # ── 覆写: UCMM — 无频率限制 ──
    def _dispatch(self, buf, addr):
        first = buf[0] if len(buf) > 0 else 0

        if len(buf) >= 6 and buf[0] == 0xFF and buf[1] == 0xFD:
            src_ip = addr[0] if addr else "0.0.0.0"
            self._ucmm_count[src_ip] += 1
            if self._ucmm_count[src_ip] > 30:
                log.warning("[VULN-CWE-400] UCMM flooding: %d messages from %s — no rate limit",
                            self._ucmm_count[src_ip], src_ip)

        return super()._dispatch(buf, addr)


if __name__ == "__main__":
    s = CIPVulnSimulator()
    s.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.stop()
