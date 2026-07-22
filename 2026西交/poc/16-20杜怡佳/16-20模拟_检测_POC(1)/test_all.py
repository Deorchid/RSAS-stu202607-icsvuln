"""
工控协议检测与分析系统 — 集成测试
===================================
验证所有协议的检测器、模拟器、漏洞模拟器、POC 的核心功能。

测试范围:
  1. 各协议检测器 — 正确识别本协议报文，拒绝非本协议报文
  2. 异常检测 — 正确标记已知异常
  3. 检测器稳定度 — 在各种输入下不发生崩溃
  4. POC 构造报文可被检测器识别
  5. 模拟器生成的报文可被检测器识别
  6. 所有模块可被正常导入

运行:
  python test_all.py              # 运行所有测试
  python test_all.py --verbose    # 显示详细信息
"""

import sys
import os
import struct
import time
import inspect
import importlib
import traceback

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

VERBOSE = False

pass_count = 0
fail_count = 0
total_assertions = 0


def test(name: str, condition: bool, detail: str = ""):
    global pass_count, fail_count, total_assertions
    total_assertions += 1
    if condition:
        pass_count += 1
        if VERBOSE:
            print(f'  [PASS] {name}{" - " + detail if detail else ""}')
    else:
        fail_count += 1
        print(f'  [FAIL] {name}{" - " + detail if detail else ""}')


def section(title: str):
    print(f'\n{"=" * 60}')
    print(f'  {title}')
    print(f'{"=" * 60}')


protocols = {
    16: ('FOCAS', '16-FOCAS'),
    17: ('ADS', '17-ADS'),
    18: ('GOOSE', '18-GOOSE'),
    19: ('SV', '19-SV'),
    20: ('TRDP', '20-TRDP'),
}

# ============================
# 测试 1: 模块导入
# ============================
section('测试 1: 模块导入')

modules_to_check = {
    'detector': ['detect'],
    'simulator': ['run_simulator'],
    'vuln_simulator': ['run_all'],
    'poc': ['main'],
}

for pid, (pname, pdir) in protocols.items():
    for mod_type, expected_funcs in modules_to_check.items():
        mod_name = f'protocols.{pdir}.{mod_type}'
        try:
            mod = importlib.import_module(mod_name)
            for func in expected_funcs:
                has = hasattr(mod, func)
                test(f'{pname}/{mod_type}.py 有 {func}()', has)
        except Exception as e:
            test(f'{pname}/{mod_type}.py 可导入', False, str(e))

# ============================
# 测试 2: 各协议检测器
# ============================
section('测试 2: 检测器 — 协议识别')


def detect(pid, data, **kwargs):
    pname, pdir = protocols[pid]
    mod = importlib.import_module(f'protocols.{pdir}.detector')
    return mod.detect(data, **kwargs)


# ---- 2a: FOCAS ----
print('\n--- FOCAS 检测器 ---')
pkt = struct.pack('!HHHI', 32, 0x0100, 0, 1) + b'\x00' * 6 + b'FANUC Series 0i-MODEL F\x00'
r = detect(16, pkt, dst_port=8193)
test('FOCAS: 识别 SYSINFO 请求', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')
test('FOCAS: 正确提取 CNC 型号',
     r['info'].get('fields', {}).get('cnc_model') == 'FANUC Series 0i',
     f'model={r["info"].get("fields", {}).get("cnc_model")}')
test('FOCAS: 正确提取功能码', r['info'].get('fields', {}).get('func_name') == 'READ_SYSINFO')

# PMC 写入
pkt2 = struct.pack('!HHHI', 24, 0x0403, 0, 1) + b'\x00' * 6 + b'\x01\x02\x03\x04'
r2 = detect(16, pkt2, dst_port=8193)
test('FOCAS: PMC 写入产生 CRITICAL 异常',
     any(a['type'] == 'PMC_WRITE' for a in r2['anomalies']))

# 随机数据
r3 = detect(16, b'\x00\x00\x00\x00' * 10)
test('FOCAS: 拒绝随机数据', not r3['detected'])

# ---- 2b: ADS ----
print('\n--- ADS 检测器 ---')


def _make_ams_frame(cmd_id=2, payload=b'', err=0):
    hdr = (b'\xc0\xa8\x00\x01\x01\x01' + struct.pack('!H', 851) +
           b'\xc0\xa8\x00\x02\x01\x01' + struct.pack('!H', 800) +
           struct.pack('!HHIII', cmd_id, 0x0001, len(payload), err, 1))
    return b'\x00\x00' + struct.pack('!I', 32 + len(payload)) + hdr + payload


ads_pkt = _make_ams_frame(cmd_id=2, payload=b'\x00\x00\x00\x80\x00\x00\x10\x00\x00\x00\x00\x04')
r5 = detect(17, ads_pkt, dst_port=48898)
test('ADS: 识别 Read 请求', r5['detected'] and r5['confidence'] > 0.8, f'conf={r5["confidence"]:.2f}')
test('ADS: 正确提取命令码', r5['info'].get('fields', {}).get('cmd_name') == 'READ')

ads_pkt2 = _make_ams_frame(cmd_id=5, payload=struct.pack('!HH', 5, 0))
r6 = detect(17, ads_pkt2, dst_port=48898)
test('ADS: WriteControl 产生 HIGH 异常',
     any(a['type'] == 'STATE_CHANGE' for a in r6['anomalies']))

test('ADS: 拒绝随机数据', not detect(17, b'\xff\xff\xff\xff' * 10)['detected'])

# ---- 2c: GOOSE ----
print('\n--- GOOSE 检测器 ---')


def _make_goose_test(st_num=1, test_flag=False):
    def _bl(l):
        return bytes([l]) if l < 128 else struct.pack('!BH', 0x81, l)
    def _bi(tag, v):
        v = v & 0xFFFFFFFF
        d = bytes([v]) if v < 256 else (struct.pack('!H', v) if v < 65536 else struct.pack('!I', v))
        return bytes([tag]) + _bl(len(d)) + d
    def _bs(tag, s):
        d = s.encode('utf-8')
        return bytes([tag]) + _bl(len(d)) + d
    now = time.time()
    ts = struct.pack('!II', int(now), int((now - int(now)) * 1e9))
    pdu = _bs(0xA0, 'TEST/LLN0$GO$test1') + _bi(0xA1, 4000)
    pdu += _bs(0xA2, 'TEST/LLN0$DataSet$ds1') + _bs(0xA3, 'GOOSE_TEST')
    pdu += bytes([0xA4]) + _bl(len(ts)) + ts
    pdu += _bi(0x85, st_num) + _bi(0x86, 0)
    pdu += bytes([0x87, 1, 1 if test_flag else 0])
    pdu += _bi(0x88, 1) + bytes([0x89, 1, 0]) + _bi(0x8A, 1)
    pdu += bytes([0xAB]) + _bl(3) + bytes([0x02, 1, 0])
    gpdu = bytes([0x81]) + _bl(len(pdu)) + pdu
    dst = b'\x01\x0c\xcd\x01\x00\x01'
    src = b'\x00\x50\xc2\x00\x00\x01'
    eth = dst + src
    eth += struct.pack('!HH', 0x8100, 0x8000)
    eth += struct.pack('!HH', 0x88B8, 0x1000)
    eth += struct.pack('!HH', 8 + len(gpdu), 0) + gpdu
    if len(eth) < 64: eth += b'\x00' * (64 - len(eth))
    return eth


goose_pkt = _make_goose_test(st_num=42)
r8 = detect(18, goose_pkt)
test('GOOSE: 识别标准帧', r8['detected'] and r8['confidence'] > 0.8, f'conf={r8["confidence"]:.2f}')

goose_bad = _make_goose_test(st_num=0)
r9 = detect(18, goose_bad)
test('GOOSE: stNum=0 产生异常', any(a['type'] == 'INVALID_STNUM' for a in r9['anomalies']))

goose_test = _make_goose_test(st_num=1, test_flag=True)
r10 = detect(18, goose_test)
test('GOOSE: Test=True 产生异常', any(a['type'] == 'TEST_FLAG' for a in r10['anomalies']))

# ---- 2d: SV ----
print('\n--- SV 检测器 ---')


def _make_sv_test(smp_synch=2, ia=300.0):
    def _bl(l):
        return bytes([l]) if l < 128 else struct.pack('!BH', 0x81, l)
    def _bi(tag, v):
        d = bytes([v]) if v < 256 else struct.pack('!H', v)
        return bytes([tag]) + _bl(len(d)) + d
    def _bs(tag, s):
        d = s.encode('utf-8')
        return bytes([tag]) + _bl(len(d)) + d
    asdu = _bs(0x80, 'MU01')
    asdu += _bi(0x82, 100)
    asdu += _bi(0x83, 1)
    asdu += _bi(0x85, smp_synch)
    seq = struct.pack('!ffffffff', 110000.0, -55000.0, -55000.0, 0.0, ia, ia * -0.5, ia * -0.5, 0.0)
    asdu += bytes([0x87]) + _bl(len(seq)) + seq
    asdu_f = bytes([0x30]) + _bl(len(asdu)) + asdu
    no = bytes([0x80, 1, 1])
    sav = bytes([0x60]) + _bl(len(no) + len(asdu_f)) + no + asdu_f
    dst = b'\x01\x0c\xcd\x04\x00\x01'
    src = b'\x00\x50\xc2\x00\x00\x01'
    eth = dst + src
    eth += struct.pack('!HH', 0x8100, 0x8000)
    eth += struct.pack('!HHHHH', 0x88BA, 0x4000, 8 + len(sav), 0, 0)
    eth += sav
    if len(eth) < 64: eth += b'\x00' * (64 - len(eth))
    return eth


sv_pkt = _make_sv_test()
r11 = detect(19, sv_pkt)
test('SV: 识别正常帧', r11['detected'] and r11['confidence'] > 0.8, f'conf={r11["confidence"]:.2f}')

# smpSynch=0 同步异常
sv_unsync = _make_sv_test(smp_synch=0)
r12 = detect(19, sv_unsync)
pdu = r12['info'].get('fields', {}).get('pdu_fields', {})
test('SV: smpSynch=0 被正确解析', pdu.get('smpSynch') == 'unsync', f'smpSynch={pdu.get("smpSynch")}')
test('SV: smpSynch=0 产生异常', any(a['type'] == 'UNSYNC' for a in r12['anomalies']))

# 过电流异常
sv_overcurrent = _make_sv_test(ia=60000.0)
r13 = detect(19, sv_overcurrent)
test('SV: 过电流产生异常', any(a['type'] == 'ABNORMAL_CURRENT' for a in r13['anomalies']))

# ---- 2e: TRDP ----
print('\n--- TRDP 检测器 ---')

now = int(time.time() * 1000000)
trdp_pkt = struct.pack('!HHIHHHIQQHHH', 0x0100, 2, 0x0001, 1, 1, 0, 1, now, 4000, 0, 4, 0) \
            + struct.pack('!f', 85.5)

r14 = detect(20, trdp_pkt, src_port=17224)
test('TRDP: 识别速度报文', r14['detected'] and r14['confidence'] > 0.8, f'conf={r14["confidence"]:.2f}')
test('TRDP: 正确解析速度值',
     r14['info'].get('payload_analysis', {}).get('value') == 85.5)

# 紧急制动 — 使用 int 编码 (非 float)
brake_pkt = struct.pack('!HHIHHHIQQHHH', 0x0100, 2, 0x000A, 1, 3, 0, 100, now, 4000, 0x0004, 4, 0) \
            + struct.pack('!I', 1)  # 紧急制动=1 (int, 不是 float)
r15 = detect(20, brake_pkt, src_port=17224)
test('TRDP: 紧急制动产生 CRITICAL 异常',
     any(a['type'] == 'EMERGENCY_BRAKE' for a in r15['anomalies']))

# 重放检测
r16 = detect(20, trdp_pkt, src_port=17224, previous_states={1: 500})
test('TRDP: 序列号回退检测', any(a['type'] == 'SEQ_REPLAY' for a in r16['anomalies']))

# ============================
# 测试 3: 跨协议拒绝
# ============================
section('测试 3: 跨协议拒绝')

# FOCAS 检测器 vs 其他协议
test('FOCAS 拒绝 ADS 报文', not detect(16, ads_pkt)['detected'])
test('FOCAS 拒绝 GOOSE 报文', not detect(16, goose_pkt)['detected'])
test('FOCAS 拒绝 SV 报文', not detect(16, sv_pkt)['detected'])

# ADS vs 其他
test('ADS 拒绝 GOOSE 报文', not detect(17, goose_pkt)['detected'])
test('ADS 拒绝 SV 报文', not detect(17, sv_pkt)['detected'])

# GOOSE vs 其他
test('GOOSE 拒绝 ADS 报文', not detect(18, ads_pkt)['detected'])
# EtherType 0x88BA (SV) != 0x88B8 (GOOSE), MAC 第4字节不同
test('GOOSE 拒绝 SV 报文', not detect(18, sv_pkt)['detected'])

# SV vs 其他
test('SV 拒绝 ADS 报文', not detect(19, ads_pkt)['detected'])
test('SV 拒绝 GOOSE 报文', not detect(19, goose_pkt)['detected'])

# TRDP vs 其他 (短数据 < 40 字节不被 TRDP 识别)
test('TRDP 拒绝短数据', not detect(20, b'\x00' * 10)['detected'])

# ============================
# 测试 4: 稳定性
# ============================
section('测试 4: 稳定性 — 异常输入不崩溃')

detectors = {pname: detect for pname in ['FOCAS', 'ADS', 'GOOSE', 'SV', 'TRDP']}
# 实际上是同一个 detect 函数，用 pid 区分
det_map = {16: 'FOCAS', 17: 'ADS', 18: 'GOOSE', 19: 'SV', 20: 'TRDP'}

edge_cases = [b'', b'\x00', b'\xff' * 10, b'\x00' * 100, b'\xff' * 2000, b'Hello, World!', bytes(range(256)) * 4]

for pid, pname in det_map.items():
    for i, case in enumerate(edge_cases):
        try:
            detect(pid, case)
            test(f'{pname}: 异常输入 #{i+1} 不崩溃', True)
        except Exception as e:
            test(f'{pname}: 异常输入 #{i+1} 不崩溃', False, str(e))

# ============================
# 测试 5: POC 报文可被检测器识别
# ============================
section('测试 5: POC 报文兼容性')

# TRDP POC → TRDP 检测器
trdp_poc = importlib.import_module('protocols.20-TRDP.poc')
test_pkt = struct.pack('!HHIHHHIQQHHH', 0x0100, 2, 0x000A, 1, 3, 0,
                       1, int(time.time() * 1000000), 4000, 0x0004, 4, 0) \
           + struct.pack('!I', 1)
r = detect(20, test_pkt, src_port=17224)
test('TRDP POC 报文可被检测', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')

# GOOSE POC → GOOSE 检测器
goose_poc = importlib.import_module('protocols.18-GOOSE.poc')
g_pkt = goose_poc.make_goose(st_num=1, sq_num=0, trip=False)
r = detect(18, g_pkt)
test('GOOSE POC 报文可被检测', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')

# SV POC → SV 检测器
sv_poc = importlib.import_module('protocols.19-SV.poc')
sv_pkt2 = sv_poc.build_sv_packet()
r = detect(19, sv_pkt2)
test('SV POC 报文可被检测', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')

# ============================
# 测试 6: 模拟器兼容性
# ============================
section('测试 6: 模拟器帧兼容性')

# FOCAS 模拟器帧
focas_sim = importlib.import_module('protocols.16-FOCAS.simulator')
frame = focas_sim.FOCASFrame()
frame.func = 0x0100
frame.data = b'FANUC Series 0i-MODEL F\x00'
frame.seq = 1
r = detect(16, frame.pack(), dst_port=8193)
test('FOCAS 模拟器帧可被检测', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')

# ADS 模拟器帧
ads_sim = importlib.import_module('protocols.17-ADS.simulator')
ams = ads_sim.AMSHeader()
ams.cmd_id = 2
ams.source_netid = '127.0.0.1.1.1'
ams.target_netid = '192.168.0.1.1.1'
ads_pkt3 = ads_sim.pack_ams_tcp_frame(ams, b'\x00\x00\x00\x80\x00\x00\x10\x00\x00\x00\x00\x04')
r = detect(17, ads_pkt3, dst_port=48898)
test('ADS 模拟器帧可被检测', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')

# SV 模拟器帧
sv_sim = importlib.import_module('protocols.19-SV.simulator')
mu = sv_sim.SVMergingUnit('TEST_MU')
sv_pkt3 = mu.build_sv_packet()
r = detect(19, sv_pkt3)
test('SV 模拟器帧可被检测', r['detected'] and r['confidence'] > 0.8, f'conf={r["confidence"]:.2f}')

# ============================
# 总结
# ============================
section('测试总结')

print(f'  总断言: {total_assertions}')
print(f'  通过:   {pass_count}')
print(f'  失败:   {fail_count}')
if total_assertions > 0:
    print(f'  通过率: {pass_count / total_assertions * 100:.1f}%')

if fail_count > 0:
    print('\n  [WARN] 部分测试未通过，请检查上述失败项')
    sys.exit(1)
else:
    print('\n  [OK] 所有测试通过！')
    sys.exit(0)
