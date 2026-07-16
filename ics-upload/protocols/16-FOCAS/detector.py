"""
工控协议信息检测逻辑代码 - FOCAS (FANUC Open CNC API)
=====================================================
基于 FANUC FOCAS1/FOCAS2 以太网协议的检测代码。
端口: TCP 8193

帧结构:
  [0-1]   长度 (2B) — 包含头部的总帧长度
  [2-3]   功能码 (2B)
  [4-5]   错误码 (2B)
  [6-9]   序列号 (4B)
  [10-15] 保留 (6B)
  [16+]   数据负载

参考: FANUC fwlib 文档, pyfanuc 逆向工程
"""

import struct
from typing import Optional, Dict, Any, List

FOCAS_PORT = 8193
FOCAS_HEADER_LEN = 16

# 功能码分类
FUNC_NAMES = {
    0x0000: 'ALLOC_HANDLE',
    0x0010: 'CONNECT',
    0x0011: 'DISCONNECT',
    0x0100: 'READ_SYSINFO',
    0x0101: 'READ_VERSION',
    0x0200: 'READ_AXIS',
    0x0201: 'READ_DYNAMIC',
    0x0202: 'READ_SPINDLE',
    0x0203: 'READ_SERVO',
    0x0300: 'READ_ALARM',
    0x0301: 'READ_ALARM_HIST',
    0x0302: 'READ_OPERATOR_MSG',
    0x0400: 'READ_PARAM',
    0x0401: 'WRITE_PARAM',
    0x0402: 'READ_PMC',
    0x0403: 'WRITE_PMC',
    0x0500: 'READ_PROGRAM',
    0x0501: 'WRITE_PROGRAM',
    0x0502: 'READ_PROGRAM_LIST',
    0x0600: 'READ_STATUS',
    0x0601: 'READ_OPERATION_MODE',
    0x0602: 'READ_FEEDRATE',
    0x0700: 'READ_SPEED',
    0x0701: 'READ_LOAD',
    0x0702: 'READ_RUN_TIME',
    0x0800: 'READ_TOOL_INFO',
    0x0801: 'READ_TOOL_OFFSET',
    0x0900: 'READ_MACRO',
    0x0901: 'WRITE_MACRO',
}

# 功能码分类 (读写/控制)
FUNC_CATEGORIES = {
    'read': [0x0100, 0x0101, 0x0200, 0x0201, 0x0202, 0x0203, 0x0300, 0x0301,
             0x0302, 0x0400, 0x0402, 0x0500, 0x0502, 0x0600, 0x0601, 0x0602,
             0x0700, 0x0701, 0x0702, 0x0800, 0x0801, 0x0900],
    'write': [0x0401, 0x0403, 0x0501, 0x0901],
    'control': [0x0000, 0x0010, 0x0011],
}

CNC_MODELS = [
    b'FANUC Series 0i', b'Series 30i', b'Series 31i',
    b'Series 32i', b'Series 35i', b'Series 16i',
    b'Series 18i', b'Series 21i', b'Power Mate',
    b'Series 0i-TF', b'Series 0i-TC', b'Series 0i-MF',
    b'Series 0i-MC', b'Series 30i-B', b'Series 31i-B5',
    b'ROBOCUT', b'ROBODRILL', b'Laser C',
]


def detect_focas_header(data: bytes) -> Optional[Dict[str, Any]]:
    """检测 FOCAS 协议帧头 (16 字节)"""
    if len(data) < FOCAS_HEADER_LEN:
        return None

    try:
        length = struct.unpack_from('!H', data, 0)[0]
        func = struct.unpack_from('!H', data, 2)[0]
        error = struct.unpack_from('!H', data, 4)[0]
        seq = struct.unpack_from('!I', data, 6)[0]

        # 合理性检查
        if length < FOCAS_HEADER_LEN or length > 65535:
            return None
        if func > 0x2000:  # 功能码超出合理范围
            return None

        func_name = FUNC_NAMES.get(func, f'0x{func:04x}')
        payload = data[FOCAS_HEADER_LEN:length] if length > FOCAS_HEADER_LEN else b''

        # CNC 型号检测
        cnc_model = 'Unknown'
        for pat in CNC_MODELS:
            if pat in payload:
                cnc_model = pat.decode('ascii')
                break

        # 操作类型
        op_type = 'other'
        if func in FUNC_CATEGORIES['read']:
            op_type = 'read'
        elif func in FUNC_CATEGORIES['write']:
            op_type = 'write'
        elif func in FUNC_CATEGORIES['control']:
            op_type = 'control'

        # 置信度计算
        confidence = 0.5  # 基础分
        if func in FUNC_NAMES:
            confidence += 0.3
        if 16 <= length <= 2048:
            confidence += 0.1
        if cnc_model != 'Unknown':
            confidence += 0.1
        if op_type in ('read', 'write'):
            confidence += 0.05

        return {
            'protocol': 'FOCAS',
            'confidence': min(confidence, 0.95),
            'fields': {
                'length': length,
                'func_code': f'0x{func:04x}',
                'func_name': func_name,
                'func_category': op_type,
                'error': error,
                'seq': seq,
                'cnc_model': cnc_model,
            },
            'payload': payload,
        }

    except (struct.error, IndexError, ValueError):
        return None


def detect_anomaly(info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """检测 FOCAS 协议异常"""
    anomalies = []
    fields = info.get('fields', {})

    length = fields.get('length', 0)
    func_name = fields.get('func_name', '')
    func_code = fields.get('func_code', '')
    error = fields.get('error', 0)
    seq = fields.get('seq', 0)
    cnc_model = fields.get('cnc_model', 'Unknown')

    # 1. 错误响应
    if error != 0:
        anomalies.append({
            'type': 'FOCAS_ERROR',
            'severity': 'MEDIUM',
            'desc': f'FOCAS 返回错误码: 0x{error:04x}',
        })

    # 2. 未知功能码
    if func_name.startswith('0x'):
        anomalies.append({
            'type': 'UNKNOWN_FUNC',
            'severity': 'MEDIUM',
            'desc': f'未知功能码: {func_code}',
        })

    # 3. 写入操作 (参数/程序修改)
    if 'WRITE_PARAM' in func_name:
        anomalies.append({
            'type': 'PARAM_WRITE',
            'severity': 'HIGH',
            'desc': f'CNC 参数写入操作: {func_name}',
        })
    if 'WRITE_PROGRAM' in func_name:
        anomalies.append({
            'type': 'PROGRAM_WRITE',
            'severity': 'HIGH',
            'desc': 'CNC 加工程序写入',
        })
    if 'WRITE_PMC' in func_name:
        anomalies.append({
            'type': 'PMC_WRITE',
            'severity': 'CRITICAL',
            'desc': 'PMC 写入操作 — 可能修改梯形图逻辑',
        })
    if 'WRITE_MACRO' in func_name:
        anomalies.append({
            'type': 'MACRO_WRITE',
            'severity': 'HIGH',
            'desc': '宏变量写入 — 可能影响加工程序',
        })

    # 4. 异常序列号
    if seq > 1_000_000:
        anomalies.append({
            'type': 'ABNORMAL_SEQ',
            'severity': 'LOW',
            'desc': f'序列号异常: {seq}',
        })

    # 5. 异常帧长度
    if length > 8000:
        anomalies.append({
            'type': 'ABNORMAL_LENGTH',
            'severity': 'MEDIUM',
            'desc': f'帧长度异常: {length}B',
        })
    elif length == FOCAS_HEADER_LEN and not func_name.startswith('0x'):
        # 空数据帧 (除了控制类)
        if 'WRITE' in func_name:
            anomalies.append({
                'type': 'EMPTY_WRITE',
                'severity': 'MEDIUM',
                'desc': f'写入操作为空数据: {func_name}',
            })

    # 6. CNC 型号识别
    if cnc_model == 'Unknown':
        anomalies.append({
            'type': 'UNKNOWN_CNC_MODEL',
            'severity': 'INFO',
            'desc': '无法识别 CNC 型号',
        })

    # 7. 控制类操作
    if func_name == 'DISCONNECT':
        anomalies.append({
            'type': 'DISCONNECT',
            'severity': 'INFO',
            'desc': 'FOCAS 断开连接请求',
        })

    return anomalies


def detect(data: bytes, src_port: int = 0, dst_port: int = 0) -> Dict[str, Any]:
    """FOCAS 协议检测主函数"""
    result = {
        'detected': False,
        'protocol': 'FOCAS',
        'confidence': 0.0,
        'info': {},
        'anomalies': [],
    }

    # 端口预检
    if src_port == FOCAS_PORT or dst_port == FOCAS_PORT:
        result['confidence'] += 0.2
        result['info']['port_hint'] = True

    # 协议头解析
    header_info = detect_focas_header(data)
    if header_info:
        result['detected'] = True
        result['confidence'] = max(result['confidence'], header_info['confidence'])
        result['info'] = header_info
        result['anomalies'] = detect_anomaly(header_info)

    return result


class FOCASFlowStats:
    """FOCAS 流量统计"""

    def __init__(self):
        self.total = 0
        self.func_count: Dict[str, int] = {}
        self.error_count = 0
        self.write_count = 0

    def update(self, info: Dict[str, Any]):
        self.total += 1
        func = info.get('fields', {}).get('func_name', 'Unknown')
        self.func_count[func] = self.func_count.get(func, 0) + 1
        if info.get('fields', {}).get('error', 0) != 0:
            self.error_count += 1
        if 'WRITE' in func:
            self.write_count += 1

    def get_stats(self) -> Dict[str, Any]:
        return {
            'total_packets': self.total,
            'func_distribution': dict(sorted(self.func_count.items())),
            'errors': self.error_count,
            'write_operations': self.write_count,
        }


if __name__ == '__main__':
    import sys

    print('=' * 60)
    print('FOCAS 检测器自测试')
    print('=' * 60)

    # Test 1: 正常系统信息读取请求
    test1 = struct.pack('!HHHI', 32, 0x0100, 0, 1) + b'\x00' * 6 + b'FANUC Series 0i-MODEL F\x00'
    r1 = detect(test1, dst_port=8193)
    print(f'\nTest 1 - 正常 SYSINFO 请求:')
    print(f'  检测: {r1["detected"]}, 置信度: {r1["confidence"]:.2f}')
    print(f'  CNC型号: {r1["info"].get("fields", {}).get("cnc_model")}')
    print(f'  功能: {r1["info"].get("fields", {}).get("func_name")}')
    print(f'  异常: {len(r1["anomalies"])} 个')

    # Test 2: PMC 写入 (高风险)
    test2 = struct.pack('!HHHI', 24, 0x0403, 0, 1) + b'\x00' * 6 + b'\x01\x02\x03\x04\x05\x06\x07\x08'
    r2 = detect(test2, dst_port=8193)
    print(f'\nTest 2 - PMC 写入 (高风险):')
    for a in r2['anomalies']:
        print(f'  [{a["severity"]}] {a["desc"]}')

    # Test 3: 连接管理
    test3 = struct.pack('!HHHI', 16, 0x0010, 0, 1) + b'\x00' * 6
    r3 = detect(test3)
    print(f'\nTest 3 - CONNECT 请求:')
    print(f'  检测: {r3["detected"]}, 置信度: {r3["confidence"]:.2f}')

    # Test 4: 错误响应
    test4 = struct.pack('!HHHI', 16, 0x0100, 0x0001, 1) + b'\x00' * 6
    r4 = detect(test4, dst_port=8193)
    print(f'\nTest 4 - 错误响应:')
    print(f'  检测: {r4["detected"]}, 置信度: {r4["confidence"]:.2f}')
    for a in r4['anomalies']:
        print(f'  [{a["severity"]}] {a["desc"]}')

    # Test 5: 流量统计
    stats = FOCASFlowStats()
    for test in [test1, test2, test3, test4]:
        r = detect(test, dst_port=8193)
        if r['detected']:
            stats.update(r['info'])
    print(f'\nTest 5 - 流量统计:')
    print(f'  总报文: {stats.get_stats()["total_packets"]}')
    print(f'  写入操作: {stats.get_stats()["write_operations"]}')
    print(f'  错误数: {stats.get_stats()["errors"]}')

    print('\n' + '=' * 60)
    print('所有测试完成')
    print('=' * 60)
