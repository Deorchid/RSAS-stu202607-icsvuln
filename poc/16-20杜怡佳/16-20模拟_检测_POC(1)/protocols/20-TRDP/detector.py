"""
工控协议信息检测逻辑代码 - TRDP (IEC 61375)
===========================================
基于 IEC 61375-2-3 标准的列车实时数据协议检测。

TRDP 帧结构 (40 字节固定头):
  [0-1]   协议版本 (2B)    0x0100 = v1.0
  [2-3]   操作码 (2B)      0=REQUEST, 1=RESPONSE, 2=PUBLISH, 3=SUBSCRIBE
  [4-5]   ComId (2B)       通信标识符
  [6-7]   ETB ID (2B)      列车骨干网段 ID
  [8-9]   源 ID (2B)       发送设备 ID
  [10-11] 目标 ID (2B)     接收设备 ID (0=广播)
  [12-15] 序列号 (4B)
  [16-23] 时间戳 (8B)      微秒级 Unix 时间戳
  [24-27] 剩余时间 (4B)    TTL
  [28-29] 标志位 (2B)
  [30-31] 数据长度 (2B)
  [32-39] 保留 (8B)
  [40+]   数据负载

参考: IEC 61375-2-3, TCNOpen TRDP (github.com/TCNOpen/trdp)
"""

import struct
import time
from typing import Optional, Dict, Any, List, Tuple

TRDP_HEADER_LEN = 40
TRDP_PD_PORT = 17224
TRDP_MD_PORT = 17225
TRDP_BROADCAST_ID = 0

# 操作码
OPCODES = {
    0: 'REQUEST',
    1: 'RESPONSE',
    2: 'PUBLISH',
    3: 'SUBSCRIBE',
    4: 'UNSUBSCRIBE',
    5: 'SUBSCRIPTION_REPLY',
    0xFF: 'ERROR',
}

# 标准信号 ComId 映射 (IEC 61375 标准定义)
SIGNALS = {
    0x0001: ('Speed', 'km/h', float),
    0x0002: ('BrakePressure', 'kPa', float),
    0x0003: ('DoorStatus', '', int),
    0x0004: ('MotorCurrent', 'A', float),
    0x0005: ('BatteryVoltage', 'V', float),
    0x0006: ('Temperature', '°C', float),
    0x0007: ('WheelSlip', '%', float),
    0x0008: ('Acceleration', 'm/s²', float),
    0x0009: ('GPS_Latitude', '°', float),
    0x000A: ('EmergencyBrake', '', int),
    0x000B: ('PassengerCount', '', int),
    0x000C: ('AirPressure', 'kPa', float),
    0x000D: ('TractionPower', 'kW', float),
    0x000E: ('SpeedLimit', 'km/h', float),
    0x0010: ('NextStation', '', str),
    0x0011: ('DoorSide', '', int),  # 0=left, 1=right, 2=both
    0x0012: ('CabinTemp', '°C', float),
    0x0013: ('HVAC_Status', '', int),
    0x0014: ('FireAlarm', '', int),
    0x0015: ('CO2_Level', 'ppm', float),
}

# 车辆功能标识 (常见设备类型)
DEVICE_TYPES = {
    0x01: 'VCU (车辆控制单元)',
    0x02: 'TCU (牵引控制单元)',
    0x03: 'BCU (制动控制单元)',
    0x04: 'DCU (车门控制单元)',
    0x05: 'ACU (空调控制单元)',
    0x06: 'PIS (乘客信息系统)',
    0x07: 'BCM (电池管理单元)',
    0x08: 'ERTMS (欧洲列车控制)',
    0xFF: 'Diagnostic tool',
}


def parse_trdp_header(data: bytes) -> Optional[Dict[str, Any]]:
    """解析 TRDP 40 字节固定头"""
    if len(data) < TRDP_HEADER_LEN:
        return None

    try:
        (version, opcode, com_id, etb_id, src_id, dst_id,
         seq_no, timestamp, remain_life, flags, data_len, _) = \
            struct.unpack_from('!HHIHHHIQQHHH', data, 0)

        op_name = OPCODES.get(opcode, f'0x{opcode:04x}')
        sig_info = SIGNALS.get(com_id)
        sig_name = sig_info[0] if sig_info else f'0x{com_id:04x}'

        # 正确计算负载 (数据长度字段指示实际负载长度)
        payload = data[TRDP_HEADER_LEN:TRDP_HEADER_LEN + data_len] if 0 < data_len <= len(data) - TRDP_HEADER_LEN else b''

        # 解析标志位
        flags_info = _parse_flags(flags)

        # 置信度计算
        confidence = 0.5  # 基础分
        if opcode in OPCODES:
            confidence += 0.15
        if com_id in SIGNALS:
            confidence += 0.1
        if version == 0x0100:
            confidence += 0.05
        if 0 < data_len < 1500:
            confidence += 0.05
        if dst_id == 0 or src_id != 0:
            confidence += 0.05
        # 时间戳合理性 (2000-2038 年范围)
        if 946684800000000 < timestamp < 2208988800000000:
            confidence += 0.05

        return {
            'protocol': 'TRDP',
            'confidence': min(confidence, 0.95),
            'fields': {
                'version': f'0x{version:04x}',
                'version_str': f'v{(version >> 8) & 0xFF}.{version & 0xFF}',
                'opcode': opcode,
                'opcode_name': op_name,
                'com_id': com_id,
                'com_id_hex': f'0x{com_id:04x}',
                'signal_name': sig_name,
                'signal_unit': sig_info[1] if sig_info else '',
                'etb_id': etb_id,
                'src_id': src_id,
                'dst_id': dst_id,
                'seq_no': seq_no,
                'timestamp': timestamp,
                'timestamp_sec': timestamp / 1000000.0,
                'remain_life': remain_life,  # 剩余有效时间 (ms)
                'flags': flags_info,
                'data_length': data_len,
            },
            'payload': payload,
        }

    except (struct.error, IndexError, ValueError):
        return None


def _parse_flags(flags: int) -> Dict[str, Any]:
    """解析 TRDP 标志位"""
    return {
        'raw': f'0x{flags:04x}',
        'valid': bool(flags & 0x0001),
        'redundant': bool(flags & 0x0002),
        'emergency': bool(flags & 0x0004),
        'test': bool(flags & 0x0008),
    }


def parse_payload_signal(payload: bytes, com_id: int) -> Optional[Dict[str, Any]]:
    """尝试解析 TRDP 数据负载中的信号值"""
    sig_info = SIGNALS.get(com_id)
    if not sig_info or len(payload) < 4:
        sig_name = f'0x{com_id:04x}'
        return {'signal': sig_name, 'raw': payload.hex()}

    sig_name, sig_unit, sig_type = sig_info

    if sig_type == float and len(payload) >= 4:
        val = struct.unpack('!f', payload[:4])[0]
        return {'signal': sig_name, 'value': round(val, 2), 'unit': sig_unit}
    elif sig_type == int and len(payload) >= 4:
        val = struct.unpack('!I', payload[:4])[0]
        return {'signal': sig_name, 'value': val, 'unit': sig_unit}

    return {'signal': sig_name, 'raw': payload.hex()}


def parse_multi_signal_payload(payload: bytes) -> List[Dict[str, Any]]:
    """
    解析多信号 TRDP 负载 (常见格式: 4B ComId + 4B Value 重复)
    有些实现使用 4B ComId + 4B float, 有些使用 2B ComId + 2B/4B value
    """
    signals = []
    pos = 0
    while pos + 8 <= len(payload):
        com_id = struct.unpack_from('!I', payload, pos)[0]
        sig_info = SIGNALS.get(com_id)
        sig_name = sig_info[0] if sig_info else f'0x{com_id:04x}'
        val_raw = payload[pos + 4:pos + 8]
        if sig_info and sig_info[2] == float:
            val = round(struct.unpack('!f', val_raw)[0], 2)
        else:
            val = struct.unpack('!I', val_raw)[0]
        signals.append({'signal': sig_name, 'value': val,
                        'unit': sig_info[1] if sig_info else ''})
        pos += 8

    # 尝试 2B ComId + 2B Value
    if not signals and pos + 4 <= len(payload):
        pos = 0
        while pos + 4 <= len(payload):
            com_id = struct.unpack_from('!H', payload, pos)[0]
            sig_info = SIGNALS.get(com_id)
            sig_name = sig_info[0] if sig_info else f'0x{com_id:04x}'
            val = struct.unpack_from('!H', payload, pos + 2)[0]
            signals.append({'signal': sig_name, 'value': val,
                            'unit': sig_info[1] if sig_info else ''})
            pos += 4

    return signals


def detect_anomaly(info: Dict[str, Any], previous_states: Optional[Dict[int, int]] = None) -> List[Dict[str, Any]]:
    """检测 TRDP 流量异常"""
    anomalies = []
    fields = info.get('fields', {})
    payload = info.get('payload', b'')

    opcode = fields.get('opcode', -1)
    op_name = fields.get('opcode_name', '')
    com_id = fields.get('com_id', 0)
    seq_no = fields.get('seq_no', 0)
    src_id = fields.get('src_id', 0)
    dst_id = fields.get('dst_id', 0)
    remain_life = fields.get('remain_life', 0)
    flags = fields.get('flags', {})
    data_len = fields.get('data_length', 0)

    # 1. 紧急制动信号
    if com_id == 0x000A:
        if len(payload) >= 4:
            brake_val = struct.unpack('!I', payload[:4])[0]
            if brake_val == 1:
                anomalies.append({
                    'type': 'EMERGENCY_BRAKE',
                    'severity': 'CRITICAL',
                    'desc': f'紧急制动触发 (src_id={src_id})',
                })

    # 2. 序列号异常 (跳号 / 重放)
    if seq_no > 10_000_000:
        anomalies.append({
            'type': 'ABNORMAL_SEQ',
            'severity': 'MEDIUM',
            'desc': f'序列号异常: {seq_no} (可能为伪造或溢出)',
        })

    # 3. 序列号跳号检测 (需要传入 previous_states)
    if previous_states is not None and src_id in previous_states:
        prev_seq = previous_states[src_id]
        if seq_no > 0 and prev_seq > 0:
            gap = seq_no - prev_seq
            if gap > 100:
                anomalies.append({
                    'type': 'SEQ_GAP',
                    'severity': 'HIGH',
                    'desc': f'序列号跳号: {prev_seq} → {seq_no} (gap={gap})',
                })
            elif gap < 0:
                anomalies.append({
                    'type': 'SEQ_REPLAY',
                    'severity': 'CRITICAL',
                    'desc': f'序列号回退 (重放攻击): {prev_seq} → {seq_no}',
                })

    # 4. 紧急标志异常
    if flags.get('emergency', False):
        anomalies.append({
            'type': 'EMERGENCY_FLAG',
            'severity': 'HIGH',
            'desc': f'TRDP 紧急标志设置 (src_id={src_id})',
        })

    # 5. 测试标志
    if flags.get('test', False):
        anomalies.append({
            'type': 'TEST_FLAG',
            'severity': 'MEDIUM',
            'desc': 'TRDP 测试标志为 True (测试报文)',
        })

    # 6. 错误操作码
    if opcode == 0xFF:
        anomalies.append({
            'type': 'TRDP_ERROR',
            'severity': 'HIGH',
            'desc': 'TRDP 错误响应 (opcode=0xFF)',
        })

    # 7. 剩余时间异常
    if remain_life == 0:
        anomalies.append({
            'type': 'TTL_ZERO',
            'severity': 'HIGH',
            'desc': 'TRDP 剩余时间=0, 报文即将过期丢弃',
        })
    elif remain_life > 60000:
        anomalies.append({
            'type': 'ABNORMAL_TTL',
            'severity': 'LOW',
            'desc': f'TRDP 剩余时间异常: {remain_life}ms',
        })

    # 8. 广播风暴检测
    if dst_id == 0 and data_len > 500:
        anomalies.append({
            'type': 'BROADCAST_STORM',
            'severity': 'MEDIUM',
            'desc': f'大型广播报文: comId=0x{com_id:04x} len={data_len}',
        })

    # 9. 未知 ComId
    if com_id not in SIGNALS and com_id != 0x1000:
        anomalies.append({
            'type': 'UNKNOWN_COMID',
            'severity': 'INFO',
            'desc': f'未知 ComId: 0x{com_id:04x}',
        })

    # 10. 异常数据长度
    if data_len > 1400:
        anomalies.append({
            'type': 'ABNORMAL_LENGTH',
            'severity': 'MEDIUM',
            'desc': f'TRDP 数据长度异常: {data_len}B (超过典型 MTU)',
        })

    # 11. 安全检查：写入关键信号
    if opcode == 3 and com_id in (0x000A, 0x0003, 0x0002):
        anomalies.append({
            'type': 'CRITICAL_SIGNAL_WRITE',
            'severity': 'CRITICAL',
            'desc': f'写入关键安全信号: {SIGNALS.get(com_id, ["Unknown"])[0]} (opcode=SUBSCRIBE → 可能为控制指令)',
        })

    # 12. 信号值合理性检查
    if payload and com_id in SIGNALS:
        sig_info = SIGNALS[com_id]
        try:
            if sig_info[2] == float and len(payload) >= 4:
                val = struct.unpack('!f', payload[:4])[0]
                if com_id == 0x0001 and val > 600:  # Speed > 600 km/h
                    anomalies.append({
                        'type': 'UNREALISTIC_SPEED',
                        'severity': 'HIGH',
                        'desc': f'速度值不合理: {val:.0f} km/h',
                    })
                elif com_id == 0x0002 and val > 1500:  # Brake pressure > 1500 kPa
                    anomalies.append({
                        'type': 'UNREALISTIC_PRESSURE',
                        'severity': 'MEDIUM',
                        'desc': f'制动压力不合理: {val:.0f} kPa',
                    })
                elif com_id == 0x0006 and abs(val) > 200:  # Temp
                    anomalies.append({
                        'type': 'ABNORMAL_TEMPERATURE',
                        'severity': 'MEDIUM',
                        'desc': f'温度值异常: {val:.0f}°C',
                    })
        except (struct.error, ValueError):
            pass

    return anomalies


def detect(data: bytes, src_port: int = 0, dst_port: int = 0,
           previous_states: Optional[Dict[int, int]] = None) -> Dict[str, Any]:
    """
    TRDP 协议检测主函数

    参数:
        data: 原始数据包字节
        src_port: 源端口
        dst_port: 目的端口
        previous_states: 先前状态 {src_id: seq_no}，用于重放/跳号检测

    返回:
        {detected, protocol, confidence, info, anomalies}
    """
    result = {
        'detected': False,
        'protocol': 'TRDP',
        'confidence': 0.0,
        'info': {},
        'anomalies': [],
    }

    # 端口预检
    if src_port in (17224, 17225) or dst_port in (17224, 17225):
        result['confidence'] += 0.25
        result['info']['port_hint'] = True
        result['info']['msg_type'] = 'PD' if (src_port == 17224 or dst_port == 17224) else 'MD'

    # 协议头解析
    header_info = parse_trdp_header(data)
    if header_info:
        result['detected'] = True
        result['confidence'] = max(result['confidence'], header_info['confidence'])
        result['info']['header'] = header_info
        result['info']['payload_analysis'] = parse_payload_signal(
            header_info.get('payload', b''),
            header_info.get('fields', {}).get('com_id', 0)
        )

        # 异常检测
        result['anomalies'] = detect_anomaly(header_info, previous_states)

        # 如果有多信号负载，尝试解析
        payload = header_info.get('payload', b'')
        if len(payload) >= 16:
            multi = parse_multi_signal_payload(payload)
            if multi:
                result['info']['multi_signals'] = multi

    return result


class TRDPFlowStats:
    """TRDP 流量统计与状态追踪"""

    def __init__(self):
        self.total_packets = 0
        self.opcode_count: Dict[str, int] = {}
        self.src_id_seqs: Dict[int, int] = {}  # src_id -> last seq_no
        self.signal_values: Dict[str, float] = {}  # signal_name -> last value
        self.devices_seen: set = set()
        self.anomaly_count = 0

    def update(self, info: Dict[str, Any]):
        """更新流量统计"""
        self.total_packets += 1

        fields = info.get('fields', {})
        op = fields.get('opcode_name', 'Unknown')
        self.opcode_count[op] = self.opcode_count.get(op, 0) + 1

        src_id = fields.get('src_id', 0)
        seq = fields.get('seq_no', 0)
        if src_id:
            self.devices_seen.add(src_id)
            if src_id in self.src_id_seqs:
                if seq < self.src_id_seqs[src_id]:
                    self.anomaly_count += 1
            self.src_id_seqs[src_id] = seq

    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            'total_packets': self.total_packets,
            'opcode_distribution': dict(sorted(self.opcode_count.items())),
            'devices_seen': sorted(self.devices_seen),
            'anomaly_count': self.anomaly_count,
        }


if __name__ == '__main__':
    import time

    print('=' * 60)
    print('TRDP 检测器自测试')
    print('=' * 60)

    # 测试 1: 正常 PUBLISH 报文 (速度信号)
    now = int(time.time() * 1000000)
    normal_pkt = struct.pack(
        '!HHIHHHIQQHHH',
        0x0100, 2, 0x0001, 1, 1, 0,
        1, now, 4000, 0, 4, 0
    ) + struct.pack('!f', 85.5)  # 速度 85.5 km/h

    r1 = detect(normal_pkt, src_port=17224)
    print(f'\nTest 1 - 正常速度报文:')
    print(f'  检测: {r1["detected"]}, 置信度: {r1["confidence"]:.2f}')
    if r1['info'].get('payload_analysis'):
        print(f'  信号: {r1["info"]["payload_analysis"]}')
    print(f'  异常: {len(r1["anomalies"])} 个')

    # 测试 2: 紧急制动信号
    brake_pkt = struct.pack(
        '!HHIHHHIQQHHH',
        0x0100, 2, 0x000A, 1, 3, 0,
        100, now + 1000, 4000, 0x0004, 4, 0
    ) + struct.pack('!I', 1)  # 紧急制动=1

    r2 = detect(brake_pkt, src_port=17224)
    print(f'\nTest 2 - 紧急制动:')
    print(f'  检测: {r2["detected"]}, 置信度: {r2["confidence"]:.2f}')
    for a in r2['anomalies']:
        print(f'  [{a["severity"]}] {a["desc"]}')

    # 测试 3: 序列号回退 (重放检测)
    prev_states = {1: 500}
    replay_pkt = struct.pack(
        '!HHIHHHIQQHHH',
        0x0100, 2, 0x0001, 1, 1, 0,
        10, now, 4000, 0, 4, 0
    ) + struct.pack('!f', 85.0)

    r3 = detect(replay_pkt, src_port=17224, previous_states=prev_states)
    print(f'\nTest 3 - 重放检测 (seq 500→10):')
    for a in r3['anomalies']:
        print(f'  [{a["severity"]}] {a["desc"]}')

    # 测试 4: 流量统计
    stats = TRDPFlowStats()
    for i in range(5):
        pkt = struct.pack(
            '!HHIHHHIQQHHH',
            0x0100, 2, 0x0001, 1, 1, 0,
            i + 1, now + i * 1000, 4000, 0, 4, 0
        ) + struct.pack('!f', 80.0 + i)
        r = detect(pkt, src_port=17224)
        stats.update(r['info'])

    print(f'\nTest 4 - 流量统计:')
    print(f'  总报文: {stats.get_stats()["total_packets"]}')
    print(f'  设备: {stats.get_stats()["devices_seen"]}')

    print('\n' + '=' * 60)
    print('所有测试完成')
    print('=' * 60)
