"""
工控协议信息检测逻辑代码 - ADS (Automation Device Specification)
==============================================================
基于真实 AMS/ADS 协议结构的检测代码

参考: Beckhoff TwinCAT ADS 规范
      pyads (github.com/stlehmann/pyads)
"""

import struct
from typing import Optional, Dict, Any, List, Tuple

# ---- 协议特征 ----
ADS_DEFAULT_PORT = 48898
AMS_HEADER_LEN = 32

CMD_NAMES = {
    0: 'INVALID', 1: 'READ_DEVICE_INFO', 2: 'READ', 3: 'WRITE',
    4: 'READ_STATE', 5: 'WRITE_CONTROL', 6: 'ADD_NOTIFICATION',
    7: 'DEL_NOTIFICATION', 8: 'NOTIFICATION', 9: 'READ_WRITE',
}

INDEX_GROUP_NAMES = {
    0x00000001: 'DEVICE_INFO',
    0x0000000F: 'SYMTAB',
    0x00000010: 'SYMBOL_NAME',
    0x00000011: 'SYMBOL_VAL',
    0x00000020: 'RETAIN_DATA',
    0x00000030: 'PLC_PROGRAM',
    0x00000040: 'ATOMIC_READ_WRITE',
    0x00000050: 'ATOMIC_READ_AND_WRITE',
    0x00000080: 'PLC_DATA',
}

ERROR_NAMES = {
    0: 'NO_ERR',
    0x700: 'DEVICE_ERROR',
    0x704: 'INVALID_AMS_NETID',
    0x708: 'INVALID_PORT',
    0x710: 'INVALID_PARAM',
    0x71C: 'ACCESS_DENIED',
    0x750: 'SRV_NOT_SUPPORTED',
}


def parse_ams_tcp_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """
    解析 AMS/TCP 帧
    帧格式: [0x0000(2B)][AMS总长(4B)][AMS头(32B)][负载]
    """
    if len(data) < 6:
        return None
    if data[:2] != b'\x00\x00':
        return None

    try:
        ams_len = struct.unpack_from('!I', data, 2)[0]
        if ams_len < AMS_HEADER_LEN or ams_len > 65535:
            return None

        if len(data) < 6 + ams_len:
            return None

        hdr = data[6:6 + AMS_HEADER_LEN]
        payload = data[6 + AMS_HEADER_LEN:6 + ams_len]

        target_net = '.'.join(str(hdr[i]) for i in range(6))
        target_port = struct.unpack_from('!H', hdr, 6)[0]
        source_net = '.'.join(str(hdr[8 + i]) for i in range(6))
        source_port = struct.unpack_from('!H', hdr, 14)[0]
        cmd_id = struct.unpack_from('!H', hdr, 16)[0]
        state_flags = struct.unpack_from('!H', hdr, 18)[0]
        data_len = struct.unpack_from('!I', hdr, 20)[0]
        error_code = struct.unpack_from('!I', hdr, 24)[0]
        invoke_id = struct.unpack_from('!I', hdr, 28)[0]

        cmd_name = CMD_NAMES.get(cmd_id, f'0x{cmd_id:04x}')
        err_name = ERROR_NAMES.get(error_code, f'0x{error_code:04x}')

        # 置信度计算
        confidence = 0.5
        if cmd_id in CMD_NAMES:
            confidence += 0.3
        if error_code in ERROR_NAMES:
            confidence += 0.1
        if 0 < data_len < 10000:
            confidence += 0.1

        # 提取读/写请求中的 indexGroup/indexOffset
        index_info = {}
        if len(payload) >= 8 and cmd_id in (2, 3):
            ig = struct.unpack_from('!I', payload, 0)[0]
            io = struct.unpack_from('!I', payload, 4)[0]
            ig_name = INDEX_GROUP_NAMES.get(ig, f'0x{ig:08x}')
            index_info = {'index_group': f'0x{ig:08x}',
                          'index_group_name': ig_name,
                          'index_offset': f'0x{io:08x}'}

        return {
            'protocol': 'ADS',
            'confidence': min(confidence, 0.99),
            'fields': {
                'target_net_id': target_net,
                'target_port': target_port,
                'source_net_id': source_net,
                'source_port': source_port,
                'cmd_id': cmd_id,
                'cmd_name': cmd_name,
                'state_flags': f'0x{state_flags:04x}',
                'data_length': data_len,
                'error_code': f'0x{error_code:04x}',
                'error_name': err_name,
                'invoke_id': invoke_id,
                'index_info': index_info,
            },
            'payload': payload,
        }

    except (struct.error, IndexError, ValueError):
        return None


def detect_anomaly(frame_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """检测 ADS 流量异常"""
    anomalies = []
    fields = frame_info.get('fields', {})

    cmd_id = fields.get('cmd_id', -1)
    cmd_name = fields.get('cmd_name', '')
    err_name = fields.get('error_name', '')
    index_info = fields.get('index_info', {})

    # 1. 未知命令码
    if cmd_id not in CMD_NAMES:
        anomalies.append({
            'type': 'UNKNOWN_CMD',
            'severity': 'HIGH',
            'desc': f'未知 ADS 命令码: 0x{cmd_id:04x}',
        })

    # 2. 错误响应
    if err_name not in ('NO_ERR', '0x0'):
        anomalies.append({
            'type': 'ADS_ERROR_RESPONSE',
            'severity': 'MEDIUM',
            'desc': f'ADS 返回错误: {err_name}',
        })

    # 3. WriteControl 操作 (状态变更)
    if cmd_id == 5:
        anomalies.append({
            'type': 'STATE_CHANGE',
            'severity': 'HIGH',
            'desc': 'ADS WriteControl — PLC 状态变更操作',
        })

    # 4. AddNotification (变量监控)
    if cmd_id == 6:
        anomalies.append({
            'type': 'NOTIFICATION_SUBSCRIBE',
            'severity': 'MEDIUM',
            'desc': 'ADS AddNotification — 变量监控订阅',
        })

    # 5. 大批量写操作
    if cmd_id == 3 and index_info:
        anomalies.append({
            'type': 'WRITE_OPERATION',
            'severity': 'INFO',
            'desc': f'ADS Write: {index_info.get("index_group_name", "")} '
                    f'@{index_info.get("index_offset", "")}',
        })

    # 6. 异常数据长度
    data_len = fields.get('data_length', 0)
    if data_len > 10000:
        anomalies.append({
            'type': 'ABNORMAL_LENGTH',
            'severity': 'HIGH',
            'desc': f'ADS 数据长度异常: {data_len}',
        })

    return anomalies


def detect(data: bytes, src_port: int = 0, dst_port: int = 0) -> Dict[str, Any]:
    """ADS 协议检测主函数"""
    result = {
        'detected': False,
        'protocol': 'ADS',
        'confidence': 0.0,
        'info': {},
        'anomalies': [],
    }

    # 端口预检
    if src_port == 48898 or dst_port == 48898:
        result['confidence'] += 0.2
        result['info']['port_hint'] = True

    frame_info = parse_ams_tcp_frame(data)
    if frame_info:
        result['detected'] = True
        result['confidence'] = max(result['confidence'], frame_info['confidence'])
        result['info'] = frame_info
        result['anomalies'] = detect_anomaly(frame_info)

    return result


class ADSFlowStats:
    """ADS 流量统计"""
    def __init__(self):
        self.total = 0
        self.cmd_count: Dict[str, int] = {}
        self.error_count = 0

    def update(self, info: Dict[str, Any]):
        self.total += 1
        fields = info.get('fields', {})
        cmd = fields.get('cmd_name', 'Unknown')
        self.cmd_count[cmd] = self.cmd_count.get(cmd, 0) + 1
        err = fields.get('error_name', '')
        if err not in ('NO_ERR', '0x0'):
            self.error_count += 1

    def get_stats(self) -> Dict[str, Any]:
        return {
            'total_packets': self.total,
            'cmd_distribution': dict(sorted(self.cmd_count.items())),
            'errors': self.error_count,
        }


if __name__ == '__main__':
    # 测试：构造一个 AMS Read 请求
    payload = b'\x00\x00\x00\x80\x00\x00\x10\x00\x00\x00\x00\x04'

    def _test_frame():
        import socket
        hdr = b''
        hdr += b'\xc0\xa8\x00\x01\x01\x01'  # target 192.168.0.1.1.1
        hdr += struct.pack('!H', 851)
        hdr += b'\xc0\xa8\x00\x02\x01\x01'  # source
        hdr += struct.pack('!H', 800)
        hdr += struct.pack('!HHIII', 2, 0x0001, len(payload), 0, 1)
        frame = b'\x00\x00' + struct.pack('!I', 32 + len(payload)) + hdr + payload
        return frame

    result = detect(_test_frame())
    print(f'检测: {result["detected"]}, 置信度: {result["confidence"]:.2f}')
    print(f'字段: {result["info"].get("fields", {})}')
    print(f'异常: {result["anomalies"]}')
