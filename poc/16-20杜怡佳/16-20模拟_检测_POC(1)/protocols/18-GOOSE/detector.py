"""
工控协议信息检测逻辑代码 - GOOSE (IEC 61850)
==============================================
基于 scapy + 手动 BER 解析的 GOOSE 协议检测

参考: GooseStalker (cutaway-security/goosestalker)
      IEC 61850-8-1
"""

import struct
from typing import Optional, Dict, Any, List, Tuple

ETHERTYPE_GOOSE = 0x88B8
ETHERTYPE_VLAN = 0x8100
GOOSE_MCAST_PREFIX = bytes([0x01, 0x0c, 0xcd, 0x01])  # 完整前缀含第4字节

# GOOSE PDU 标签
TAG_GOCB_REF = 0xA0
TAG_TIME_ALLOWED = 0xA1
TAG_DAT_SET = 0xA2
TAG_GO_ID = 0xA3
TAG_T = 0xA4
TAG_ST_NUM = 0x85
TAG_SQ_NUM = 0x86
TAG_TEST = 0x87
TAG_CONF_REV = 0x88
TAG_NDS_COM = 0x89
TAG_NUM_DAT_SET_ENTRIES = 0x8A
TAG_ALL_DATA = 0xAB

TAG_NAMES = {
    0xA0: 'gocbRef', 0xA1: 'timeAllowedtoLive', 0xA2: 'datSet',
    0xA3: 'goID', 0xA4: 't', 0x85: 'stNum', 0x86: 'sqNum',
    0x87: 'test', 0x88: 'confRev', 0x89: 'ndsCom',
    0x8A: 'numDatSetEntries', 0xAB: 'allData',
}


def parse_ber_length(data: bytes, pos: int) -> Tuple[int, int]:
    """解析 BER 长度"""
    if pos >= len(data):
        return 0, 0
    b = data[pos]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    if n == 0:
        return 0, 1
    if pos + 1 + n > len(data):
        return 0, 0
    length = 0
    for i in range(n):
        length = (length << 8) | data[pos + 1 + i]
    return length, 1 + n


def parse_ber_integer(data: bytes, pos: int, length: int) -> int:
    """解析 BER 整数"""
    val = 0
    for i in range(length):
        if pos + i < len(data):
            val = (val << 8) | data[pos + i]
    return val


def parse_ber_string(data: bytes, pos: int, length: int) -> str:
    """解析 BER VisibleString"""
    end = min(pos + length, len(data))
    return data[pos:end].decode('utf-8', errors='replace')


def parse_ber_timestamp(data: bytes, pos: int, length: int) -> str:
    """解析 BER Timestamp"""
    if length >= 8:
        sec = struct.unpack_from('!I', data, pos)[0]
        nsec = struct.unpack_from('!I', data, pos + 4)[0]
        return f'{sec}s+{nsec}ns'
    return f'<{length}B>'


def detect_goose_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """检测 GOOSE 以太网帧"""
    if len(data) < 18:
        return None

    try:
        dst_mac = data[0:6]
        src_mac = data[6:12]
        is_goose_mcast = dst_mac[:4] == GOOSE_MCAST_PREFIX

        # 解析 VLAN / EtherType
        offset = 12
        eth_type = struct.unpack_from('!H', data, offset)[0]
        if eth_type == ETHERTYPE_VLAN:
            offset += 4
            eth_type = struct.unpack_from('!H', data, offset)[0]
        offset += 2

        if eth_type != ETHERTYPE_GOOSE and not is_goose_mcast:
            return None

        # GOOSE 头
        appid = struct.unpack_from('!H', data, offset)[0]
        length = struct.unpack_from('!H', data, offset + 2)[0]
        resv = data[offset + 4:offset + 8]

        pdu_data = data[offset + 8:]

        # 解析 BER PDU
        pdu_fields = {}
        pos = 0
        while pos < len(pdu_data) - 1:
            tag = pdu_data[pos]
            pos += 1
            if pos >= len(pdu_data):
                break
            length, consumed = parse_ber_length(pdu_data, pos)
            pos += consumed
            if length == 0 or pos + length > len(pdu_data):
                break

            tag_name = TAG_NAMES.get(tag, f'0x{tag:02x}')

            if tag == TAG_GOCB_REF:
                pdu_fields['gocbRef'] = parse_ber_string(pdu_data, pos, length)
            elif tag == TAG_TIME_ALLOWED:
                pdu_fields['timeAllowedtoLive'] = parse_ber_integer(pdu_data, pos, length)
            elif tag == TAG_DAT_SET:
                pdu_fields['datSet'] = parse_ber_string(pdu_data, pos, length)
            elif tag == TAG_GO_ID:
                pdu_fields['goID'] = parse_ber_string(pdu_data, pos, length)
            elif tag == TAG_T:
                pdu_fields['t'] = parse_ber_timestamp(pdu_data, pos, length)
            elif tag in (TAG_ST_NUM, TAG_SQ_NUM, TAG_CONF_REV, TAG_NUM_DAT_SET_ENTRIES):
                pdu_fields[tag_name] = parse_ber_integer(pdu_data, pos, length)
            elif tag in (TAG_TEST, TAG_NDS_COM):
                pdu_fields[tag_name] = bool(parse_ber_integer(pdu_data, pos, length))
            elif tag == TAG_ALL_DATA:
                pdu_fields['allData'] = f'<{length}B BER data>'
            else:
                pdu_fields[f'0x{tag:02x}'] = pdu_data[pos:pos + length].hex()

            pos += length

        conf = 0.9 if is_goose_mcast else 0.7

        return {
            'protocol': 'GOOSE',
            'confidence': conf,
            'fields': {
                'dst_mac': ':'.join(f'{b:02x}' for b in dst_mac),
                'src_mac': ':'.join(f'{b:02x}' for b in src_mac),
                'appid': f'0x{appid:04x}',
                'length': length,
                'pdu_fields': pdu_fields,
            },
            'payload': pdu_data,
        }

    except (struct.error, IndexError, ValueError):
        return None


def detect_anomaly(frame_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """检测 GOOSE 异常"""
    anomalies = []
    fields = frame_info.get('fields', {})
    pdu = fields.get('pdu_fields', {})

    if pdu.get('stNum', 0) == 0:
        anomalies.append({
            'type': 'INVALID_STNUM',
            'severity': 'HIGH',
            'desc': 'GOOSE stNum=0，可能为伪造报文',
        })

    if pdu.get('test', False):
        anomalies.append({
            'type': 'TEST_FLAG',
            'severity': 'MEDIUM',
            'desc': 'GOOSE test=True (测试报文)',
        })

    ttl = pdu.get('timeAllowedtoLive', 0)
    if ttl == 0:
        anomalies.append({
            'type': 'TTL_ZERO',
            'severity': 'CRITICAL',
            'desc': 'timeAllowedtoLive=0, 报文将被丢弃',
        })
    elif ttl > 60000:
        anomalies.append({
            'type': 'ABNORMAL_TTL',
            'severity': 'HIGH',
            'desc': f'timeAllowedtoLive 异常: {ttl}ms',
        })

    dst = fields.get('dst_mac', '')
    if dst and not dst.startswith('01:0c:cd'):
        anomalies.append({
            'type': 'NON_STANDARD_MAC',
            'severity': 'MEDIUM',
            'desc': f'非标准 GOOSE 多播 MAC: {dst}',
        })

    return anomalies


def detect(data: bytes, src_port: int = 0, dst_port: int = 0) -> Dict[str, Any]:
    """GOOSE 检测主函数"""
    result = {
        'detected': False,
        'protocol': 'GOOSE',
        'confidence': 0.0,
        'info': {},
        'anomalies': [],
    }
    info = detect_goose_frame(data)
    if info:
        result['detected'] = True
        result['confidence'] = info['confidence']
        result['info'] = info
        result['anomalies'] = detect_anomaly(info)
    return result


if __name__ == '__main__':
    # 测试帧
    test = (
        b'\x01\x0c\xcd\x01\x00\x01'
        b'\x00\x50\xc2\x00\x00\x01'
        b'\x81\x00\x80\x00\x88\xb8'
        b'\x10\x00\x00\x4e\x00\x00\x00\x00'
        b'\x81\x46'  # GOOSE PDU tag + length
    )
    r = detect(test)
    print(f'检测: {r["detected"]}, 置信度: {r["confidence"]:.2f}')
    print(f'异常: {r["anomalies"]}')
