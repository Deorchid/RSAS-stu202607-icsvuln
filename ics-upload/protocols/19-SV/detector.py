"""
工控协议信息检测逻辑代码 - SV (Sampled Values, IEC 61850-9-2)
==========================================================
基于 BER 编码的 SV 协议检测。
"""

import struct
from typing import Optional, Dict, Any, List, Tuple

ETHERTYPE_SV = 0x88BA
SV_MCAST_PREFIX = bytes([0x01, 0x0c, 0xcd, 0x04])

TAG_SAV_PDU = 0x60
TAG_ASDU = 0x30
TAG_SV_ID = 0x80
TAG_SMP_CNT = 0x82
TAG_CONF_REV = 0x83
TAG_SMP_SYNCH = 0x85
TAG_SEQ_DATA = 0x87


def _bl(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data): return 0, 0
    b = data[pos]
    if b < 0x80: return b, 1
    n = b & 0x7F
    length = 0
    for i in range(n):
        if pos + 1 + i >= len(data): return 0, 0
        length = (length << 8) | data[pos + 1 + i]
    return length, 1 + n


def detect_sv_frame(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 18: return None
    try:
        dst_mac = data[0:6]
        src_mac = data[6:12]
        is_sv_mcast = dst_mac[:4] == SV_MCAST_PREFIX

        offset = 12
        etype = struct.unpack_from('!H', data, offset)[0]
        if etype == 0x8100:
            offset += 4
            etype = struct.unpack_from('!H', data, offset)[0]
        offset += 2

        if etype != ETHERTYPE_SV and not is_sv_mcast:
            return None

        appid = struct.unpack_from('!H', data, offset)[0]
        length = struct.unpack_from('!H', data, offset + 2)[0]

        pdu_data = data[offset + 8:]

        # 解析 ASDU
        asdu_info = {}
        pos = 0
        if pos < len(pdu_data) and pdu_data[pos] == TAG_SAV_PDU:
            pos += 1
            l, c = _bl(pdu_data, pos); pos += c
            # noASDU
            if pos < len(pdu_data) and pdu_data[pos] == 0x80:
                pos += 1
                l, c = _bl(pdu_data, pos); pos += c
                asdu_info['noASDU'] = pdu_data[pos] if l > 0 else 0
                pos += l

            # ASDU 序列
            while pos < len(pdu_data) and pdu_data[pos] == TAG_ASDU:
                pos += 1
                l, c = _bl(pdu_data, pos); pos += c
                end = pos + l
                while pos < end:
                    tag = pdu_data[pos]; pos += 1
                    vl, c = _bl(pdu_data, pos); pos += c
                    if tag == TAG_SV_ID:
                        asdu_info['svID'] = pdu_data[pos:pos+vl].decode('utf-8', errors='replace')
                    elif tag == TAG_SMP_CNT:
                        asdu_info['smpCnt'] = sum(pdu_data[pos+i] << (8*(vl-1-i)) for i in range(vl))
                    elif tag == TAG_CONF_REV:
                        asdu_info['confRev'] = sum(pdu_data[pos+i] << (8*(vl-1-i)) for i in range(vl))
                    elif tag == TAG_SMP_SYNCH:
                        synch_map = {0: 'unsync', 1: 'local', 2: 'global'}
                        synch = sum(pdu_data[pos+i] << (8*(vl-1-i)) for i in range(vl))
                        asdu_info['smpSynch'] = synch_map.get(synch, synch)
                    elif tag == TAG_SEQ_DATA and vl >= 32:
                        ch = ['Ua','Ub','Uc','Un','Ia','Ib','Ic','In']
                        vals = {}
                        for i in range(8):
                            off = pos + i*4
                            if off + 4 <= len(pdu_data):
                                vals[ch[i]] = round(struct.unpack_from('!f', pdu_data, off)[0], 2)
                        asdu_info['seqData'] = vals
                    pos += vl

        return {
            'protocol': 'SV',
            'confidence': 0.9 if is_sv_mcast else 0.7,
            'fields': {
                'dst_mac': ':'.join(f'{b:02x}' for b in dst_mac),
                'src_mac': ':'.join(f'{b:02x}' for b in src_mac),
                'appid': f'0x{appid:04x}',
                'length': length,
                'pdu_fields': asdu_info,
            },
            'payload': pdu_data,
        }
    except (struct.error, IndexError):
        return None


def detect_anomaly(info: Dict[str, Any]) -> List[Dict[str, Any]]:
    anomalies = []
    f = info.get('fields', {})
    pdu = f.get('pdu_fields', {})

    sc = pdu.get('smpCnt', 0)
    if sc > 5000:
        anomalies.append({'type': 'ABNORMAL_SMP_CNT', 'severity': 'HIGH',
                         'desc': f'smpCnt={sc} (期望 0-3999)'})
    if pdu.get('smpSynch') == 'unsync':
        anomalies.append({'type': 'UNSYNC', 'severity': 'MEDIUM',
                         'desc': '采样未同步 (smpSynch=0)'})
    seq = pdu.get('seqData', {})
    if isinstance(seq, dict):
        for k in ['Ia','Ib','Ic']:
            if abs(seq.get(k, 0)) > 50000:
                anomalies.append({'type': 'ABNORMAL_CURRENT', 'severity': 'CRITICAL',
                                 'desc': f'{k}={seq[k]}A 异常偏高'})
    return anomalies


def detect(data: bytes, src_port: int = 0, dst_port: int = 0) -> Dict[str, Any]:
    result = {'detected': False, 'protocol': 'SV', 'confidence': 0.0, 'info': {}, 'anomalies': []}
    info = detect_sv_frame(data)
    if info:
        result['detected'] = True
        result['confidence'] = info['confidence']
        result['info'] = info
        result['anomalies'] = detect_anomaly(info)
    return result


if __name__ == '__main__':
    # 构造完整 SV 帧测试
    def _build_test_sv():
        dst = b'\x01\x0c\xcd\x04\x00\x01'
        src = b'\x00\x50\xc2\x00\x00\x01'
        # ASDU: svID="MU01", smpCnt=100, confRev=1, smpSynch=2, seqData(8*float)
        asdu = b'\x80\x04MU01'           # svID
        asdu += b'\x82\x01\x64'          # smpCnt=100
        asdu += b'\x83\x01\x01'          # confRev=1
        asdu += b'\x85\x01\x02'          # smpSynch=2
        seq = struct.pack('!ffffffff', 110000.0, 110000.0, 110000.0, 0.0,
                          500.0, 500.0, 500.0, 0.0)
        asdu += b'\x87' + bytes([len(seq)]) + seq
        asdu_frame = b'\x30' + bytes([len(asdu)]) + asdu
        no_asdu = b'\x80\x01\x01'
        sav = b'\x60' + bytes([len(no_asdu) + len(asdu_frame)]) + no_asdu + asdu_frame
        length = 8 + len(sav)
        return dst + src + struct.pack('!HH', 0x8100, 0x8000) + struct.pack('!HHHHH', 0x88BA, 0x4000, length, 0, 0) + sav

    r = detect(_build_test_sv())
    print(f'SV 检测: {r["detected"]}, 置信度: {r["confidence"]:.2f}')
    if r['info']:
        pdu = r['info'].get('fields', {}).get('pdu_fields', {})
        print(f'  svID={pdu.get("svID")} smpCnt={pdu.get("smpCnt")}')
        print(f'  smpSynch={pdu.get("smpSynch")} seqData={pdu.get("seqData")}')
    print(f'异常: {r["anomalies"]}')
