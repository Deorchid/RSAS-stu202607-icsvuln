"""
工控协议模拟器 - GOOSE (Generic Object Oriented Substation Events)
==============================================================
基于 scapy + 真实 ASN.1/BER 编码的 GOOSE 协议模拟
EtherType: 0x88B8

参考: GooseStalker (cutaway-security/goosestalker)
      IEC 61850-8-1 标准
"""

import struct
import time
import random
import threading
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ---- GOOSE 常量 ----
ETHERTYPE_GOOSE = 0x88B8
GOOSE_MULTICAST_MAC = '01:0c:cd:01:00:01'

# ---- BER 编码标签 ----
BER_CLASS_CONTEXT = 0x80
BER_CLASS_APPLICATION = 0x40
BER_CLASS_UNIVERSAL = 0x00
BER_PC_CONSTRUCTED = 0x20
BER_PC_PRIMITIVE = 0x00

# GOOSE PDU 字段标签 (context-specific)
TAG_GOCB_REF = 0xA0        # [0] IMPLICIT VisibleString
TAG_TIME_ALLOWED = 0xA1     # [1] IMPLICIT INTEGER
TAG_DAT_SET = 0xA2         # [2] IMPLICIT VisibleString
TAG_GO_ID = 0xA3            # [3] IMPLICIT VisibleString
TAG_T = 0xA4                # [4] IMPLICIT Timestamp (UtcTime)
TAG_ST_NUM = 0x85           # [5] IMPLICIT INTEGER (primitive)
TAG_SQ_NUM = 0x86           # [6] IMPLICIT INTEGER
TAG_TEST = 0x87             # [7] IMPLICIT BOOLEAN
TAG_CONF_REV = 0x88         # [8] IMPLICIT INTEGER
TAG_NDS_COM = 0x89          # [9] IMPLICIT BOOLEAN
TAG_NUM_DAT_SET_ENTRIES = 0x8A  # [10] IMPLICIT INTEGER
TAG_ALL_DATA = 0xAB         # [11] IMPLICIT Sequence (constructed)

# VLAN 优先级
VLAN_PRIORITY_GOOSE = 4  # GOOSE 推荐 VLAN 优先级


def ber_encode_length(length: int) -> bytes:
    """BER 编码长度"""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return struct.pack('!BH', 0x82, length)
    else:
        return struct.pack('!BI', 0x84, length)


def ber_encode_integer(value: int, tag: int = None) -> bytes:
    """BER 编码整数"""
    if value == 0:
        data = b'\x00'
    elif value < 0x80:
        data = bytes([value])
    elif value < 0x100:
        data = bytes([value])
    elif value < 0x10000:
        data = struct.pack('!H', value)
    elif value < 0x100000000:
        data = struct.pack('!I', value)
    else:
        data = struct.pack('!Q', value)

    if tag is not None:
        return bytes([tag]) + ber_encode_length(len(data)) + data
    return data


def ber_encode_visible_string(value: str, tag: int = None) -> bytes:
    """BER 编码 VisibleString"""
    data = value.encode('utf-8')
    if tag is not None:
        return bytes([tag]) + ber_encode_length(len(data)) + data
    return data


def ber_encode_boolean(value: bool, tag: int = None) -> bytes:
    """BER 编码 BOOLEAN"""
    data = b'\x01' if value else b'\x00'
    if tag is not None:
        return bytes([tag]) + ber_encode_length(1) + data
    return data


def ber_encode_timestamp(tag: int = None) -> bytes:
    """BER 编码 UtcTime (4字节秒 + 4字节纳秒)"""
    now = time.time()
    sec = int(now)
    nsec = int((now - sec) * 1e9)
    data = struct.pack('!II', sec, nsec)
    if tag is not None:
        return bytes([tag]) + ber_encode_length(len(data)) + data
    return data


def ber_encode_dataset(values: List[Any]) -> bytes:
    """BER 编码数据集 (Sequence of Data)"""
    data = b''
    for val in values:
        if isinstance(val, bool):
            data += ber_encode_boolean(val, 0x83)  # BOOLEAN tag
        elif isinstance(val, int):
            data += ber_encode_integer(val, 0x85)  # INTEGER tag
        elif isinstance(val, float):
            data += ber_encode_integer(struct.pack('!f', val), 0x85)
        elif isinstance(val, str):
            data += ber_encode_visible_string(val, 0xA0)
        else:
            data += ber_encode_integer(0, 0x85)
    return data


class GOOSEPacket:
    """GOOSE 报文构造器"""

    def __init__(self):
        self.dst_mac = GOOSE_MULTICAST_MAC
        self.src_mac = '00:50:c2:00:00:01'
        self.vlan_id = 0
        self.vlan_priority = VLAN_PRIORITY_GOOSE
        self.appid = 0x1000

        # PDU 字段
        self.gocb_ref = 'CB1/LLN0$GO$gcb1'
        self.time_allowed_to_live = 4000
        self.dat_set = 'CB1/LLN0$DataSet$ds1'
        self.go_id = 'GOOSE_CB1'
        self.st_num = 1
        self.sq_num = 1
        self.test = False
        self.conf_rev = 1
        self.nds_com = False
        self.num_dat_set_entries = 0
        self.dataset_values: List[Any] = []

    def build(self) -> bytes:
        """构造完整的 GOOSE 以太网帧"""
        # 1. 构建 PDU
        pdu = b''
        pdu += ber_encode_visible_string(self.gocb_ref, TAG_GOCB_REF)
        pdu += ber_encode_integer(self.time_allowed_to_live, TAG_TIME_ALLOWED)
        pdu += ber_encode_visible_string(self.dat_set, TAG_DAT_SET)
        pdu += ber_encode_visible_string(self.go_id, TAG_GO_ID)
        pdu += ber_encode_timestamp(TAG_T)
        pdu += ber_encode_integer(self.st_num, TAG_ST_NUM)
        pdu += ber_encode_integer(self.sq_num, TAG_SQ_NUM)
        pdu += ber_encode_boolean(self.test, TAG_TEST)
        pdu += ber_encode_integer(self.conf_rev, TAG_CONF_REV)
        pdu += ber_encode_boolean(self.nds_com, TAG_NDS_COM)
        pdu += ber_encode_integer(self.num_dat_set_entries, TAG_NUM_DAT_SET_ENTRIES)

        # 数据集
        ds_data = ber_encode_dataset(self.dataset_values)
        pdu += bytes([TAG_ALL_DATA]) + ber_encode_length(len(ds_data)) + ds_data

        # GOOSE PDU 封装 (tag 0x81 = context + constructed + 1)
        goose_pdu = bytes([0x81]) + ber_encode_length(len(pdu)) + pdu

        # 2. 构建以太网帧
        dst = bytes(int(x, 16) for x in self.dst_mac.split(':'))
        src = bytes(int(x, 16) for x in self.src_mac.split(':'))

        # VLAN 标签
        tci = (self.vlan_priority << 13) | (self.vlan_id & 0x0FFF)
        vlan_tag = struct.pack('!HH', 0x8100, tci)

        # GOOSE 头
        length = 8 + len(goose_pdu)
        goose_header = struct.pack('!HHHH', ETHERTYPE_GOOSE, self.appid, length, 0x0000)

        frame = dst + src + vlan_tag + goose_header + goose_pdu

        # 最小 64 字节
        if len(frame) < 64:
            frame += b'\x00' * (64 - len(frame))

        return frame


class IEDSimulator:
    """IED (智能电子设备) GOOSE 模拟器"""

    def __init__(self, name: str = 'PROT_1', mac: str = '00:50:c2:00:00:01'):
        self.name = name
        self.mac = mac
        self.state = 'CLOSED'  # 断路器状态
        self.voltage = 110.0    # kV
        self.current = 500.0    # A
        self.trip_signal = False
        self.st_num = 1
        self.sq_num = 0
        self._running = False

    def get_dataset(self) -> List[Any]:
        """构造数据集值"""
        return [
            self.state == 'CLOSED',      # 断路器位置
            int(self.voltage),            # 电压
            int(self.current),            # 电流
            self.trip_signal,             # 跳闸信号
            0,                             # 保留
        ]

    def trigger_trip(self):
        """触发跳闸事件 (stNum 递增)"""
        self.trip_signal = True
        self.state = 'OPEN'
        self.st_num += 1
        self.sq_num = 0
        print(f'[GOOSE] 跳闸事件! stNum={self.st_num}')

    def clear_trip(self):
        """清除跳闸"""
        self.trip_signal = False
        self.state = 'CLOSED'
        self.st_num += 1
        self.sq_num = 0
        print(f'[GOOSE] 合闸事件 stNum={self.st_num}')


def run_simulator():
    """启动 GOOSE 模拟器（控制台交互版）"""
    ied = IEDSimulator('PROT_1')
    print(f'[GOOSE] IED {ied.name} 模拟器启动')
    print(f'[GOOSE] 初始: stNum={ied.st_num} sqNum={ied.sq_num}')
    print(f'[GOOSE] 命令: trip, close, status, packet, quit')

    pkt_count = 0
    while True:
        try:
            cmd = input('> ').strip().lower()
            if cmd in ('quit', 'q'):
                break
            elif cmd == 'trip':
                ied.trigger_trip()
            elif cmd == 'close':
                ied.clear_trip()
            elif cmd == 'status':
                print(f'  IED={ied.name} state={ied.state}')
                print(f'  stNum={ied.st_num} sqNum={ied.sq_num}')
                print(f'  V={ied.voltage:.0f}kV I={ied.current:.0f}A trip={ied.trip_signal}')
            elif cmd == 'packet':
                goose = GOOSEPacket()
                goose.st_num = ied.st_num
                goose.sq_num = ied.sq_num
                goose.dataset_values = ied.get_dataset()
                pkt = goose.build()
                pkt_count += 1
                print(f'  Packet #{pkt_count}: {len(pkt)} bytes')
                print(f'  dst={goose.dst_mac} src={goose.src_mac}')
                print(f'  APPID=0x{goose.appid:04x} VLAN=0x{goose.vlan_priority:x}')
                print(f'  gocbRef={goose.gocb_ref}')
                print(f'  stNum={goose.st_num} sqNum={goose.sq_num}')
                print(f'  dataset={goose.dataset_values}')
                if ied.sq_num % 5 == 0:
                    ied.sq_num += 1
            elif cmd == '':
                # 自动发送
                goose = GOOSEPacket()
                goose.st_num = ied.st_num
                goose.sq_num = ied.sq_num
                goose.dataset_values = ied.get_dataset()
                pkt = goose.build()
                pkt_count += 1
                ied.sq_num += 1
                if pkt_count % 10 == 0:
                    print(f'  [GOOSE] #{pkt_count} st{goose.st_num} sq{goose.sq_num}')
            else:
                print(f'  未知命令: {cmd}')
        except KeyboardInterrupt:
            break

    print('[GOOSE] 退出')


if __name__ == '__main__':
    run_simulator()
