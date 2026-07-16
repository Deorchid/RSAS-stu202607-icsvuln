"""
工控协议检测与分析系统 - 公共工具模块
提供十六进制转换、校验和计算、数据包构造等通用功能
"""

import struct
import hashlib
import socket
import random
from typing import Optional, Tuple, Dict, Any


def hex_dump(data: bytes, width: int = 16) -> str:
    """生成十六进制转储字符串，用于调试和日志"""
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        result.append(f'{i:04x}  {hex_part:<{width*3}}  {ascii_part}')
    return '\n'.join(result)


def crc16(data: bytes) -> int:
    """CRC-16/MODBUS 校验计算"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc


def crc32(data: bytes) -> int:
    """CRC32 校验计算"""
    return hashlib.crc32(data) & 0xFFFFFFFF


def ip_checksum(header: bytes) -> int:
    """IP首部校验和计算"""
    if len(header) % 2 != 0:
        header += b'\x00'
    s = 0
    for i in range(0, len(header), 2):
        w = (header[i] << 8) + header[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def build_ether_frame(dst_mac: bytes, src_mac: bytes, ether_type: int, payload: bytes) -> bytes:
    """构造以太网帧"""
    return dst_mac + src_mac + struct.pack('!H', ether_type) + payload


def parse_ether_frame(data: bytes) -> Optional[Dict[str, Any]]:
    """解析以太网帧"""
    if len(data) < 14:
        return None
    return {
        'dst_mac': data[0:6],
        'src_mac': data[6:12],
        'ether_type': struct.unpack('!H', data[12:14])[0],
        'payload': data[14:]
    }


def mac_to_bytes(mac_str: str) -> bytes:
    """将 MAC 地址字符串转换为字节"""
    mac_str = mac_str.replace('-', ':')
    parts = mac_str.split(':')
    return bytes(int(p, 16) for p in parts)


def mac_to_str(mac_bytes: bytes) -> str:
    """将 MAC 地址字节转换为字符串"""
    return ':'.join(f'{b:02x}' for b in mac_bytes)


def ip_to_bytes(ip_str: str) -> bytes:
    """将 IP 地址字符串转换为字节"""
    return socket.inet_aton(ip_str)


def bytes_to_ip(ip_bytes: bytes) -> str:
    """将 IP 地址字节转换为字符串"""
    return socket.inet_ntoa(ip_bytes)


def build_tcp_packet(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int,
                     seq: int, ack_seq: int, flags: int, payload: bytes) -> bytes:
    """构造 TCP 数据包（用于 raw socket）"""
    # TCP 首部固定部分 20 字节
    data_offset = 5  # 20 bytes / 4
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, ack_seq,
                             (data_offset << 4), flags, 65535, 0, 0)
    # 计算 TCP 校验和
    pseudo_header = struct.pack('!4s4sBBH',
                                src_ip, dst_ip, 0, 6, len(tcp_header) + len(payload))
    tcp_checksum_data = pseudo_header + tcp_header + payload
    if len(tcp_checksum_data) % 2 != 0:
        tcp_checksum_data += b'\x00'
    s = 0
    for i in range(0, len(tcp_checksum_data), 2):
        w = (tcp_checksum_data[i] << 8) + tcp_checksum_data[i + 1]
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s = (~s) & 0xFFFF
    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, ack_seq,
                             (data_offset << 4), flags, 65535, s, 0)
    return tcp_header + payload


def find_protocol_by_port(port: int) -> Optional[str]:
    """根据端口号识别可能的工控协议"""
    port_map = {
        502: 'Modbus/TCP',
        4840: 'OPC UA',
        102: 'S7COMM',
        44818: 'EtherNet/IP',
        2222: 'EtherNet/IP',
        34962: 'PROFINET_IO',
        34963: 'PROFINET_IO',
        34964: 'PROFINET_IO',
        1883: 'MQTT',
        8883: 'MQTT/TLS',
        2404: 'IEC104',
        20000: 'DNP3',
        19999: 'DNP3',
        47808: 'BACnet/IP',
        47809: 'BACnet/IP',
        8193: 'FOCAS',
        48898: 'ADS',
        48899: 'ADS',
    }
    return port_map.get(port)


def apply_modbus_mask(data: int, mask: int, operation: int) -> int:
    """
    Modbus 位掩码操作
    operation: 1=AND, 2=OR, 3=XOR
    """
    if operation == 1:  # AND
        return data & mask
    elif operation == 2:  # OR
        return data | mask
    elif operation == 3:  # XOR
        return data ^ mask
    return data


class ProtocolFrame:
    """协议帧基类，提供序列化和反序列化接口"""

    def __init__(self):
        self.fields: Dict[str, Any] = {}

    def serialize(self) -> bytes:
        """序列化为字节流"""
        raise NotImplementedError

    def deserialize(self, data: bytes) -> bool:
        """从字节流解析"""
        raise NotImplementedError

    def __str__(self) -> str:
        return f'{self.__class__.__name__}({self.fields})'

    def __repr__(self) -> str:
        return self.__str__()
