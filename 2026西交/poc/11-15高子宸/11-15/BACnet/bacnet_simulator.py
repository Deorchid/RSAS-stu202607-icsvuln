import socket
import struct

BACNET_PORT = 0xBAC0  # 47808

def build_i_am(device_id=1234):
    """响应 Who-Is 的 I-Am 报文"""
    apdu = bytes([
        0x00, 0x00,                # PDU type, Reserved
        0x08,                       # Device Object type (8)
        (device_id >> 8) & 0xFF,    # instance high byte
        device_id & 0xFF,           # instance low byte
        0x01, 0xE0,                 # Max APDU (480)
        0x00,                       # Segmentation
        0x00, 0x00                  # Vendor ID
    ])
    npdu = bytes([0x01, 0x20])     # version=1, control=no reply, broadcast
    bvlc = struct.pack('>BBH', 0x81, 0x0B, 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu

def build_complex_ack(invoke_id, service, data_part):
    """构造 Complex-ACK 响应"""
    apdu = bytes([0x30, invoke_id, service]) + data_part
    npdu = bytes([0x01, 0x20])     # no reply
    bvlc = struct.pack('>BBH', 0x81, 0x0A, 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu

def build_simple_ack(invoke_id, service):
    """构造 Simple-ACK 响应"""
    apdu = bytes([0x20, invoke_id, service])
    npdu = bytes([0x01, 0x20])
    bvlc = struct.pack('>BBH', 0x81, 0x0A, 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu

def handle_packet(data, addr, sock):
    if len(data) < 4:
        return
    bvlc_type = data[0]
    if bvlc_type != 0x81:
        return
    bvlc_func = data[1]
    bvlc_len = struct.unpack('>H', data[2:4])[0]
    print(f"[模拟器] 收到 BVLC func=0x{bvlc_func:02X}, len={bvlc_len}")

    if bvlc_func == 0x0B:                     # Original-Broadcast-NPDU
        npdu = data[4:]
        if len(npdu) >= 2 and npdu[0] == 0x01 and npdu[1] & 0xF0 == 0x20:
            apdu = npdu[2:]
            if len(apdu) >= 2 and apdu[0] == 0x10 and apdu[1] == 0x08:  # Who-Is
                print("[模拟器] 收到 Who-Is，回复 I-Am")
                resp = build_i_am()
                sock.sendto(resp, addr)
                return
            else:
                print("[模拟器] 未处理的广播")
        else:
            print("[模拟器] 广播包解析异常")

    elif bvlc_func == 0x0A:                   # Original-Unicast-NPDU
        npdu = data[4:]
        if len(npdu) < 2:
            return
        apdu = npdu[2:]
        if len(apdu) >= 3:
            pdu_type = apdu[0] >> 4
            if pdu_type == 0x0:               # Confirmed-Request
                invoke_id = apdu[1]
                service = apdu[2]
                if service == 0x0C:           # Read-Property
                    print("[模拟器] 收到 Read-Property，回复模拟值 (1.0)")
                    # 返回 REAL 1.0，对象类型8，实例1234，属性85
                    data_part = bytes([0x08, 0x00, 0x00, 85, 0x44]) + struct.pack('>f', 1.0)
                    resp = build_complex_ack(invoke_id, 0x0C, data_part)
                    sock.sendto(resp, addr)
                elif service == 0x0F:         # Write-Property
                    print("[模拟器] 收到 Write-Property，回复 Simple-ACK")
                    resp = build_simple_ack(invoke_id, 0x0F)
                    sock.sendto(resp, addr)
                else:
                    print(f"[模拟器] 未处理的服务: 0x{service:02X}")
            else:
                print(f"[模拟器] PDU 类型 0x{pdu_type:X} 忽略")
        else:
            print("[模拟器] 非 Confirmed-Request 忽略")
    else:
        print(f"[模拟器] 未处理的 BVLC 功能: 0x{bvlc_func:02X}")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', BACNET_PORT))
    print(f"[BACnet Simulator] 监听 UDP {BACNET_PORT} (0x{BACNET_PORT:04X})")
    while True:
        data, addr = sock.recvfrom(1024)
        handle_packet(data, addr, sock)

if __name__ == '__main__':
    main()