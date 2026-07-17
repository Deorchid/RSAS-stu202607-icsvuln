import struct

def detect_bacnet(data):
    """解析 BACnet/IP 报文，打印关键字段"""
    if len(data) < 4:
        print("[检测] 数据太短，不是 BACnet")
        return
    bvlc_type = data[0]
    if bvlc_type != 0x81:
        print("[检测] 非 BACnet/IP (BVLC类型错误)")
        return

    bvlc_func = data[1]
    bvlc_len = struct.unpack('>H', data[2:4])[0]
    func_names = {
        0x00: "Who-Is-Router-To-Network",
        0x01: "I-Am-Router-To-Network",
        0x02: "Who-Is",
        0x03: "I-Am",
        0x04: "Who-Has",
        0x05: "I-Have",
        0x06: "Unicast-NPDU",
        0x07: "Broadcast-NPDU",
        0x0A: "Original-Unicast-NPDU",
        0x0B: "Original-Broadcast-NPDU",
    }
    func_name = func_names.get(bvlc_func, f"未知 (0x{bvlc_func:02X})")
    print(f"[检测] BVLC 功能: {func_name}, 长度={bvlc_len}")

    if len(data) < bvlc_len:
        print("[检测] 声明长度超过实际数据，可能被截断")
        return

    npdu = data[4:bvlc_len]
    if len(npdu) < 2:
        print("[检测] NPDU 太短")
        return
    version = npdu[0]
    control = npdu[1]
    print(f"[检测] NPDU 版本={version}, 控制=0x{control:02X}")

    apdu = npdu[2:]
    if len(apdu) < 2:
        print("[检测] APDU 缺失")
        return

    pdu_type = apdu[0] >> 4
    pdu_names = {
        0x0: "Confirmed-Request",
        0x1: "Unconfirmed-Request",
        0x2: "Simple-ACK",
        0x3: "Complex-ACK",
        0x4: "Segment-ACK",
        0x5: "Error",
        0x6: "Reject",
        0x7: "Abort",
    }
    pdu_name = pdu_names.get(pdu_type, f"未知PDU类型(0x{pdu_type:X})")
    print(f"[检测] APDU 类型: {pdu_name}")

    if pdu_type == 0x0:  # Confirmed-Request
        if len(apdu) < 3:
            return
        invoke_id = apdu[1]
        service = apdu[2]
        service_names = {
            0x0C: "Read-Property",
            0x0F: "Write-Property",
            0x10: "Write-Property-Multiple",
            0x08: "Who-Is",
            0x09: "I-Am",
        }
        service_name = service_names.get(service, f"未知(0x{service:02X})")
        print(f"[检测] 服务: {service_name}")
        if service == 0x0F:  # Write-Property
            print("[检测] ⚠️ 警报：检测到未授权写属性操作！")
    elif pdu_type == 0x1:  # Unconfirmed-Request
        if len(apdu) >= 3:
            service = apdu[1]
            if service == 0x08:  # Who-Is
                print("[检测] 服务: Who-Is (设备枚举)")
                print("[检测] ⚠️ 提示：Who-Is 可能用于网络侦察")
    elif pdu_type == 0x3:  # Complex-ACK
        print("[检测] 服务: 复杂确认响应")

if __name__ == '__main__':
    # 测试一个 I-Am 包
    test = bytes.fromhex('810B0018012400000800D201E00000')
    detect_bacnet(test)