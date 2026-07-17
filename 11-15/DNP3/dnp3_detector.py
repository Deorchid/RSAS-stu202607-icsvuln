import struct

def detect_dnp3(data):
    """解析 DNP3 链路帧，打印关键字段"""
    if len(data) < 10:
        print("[检测] 数据太短，不是 DNP3")
        return
    if data[0:2] != b'\x05\x64':
        print("[检测] 起始字节错误，非 DNP3")
        return

    length = data[2]
    control = data[3]
    dst = struct.unpack('<H', data[4:6])[0]
    src = struct.unpack('<H', data[6:8])[0]

    print(f"[检测] DNP3 链路帧: 长度={length}, 控制=0x{control:02X}, 目的={dst}, 源={src}")

    # 控制字解释
    ctrl_names = {
        0x44: "非确认用户数据请求",
        0xC4: "非确认用户数据响应",
        0x40: "确认请求",
        0xC0: "确认响应",
        0x10: "链路状态请求",
        0x00: "NOP",
    }
    func = ctrl_names.get(control & 0xFC, "未知")  # 简单屏蔽方向位
    print(f"[检测]   功能: {func}")

    # 如果有应用层数据 (长度 > 5，即控制+地址 5 字节)
    if length > 5:
        app_data = data[8:8 + length - 5]  # 链路头8字节，后面是应用层
        print(f"[检测]   应用层数据({len(app_data)}字节): {app_data.hex()}")
        if len(app_data) >= 2:
            app_func = app_data[0]
            app_func_names = {
                0x01: "Read",
                0x02: "Write",
                0x05: "Direct Operate",
                0x81: "Read Response",
                0x82: "Write Response",
                0x85: "Direct Operate Response",
            }
            func_name = app_func_names.get(app_func, f"未知(0x{app_func:02X})")
            print(f"[检测]   应用功能码: {func_name}")

            # 如果是 Direct Operate (0x05) 则标记为可疑操作
            if app_func == 0x05:
                print("[检测] ⚠️ 警报：检测到未授权直接操作指令！")
    else:
        print("[检测]   无应用层数据 (纯链路帧)")

if __name__ == '__main__':
    # 独立测试：接收十六进制字符串
    import sys
    if len(sys.argv) > 1:
        hex_data = sys.argv[1]
        data = bytes.fromhex(hex_data)
        detect_dnp3(data)
    else:
        print("Usage: python dnp3_detector.py <hex_packet>")
        # 提供一个示例
        test_data = bytes.fromhex('05640544C401006400')  # 一个读请求帧
        detect_dnp3(test_data)