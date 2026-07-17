import struct

def detect_fins(data):
    """解析 FINS 报文"""
    if len(data) < 8 or data[:4] != b'FINS':
        print("[检测] 非 FINS 报文")
        return

    fins_len = struct.unpack('<I', data[4:8])[0]
    fins_frame = data[8:8+fins_len]
    print(f"[检测] FINS 帧长度={fins_len}")

    if len(fins_frame) < 2:
        print("[检测] FINS 帧太短")
        return

    mrc = fins_frame[0]
    src = fins_frame[1]
    cmd_code = (mrc, src)

    cmd_names = {
        (0x01, 0x01): "内存读",
        (0x01, 0x02): "内存写",
        (0x23, 0x01): "强制位ON",
        (0x23, 0x02): "强制位OFF",
        (0x04, 0x01): "运行模式",
        (0x04, 0x02): "停止模式",
    }
    cmd_name = cmd_names.get(cmd_code, f"未知命令 (0x{mrc:02X}{src:02X})")
    print(f"[检测] FINS 命令码: {cmd_name}")

    # 警告
    if cmd_code in ((0x23, 0x01), (0x23, 0x02)):
        print("[检测] ⚠️ 警报：检测到未授权强制操作！")
    elif cmd_code in ((0x04, 0x01), (0x04, 0x02)):
        print("[检测] ⚠️ 警报：检测到PLC模式控制命令！")
    elif cmd_code == (0x01, 0x01):
        # 尝试读取内存区域 (帧头通常还有区域代码、地址等)
        if len(fins_frame) >= 6:
            area = fins_frame[2]
            addr = struct.unpack('>H', fins_frame[3:5])[0]  # 大端地址
            print(f"[检测] 内存读: 区域=0x{area:02X}, 地址=0x{addr:04X}")
            print("[检测] ⚠️ 提示：可能未授权读取内存")