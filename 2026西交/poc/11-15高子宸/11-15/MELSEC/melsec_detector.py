import struct

def detect_melsec(data):
    """解析三菱 MELSEC 3E 二进制帧"""
    if len(data) < 8:
        print("[检测] 数据太短，不是 MELSEC 帧")
        return

    # 判断帧类型
    if data[0:2] == b'\x50\x00':  # 请求帧（命令）
        direction = "请求"
    elif data[0:2] == b'\xD0\x00': # 响应帧
        direction = "响应"
    else:
        print("[检测] 非 MELSEC 3E 帧")
        return

    # 网络号（偏移2），PC号（偏移3），目标模块IO（偏移4-5），数据长度（偏移6-7）
    net = data[2]
    pc = data[3]
    dest = struct.unpack('>H', data[4:6])[0]
    data_len = struct.unpack('>H', data[6:8])[0]
    print(f"[检测] MELSEC 3E {direction}: 网络={net}, PC={pc}, 目标模块=0x{dest:04X}, 数据长度={data_len}")

    if direction == "请求" and len(data) >= 12:
        cmd = struct.unpack('>H', data[10:12])[0]
        cmd_names = {
            0x0401: "读元件",
            0x1401: "写元件",
            0x1001: "远程PAUSE",
            0x1002: "远程STOP",
            0x1003: "远程RUN",
        }
        cmd_name = cmd_names.get(cmd, f"未知命令 (0x{cmd:04X})")
        print(f"[检测] 命令码: {cmd_name}")
        # 告警远程控制命令
        if cmd in (0x1001, 0x1002, 0x1003):
            print("[检测] ⚠️ 警报：检测到远程运行控制命令！")