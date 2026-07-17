import socket
import struct

HOST = '127.0.0.1'
PORT = 20000

def build_static_response():
    """构造 DNP3 应用层响应帧（静态遥测数据）"""
    # 应用层数据 (功能码 0x81, IIN 0x0000, 对象组60变种1，标志0x06，数据两个字节)
    app_data = bytes([
        0x81, 0x00, 0x00,  # 功能码81(读响应) + IIN
        0x3C, 0x01, 0x06,  # 组60, 变种1, 标志0x06(在线)
        0x00, 0x00         # 数据: 两个字节(示例)
    ])
    length = len(app_data) + 5  # 控制1 + 目的2 + 源2
    control = 0xC4  # 非确认用户数据响应
    dst = 1
    src = 100
    start = b'\x05\x64'
    # 修正：<BBHH 对应 1B长度, 1B控制, 2B目的, 2B源
    link_frame = start + struct.pack('<BBHH', length, control, dst, src) + app_data
    return link_frame

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[DNP3 Simulator] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        print(f"[模拟器] 收到来自 {addr} 的数据: {data.hex()}")
        resp = build_static_response()
        conn.send(resp)
        print(f"[模拟器] 回复: {resp.hex()}")
        conn.close()

if __name__ == '__main__':
    main()