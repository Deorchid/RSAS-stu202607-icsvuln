import socket
import struct

HOST = '127.0.0.1'
PORT = 5000

def build_read_response():
    """构造一个读元件响应的二进制帧（读取 D0 返回 0x1234）"""
    # 3E 二进制帧头：0xD000，网络号0，PC号0xFF，目标模块0x03FF，数据长度
    # 响应数据：D0 的值 0x1234
    response = bytes.fromhex('D00000FF03FF030000003412')
    return response

def build_stop_response():
    """构造远程 STOP 命令的确认响应（简单返回一个通用确认）"""
    # 正常情况 PLC 会回复类似 D000 00 FF 03FF 0000（结束码0000）
    response = bytes.fromhex('D00000FF03FF00000000')
    return response

def handle_request(data):
    """简单解析请求并决定回复什么"""
    if len(data) < 8:
        return None
    # 判断是命令帧（0x5000）还是其他
    if data[0:2] == b'\x50\x00':
        # 提取命令码（一般在偏移10-11）
        if len(data) >= 12:
            cmd = struct.unpack('>H', data[10:12])[0]
            print(f"[模拟器] 收到命令码: 0x{cmd:04X}")
            if cmd == 0x0401:  # 读元件
                return build_read_response()
            elif cmd == 0x1401:  # 写元件（这里简单返回确认）
                # 返回一个写确认，结束码0
                return bytes.fromhex('D00000FF03FF00000000')
            elif cmd in (0x1001, 0x1002):  # 远程操作（PAUSE/STOP）
                print("[模拟器] ⚠️ 收到远程控制命令！")
                return build_stop_response()
    # 未知请求，返回一个基本确认
    return bytes.fromhex('D00000FF03FF00000000')

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[MELSEC Simulator] Listening on {HOST}:{PORT}")
    while True:
        conn, addr = s.accept()
        data = conn.recv(1024)
        print(f"[模拟器] 收到来自 {addr} 的数据: {data.hex()}")
        resp = handle_request(data)
        if resp:
            conn.send(resp)
            print(f"[模拟器] 回复: {resp.hex()}")
        else:
            print("[模拟器] 无响应发送")
        conn.close()

if __name__ == '__main__':
    main()