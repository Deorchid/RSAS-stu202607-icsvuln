import socket
import struct

FINS_PORT = 9600

def build_mem_read_response(data=0x1234):
    """构造内存读响应 (0101)"""
    # FINS/UDP 头部: 'FINS' + 4字节长度（含FINS帧长度）
    # FINS 帧: MRC=01,SRC=01,结束代码=0000,数据
    fins_frame = struct.pack('<BBHH', 0x01, 0x01, 0x0000, data)  # 结束码0，数据2字节
    header = b'FINS' + struct.pack('<I', len(fins_frame))
    return header + fins_frame

def build_force_response():
    """构造强制位响应 (2301)"""
    # FINS 帧: MRC=23,SRC=01,结束代码=0000
    fins_frame = struct.pack('<BBH', 0x23, 0x01, 0x0000)
    header = b'FINS' + struct.pack('<I', len(fins_frame))
    return header + fins_frame

def handle_packet(data, addr, sock):
    if len(data) < 8 or data[:4] != b'FINS':
        return
    fins_len = struct.unpack('<I', data[4:8])[0]
    fins_frame = data[8:8+fins_len]
    if len(fins_frame) < 2:
        return

    mrc = fins_frame[0]
    src = fins_frame[1]
    cmd = (mrc, src)
    print(f"[模拟器] 收到命令码: {mrc:02X}{src:02X}")

    if cmd == (0x01, 0x01):  # 内存读
        print("[模拟器] 响应内存读 (返回 0x1234)")
        resp = build_mem_read_response()
        sock.sendto(resp, addr)
    elif cmd == (0x01, 0x02):  # 内存写
        print("[模拟器] 响应内存写")
        # 简单回复成功
        fins_frame = struct.pack('<BBH', 0x01, 0x02, 0x0000)
        header = b'FINS' + struct.pack('<I', len(fins_frame))
        sock.sendto(header + fins_frame, addr)
    elif cmd == (0x23, 0x01):  # 强制位ON
        print("[模拟器] ⚠️ 收到强制位ON命令！")
        resp = build_force_response()
        sock.sendto(resp, addr)
    elif cmd == (0x23, 0x02):  # 强制位OFF
        print("[模拟器] ⚠️ 收到强制位OFF命令！")
        fins_frame = struct.pack('<BBH', 0x23, 0x02, 0x0000)
        header = b'FINS' + struct.pack('<I', len(fins_frame))
        sock.sendto(header + fins_frame, addr)
    else:
        print(f"[模拟器] 未处理的命令: {mrc:02X}{src:02X}")

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', FINS_PORT))
    print(f"[FINS Simulator] 监听 UDP {FINS_PORT}")
    while True:
        data, addr = sock.recvfrom(1024)
        handle_packet(data, addr, sock)

if __name__ == '__main__':
    main()