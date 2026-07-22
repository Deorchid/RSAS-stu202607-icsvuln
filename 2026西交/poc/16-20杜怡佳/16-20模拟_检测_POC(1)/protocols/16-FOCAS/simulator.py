"""
工控协议模拟器 - FOCAS (FANUC Open CNC API System)
==================================================
基于 FOCAS1 以太网协议实现 (端口 TCP 8193)
模拟 FANUC CNC 控制器 FOCAS 服务

参考: FANUC FOCAS1/FOCAS2 规范
      pyfanuc (github.com/diohpix/pyfanuc) — 逆向工程实现
      fwlib — FANUC 官方 FOCAS 库
"""

import socket
import struct
import threading
import time
import random
import logging
from typing import Optional

logger = logging.getLogger(__name__)

FOCAS_PORT = 8193

# ---- FOCAS 函数码 ----
# (基于 fwlib 文档和 pyfanuc 逆向)
FUNC_HANDLE = 0x0000       # 分配句柄
FUNC_CONNECT = 0x0010      # 建立连接
FUNC_DISCONNECT = 0x0011   # 断开连接
FUNC_READ_SYSINFO = 0x0100 # 读取系统信息
FUNC_READ_AXIS = 0x0200    # 读取轴坐标 (cnc_rdaxis2)
FUNC_READ_DYNAMIC = 0x0201 # 读取动态数据 (cnc_rddynamic2)
FUNC_READ_ALARM = 0x0300   # 读取报警
FUNC_READ_PARAM = 0x0400   # 读取参数
FUNC_WRITE_PARAM = 0x0401  # 写入参数
FUNC_READ_PROGRAM = 0x0500 # 读取程序
FUNC_WRITE_PROGRAM = 0x0501 # 写入程序
FUNC_READ_STATUS = 0x0600  # 读取状态
FUNC_READ_SPEED = 0x0700   # 读取主轴速度
FUNC_READ_LOAD = 0x0701    # 读取负载

# ---- FOCAS 协议帧结构 ----
# 帧头 (16 字节):
#   [0-1]  长度 (2B)
#   [2-3]  函数码 (2B)
#   [4-5]  错误码 (2B)
#   [6-9]  序列号 (4B)
#   [10-15] 保留 (6B)
#   [16+]  数据

FOCAS_HEADER_LEN = 16


class FOCASFrame:
    """FOCAS 协议帧"""

    def __init__(self):
        self.length = 0
        self.func = 0
        self.error = 0
        self.seq = 0
        self.data = b''

    def pack(self) -> bytes:
        self.length = FOCAS_HEADER_LEN + len(self.data)
        hdr = struct.pack('!HHHI', self.length, self.func, self.error, self.seq)
        hdr += b'\x00' * 6  # 保留
        return hdr + self.data

    def unpack(self, data: bytes) -> bool:
        if len(data) < FOCAS_HEADER_LEN:
            return False
        try:
            self.length = struct.unpack_from('!H', data, 0)[0]
            self.func = struct.unpack_from('!H', data, 2)[0]
            self.error = struct.unpack_from('!H', data, 4)[0]
            self.seq = struct.unpack_from('!I', data, 6)[0]
            data_len = self.length - FOCAS_HEADER_LEN
            if data_len > 0:
                self.data = data[FOCAS_HEADER_LEN:FOCAS_HEADER_LEN + data_len]
            else:
                self.data = b''
            return True
        except struct.error:
            return False

    def reply(self, data: bytes = b'', error: int = 0) -> 'FOCASFrame':
        r = FOCASFrame()
        r.func = self.func
        r.seq = self.seq
        r.data = data
        r.error = error
        return r

    def __str__(self):
        return f'FOCAS(len={self.length} func=0x{self.func:04x} err=0x{self.error:04x} seq={self.seq})'


class CNCSimulator:
    """CNC 控制器模拟"""

    def __init__(self):
        self.model = 'FANUC Series 0i-MODEL F'
        self.series = '0i-F'
        self.version = '04.10'
        self.max_axis = 5
        self.axes = {i: {'pos': 0.0, 'load': 0.0} for i in range(1, 6)}
        self.spindle_speed = 0
        self.alarm = False
        self.alarm_code = 0
        self.operating = True
        self._seq = 0

    def update(self):
        """模拟 CNC 状态变化"""
        for ax in self.axes.values():
            ax['pos'] += random.uniform(-0.5, 0.5)
            ax['load'] = random.uniform(10, 80)
        self.spindle_speed = random.randint(0, 8000)

    def _pack_axis_data(self) -> bytes:
        """打包轴数据 (用于 cnc_rdaxis2 响应)"""
        data = b''
        for i in range(1, self.max_axis + 1):
            # 轴位置以最小输入增量单位 (0.001mm) 返回
            pos_encoded = int(self.axes[i]['pos'] * 1000)
            data += struct.pack('!h', i)  # 轴号
            data += struct.pack('!i', pos_encoded)  # 位置
        return data

    def handle_request(self, frame: FOCASFrame) -> FOCASFrame:
        """处理 FOCAS 请求"""
        self.update()

        if frame.func == FUNC_CONNECT:
            return frame.reply(b'\x00\x01')  # 连接成功

        elif frame.func == FUNC_READ_SYSINFO:
            info = self.model.encode('ascii').ljust(32, b'\x00')
            info += self.version.encode('ascii').ljust(8, b'\x00')
            info += struct.pack('!H', self.max_axis)
            info += bytes([random.randint(0, 99) for _ in range(4)])  # 序列号
            return frame.reply(info)

        elif frame.func == FUNC_READ_AXIS:
            return frame.reply(self._pack_axis_data())

        elif frame.func == FUNC_READ_DYNAMIC:
            data = struct.pack('!H', self.max_axis)  # 轴数
            for i in range(1, self.max_axis + 1):
                pos = int(self.axes[i]['pos'] * 1000)
                load = int(self.axes[i]['load'] * 10)
                data += struct.pack('!i', pos)
                data += struct.pack('!H', load)
            data += struct.pack('!i', self.spindle_speed)
            return frame.reply(data)

        elif frame.func == FUNC_READ_ALARM:
            if self.alarm:
                return frame.reply(struct.pack('!H', self.alarm_code) +
                                   b'ALARM\0')
            return frame.reply(b'\x00\x00')

        elif frame.func == FUNC_READ_STATUS:
            status = struct.pack('!H', 0x0001 if self.operating else 0x0000)
            status += struct.pack('!H', 0x0001 if self.alarm else 0x0000)
            return frame.reply(status)

        elif frame.func == FUNC_READ_SPEED:
            return frame.reply(struct.pack('!i', self.spindle_speed))

        elif frame.func == FUNC_READ_LOAD:
            avg_load = sum(self.axes[i]['load'] for i in range(1, self.max_axis + 1)) / self.max_axis
            return frame.reply(struct.pack('!H', int(avg_load)))

        elif frame.func == FUNC_HANDLE:
            return frame.reply(b'\x01\x00')  # 句柄分配成功

        else:
            logger.warning(f'未知功能码: 0x{frame.func:04x}')
            return frame.reply(b'', error=0x0001)


class FOCASSimulator:
    """FOCAS 模拟服务器"""

    def __init__(self, host: str = '0.0.0.0', port: int = FOCAS_PORT):
        self.host = host
        self.port = port
        self.cnc = CNCSimulator()
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(5)
        self._running = True

        print(f'[FOCAS] CNC 模拟器启动: TCP {self.host}:{self.port}')
        print(f'[FOCAS] CNC 型号: {self.cnc.model}')
        print(f'[FOCAS] 最大轴数: {self.cnc.max_axis}')

        while self._running:
            try:
                client, addr = self._server.accept()
                print(f'[FOCAS] 客户端: {addr[0]}:{addr[1]}')
                threading.Thread(target=self._handle_client,
                                 args=(client, addr), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

        self.cleanup()

    def stop(self):
        self._running = False
        self.cleanup()

    def cleanup(self):
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket, addr: tuple):
        buf = b''
        try:
            while self._running:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buf += chunk

                while len(buf) >= FOCAS_HEADER_LEN:
                    frame = FOCASFrame()
                    if not frame.unpack(buf):
                        break
                    if frame.length > len(buf):
                        break

                    print(f'[FOCAS]  收到: func=0x{frame.func:04x} len={frame.length}')
                    resp = self.cnc.handle_request(frame)
                    client.sendall(resp.pack())
                    print(f'[FOCAS]  响应: func=0x{resp.func:04x} err=0x{resp.error:04x}')

                    buf = buf[frame.length:]
                    if len(buf) < FOCAS_HEADER_LEN:
                        break

        except (ConnectionError, socket.timeout):
            pass
        finally:
            client.close()
            print(f'[FOCAS] 断开: {addr[0]}:{addr[1]}')


def run_simulator(host: str = '0.0.0.0', port: int = FOCAS_PORT):
    sim = FOCASSimulator(host, port)
    try:
        sim.start()
    except KeyboardInterrupt:
        print('\n[FOCAS] 停止...')
        sim.stop()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    run_simulator()
