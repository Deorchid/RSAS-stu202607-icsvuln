"""
工控协议模拟器 - ADS (Automation Device Specification)
=====================================================
基于真实 AMS/ADS 协议实现（参考 pyads testserver 源代码）
端口: TCP 48898

AMS TCP 组帧格式:
  [0x0000 (2B 保留)] + [AMS长度 (4B 大端)] + [AMS头 (32B)] + [负载]

AMS 头部 (32 字节):
  Offset  Size  字段
  0       6     目标 AMS NetId
  6       2     目标 AMS Port
  8       6     源 AMS NetId
  14      2     源 AMS Port
  16      2     命令 ID (Command ID)
  18      2     状态标志 (State Flags)
  20      4     数据长度
  24      4     错误码
  28      4     调用 ID (Invoke ID)

参考: pyads (https://github.com/stlehmann/pyads)
      Beckhoff TwinCAT ADS 规范
"""

import socket
import struct
import threading
import time
import random
import logging
from typing import Optional, Callable, Dict, Any, Tuple

logger = logging.getLogger(__name__)

# ---- 协议常量 ----
ADS_TCP_PORT = 48898
AMS_HEADER_LEN = 32

# ---- AMS/TCP 帧前缀 ----
AMS_TCP_RESERVED = b'\x00\x00'

# ---- 命令 ID ----
ADS_CMD_INVALID = 0
ADS_CMD_READ_DEVICE_INFO = 1
ADS_CMD_READ = 2
ADS_CMD_WRITE = 3
ADS_CMD_READ_STATE = 4
ADS_CMD_WRITE_CONTROL = 5
ADS_CMD_ADD_NOTIFICATION = 6
ADS_CMD_DEL_NOTIFICATION = 7
ADS_CMD_NOTIFICATION = 8
ADS_CMD_READ_WRITE = 9

CMD_NAMES = {
    0: 'INVALID', 1: 'READ_DEVICE_INFO', 2: 'READ', 3: 'WRITE',
    4: 'READ_STATE', 5: 'WRITE_CONTROL', 6: 'ADD_NOTIFICATION',
    7: 'DEL_NOTIFICATION', 8: 'NOTIFICATION', 9: 'READ_WRITE',
}

# ---- ADS 错误码 ----
ADS_ERR_NO_ERR = 0
ADS_ERR_DEVICE_ERROR = 0x700
ADS_ERR_DEVICE_INVALID_AMS_NETID = 0x704
ADS_ERR_DEVICE_INVALID_PORT = 0x708
ADS_ERR_DEVICE_INVALID_PARAM = 0x710
ADS_ERR_DEVICE_ACCESS_DENIED = 0x71C
ADS_ERR_DEVICE_SRV_NOT_SUPPORTED = 0x750
ADS_ERR_CLIENT_INVALID_PARAM = 0x7F0

# ---- ADS 状态 ----
ADS_STATE_INVALID = 0
ADS_STATE_IDLE = 1
ADS_STATE_RESET = 2
ADS_STATE_INIT = 3
ADS_STATE_START = 4
ADS_STATE_RUN = 5
ADS_STATE_STOP = 6
ADS_STATE_SAVECFG = 7
ADS_STATE_LOADCFG = 8
ADS_STATE_POWER_FAILURE = 9
ADS_STATE_POWER_GOOD = 10
ADS_STATE_ERROR = 11
ADS_STATE_SHUTDOWN = 12

STATE_NAMES = {
    0: 'INVALID', 1: 'IDLE', 2: 'RESET', 3: 'INIT', 4: 'START',
    5: 'RUN', 6: 'STOP', 7: 'SAVECFG', 8: 'LOADCFG',
    9: 'POWER_FAILURE', 10: 'POWER_GOOD', 11: 'ERROR', 12: 'SHUTDOWN',
}

# ---- IndexGroup 常量 ----
INDEXG_RW_DEVICE_INFO = 0x00000001
INDEXG_RW_SYMTAB = 0x0000000F
INDEXG_RW_SYMBOL_NAME = 0x00000010
INDEXG_RW_SYMBOL_VAL = 0x00000011
INDEXG_RW_RETAIN = 0x00000020
INDEXG_RW_PLC_PROGRAM = 0x00000030
INDEXG_RW_SYMBOL_NAME_BY_HANDLE = 0x00000031
INDEXG_RW_ATOMIC_READ_WRITE = 0x00000040
INDEXG_RW_ATOMIC_READ_AND_WRITE = 0x00000050
INDEXG_RW_ARRAY_INFO = 0x00000060
INDEXG_RW_PLCDATA = 0x00000080
INDEXG_RW_PLCDATA_STR = 0x00000081
INDEXG_RW_PLCDATA_AUTO = 0x00000082


def parse_net_id(data: bytes, offset: int = 0) -> str:
    """将 6 字节 AMS NetId 解析为字符串"""
    return '.'.join(str(data[offset + i]) for i in range(6))


def format_net_id(net_id: str) -> bytes:
    """将 AMS NetId 字符串转为 6 字节"""
    parts = [int(x) for x in net_id.split('.')]
    while len(parts) < 6:
        parts.append(1)
    return bytes(parts[:6])


class AMSHeader:
    """AMS 协议头部 — 精准匹配 pyads testserver 结构"""

    __slots__ = ('target_netid', 'target_port', 'source_netid', 'source_port',
                 'cmd_id', 'state_flags', 'data_length', 'error_code', 'invoke_id')

    def __init__(self):
        self.target_netid: str = '127.0.0.1.1.1'
        self.target_port: int = 851
        self.source_netid: str = '127.0.0.1.1.1'
        self.source_port: int = 851
        self.cmd_id: int = 0
        self.state_flags: int = 0
        self.data_length: int = 0
        self.error_code: int = 0
        self.invoke_id: int = 0

    def pack(self) -> bytes:
        """打包为 32 字节 AMS 头部"""
        return (format_net_id(self.target_netid) +
                struct.pack('!H', self.target_port) +
                format_net_id(self.source_netid) +
                struct.pack('!H', self.source_port) +
                struct.pack('!HHIII', self.cmd_id, self.state_flags,
                            self.data_length, self.error_code, self.invoke_id))

    def unpack(self, data: bytes) -> bool:
        """从 32 字节解析 AMS 头部"""
        if len(data) < AMS_HEADER_LEN:
            return False
        self.target_netid = parse_net_id(data, 0)
        self.target_port = struct.unpack_from('!H', data, 6)[0]
        self.source_netid = parse_net_id(data, 8)
        self.source_port = struct.unpack_from('!H', data, 14)[0]
        (self.cmd_id, self.state_flags, self.data_length,
         self.error_code, self.invoke_id) = struct.unpack_from('!HHIII', data, 16)
        return True

    def build_reply(self, cmd_id: int, error_code: int = ADS_ERR_NO_ERR,
                    data: bytes = b'') -> 'AMSHeader':
        """构建响应头（交换源和目标）"""
        reply = AMSHeader()
        reply.target_netid = self.source_netid
        reply.target_port = self.source_port
        reply.source_netid = self.target_netid
        reply.source_port = self.target_port
        reply.cmd_id = cmd_id
        reply.state_flags = 0x0001
        reply.data_length = len(data)
        reply.error_code = error_code
        reply.invoke_id = self.invoke_id
        return reply

    def __str__(self) -> str:
        cmd = CMD_NAMES.get(self.cmd_id, f'0x{self.cmd_id:04x}')
        return (f'AMS({cmd} tgt={self.target_netid}:{self.target_port} '
                f'src={self.source_netid}:{self.source_port} '
                f'len={self.data_length} err=0x{self.error_code:04x} '
                f'inv={self.invoke_id})')


def pack_ams_tcp_frame(ams_header: AMSHeader, payload: bytes = b'') -> bytes:
    """打包 AMS/TCP 帧 ([0x0000][4B len][32B AMS header][payload])"""
    ams_header.data_length = len(payload)
    hdr_bytes = ams_header.pack()
    length = AMS_HEADER_LEN + len(payload)
    return AMS_TCP_RESERVED + struct.pack('!I', length) + hdr_bytes + payload


def unpack_ams_tcp_frame(data: bytes) -> Tuple[Optional[AMSHeader], bytes, int]:
    """
    解包 AMS/TCP 帧
    返回: (AMSHeader, payload, total_frame_size) 或 (None, b'', 0)
    """
    if len(data) < 6:  # 至少 2+4 字节头
        return None, b'', 0
    if data[:2] != AMS_TCP_RESERVED:
        return None, b'', 0
    ams_len = struct.unpack_from('!I', data, 2)[0]
    total_len = 6 + ams_len  # 6 = 2(保留) + 4(长度)
    if len(data) < total_len:
        return None, b'', 0

    ams = AMSHeader()
    if not ams.unpack(data[6:6 + AMS_HEADER_LEN]):
        return None, b'', 0
    payload = data[6 + AMS_HEADER_LEN:6 + ams_len]
    return ams, payload, total_len


# ==================== ADS 变量模拟 ====================

class PLCVariable:
    """模拟 TwinCAT PLC 变量"""

    def __init__(self, name: str, value: bytes = b'\x00' * 4,
                 ads_type: int = 0x0002, index_group: int = INDEXG_RW_PLCDATA,
                 index_offset: int = 0x1000):
        self.name = name
        self.value = value
        self.ads_type = ads_type
        self.index_group = index_group
        self.index_offset = index_offset

    @property
    def as_int(self) -> int:
        if len(self.value) >= 4:
            return struct.unpack('!I', self.value[:4])[0]
        return int.from_bytes(self.value, 'big')

    @property
    def as_float(self) -> float:
        if len(self.value) >= 4:
            return struct.unpack('!f', self.value[:4])[0]
        return 0.0

    def __str__(self) -> str:
        return f'{self.name}=0x{self.value.hex()} @[{hex(self.index_group)}:{hex(self.index_offset)}]'


class TwinCATDevice:
    """模拟 TwinCAT 运行时设备"""

    def __init__(self):
        self.name = 'CX-Embedded'
        self.version_major = 3
        self.version_minor = 1
        self.version_build = 4024
        self.ads_state = ADS_STATE_RUN
        self.device_state = 0

        # 模拟变量表
        self.variables: Dict[Tuple[int, int], PLCVariable] = {}
        self._init_variables()

    def _init_variables(self):
        """初始化典型 PLC 变量"""
        defaults = [
            PLCVariable('GVL.nCounter', struct.pack('!I', 0), index_offset=0x1000),
            PLCVariable('GVL.fTemperature', struct.pack('!f', 25.5), index_offset=0x1004),
            PLCVariable('GVL.fPressure', struct.pack('!f', 100.0), index_offset=0x1008),
            PLCVariable('GVL.bValveOpen', b'\x01', index_offset=0x100C),
            PLCVariable('GVL.bMotorRun', b'\x00', index_offset=0x100D),
            PLCVariable('GVL.nSpeedSP', struct.pack('!H', 1500), index_offset=0x100E),
            PLCVariable('GVL.sProductCode', b'MACHINE_01\x00\x00\x00\x00\x00\x00\x00\x00',
                       index_offset=0x2000),
        ]
        for var in defaults:
            key = (var.index_group, var.index_offset)
            self.variables[key] = var

    def start_simulation(self):
        """启动变量模拟更新"""
        threading.Thread(target=self._sim_loop, daemon=True).start()

    def _sim_loop(self):
        while True:
            # 递增计数器
            cnt_key = (INDEXG_RW_PLCDATA, 0x1000)
            if cnt_key in self.variables:
                val = self.variables[cnt_key].as_int
                val = (val + 1) & 0xFFFFFFFF
                self.variables[cnt_key].value = struct.pack('!I', val)

            # 温度随机波动
            temp_key = (INDEXG_RW_PLCDATA, 0x1004)
            if temp_key in self.variables:
                val = self.variables[temp_key].as_float
                val += random.uniform(-0.5, 0.5)
                self.variables[temp_key].value = struct.pack('!f', val)

            time.sleep(1.0)


# ==================== ADS 模拟服务器 ====================

class ADSSimulator:
    """ADS 协议模拟服务器 — 基于 pyads testserver 架构"""

    def __init__(self, host: str = '0.0.0.0', port: int = ADS_TCP_PORT,
                 net_id: str = '192.168.0.1.1.1'):
        self.host = host
        self.port = port
        self.net_id = net_id
        self.device = TwinCATDevice()
        self._server: Optional[socket.socket] = None
        self._running = False

    def start(self):
        """启动 ADS 模拟服务器"""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(5)
        self._running = True
        self.device.start_simulation()

        logger.info(f'[ADS] 模拟器启动: {self.host}:{self.port}')
        print(f'[ADS] ADS 模拟服务器启动')
        print(f'[ADS]   监听: TCP {self.host}:{self.port}')
        print(f'[ADS]   AMS NetId: {self.net_id}')
        print(f'[ADS]   设备: {self.device.name} v{self.device.version_major}.{self.device.version_minor}')
        print(f'[ADS]   状态: {STATE_NAMES.get(self.device.ads_state, "?")}')

        while self._running:
            try:
                client, addr = self._server.accept()
                logger.info(f'[ADS] 客户端连接: {addr[0]}:{addr[1]}')
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
        logger.info('[ADS] 模拟器已停止')

    def cleanup(self):
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket, addr: tuple):
        """处理 ADS 客户端连接"""
        buf = b''
        try:
            while self._running:
                chunk = client.recv(4096)
                if not chunk:
                    break
                buf += chunk

                while True:
                    ams, payload, consumed = unpack_ams_tcp_frame(buf)
                    if ams is None:
                        if len(buf) > 6 and buf[:2] != b'\x00\x00':
                            buf = buf[1:]
                            continue
                        break

                    logger.debug(f'[ADS] 收到: {ams} ({len(payload)}B)')
                    response = self._handle_ams_request(ams, payload)
                    if response:
                        client.sendall(response)

                    buf = buf[consumed:]
                    if len(buf) < 6:
                        break

        except (ConnectionError, socket.timeout):
            pass
        except Exception as e:
            logger.error(f'[ADS] 客户端异常: {e}')
        finally:
            client.close()
            logger.info(f'[ADS] 客户端断开: {addr[0]}:{addr[1]}')

    def _handle_ams_request(self, req: AMSHeader, payload: bytes) -> Optional[bytes]:
        """处理 AMS 请求并返回响应帧"""
        try:
            if req.cmd_id == ADS_CMD_READ_DEVICE_INFO:
                return self._cmd_read_device_info(req)
            elif req.cmd_id == ADS_CMD_READ:
                return self._cmd_read(req, payload)
            elif req.cmd_id == ADS_CMD_WRITE:
                return self._cmd_write(req, payload)
            elif req.cmd_id == ADS_CMD_READ_STATE:
                return self._cmd_read_state(req)
            elif req.cmd_id == ADS_CMD_READ_WRITE:
                return self._cmd_read_write(req, payload)
            elif req.cmd_id == ADS_CMD_WRITE_CONTROL:
                return self._cmd_write_control(req, payload)
            elif req.cmd_id == ADS_CMD_ADD_NOTIFICATION:
                return self._cmd_add_notification(req, payload)
            elif req.cmd_id == ADS_CMD_DEL_NOTIFICATION:
                return self._cmd_del_notification(req, payload)
            else:
                logger.warning(f'[ADS] 未支持的命令: {req.cmd_id}')
                return self._build_error(req, ADS_ERR_DEVICE_SRV_NOT_SUPPORTED)
        except Exception as e:
            logger.error(f'[ADS] 处理异常: {e}')
            return self._build_error(req, ADS_ERR_DEVICE_ERROR)

    def _build_error(self, req: AMSHeader, err_code: int) -> bytes:
        reply = req.build_reply(req.cmd_id, err_code)
        return pack_ams_tcp_frame(reply)

    def _cmd_read_device_info(self, req: AMSHeader) -> bytes:
        """ADS ReadDeviceInfo 响应"""
        data = struct.pack('!IHHI', self.device.version_major,
                           self.device.version_minor, 0, self.device.version_build)
        name_bytes = self.device.name.encode('utf-8')[:16].ljust(16, b'\x00')
        data += name_bytes
        reply = req.build_reply(ADS_CMD_READ_DEVICE_INFO, data=data)
        return pack_ams_tcp_frame(reply, data)

    def _cmd_read(self, req: AMSHeader, payload: bytes) -> bytes:
        """ADS Read 响应 — 读取 PLC 变量"""
        if len(payload) < 12:
            return self._build_error(req, ADS_ERR_DEVICE_INVALID_PARAM)

        index_group = struct.unpack_from('!I', payload, 0)[0]
        index_offset = struct.unpack_from('!I', payload, 4)[0]
        read_length = struct.unpack_from('!I', payload, 8)[0]

        key = (index_group, index_offset)
        var = self.device.variables.get(key)

        if var is None:
            # 未知地址返回零填充
            value = b'\x00' * read_length
        else:
            value = var.value[:read_length].ljust(read_length, b'\x00')

        resp_data = struct.pack('!I', len(value)) + value
        reply = req.build_reply(ADS_CMD_READ, data=resp_data)
        return pack_ams_tcp_frame(reply, resp_data)

    def _cmd_write(self, req: AMSHeader, payload: bytes) -> bytes:
        """ADS Write 响应 — 写入 PLC 变量"""
        if len(payload) < 12:
            return self._build_error(req, ADS_ERR_DEVICE_INVALID_PARAM)

        index_group = struct.unpack_from('!I', payload, 0)[0]
        index_offset = struct.unpack_from('!I', payload, 4)[0]
        write_length = struct.unpack_from('!I', payload, 8)[0]
        write_data = payload[12:12 + write_length]

        key = (index_group, index_offset)
        if key in self.device.variables:
            self.device.variables[key].value = write_data
        else:
            # 自动创建新变量
            self.device.variables[key] = PLCVariable(
                f'Dynamic@{hex(index_offset)}', write_data,
                index_group=index_group, index_offset=index_offset)

        resp_data = struct.pack('!I', write_length)
        reply = req.build_reply(ADS_CMD_WRITE, data=resp_data)
        return pack_ams_tcp_frame(reply, resp_data)

    def _cmd_read_state(self, req: AMSHeader) -> bytes:
        """ADS ReadState 响应"""
        resp_data = struct.pack('!HH', self.device.ads_state, self.device.device_state)
        reply = req.build_reply(ADS_CMD_READ_STATE, data=resp_data)
        return pack_ams_tcp_frame(reply, resp_data)

    def _cmd_read_write(self, req: AMSHeader, payload: bytes) -> bytes:
        """ADS ReadWrite 响应"""
        if len(payload) < 16:
            return self._build_error(req, ADS_ERR_DEVICE_INVALID_PARAM)

        index_group = struct.unpack_from('!I', payload, 0)[0]
        index_offset = struct.unpack_from('!I', payload, 4)[0]
        read_len = struct.unpack_from('!I', payload, 8)[0]
        write_len = struct.unpack_from('!I', payload, 12)[0]
        write_data = payload[16:16 + write_len]

        key = (index_group, index_offset)

        # 先写
        if write_len > 0:
            if key in self.device.variables:
                self.device.variables[key].value = write_data
            else:
                self.device.variables[key] = PLCVariable(
                    f'Dynamic@{hex(index_offset)}', write_data,
                    index_group=index_group, index_offset=index_offset)

        # 后读
        if key in self.device.variables:
            value = self.device.variables[key].value[:read_len].ljust(read_len, b'\x00')
        else:
            value = b'\x00' * read_len

        resp_data = struct.pack('!I', len(value)) + value
        reply = req.build_reply(ADS_CMD_READ_WRITE, data=resp_data)
        return pack_ams_tcp_frame(reply, resp_data)

    def _cmd_write_control(self, req: AMSHeader, payload: bytes) -> bytes:
        """ADS WriteControl 响应 — 修改 ADS 状态"""
        if len(payload) >= 4:
            ads_state = struct.unpack_from('!H', payload, 0)[0]
            device_state = struct.unpack_from('!H', payload, 2)[0]
            if ads_state in STATE_NAMES:
                self.device.ads_state = ads_state
                print(f'[ADS] 状态变更 -> {STATE_NAMES.get(ads_state, "?")}')
            self.device.device_state = device_state

        reply = req.build_reply(ADS_CMD_WRITE_CONTROL)
        return pack_ams_tcp_frame(reply)

    def _cmd_add_notification(self, req: AMSHeader, payload: bytes) -> bytes:
        """ADS AddNotification 响应（简化）"""
        if len(payload) < 24:
            return self._build_error(req, ADS_ERR_DEVICE_INVALID_PARAM)

        # 返回句柄 0x1000
        resp_data = struct.pack('!I', 0x1000)
        reply = req.build_reply(ADS_CMD_ADD_NOTIFICATION, data=resp_data)
        return pack_ams_tcp_frame(reply, resp_data)

    def _cmd_del_notification(self, req: AMSHeader, payload: bytes) -> bytes:
        """ADS DeleteNotification 响应"""
        reply = req.build_reply(ADS_CMD_DEL_NOTIFICATION)
        return pack_ams_tcp_frame(reply)


def run_simulator(host: str = '0.0.0.0', port: int = ADS_TCP_PORT):
    sim = ADSSimulator(host, port)
    try:
        sim.start()
    except KeyboardInterrupt:
        print('\n[ADS] 正在停止...')
        sim.stop()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')
    run_simulator()
