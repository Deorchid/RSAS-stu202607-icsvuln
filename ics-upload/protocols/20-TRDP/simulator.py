"""
工控协议模拟器 - TRDP (Train Real-time Data Protocol)
===================================================
基于 IEC 61375 标准的列车实时数据协议模拟
端口: UDP 17224 (PD), 17225 (MD)

TRDP 格式: 40 字节固定头 + 负载
  version(2) opcode(2) comId(4) etbId(2) srcId(2) dstId(2)
  seqNo(4) timestamp(8) replyTimeout(4) flags(2) length(2) unused(2)

参考: IEC 61375-2-3, TCNOpen TRDP 实现
"""

import socket, struct, threading, time, random, logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

TRDP_PD_PORT = 17224
TRDP_MD_PORT = 17225

OP_PUBLISH = 2
OP_SUBSCRIBE = 3

# 列车数据类型 (comId -> (name, unit))
TRAIN_SIGNALS = {
    0x0001: ('Speed', 'km/h'),
    0x0002: ('BrakePressure', 'kPa'),
    0x0003: ('DoorStatus', ''),
    0x0004: ('MotorCurrent', 'A'),
    0x0006: ('Temperature', 'degC'),
    0x000A: ('EmergencyBrake', ''),
    0x000C: ('AirPressure', 'kPa'),
}


class TRDPHeader:
    """TRDP 40 字节固定头"""

    def __init__(self):
        self.version = 0x0100
        self.opcode = OP_PUBLISH
        self.com_id = 0x1000
        self.etb_id = 1
        self.src_id = 1
        self.dst_id = 0
        self.seq_no = 0
        self.timestamp = 0
        self.reply_timeout = 0
        self.flags = 0
        self.length = 0

    def pack(self) -> bytes:
        self.timestamp = int(time.time() * 1000)
        return struct.pack('!HHIHHHIQQHHH',
                           self.version, self.opcode, self.com_id, self.etb_id,
                           self.src_id, self.dst_id, self.seq_no, self.timestamp,
                           self.reply_timeout, self.flags, self.length, 0)

    def unpack(self, data: bytes) -> bool:
        if len(data) < 40: return False
        try:
            (self.version, self.opcode, self.com_id, self.etb_id,
             self.src_id, self.dst_id, self.seq_no, self.timestamp,
             self.reply_timeout, self.flags, self.length, _) = struct.unpack_from('!HHIHHHIQQHHH', data, 0)
            return True
        except struct.error:
            return False


class TrainController:
    """模拟列车控制单元"""

    def __init__(self, device_id: int = 1, name: str = 'TCU1'):
        self.id = device_id
        self.name = name
        self.seq = 0
        # 列车状态
        self.speed = 0.0
        self.brake_pressure = 500.0
        self.doors_open = False
        self.motor_current = 0.0
        self.temperature = 25.0
        self.emergency_brake = False
        self.air_pressure = 900.0
        self._target_speed = 0.0
        self._running = False

    def start(self):
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            # 速度变化
            if self.emergency_brake:
                self.speed = max(0, self.speed - 5.0)
                self.brake_pressure = 900.0
            elif self._target_speed > self.speed:
                self.speed = min(self.speed + 0.5, self._target_speed)
                self.motor_current = 100 + self.speed * 2
                self.brake_pressure = 200
            elif self._target_speed < self.speed:
                self.speed = max(self.speed - 0.3, self._target_speed)
                self.motor_current = max(0, self.speed * 1.5)
                self.brake_pressure = 400 + int(self.speed * 2)
            else:
                self.motor_current = max(5, self.speed * 1.2)

            self.temperature += random.uniform(-0.2, 0.3)
            self.air_pressure += random.uniform(-5, 5)
            self.air_pressure = max(700, min(1000, self.air_pressure))
            self.seq = (self.seq + 1) & 0xFFFFFFFF
            time.sleep(0.1)

    def set_speed(self, s: float):
        self._target_speed = max(0, min(300, s))

    def set_ebrake(self, active: bool):
        self.emergency_brake = active
        if active: self._target_speed = 0

    def get_pd_payload(self) -> bytes:
        """打包过程数据"""
        data = b''
        for com_id, val in [(0x0001, self.speed), (0x0002, self.brake_pressure),
                             (0x0003, 1 if self.doors_open else 0),
                             (0x0004, self.motor_current), (0x0006, self.temperature),
                             (0x000A, 1 if self.emergency_brake else 0),
                             (0x000C, self.air_pressure)]:
            data += struct.pack('!I', com_id)
            if isinstance(val, float):
                data += struct.pack('!f', val)
            else:
                data += struct.pack('!i', val)
        return data


class TRDPSimulator:
    """TRDP 模拟器"""

    def __init__(self, device_id: int = 1):
        self.train = TrainController(device_id, f'TCU{device_id}')
        self._running = False

    def start(self):
        self.train.start()
        self._running = True
        print(f'[TRDP] 列车控制单元: {self.train.name} (ID={self.train.id})')
        print(f'[TRDP] PD端口: UDP {TRDP_PD_PORT} | MD端口: UDP {TRDP_MD_PORT}')
        print(f'[TRDP] 命令: speed N, brake, release, doors, status, packet, quit\n')

        while True:
            try:
                cmd = input('> ').strip().lower()
                if cmd in ('quit', 'q'):
                    break
                elif cmd.startswith('speed'):
                    s = float(cmd.split()[1])
                    self.train.set_speed(s)
                    print(f'  目标速度: {s} km/h')
                elif cmd == 'brake':
                    self.train.set_ebrake(True)
                    print('  紧急制动!')
                elif cmd == 'release':
                    self.train.set_ebrake(False)
                    print('  制动释放')
                elif cmd == 'doors':
                    self.train.doors_open = not self.train.doors_open
                    print(f'  车门: {"OPEN" if self.train.doors_open else "CLOSED"}')
                elif cmd == 'packet':
                    h = TRDPHeader()
                    h.com_id = 0x1000; h.src_id = self.train.id
                    h.seq_no = self.train.seq
                    payload = self.train.get_pd_payload()
                    h.length = len(payload)
                    pkt = h.pack() + payload
                    print(f'  PD 报文: {len(pkt)}B seq={self.train.seq}')
                    print(f'  Speed={self.train.speed:.0f} Brake={self.train.brake_pressure:.0f}')
                    print(f'  Emergency={self.train.emergency_brake}')
                elif cmd == 'status':
                    t = self.train
                    print(f'  Speed={t.speed:.0f} Brake={t.brake_pressure:.0f}')
                    print(f'  Doors={"OPEN" if t.doors_open else "CLOSED"}')
                    print(f'  Motor={t.motor_current:.0f}A Temp={t.temperature:.0f}°C')
                    print(f'  Emergency={t.emergency_brake} Air={t.air_pressure:.0f}kPa')
                    print(f'  Seq={t.seq}')
                elif cmd == '':
                    if self.train.seq % 20 == 0:
                        print(f'  v={self.train.speed:.0f}km/h')
            except KeyboardInterrupt:
                break

        self.train.stop()
        print('[TRDP] 退出')

    def stop(self):
        self.train.stop()
        self._running = False


def run_simulator():
    sim = TRDPSimulator(1)
    sim.start()


if __name__ == '__main__':
    run_simulator()
