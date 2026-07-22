"""
工控协议模拟器 - SV (Sampled Values, IEC 61850-9-2)
===================================================
合并单元 (Merging Unit) 模拟器，基于 ASN.1/BER 编码。
EtherType: 0x88BA

功能:
  - 8 通道采样值输出 (Ua Ub Uc Un Ia Ib Ic In)
  - 多种故障模拟 (三相短路、单相接地、相间故障、过电流等)
  - 交互式控制
  - 采样计数器维护 (0-3999 @ 50Hz)
  - smpSynch 状态设置

参考: IEC 61850-9-2 LE (Light Edition)
      libiec61850 (mz-automation/libiec61850)
"""

import struct
import time
import math
import threading
import random
from typing import Optional, List, Tuple, Dict, Any

ETHERTYPE_SV = 0x88BA
SV_MULTICAST_MAC = '01:0c:cd:04:00:01'
SAMPLE_RATE = 4000  # 80 采样/周波 @ 50Hz
FREQUENCY = 50.0
CHANNEL_NAMES = ['Ua', 'Ub', 'Uc', 'Un', 'Ia', 'Ib', 'Ic', 'In']


def _bl(l: int) -> bytes:
    if l < 128:
        return bytes([l])
    return struct.pack('!BH', 0x81, l)


def _bi(tag: int, v: int) -> bytes:
    if v < 256:
        d = bytes([v])
    elif v < 65536:
        d = struct.pack('!H', v)
    else:
        d = struct.pack('!I', v)
    return bytes([tag]) + _bl(len(d)) + d


def _bs(tag: int, s: str) -> bytes:
    d = s.encode('utf-8')
    return bytes([tag]) + _bl(len(d)) + d


class SVMergingUnit:
    """合并单元 (Merging Unit) 模拟器

    模拟真实 MU，维护 8 通道采样数据，支持故障注入。
    """

    def __init__(self, name: str = 'MU01', rated_voltage: float = 110000.0):
        self.name = name
        self.sv_id = f'{name}/LLN0$MS$PhsMeas1'
        self.smp_cnt = 0
        self.conf_rev = 1
        self.smp_synch = 2  # 2=global (GPS), 1=local, 0=unsync

        # 额定值
        self.rated_voltage_ll = rated_voltage  # 线电压 (V)
        self.rated_voltage_ph = rated_voltage / math.sqrt(3)  # 相电压 (V)
        self.rated_current = 1000.0  # 额定电流 (A)

        # 故障状态
        self.fault_active = False
        self.fault_type = 'none'
        self.fault_params: Dict[str, Any] = {}
        self._angle = 0.0

        # 运行统计
        self.packet_count = 0
        self.start_time = time.time()

        # 叠加谐波
        self.harmonic_3rd = 0.0  # 3 次谐波幅值
        self.harmonic_5th = 0.0  # 5 次谐波幅值

        # 自动发送
        self._auto_send = False
        self._auto_thread: Optional[threading.Thread] = None

    def get_angle(self) -> float:
        """获取当前采样角度"""
        self._angle = (self.smp_cnt / SAMPLE_RATE) * 2 * math.pi * FREQUENCY
        return self._angle

    def _add_harmonics(self, t: float, fundamental: float, freq: float = FREQUENCY) -> float:
        """叠加谐波到基波"""
        harmonic = 0.0
        if self.harmonic_3rd != 0:
            harmonic += self.harmonic_3rd * math.sin(3 * 2 * math.pi * freq * t)
        if self.harmonic_5th != 0:
            harmonic += self.harmonic_5th * math.sin(5 * 2 * math.pi * freq * t)
        return fundamental + harmonic

    def get_samples(self) -> Tuple[float, float, float, float,
                                   float, float, float, float]:
        """获取 8 通道采样值: Ua Ub Uc Un Ia Ib Ic In

        Normal: 三相平衡系统
        Fault: 根据故障类型修改采样值
        """
        self.smp_cnt = (self.smp_cnt + 1) % SAMPLE_RATE
        angle = self.get_angle()

        # 三相平衡基波
        u_a = self.rated_voltage_ph * math.sin(angle)
        u_b = self.rated_voltage_ph * math.sin(angle - 2 * math.pi / 3)
        u_c = self.rated_voltage_ph * math.sin(angle + 2 * math.pi / 3)
        u_n = 0.0

        i_a = 300.0 * math.sin(angle + math.pi / 6)
        i_b = 300.0 * math.sin(angle - 2 * math.pi / 3 + math.pi / 6)
        i_c = 300.0 * math.sin(angle + 2 * math.pi / 3 + math.pi / 6)
        i_n = 0.0

        if self.fault_active:
            u_a, u_b, u_c, u_n, i_a, i_b, i_c, i_n = self._apply_fault(angle)

        # 叠加谐波
        t = self.smp_cnt / (SAMPLE_RATE * FREQUENCY)
        if self.harmonic_3rd != 0 or self.harmonic_5th != 0:
            u_a = self._add_harmonics(t, u_a)
            u_b = self._add_harmonics(t, u_b)
            u_c = self._add_harmonics(t, u_c)

        return (u_a, u_b, u_c, u_n, i_a, i_b, i_c, i_n)

    def _apply_fault(self, angle: float) -> Tuple[float, float, float, float,
                                                   float, float, float, float]:
        """应用故障状态到采样值"""
        ft = self.fault_type

        if ft == 'three_phase':
            # 三相短路: 电压大幅下降, 电流剧增
            u = 5000.0 * math.sin(angle)
            i = 18000.0 * math.sin(angle + math.pi / 6)
            return (u, u, u, 0.0, i, i, i, 0.0)

        elif ft == 'single_phase':
            # A 相接地: Ua 降为 0, Ia 剧增
            u_a = 500.0 * math.sin(angle)
            u_b = self.rated_voltage_ph * math.sin(angle - 2 * math.pi / 3)
            u_c = self.rated_voltage_ph * math.sin(angle + 2 * math.pi / 3)
            i_a = 15000.0 * math.sin(angle + math.pi / 6)
            i_b = 10.0 * math.sin(angle - 2 * math.pi / 3 + math.pi / 6)
            i_c = 10.0 * math.sin(angle + 2 * math.pi / 3 + math.pi / 6)
            return (u_a, u_b, u_c, 5000.0, i_a, i_b, i_c, i_n := 15000.0)

        elif ft == 'phase_to_phase':
            # AB 相间故障: Ua=Ub=0, Ia/Ib 剧增
            u_a = 2000.0 * math.sin(angle)
            u_b = -2000.0 * math.sin(angle)
            u_c = self.rated_voltage_ph * math.sin(angle + 2 * math.pi / 3)
            i_a = 16000.0 * math.sin(angle + math.pi / 6)
            i_b = -16000.0 * math.sin(angle + math.pi / 6)
            i_c = 50.0 * math.sin(angle + 2 * math.pi / 3 + math.pi / 6)
            return (u_a, u_b, u_c, 0.0, i_a, i_b, i_c, 0.0)

        elif ft == 'overcurrent':
            # 过电流: 电压正常, 电流超限
            u_a = self.rated_voltage_ph * math.sin(angle)
            u_b = self.rated_voltage_ph * math.sin(angle - 2 * math.pi / 3)
            u_c = self.rated_voltage_ph * math.sin(angle + 2 * math.pi / 3)
            i = 25000.0 * math.sin(angle + math.pi / 6)
            return (u_a, u_b, u_c, 0.0, i, i * 0.9, i * 0.8, 0.0)

        elif ft == 'undervoltage':
            # 低电压: 三相电压均下降
            u = 3000.0 * math.sin(angle)
            i = 300.0 * math.sin(angle + math.pi / 6)
            return (u, u, u, 0.0, i, i, i, 0.0)

        elif ft == 'overvoltage':
            # 过电压: 三相电压均升高
            u = 200000.0 * math.sin(angle)
            i = 350.0 * math.sin(angle + math.pi / 6)
            return (u, u, u, 0.0, i, i, i, 0.0)

        elif ft == 'zero_sequence':
            # 零序故障: 三相不平衡+零序电压/电流
            u_a = 20000.0 * math.sin(angle)
            u_b = self.rated_voltage_ph * math.sin(angle - 2 * math.pi / 3)
            u_c = self.rated_voltage_ph * math.sin(angle + 2 * math.pi / 3)
            i_a = 10000.0 * math.sin(angle + math.pi / 6)
            i_b = 300.0 * math.sin(angle - 2 * math.pi / 3 + math.pi / 6)
            i_c = 300.0 * math.sin(angle + 2 * math.pi / 3 + math.pi / 6)
            return (u_a, u_b, u_c, 35000.0, i_a, i_b, i_c, 8000.0)

        # 默认为 normal
        return (self.rated_voltage_ph * math.sin(angle),
                self.rated_voltage_ph * math.sin(angle - 2 * math.pi / 3),
                self.rated_voltage_ph * math.sin(angle + 2 * math.pi / 3),
                0.0,
                300.0 * math.sin(angle + math.pi / 6),
                300.0 * math.sin(angle - 2 * math.pi / 3 + math.pi / 6),
                300.0 * math.sin(angle + 2 * math.pi / 3 + math.pi / 6),
                0.0)

    def build_sv_packet(self, src_mac: Optional[bytes] = None) -> bytes:
        """构造 SV 以太网帧"""
        if src_mac is None:
            src_mac = bytes([0x00, 0x50, 0xc2, 0x00, 0x00, 0x01])

        ua, ub, uc, un, ia, ib, ic, ins = self.get_samples()

        # ASDU
        asdu = b''
        asdu += _bs(0x80, self.sv_id)
        asdu += _bi(0x82, self.smp_cnt)
        asdu += _bi(0x83, self.conf_rev)
        asdu += _bi(0x85, self.smp_synch)

        seq = struct.pack('!ffffffff', ua, ub, uc, un, ia, ib, ic, ins)
        asdu += bytes([0x87]) + _bl(len(seq)) + seq

        asdu_frame = bytes([0x30]) + _bl(len(asdu)) + asdu
        no_asdu = bytes([0x80, 1, 1])
        sav_pdu = bytes([0x60]) + _bl(len(no_asdu) + len(asdu_frame)) + no_asdu + asdu_frame

        dst_mac = bytes(int(x, 16) for x in SV_MULTICAST_MAC.split(':'))
        frame = dst_mac + src_mac
        frame += struct.pack('!HH', 0x8100, 0x8000)  # VLAN (优先级 4)
        frame += struct.pack('!HHHHH', ETHERTYPE_SV, 0x4000, 8 + len(sav_pdu), 0, 0)
        frame += sav_pdu
        if len(frame) < 64:
            frame += b'\x00' * (64 - len(frame))

        self.packet_count += 1
        return frame

    def get_status(self) -> Dict[str, Any]:
        """获取当前状态"""
        return {
            'name': self.name,
            'sv_id': self.sv_id,
            'smp_cnt': self.smp_cnt,
            'conf_rev': self.conf_rev,
            'smp_synch': ['unsync', 'local', 'global'][min(self.smp_synch, 2)],
            'fault_active': self.fault_active,
            'fault_type': self.fault_type,
            'rated_voltage': f'{self.rated_voltage_ll / 1000:.0f} kV',
            'harmonic_3rd': f'{self.harmonic_3rd * 100:.1f}%',
            'harmonic_5th': f'{self.harmonic_5th * 100:.1f}%',
            'packet_count': self.packet_count,
            'uptime': f'{time.time() - self.start_time:.0f}s',
        }


def run_simulator():
    """交互式 SV 模拟器"""
    mu = SVMergingUnit('MU01')
    print(f'[SV] 合并单元 {mu.name} 模拟器')
    print(f'[SV] svID={mu.sv_id}')
    print(f'[SV] 额定电压={mu.rated_voltage_ll/1000:.0f}kV')
    print(f'[SV] 采样率={SAMPLE_RATE}Hz')
    print(f'[SV] 通道={", ".join(CHANNEL_NAMES)}')
    print()
    print('  命令:')
    print('    packet           — 生成并显示一个 SV 报文')
    print('    status           — 显示当前状态')
    print('    fault <type>     — 触发故障 (types below)')
    print('    clear            — 清除故障')
    print('    synch <0|1|2>    — 设置 smpSynch')
    print('    harm <3rd%> <5th%> — 设置谐波含量')
    print('    auto [n]         — 自动生成 n 个采样 (默认 80)')
    print('    count <N>        — 设置采样计数器')
    print('    help             — 显示帮助')
    print('    quit             — 退出')
    print()
    print(f'  故障类型: three_phase | single_phase | phase_to_phase |')
    print(f'            overcurrent | undervoltage | overvoltage | zero_sequence')
    print()

    count = 0
    while True:
        try:
            cmd = input('SV> ').strip().lower()
            if not cmd:
                continue

            parts = cmd.split()
            action = parts[0]

            if action in ('quit', 'q', 'exit'):
                break

            elif action == 'help':
                print('  packet           — 生成 SV 报文 (显示 hex dump)')
                print('  status           — 当前状态')
                print('  fault <type>     — 触发故障')
                print('  clear            — 清除故障')
                print('  synch <0|1|2>    — 同步状态')
                print('  harm <3rd%> <5th%> — 谐波')
                print('  auto [n]         — 自动发包')
                print('  count <N>        — 设采样计数器')

            elif action == 'packet':
                count += 1
                pkt = mu.build_sv_packet()
                ua = struct.unpack_from('!f', pkt, 42)[0]
                ia = struct.unpack_from('!f', pkt, 58)[0]
                print(f'  Packet #{count} | smpCnt={mu.smp_cnt} | {len(pkt)}B')
                print(f'  Ua={ua:.0f}V Ub={struct.unpack_from("!f", pkt, 46)[0]:.0f}V')
                print(f'  Ia={ia:.0f}A Ib={struct.unpack_from("!f", pkt, 62)[0]:.0f}A')
                if mu.fault_active:
                    print(f'  ⚠ 故障: {mu.fault_type}')

            elif action == 'status':
                s = mu.get_status()
                for k, v in s.items():
                    print(f'  {k}: {v}')
                # 显示当前采样值
                ua, ub, uc, un, ia, ib, ic, ins = mu.get_samples()
                print(f'  Ua={ua:.0f}V  Ub={ub:.0f}V  Uc={uc:.0f}V  Un={un:.0f}V')
                print(f'  Ia={ia:.0f}A  Ib={ib:.0f}A  Ic={ic:.0f}A  In={ins:.0f}A')

            elif action == 'fault':
                if len(parts) > 1:
                    ft = parts[1]
                    valid_types = ['three_phase', 'single_phase', 'phase_to_phase',
                                   'overcurrent', 'undervoltage', 'overvoltage',
                                   'zero_sequence']
                    if ft in valid_types:
                        mu.fault_active = True
                        mu.fault_type = ft
                        print(f'  触发故障: {ft}')
                        s = mu.get_status()
                        print(f'  smpCnt={s["smp_cnt"]} voltage={s["rated_voltage"]}')
                    else:
                        print(f'  无效故障类型: {ft}')
                        print(f'  可选: {", ".join(valid_types)}')
                else:
                    print('  用法: fault <type>')

            elif action == 'clear':
                mu.fault_active = False
                mu.fault_type = 'none'
                mu.fault_params = {}
                print('  故障已清除')

            elif action == 'synch':
                if len(parts) > 1:
                    try:
                        val = int(parts[1])
                        if val in (0, 1, 2):
                            mu.smp_synch = val
                            label = ['unsync', 'local', 'global'][val]
                            print(f'  smpSynch 已设为 {val} ({label})')
                        else:
                            print('  smpSynch 应为 0, 1 或 2')
                    except ValueError:
                        print('  用法: synch <0|1|2>')
                else:
                    print(f'  当前 smpSynch={mu.smp_synch}')

            elif action == 'harm':
                if len(parts) > 2:
                    try:
                        mu.harmonic_3rd = float(parts[1]) / 100.0
                        mu.harmonic_5th = float(parts[2]) / 100.0
                        print(f'  谐波: 3次={mu.harmonic_3rd*100:.0f}% 5次={mu.harmonic_5th*100:.0f}%')
                    except ValueError:
                        print('  用法: harm <3rd%> <5th%>')
                else:
                    print(f'  当前谐波: 3次={mu.harmonic_3rd*100:.0f}% 5次={mu.harmonic_5th*100:.0f}%')

            elif action == 'auto':
                n = int(parts[1]) if len(parts) > 1 else 80
                print(f'  自动发送 {n} 个 SV 报文...')
                for i in range(n):
                    pkt = mu.build_sv_packet()
                    ua = struct.unpack_from('!f', pkt, 42)[0]
                    if i % 20 == 0:
                        print(f'    #{i+1}: smp={mu.smp_cnt} Ua={ua:.0f}V')
                print(f'  完成: {n} 个报文')

            elif action == 'count':
                if len(parts) > 1:
                    try:
                        mu.smp_cnt = int(parts[1]) % SAMPLE_RATE
                        print(f'  采样计数器已设为 {mu.smp_cnt}')
                    except ValueError:
                        print('  用法: count <N>')
                else:
                    print(f'  当前 smpCnt={mu.smp_cnt}')

            else:
                print(f'  未知命令: {action} (输入 help 查看帮助)')

        except KeyboardInterrupt:
            print('\n[SV] 退出')
            break
        except Exception as e:
            print(f'  [错误] {e}')

    print('[SV] 模拟器已停止')


if __name__ == '__main__':
    run_simulator()
