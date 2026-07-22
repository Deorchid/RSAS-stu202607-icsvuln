"""
工控协议检测与分析系统
========================
协议 16-20: FOCAS, ADS, GOOSE, SV, TRDP

功能:
  - 工控协议模拟器
  - 工控协议信息检测逻辑
  - 工控漏洞模拟器
  - POC

使用:
  python main.py --list                  # 列出所有可用协议
  python main.py --protocol 16           # 查看协议16信息
  python main.py --run 17 sim            # 运行协议17的模拟器
  python main.py --run 17 detect         # 运行协议17的检测器测试
  python main.py --run 17 vuln           # 运行协议17的漏洞模拟器
  python main.py --run 17 poc            # 运行协议17的 POC
  python main.py --run 19 poc --vuln all # 传递额外参数到目标模块
  python main.py --run all sim           # 运行所有协议的模拟器
"""

import argparse
import sys
import importlib
import os
import subprocess
import signal

PROTOCOLS = {
    16: {
        'name': 'FOCAS',
        'desc': 'FANUC CNC 机床通信协议',
        'port': 'TCP 8193',
        'dir': '16-FOCAS',
    },
    17: {
        'name': 'ADS',
        'desc': 'Beckhoff TwinCAT PLC 通信协议',
        'port': 'TCP 48898',
        'dir': '17-ADS',
    },
    18: {
        'name': 'GOOSE',
        'desc': 'IEC 61850 变电站保护通信协议',
        'port': 'EtherType 0x88B8',
        'dir': '18-GOOSE',
    },
    19: {
        'name': 'SV',
        'desc': 'IEC 61850-9-2 采样值通信协议',
        'port': 'EtherType 0x88BA',
        'dir': '19-SV',
    },
    20: {
        'name': 'TRDP',
        'desc': 'IEC 61375 列车实时数据协议',
        'port': 'UDP 17224/17225',
        'dir': '20-TRDP',
    },
}

ACTIONS = {
    'sim': ('simulator', '模拟器'),
    'detect': ('detector', '检测器'),
    'vuln': ('vuln_simulator', '漏洞模拟器'),
    'poc': ('poc', 'POC'),
}

# 正在运行的子进程 (用于模拟器)
_running_processes = []


def list_protocols():
    """列出所有可用协议"""
    print('=' * 70)
    print('  工控协议检测与分析系统')
    print('  协议 16-20')
    print('=' * 70)
    print(f'{"ID":>4}  {"协议":<12} {"说明":<30} {"端口/类型":<20}')
    print('-' * 70)
    for pid in sorted(PROTOCOLS.keys()):
        info = PROTOCOLS[pid]
        print(f'{pid:>4}  {info["name"]:<12} {info["desc"]:<30} {info["port"]:<20}')
    print('-' * 70)
    print(f'{"可用操作:":>4}  sim(模拟器), detect(检测器), vuln(漏洞模拟器), poc(POC)')
    print()
    print('示例:')
    print('  python main.py --run 17 sim            # 启动 ADS 模拟器')
    print('  python main.py --run 16 detect         # 测试 FOCAS 检测器')
    print('  python main.py --run 18 poc --vuln all # GOOSE POC 全扫描')
    print('  python main.py --run 20 vuln           # TRDP 漏洞模拟')


def show_protocol_info(pid: int):
    """显示指定协议的详细信息"""
    if pid not in PROTOCOLS:
        print(f'错误: 无效协议编号 {pid}')
        return

    info = PROTOCOLS[pid]

    # 统计代码行数
    dir_path = os.path.join(os.path.dirname(__file__), 'protocols', info['dir'])
    total_lines = 0
    file_info = []

    if os.path.exists(dir_path):
        for f in sorted(os.listdir(dir_path)):
            if f.endswith('.py') or f.endswith('.md'):
                fpath = os.path.join(dir_path, f)
                size = os.path.getsize(fpath)
                with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = sum(1 for _ in fh)
                total_lines += lines
                file_info.append((f, lines, size))

    print(f'\n{"=" * 50}')
    print(f'  协议 #{pid}: {info["name"]}')
    print(f'  {info["desc"]}')
    print(f'  端口/类型: {info["port"]}')
    print(f'  目录: protocols/{info["dir"]}')
    print(f'  总行数: {total_lines}')
    print(f'{"=" * 50}')

    if file_info:
        print(f'\n  文件列表:')
        for fname, lines, size in file_info:
            print(f'    {fname:<25} {lines:>5} 行 {size:>7} 字节')

    print(f'\n  支持的操作:')
    for action_key, (module_name, action_label) in ACTIONS.items():
        print(f'    main.py --run {pid} {action_key}  # {action_label}')
    print()


def run_action(pid: int, action: str, extra_args: list):
    """运行指定协议的动作 — 实际执行目标模块"""
    if action not in ACTIONS:
        print(f'错误: 无效操作 "{action}"')
        print(f'可用操作: {", ".join(ACTIONS.keys())}')
        return

    if pid not in PROTOCOLS:
        print(f'错误: 无效协议编号 {pid}')
        return

    info = PROTOCOLS[pid]
    module_name = ACTIONS[action][0]
    action_label = ACTIONS[action][1]

    # 构建模块文件路径
    protocol_dir = os.path.join(os.path.dirname(__file__), 'protocols', info['dir'])
    module_path = os.path.join(protocol_dir, f'{module_name}.py')

    if not os.path.exists(module_path):
        print(f'[错误] 文件不存在: {module_path}')
        return

    print(f'\n[启动] 协议 #{pid} {info["name"]} - {action_label}')
    print(f'[路径] {module_path}')
    print('-' * 50)

    # 使用子进程执行目标模块
    cmd = [sys.executable, module_path] + extra_args

    try:
        if action == 'sim':
            # 模拟器 — 前台运行，Ctrl+C 停止
            print(f'[提示] 按 Ctrl+C 停止模拟器\n')
            proc = subprocess.Popen(cmd)
            _running_processes.append(proc)
            proc.wait()
        else:
            # 检测器/漏洞模拟器/POC — 运行后退出
            proc = subprocess.Popen(cmd)
            _running_processes.append(proc)
            proc.wait()

    except KeyboardInterrupt:
        print(f'\n[停止] {info["name"]} {action_label}')
        for proc in _running_processes:
            if proc.poll() is None:
                proc.terminate()
        _running_processes.clear()
    except Exception as e:
        print(f'[错误] 运行失败: {e}')
    finally:
        # 清理已完成的进程
        for proc in _running_processes[:]:
            if proc.poll() is not None:
                _running_processes.remove(proc)


def main():
    parser = argparse.ArgumentParser(
        description='工控协议检测与分析系统 (协议 16-20)')
    parser.add_argument('--list', action='store_true', help='列出所有协议')
    parser.add_argument('--protocol', type=int, choices=[16, 17, 18, 19, 20],
                        help='显示协议信息')
    parser.add_argument('--run', nargs='+', metavar=('PROTOCOL', 'ACTION'),
                        help='运行操作: main.py --run 16 sim [--vuln ...]')

    # 解析已知参数，其余传递给目标模块
    args, unknown_args = parser.parse_known_args()

    if args.list:
        list_protocols()
    elif args.protocol:
        show_protocol_info(args.protocol)
    elif args.run:
        if len(args.run) < 2:
            print('错误: 需要指定协议和操作')
            print('示例: python main.py --run 16 sim')
            return
        proto_str = args.run[0]
        action = args.run[1]
        extra = args.run[2:] + unknown_args

        if proto_str == 'all':
            for pid in sorted(PROTOCOLS.keys()):
                run_action(pid, action, extra)
        else:
            try:
                pid = int(proto_str)
                run_action(pid, action, extra)
            except ValueError:
                print(f'错误: 无效协议 "{proto_str}"')
    else:
        list_protocols()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n正在停止...')
        for proc in _running_processes:
            if proc.poll() is None:
                proc.terminate()
        sys.exit(0)
