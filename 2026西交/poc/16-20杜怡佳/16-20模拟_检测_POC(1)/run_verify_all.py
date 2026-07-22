"""
全自动验证脚本
=============
启动模拟器 → 运行 POC → 运行漏洞模拟器 → 运行检测器 → 生成报告
"""

import subprocess
import sys
import os
import time
import signal
import re

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(PROJECT_DIR)

results = []
POC_DIR = 'protocols'


def log(msg):
    print(f'\n{"=" * 60}')
    print(f'  {msg}')
    print(f'{"=" * 60}')


def run(cmd, timeout=15, input_text=None):
    """运行命令并返回输出"""
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=PROJECT_DIR, text=True)
        out, _ = proc.communicate(input=input_text, timeout=timeout)
        return out, proc.returncode
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
        return out + '\n[超时]', -1
    except Exception as e:
        return f'[错误] {e}', -1


def start_simulator(pid, name, port, start_pattern, timeout=8):
    """启动模拟器，等待就绪"""
    proc = subprocess.Popen(
        [sys.executable, f'{POC_DIR}/{pid}-{name}/simulator.py'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=PROJECT_DIR, text=True)

    # 等待模拟器就绪
    for _ in range(timeout * 10):
        ret = proc.poll()
        if ret is not None:
            out = proc.stdout.read()
            return None, f'模拟器提前退出 (code={ret})', out

        import select
        import msvcrt
        try:
            import msvcrt
            # Check if there's output
            pass
        except:
            pass

        time.sleep(0.1)
        try:
            line = proc.stdout.readline()
            if start_pattern in line:
                return proc, '就绪', line
        except:
            pass

    # 超时未就绪也返回
    return proc, '可能就绪', ''


def stop_simulator(proc):
    """停止模拟器"""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except:
            proc.kill()


def test_poc(name, cmd):
    """运行 POC 并记录结果"""
    log(f'运行 {name} POC')
    out, code = run(cmd, timeout=30)
    success = '[+]' in out or '[OK]' in out or '通过' in out or '成功' in out
    # 提取关键行
    key_lines = [l.strip() for l in out.split('\n')
                 if any(k in l for k in ['[+]', '[-]', '[!]', '[OK]', '[FAIL]', '结果', '通过'])]
    results.append((name, 'POC', 'PASS' if success else 'FAIL', out[:2000]))
    for l in key_lines[:20]:
        print(f'  {l}')
    return success


def test_detector(name, pid):
    """运行检测器自测试"""
    log(f'运行 {name} 检测器自测试')
    out, code = run([sys.executable, f'{POC_DIR}/{pid}-{name}/detector.py'], timeout=15)
    success = '测试完成' in out or 'PASS' in out or code == 0
    results.append((name, '检测器', 'PASS' if success else 'FAIL', out[:1000]))
    # 显示关键行
    for l in out.split('\n'):
        if '[PASS]' in l or '[FAIL]' in l or 'Test' in l or '置信度' in l or '测试完成' in l or '异常' in l:
            print(f'  {l.strip()}')
    return success


def test_vuln_sim(name, pid):
    """运行漏洞模拟器"""
    log(f'运行 {name} 漏洞模拟器 (本地模式)')
    out = ''

    if name == 'FOCAS':
        out, code = run([sys.executable, f'{POC_DIR}/{pid}-{name}/vuln_simulator.py',
                         '--vuln', 'list'], timeout=15)
    elif name == 'ADS':
        out, code = run([sys.executable, f'{POC_DIR}/{pid}-{name}/vuln_simulator.py',
                         '--target', '127.0.0.1'], timeout=15)
    else:
        out, code = run([sys.executable, f'{POC_DIR}/{pid}-{name}/vuln_simulator.py'],
                        timeout=15)

    # GBK 兼容显示
    lines = out.split('\n')
    key_lines = []
    for l in lines:
        stripped = l.strip()
        if stripped and ('[+]' in stripped or '[OK]' in stripped or
                         '[FAIL]' in stripped or '漏洞' in stripped or
                         'CVE' in stripped):
            key_lines.append(stripped)

    success = '[+]' in out or '[OK]' in out
    results.append((name, '漏洞模拟器', 'PASS' if success else 'FAIL', out[:1000]))
    for l in key_lines[:15]:
        safe = l.encode('ascii', errors='replace').decode('ascii')
        print(f'  {safe}')
    return success


def run_with_simulator(name, pid, port, start_pattern, poc_cmds, vuln_cmds=None):
    """启动模拟器 → 运行 POC → 停止模拟器"""
    log(f'启动 {name} 模拟器 (端口 {port})')

    # 先检查端口是否被占用
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    already_running = False
    try:
        s.connect(('127.0.0.1', port))
        already_running = True
        s.close()
        print(f'  端口 {port} 已有服务运行，跳过启动')
    except:
        pass

    sim_proc = None
    if not already_running:
        sim_proc = subprocess.Popen(
            [sys.executable, f'{POC_DIR}/{pid}-{name}/simulator.py'],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=PROJECT_DIR, text=True)
        time.sleep(1)
        print(f'  模拟器已启动 (PID={sim_proc.pid})')

    # 运行 POC
    for label, cmd in poc_cmds:
        log(f'{name} - {label}')
        out, code = run(cmd, timeout=30)
        success = any(k in out for k in ['[+]', '[OK]', '成功', '通过'])
        key_lines = [l.strip() for l in out.split('\n')
                     if any(k in l for k in ['[+]', '[-]', '成功', '失败', '结果', '通过'])]
        results.append((name, label, 'PASS' if success else 'FAIL', out[:1500]))
        for l in key_lines[:10]:
            safe = l.encode('ascii', errors='replace').decode('ascii')
            print(f'  {safe}')

    # 停止模拟器
    if sim_proc and sim_proc.poll() is None:
        sim_proc.terminate()
        try:
            sim_proc.wait(timeout=3)
        except:
            sim_proc.kill()
        print(f'  模拟器已停止')


# ========== 主流程 ==========
print('''
============================================================
  工控协议检测与分析系统 — 全自动验证
============================================================
''')

# 第1步: ADS (需要模拟器)
run_with_simulator('17-ADS', '17-ADS', 48898, 'ADS', [
    ('未授权访问', [sys.executable, f'{POC_DIR}/17-ADS/poc.py', '--target', '127.0.0.1', '--vuln', 'unauthorized']),
    ('变量读取', [sys.executable, f'{POC_DIR}/17-ADS/poc.py', '--target', '127.0.0.1', '--vuln', 'read']),
])

# 第2步: FOCAS (需要模拟器)
run_with_simulator('16-FOCAS', '16-FOCAS', 8193, 'FOCAS', [
    ('未授权访问', [sys.executable, f'{POC_DIR}/16-FOCAS/poc.py', '--target', '127.0.0.1', '--vuln', 'unauthorized']),
    ('轴数据读取', [sys.executable, f'{POC_DIR}/16-FOCAS/poc.py', '--target', '127.0.0.1', '--vuln', 'axis']),
    ('全扫描', [sys.executable, f'{POC_DIR}/16-FOCAS/poc.py', '--target', '127.0.0.1', '--vuln', 'all']),
])

# 第3步: GOOSE (POC 不需要模拟器)
test_poc('GOOSE', [sys.executable, f'{POC_DIR}/18-GOOSE/poc.py', '--vuln', 'all'])

# 第4步: SV (POC 不需要模拟器)
test_poc('SV', [sys.executable, f'{POC_DIR}/19-SV/poc.py', '--vuln', 'all'])

# 第5步: TRDP (POC 不需要模拟器)
test_poc('TRDP', [sys.executable, f'{POC_DIR}/20-TRDP/poc.py', '--vuln', 'all'])

# 第6步: 漏洞模拟器
for name, pid in [('16-FOCAS', '16-FOCAS'), ('17-ADS', '17-ADS'),
                   ('18-GOOSE', '18-GOOSE'), ('19-SV', '19-SV'),
                   ('20-TRDP', '20-TRDP')]:
    test_vuln_sim(name, pid)

# 第7步: 检测器自测试 (全协议)
test_detector('16-FOCAS', '16-FOCAS')
test_detector('17-ADS', '17-ADS')
test_detector('18-GOOSE', '18-GOOSE')
test_detector('19-SV', '19-SV')
test_detector('20-TRDP', '20-TRDP')

# 第8步: 集成测试
log('集成测试')
out, code = run([sys.executable, 'test_all.py'], timeout=60)
test_pass = '100.0%' in out and '失败:   0' in out
results.append(('集成测试', 'test_all.py', 'PASS' if test_pass else 'FAIL', out[:500]))
last_lines = out.strip().split('\n')[-5:]
for l in last_lines:
    safe = l.encode('ascii', errors='replace').decode('ascii')
    print(f'  {safe}')

# ========== 报告 ==========
print(f'\n\n{"=" * 60}')
print(f'  验 证 报 告')
print(f'{"=" * 60}')
print(f'  {"协议":<15} {"测试项":<20} {"结果":<8}')
print(f'  {"-" * 45}')

pass_count = 0
fail_count = 0
for name, test_type, status, _ in results:
    mark = '[OK]' if status == 'PASS' else '[FAIL]'
    safe_name = name.encode('ascii', errors='replace').decode('ascii')
    safe_test = test_type.encode('ascii', errors='replace').decode('ascii')
    print(f'  {safe_name:<15} {safe_test:<20} {mark}')
    if status == 'PASS':
        pass_count += 1
    else:
        fail_count += 1

print(f'  {"-" * 45}')
print(f'  {"总计":<15} {"":<20} {pass_count}/{pass_count + fail_count} 通过')
print(f'  {"通过率":<15} {"":<20} {pass_count / (pass_count + fail_count) * 100:.1f}%')

if fail_count == 0:
    print(f'\n  [OK] 所有验证通过！')
else:
    print(f'\n  [WARN] {fail_count} 项失败，详情见上')
