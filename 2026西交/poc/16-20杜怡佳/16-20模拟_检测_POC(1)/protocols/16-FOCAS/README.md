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
