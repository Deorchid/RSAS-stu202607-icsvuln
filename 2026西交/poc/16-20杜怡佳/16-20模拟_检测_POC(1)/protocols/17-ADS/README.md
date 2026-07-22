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
