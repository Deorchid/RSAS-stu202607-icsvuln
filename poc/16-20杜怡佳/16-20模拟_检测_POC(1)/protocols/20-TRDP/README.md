# TRDP 协议 (Train Real-time Data Protocol)

## 协议信息

| 属性 | 说明 |
|------|------|
| **排名** | 20 |
| **协议名称** | TRDP (Train Real-time Data Protocol) |
| **主要应用** | 轨道交通列车控制网络 (IEC 61375) |
| **传输层** | UDP |
| **默认端口** | 17224 (PD), 17225 (MD) |
| **重要性** | ★★★ |

## 协议简介

TRDP (Train Real-time Data Protocol) 是 IEC 61375 标准定义的列车实时数据协议，用于列车通信网络(TCN, Train Communication Network)中的数据交换。

TRDP 包含两种数据类型：
- **PD (Process Data)**: 实时周期性数据，如速度、制动压力、车门状态、加速度等
- **MD (Message Data)**: 事件驱动的消息数据，如诊断报警、配置信息等

## 文件说明

| 文件 | 说明 |
|------|------|
| `simulator.py` | TRDP 协议模拟器 - 模拟列车控制单元发送 PD/MD 数据 |
| `detector.py` | TRDP 协议检测逻辑 - 识别和分析 TRDP 流量 |
| `vuln_simulator.py` | 漏洞模拟器 - 模拟 TRDP 安全漏洞 |
| `poc.py` | POC 代码 - TRDP 漏洞利用验证 |
| `README.md` | 本说明文件 |

## 模拟器使用

```bash
python simulator.py
# 交互命令: speed [val], brake, doors [open/closed], status, quit
```

## POC 使用

```bash
# PD数据伪造
python poc.py --vuln pd_spoof

# 紧急制动注入
python poc.py --vuln brake_inject

# 车门控制注入
python poc.py --vuln door_inject

# 拒绝服务
python poc.py --vuln dos

# 全部测试
python poc.py --vuln all
```

## 已知漏洞

| 漏洞 | 严重程度 | 说明 |
|------|----------|------|
| PD数据伪造 | 严重 | 构造虚假列车过程数据 |
| 紧急制动注入 | 严重 | 伪造紧急制动信号 |
| 车门控制注入 | 严重 | 伪造车门状态信息 |
| 拒绝服务 | 高危 | 大量报文导致网络拥塞 |
