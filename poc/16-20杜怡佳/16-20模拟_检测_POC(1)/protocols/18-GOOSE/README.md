# GOOSE 协议 (Generic Object Oriented Substation Events)

## 协议信息

| 属性 | 说明 |
|------|------|
| **排名** | 18 |
| **协议名称** | GOOSE (IEC 61850) |
| **主要应用** | 智能变电站保护通信 |
| **传输层** | 以太网二层 (多播) |
| **EtherType** | 0x88B8 |
| **重要性** | ★★★★ |

## 协议简介

GOOSE (Generic Object Oriented Substation Events) 是 IEC 61850 标准定义的高可靠性变电站事件通信协议。它使用以太网多播直接在链路层传输，无需 TCP/IP 协议栈。GOOSE 报文包含开关状态、跳闸信号、测量值等保护控制信息。

GOOSE 的核心机制是基于状态编号 (stNum) 和序列编号 (sqNum) 的重发机制：状态变化时 stNum 递增，以最小间隔重复发送；稳态时 sqNum 递增，以最大间隔重复发送。

## 文件说明

| 文件 | 说明 |
|------|------|
| `simulator.py` | GOOSE 协议模拟器 - 模拟 IED 发送 GOOSE 报文 |
| `detector.py` | GOOSE 协议检测逻辑 - 识别和解析 GOOSE 流量 |
| `vuln_simulator.py` | 漏洞模拟器 - 模拟 GOOSE 安全漏洞 |
| `poc.py` | POC 代码 - GOOSE 漏洞利用验证 |
| `README.md` | 本说明文件 |

## 模拟器使用

```bash
python simulator.py
# 交互命令: trip, close, status, quit
```

## 检测器使用

```bash
python detector.py
```

## 漏洞模拟器使用

```bash
python vuln_simulator.py
python vuln_simulator.py --real  # 实际发包模式
```

## POC 使用

```bash
# 报文伪造
python poc.py --vuln spoof

# 重放攻击
python poc.py --vuln replay

# 风暴攻击
python poc.py --vuln storm --events 500

# Test标志位滥用
python poc.py --vuln test_flag

# 全部测试
python poc.py --vuln all
```

## 已知漏洞

| 漏洞 | 严重程度 | 说明 |
|------|----------|------|
| 报文伪造/欺骗 | 严重 | GOOSE 无源认证机制 |
| 重放攻击 | 高危 | 无重放保护 |
| 拒绝服务/GOOSE风暴 | 严重 | 大量报文瘫痪网络 |
| Test标志位滥用 | 中危 | 测试报文可绕过安全检测 |
