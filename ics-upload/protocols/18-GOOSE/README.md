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

## POC 验证方法

### 前置条件
1. GOOSE POC 默认在本地模式运行（仅构造报文，不实际发送）
2. 如需实际发送，需指定 `--interface` 参数（Linux 需要 root 权限，Windows 需要 Npcap）

### 验证步骤

#### 1. 报文伪造（虚假跳闸）
```bash
python poc.py --vuln spoof
```
**验证原理**：构造 stNum=200、trip=True 的虚假 GOOSE 跳闸报文。GOOSE 无源认证机制，IED 无法区分真假。

**预期输出**：
```
[*] POC: GOOSE 报文伪造
  正常合闸: stNum=100, sqNum=0, trip=False (xxB)
  伪造跳闸: stNum=200, sqNum=0, trip=True (xxB)
  [!] 攻击后果: 断路器误跳导致停电事故
```

#### 2. 重放攻击
```bash
python poc.py --vuln replay
```
**验证原理**：捕获合法 GOOSE 报文后原封不动重放，验证 IED 是否具备重放检测能力。

**预期输出**：
```
[*] POC: GOOSE 重放攻击
  捕获报文: stNum=5, sqNum=10, trip=False (xxB)
  等待 1s...
  重放相同报文 (含原始时间戳)...
  [!] GOOSE 缺乏时间戳校验和重放保护机制
  [!] IED 无法区分原始报文和重放报文
```

#### 3. StNum 泛洪（DoS）
```bash
python poc.py --vuln flood --count 500
```
**验证原理**：生成大量 stNum 递增的 GOOSE 事件，IED 需逐个处理可能导致 CPU 过载。

**预期输出**：
```
[*] POC: GOOSE StNum 泛洪 (500 个状态变更)
  生成 500 个 GOOSE 事件, x.xs (xxxxx pps)
  [!] IED 需逐个处理 stNum 递增, CPU 可能过载
```

#### 4. stNum 篡改
```bash
python poc.py --vuln stnum_tamper
```
**验证原理**：发送异常 stNum 值（0、0xFFFFFFFF、负数），测试 IED stNum 比较逻辑。

**预期输出**：显示 4 种异常 stNum 场景及影响说明。

#### 5. Test 标志滥用
```bash
python poc.py --vuln test_flag
```
**验证原理**：将 test 标志设为 True 发送恶意报文，部分 IED 会忽略 test=True 的跳闸信号。

#### 6. 全扫描
```bash
python poc.py --vuln all
```
**预期输出**：依次执行以上 5 项测试，末尾显示 POC 扫描报告。

### 通过标准
- 本地模式下每项测试均打印报文构造详情和攻击影响说明
- `--interface` 指定网卡后能通过 raw socket 发送

### 自动验证
```bash
python run_verify_all.py
```
脚本会自动运行 GOOSE POC 全扫描模式，验证报文构造功能。|
