# SV 协议 (Sampled Values, IEC 61850-9-2)

## 协议信息

| 属性 | 说明 |
|------|------|
| **排名** | 19 |
| **协议名称** | SV (Sampled Values) |
| **主要应用** | 智能变电站采样值传输 |
| **传输层** | 以太网二层 (多播) |
| **EtherType** | 0x88BA |
| **重要性** | ★★★★ |

## 协议简介

SV (Sampled Values) 是 IEC 61850-9-2 标准定义的采样值传输协议，用于将合并单元(MU)采集的电压、电流等模拟量采样值通过以太网传输给保护测控装置。典型配置为 80 采样点/周波 (50Hz 下 4000 采样/秒)。

SV 使用 ASN.1/BER 编码，每个 ASDU 包含 svID、smpCnt、confRev、smpSynch、seqData 等字段。

## 文件说明

| 文件 | 说明 |
|------|------|
| `simulator.py` | SV 协议模拟器 - 模拟合并单元发送采样值 |
| `detector.py` | SV 协议检测逻辑 - 识别和解析 SV 流量 |
| `vuln_simulator.py` | 漏洞模拟器 - 模拟 SV 安全漏洞 |
| `poc.py` | POC 代码 - SV 漏洞利用验证 |
| `README.md` | 本说明文件 |

## 模拟器使用

```bash
python simulator.py
# 交互: fault [mu] [type], clear [mu], status, quit
```

## POC 使用

```bash
# 采样值伪造
python poc.py --vuln spoof

# 重放攻击
python poc.py --vuln replay

# 采样值篡改
python poc.py --vuln manipulate

# 同步攻击
python poc.py --vuln sync

# 全部测试
python poc.py --vuln all
```

## 已知漏洞

| 漏洞 | 严重程度 | 说明 |
|------|----------|------|
| 采样值伪造 | 严重 | 构造虚假采样值影响保护决策 |
| 重放攻击 | 高危 | 重放合法采样值 |
| 采样值篡改 | 严重 | 修改采样值影响故障判断 |
| 同步攻击 | 高危 | 破坏采样同步状态 |
| 拒绝服务 | 高危 | 大量报文导致网络拥塞 |

## POC 验证方法

### 前置条件
1. SV POC 默认在本地模式运行（仅构造报文）
2. 如需实际发送，使用 `--target` 指定目标 IP

### 验证步骤

#### 1. 采样值伪造
```bash
python poc.py --vuln spoof
```
**验证原理**：构造电压 5kV、电流 20kA 的虚假故障采样值（正常为 110kV/300A）。保护装置基于伪造值可能误发跳闸信号。

**预期输出**：
```
[*] POC: SV 采样值伪造
  正常采样: Ua=110000V Ub=-55000V Uc=-55000V  Ia=300A
  伪造故障: Ua=5000V Ia=20000A (过电流故障场景)
  [!] 风险: 保护装置基于伪造采样值可能误发跳闸信号
```

#### 2. 采样值篡改
```bash
python poc.py --vuln manipulate
```
**验证原理**：展示 5 种篡改场景（过电流、低电压、三相不平衡、频率偏移、谐波注入）。

**预期输出**：逐条显示 5 种篡改场景及其对保护装置的影响说明。

#### 3. 同步攻击
```bash
python poc.py --vuln sync
```
**验证原理**：修改 smpSynch 标志（0=未同步，1=本地同步，2=全球同步），smpSynch=0 时 IED 可能丢弃所有采样数据。

**预期输出**：显示 3 种同步状态的报文构造详情。

#### 4. 拒绝服务
```bash
python poc.py --vuln dos --count 500
```
**验证原理**：生成大量 SV 报文，测试网络和 IED 的处理能力。

**预期输出**：
```
[*] POC: SV DoS (500 报文)
  构造 500 个 SV 报文, x.xs (xxxxx pps)
  [!] 风险: 交换机端口过载 / IED 采样处理延迟
```

#### 5. 全扫描
```bash
python poc.py --vuln all
```
**预期输出**：依次执行以上 4 项测试，末尾显示扫描报告。

### 通过标准
- 本地模式下每项测试均输出报文构造细节和攻击影响评估
- 使用 `--target` 实际发送时目标收到有效 SV 报文

### 自动验证
```bash
python run_verify_all.py
```
脚本会自动运行 SV POC 全扫描模式。|
