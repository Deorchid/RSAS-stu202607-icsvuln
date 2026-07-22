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
