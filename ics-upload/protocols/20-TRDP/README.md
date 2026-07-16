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

## POC 验证方法

### 前置条件
1. TRDP POC 默认在本地模式运行（仅构造报文）
2. 如需实际发送，使用 `--target` 指定目标 IP，报文通过 UDP 17224 端口发送

### 验证步骤

#### 1. 紧急制动注入
```bash
python poc.py --vuln brake_inject
```
**验证原理**：构造 ComId=0x000A(EmergencyBrake)=1、Speed=0、BrakePressure=900kPa 的伪造报文，冒充 VCU（源ID=3）发送紧急制动指令。

**预期输出**：
```
[*] POC: TRDP 紧急制动注入
  源ID=3 (伪装VCU)
  紧急制动=True, 速度=0km/h, 制动压力=900kPa
  [!] 攻击后果: 伪造紧急制动可导致全列车急停
```
同时打印报文完整十六进制转储（40 字节头 + 负载）。

#### 2. PD 数据伪造
```bash
python poc.py --vuln pd_spoof
```
**验证原理**：伪造列车运行状态（Speed=0/Brake=900kPa），控制系统基于虚假数据可能发出危险指令。

**预期输出**：
```
[*] POC: TRDP PD 数据伪造
  正常状态报文: speed=60km/h brake=200kPa door=closed
  伪造状态报文: speed=0km/h brake=900kPa emergency=True
```

#### 3. 车门控制注入
```bash
python poc.py --vuln door_inject
```
**验证原理**：冒充 DCU（车门控制单元，源ID=4）发送 DoorStatus 状态信号，演示开关状态切换。

**预期输出**：显示 3 次车门状态切换（关闭→开启→关闭）的报文详情。

#### 4. 源 ID 欺骗
```bash
python poc.py --vuln source_spoof
```
**验证原理**：分别伪装 4 种车辆单元（VCU/TCU/BCU/DCU）发送数据，验证协议是否校验源身份。

**预期输出**：显示 4 种不同源 ID 的报文构造详情。

#### 5. 重放攻击
```bash
python poc.py --vuln replay
```
**验证原理**：捕获合法 TRDP 报文后原封不动重放，验证 IED 是否具备重放检测能力。

**预期输出**：
```
[*] POC: TRDP 重放攻击
  原始报文 (t=0): src_id=1, seq=100, val=75.0km/h
  重放相同报文 (t=1s 后)...
  [!] 由于无时间戳校验/加密, IED 无法区分重放
```

#### 6. 全扫描
```bash
python poc.py --vuln all
```
**预期输出**：依次执行以上 5 项测试，末尾显示扫描报告。

### 通过标准
- 本地模式下每项测试均输出报文构造详情和威胁评估
- 使用 `--target` 实际发送时目标 UDP 17224 端口收到有效 TRDP 报文
- 检测器能正确识别 POC 构造的 TRDP 报文（调用 `detector.py` 验证）

### 自动验证
```bash
python run_verify_all.py
```
脚本会自动运行 TRDP POC 全扫描模式。|
