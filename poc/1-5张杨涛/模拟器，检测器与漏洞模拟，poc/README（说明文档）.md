# ICS 工业控制系统安全实验室

一个覆盖 **5 种主流工控协议**的综合安全测试平台。每个协议都包含：

- **设备模拟器** — 逼真模拟 PLC/RTU 等工控设备的行为
- **漏洞模拟器** — 故意暴露已知漏洞的设备，作为攻击训练的靶标
- **威胁检测器** — 实时监控并告警异常行为
- **PoC 攻击脚本** — 从单步测试到多阶段攻击链的完整验证工具

全部使用 Python 标准库实现，**无需安装任何第三方依赖**。

---

## 五种协议概览

### 1. Modbus TCP（端口 502）

工控领域最通用的协议，广泛应用于 PLC、RTU 和传感器。

| 能力 | 说明 |
|------|------|
| 功能码 | 支持 19 个功能码（读写线圈/寄存器、诊断、文件操作、设备识别等） |
| 诊断 | 17 个子诊断功能（计数器清除、强制监听模式等） |
| 梯形逻辑 | 4 个梯级，5 种触点类型（常开/常闭/上升沿/下降沿），2 种定时器（TON/TOFF） |
| 扫描周期 | 50ms，模拟真实 PLC 的循环执行 |
| 异常状态 | 8 位状态字（内存故障/IO故障/通信故障/看门狗超时等） |
| 漏洞模式 | **14 种**（安全链绕过、写洪水、异常抑制、内存腐蚀、身份伪造、广播风暴、硬编码密码泄露等） |

### 2. OPC UA（端口 4840）

现代化的工业通信协议，广泛用于 SCADA 和 MES 系统。

| 能力 | 说明 |
|------|------|
| 消息类型 | 6 种（HEL 握手 / OPN 开通道 / CLO 关通道 / MSG 消息 / ACK 确认 / ERR 错误） |
| 节点空间 | 3 个命名空间，41 个节点（传感器、执行器、告警、诊断、配置） |
| 会话管理 | 最大 50 会话，1 小时超时自动清理 |
| 浏览/订阅 | 支持带续传点的层级浏览，完整订阅引擎（创建订阅 → 监控项 → 发布） |
| 数据类型 | 15 种内置类型（布尔、整型、浮点、字符串、时间戳、GUID 等） |
| 漏洞模式 | **8 种**（免认证访问、安全策略绕过、无限会话、任意节点写入、诊断泄露、证书绕过、可预测令牌等） |

### 3. S7COMM（端口 102）

西门子 S7 系列 PLC 的私有协议，全球工业自动化部署量极大。

| 能力 | 说明 |
|------|------|
| 传输层 | 完整 COTP 连接管理（连接请求 CR / 连接确认 CC / 数据传输 DT / 快速数据 ED/SR） |
| CPU 状态 | 4 种状态（STOP / RUN / STARTUP / HOLD），带自动状态转换 |
| 数据块 | 10 个 DB（128~8192 字节），4 个预置程序块（OB1/OB100/FB1/FC1） |
| 定时器/计数器 | 各 256 个，随扫描周期自动更新 |
| 扫描周期 | 100ms，模拟完整的 OB1 执行流程（PII → OB1 → PIQ → 定时器 → 循环数据） |
| 7 个数据区 | PE（输入映像）/ PA（输出映像）/ MK（位存储）/ DB / DI / LB / LD |
| 12 个 S7 功能 | Setup / Read / Write / Control / Block 操作 / SZL 系统读取 / 时钟 / 密码等 |
| 漏洞模式 | **13 种**（保护级别绕过、任意密码接受、后门密码、弱密码、程序块注入、诊断抑制、伪造 CPU 状态、过程映像劫持等） |

### 4. EtherNet/IP（端口 44818）

ODVA 开放标准，支持实时 I/O 和显式消息（CIP），在 Rockwell/Allen-Bradley 生态中占主流。

| 能力 | 说明 |
|------|------|
| ENCAP 命令 | 8 种（ListIdentity / ListServices / RegisterSession / SendRRData / SendUnitData 等） |
| CIP 路由 | 通过 SendRRData 封装 CIP 显式消息 |
| 对象模型 | 8 个 CIP 类（Identity / Assembly / Connection / TCP/IP / Ethernet Link 等） |
| 连接管理 | 5 状态机（空 / 配置中 / 等待 / 已建立 / 超时），60s 会话超时 |
| 装配对象 | 输入装配 100 字节 + 输出装配 100 字节，含循环更新的传感器数据 |
| 扫描周期 | 10ms，模拟状态字/计数器/温度/压力等动态字段 |
| 漏洞模式 | **11 种**（免认证注册、无连接限制、无电子密钥验证、装配数据泄露、身份泄露、会话劫持、未保护写入等） |

### 5. CIP（端口 44819）

通用工业协议，可在 TCP 上独立运行（UCMM + 已连接模式），EtherNet/IP 的核心。

| 能力 | 说明 |
|------|------|
| CIP 服务 | 14 种（获取/设置属性、ForwardOpen/Close、Reset/Stop、Create/Delete、MultipleService） |
| 对象类 | 11 个（Identity / MessageRouter / Assembly / Connection / AnalogInput 等），共 14+ 个实例 |
| 双模式 | UCMM（无连接） + Connected（已连接），支持序列号校验 |
| 路径解析 | 7 种段类型（逻辑类/实例/属性段、电子密钥段、符号段、端口段） |
| 连接状态机 | 5 状态，30s 超时自动清理 |
| 漏洞模式 | **9 种 CWE**（CWE-306 缺认证、CWE-862 电子键绕过、CWE-22 路径穿越、CWE-400 无连接限制、CWE-404 不当关停、CWE-416 Use-After-Free、CWE-787 内存耗尽、CWE-20 弱序列号等） |

---

## 目录结构

```
├── Modbus/                  # Modbus TCP
│   ├── simulator.py         #   正常设备模拟器
│   ├── vuln_simulator.py    #   漏洞靶标（14种漏洞模式）
│   ├── detector.py          #   威胁检测引擎
│   └── poc/                 #   攻击脚本
│       ├── advanced_attack.py   # 6阶段完整攻击链
│       ├── device_id.py         # 设备指纹识别（FC43）
│       ├── function_scan.py     # 功能码扫描（19个）
│       ├── scan_coils.py        # 线圈批量读取（FC1）
│       └── write_register.py    # 单寄存器写入（FC6）
├── OPCUA/                   # OPC UA
│   ├── simulator.py
│   ├── vuln_simulator.py    #   漏洞靶标（8种漏洞模式）
│   ├── detector.py
│   └── poc/
│       ├── advanced_attack.py   # 6阶段（握手→会话→浏览→读→写→订阅）
│       └── enumerate_endpoints.py  # 端点探测
├── S7COMM/                  # Siemens S7
│   ├── simulator.py
│   ├── vuln_simulator.py    #   漏洞靶标（13种漏洞模式）
│   ├── detector.py
│   └── poc/
│       ├── advanced_attack.py   # 5阶段（COTP→状态→DB读→DB写→STOP）
│       ├── plc_stop.py          # 远程STOP命令
│       └── read_db.py           # 数据块无认证读取
├── EtherNetIP/              # EtherNet/IP + CIP
│   ├── simulator.py
│   ├── vuln_simulator.py    #   漏洞靶标（11种漏洞模式）
│   ├── detector.py
│   └── poc/
│       ├── advanced_attack.py   # 6阶段（指纹→服务→连接→装配→写入→关闭）
│       └── list_identity.py     # 设备发现
├── CIP/                     # 独立 CIP
│   ├── simulator.py
│   ├── vuln_simulator.py    #   漏洞靶标（9种CWE）
│   ├── detector.py
│   └── poc/
│       ├── advanced_attack.py   # 7阶段完整攻击链
│       ├── cip_enum.py          # 对象枚举
│       └── cip_stop.py          # Stop + Reset
├── README.md                # 本说明文档
└── .gitignore
```

---

## 快速开始

**环境要求：** Python 3.7 或更高版本（仅需标准库，无需 pip install 任何包）

### 基本用法（以 Modbus 为例）

打开 **3 个终端窗口**，依次执行：

```bash
# 终端 1 — 启动漏洞靶标
cd Modbus
python vuln_simulator.py

# 终端 2 — 运行攻击脚本
cd Modbus\poc
python advanced_attack.py 127.0.0.1 502

# 终端 3 — 运行检测器看告警
cd Modbus
python detector.py
```

其他四个协议的操作完全一样，只需要把目录名和端口号替换即可：

| 协议 | 目录 | 端口 |
|------|------|------|
| OPC UA | `OPCUA` | 4840 |
| S7COMM | `S7COMM` | 102 |
| EtherNet/IP | `EtherNetIP` | 44818 |
| CIP | `CIP` | 44819 |

### 单步 PoC 测试

每个协议的 `poc/` 目录下除了完整的 `advanced_attack.py` 攻击链外，还提供了**单步测试脚本**，方便验证特定功能：

```bash
# Modbus — 设备指纹识别
python Modbus\poc\device_id.py 127.0.0.1

# Modbus — 扫描支持的功能码
python Modbus\poc\function_scan.py 127.0.0.1

# Modbus — 无认证写入寄存器
python Modbus\poc\write_register.py 127.0.0.1 0x2000 1234

# S7COMM — 无认证读取 DB
python S7COMM\poc\read_db.py 127.0.0.1 1 0 64

# S7COMM — 远程 PLC 停机
python S7COMM\poc\plc_stop.py 127.0.0.1

# EtherNet/IP — 设备发现
python EtherNetIP\poc\list_identity.py 127.0.0.1

# CIP — 对象枚举
python CIP\poc\cip_enum.py 127.0.0.1

# CIP — 远程停止/复位设备
python CIP\poc\cip_stop.py 127.0.0.1

# OPC UA — 端点探测
python OPCUA\poc\enumerate_endpoints.py 127.0.0.1
```

---

## 攻击链详解

### Modbus — 6 阶段攻击

```
阶段1: 设备指纹识别 (FC43)            → 获取厂商/型号/版本/序列号
阶段2: 功能码扫描 (19个功能码全部探测) → 绘制目标功能码地图，记录响应时间
阶段3: 内存映射 (线圈+离散输入+寄存器)  → 读取全部可寻址数据空间
阶段4: 关键寄存器写入 (安全链/急停/看门狗) → 写入安全关键地址，破坏保护机制
阶段5: 诊断洪水 (50条诊断命令)          → 清除攻击痕迹，淹没审计日志
阶段6: 覆写验证 (回读关键地址)           → 确认攻击生效，输出验证报告
```

**成功标志：** 终输出 `ATTACK COMPLETE` 并显示总耗时。

### OPC UA — 6 阶段攻击

```
阶段1: Hello 握手 + GetEndpoints        → 完成协议握手，发现服务端点
阶段2: CreateSession + ActivateSession  → 免认证建立会话，激活会话令牌
阶段3: Browse 浏览服务器命名空间         → 递归遍历所有节点，统计文件夹/对象/变量数量
阶段4: Read 读取全部变量                 → 批量读取所有已发现的变量当前值
阶段5: Write 写入指定节点                → 无 ACL 校验写入 SetPoint = 99.9，回读验证
阶段6: Subscribe 订阅 + 接收通知         → 创建订阅和监控项，轮询 Publish 接收数据变化
```

**成功标志：** 输出 `=== Attack sequence complete ===`。

### S7COMM — 5 阶段攻击

```
阶段1: COTP 连接 + S7 Setup             → 建立传输连接，协商 PDU 长度
阶段2: 读取 CPU 状态 + 诊断缓冲区       → 通过 SZL 获取 CPU 状态字和最近故障记录
阶段3: 读取 DB1                         → 无认证读取数据块，结构化解析温度/设定值/压力
阶段4: 写入 DB1                         → 注入新设定值 99.9 到 DB1[0]，读取验证
阶段5: 发送 STOP 命令 + 事后验证         → 远程停止 PLC，重新读取诊断缓冲区和状态字
```

**成功标志：** 输出 `Attack Complete`。

### EtherNet/IP — 6 阶段攻击

```
阶段1: ListIdentity                     → 获取设备身份（厂商/产品/版本/序列号/状态）
阶段2: ListServices                     → 发现设备支持的全部服务类型
阶段3: RegisterSession + ForwardOpen    → 注册会话，建立 Class 1 I/O 连接（免电子键验证）
阶段4: GetAttributeSingle 读取装配数据  → 解析 I/O 状态字/计数器/温度/压力等实时数据
阶段5: SetAttributeSingle 修改 Identity → 尝试覆盖固件名称为 "PWNED"
阶段6: ForwardClose + UnregisterSession → 清理连接，注销会话
```

**成功标志：** 每个阶段输出 `[+]` 或 `SUCCESS`。

### CIP — 7 阶段攻击

```
阶段1: GetAttributeAll 指纹识别         → 读取 Identity 对象，获取厂商/设备类型/版本/序列号
阶段2: GetAttributeSingle 读取装配      → 读取 Assembly 对象输出数据（状态/计数器/传感器值）
阶段3: ForwardOpen 建立连接             → 自定义 RPI=5000 建立 I/O 连接
阶段4: SetAttributeSingle 写入模拟输出   → 注入 999.9 到 AnalogOutputPoint（无认证）
阶段5: 符号段读取 "LoopGain"            → 通过 ANSI 符号名查找并读取参数对象
阶段6: Reset + Stop                     → 无认证执行设备复位和停机
阶段7: ForwardClose + 设备状态验证       → 关闭连接，确认设备已进入停止状态
```

**成功标志：** 7 个阶段全部完成，输出最终设备状态。

---

## 检测器使用说明

每个协议的 `detector.py` 是一个**独立的威胁检测引擎**，不依赖模拟器：

- 它会分析流量/日志中的异常模式
- 输出分级告警：`[INFO]` / `[HIGH]` / `[CRITICAL]`
- 检测示例：未认证写入、功能码扫描、会话洪水、电子键绕过、异常 STOP 命令等

```bash
# 在任意协议目录下运行
python detector.py
```

---

## 漏洞模式汇总

所有漏洞模拟器默认**全部漏洞已激活**，启动时会在日志中输出黄色 `[WARNING]` 提示。

| 漏洞类型 | Modbus | OPC UA | S7COMM | EIP | CIP |
|----------|:------:|:------:|:------:|:---:|:---:|
| 缺认证 / 任意访问 | ✓ | ✓ | ✓ | ✓ | ✓ |
| 权限绕过 | ✓ | ✓ | ✓ |   | ✓ |
| 无速率/连接限制 | ✓ | ✓ |   | ✓ | ✓ |
| 硬编码/弱凭证 | ✓ |   | ✓ |   |   |
| 内存腐蚀/越界写 | ✓ |   | ✓ |   | ✓ |
| 日志/审计清除 | ✓ |   | ✓ |   |   |
| DoS 资源耗尽 | ✓ | ✓ |   | ✓ |   |
| 身份伪造/设备欺骗 | ✓ | ✓ | ✓ | ✓ |   |
| 不安全状态转换 | ✓ |   | ✓ |   | ✓ |
| Use-After-Free |   |   |   |   | ✓ |
| 路径穿越 |   |   |   |   | ✓ |

---

## 注意事项

- 所有模拟器仅用于**本地安全研究和教育培训**，请勿对未授权设备使用
- 脚本默认连接 `127.0.0.1`（本机回环），不产生任何外部流量
- Windows 上建议串行测试（先停上一个再启下一个），避免端口残余占用
- `function_scan.py` 和 `advanced_attack.py` 会产生大量模拟器日志输出，属于正常现象
