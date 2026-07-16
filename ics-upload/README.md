# 工控协议检测与分析系统 (16-20)

> RSAS-stu202607-icsvuln — 面向工控安全研究的协议级仿真、检测与漏洞验证框架

> 面向工控安全研究的协议级仿真、检测与漏洞验证框架  
> 覆盖 **FOCAS / ADS / GOOSE / SV / TRDP** 五种工控协议

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-91%2F91%20passing-brightgreen)](test_all.py)

---

## 📋 协议总览

| 排名 | 协议 | 全称 | 行业 | 端口/EtherType |
|:---:|:----|:----|:----|:--------------|
| 16 | **FOCAS** | FANUC Open CNC API | 数控机床 | TCP 8193 |
| 17 | **ADS** | Automation Device Specification | PLC 自动化 | TCP 48898 |
| 18 | **GOOSE** | Generic Object Oriented Substation Events | 智能变电站 | EtherType 0x88B8 |
| 19 | **SV** | Sampled Values (IEC 61850-9-2) | 智能变电站 | EtherType 0x88BA |
| 20 | **TRDP** | Train Real-time Data Protocol (IEC 61375) | 轨道交通 | UDP 17224/17225 |

---

## 🏗️ 项目结构

```
├── main.py                       # CLI 统一入口
├── test_all.py                   # 集成测试 (91 断言)
├── run_verify_all.py             # 全自动验证脚本
├── requirements.txt              # 依赖清单
├── protocols/
│   ├── 16-FOCAS/                 # FANUC CNC 机床协议
│   ├── 17-ADS/                   # Beckhoff TwinCAT PLC 协议
│   ├── 18-GOOSE/                 # IEC 61850 变电站事件协议
│   ├── 19-SV/                    # IEC 61850-9-2 采样值协议
│   └── 20-TRDP/                  # IEC 61375 列车控制协议
└── utils/
    └── common.py                 # 公共工具函数
```

每个协议目录包含 **5 个核心文件**：

| 文件 | 功能 | 说明 |
|:----|:----|:----|
| `simulator.py` | 工控协议模拟器 | TCP/UDP 服务端，模拟真实设备行为 |
| `detector.py` | 工控协议检测逻辑 | 帧解析、协议识别、异常检测 |
| `vuln_simulator.py` | 工控漏洞模拟器 | 常见安全漏洞场景模拟 |
| `poc.py` | POC 验证代码 | 命令行漏洞利用验证工具 |
| `README.md` | 协议说明文档 | 协议信息、使用指南、验证方法 |

---

## 🚀 快速开始

### 安装依赖

```bash
pip install scapy>=2.5.0 pyads>=3.4.0
```

### 运行集成测试

```bash
python test_all.py
```

### 一键全自动验证

```bash
python run_verify_all.py
```
自动启动所有模拟器 → 运行 POC → 验证检测器 → 生成报告。

### CLI 统一入口

```bash
# 列出所有协议
python main.py --list

# 查看协议信息
python main.py --protocol 17

# 运行模拟器
python main.py --run 17 sim

# 运行检测器自测试
python main.py --run 16 detect

# 运行 POC
python main.py --run 18 poc --vuln all
```

---

## 🔍 POC 验证清单

| 协议 | POC 项数 | 覆盖漏洞 |
|:----|:--------:|:--------|
| **16-FOCAS** | 5 | 未授权访问(CVE-2017-16730)、轴数据泄露、状态读取、动态数据、报警信息 |
| **17-ADS** | 4 | 未授权访问、变量读取、WriteControl 状态篡改、DoS |
| **18-GOOSE** | 5 | 报文伪造、重放攻击、stNum篡改、Test标志滥用、StNum泛洪 |
| **19-SV** | 4 | 采样值伪造、篡改、同步攻击、DoS |
| **20-TRDP** | 5 | PD数据伪造、紧急制动注入、车门控制注入、源ID欺骗、重放攻击 |

> 详细验证方法见各协议目录下的 README.md → **POC 验证方法** 章节。

---

## 📊 项目统计

| 指标 | 数值 |
|:----|:----:|
| Python 文件数 | 22 |
| 代码总行数 | ~4600+ |
| 测试断言数 | 91 |
| 测试通过率 | 100% |
| 支持的漏洞类型 | 25+ |
| 检测的异常类型 | 40+ |

---

## 📖 详细文档

- [工控协议检测与分析系统_技术文档.md](工控协议检测与分析系统_技术文档.md) — 技术细节、实现状态、验证报告
- `protocols/*/README.md` — 各协议使用指南与 POC 验证方法

---

## ⚠️ 免责声明

本项目**仅限**工控安全研究、教学和授权渗透测试使用。未经授权将本工具用于非法攻击行为，使用者自行承担法律责任。
