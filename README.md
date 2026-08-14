# 天宏安全防御 TianHong Security Defense

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11%20x64-blue)]()
[![Qt](https://img.shields.io/badge/Qt-6.9.2-green)]()
[![C++](https://img.shields.io/badge/C%2B%2B-C%2B%2B20-blue)]()

一款基于内核驱动 + 用户态挂钩 + 启发式分析的 Windows 安全防护系统。

> **⚠️ 免责声明 / Disclaimer**
>
> 本程序及其衍生程序均仅供**技术交流与学术研究**使用。作者不对程序的安全性、稳定性、适用性做任何明示或暗示的保证，包括但不限于适销性、特定用途适用性和非侵权性的保证。
>
> **严禁在实体机（Physical Machine）上运行本程序**。内核驱动级别的挂钩、过滤和进程干预操作可能导致系统蓝屏、数据丢失或不可恢复的系统损坏。请使用虚拟机（VMware / VirtualBox / Hyper-V 等）在隔离环境中进行测试。
>
> 使用者自行承担使用本程序的一切风险。作者不对任何直接、间接、偶然、特殊或后果性的损害承担责任。

---

## 目录

- [架构概述](#架构概述)
- [核心功能](#核心功能)
- [项目结构](#项目结构)
- [技术实现](#技术实现)
- [构建与运行](#构建与运行)
- [安全须知](#安全须知)
- [第三方组件](#第三方组件)
- [开源协议](#开源协议)

---

## 架构概述

```
┌─────────────────────────────────────────────────────────┐
│         天宏安全防御主程序 (TianHong-Security-Defense)      │
│                    Qt 6 GUI 界面                         │
└──────────────────┬──────────────────────────────────────┘
                   │ IPC (本地回环 Socket 通信)
    ┌──────────────┼──────────────┬──────────────────────┐
    ▼              ▼              ▼                      │
┌────────┐  ┌─────────────┐  ┌──────────────┐          │
│内核驱动 │  │ TianHong    │  │ TianHong     │          │
│(R0)    │  │ Defense DLL │  │ Injector     │          │
│        │  │ (API Hook)  │  │ (R3 辅助)    │          │
└───┬────┘  └──────┬──────┘  └──────┬───────┘          │
    │              │               │                    │
    │              │               │                    │
    ▼              ▼               ▼                    │
┌──────────────────────────────────────────────────────┐ │
│                内核防护模块 (R0)                        │ │
│  ┌──────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐  │ │
│  │行为分析    │ │HIPS规则   │ │注入防护   │ │文件系统  │  │ │
│  │引擎       │ │引擎      │ │三层防护   │ │过滤驱动  │  │ │
│  └──────────┘ └─────────┘ └─────────┘ └──────────┘  │ │
│  ┌──────────┐ ┌─────────┐ ┌────────────────────────┐ │ │
│  │注册表防护  │ │磁盘过滤  │ │网络过滤                │ │ │
│  │          │ │(MBR保护) │ │(WFP Callout)           │ │ │
│  └──────────┘ └─────────┘ └────────────────────────┘ │ │
└──────────────────────────────────────────────────────┘ │
```

### 三层防护架构

| 层级 | 名称 | 说明 |
|------|------|------|
| **R3** | 用户态挂钩层 | 注入到目标进程，拦截 NtCreateUserProcess 等 API，通过 DLL 通信控制 |
| **R0** | 内核防护层 | 驱动级行为分析、HIPS 规则引擎、文件/注册表/网络过滤 |
| **扫描层** | 静态检测层 | YARA 规则 + ClamAV 引擎 + LightGBM 机器学习模型 |

---

## 核心功能

### 1. 内核行为分析引擎 (BehaviorAnalysis)

- **实时采集**：通过定时器（500ms 间隔）收集所有活跃 PID 的行为数据
- **指标体系**：内存操作、进程创建、网络连接、文件操作、注册表变更、COM 调用、ETW 事件等
- **威胁评分**：基于加权指标评分，达到阈值后挂起进程并请求用户决策
- **行为链检测**：识别进程空心化 (Process Hollowing)、远程线程注入、代码注入等高级攻击手法
- **动态规则**：支持 TOML 格式的动态规则加载，无需重新编译驱动

### 2. HIPS 主机入侵防御系统 (Host Intrusion Prevention System)

- **规则引擎**：基于 TOML 配置文件定义规则，支持文件、注册表、网络、进程四类规则
- **意图判断**：根据 DesiredAccess 和 CreateDisposition 判断真实操作意图（写/删/重命名）
- **用户决策**：匹配规则后弹出 MessageBox 等待用户 Allow/Block 决策（30秒超时）
- **决策缓存**：同一进程+请求的决策缓存 5 分钟，避免重复弹窗
- **热更新**：支持运行时添加/删除/清除规则

### 3. 注入防护 (Injection Protection)

**三层防护架构：**

| 层级 | 技术 | 作用 |
|------|------|------|
| 句柄层 | ObRegisterCallbacks | 拦截 OpenProcess/OpenThread，剥离注入权限 |
| 线程层 | PsSetCreateThreadNotifyRoutine | 检测到 CreateRemoteThread/NtCreateThreadEx 时立即挂起 |
| 行为层 | BehaviorAnalysis | 异步工作项处理注入告警，等待用户决策 |

**支持的注入手法检测：**
- CreateRemoteThread / NtCreateThreadEx 远程线程创建
- 线程池注入 (Thread Pool)
- APC 注入
- 进程空心化 (Process Hollowing)
- PoolParty 系列注入检测

### 4. 脚本沙箱 (Script Sandbox)

对 JS/VBS/HTA/PS1/BAT 等脚本进行**行为分析**，无需执行脚本：

- **内容指纹检测**：RC4/Base64 加壳、JSON 数据加载器、西里尔字母替换密码
- **行为链检测**：模拟解释脚本行为，识别下载器、凭证窃取、持久化等恶意行为
- **递归深度限制**：防止栈溢出（64 层上限）
- **UTF-16LE 支持**：正确处理 PowerShell 脚本编码
- **文件大小保护**：超过 20MB 的文件跳过分析，防止 OOM

### 5. 静态特征扫描

| 引擎 | 用途 | License |
|------|------|---------|
| **YARA** | 恶意软件签名匹配 | Apache 2.0 / BSD-3 |
| **ClamAV** | 商业病毒库扫描（动态加载 DLL） | GPL-2.0+ |
| **LightGBM** | PE 文件机器学习分类 | MIT |

### 6. MBR/磁盘保护 (Disk Filter Driver)

- 独立的 WDM 磁盘过滤驱动，附加到所有物理磁盘设备栈
- 拦截对启动区域（扇区 0-62，31KB）的写入，保护 MBR 和 DBR
- 通过 IOCTL 轮询机制与客户端通信告警

### 7. 网络过滤驱动 (Network Filter Driver)

- 基于 Windows Filtering Platform (WFP) Callout
- 拦截 DNS/DOH 查询，防止 C2 通信
- 支持动态规则同步

---

## 项目结构

```
TianHong-Security-Defense/
├── TianHong-Security-Defense/        # 主 GUI 程序 (Qt 6)
│   ├── main.cpp                      # 入口、线程管理、通信
│   ├── PublicFunction.cpp             # 公共函数（进程路径、文件操作等）
│   ├── Sandbox.cpp                    # 脚本沙盒行为分析
│   ├── BatchScan.h                    # 批量扫描 + 家族分类器
│   ├── PEScan.h                       # PE 扫描 + LightGBM 分类器
│   ├── VirusScanPage.cpp/.h          # 病毒扫描页面
│   ├── ElaWidgetTools/               # Qt 扩展组件库
│   ├── include/                      # 第三方头文件
│   │   ├── libyara/                  # YARA 引擎头文件
│   │   ├── libarchive/               # libarchive 头文件
│   │   └── LightGBM/                 # LightGBM C API
│   └── ClamAV/clamav-main/           # ClamAV 源码（本地自行获取，详见构建说明）
│
├── TianHongDefense/                  # R3 API 挂钩 DLL
│   ├── dllmain.cpp                   # DLL 入口、Detours 钩子
│   └── detours.h                     # Microsoft Detours 头文件
│
├── TianHongInjector32/               # R3 进程注入工具
│   └── main.cpp                      # 远程线程注入实现
│
├── TianHongScanner/                  # 独立 PE 扫描引擎
│   └── main.cpp                      # 命令行扫描工具
│
├── TianHongDefenseKernelProtection/  # R0 内核驱动 (主驱动)
│   ├── kernel/                       # 内核代码
│   │   ├── BehaviorAnalysis.h/.c     # 行为分析引擎
│   │   ├── FileFilter.h/.c           # 文件系统过滤
│   │   ├── RegistryCallback.h/.c     # 注册表回调
│   │   ├── ProcessCallback.h/.c      # 进程回调
│   │   ├── KernelRuleEngine.h/.c     # 内核规则引擎
│   │   └── ResponseSystem.h/.c       # 响应系统（挂起/终止进程）
│   └── shared/                       # 共享定义
│       ├── Common.h                  # IOCTL 码、数据结构
│       ├── Event.h                   # 事件类型
│       └── Ioctl.h                   # IOCTL 接口
│
├── TianHongDefenseKernelProtection.Disk/  # R0 磁盘过滤驱动 (MBR 保护)
│   ├── Main_disk.c                   # 驱动入口
│   ├── FileFilter_disk.c             # 磁盘过滤逻辑
│   └── shared/                       # 共享定义（副本）
│
├── TianHongDefenseKernelProtection.Network/  # R0 网络过滤驱动
│   └── kernel/
│       └── WfpCallout.h              # WFP Callout 实现
│
├── TianHongDefenseKernelProtectionClient/  # 驱动控制客户端
│   └── client/
│       ├── ServiceMain.cpp           # 服务主逻辑、驱动安装
│       ├── Comm.cpp                  # 通信层
│       └── DynamicRuleLoader.cpp     # 动态规则加载
│
├── LICENSE                           # MIT License
├── README.md                         # 本文件
├── THIRD-PARTY-LICENSES.md           # 第三方 License 汇总
└── .gitignore                        # Git 忽略规则
```

---

## 技术实现

### 驱动模块

| 模块 | 类型 | 技术 |
|------|------|------|
| 主驱动 | Filter Manager (filesys) | 非分页内存过滤、进程/线程/注册表回调 |
| 磁盘驱动 | WDM 磁盘过滤 | 物理磁盘附加、MBR 扇区拦截 |
| 网络驱动 | WFP Callout | 网络数据包过滤、DNS 拦截 |
| R3 DLL | 用户态挂钩 | Microsoft Detours API 拦截 |

### 通信协议

主程序与驱动客户端通过本地回环 Socket 通信，支持以下消息类型：

```
COMMAND / RESULT / HEARTBEAT / QUIT / READY / LOG / ALERT
ALERT_RESPONSE / PROCESS_CHECK / PROCESS_CHECK_RESP
```

### 内核安全设计

- **堆分配大结构体**：内核栈空间有限（~12-24KB），大型数组使用 `ExAllocatePool2`
- **RAII 颜色恢复**：控制台输出使用 `ColorGuard` 确保退出时恢复原始颜色
- **SEH 异常保护**：关键回调函数用 `__try/__except` 包裹，防止蓝屏
- **PID 去重**：行为分析按 PID 去重，防止同一进程重复告警
- **进程树管理**：检测到威胁时挂起根进程及其所有子孙进程

---

## 构建与运行

### 环境要求

| 项目 | 版本 |
|------|------|
| 操作系统 | Windows 10/11 (x64) |
| 编译器 | MSVC v145 (Visual Studio 2022 Community) 或 mingw |
| Qt | 6.9.2 (mingw_64) |
| Windows SDK | 10.0.28000.0+ |
| ClamAV 源码 | 需自行获取（见下方说明） |
| 测试签名 | 必须开启 (`bcdedit /set testsigning on`) |

### 获取 ClamAV 源码

本项目通过 `LoadLibrary` 动态加载 `libclamav.dll` 使用 ClamAV 引擎，**但编译时需要 ClamAV 头文件**。开源仓库已排除 ClamAV 源码目录，请在本地按以下步骤准备：

1. 从 [ClamAV 官方仓库](https://github.com/Cisco-Talos/clamav) 下载对应版本的源码
2. 解压至 `TianHong-Security-Defense/TianHong-Security-Defense/ClamAV/clamav-main/`
3. 确保目录结构为 `ClamAV/clamav-main/libclamav/clamav.h`（与 `.gitignore` 规则匹配）

> ClamAV 采用 GPL-2.0+ 许可，本程序通过动态加载方式（`LoadLibrary`）使用，不构成 GPL 传染性。

### 构建步骤

> ⚠️ **重要：Win32 与 x64 构建需分开进行**
>
> `TianHongInjector32`（R3 进程注入工具）必须使用 **Win32 (x86)** 平台构建，其余驱动和主程序使用 **x64** 平台。**两者无法在同一平台下同时生成**。

1. 以管理员身份打开 Visual Studio
2. 打开 `TianHong-Security-Defense.sln`
3. **第一次构建（x64）**：选择 `Release|x64` 配置，依次构建：
   - `TianHongDefenseKernelProtection` (主驱动)
   - `TianHongDefenseKernelProtection.Disk` (磁盘驱动)
   - `TianHongDefenseKernelProtection.Network` (网络驱动)
   - `TianHongDefenseKernelProtectionClient` (驱动客户端)
   - `TianHongDefense` (R3 挂钩 DLL - x64)
   - `TianHong-Security-Defense` (主程序)
4. **第二次构建（Win32）**：切换配置为 `Release|Win32`，依次构建：
   - `TianHongDefense` (R3 挂钩 DLL - Win32)
   - `TianHongInjector32` (R3 进程注入工具)

> **说明**：每次切换平台后，需要重新构建受影响的子项目。

### 资源文件说明

程序运行依赖 `Resources\DataBase\` 目录下的规则文件和模型文件，可通过替换以下文件来自定义行为：

| 文件 | 用途 | 可配置方式 |
|------|------|-----------|
| `Malware.yarac` / `MalwareMemory.yarac` | YARA 恶意软件签名库（编译版） | 替换为自定义 `.yarac` 文件，或改为 `.yara` 源码文件（需同时设置 `IS_LOAD_YARAC` 为 `FALSE`） |
| `Heur.data`（及 `.base`、`.extra` 配套文件） | LightGBM PE 行为分析模型 | 训练新模型后替换整组文件 |
| `ClamAVDataBase\` | ClamAV 病毒库（目录） | 通过 `freshclam` 更新，或直接替换整个目录 |

> `Resources\BinaryFiles\` 目录下的其他文件（如 `TianHongDefense32/64.dll`、`TianHongInjector32.exe` 等）为程序运行时必需组件，请勿随意删除。

### 外部依赖 DLL

程序还需要以下外部 DLL（MSVC 运行时、Qt、第三方库等），这些文件**不会由编译步骤自动生成**，需从根目录的 `ExternalBinaries\` 文件夹手动复制到程序输出目录（与 `TianHong-Security-Defense.exe` 同级）：

```powershell
xcopy /E /I /Y "ExternalBinaries\*" "x64\Release\"
```

> **⚠️ 免责声明**：`ExternalBinaries\` 下的所有 PE 文件（.dll、.exe）均来自第三方开源项目或系统组件，仅供本项目运行时依赖使用。作者不对这些文件的来源安全性、无毒状态做任何保证，使用者应自行评估风险，建议在虚拟机中运行。详见 [ExternalBinaries/README.md](ExternalBinaries/README.md)。

### 运行说明

1. 确保测试签名已启用
2. 以管理员权限运行主程序
3. 主程序会自动安装并启动各驱动服务
4. 驱动停止顺序：网络 → 磁盘 → 主驱动 → R3 DLL 卸载

---

## 安全须知

> ⚠️ **重要提示**：在分发或贡献代码前，请处理以下敏感信息

| 项目 | 位置 | 风险 | 建议 |
|------|------|------|------|
| XOR 加密密钥 | `PublicDefine.h:7` | 硬编码密钥可被逆向获取 | 部署前更改或移至配置文件 |
| 根证书 | `Resources/BinaryFiles/root.spc` | 自签名证书可被利用签名恶意程序 | 替换为正式证书或删除 |
| 网络端口 | `main.cpp:8439-8477` | 12345-12347 绑定 localhost | 生产环境更改端口号 |

---

## 免责声明

本程序及其衍生程序均仅供**技术交流与学术研究**使用。作者不对程序的安全性、稳定性、适用性做任何明示或暗示的保证，包括但不限于适销性、特定用途适用性和非侵权性的保证。

**严禁在实体机（Physical Machine）上运行本程序**。内核驱动级别的挂钩、过滤和进程干预操作可能导致系统蓝屏、数据丢失或不可恢复的系统损坏。请使用虚拟机（VMware / VirtualBox / Hyper-V 等）在隔离环境中进行测试。

使用者自行承担使用本程序的一切风险。作者不对任何直接、间接、偶然、特殊或后果性的损害承担责任。

---

## 第三方组件

本项目集成了多个优秀的开源项目，感谢所有贡献者：

| 组件 | License | 用途 |
|------|---------|------|
| [Qt 6](https://www.qt.io/) | LGPL-3.0 / Commercial | GUI 框架 |
| [YARA](https://github.com/VirusTotal/yara) | Apache 2.0 / BSD-3 | 恶意软件签名匹配 |
| [ClamAV](https://www.clamav.net/) | GPL-2.0+ | 病毒扫描引擎（动态加载） |
| [LightGBM](https://github.com/microsoft/LightGBM) | MIT | 机器学习 PE 分类 |
| [libarchive](https://libarchive.org/) | BSD-2-Clause | 归档文件解压 |
| [Microsoft Detours](https://github.com/microsoft/Detours) | Research License | API 拦截 |
| [OpenSSL](https://www.openssl.org/) | OpenSSL License | 加密库（通过 YARA NuGet） |
| [Jansson](https://www.digip.org/jansson/) | MIT | JSON 解析（通过 YARA NuGet） |
| [ElaWidgetTools](https://github.com/Ellise961/ElaWidgetTools) | TBD | Qt 组件扩展库 |

完整 license 详情见 [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)。

> **注意**：ClamAV 以动态加载方式（`LoadLibrary`）使用 `libclamav.dll`，不构成 GPL 传染性。编译时需要 ClamAV 头文件（参见"获取 ClamAV 源码"说明），发行时需附带 `libclamav.dll`。

---

## 开源协议

本项目采用 [MIT License](LICENSE) 开源协议。

第三方组件保留其各自的原许可证。详见 [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md)。
