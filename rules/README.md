# 规则与模型文件说明

本目录存放程序运行所需的**规则文件**，构建/运行时会被复制到输出目录的 `Resources\rules\` 下。

## 目录结构

```
rules/
├── behavior/        # 行为分析动态规则（TOML，无需重新编译驱动）
│   ├── credential_access.toml   # 凭据窃取
│   ├── discovery.toml           # 信息收集
│   ├── disk.toml                # 磁盘操作
│   ├── etw_network.toml         # ETW 网络事件
│   ├── evasion.toml             # 防御规避
│   ├── impact.toml              # 破坏性影响
│   ├── injection.toml           # 注入检测
│   ├── network.toml             # 网络行为
│   └── persistence.toml         # 持久化
├── hips/            # HIPS 规则（文件/注册表/网络/进程）
│   ├── elevation_service.toml   # 服务提权
│   ├── hips_files.toml          # 文件保护规则
│   ├── hips_extended_files.toml # 文件保护扩展规则
│   ├── hips_extended_reg.toml   # 注册表保护扩展规则
│   └── hips_reg.toml            # 注册表保护规则
└── indicators/      # 行为指标规则
    ├── extra.toml               # 附加指标
    ├── file.toml                # 文件指标
    ├── network.toml             # 网络指标
    ├── process.toml             # 进程指标
    └── registry.toml            # 注册表指标
```

## 复制方式

将规则文件复制到程序输出目录的 `Resources\rules\` 下：

```powershell
xcopy /E /I /Y "rules\*" "x64\Release\Resources\rules\"
```

> **注意**：`Heur.data.*`（LightGBM ML 模型权重）、`Malware.yarac` / `MalwareMemory.yarac`（YARA 编译规则）位于 `Release\` 目录，复制方式见根目录 `README.md`。
