# TianHong Security Defense

A comprehensive Windows security defense system with three-layer architecture combining kernel-mode driver, user-mode hooks, and heuristic analysis.

## Architecture

```
┌─────────────────────────────────────────────┐
│           TianHong-Security-Defense (GUI)    │
│         Main Application + Detection UI      │
└──────────────────┬──────────────────────────┘
                   │ IPC (localhost sockets)
    ┌──────────────┼──────────────┐
    ▼              ▼              ▼
┌────────┐  ┌─────────────┐  ┌──────────────┐
│ Kernel  │  │ TianHong    │  │ TianHong     │
│ Driver  │  │ Defense DLL │  │ Injector     │
│(x64)   │  │ (API Hooks) │  │ (R3 helper)  │
└────────┘  └─────────────┘  └──────────────┘
    │
    └─── Kernel Protection (R0)
         ├─ Behavior Analysis Engine
         ├─ HIPS Rule Engine
         ├─ Injection Protection
         ├─ File System Filter
         └─ Registry Protection
```

### Components

| Component | Description |
|-----------|-------------|
| `TianHong-Security-Defense` | Main GUI application (Qt 6) |
| `TianHongDefense` | User-mode hook DLL (NtCreateUserProcess, etc.) |
| `TianHongInjector32` | 32-bit process injector utility |
| `TianHongScanner` | Standalone PE scan engine |
| `TianHongDefenseKernelProtection` | Kernel-mode driver (x64) |
| `TianHongDefenseKernelProtectionClient` | Driver control client |
| `TianHongDefenseKernelProtection.Network` | Network filter driver |
| `TianHongDefenseKernelProtectionDisk` | Disk filter driver |

## Features

- **Kernel-level behavior analysis** — Real-time detection via `BehaviorAnalysis` timer
- **HIPS (Host-based Intrusion Prevention)** — TOML-based rule engine for file/registry/network
- **Injection protection** — Three-layer: ObRegisterCallbacks → PsSetCreateThreadNotifyRoutine → BehaviorAnalysis
- **Script sandbox** — Behavioral analysis for JS/VBS/HTA/PS1/BAT without execution
- **YARA scanning** — Static signature matching via libyara
- **Heuristic detection** — BSD/Heur/ classification for unknown threats
- **LightGBM ML model** — PE feature-based classification
- **ClamAV integration** — Dynamic-loaded virus scanning engine
- **Process tree management** — Root process + all descendant PID tracking

## Build Requirements

- **OS**: Windows 10/11 (x64)
- **Compiler**: MSVC v145 (Visual Studio 2022 Community) or mingw
- **Qt**: 6.9.2 (mingw_64)
- **Windows SDK**: Latest
- **Test signing**: Required for kernel driver (`bcdedit /set testsigning on`)

## Security Notes

⚠️ **Important**: This project contains sensitive cryptographic materials that should be handled carefully:

- The XOR encryption key is hardcoded in `PublicDefine.h` — change it before distribution
- The `root.spc` certificate should be replaced with your own or removed
- Network ports (12345-12347) are localhost-only but should be changed for production

## Third-Party Components

See [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES.md) for full license details of all third-party dependencies.

### Key Dependencies

| Library | License | Usage |
|---------|---------|-------|
| Qt 6 | LGPL-3.0 / Commercial | GUI framework |
| YARA (libyara) | Apache 2.0 / BSD-3 | Static signature scanning |
| ClamAV (libclamav.dll) | GPL-2.0+ | Dynamic-load virus engine |
| LightGBM | MIT | ML-based PE classification |
| libarchive | BSD-2-Clause | Archive extraction |
| Microsoft Detours | Research License | API hooking |
| OpenSSL | OpenSSL License | Cryptography (via YARA NuGet) |
| Jansson | MIT | JSON parsing (via YARA NuGet) |

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
Third-party components retain their respective licenses. See [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES.md).