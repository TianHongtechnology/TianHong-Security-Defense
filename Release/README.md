# Release 目录

此目录包含程序运行时必需、**不在编译名单内且正常无法成套获得**的二进制文件。编译产生的可执行文件与驱动（`.exe`、`.sys`）不在此目录，需自行构建。

## 免责声明 / Disclaimer

> **本目录下的所有 PE 文件（.dll、.exe）均来自第三方开源项目或系统组件，仅供本项目运行时依赖使用。**
>
> 作者不对这些文件的来源安全性、无毒状态做任何保证。使用者应自行评估风险，建议在隔离环境（虚拟机）中运行。
>
> **严禁在实体机（Physical Machine）上直接运行本目录下的任何文件**。内核驱动级别的防护程序可能导致系统不稳定。

## 文件说明

| 文件 | 来源 | 用途 |
|------|------|------|
| `ElaWidgetTools.dll` | [ElaWidgetTools](https://github.com/Ellise961/ElaWidgetTools) | Qt 扩展组件库 |
| `certmgr.exe` | Windows SDK | 证书管理工具（安装根证书） |
| `libclamav.dll` | ClamAV | 病毒扫描引擎（动态加载） |
| `libclamunrar.dll` | ClamAV | RAR 解压支持 |
| `libclamunrar_iface.dll` | ClamAV | RAR 解压接口 |
| `libfreshclam.dll` | ClamAV | 病毒库更新 |
| `libcurl.dll` | libcurl | HTTP/HTTPS 传输 |
| `libssl-3-x64.dll` / `libcrypto-3-x64.dll` | OpenSSL | 加密库 |
| `libssh2.dll` | libssh2 | SSH 传输 |
| `nghttp2.dll` | nghttp2 | HTTP/2 传输 |
| `libxml2.dll` | libxml2 | XML 解析 |
| `libbz2.dll` | bzip2 | bzip2 压缩 |
| `json-c.dll` | json-c | JSON 解析 |
| `libmspack.dll` | libmspack | 压缩格式支持 |
| `pcre2-8.dll` | PCRE2 | 正则表达式 |
| `pdcurses.dll` | PDCurses | 终端 UI |
| `pthreadVC3.dll` | pthreads-win32 | 线程库 |
| `archive.dll` | libarchive | 归档文件解压 |

> 以上 ClamAV 相关 DLL 为成套运行时依赖，编译名单外且正常无法单独成套获得，故随仓库提供。

## 使用方式

将本目录下的文件复制到程序输出目录（与 `TianHong-Security-Defense.exe` 同级）：

```powershell
# 复制到 x64\Release\
Copy-Item "Release\*" "x64\Release\" -Force
Copy-Item "Release\certmgr.exe" "x64\Release\Resources\BinaryFiles\" -Force
```

驱动 `.sys` 文件与各可执行文件（`.exe`）不在本目录，需自行编译生成。

## ⚠️ 使用 Qt 自带功能补充 PE 文件（重要）

Qt 核心库、插件（platforms/styles/imageformats 等）和 **MSVC 运行时**不在本目录，请使用 **Qt 自带部署工具 `windeployqt`** 自动补充，不要手动复制：

```powershell
# 打开 "Qt 6.x.x (MinGW 64-bit)" 命令行，切换到输出目录后执行：
cd x64\Release
windeployqt --release TianHong-Security-Defense.exe
```

`windeployqt` 会自动复制程序依赖的 Qt6*.dll、插件目录、以及对应的 VC 运行时（vcruntime140.dll、msvcp140.dll 等）。如未安装 Qt 命令行环境，也可直接在 Qt Creator 中运行程序让其自动部署，或手动从 `Qt\6.9.2\mingw_64\bin` 复制。
