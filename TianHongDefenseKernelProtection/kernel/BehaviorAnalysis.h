#pragma once
#include "../shared/Common.h"

/* ============================================================================
 * BehaviorAnalysis.h — 动态行为分析引擎
 * 基于指标评分 + 威胁画像匹配的进程行为检测
 * ========================================================================== */

// ── 行为分析常量 ──
#define BA_MAX_PATH            1024
#define BA_MAX_NAME            256
#define BA_MAX_PROCESSES       512
#define BA_MAX_HISTORY         10240
#define BA_MAX_CHILDREN        64
#define BA_MAX_EVIDENCE        64
#define BA_MAX_INDICATORS      187
#define BA_MAX_PROFILES        256
#define BA_MAX_RESULTS         64
#define BA_MAX_CRYPT_EXTS      64
#define BA_MAX_RANSOM_NOTES    64
#define BA_MAX_BYOVD_DRIVERS   64
#define BA_MAX_SYS_PROCS       16
#define BA_MAX_SEC_PROCS       64
#define BA_MAX_KNOWN_DLLS      16
#define BA_MAX_FAKE_NAMES      16
#define BA_MAX_BASELINES       2048
#define BA_MAX_CMDLINE         512   /* 进程命令行最大长度（字符） */
#define BA_MAX_GHOST_PROCESSES 128   /* 已退出进程幽灵追踪数量 */
#define BA_GHOST_TTL_TICKS     12000 /* 幽灵进程TTL：120秒（12000 * 10ms tick） */

// ── 误报缓解：白名单、例外、信任上下文、时间窗口、证据质量、签名信任 ──
#define BA_MAX_WHITELIST       512
#define BA_MAX_EXCEPTIONS     256
#define BA_MAX_TRUSTED_PRODUCTORS 128
#define BA_MAX_SIGNED_PRODUCTORS 256
#define BA_MAX_RULE_SUPPRESSIONS 128
#define BA_MAX_LOOKBACK_WINDOWS 32
#define BA_DEFAULT_LOOKBACK_MS 60000
#define BA_DEFAULT_SUPPRESSION_MS 300000
#define BA_DEFAULT_EXCEPTION_TTL_MS 3600000
#define BA_DEFAULT_INDICATOR_QUALITY_THRESHOLD 0.4
#define BA_DEFAULT_PROCESS_REPUTATION_THRESHOLD 0.7
#define BA_DEFAULT_SIGNED_PRODUCER_BONUS 0.3
#define BA_DEFAULT_SECURITY_PRODUCT_DISCOUNT 0.5
#define BA_DEFAULT_EVIDENCE_DEDUP_WINDOW_MS 5000
#define BA_DEFAULT_CORRELATION_WINDOW_MS 30000
#define BA_DEFAULT_MIN_CORRELATION_COUNT 3
#define BA_DEFAULT_ANOMALY_Z_THRESHOLD 3.5
#define BA_DEFAULT_BASELINE_MIN_SAMPLES 10

// ── 事件类别 ──
typedef enum _BA_EVENT_CATEGORY {
    BA_EC_File = 0,
    BA_EC_Registry,
    BA_EC_Memory,
    BA_EC_Process
} BA_EVENT_CATEGORY;

// ── 文件操作 ──
typedef enum _BA_FILE_OP {
    BA_FOP_Create = 0,
    BA_FOP_Modify,
    BA_FOP_Read,
    BA_FOP_Write,
    BA_FOP_Delete
} BA_FILE_OP;

// ── 注册表操作 ──
typedef enum _BA_REG_OP {
    BA_ROP_CreateKey = 0,
    BA_ROP_SetValue,
    BA_ROP_DeleteKey,
    BA_ROP_DeleteValue,
    BA_ROP_QueryValue   /* RegNtQueryValueKey 读取操作，用于 VM/RDP 探测检测 */
} BA_REG_OP;

// ── 内存操作 ──
typedef enum _BA_MEM_OP {
    BA_MOP_HandleCreate = 0,
    BA_MOP_HandleDuplicate,
    BA_MOP_SetWindowsHookEx,
    /* Phase 4: 原子权限组合（替代 8 个 PoolParty 变体）*/
    BA_MOP_VMWriteVMOperate,        // 原子组合 1: VM_WRITE + VM_OPERATION
    BA_MOP_VMOperCreateThread,      // 原子组合 2: VM_OPERATION + CREATE_THREAD
    BA_MOP_VMOperDupHandle,         // 原子组合 3: VM_OPERATION + DUP_HANDLE
    BA_MOP_PoolParty_HandleRequest, // PoolParty 精确匹配: 0x0478
    /* ETW Threat-Intelligence memory operation indicators */
    BA_MOP_RemoteAllocExecutable,    // Remote alloc with executable protection
    BA_MOP_RemoteProtectExecutable,  // Remote protect to executable
    BA_MOP_RemoteWriteMemory,        // Remote NtWriteVirtualMemory
    BA_MOP_RemoteQueueApc,           // Remote NtQueueApcThread
    BA_MOP_RemoteSetThreadContext,   // Remote SetThreadContext
    BA_MOP_RemoteMapViewExecutable,  // Remote NtMapViewOfSection with executable view
    BA_MOP_AllocToProtectChain,      // RW alloc later protected to executable (shellcode pattern)
    BA_MOP_WriteToProtectChain,      // Write then protect to executable (shellcode pattern)
    BA_MOP_DllLoadViaRop,            // DLL 加载通过 ROP 链发起（调用栈含非镜像返回地址）
    BA_MOP_RemoteThreadUnbacked      // 远程线程起始地址位于非镜像内存（shellcode 注入 T1055）
} BA_MEM_OP;

// ── 行为指标 ──
typedef enum _BA_INDICATOR {
    BA_IND_PROC_FROM_TEMP_DIR = 0,
    BA_IND_PROC_FROM_DOWNLOADS_DIR,
    BA_IND_PROC_FROM_APPDATA_DIR,
    BA_IND_PROC_UNSIGNED,
    BA_IND_FILE_CREATE_SYSTEM_DIR,
    BA_IND_FILE_CREATE_DRIVER,
    BA_IND_FILE_CREATE_STARTUP_EXE,
    BA_IND_FILE_DROP_FROM_TEMP,
    BA_IND_FILE_CREATE_DLL_HIJACK,
    BA_IND_FILE_ENCRYPTED_EXTENSION,
    BA_IND_FILE_RANSOM_NOTE,
    BA_IND_FILE_DLL_SIDE_LOAD,
    BA_IND_FILE_BROWSER_CRED_TARGET,
    BA_IND_FILE_SELF_DELETE,
    BA_IND_FILE_NETWORK_SHARE,
    BA_IND_FILE_INF_AUTORUN,
    BA_IND_FILE_HOSTS_MODIFY,
    BA_IND_FILE_DISK_RAW_ACCESS,
    BA_IND_FILE_BYOVD_DRIVER_LOAD,
    BA_IND_REG_MODIFY_RUN_KEY,
    BA_IND_REG_MODIFY_IFEO_DEBUGGER,
    BA_IND_REG_MODIFY_WINLOGON,
    BA_IND_REG_CREATE_SERVICE,
    BA_IND_REG_MODIFY_SHELL_OPEN,
    BA_IND_REG_SCHEDULED_TASK_CREATE,
    BA_IND_MEM_OPEN_SYSTEM_PROCESS,
    BA_IND_MEM_OPEN_REMOTE_THREAD,
    BA_IND_MEM_READ_LSASS,
    BA_IND_PROC_KILL_SECURITY_PROCESS,
    BA_IND_PROC_VSSADMIN_SHADOW_DELETE,
    BA_IND_PROC_BCDEDIT_RECOVERY_DISABLE,
    BA_IND_PROC_FAKE_UPDATE_INSTALLER,
    BA_IND_PROC_KEYBOARD_HOOK,
    BA_IND_PROC_HIDDEN_WINDOW,
    BA_IND_FILE_APPDATA_DLL,
    BA_IND_NETWORK_C2_CONNECT,
    BA_IND_FILE_BOOT_EXECUTE,
    /* Winkiller 专用指标 (37-41) */
    BA_IND_FILE_MASS_SYSTEM_DELETE,
    BA_IND_REG_MASS_DELETE,
    BA_IND_FILE_BOOT_SECTOR,
    BA_IND_DISK_MBR_WRITE,
    BA_IND_PROC_CRITICAL_PROCESS_KILL,
    /* 脚本解释器检测 (42) */
    BA_IND_PROC_SCRIPT_INTERPRETER,
    /* Command-line context indicators (43-51) */
    BA_IND_OFFICE_SPAWN_CMD,          // Office app spawns cmd/powershell (T1566)
    BA_IND_CERTUTIL_DOWNLOAD,         // certutil -decode/-urlcache download (T1105)
    BA_IND_BITSADMIN_TRANSFER,        // bitsadmin /transfer download (T1105)
    BA_IND_NET_USER_MODIFY,           // net user add/delete (T1136)
    BA_IND_SVCHOST_ANOMALY,           // svchost.exe with wrong parent (T1055)
    BA_IND_ICACLS_MODIFY,             // icacls permission modification (T1222)
    BA_IND_TASKKILL_SECURITY,         // taskkill targeting security tools (T1562)
    BA_IND_MSIEXEC_SILENT_INSTALL,    // msiexec /quiet /i from suspicious context (T1218)
    BA_IND_WMI_PERSISTENCE,           // WMI event subscription creation (T1546.003)
    /* Injection detection (52-54) */
    BA_IND_MEM_CROSS_PROCESS_WRITE,   // Cross-process memory write: VM_WRITE/VM_OPERATION (T1055)
    BA_IND_MEM_INJECTION_CHAIN,       // Injection chain: cross-process write + remote thread (T1055)
    BA_IND_MEM_PROCESS_HOLLOWING,     // Process hollowing: create suspended + write + remote thread
    /* dllmain.cpp 补充：高危系统操作 (55-58) */
    BA_IND_PROC_RAISE_HARD_ERROR,     // NtRaiseHardError: R3层调用蓝屏 (T1561)
    BA_IND_PROC_SET_CRITICAL,         // RtlSetProcessIsCritical/NtSetInformationProcess(ProcessBreakOnTermination): 设置关键进程
    BA_IND_PROC_APC_INJECTION,        // NtQueueApcThread: 跨进程APC注入 (T1055.004)
    BA_IND_PROC_MAP_SECTION,          // NtMapViewOfSection: 跨进程内存映射注入 (T1055.012)
    /* PoolParty / 原子权限组合指标 (59-64) */
    BA_IND_MEM_VM_WRITE_VM_OPERATE,      // 原子权限组合 1: VM_WRITE + VM_OPERATION
    BA_IND_MEM_VM_OPER_CREATE_THREAD,    // 原子权限组合 2: VM_OPERATION + CREATE_THREAD
    BA_IND_MEM_VM_OPER_DUP_HANDLE,       // 原子权限组合 3: VM_OPERATION + DUP_HANDLE
    BA_IND_MEM_POOLPARTY_HANDLE_REQUEST, // PoolParty 精确匹配: 0x0478
    /* ETW Threat-Intelligence injection indicators (65-72) */
    BA_IND_MEM_ETW_REMOTE_ALLOC_EXECUTABLE,   // Remote executable memory allocation
    BA_IND_MEM_ETW_REMOTE_PROTECT_EXECUTABLE, // Remote memory protected to executable
    BA_IND_MEM_ETW_REMOTE_WRITE_MEMORY,       // Remote virtual memory write
    BA_IND_MEM_ETW_REMOTE_QUEUE_APC,          // Remote APC insertion
    BA_IND_MEM_ETW_REMOTE_SET_THREAD_CONTEXT, // Remote thread context manipulation
    BA_IND_MEM_ETW_REMOTE_MAP_VIEW_EXECUTABLE, // Remote executable mapped view
    BA_IND_MEM_ETW_ALLOC_TO_PROTECT_CHAIN,    // Non-exec alloc later protected to exec (suspicious chain)
    BA_IND_MEM_ETW_WRITE_TO_PROTECT_CHAIN,    // Write then protect to exec (shellcode pattern)
    BA_IND_MEM_DIRECT_SYSCALL,                // Direct syscall to bypass R3/用户态 EDR hooks (return address not in ntdll.dll)
    BA_IND_MEM_INDIRECT_SYSCALL,              // Indirect syscall to bypass R3/用户态 EDR hooks (jmp to ntdll syscall instr)
    BA_IND_FILE_SELF_LOADING,                 // Self-loading DLL evasion (e.g. DLL side-loading / 自加载)
    /* Additional execution indicators for T1218 and related */
    BA_IND_MSHTA_EXECUTION,                   // mshta.exe executing HTA/script (T1218.005)
    BA_IND_REGSVR32_EXECUTION,                // regsvr32.exe executing scriptlet (T1218.003)
    BA_IND_CONTROL_PANEL_ITEM,                // control panel item (CPL) execution (T1218.002)
    BA_IND_MAVINJECT_INJECTION,               // mavinject.exe remote thread injection (T1055)
    BA_IND_CMSTP_EXECUTION,                   // CMSTP INF script execution (T1218.003)
    BA_IND_MSDT_EXECUTION,                    // msdt.exe troubleshooting pack execution (T1218)
    BA_IND_SIGNED_BINARY_PROXY,               // Signed binary proxy execution (T1218)
    BA_IND_APPLOCKER_BYPASS,                  // AppLocker / application whitelisting bypass
    /* Network / C2 indicators */
    BA_IND_NET_C2_CONNECT,                    // Suspicious outbound connection to known C2 port/IP
    BA_IND_NET_UNKNOWN_PORT,                  // Outbound connection to uncommon/high port
    BA_IND_NET_SUSPICIOUS_DNS,                // Suspicious DNS query pattern
    BA_IND_NET_PROCESS_NETWORK,               // Process with network activity + injection indicators
    BA_IND_NET_LONG_CONNECTION,
    BA_IND_NTDLL_UNHOOK,               // ntdll.dll unhook/reload detected
    BA_IND_NTDLL_REMAP,                // ntdll.dll remap/base change detected
    BA_IND_NTDLL_PATH_ANOMALY,         // ntdll.dll loaded from non-system path
    BA_IND_FILE_BULK_WRITE,            // 短时间内批量修改文件（勒索软件加密行为检测）
    /* DCOM lateral movement indicators (95-101) */
    BA_IND_DCOM_REMOTE_ACTIVATION,     // DCOM remote activation detected
    BA_IND_DCOM_MMC20_SHELLEXEC,       // MMC20.Application ExecuteShellCommand
    BA_IND_DCOM_SHELLWINDOWS,          // ShellWindows/ShellBrowserWindow ShellExecute
    BA_IND_DCOM_EXCEL_DDE,             // Excel.Application via DCOM (DDE/macro)
    BA_IND_DCOM_OUTLOOK_CREATEOBJECT,  // Outlook.Application CreateObject
    BA_IND_DCOM_CHILD_PROCESS,         // dllhost.exe/svchost.exe spawning suspicious child
    BA_IND_DCOM_WMI_REMOTE,            // WMI remote execution via DCOM
    /* Syscall 分类追踪指标 (102-110)：用于检测直接/间接 syscall 的具体类型 */
    BA_IND_SYSCALL_ALLOC_VM,           // NtAllocateVirtualMemory via direct/indirect syscall
    BA_IND_SYSCALL_PROTECT_VM,         // NtProtectVirtualMemory via direct/indirect syscall
    BA_IND_SYSCALL_WRITE_VM,           // NtWriteVirtualMemory via direct/indirect syscall
    BA_IND_SYSCALL_CREATE_THREAD,      // NtCreateThreadEx via direct/indirect syscall
    BA_IND_SYSCALL_QUEUE_APC,          // NtQueueApcThread via direct/indirect syscall
    BA_IND_SYSCALL_MAP_VIEW,           // NtMapViewOfSection via direct/indirect syscall
    BA_IND_SYSCALL_OPEN_PROCESS,       // NtOpenProcess via direct/indirect syscall
    BA_IND_SYSCALL_MULTI_TYPE,         // 多种类型 syscall 同时使用（indicates tool usage）
    BA_IND_SYSCALL_INJECTION_CHAIN,    // syscall 注入链: Alloc+Write+Protect+Thread 组合
    /* 扩展 syscall 指标 (111-122)：覆盖更多攻击面 */
    BA_IND_SYSCALL_READ_VM,            // NtReadVirtualMemory via direct/indirect syscall（LSASS dump 常用）
    BA_IND_SYSCALL_SET_CONTEXT,        // NtSetContextThread via direct/indirect syscall（SetThreadContext 注入）
    BA_IND_SYSCALL_RESUME_THREAD,      // NtResumeThread via direct/indirect syscall（进程空心化）
    BA_IND_SYSCALL_TOKEN_MANIP,        // NtAdjustPrivilegesToken/NtSetInformationToken（提权操作）
    BA_IND_SYSCALL_HANDLE_DUP,         // NtDuplicateObject（句柄复制/窃取）
    BA_IND_SYSCALL_CREATE_PROCESS,     // NtCreateUserProcess via direct/indirect syscall（fork&run）
    BA_IND_SYSCALL_QUERY_SYSINFO,      // NtQuerySystemInformation（进程枚举/反调试）
    BA_IND_SYSCALL_QUERY_PROCESS,      // NtQueryInformationProcess（进程信息查询）
    BA_IND_SYSCALL_CREATE_SECTION,     // NtCreateSection（共享内存段创建）
    BA_IND_SYSCALL_READ_LSASS_CHAIN,   // syscall LSASS 读取链: OpenProcess+ReadVM+MapView（凭据窃取）
    BA_IND_SYSCALL_TOKEN_STEAL_CHAIN,  // syscall 令牌窃取链: OpenProcess+DuplicateObject+SetThreadToken
    BA_IND_SYSCALL_PROCESS_HOLLOW,     // syscall 进程空心化: CreateProcess(SUSPENDED)+Unmap+Write+Resume
    /* 扩展 syscall 指标 (123-135)：覆盖更多攻击面 */
    BA_IND_SYSCALL_SUSPEND_THREAD,     // NtSuspendThread via direct/indirect syscall（空心化/注入前暂停）
    BA_IND_SYSCALL_GET_CONTEXT,        // NtGetContextThread via direct/indirect syscall（shellcode 注入）
    BA_IND_SYSCALL_TERMINATE_PROCESS,  // NtTerminateProcess via direct/indirect syscall（杀安全软件）
    BA_IND_SYSCALL_FLUSH_INST_CACHE,   // NtFlushInstructionCache via direct/indirect syscall（shellcode 执行前）
    BA_IND_SYSCALL_CREATE_KEY,         // NtCreateKey via direct/indirect syscall（注册表持久化）
    BA_IND_SYSCALL_SET_VALUE_KEY,      // NtSetValueKey via direct/indirect syscall（注册表修改）
    BA_IND_SYSCALL_CREATE_FILE,        // NtCreateFile via direct/indirect syscall（文件投放）
    BA_IND_SYSCALL_DELETE_FILE,        // NtDeleteFile via direct/indirect syscall（文件清理/自删除）
    BA_IND_SYSCALL_LOAD_DRIVER,        // NtLoadDriver via direct/indirect syscall（BYOVD 驱动加载）
    BA_IND_SYSCALL_WORKER_FACTORY,     // NtCreateWorkerFactory via direct/indirect syscall（PoolParty 注入）
    BA_IND_SYSCALL_CREATE_NAMED_PIPE,  // NtCreateNamedPipeFile via direct/indirect syscall（C2 命名管道）
    BA_IND_SYSCALL_SET_INFO_PROCESS,   // NtSetInformationProcess via direct/indirect syscall（关键进程/断链）
    BA_IND_SYSCALL_PERSISTENCE_CHAIN,  // syscall 持久化链: CreateKey+SetValueKey+CreateFile（注册表+文件持久化）
    /* 漏报修复新增指标 (136-139) */
    BA_IND_MEM_SELF_PROTECT_EXECUTABLE, // 自身内存 RW→RX 转换（shellcode 执行/载荷解密），仅可疑进程触发
    BA_IND_FILE_CREATE_FAKE_SYS_DIR,    // 在伪系统目录（C:\Drivers\<随机>\ 等）创建无签名可执行文件
    BA_IND_PROC_TASKKILL_SECURITY_TOOL, // taskkill 针对安全工具/系统管理工具（taskmgr/regedit/msconfig 等）
    BA_IND_REG_MASS_MODIFY,             // 短时间内批量修改注册表（Winkiller 持久化/破坏行为）
    /* 关键证据指标 (140-144)：病毒行为分析关键证据，纯 R0 检测 */
    BA_IND_REG_VM_TZ_QUERY,             // 读取 TimeZoneInformation 键（VM/沙箱规避 T1497.003）
    BA_IND_REG_VM_BIOS_QUERY,           // 读取 HARDWARE\DESCRIPTION\System\BIOS 键（VM 检测 T1497.001）
    BA_IND_REG_TS_KEY_READ,            // 读取 Terminal Server 键（RDP 探测 T1021.001）
    BA_IND_MEM_PROCESS_ENUM_BATCH,     // 60s 内打开 ≥5 个进程 PROCESS_QUERY_INFORMATION（进程发现 T1057）
    BA_IND_MEM_SELF_VM_OPERATION_OPEN, // 进程对自身打开 PROCESS_VM_OPERATION（shellcode RW→RX 前置 T1055）
    BA_IND_IMG_LOAD_VIA_ROP,           // DLL 加载通过 ROP 链发起（调用栈含非镜像返回地址 T1055.001）
    /* ATT&CK 战术补充指标 (146-160)：覆盖 0% 覆盖率战术的关键行为 */
    /* TA0001 初始访问 */
    BA_IND_FILE_MOTW_ZONE_IDENTIFIER,  // 读取 Zone.Identifier ADS（Mark of the Web 钓鱼附件 T1566.001）
    BA_IND_FILE_DLL_UNSIGNED_CHAIN,    // 已签名 EXE 加载未签名 DLL（供应链/DLL 侧加载签名链 T1195.002）
    /* TA0004 提权 */
    BA_IND_REG_UAC_BYPASS_CLASSES,     // HKCU\Software\Classes\*\shell\open\command 劫持（fodhelper/eventvwr UAC Bypass T1548.002）
    BA_IND_MEM_TOKEN_IMPERSONATION,    // OpenProcess(TOKEN_DUPLICATE)+AdjustTokenPrivileges 链（令牌窃取 T1134.001）
    BA_IND_PROC_CREATE_WITH_TOKEN,     // 提权子进程+令牌操作链（CreateProcessAsUser/withToken T1134.002）
    /* TA0006 凭据访问 */
    BA_IND_FILE_SAM_HIVE_READ,         // 读取 \Windows\System32\config\SAM|SYSTEM|SECURITY（凭据转储 T1003.002）
    BA_IND_REG_DS_REPLICATION_QUERY,   // 读取 DS 恢复模式密码/DSRM（DCSync 前置 T1003.006）
    BA_IND_FILE_DPAPI_MASTER_KEY,      // 读取 %APPDATA%\Microsoft\Protect\<SID>\ 主密钥（DPAPI 凭据存储 T1555）
    BA_IND_REG_LSA_SECRETS_QUERY,      // 读取 SECURITY\Policy\Secrets（LSA Secrets 提取 T1003.004）
    /* TA0007 发现 */
    BA_IND_PROC_ACCOUNT_DISCOVERY,     // net.exe user/group/localgroup + whoami（账户发现 T1087）
    BA_IND_REG_SYSTEM_INFO_DISCOVERY,  // 读取 HARDWARE\DESCRIPTION/System 信息频次（系统信息发现 T1082）
    /* TA0009 收集 */
    BA_IND_FILE_SCREEN_CAPTURE,        // 非截图工具创建 .png/.bmp 至 temp/appdata（屏幕捕获 T1113）
    BA_IND_FILE_DATA_STAGED,           // 短时间内批量复制 exe/dll 至暂存目录（数据暂存 T1074）
    /* TA0040 影响 */
    BA_IND_PROC_SYSTEM_SHUTDOWN,       // shutdown.exe /s /r /t 0 /f（系统关机/重启 T1529）
    /* 浏览器 elevation_service 持久化（T1574.002 / T1543.003 / T1546.015）
     * Chromium 系（Chrome/Edge/Brave）浏览器 elevation_service.exe 持久化路径滥用 */
    BA_IND_FILE_ELEVATION_SERVICE_HIJACK,  // 替换/投放 elevation_service 加载的 DLL 或 EXE 本体（T1574.002 DLL 侧加载）
    BA_IND_REG_ELEVATION_SERVICE_HIJACK,   // 修改 elevation_service CLSID/服务/Update Client 相关键（T1543.003/T1546.015）
    /* 银狐家族分类低危指标（仅作家族归类，不单独触发警报）
     * 这些指标权重极低，仅当综合行为分析判定为病毒时用于归类为 SilverFox 家族 */
    BA_IND_FILE_FAKE_DIR_DROP,         // 伪装目录（temp/appdata/c:\drivers）投放可执行文件（银狐家族特征）
    BA_IND_FILE_TEMP_RANDOM_NAME_EXE,  // 临时目录随机文件名可执行文件（银狐家族特征）
    /* 注入防护强化指标 (164-167)：参考 Elastic Security shellcode thread 检测策略 */
    BA_IND_MEM_THREAD_START_UNBACKED,  // 远程线程起始地址位于非镜像内存（shellcode 注入 T1055）
    BA_IND_PROC_HIGH_RISK_PARENT,      // 高风险父进程上下文加权（Office/脚本/LOLBin 发起注入操作）
    BA_IND_PROC_EDR_FREEZE,            // WerFaultSecure 异常启动（EDR-Freeze 技术 T1562.001）
    BA_IND_MEM_INJECTION_RATE_LIMIT,   // 同一源进程短时间多次注入尝试（频率抑制，工具行为）
    /* Trojan.SilverFox 指标：文件隐藏 + 图片内嵌PE */
    BA_IND_FILE_SET_SYSTEM_HIDDEN,     // 将新创建文件设置为系统级隐藏属性（银狐家族特征 T1562.002）
    BA_IND_FILE_PE_IN_IMAGE,           // 图像文件（jpg/png/bmp）内含PE可执行特征（银狐家族特征 T1566.001）
    /* Trojan.AVBypass 指标：ETW/InstrumentationCallback 绕过 */
    BA_IND_REG_ETW_PATCH,              // 修改 ETW 注册表禁用事件追踪（T1562.002）
    BA_IND_REG_INSTRUMENTATION_CALLBACK, // 修改 InstrumentationCallback 绕过监控（T1562.001）
    BA_IND_MEM_ETW_INLINE_PATCH,       // 直接 patch ETW 内核函数（T1562.002）
    /* Trojan.Rootkit 指标：高危驱动加载 */
    BA_IND_PROC_LOAD_HIGH_RISK_DRIVER, // 加载已知高危/漏洞驱动（BYOVD T1068）
    BA_IND_REG_DRIVER_SERVICE_CREATE,  // 创建高危驱动服务（Rootkit 持久化 T1547.001）
    /* Trojan.Exploit 指标：可执行内存分配与执行 */
    BA_IND_MEM_ALLOC_EXECUTE,          // 分配可执行内存（自身 shellcode 解密执行 T1055.003）
    BA_IND_MEM_ALLOC_EXECUTE_SELF,     // 自身进程分配并执行可执行内存（自解密 shellcode T1055）
    BA_IND_MEM_NONSYSTEM_RWX,          // 非系统进程将非MEM_IMAGE内存设为RWX（PAGE_EXECUTE_READWRITE）
    BA_IND_MEM_NONSYSTEM_EXEC_READ,    // 非系统进程将非MEM_IMAGE内存设为只读可执行（PAGE_EXECUTE_READ）
    BA_IND_PROC_DACL_MODIFY,           // 非签名进程修改系统目录DACL（CVE-2021-41379 提权 T1222）
    BA_IND_PROC_TRUSTEDINSTALLER_DUP,  // 复制TrustedInstaller句柄提权（T1134.003）
    BA_IND_FILE_RENAME,                // 文件重命名操作（用于追踪伪装/覆盖行为 T1036/T1222）
    BA_IND_MEM_SHELLCODE_DETECTED,     // 检测到shellcode特征（多家族深度分析+静态沙盒，评分制判定）
    BA_IND_FILE_INVALID_EXT_EXE,       // 创建非标准后缀名的可执行文件（非dll/exe/sys/com但有PE特征）
    BA_IND_FILE_HIDDEN_EXE,            // 创建隐藏的可执行文件
    BA_IND_FILE_SYSTEM_HIDDEN_EXE,     // 创建系统级隐藏的可执行文件
    BA_IND_FILE_HIDDEN_EXE_WITH_SIBLING, // 同目录下存在可执行文件时创建隐藏的可执行文件
    BA_IND_FILE_DLL_SIDE_LOAD_UNSIGNED,  // 未签名进程加载同目录未签名 DLL（侧载，低分 T1195.002）
    BA_IND_INVALID                     // Invalid/unknown indicator
} BA_INDICATOR;

// BA_MAX_INDICATORS已定义在文件顶部（第16行），不再重复定义

// 指标值（与 BA_INDICATOR 一一对应，用于数组索引与快速查找）
typedef enum _BA_INDICATOR_VALUE {
    BA_IV_INVALID = 0,
    BA_IV_DISK_MBR_WRITE,
    BA_IV_PROC_CRITICAL_PROCESS_KILL,
    BA_IV_PROC_SCRIPT_INTERPRETER,
    BA_IV_OFFICE_SPAWN_CMD,
    BA_IV_CERTUTIL_DOWNLOAD,
    BA_IV_BITSADMIN_TRANSFER,
    BA_IV_NET_USER_MODIFY,
    BA_IV_SVCHOST_ANOMALY,
    BA_IV_ICACLS_MODIFY,
    BA_IV_TASKKILL_SECURITY,
    BA_IV_MSIEXEC_SILENT_INSTALL,
    BA_IV_WMI_PERSISTENCE,
    BA_IV_MEM_CROSS_PROCESS_WRITE,
    BA_IV_MEM_INJECTION_CHAIN,
    BA_IV_MEM_PROCESS_HOLLOWING,
    BA_IV_PROC_RAISE_HARD_ERROR,
    BA_IV_PROC_SET_CRITICAL,
    BA_IV_PROC_APC_INJECTION,
    BA_IV_PROC_MAP_SECTION,
    BA_IV_MEM_POOLPARTY_FACTORY,
    BA_IV_MEM_POOLPARTY_WORK,
    BA_IV_MEM_POOLPARTY_WAIT,
    BA_IV_MEM_POOLPARTY_IO,
    BA_IV_MEM_POOLPARTY_ALPC,
    BA_IV_MEM_POOLPARTY_JOB,
    BA_IV_MEM_POOLPARTY_DIRECT,
    BA_IV_MEM_POOLPARTY_TIMER,
    BA_IV_MEM_ETW_REMOTE_ALLOC_EXECUTABLE,
    BA_IV_MEM_ETW_REMOTE_PROTECT_EXECUTABLE,
    BA_IV_MEM_ETW_REMOTE_WRITE_MEMORY,
    BA_IV_MEM_ETW_REMOTE_QUEUE_APC,
    BA_IV_MEM_ETW_REMOTE_SET_THREAD_CONTEXT,
    BA_IV_MEM_ETW_REMOTE_MAP_VIEW_EXECUTABLE,
    BA_IV_MEM_ETW_ALLOC_TO_PROTECT_CHAIN,
    BA_IV_MEM_ETW_WRITE_TO_PROTECT_CHAIN,
    BA_IV_MEM_DIRECT_SYSCALL,
    BA_IV_MEM_INDIRECT_SYSCALL,
    BA_IV_FILE_SELF_LOADING,
    BA_IV_MSHTA_EXECUTION,
    BA_IV_REGSVR32_EXECUTION,
    BA_IV_CONTROL_PANEL_ITEM,
    BA_IV_MAVINJECT_INJECTION,
    BA_IV_CMSTP_EXECUTION,
    BA_IV_MSDT_EXECUTION,
    BA_IV_SIGNED_BINARY_PROXY,
    BA_IV_APPLOCKER_BYPASS,
    BA_IV_NET_C2_CONNECT,
    BA_IV_NET_UNKNOWN_PORT,
    BA_IV_NET_SUSPICIOUS_DNS,
    BA_IV_NET_PROCESS_NETWORK,
    BA_IV_NET_LONG_CONNECTION,
    BA_IV_NTDLL_UNHOOK,
    BA_IV_NTDLL_REMAP,
    BA_IV_NTDLL_PATH_ANOMALY,
    BA_IV_FILE_BULK_WRITE,
    BA_IV_DCOM_REMOTE_ACTIVATION,
    BA_IV_DCOM_MMC20_SHELLEXEC,
    BA_IV_DCOM_SHELLWINDOWS,
    BA_IV_DCOM_EXCEL_DDE,
    BA_IV_DCOM_OUTLOOK_CREATEOBJECT,
    BA_IV_DCOM_CHILD_PROCESS,
    BA_IV_DCOM_WMI_REMOTE
} BA_INDICATOR_VALUE;


// ── 规则 ID 与版本 ──
typedef struct _BA_RULE_ID {
    ULONG RuleId;
    ULONG Version;
    ULONG Revision;
} BA_RULE_ID;

// ── 规则状态 ──
typedef enum _BA_RULE_STATE {
    BA_RS_DISABLED = 0,
    BA_RS_ENABLED,
    BA_RS_TESTING,
    BA_RS_DEPRECATED
} BA_RULE_STATE;

// ── 规则类型 ──
typedef enum _BA_RULE_TYPE {
    BA_RT_SIGNATURE = 0,
    BA_RT_BEHAVIORAL,
    BA_RT_ANOMALY,
    BA_RT_CORRELATION,
    BA_RT_ML
} BA_RULE_TYPE;

// ── 规则性能统计 ──
typedef struct _BA_RULE_STATS {
    ULONG RuleId;
    ULONG TriggerCount;
    ULONG TruePositiveCount;
    ULONG FalsePositiveCount;
    DOUBLE AvgScore;
    INT64 LastTriggered;
} BA_RULE_STATS, *PBA_RULE_STATS;

// ── 异常检测基线 ──
typedef struct _BA_BASELINE {
    INT64  Pid;
    BA_INDICATOR Indicator;
    DOUBLE Mean;
    DOUBLE StdDev;
    INT    SampleCount;
    INT64  LastUpdateTick;
} BA_BASELINE;

// ── 增强版威胁画像（含元数据）──
typedef struct _BA_RULE {
    BA_RULE_ID     RuleId;
    CHAR           Name[128];
    CHAR           ThreatClass[128];
    CHAR           Description[256];
    BA_RULE_TYPE   Type;
    BA_RULE_STATE  State;
    ULONG          Severity;
    ULONG          MitreTactic;
    ULONG          MitreTechnique;
    DOUBLE         RiskScore;
    DOUBLE         Threshold;
    INT            MinMatchCount;
    INT            IndicatorCount;
    BA_INDICATOR   Indicators[BA_MAX_INDICATORS];
    DOUBLE         Weights[BA_MAX_INDICATORS];
    BA_RULE_STATS  Stats;
} BA_RULE;

// ── 进程节点 ──
typedef struct _BA_PROCESS_NODE {
    INT64  pid;
    INT64  parentPid;
    CHAR   imagePath[BA_MAX_PATH];
    CHAR   commandLine[BA_MAX_CMDLINE]; /* 进程命令行，用于 taskkill 目标检测等 */
    INT64  createTickMs;        /* 进程创建时间（毫秒），用于判断 ProcessHollowing 等是否发生在创建初期 */
    INT    childCount;
    INT64  childPids[BA_MAX_CHILDREN];
    BOOLEAN isSystemSidProcess; /* 进程是否运行在 SYSTEM SID 下（在创建时通过 IsSystemProcessByEPROCESS 预计算），
                                 * 用于区分真正的系统进程与冒名病毒。仅 isSystemProcessByPath() 不够：
                                 * 病毒可命名 consent.exe 并投放至 System32，但无法以 SYSTEM 身份运行。 */
} BA_PROCESS_NODE;

// ── 注册表操作回滚跟踪常量 ──
#define BA_MAX_REG_OPS            1024  /* 扩容：256 -> 1024（堆分配） */
#define BA_REG_KEY_PATH_LEN       320   /* WCHAR count */
#define BA_REG_VALUE_NAME_LEN     64    /* WCHAR count */
#define BA_REG_BACKUP_DATA_LEN    1024  /* bytes */

// ── 存储事件 ──
typedef struct _BA_STORED_EVENT {
    INT64           tick;
    INT64           pid;
    INT64           parentPid;       /* 事件发生时该进程的父 PID（在记录时从进程树快照），
                                      * 用于进程树不可信（中间进程已退出）时仍能追溯祖先链 */
    BA_EVENT_CATEGORY category;
    CHAR            imagePath[BA_MAX_PATH];
    // ── 文件事件数据 ──
    CHAR            filePath[BA_MAX_PATH];
    CHAR            fileDir[BA_MAX_PATH];
    CHAR            fileName[BA_MAX_NAME];
    CHAR            fileExt[16];
    BA_FILE_OP      fileOp;
    BOOLEAN         isSigned;
    UCHAR           fileAttributes;     // FILE_ATTRIBUTE_* flags (FILE_ATTRIBUTE_HIDDEN/SYSTEM等)
    BOOLEAN         isPeFile;           // 文件头包含 MZ 签名（PE/COFF 可执行文件）
    // ── 注册表事件数据 ──
    CHAR            regPath[BA_MAX_PATH];
    CHAR            regValue[BA_MAX_NAME];
    BA_REG_OP       regOp;
    // ── 内存事件数据 ──
    CHAR            targetProcess[BA_MAX_NAME];
    INT64           targetPid;
    INT64           desiredAccess;
    BA_MEM_OP       memOp;
    BOOLEAN         isParentChild;  /* 源进程是否为目标进程的父进程（ProcessHollowing 限定条件） */
    BOOLEAN         isTargetSystemProcess;  /* 目标进程是否为 SYSTEM 进程（在锁外预计算，避免 DISPATCH_LEVEL 调用 SeQueryInformationToken） */
    BOOLEAN         targetIsSigned;         /* 目标进程是否已签名（在锁外预计算，用于互签检测：双签名进程互操作不视为注入） */
    PVOID           threadStartAddr;        /* 远程线程起始地址（用于 shellcode 注入检测，0 表示不适用） */
} BA_STORED_EVENT;

// ── 注册表操作回滚记录 ──
/* 记录进程对注册表值的修改/删除操作，并备份修改前的原始值。
 * 用户选择 Block 时，BehaviorRollbackChain 据此回滚（删除新增值 / 恢复被修改值）。
 * 仅备份 SetValue / DeleteValue（常见持久化与篡改向量），DeleteKey 不备份（整键恢复代价过高）。 */
typedef struct _BA_REG_OP_RECORD {
    INT64    pid;
    WCHAR    keyPath[BA_REG_KEY_PATH_LEN];   /* 内核格式完整键路径 \REGISTRY\MACHINE\... */
    USHORT   keyPathLen;                      /* 实际 WCHAR 数（不含 null） */
    WCHAR    valueName[BA_REG_VALUE_NAME_LEN];
    USHORT   valueNameLen;
    BA_REG_OP regOp;
    BOOLEAN  valid;
    BOOLEAN  hadExistingValue;               /* 修改前是否存在值 */
    ULONG    originalType;                   /* 原始值类型 REG_DWORD/REG_SZ... */
    ULONG    originalDataLen;                /* 原始值数据字节数 */
    UCHAR    originalData[BA_REG_BACKUP_DATA_LEN];
} BA_REG_OP_RECORD;

// ── 威胁判定结果 ──
/* 注意: 必须使用 pack(1) 与客户端 shared/Common.h 中的定义保持一致，
 * 否则内核-用户态结构布局不匹配，RtlCopyMemory 传递数据时字段偏移错位 */
#pragma pack(push, 1)
typedef struct _BA_THREAT_RESULT {
    INT    isThreat;
    INT64  pid;
    CHAR   processPath[BA_MAX_PATH];
    CHAR   threatClass[128];
    CHAR   description[256];
    DOUBLE confidence;
    INT    evidenceCount;
    CHAR   evidence[BA_MAX_EVIDENCE][128];
} BA_THREAT_RESULT;
#pragma pack(pop)

// ── 证据条目 ──
typedef struct _BA_EVIDENCE_ENTRY {
    INT  count;
    CHAR items[BA_MAX_EVIDENCE][128];
} BA_EVIDENCE_ENTRY;

// ── 进程统计信息 ──
typedef struct _BA_STATS {
    INT processCount;
    INT historyCount;
    INT threatCount;
    INT indicatorCount;
    INT64 tickCounter;
} BA_STATS;

// ── 测试用例结果 ──
typedef struct _BA_TEST_CASE_RESULT {
    ULONG RuleId;
    BOOLEAN Passed;
    DOUBLE Score;
    DOUBLE ExpectedScore;
    DOUBLE Tolerance;
    INT MatchedIndicators;
    INT ExpectedIndicators;
    CHAR Description[256];
} BA_TEST_CASE_RESULT;

// ── 测试套件结果 ──
typedef struct _BA_TEST_SUITE_RESULT {
    INT TotalTests;
    INT PassedTests;
    INT FailedTests;
    DOUBLE AvgScore;
    DOUBLE AvgExecutionTimeMs;
} BA_TEST_SUITE_RESULT;

// ── 误报缓解：进程白名单 ──
typedef struct _BA_WHITELIST_ENTRY {
    CHAR ImagePath[BA_MAX_PATH];
    CHAR Publisher[BA_MAX_NAME];
    BOOLEAN IsSecurityProduct;
    BOOLEAN IsMicrosoftSigned;
    BOOLEAN IsSystemProcess;
    INT64 ExpireTickMs;
} BA_WHITELIST_ENTRY;

// ── 误报缓解：规则例外 ──
typedef struct _BA_EXCEPTION_ENTRY {
    ULONG RuleId;
    CHAR ImagePath[BA_MAX_PATH];
    CHAR Condition[256];
    INT64 ExpireTickMs;
    BOOLEAN Active;
} BA_EXCEPTION_ENTRY;

// ── 误报缓解：可信发布者 ──
typedef struct _BA_TRUSTED_PRODUCTOR {
    CHAR PublisherName[BA_MAX_NAME];
    CHAR CertificateSubject[BA_MAX_PATH];
    BOOLEAN IsMicrosoftRoot;
    BOOLEAN IsKnownSecurityVendor;
    DOUBLE TrustScore;
} BA_TRUSTED_PRODUCTOR;

// ── 误报缓解：签名软件跟踪 ──
typedef struct _BA_SIGNED_PRODUCTOR {
    CHAR ImagePath[BA_MAX_PATH];
    CHAR Publisher[BA_MAX_NAME];
    INT64 FirstSeenTickMs;
    INT64 LastSeenTickMs;
    ULONG SeenCount;
    BOOLEAN IsWhitelisted;
} BA_SIGNED_PRODUCTOR;

// ── 误报缓解：规则抑制 ──
typedef struct _BA_RULE_SUPPRESSION {
    ULONG RuleId;
    INT64 Pid;
    CHAR ImagePath[BA_MAX_PATH];
    INT64 StartTickMs;
    INT64 EndTickMs;
    CHAR Reason[256];
} BA_RULE_SUPPRESSION;

// ── 误报缓解：时间窗口 ──
typedef struct _BA_LOOKBACK_WINDOW {
    BA_INDICATOR Indicator;
    INT64 WindowMs;
    INT MinCount;
    BOOLEAN RequireDistinctPids;
} BA_LOOKBACK_WINDOW;

// ── 误报缓解：进程信誉 ──
typedef struct _BA_PROCESS_REPUTATION {
    INT64 Pid;
    CHAR ImagePath[BA_MAX_PATH];
    DOUBLE ReputationScore;
    BOOLEAN IsKnownGood;
    BOOLEAN IsKnownBad;
    INT64 FirstSeenTickMs;
    INT64 LastUpdatedTickMs;
} BA_PROCESS_REPUTATION;

// ── 误报缓解：证据质量评估 ──
typedef struct _BA_EVIDENCE_QUALITY {
    BA_INDICATOR Indicator;
    DOUBLE QualityScore;
    BOOLEAN RequiresConfirmation;
    BOOLEAN IsTransient;
    INT Weight;
} BA_EVIDENCE_QUALITY;

// 公开 API
VOID BehaviorAnalysisInit();
VOID BehaviorAnalysisCleanup();

// 行为检测总开关（由用户态 IOCTL_SET_BEHAVIOR_DETECTION_ENABLED 控制）
extern BOOLEAN g_bBehaviorDetectionEnabled;
VOID BehaviorSetDetectionEnabled(BOOLEAN enabled);

extern const DOUBLE g_baIndicatorScores[];
extern BA_PROCESS_NODE g_baProcTree[];
extern INT g_baProcCount;
extern INT64 g_baIndicatorPids[];
extern INT g_baPidIndicators[][BA_MAX_INDICATORS];
extern ULONG g_baPidSyscallTypes[];
extern INT g_baIndicatorCount;
extern BA_EVIDENCE_ENTRY g_baEvidence[];
extern INT64 baEtwTickMs(VOID);
extern BA_PROCESS_REPUTATION g_baReputations[];
extern BA_SIGNED_PRODUCTOR g_baSignedProducers[];

// 记录进程创建，加入进程树
// commandLine 可为 NULL（无命令行信息时）
VOID BehaviorRecordProcessCreate(INT64 pid, INT64 parentPid, const CHAR* imagePath, const CHAR* commandLine);
// 记录进程退出，移除出进程树
VOID BehaviorRecordProcessExit(INT64 pid);
// 记录文件系统事件记录文件事件
VOID BehaviorRecordFileEvent(
    INT64 pid, const CHAR* imagePath,
    const CHAR* filePath, const CHAR* fileDir, const CHAR* fileName, const CHAR* fileExt,
    BA_FILE_OP fileOp, BOOLEAN isSigned, UCHAR fileAttributes, BOOLEAN isPeFile);

// 记录注册表事件
VOID BehaviorRecordRegistryEvent(
    INT64 pid, const CHAR* imagePath,
    const CHAR* regPath, const CHAR* regValue,
    BA_REG_OP regOp);

// 记录内存事件
VOID BehaviorRecordMemoryEvent(
    INT64 pid, const CHAR* imagePath,
    const CHAR* targetProcess, INT64 targetPid, INT64 desiredAccess,
    BA_MEM_OP memOp,
    BOOLEAN isParentChild,
    PVOID threadStartAddr);

// 处理 ETW Threat-Intelligence 内存事件（用户态 ETW Consumer 通过 IOCTL 下发）
VOID BehaviorHandleEtwMemoryEvent(PETW_MEMORY_EVENT_DATA pEvent);

// 处理 ETW 网络事件（用户态 ETW Consumer 通过 IOCTL 下发）
VOID BehaviorHandleEtwNetworkEvent(PETW_NETWORK_EVENT_DATA pEvent);

// 处理 ETW syscall 事件（direct/indirect syscall 检测）
VOID BehaviorHandleEtwSyscallEvent(PETW_SYSCALL_EVENT_DATA pEvent);

// 处理 ntdll 重载/Unhook 事件（用户态检测后下发给驱动做行为评估）
VOID BehaviorHandleNtdllReloadEvent(PNTDLL_RELOAD_EVENT_DATA pEvent);

// 处理 DCOM 横向移动事件（用户态检测后下发给驱动做行为评估）
VOID BehaviorHandleDcomEvent(PDCOM_EVENT_DATA pEvent);

// 评估单个进程
VOID BehaviorEvaluateProcess(INT64 pid, BA_THREAT_RESULT* result);

// ── 无签名脚本宿主检测（独立通道，更低阈值） ──
VOID BehaviorCheckUnsignedScriptHost(INT64 pid, INT64 parentPid, const CHAR* imagePath);

// 评估所有活跃进程
VOID BehaviorEvaluateAll(BA_THREAT_RESULT* results, INT maxResults, INT* outCount);

// 获取统计信息
VOID BehaviorGetStats(BA_STATS* stats);

// 获取进程树
const BA_PROCESS_NODE* BehaviorGetProcessTree(_Out_ INT* count);

// 获取历史事件
const BA_STORED_EVENT* BehaviorGetHistory(_Out_ INT* count);

// 检查进程是否为已知系统关键进程（精确匹配短名）
BOOLEAN IsCriticalSystemProcess(PEPROCESS process);

// 判断进程短名是否为已知 Windows 系统进程（精确匹配小写名称）
BOOLEAN IsKnownSystemProcessName(const CHAR* nameLower);

// 检查进程路径是否为系统进程
BOOLEAN isSystemProcessByPath(const CHAR* imagePath);

// 三重验证（路径+名称+SYSTEM SID）判断是否为真正的系统进程
// 防止病毒通过改名/投放冒充系统进程
BOOLEAN isGenuineSystemProcess(int idx, const CHAR* imagePath);

// 实时行为检查：事件发生后立即评估，超过阈值则挂起进程并告警
// 返回: STATUS_SUCCESS = 允许, STATUS_ACCESS_DENIED = 阻止/超时
NTSTATUS BehaviorCheckAndAlert(INT64 pid, const CHAR* imagePath);

// 异步定时器线程（卡巴斯基思路：回调同步记录，定时器异步分析）
VOID BehaviorStartTimerThread(VOID);
VOID BehaviorStopTimerThread(VOID);

// ── 文件释放跟踪与清除 ──
// 记录进程创建的新文件（由 FileFilter post-create 回调调用）
VOID BehaviorRecordDroppedFile(INT64 pid, PUNICODE_STRING filePath);

// 清除进程树释放的新文件（终止决策后调用）
// 仅对无签名/脚本进程启用，排除系统文件，跳过进程本体
VOID BehaviorCleanupDroppedFiles(INT64* treePids, int treePidCount,
    const CHAR* rootImagePath, const CHAR* rootProcessName);

// ── 注册表操作回滚跟踪 ──
// 在注册表 pre-callback 中调用，备份 SetValue/DeleteValue 操作前的原始值。
// keyPath 为内核格式完整键路径（\REGISTRY\MACHINE\...），valueName 可为 NULL。
VOID BehaviorRecordRegOpWithBackup(
    INT64 pid, const CHAR* imageName,
    PUNICODE_STRING keyPath,
    PUNICODE_STRING valueName,
    BA_REG_OP regOp);

// ── 威胁回滚（参考杀软回滚机制）──
// 用户选择 Block 后调用：沿祖先链追溯至 explorer（不含 explorer），对链上每个进程
// （含根进程及其子孙树）执行的文件释放与注册表修改进行回滚（删除/恢复）。
// 仅回滚由链上进程执行的操作，绝不回滚无关进程。
// 进程树不可信（中间进程已退出）时，依据事件记录中保存的 parentPid 重建祖先链。
VOID BehaviorRollbackChain(INT64 rootPid,
    const CHAR* rootImagePath, const CHAR* rootProcessName,
    INT64* treePids, int treePidCount);

// ── 威胁回滚（分阶段：收集 → 用户确认 → 执行）──
// BehaviorCollectRollbackItems: 收集回滚项（文件+注册表）到 BA_ROLLBACK_LIST，
//   不执行任何删除/恢复操作。outList 调用者分配。
VOID BehaviorCollectRollbackItems(INT64 rootPid,
    const CHAR* rootImagePath, const CHAR* rootProcessName,
    const CHAR* threatClass,
    INT64* treePids, int treePidCount,
    PBA_ROLLBACK_LIST outList);

// BehaviorExecuteRollbackSelected: 根据 userSelection 执行选中的回滚项。
//   selected[i]=1 表示执行第 i 项（对应 outList->items[i]）。
VOID BehaviorExecuteRollbackSelected(
    const BA_ROLLBACK_LIST* rollbacList,
    const BA_ROLLBACK_SELECTION* userSelection);

// ── 注册表回调重入保护深度计数器 ──
// 驱动自身发起的注册表访问（备份查询 / 回滚恢复）会触发回调重入，
// 此计数器 >0 时回调跳过记录与检测，避免污染事件日志与误报。
extern volatile LONG g_regDriverAccessDepth;

// ── 注入检测Alert（异步）──
// 检测到注入行为时调用：先剥离权限阻止注入，再异步挂起源进程并发送alert
// 此函数内部会：
//   1. 检查源进程是否为目标进程的父进程（正常进程创建，放行）
//   2. 如果不是父子关系 → 入队work item → 挂起源进程 → 发送alert → 等待用户决策
//   3. Block: 终止源进程, Allow: 恢复源进程
// 注意：此函数异步执行，回调中调用后立即返回，不阻塞PreCreateHandle
// threadStartAddr：远程线程起始地址（shellcode 内存证据，无则传 NULL）
VOID BehaviorHandleInjectionAlertAsync(
    INT64 sourcePid, const CHAR* sourceName,
    INT64 targetPid, const CHAR* targetName,
    const CHAR* injectType,
    INT64 threadId,
    PVOID threadStartAddr);

// ── 检查地址是否落在目标进程已加载镜像范围内（shellcode 注入检测辅助）──
// 返回 TRUE 表示地址在某个已加载 DLL/EXE 范围内（合法），
// 返回 FALSE 表示地址在非镜像内存中（shellcode 注入可疑）。
BOOLEAN BehaviorIsAddressInLoadedModule(
    INT64 targetPid,
    PVOID address);

// ── 检查地址是否落在非镜像可执行内存（Elastic shellcode-thread 判定）──
// 判定条件（对齐 Elastic kernel_shellcode_event）：
//   - State == MEM_COMMIT
//   - Protect 含 PAGE_EXECUTE_*（EXECUTE_READ / EXECUTE_READWRITE 等）
//   - Type != MEM_IMAGE（无磁盘 PE 镜像映射，unbacked）
// 返回 TRUE = unbacked executable（shellcode 注入强证据）
// isExecutable 输出该页是否可执行（非 NULL 时填充）。
BOOLEAN BehaviorCheckStartAddressUnbacked(
    INT64 targetPid,
    PVOID address,
    BOOLEAN* isExecutable);

// ── Trampoline 跳板检测：线程 Rip 采样（Elastic 博客公开对抗手段）──
// StartAddress 指向合法模块导出、内部 jmp 到 shellcode 时，unbacked 判断失效；
// 通过采样线程上下文 Rip，若 Rip 落入非镜像可执行内存则仍判定可疑。
// 返回 TRUE = 当前 Rip 处于非镜像可执行区（trampoline 强证据）。
// 采样失败/线程不可访问 → 返回 FALSE（无证据，保守放行）。
BOOLEAN BehaviorIsThreadRipInUnbackedExecutable(
    INT64 threadId,
    INT64 targetPid);

// ── 检测 EDR-Freeze: WerFaultSecure.exe 被非 WER 服务启动 ──
// 在 ProcessCreateNotifyRoutine 中调用，匹配 Elastic 规则
// defense_evasion_edr_freeze_via_werfaultsecure.toml
BOOLEAN BehaviorDetectEdrFreeze(
    INT64 newPid,
    const CHAR* newProcName,
    const CHAR* newProcPath,
    const CHAR* cmdLine,
    INT64 parentPid,
    const CHAR* parentProcName,
    const CHAR* parentProcPath);

// ── 按 TID 挂起线程（用于 ThreadCreateNotifyRoutine 立即阻止远程线程）──
NTSTATUS BehaviorSuspendThreadById(HANDLE ThreadId);

// ── 判断是否为正常进程创建（源进程是目标进程的父进程）──
BOOLEAN BehaviorIsLegitimateProcessCreation(INT64 childPid, INT64 parentPid);

// ── 判断目标是否为源进程同一家族的最近创建子进程 ──
// 用于消除 Edge/Chrome 等多进程浏览器中兄弟进程打开 helper 子进程导致的误报。
BOOLEAN BehaviorIsRecentSameFamilyProcess(INT64 sourcePid, INT64 targetPid);

// ── 恶意软件家族归类（低危指标辅助分类）──
// 当 BehaviorCheckAndAlert 判定为威胁后调用，检查进程树中是否出现家族特征指标，
// 若出现则将 threatClass 覆盖为对应家族（如 SilverFox）。
// threatClassBuf/threatClassBufLen 为待修改的 threatClass 缓冲区，
// descriptionBuf/descriptionBufLen 为待修改的 description 缓冲区。
// 返回 TRUE 表示已归类（缓冲区被覆盖），FALSE 表示未归类（保持原值）。
BOOLEAN BehaviorClassifyMalwareFamily(
    INT64* treePids, int treePidCount,
    CHAR* threatClassBuf, ULONG threatClassBufLen,
    CHAR* descriptionBuf, ULONG descriptionBufLen);

// ── 规则管理 API ──
BA_RULE* BehaviorGetRule(ULONG ruleId);
ULONG BehaviorGetRuleCount(VOID);
NTSTATUS BehaviorSetRuleState(ULONG ruleId, BA_RULE_STATE state);
BA_RULE_STATE BehaviorGetRuleState(ULONG ruleId);
VOID BehaviorGetRuleStats(ULONG ruleId, BA_RULE_STATS* stats);
VOID BehaviorResetRuleStats(ULONG ruleId);

// ── 异常检测基线 API ──
NTSTATUS BehaviorUpdateBaseline(INT64 pid, BA_INDICATOR indicator, DOUBLE value);
BOOLEAN BehaviorDetectAnomaly(INT64 pid, BA_INDICATOR indicator, DOUBLE value, DOUBLE* zScore);
VOID BehaviorCleanupBaseline(INT64 pid);

// ── 统一日志 API ──
VOID BehaviorLogDebug(const CHAR* format, ...);
VOID BehaviorLogInfo(const CHAR* format, ...);
VOID BehaviorLogWarning(const CHAR* format, ...);
VOID BehaviorLogError(const CHAR* format, ...);

// ── 模块化指标提取 API ──
VOID BehaviorExtractProcessIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractFileIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractRegistryIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractMemoryIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractCrossCategoryIndicators(int idx, const BA_STORED_EVENT* ev);

// ── 评分引擎 API ──
DOUBLE BehaviorGetIndicatorBaseScore(BA_INDICATOR id);
VOID BehaviorScoreProcess(INT64 pid, BA_THREAT_RESULT* result);
VOID BehaviorAggregateTreeIndicators(INT64 rootPid, DOUBLE* combined, int* pDistinctCnt, DOUBLE* pTotalScore);
VOID BehaviorAggregateTreeEvidence(INT64 rootPid, BEHAVIOR_DETECTED_RESPONSE* alertInfo);

/* 进程树查找辅助（供多个 .c 文件使用） */
int findProc(INT64 pid);
int findPidIndex(INT64 pid);

// ── 规则测试框架 API ──
NTSTATUS BehaviorRunRuleTest(ULONG ruleId, BA_TEST_CASE_RESULT* result);
NTSTATUS BehaviorRunAllRuleTests(BA_TEST_SUITE_RESULT* suiteResult);
NTSTATUS BehaviorBenchmarkEvaluation(INT iterations, DOUBLE* avgTimeMs);
NTSTATUS BehaviorValidateRules(CHAR* errorBuffer, ULONG bufferSize);

// ── 误报缓解 API ──
// 白名单管理
NTSTATUS BehaviorAddWhitelistEntry(const BA_WHITELIST_ENTRY* entry);
NTSTATUS BehaviorRemoveWhitelistEntry(const CHAR* imagePath);
BOOLEAN BehaviorIsWhitelisted(const CHAR* imagePath);

// 进程签名检查
BOOLEAN BaIsProcessSigned(INT64 pid);

// 从外部模块记录提权指标并触发告警（CVE-2021-41379 / TrustedInstaller 提权）
VOID BehaviorRecordPrivilegeEscalationIndicator(
    INT64 pid,
    const CHAR* imageName,
    const CHAR* targetPath,
    BA_INDICATOR indicatorId,
    const CHAR* evidenceText);

// 记录 DLL 侧载指标（同目录未签名 DLL）：
// - 签名进程加载未签名 DLL：BA_IND_FILE_DLL_SIDE_LOAD（标准分）
// - 未签名进程加载未签名 DLL：BA_IND_FILE_DLL_SIDE_LOAD_UNSIGNED（低分）
VOID BehaviorRecordDllSideLoad(INT64 pid, const CHAR* dllPath, BOOLEAN processSigned);

// 规则例外管理
NTSTATUS BehaviorAddException(const BA_EXCEPTION_ENTRY* exception);
NTSTATUS BehaviorRemoveException(ULONG ruleId, const CHAR* imagePath);
BOOLEAN BehaviorCheckException(ULONG ruleId, const CHAR* imagePath);

// 规则抑制管理
NTSTATUS BehaviorSuppressRule(ULONG ruleId, INT64 pid, INT64 durationMs, const CHAR* reason);
BOOLEAN BehaviorIsRuleSuppressed(ULONG ruleId, INT64 pid);

// 字符串辅助函数
int kStrLen(const CHAR* s);
int kStrCmp(const CHAR* a, const CHAR* b);
int kStrNCmp(const CHAR* a, const CHAR* b, int n);
int kStrIStrLen(const CHAR* haystack, int hayLen, const CHAR* needle, int needleLen);
int kStrStrLen(const CHAR* haystack, int hayLen, const CHAR* needle, int needleLen);
int kStrStr(const CHAR* haystack, const CHAR* needle);
int kStrEndsWith(const CHAR* str, const CHAR* suffix);
int kStrToInt64(const CHAR* str, INT64* out);

