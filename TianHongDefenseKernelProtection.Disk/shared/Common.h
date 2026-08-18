#pragma once
/* ============================================================================
 * Common.h - Shared definitions for driver and user mode
 * ========================================================================== */

#ifdef _KERNEL_MODE
#include <fltKernel.h>
#include <ntstrsafe.h>
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#else
#include <windows.h>
#include <winioctl.h>
#ifndef MAX_PATH
#define MAX_PATH 260
#endif
#endif

// -- Driver Name --
#define DEVICE_NAME      L"\\Device\\TianHongHips"
#define SYMLINK_NAME     L"\\??\\TianHongHips"
#define DRIVER_PREFIX    "[TianHongHips] "

// -- Shared service / file / user-mode device names --
#define THSD_SERVICE_NAME_A       "TianHongHips"
#define THSD_SERVICE_NAME_W       L"TianHongHips"
#define THSD_INSTANCE_NAME_A      "TianHongHipsInstance"
#define THSD_INSTANCE_NAME_W      L"TianHongHipsInstance"
#define THSD_USER_DEVICE_PATH_W   L"\\\\.\\TianHongHips"
#define THSD_DRIVER_FILENAME_A    "TianHongDefenseKernelProtection.sys"
#define THSD_DRIVER_FILENAME_W    L"TianHongDefenseKernelProtection.sys"

// -- Build Mode: TH_RELEASE_BUILD=1 suppresses all debug output --
#define TH_RELEASE_BUILD  0

// -- Max Limits --
#define MAX_RULES              1024
#define MAX_PROTECTED_PIDS     64
#define MAX_FILE_RULES         1024
#define MAX_PATH_LEN            1024
#define MAX_VALUE_NAME_LEN      256
#define MAX_DETECT_VALUE_LEN    256
#define MAX_RULE_DATA_LEN       9500
/* MAX_CTL_PACKET_LEN 必须足够大以容纳 COMM_RULE_DETECTED（header 1296 字节
 * + Data 字段）。RULE_REG_DETECTED_RESPONSE（9218 字节）和
 * RULE_FILE_DETECTED_RESPONSE（5409 字节）需写入 COMM_RULE_DETECTED.Data。
 * 原值 10240 不足：1296 + 9218 = 10514 > 10240，导致 RtlZeroMemory 溢出
 * IRP SystemBuffer，损坏相邻池块元数据 → RBTree 损坏 → 0x139 蓝屏。 */
#define MAX_CTL_PACKET_LEN      16384

// -- IOCTL Codes --
#define IOCTL_PROTECT_PROCESS                       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_RULE                              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RULE_DETECTED_REQUEST                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_RULE_DETECTED_SEND_USER_RESPONSE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ADD_FILE_RULE                         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_FILE_RULE                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_FILE_RULE_STATS                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_FILE_RULES                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_RULE                           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_RULES                           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_RESPONSE_CACHE                    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLEAR_PROTECTED_PIDS                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x80B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_ANALYSIS_EVALUATE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_ANALYSIS_GET_STATS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_ANALYSIS_CLEAR               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PREPARE_UNLOAD                        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_DLL_INJECT_PATH                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_R3_PROTECTION_ENABLED            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_BEHAVIOR_DETECTION_ENABLED       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PROCESS_PROTECTION_ENABLED       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_TRUSTED_PID                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SYNC_WHITELIST_TO_DRIVER             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PROCESS_PPL                      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_ETW_MEMORY_EVENT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_ETW_NETWORK_EVENT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_ETW_SYSCALL_EVENT            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_NTDLL_RELOAD_EVENT           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_UNSIGNED_DLL_SCAN                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_SILENT_MODE                       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_MEMORY_PROTECTION_ENABLED         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_DCOM_EVENT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_DCOM_PROTECTION_ENABLED          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ── 动态行为规则 IOCTL（重构方案 Phase 1）──
#define IOCTL_BA_LOAD_DYNAMIC_RULE                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_REMOVE_DYNAMIC_RULE               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_CLEAR_DYNAMIC_RULES               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_SET_DYNAMIC_RULE_STATE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x829, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_GET_DYNAMIC_RULE_STATS            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_GET_DYNAMIC_RULE_LIST             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_GET_DYNAMIC_RULE_VERSION          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_REPORT_FEEDBACK                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82D, METHOD_BUFFERED, FILE_ANY_ACCESS)

// ── 新增威胁检测 IOCTL（SilverFox/AVBypass/Rootkit/Exploit）──
#define IOCTL_SET_SILVERFOX_ENABLED                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_AVBYPASS_ENABLED                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82F, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -- Disk Filter IOCTL Codes (TianHongHips.Disk driver) --
#define IOCTL_DISK_FILTER_SET_ENABLED              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_POLL_ALERT               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_SEND_RESPONSE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_GET_STATUS               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_POLL_LOG                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -- Disk Filter Driver Names --
#define DISK_DEVICE_NAME           L"\\Device\\TianHongDiskFilter"
#define DISK_SYMLINK_NAME          L"\\??\\TianHongDiskFilter"
#define DISK_DRIVER_PREFIX         "[TianHongHips.Disk] "
#define THSD_DISK_SERVICE_NAME_A   "TianHongHips.Disk"
#define THSD_DISK_SERVICE_NAME_W   L"TianHongHips.Disk"
#define THSD_DISK_USER_DEVICE_PATH_W  L"\\\\.\\TianHongDiskFilter"
#define THSD_DISK_DRIVER_FILENAME_A   "TianHongDefenseKernelProtection.Disk.sys"
#define THSD_DISK_DRIVER_FILENAME_W   L"TianHongDefenseKernelProtection.Disk.sys"

// -- Network Filter IOCTL Codes (TianHongHips.Network driver) --
#define IOCTL_NETWORK_SET_ENABLED                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_POLL_EVENT                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_GET_STATUS                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_ADD_DOH_SERVER                CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_CLEAR_DOH_SERVERS             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -- Network Filter Driver Names --
#define NETWORK_DEVICE_NAME          L"\\Device\\TianHongNetworkFilter"
#define NETWORK_SYMLINK_NAME         L"\\??\\TianHongNetworkFilter"
#define NETWORK_DRIVER_PREFIX        "[TianHongHips.Network] "
#define THSD_NETWORK_SERVICE_NAME_A   "TianHongHips.Network"
#define THSD_NETWORK_SERVICE_NAME_W   L"TianHongHips.Network"
#define THSD_NETWORK_USER_DEVICE_PATH_W  L"\\\\.\\TianHongNetworkFilter"
#define THSD_NETWORK_DRIVER_FILENAME_A   "TianHongDefenseKernelProtection.Network.sys"
#define THSD_NETWORK_DRIVER_FILENAME_W   L"TianHongDefenseKernelProtection.Network.sys"

// -- Network event types --
#define NET_EVENT_TCP_CONNECT         1
#define NET_EVENT_UDP_SEND            2
#define NET_EVENT_DOH_CONNECT         3   /* 连接到已知 DoH 服务器 */
#define NET_EVENT_HTTP_POST_LARGE     4   /* HTTP POST 大流量 */
#define NET_EVENT_DNS_TUNNEL          5   /* DNS 隧道检测 */
#define NET_EVENT_C2_PORT             6   /* 连接到已知 C2 端口 */

// -- Network event data (kernel -> user shared) --
#pragma pack(push, 8)
typedef struct _NETWORK_EVENT_DATA {
    INT64   CallerPid;              /* 发起网络操作的进程 PID */
    ULONG   EventType;             /* NET_EVENT_* */
    ULONG   Protocol;              /* IPPROTO_TCP=6, IPPROTO_UDP=17 */
    ULONG   LocalPort;             /* 本地端口 */
    ULONG   RemotePort;            /* 远程端口 */
    UCHAR   RemoteAddress[16];     /* IPv4/IPv6 */
    ULONG   RemoteAddressType;     /* 0=IPv4, 1=IPv6 */
    ULONG   IsOutbound;            /* TRUE=出站 */
    ULONG   ProcessNameOffset;     /* 进程名在 Payload 中的偏移 */
    ULONG   PayloadSize;           /* Payload 有效字节数 */
    UCHAR   Payload[256];           /* 进程名 + URL/域名等上下文 */
} NETWORK_EVENT_DATA, *PNETWORK_EVENT_DATA;
#pragma pack(pop)

// -- DoH server entry (user -> kernel) --
#pragma pack(push, 8)
typedef struct _DOH_SERVER_ENTRY {
    UCHAR   AddressType;           /* 0=IPv4, 1=IPv6, 2=domain name */
    UCHAR   Address[64];           /* IP 地址或域名 */
    ULONG   Port;                  /* 端口（通常 443） */
} DOH_SERVER_ENTRY, *PDOH_SERVER_ENTRY;
#pragma pack(pop)

// -- MBR protection: boot region sectors 0-62 (31KB, covers MBR + gap before first partition) --
#define MBR_PROTECTION_SECTOR_COUNT   63

// -- ETW Threat-Intelligence memory event (kernel <-> user shared) --
#pragma pack(push, 8)
typedef struct _ETW_MEMORY_EVENT_DATA {
    INT64   CallerPid;          // Process that initiated the operation
    INT64   TargetPid;          // Remote target process (0 if local)
    INT64   BaseAddress;        // Allocated/protected base address
    INT64   RegionSize;         // Region size in bytes
    ULONG   AllocationType;     // NtAllocateVirtualMemory AllocationType (MEM_COMMIT etc.)
    ULONG   Protection;         // PAGE_EXECUTE_* / PAGE_READWRITE etc.
    ULONG   EventId;            // ETW event ID: 1=AllocVM remote, 2=ProtectVM remote, etc.
    ULONG   PayloadSize;        // 实际捕获的内存内容字节数
    UCHAR   Payload[256];       // 远程写入/保护内存的前 256 字节（用于 shellcode 深度分析）
} ETW_MEMORY_EVENT_DATA, *PETW_MEMORY_EVENT_DATA;

// -- ETW network event for C2 detection (kernel <-> user shared) --
typedef struct _ETW_NETWORK_EVENT_DATA {
    INT64   CallerPid;          // Process that initiated the network operation
    ULONG   EventId;            // 1=TCP connect, 2=TCP accept, 3=UDP send, 4=DNS query
    ULONG   Protocol;           // IPPROTO_TCP=6, IPPROTO_UDP=17
    ULONG   LocalPort;          // Host byte order
    ULONG   RemotePort;         // Host byte order
    UCHAR   RemoteAddress[16];  // IPv4/IPv6 address
    ULONG   RemoteAddressType;  // 0=IPv4, 1=IPv6
    ULONG   IsOutbound;         // TRUE=outbound, FALSE=inbound
    ULONG   ProcessNameOffset;  // Offset to process name in payload
    ULONG   PayloadSize;        // Valid payload bytes
    UCHAR   Payload[128];       // Process name + extra context
} ETW_NETWORK_EVENT_DATA, *PETW_NETWORK_EVENT_DATA;

// -- ETW syscall event for direct/indirect syscall detection (kernel <-> user shared) --
typedef struct _ETW_SYSCALL_EVENT_DATA {
    INT64   CallerPid;                  // Process that made the syscall
    INT64   ThreadId;                   // Thread ID
    INT64   ReturnAddress;              // RIP in user mode before entering kernel
    INT64   SyscallInstructionAddress;  // Address of syscall/sysenter instruction
    INT64   CallOriginAddress;          // Address that called/jmp'd to the syscall instruction (call stack top)
    ULONG   SyscallNumber;              // Windows syscall number
    ULONG   EventId;                    // ETW provider event ID
    ULONG   IsDirectSyscall;            // Return address module is not ntdll.dll (or unknown)
    ULONG   IsIndirectSyscall;          // Return address is in ntdll.dll but call origin is not
    ULONG   IsHookedSyscall;            // Syscall number is commonly hooked by R3 EDR/security software
    CHAR    ReturnAddressModule[64];    // Module name containing ReturnAddress (e.g., "ntdll.dll")
    CHAR    SyscallInstructionModule[64]; // Module name containing syscall instruction
    CHAR    ProcessName[64];            // Source process image name
} ETW_SYSCALL_EVENT_DATA, *PETW_SYSCALL_EVENT_DATA;

// -- Ntdll reload / unhook detection event (kernel -> user) --
#pragma pack(push, 8)
typedef struct _NTDLL_RELOAD_EVENT_DATA {
    INT64   ProcessId;                // Target process PID
    INT64   ParentProcessId;          // Parent process PID (0 if unknown)
    ULONG_PTR ImageBase;              // Base address of loaded ntdll.dll
    ULONG   ImageSize;                // Size of ntdll.dll image
    ULONG   LoadSequence;             // Load sequence number (increments per load)
    ULONG   Flags;                    // Reload flags: UNHOOK/REMAP/PATH
    ULONG   IsFromSystemPath;         // TRUE if loaded from system directory
    ULONG   IsHooked;                 // TRUE if ntdll appears to be hooked (based on heuristic)
    ULONG   ReloadCount;              // Number of times ntdll has been reloaded in this process
    INT64   EventSequence;            // 全局递增事件序列号
    CHAR    FullImagePath[MAX_PATH];  // Full path to loaded ntdll.dll
    CHAR    ProcessImagePath[MAX_PATH]; // Full path to the process executable
    CHAR    ProcessName[64];          // Process image name
} NTDLL_RELOAD_EVENT_DATA, *PNTDLL_RELOAD_EVENT_DATA;
#pragma pack(pop)

// -- DCOM lateral movement detection event (R3 -> kernel) --
#pragma pack(push, 8)
typedef struct _DCOM_EVENT_DATA {
    INT64   CallerPid;              // Process that initiated DCOM activation
    INT64   TargetPid;              // Target process spawned via DCOM (0 if unknown)
    INT64   ParentPid;              // Parent process PID
    ULONG   EventType;              // 1=MMC20.Application, 2=ShellWindows, 3=ShellBrowserWindow, 4=Excel.Application, 5=Outlook.Application, 6=Generic DCOM child
    ULONG   IsRemoteActivation;     // TRUE if DCOM activation came from remote machine
    CHAR    CallerProcessName[64];  // Process that initiated the DCOM call
    CHAR    TargetProcessName[64];  // Process spawned via DCOM
    CHAR    TargetProcessPath[MAX_PATH]; // Full path of target process
    CHAR    DcomObjectCLSID[64];   // DCOM object CLSID or ProgID (e.g. "MMC20.Application")
    CHAR    RemoteAddress[46];      // Remote IP address if remote activation (IPv4/IPv6 string)
} DCOM_EVENT_DATA, *PDCOM_EVENT_DATA;
#pragma pack(pop)

// -- Enums --
typedef enum _REG_OPERATION {
    REG_OPERATION_SET = 0,
    REG_OPERATION_DELETE,
    REG_OPERATION_RENAME,
    REG_OPERATION_READ,
    REG_OPERATION_SET_SECURITY
} REG_OPERATION;

typedef enum _FILE_OPERATION {
    FILE_OPERATION_WRITE = 0,
    FILE_OPERATION_DELETE,
    FILE_OPERATION_RENAME,
    FILE_OPERATION_READ
} FILE_OPERATION;

typedef enum _SECURITY_FLAG {
    SEF_ALL_BLOCKED = 0,
    SEF_NOT_SYSTEM_BLOCKED,
    SEF_UNSIGNED_BLOCKED,
    SEF_PROCESS_START_BY_EXPLORER_BLOCKED,
    SEF_ALL_ACCESS
} SECURITY_FLAG;

typedef enum _RULE_TYPE {
    RULE_TYPE_REG = 0,
    RULE_TYPE_FILE,
    RULE_TYPE_BEHAVIOR,
    RULE_TYPE_INJECTION_LOG,   // 驱动注入日志（Fire-and-Forget）
    RULE_TYPE_PROCESS_CHECK,   // 进程启动命令行/静态扫描检查
    RULE_TYPE_DLL_SCAN,        // 签名程序加载未签名 DLL 检查
    RULE_TYPE_NTDLL_RELOAD,    // ntdll.dll 重载/Unhook 检测事件
    RULE_TYPE_DCOM_LATERAL_MOVEMENT,  // DCOM 横向移动检测
    RULE_TYPE_ROLLBACK_CONFIRM,       // 威胁回滚确认（用户选择回滚/忽略）
    RULE_TYPE_ROLLBACK_LOG            // 回滚记录日志（溢出丢磁盘，主程序持久化）
} RULE_TYPE;

typedef enum _PACKET_TYPE {
    PACKET_TYPE_PROTECT_PROCESS = 0,
    PACKET_TYPE_ADD_RULE,
    PACKET_TYPE_ADD_FILE_RULE,
    PACKET_TYPE_REMOVE_FILE_RULE,
    PACKET_TYPE_CLEAR_FILE_RULES,
    PACKET_TYPE_REMOVE_RULE,
    PACKET_TYPE_CLEAR_RULES,
    PACKET_TYPE_GENERIC
} PACKET_TYPE;

typedef enum _RESPONSE_TYPE {
    RESPONSE_RESULT = 0,
    RESPONSE_RULE_DETECTED,
    RESPONSE_BEHAVIOR_DETECTED,
    RESPONSE_INJECTION_LOG     // 驱动注入日志（Fire-and-Forget，不等待响应）
} RESPONSE_TYPE;

// -- Structures --
#pragma pack(push, 1)

typedef struct _RULE_DATA {
    ULONG           RuleId;
    RULE_TYPE       rt;
    CHAR            Data[MAX_RULE_DATA_LEN];
    SECURITY_FLAG   sef;
} RULE_DATA;

typedef struct _RULE_REG_DATA {
    ULONG           RuleId;
    REG_OPERATION   Operation;
    CHAR            FullPathWithOutValueName[MAX_PATH_LEN];
    CHAR            ValueName[MAX_VALUE_NAME_LEN];
    CHAR            DetectValue[MAX_DETECT_VALUE_LEN];
    BOOLEAN         IsNeedValueName;
    SECURITY_FLAG   sef;
    CHAR            Description[128];
} RULE_REG_DATA;

typedef struct _RULE_FILE_DATA {
    ULONG           RuleId;
    FILE_OPERATION  Operation;
    CHAR            FullPath[MAX_PATH_LEN];
    CHAR            FileName[MAX_VALUE_NAME_LEN];
    CHAR            FileExt[32];
    SECURITY_FLAG   sef;
    CHAR            Description[128];
} RULE_FILE_DATA;

typedef struct _COMM_CONTROL_PACKET {
    PACKET_TYPE     Type;
    CHAR            Data[MAX_CTL_PACKET_LEN];
} COMM_CONTROL_PACKET;

typedef struct _COMM_RESPONSE_RESULT {
    NTSTATUS        nts;
    CHAR            Data[5120];
} COMM_RESPONSE_RESULT;

typedef struct _RULE_REG_DETECTED_RESPONSE {
    CHAR            FullPath[MAX_PATH_LEN];
    CHAR            ChangeValue[4096];
    BOOLEAN         IsChangeValueEnabled;
    CHAR            ChangeName[4096];
    BOOLEAN         IsChangeNameEnabled;
} RULE_REG_DETECTED_RESPONSE;

typedef struct _RULE_FILE_DETECTED_RESPONSE {
    CHAR            FullPath[MAX_PATH_LEN];
    CHAR            FileName[MAX_VALUE_NAME_LEN];
    CHAR            FileExt[32];
    CHAR            ChangePath[4096];
    BOOLEAN         IsChangePathEnabled;
} RULE_FILE_DETECTED_RESPONSE;

// Behavior analysis detection response (real-time alert)
#define BA_ALERT_EVIDENCE_MAX 8
typedef struct _BEHAVIOR_DETECTED_RESPONSE {
    INT64           Pid;
    CHAR            ProcessPath[256];
    CHAR            ThreatClass[128];
    CHAR            Description[256];
    DOUBLE          Confidence;
    INT             EvidenceCount;
    CHAR            Evidence[BA_ALERT_EVIDENCE_MAX][128];
    BOOLEAN         SilentMode;
} BEHAVIOR_DETECTED_RESPONSE;

typedef BEHAVIOR_DETECTED_RESPONSE* PBEHAVIOR_DETECTED_RESPONSE;

// Injection log data (sent from driver to client for display in main.cpp log)
typedef struct _INJECTION_LOG_DATA {
    CHAR            Message[512];   // 日志消息内容
} INJECTION_LOG_DATA;

typedef INJECTION_LOG_DATA* PINJECTION_LOG_DATA;

// -- Rollback confirmation structures (kernel ↔ client ↔ main.cpp) --
// Compact display item: fits in both COMM_RULE_DETECTED.Data[10240] and Packet.Message[4096]
#ifndef _BA_ROLLBACK_STRUCTS_DEFINED
#define _BA_ROLLBACK_STRUCTS_DEFINED
#pragma pack(push, 1)
typedef struct _BA_ROLLBACK_ITEM {
    UINT8   type;           // 0=file, 1=registry
    INT64   pid;            // process that performed the operation
    CHAR    path[180];      // ASCII path (file path or registry key path, truncated)
    CHAR    valueName[32];  // registry value name (empty for files)
    UINT8   regOp;          // 0=SetValue, 1=DeleteValue (for registry only)
    UINT8   hadExisting;    // whether original value existed (for registry only)
} BA_ROLLBACK_ITEM;

#define BA_MAX_ROLLBACK_ITEMS  16

typedef struct _BA_ROLLBACK_LIST {
    INT64   rootPid;
    CHAR    rootProcessName[64];
    CHAR    threatClass[128];
    INT32   itemCount;
    BA_ROLLBACK_ITEM items[BA_MAX_ROLLBACK_ITEMS];
} BA_ROLLBACK_LIST;

typedef struct _BA_ROLLBACK_SELECTION {
    INT32   decision;       // 0=ignore, 1=rollback
    INT32   itemCount;
    UINT8   selected[BA_MAX_ROLLBACK_ITEMS];  // 1=selected for rollback
} BA_ROLLBACK_SELECTION;

// -- Rollback log record (kernel overflow -> client -> main 磁盘缓存) --
// 自包含的回滚记录：文件=待删除路径；注册表=键路径+值名+原始值备份。
// 驱动 g_baDroppedFiles / g_baRegOps 环形缓冲区溢出时，将覆盖前的记录
// 以本结构上报到用户态，主程序持久化到行为磁盘缓存（300MB 上限），
// 回滚时结合驱动当前 BA_ROLLBACK_LIST 一起执行。
#define BA_RBLOG_PATH_LEN      180
#define BA_RBLOG_VALUE_NAME_LEN 32
#define BA_RBLOG_BACKUP_LEN    1024

typedef struct _BA_ROLLBACK_LOG_RECORD {
    UINT8   type;              // 0=file, 1=registry
    INT64   pid;               // process that performed the operation
    CHAR    path[BA_RBLOG_PATH_LEN];        // file path or registry key path
    CHAR    valueName[BA_RBLOG_VALUE_NAME_LEN]; // registry value name (empty for files)
    UINT8   regOp;             // 0=SetValue, 1=DeleteValue (for registry only)
    UINT8   hadExisting;       // whether original value existed (for registry only)
    UINT32  originalType;      // original value type REG_DWORD/REG_SZ...
    UINT32  originalDataLen;   // original value data bytes
    UINT8   originalData[BA_RBLOG_BACKUP_LEN]; // original value backup data
} BA_ROLLBACK_LOG_RECORD;
#pragma pack(pop)

typedef BA_ROLLBACK_ITEM* PBA_ROLLBACK_ITEM;
typedef BA_ROLLBACK_LIST* PBA_ROLLBACK_LIST;
typedef BA_ROLLBACK_SELECTION* PBA_ROLLBACK_SELECTION;
typedef BA_ROLLBACK_LOG_RECORD* PBA_ROLLBACK_LOG_RECORD;
#endif /* _BA_ROLLBACK_STRUCTS_DEFINED */

// R0 whitelist sync (AutoAllowList / AutoPreventList from main.cpp)
#define WHITELIST_TYPE_ALLOW   0
#define WHITELIST_TYPE_PREVENT 1
#define WHITELIST_MAX_ENTRIES  128
#define WHITELIST_NAME_LEN     128

typedef struct _WHITELIST_ENTRY {
    INT64  Pid;
    CHAR   Name[WHITELIST_NAME_LEN];
} WHITELIST_ENTRY, *PWHITELIST_ENTRY;

typedef struct _WHITELIST_SYNC_DATA {
    ULONG            Type;       // WHITELIST_TYPE_ALLOW or WHITELIST_TYPE_PREVENT
    ULONG            Count;
    WHITELIST_ENTRY  Entries[WHITELIST_MAX_ENTRIES];
} WHITELIST_SYNC_DATA, *PWHITELIST_SYNC_DATA;

// Behavior analysis special RuleId
#define RULE_ID_BEHAVIOR_ANALYSIS  0x7FFFFFFF

typedef struct _COMM_RULE_DETECTED {
    int             RuleId;
    int             RuleType;       // 0=REG, 1=FILE
    int             ProcessPid;
    CHAR            ProcessName[64];    // triggering process image name
    int             ParentPid;          // parent process PID
    CHAR            ParentName[64];     // parent process image name
    CHAR            ProcessPath[512];   // triggering process image full path
    CHAR            DllPath[512];       // DLL path (for RULE_TYPE_DLL_SCAN)
    CHAR            RuleDesc[128];      // matched rule description
    int             IsSideLoad;         // 1=同目录未签名DLL（进程签名已降级）
    /* Data 必须能容纳 RULE_REG_DETECTED_RESPONSE（9218 字节）和
     * RULE_FILE_DETECTED_RESPONSE（5409 字节）。原值 5120 不足，导致
     * GetPendingRequest 中 RtlZeroMemory 写入超出 Data 边界，溢出
     * COMM_RESPONSE_PACKET.Data 及 IRP SystemBuffer，损坏池元数据。 */
    CHAR            Data[10240];
} COMM_RULE_DETECTED;

/* 编译期检查：确保 COMM_RULE_DETECTED.Data 足够容纳所有写入其中的响应结构。
 * 如果某个响应结构增大超过 Data 大小，编译会报错（负数组大小）。 */
typedef char _static_assert_file_resp_fits[sizeof(RULE_FILE_DETECTED_RESPONSE) <= sizeof(((COMM_RULE_DETECTED*)0)->Data) ? 1 : -1];
typedef char _static_assert_reg_resp_fits[sizeof(RULE_REG_DETECTED_RESPONSE) <= sizeof(((COMM_RULE_DETECTED*)0)->Data) ? 1 : -1];
typedef char _static_assert_behavior_resp_fits[sizeof(BEHAVIOR_DETECTED_RESPONSE) <= sizeof(((COMM_RULE_DETECTED*)0)->Data) ? 1 : -1];
typedef char _static_assert_ntdll_resp_fits[sizeof(NTDLL_RELOAD_EVENT_DATA) <= sizeof(((COMM_RULE_DETECTED*)0)->Data) ? 1 : -1];
typedef char _static_assert_injection_resp_fits[sizeof(INJECTION_LOG_DATA) <= sizeof(((COMM_RULE_DETECTED*)0)->Data) ? 1 : -1];
typedef char _static_assert_rollback_list_fits[sizeof(BA_ROLLBACK_LIST) <= sizeof(((COMM_RULE_DETECTED*)0)->Data) ? 1 : -1];

typedef struct _COMM_RESPONSE_PACKET {
    RESPONSE_TYPE   Type;
    CHAR            Data[MAX_CTL_PACKET_LEN];
} COMM_RESPONSE_PACKET;

#pragma pack(pop)

// Process signature / PPL setting input (user -> kernel)
// SignerType: 0=None, 1=ProtectedLight, 2=Protected
// SignatureSigner: 0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware, ...
typedef struct _PROCESS_SIGNATURE {
    ULONG Pid;
    UCHAR SignerType;
    UCHAR SignatureSigner;
} PROCESS_SIGNATURE, *PPROCESS_SIGNATURE;

// -- Pointer Type Aliases --
typedef COMM_CONTROL_PACKET* PCOMM_CONTROL_PACKET;
typedef COMM_RESPONSE_PACKET* PCOMM_RESPONSE_PACKET;
typedef COMM_RESPONSE_RESULT* PCOMM_RESPONSE_RESULT;
typedef COMM_RULE_DETECTED* PCOMM_RULE_DETECTED;
typedef RULE_DATA* PRULE_DATA;
typedef RULE_REG_DATA* PRULE_REG_DATA;
typedef RULE_FILE_DATA* PRULE_FILE_DATA;
typedef RULE_REG_DETECTED_RESPONSE* PRULE_REG_DETECTED_RESPONSE;
typedef RULE_FILE_DETECTED_RESPONSE* PRULE_FILE_DETECTED_RESPONSE;

// -- Disk Filter Alert Structures (for MBR write interception) --
#pragma pack(push, 1)
typedef struct _DISK_FILTER_ALERT {
    INT64       timestampMs;         /* 告警时间戳 */
    INT64       pid;                 /* 发起写入的进程PID */
    CHAR        processName[64];     /* 进程名 */
    CHAR        processPath[512];    /* 进程完整路径 */
    ULONG       diskNumber;          /* 物理磁盘编号 */
    LARGE_INTEGER byteOffset;        /* 写入起始字节偏移 */
    ULONG       writeLength;         /* 写入字节数 */
    CHAR        deviceName[128];     /* 设备名（如 \Device\Harddisk0\DR0） */
} DISK_FILTER_ALERT;

typedef struct _DISK_FILTER_RESPONSE {
    INT64       pid;                 /* 对应告警的进程PID */
    INT         decision;            /* 0=Allow, 1=Block */
} DISK_FILTER_RESPONSE;

/* 防护状态查询结果（IOCTL_DISK_FILTER_GET_STATUS 返回） */
typedef struct _DISK_FILTER_STATUS {
    BOOLEAN     protectionEnabled;   /* MBR 保护是否启用 */
    ULONG       attachedDiskCount;   /* 已 attach 的物理磁盘设备数（0=未生效） */
    ULONG       attachedVolumeCount; /* 已 attach 的卷设备数 */
    ULONG       pendingAlerts;       /* 队列中待处理的告警数 */
    ULONG       totalBlockedWrites;  /* 累计拦截的写入次数 */
} DISK_FILTER_STATUS;

/* 日志条目（IOCTL_DISK_FILTER_POLL_LOG 返回，供客户端转发到 main UI 显示） */
#define DISK_FILTER_LOG_MSG_MAX  512
typedef struct _DISK_FILTER_LOG {
    INT64       timestampMs;         /* 日志时间戳 */
    CHAR        Message[DISK_FILTER_LOG_MSG_MAX]; /* 日志文本（已含 [TianHongHips.Disk] 前缀） */
} DISK_FILTER_LOG;
#pragma pack(pop)

typedef DISK_FILTER_ALERT* PDISK_FILTER_ALERT;
typedef DISK_FILTER_RESPONSE* PDISK_FILTER_RESPONSE;
typedef DISK_FILTER_STATUS* PDISK_FILTER_STATUS;
typedef DISK_FILTER_LOG* PDISK_FILTER_LOG;
typedef PROCESS_SIGNATURE* PPROCESS_SIGNATURE;

// -- File Rule Stats --
typedef struct _FILE_RULE_STATS {
    ULONG TotalRules;
    ULONG ActiveRules;
    ULONG BlockedOperations;
    ULONG AllowedOperations;
} FILE_RULE_STATS;

// -- Kernel-mode request/response queue node --
#ifdef _KERNEL_MODE
typedef struct _RESPONSE_REQUEST {
    LIST_ENTRY      ListEntry;
    int             RuleId;
    int             RuleType;
    int             ProcessPid;
    CHAR            ProcessName[64];
    int             ParentPid;
    CHAR            ParentName[64];
    CHAR            ProcessPath[512];
    CHAR            DllPath[512];
    CHAR            RuleDesc[128];
    int             IsSideLoad;       // 1=同目录未签名DLL（进程签名已降级）
    PUNICODE_STRING FullPath;
    PUNICODE_STRING ValueName;
    PVOID           NewValueData;
    ULONG           NewValueSize;
    ULONG           ValueType;
    BEHAVIOR_DETECTED_RESPONSE BehaviorAlert;  // Behavior analysis alert data
    INJECTION_LOG_DATA      InjectionLog;     // Injection log data
    PBA_ROLLBACK_LIST       RollbackList;     // Rollback item list (for RULE_TYPE_ROLLBACK_CONFIRM)
    BA_ROLLBACK_SELECTION   RollbackSelection; // User's rollback selection (filled by HandleUserResponse)
    BA_ROLLBACK_LOG_RECORD  RollbackLogRec;    // 回滚记录（for RULE_TYPE_ROLLBACK_LOG，溢出丢磁盘）
    KEVENT          CompletionEvent;
    NTSTATUS        ResultStatus;
    BOOLEAN         FireAndForget;  // TRUE=fire-and-forget, freed by HandleUserResponse
} RESPONSE_REQUEST, *PRESPONSE_REQUEST;
#endif

// -- Kernel EA (Extended Attribute) for signature verification --
// EA name: "TianHongSigVerify"
// EA value: SIGNATURE_EA_VALUE structure
#ifdef _KERNEL_MODE
#define SIG_VERIFY_EA_NAME           "TianHongSigVerify"
#define SIG_VERIFY_EA_NAME_LENGTH    18
#define SIG_VERIFY_EA_VALUE_LENGTH   sizeof(SIGNATURE_EA_VALUE)
#define SIG_VERIFY_EA_FLAG_OVERWRITE 0x01

typedef struct _SIGNATURE_EA_VALUE {
    ULONGLONG FileSize;
    ULONGLONG LastWriteTime;
    BOOLEAN   IsSigned;
    NTSTATUS  VerifyStatus;
    ULONGLONG Timestamp;
    ULONG     Flags;
} SIGNATURE_EA_VALUE, *PSIGNATURE_EA_VALUE;

// -- CI.DLL kernel-mode code integrity interface --
typedef struct _CI_POLICY_INFO {
    ULONG  StructSize;
    NTSTATUS VerificationStatus;
    ULONG  Flags;
    PVOID  CertChainInfo;
    LARGE_INTEGER RevocationTime;
    LARGE_INTEGER NotBeforeTime;
    LARGE_INTEGER NotAfterTime;
} CI_POLICY_INFO, *PCI_POLICY_INFO;

typedef NTSTATUS (*CI_VALIDATE_FILE_OBJECT)(
    struct _FILE_OBJECT* FileObject,
    ULONG PolicyFlags,
    ULONG Unknown,
    PCI_POLICY_INFO PolicyInfoForSigner,
    PCI_POLICY_INFO PolicyInfoForTimestampingAuthority,
    PLARGE_INTEGER SigningTime,
    PUCHAR DigestBuffer,
    PULONG DigestSize,
    PULONG DigestIdentifier
);

typedef VOID (*CI_FREE_POLICY_INFO)(PCI_POLICY_INFO PolicyInfo);

extern CI_VALIDATE_FILE_OBJECT g_CiValidateFileObject;
extern CI_FREE_POLICY_INFO g_CiFreePolicyInfo;

NTSTATUS CiInitialize(VOID);
VOID CiCleanup(VOID);
NTSTATUS CiVerifyFileObject(_In_ struct _FILE_OBJECT* FileObject, _Out_ PBOOLEAN IsSigned);

// -- Signature verification cache configuration --
#define MAX_SIGNATURE_CACHE_ENTRIES    256
#define SIGNATURE_CACHE_TTL_SECONDS    3600

// -- Kernel-mode signature cache entry --
typedef struct _SIGNATURE_CACHE_ENTRY {
    CHAR            FilePath[MAX_PATH_LEN];
    ULONGLONG       FileSize;
    ULONGLONG       LastWriteTime;
    BOOLEAN         IsSigned;
    NTSTATUS        VerifyStatus;
    ULONGLONG       Timestamp;
    BOOLEAN         Valid;
} SIGNATURE_CACHE_ENTRY, *PSIGNATURE_CACHE_ENTRY;
#endif