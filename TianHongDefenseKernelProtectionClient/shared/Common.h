#pragma once
/* ============================================================================
 * Common.h - Shared definitions for driver and user mode
 * ========================================================================== */

#ifdef _KERNEL_MODE
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#else
#include <windows.h>
#include <winioctl.h>
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

// -- Max Limits --
#define MAX_RULES              1024
#define MAX_PROTECTED_PIDS     64
#define MAX_FILE_RULES         1024
#define MAX_PATH_LEN            1024
#define MAX_VALUE_NAME_LEN      256
#define MAX_DETECT_VALUE_LEN    256
#define MAX_RULE_DATA_LEN       9500
/* MAX_CTL_PACKET_LEN 必须足够大以容纳 COMM_RULE_DETECTED（header 1296 字节
 * + Data 字段 10240 字节 = 11536）。原值 10240 不足，导致池溢出蓝屏。 */
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
#define IOCTL_SET_UNSIGNED_DLL_SCAN                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_DCOM_PROTECTION_ENABLED          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BEHAVIOR_DCOM_EVENT                  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_LOAD_DYNAMIC_RULE                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x826, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_REMOVE_DYNAMIC_RULE               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x827, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_CLEAR_DYNAMIC_RULES               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x828, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_GET_DYNAMIC_RULE_STATS            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82A, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_GET_DYNAMIC_RULE_LIST             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82B, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_GET_DYNAMIC_RULE_VERSION          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82C, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BA_REPORT_FEEDBACK                   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82D, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -- Disk Filter IOCTL Codes (TianHongHips.Disk driver) --
#define IOCTL_DISK_FILTER_SET_ENABLED              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x830, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_POLL_ALERT               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x831, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_SEND_RESPONSE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x832, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_GET_STATUS               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x833, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISK_FILTER_POLL_LOG                 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x834, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -- Network Filter IOCTL Codes (TianHongHips.Network driver) --
#define IOCTL_NETWORK_SET_ENABLED              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_POLL_EVENT               CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)

// -- Disk Filter Driver Names --
#define DISK_DEVICE_NAME           L"\\Device\\TianHongDiskFilter"
#define DISK_SYMLINK_NAME          L"\\??\\TianHongDiskFilter"
#define DISK_DRIVER_PREFIX         "[TianHongHips.Disk] "
#define THSD_DISK_SERVICE_NAME_A   "TianHongHips.Disk"
#define THSD_DISK_SERVICE_NAME_W   L"TianHongHips.Disk"
#define THSD_DISK_USER_DEVICE_PATH_W  L"\\\\.\\TianHongDiskFilter"
#define THSD_DISK_DRIVER_FILENAME_A   "TianHongDefenseKernelProtection.Disk.sys"
#define THSD_DISK_DRIVER_FILENAME_W   L"TianHongDefenseKernelProtection.Disk.sys"

// -- Network Filter Driver Names --
#define NETWORK_DEVICE_NAME           L"\\Device\\TianHongNetworkFilter"
#define NETWORK_SYMLINK_NAME          L"\\??\\TianHongNetworkFilter"
#define NETWORK_DRIVER_PREFIX         "[TianHongHips.Network] "
#define THSD_NETWORK_SERVICE_NAME_A   "TianHongHips.Network"
#define THSD_NETWORK_SERVICE_NAME_W   L"TianHongHips.Network"
#define THSD_NETWORK_USER_DEVICE_PATH_W  L"\\\\.\\TianHongNetworkFilter"
#define THSD_NETWORK_DRIVER_FILENAME_A   "TianHongDefenseKernelProtection.Network.sys"
#define THSD_NETWORK_DRIVER_FILENAME_W   L"TianHongDefenseKernelProtection.Network.sys"

// -- MBR protection: boot region sectors 0-62 (31KB, covers MBR + gap before first partition) --
#define MBR_PROTECTION_SECTOR_COUNT   63

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
    RULE_TYPE_INJECTION_LOG,   // Fire-and-Forget driver injection log
    RULE_TYPE_PROCESS_CHECK,   // R0 独立进程创建检查
    RULE_TYPE_DLL_SCAN,        // 未签名 DLL 扫描
    RULE_TYPE_NTDLL_RELOAD,    // ntdll.dll 重载/Unhook 检测事件
    RULE_TYPE_DCOM_LATERAL_MOVEMENT,  // DCOM 横向移动检测
    RULE_TYPE_ROLLBACK_CONFIRM,      // 威胁回滚确认（用户选择回滚/忽略）
    RULE_TYPE_ROLLBACK_LOG           // 回滚记录日志（溢出丢磁盘，主程序持久化）
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
    RESPONSE_BEHAVIOR_DETECTED
} RESPONSE_TYPE;

// -- Structures --
// Use pack(1) in both kernel and user mode to ensure identical struct layout
// across the kernel-usermode boundary. Windows SDK headers are included above
// (before this pragma) so they are unaffected.
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

// -- Dynamic Behavior Analysis Results --
#define BA_MAX_EVIDENCE    64

typedef struct _BA_THREAT_RESULT {
    INT    isThreat;
    INT64  pid;
    CHAR   processPath[1024];
    CHAR   threatClass[128];
    CHAR   description[256];
    DOUBLE confidence;
    INT    evidenceCount;
    CHAR   evidence[BA_MAX_EVIDENCE][128];
} BA_THREAT_RESULT;

typedef struct _BA_STATS {
    INT processCount;
    INT historyCount;
    INT threatCount;
    INT indicatorCount;
    INT64 tickCounter;
} BA_STATS;

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
    CHAR            Message[512];   // Log message content
} INJECTION_LOG_DATA;

typedef INJECTION_LOG_DATA* PINJECTION_LOG_DATA;

// -- Rollback confirmation structures (kernel ↔ client ↔ main.cpp) --
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
typedef BA_ROLLBACK_LOG_RECORD* PBA_ROLLBACK_LOG_RECORD;
#pragma pack(pop)
#endif /* _BA_ROLLBACK_STRUCTS_DEFINED */

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
     * RULE_FILE_DETECTED_RESPONSE（5409 字节）。原值 5120 不足，导致池溢出蓝屏。 */
    CHAR            Data[10240];
} COMM_RULE_DETECTED;

/* 编译期检查：确保 COMM_RULE_DETECTED.Data 足够容纳所有写入其中的响应结构。 */
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

// -- Network Filter Event Structures (for DoH/C2/data exfiltration detection) --
#pragma pack(push, 8)
typedef struct _NETWORK_EVENT_DATA {
    INT64       CallerPid;              /* 发起连接的进程PID */
    ULONG       EventType;              /* 事件类型: 1=connect, 2=send, 3=DNS, 4=DoH */
    ULONG       Protocol;               /* 协议: 6=TCP, 17=UDP */
    ULONG       LocalPort;              /* 本地端口 */
    ULONG       RemotePort;             /* 远程端口 */
    BYTE        RemoteAddress[16];      /* 远程IP地址 (IPv4 mapped to IPv6) */
    ULONG       RemoteAddressType;      /* 地址类型: 0=IPv4, 1=IPv6 */
    ULONG       IsOutbound;             /* TRUE=出站, FALSE=入站 */
    ULONG       ProcessNameOffset;      /* 进程名偏移 (保留) */
    ULONG       PayloadSize;            /* Payload 字节数 */
    BYTE        Payload[256];           /* 载荷数据 (DNS查询/HTTP头等) */
} NETWORK_EVENT_DATA;

typedef struct _ETW_NETWORK_EVENT_DATA {
    INT64       CallerPid;              /* 发起连接的进程PID */
    ULONG       EventId;                /* 事件ID (对应 EventType) */
    ULONG       Protocol;               /* 协议: 6=TCP, 17=UDP */
    ULONG       LocalPort;              /* 本地端口 */
    ULONG       RemotePort;             /* 远程端口 */
    BYTE        RemoteAddress[16];      /* 远程IP地址 */
    ULONG       RemoteAddressType;      /* 地址类型 */
    ULONG       IsOutbound;             /* TRUE=出站 */
    ULONG       ProcessNameOffset;      /* 进程名偏移 */
    ULONG       PayloadSize;            /* Payload 字节数 */
    BYTE        Payload[128];           /* 载荷数据 */
} ETW_NETWORK_EVENT_DATA;
#pragma pack(pop)

typedef NETWORK_EVENT_DATA* PNETWORK_EVENT_DATA;
typedef ETW_NETWORK_EVENT_DATA* PETW_NETWORK_EVENT_DATA;

// -- File Rule Stats --
typedef struct _FILE_RULE_STATS {
    ULONG TotalRules;
    ULONG ActiveRules;
    ULONG BlockedOperations;
    ULONG AllowedOperations;
} FILE_RULE_STATS;

// -- Dynamic Behavior Rule Types (mirrors kernel BehaviorDynamicRules.h) --
#define BA_MAX_PATH            1024
#define BA_DYN_MAX_RULES              512
#define BA_DYN_MAX_INDICATORS         32
#define BA_DYN_MAX_EXCEPTIONS         16
#define BA_DYN_MAX_SUPPRESSIONS       8
#define BA_DYN_RULE_FIELD_LEN         256
#define BA_DYN_RULE_DESC_LEN          512
#define BA_DYN_RULE_PATH_LEN          260
#define BA_DYN_RULE_REASON_LEN        128
#define BA_DYN_RULE_NAME_LEN          128
#define BA_DYN_RULE_CLASS_LEN         128

typedef enum _BA_RULE_STATE {
    BA_RS_DISABLED = 0,
    BA_RS_ENABLED,
    BA_RS_TESTING,
    BA_RS_DEPRECATED
} BA_RULE_STATE;

typedef struct _BA_RULE_STATS {
    ULONG RuleId;
    ULONG TriggerCount;
    ULONG TruePositiveCount;
    ULONG FalsePositiveCount;
    DOUBLE AvgScore;
    INT64 LastTriggered;
} BA_RULE_STATS, *PBA_RULE_STATS;

typedef struct _BA_DYN_INDICATOR_REF {
    ULONG  IndicatorId;
    DOUBLE Weight;
    BOOLEAN Required;
} BA_DYN_INDICATOR_REF;

typedef struct _BA_DYN_EXCEPTION {
    CHAR   ImagePath[BA_DYN_RULE_PATH_LEN];
    CHAR   Reason[BA_DYN_RULE_REASON_LEN];
    BOOLEAN Enabled;
} BA_DYN_EXCEPTION;

typedef struct _BA_DYN_SUPPRESSION {
    CHAR   ImagePath[BA_DYN_RULE_PATH_LEN];
    INT64  DurationMs;
    CHAR   Reason[BA_DYN_RULE_REASON_LEN];
    INT64  StartTickMs;
} BA_DYN_SUPPRESSION;

typedef struct _BA_DYN_CONTEXT_FILTER {
    CHAR   ParentName[BA_DYN_RULE_NAME_LEN];
    CHAR   ParentPathPattern[BA_DYN_RULE_PATH_LEN];
    BOOLEAN ExcludeSignedParent;
    BOOLEAN RequireUnsignedSelf;
} BA_DYN_CONTEXT_FILTER;

typedef struct _BA_DYN_EVIDENCE_QUALITY_REQ {
    DOUBLE MinQualityScore;
    BOOLEAN RequireConfirmation;
} BA_DYN_EVIDENCE_QUALITY_REQ;

typedef struct _BA_DYNAMIC_RULE {
    ULONG   RuleId;
    ULONG   Version;
    CHAR    Name[BA_DYN_RULE_NAME_LEN];
    CHAR    ThreatClass[BA_DYN_RULE_CLASS_LEN];
    CHAR    Description[BA_DYN_RULE_DESC_LEN];
    ULONG   Severity;
    ULONG   RiskScore;
    ULONG   MitreTactic;
    CHAR    MitreTechnique[32];
    DOUBLE  Threshold;
    INT     MinMatchCount;
    BOOLEAN DirectMalicious;
    INT     IndicatorCount;
    BA_DYN_INDICATOR_REF Indicators[BA_DYN_MAX_INDICATORS];
    BA_DYN_CONTEXT_FILTER Context;
    INT     ExceptionCount;
    BA_DYN_EXCEPTION Exceptions[BA_DYN_MAX_EXCEPTIONS];
    INT     SuppressionCount;
    BA_DYN_SUPPRESSION Suppressions[BA_DYN_MAX_SUPPRESSIONS];
    BA_DYN_EVIDENCE_QUALITY_REQ EvidenceQuality;
    BA_RULE_STATE State;
    BA_RULE_STATS Stats;
    INT64   LastLoadedTickMs;
} BA_DYNAMIC_RULE, *PBA_DYNAMIC_RULE;

typedef struct _BA_DYNAMIC_RULE_LOAD_REQ {
    BA_DYNAMIC_RULE Rule;
} BA_DYNAMIC_RULE_LOAD_REQ, *PBA_DYNAMIC_RULE_LOAD_REQ;

typedef struct _BA_DYNAMIC_RULE_REMOVE_REQ {
    ULONG RuleId;
} BA_DYNAMIC_RULE_REMOVE_REQ, *PBA_DYNAMIC_RULE_REMOVE_REQ;

typedef struct _BA_DYNAMIC_RULE_STATE_REQ {
    ULONG RuleId;
    BA_RULE_STATE State;
} BA_DYNAMIC_RULE_STATE_REQ, *PBA_DYNAMIC_RULE_STATE_REQ;

typedef struct _BA_DYNAMIC_RULE_STATS_REQ {
    ULONG RuleId;
} BA_DYNAMIC_RULE_STATS_REQ, *PBA_DYNAMIC_RULE_STATS_REQ;

typedef struct _BA_DYNAMIC_RULE_LIST_REQ {
    ULONG Offset;
    ULONG Count;
} BA_DYNAMIC_RULE_LIST_REQ, *PBA_DYNAMIC_RULE_LIST_REQ;

// -- Indicator Definition Types (mirrors kernel BehaviorIndicatorDefs.h) --
#define BA_IND_DEF_MAX              256
#define BA_IND_MAX_SUB_CONDITIONS   8
#define BA_IND_MAX_EXCLUDE_PATTERNS 8
#define BA_IND_MAX_STRING_LIST      64
#define BA_IND_DEF_NAME_LEN         128
#define BA_IND_DEF_DESC_LEN         256
#define BA_IND_DEF_FIELD_LEN        128

typedef enum _BA_EVENT_CATEGORY {
    BA_EC_File = 0,
    BA_EC_Registry,
    BA_EC_Memory,
    BA_EC_Process
} BA_EVENT_CATEGORY;

typedef enum _BA_INDICATOR_CONDITION_TYPE {
    BA_COND_ALWAYS_TRUE = 0,
    BA_COND_PATH_CONTAINS,
    BA_COND_PATH_NOT_CONTAINS,
    BA_COND_PATH_MATCHES,
    BA_COND_FILE_OP_EQ,
    BA_COND_REG_OP_EQ,
    BA_COND_MEM_OP_EQ,
    BA_COND_DESIRED_ACCESS_HAS_FLAG,
    BA_COND_IS_SIGNED_EQ,
    BA_COND_FILE_EXT_IN_LIST,
    BA_COND_FILE_EXT_EQ,
    BA_COND_PARENT_NAME_IN_LIST,
    BA_COND_ALL_OF,
    BA_COND_ANY_OF,
    BA_COND_BULK_OPERATION,
    BA_COND_TIME_WINDOW_COUNT,
    BA_COND_PARENT_CHILD_MATCH
} BA_INDICATOR_CONDITION_TYPE;

typedef enum _BA_INDICATOR_CONDITION_FIELD {
    BA_FIELD_IMAGE_PATH = 0,
    BA_FIELD_FILE_PATH,
    BA_FIELD_FILE_DIR,
    BA_FIELD_FILE_NAME,
    BA_FIELD_FILE_EXT,
    BA_FIELD_REG_PATH,
    BA_FIELD_REG_VALUE,
    BA_FIELD_DESIRED_ACCESS,
    BA_FIELD_MEM_OP,
    BA_FIELD_FILE_OP,
    BA_FIELD_REG_OP,
    BA_FIELD_IS_SIGNED,
    BA_FIELD_TARGET_PROCESS,
    BA_FIELD_TARGET_PID,
    BA_FIELD_PARENT_NAME,
    BA_FIELD_PARENT_PATH,
    BA_FIELD_CATEGORY
} BA_INDICATOR_CONDITION_FIELD;

typedef enum _BA_INDICATOR_CONDITION_OP {
    BA_OP_EQ = 0,
    BA_OP_NEQ,
    BA_OP_CONTAINS,
    BA_OP_NOT_CONTAINS,
    BA_OP_MATCHES,
    BA_OP_IN_LIST,
    BA_OP_HAS_FLAG
} BA_INDICATOR_CONDITION_OP;

typedef struct _BA_INDICATOR_SUB_COND {
    BA_INDICATOR_CONDITION_FIELD Field;
    BA_INDICATOR_CONDITION_OP Op;
    CHAR StringValue[BA_IND_DEF_FIELD_LEN];
    ULONG UlongValue;
    BOOLEAN Negate;
} BA_INDICATOR_SUB_COND;

typedef struct _BA_INDICATOR_DEFINITION {
    ULONG   IndicatorId;
    CHAR    Name[BA_IND_DEF_NAME_LEN];
    CHAR    Description[BA_IND_DEF_DESC_LEN];
    BA_EVENT_CATEGORY Category;
    DOUBLE  BaseScore;
    BOOLEAN IsDynamic;
    BA_INDICATOR_CONDITION_TYPE ConditionType;
    BA_INDICATOR_SUB_COND SubConditions[BA_IND_MAX_SUB_CONDITIONS];
    INT     SubConditionCount;
    BA_INDICATOR_SUB_COND ExcludeConditions[BA_IND_MAX_EXCLUDE_PATTERNS];
    INT     ExcludeConditionCount;
    CHAR    StringList[BA_IND_MAX_STRING_LIST][32];
    INT     StringListCount;
    struct {
        INT LookbackCount;
        INT Threshold;
        INT64 TimeWindowMs;
    } BulkParams;
    BA_DYN_CONTEXT_FILTER RequiredContext;
} BA_INDICATOR_DEFINITION, *PBA_INDICATOR_DEFINITION;

// -- Kernel-mode request/response queue node --
#ifdef _KERNEL_MODE
typedef struct _RESPONSE_REQUEST {
    LIST_ENTRY      ListEntry;
    int             RuleId;
    int             RuleType;
    int             ProcessPid;
    PUNICODE_STRING FullPath;
    PUNICODE_STRING ValueName;
    PVOID           NewValueData;
    ULONG           NewValueSize;
    ULONG           ValueType;
    KEVENT          CompletionEvent;
    NTSTATUS        ResultStatus;
} RESPONSE_REQUEST, *PRESPONSE_REQUEST;
#endif