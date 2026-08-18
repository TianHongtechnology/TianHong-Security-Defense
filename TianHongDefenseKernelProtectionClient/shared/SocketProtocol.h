/* ============================================================================
 * SocketProtocol.h - Socket protocol between Client and main.cpp
 *
 * Reuses the mature socket communication between main and DLL, replaces named pipe
 * main.cpp listens on port 12347, Client connects via 127.0.0.1:12347
 *
 * Protocol format: fully compatible with Packet struct in main.cpp PublicDefine.h
 *   - PacketType: PTClientMessage (6)
 *   - InfoTitle:  Message subtype (READY/LOG/ALERT/COMMAND/...)
 *   - Message:    Data payload
 *   - WarnTitle:  Additional info
 *   - Pid:        Related process PID
 * ========================================================================== */

#pragma once

#include <WinSock2.h>   // Must be before windows.h to avoid winsock.h conflict
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")

// -- Message subtypes (distinguished by InfoTitle field) --
#define CLIENT_MSG_READY            "READY"             // Client -> main: Ready
#define CLIENT_MSG_AUTH_OK          "AUTH_OK"           // main -> Client: 认证通过
#define CLIENT_MSG_LOG              "LOG"               // Client -> main: Driver log
#define CLIENT_MSG_ALERT            "ALERT"             // Client -> main: Behavior alert
#define CLIENT_MSG_ALERT_RESPONSE   "ALERT_RESPONSE"    // main -> Client: Alert user decision
#define CLIENT_MSG_COMMAND          "COMMAND"           // main -> Client: Execute command
#define CLIENT_MSG_RESULT           "RESULT"            // Client -> main: Command result
#define CLIENT_MSG_HEARTBEAT        "HEARTBEAT"         // Bidirectional heartbeat
#define CLIENT_MSG_QUIT             "QUIT"              // main -> Client: Quit notification
#define CLIENT_MSG_PROCESS_CHECK    "PROCESS_CHECK"     // Client -> main: R0 process check
#define CLIENT_MSG_PROCESS_CHECK_RESP "PROCESS_CHECK_RESP" // main -> Client: Check result
#define CLIENT_MSG_SET_FULL_SCAN    "SET_FULL_SCAN"     // main -> Client: 设置进程检查是否阻塞（完整扫描）
#define CLIENT_MSG_DLL_SCAN         "DLL_SCAN"          // Client -> main: 签名程序加载未签名 DLL 检查
#define CLIENT_MSG_DLL_SCAN_RESP    "DLL_SCAN_RESP"     // main -> Client: DLL 检查结果
#define CLIENT_MSG_ROLLBACK_CONFIRM       "ROLLBACK_CONFIRM"        // Client -> main: 威胁回滚确认
#define CLIENT_MSG_ROLLBACK_CONFIRM_RESP  "ROLLBACK_CONFIRM_RESP"   // main -> Client: 回滚选择结果
#define CLIENT_MSG_ROLLBACK_LOG           "ROLLBACK_LOG"            // Client -> main: 回滚记录（溢出丢磁盘，主程序持久化）

// -- Port number --
#define CLIENT_SOCKET_PORT          12347
#define CLIENT_SOCKET_IP            "127.0.0.1"

// -- Alert data structures (must fit within Packet.Message[4096]) --
struct ClientAlertData {
    INT64 pid;
    INT64 parentPid;          // 父进程PID
    char title[128];
    char parentName[64];      // 父进程名
    char parentPath[520];     // 父进程路径
    char processPath[520];    // 当前进程路径（来自内核 COMM_RULE_DETECTED.ProcessPath）
    char message[2840];       // 相应缩小以保持结构体大小不变
};

struct ClientAlertResponse {
    INT64 pid;
    int decision;  // 0=Allow, 1=Block, 2=Timeout
};

// -- Process check data structures --
struct ClientProcessCheckData {
    INT64 pid;
    INT64 parentPid;
    char processPath[520];
    char processName[64];
    char parentName[64];
};

struct ClientProcessCheckResponse {
    INT64 pid;
    int allow;  // 0=Block, 1=Allow
};

struct ClientDllScanData {
    INT64 pid;
    INT64 parentPid;
    char processPath[520];
    char processName[64];
    char dllPath[520];
    int blocking;       // 1=阻塞扫描, 0=异步扫描
    int isSideLoad;     // 1=同目录未签名DLL（进程签名已降级）
};

struct ClientDllScanResponse {
    INT64 pid;
    int allow;       // 0=Block, 1=Allow
    int isSideLoad;  // 1=同目录未签名DLL（进程签名已降级），0=普通DLL扫描
};

// -- Rollback confirmation structures (also defined in Common.h with guard) --
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

// -- Rollback confirm response wrapper (main -> Client) --
// BA_ROLLBACK_LIST is sent directly in Packet.Message (fits in 4096 bytes).
// Response wraps PID for matching + BA_ROLLBACK_SELECTION.
struct ClientRollbackConfirmResponse {
    INT64 pid;                      // matches rollbackList.rootPid
    BA_ROLLBACK_SELECTION selection; // user's selection
};

// Packet/WarnDlgType/PacketType are defined in main.cpp PublicDefine.h.
// Do NOT redefine them here to avoid C2011 redefinition errors.