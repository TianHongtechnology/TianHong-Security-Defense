#pragma once
/* ============================================================================
 * Event.h — 事件类型定义（驱动与用户态共享）
 * ========================================================================== */

#include "Common.h"

// ── 事件来源 ──
typedef enum _TH_EVENT_SOURCE {
    TH_EVENT_SOURCE_REGISTRY = 0,
    TH_EVENT_SOURCE_FILE_SYSTEM,
    TH_EVENT_SOURCE_PROCESS,
    TH_EVENT_SOURCE_MEMORY
} TH_EVENT_SOURCE;

// ── 事件动作 ──
typedef enum _TH_EVENT_ACTION {
    TH_EVENT_ACTION_SET = 0,
    TH_EVENT_ACTION_DELETE,
    TH_EVENT_ACTION_RENAME,
    TH_EVENT_ACTION_READ,
    TH_EVENT_ACTION_WRITE,
    TH_EVENT_ACTION_CREATE,
    TH_EVENT_ACTION_EXECUTE
} TH_EVENT_ACTION;

// ── 事件严重级别 ──
typedef enum _TH_EVENT_SEVERITY {
    TH_SEVERITY_LOW = 0,
    TH_SEVERITY_MEDIUM,
    TH_SEVERITY_HIGH,
    TH_SEVERITY_CRITICAL
} TH_EVENT_SEVERITY;

// ── 事件结构体 ──
#pragma pack(push, 1)

typedef struct _TH_EVENT_INFO {
    TH_EVENT_SOURCE  Source;
    TH_EVENT_ACTION  Action;
    TH_EVENT_SEVERITY Severity;
    int              ProcessPid;
    CHAR             ProcessName[MAX_PATH_LEN];
    CHAR             TargetPath[MAX_PATH_LEN];
    CHAR             TargetName[MAX_VALUE_NAME_LEN];
    CHAR             Detail[4096];
    ULONG64          Timestamp;
} TH_EVENT_INFO;

#pragma pack(pop)