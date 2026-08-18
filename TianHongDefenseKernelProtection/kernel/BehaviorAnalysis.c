#include "../shared/Common.h"
#include "Main.h"
#include "BehaviorAnalysis.h"
#include "BehaviorAnalysisScoring.h"
#include "BehaviorAnalysisRules.h"
#include "BehaviorDynamicRules.h"
#include "ResponseSystem.h"
#include "RegistryCallback.h"  /* IsSystemProcessByEPROCESS() */
#include "Whitelist.h"
#include "ci_verify.h"         /* CiIsImageSignedAndTrusted / CiIsPidSigned / CiRecordProcessSignature */

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* MEM_IMAGE — 内存类型：PE 镜像映射（用于 ZwQueryVirtualMemory 检测 shellcode 注入）
 * 在 WDK 某些版本中未定义，需手动定义 */
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x1000000
#endif

/* MEM_COMMIT — 已提交内存（Elastic shellcode-thread 判定条件之一） */
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x1000
#endif

/* 外部 API 声明 */
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_to_opt_(ProcessInformationLength, *ReturnLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

/* ZwSetInformationProcess - 设置进程信息（用于 ProcessBreakOnTermination）
 * 内核态需要手动声明，wdm.h 中通常未导出此函数 */
NTSYSAPI NTSTATUS NTAPI ZwSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength);

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId,
    _Out_ PETHREAD* Thread);

/* PsGetProcessInheritedFromUniqueProcessId — 获取进程继承父进程 PID */
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(__in PEPROCESS Process);

/* NtTerminateThread — 终止线程（ntoskrnl.lib 未导出，需动态获取） */
typedef NTSTATUS (*PFN_NtTerminateThread)(_In_ HANDLE ThreadHandle, _In_ NTSTATUS ExitStatus);
static PFN_NtTerminateThread g_pNtTerminateThread = NULL;


/* ============================================================================
 * BehaviorAnalysis.c — 动态行为分析引擎实现
 * 基于指标评分 + 威胁画像匹配的进程行为检测
 *
 * 核心组件：
 *   1. 指标提取 — 从文件/注册表/内存/网络/syscall 事件中提取 91 种行为指标
 *   2. 进程树 — 跟踪进程父子关系，聚合子进程行为
 *   3. 威胁画像 — 预定义威胁画像（勒索/注入/持久化/Winkiller/脚本型/银狐/凭据窃取/蓝屏/关键进程劫持/C2/外泄/LotL/Direct-Indirect Syscall Hook Bypass）
 *   4. 评分引擎 — 加权评分 + 阈值判定 + 置信度计算
 *
 * 增强特性 (Phase 1/2):
 *   - 规则 ID 与版本管理系统
 *   - 统一结构化日志
 *   - 模块化指标提取
 *   - 规则性能统计
 *   - 异常检测基线
 *   - 规则状态管理
 * ========================================================================== */

/* ── 统一日志系统 ── */
#define BA_LOG_BUFFER_SIZE 512

static VOID BehaviorVLog(const CHAR* level, const CHAR* format, va_list args)
{
    CHAR buffer[BA_LOG_BUFFER_SIZE];
    NTSTATUS status = RtlStringCbVPrintfA(buffer, sizeof(buffer), format, args);
    if (NT_SUCCESS(status)) {
        DbgPrint("[BA-%s] %s\n", level, buffer);
    }
}

VOID BehaviorLogDebug(const CHAR* format, ...)
{
    va_list args;
    va_start(args, format);
    BehaviorVLog("DBG", format, args);
    va_end(args);
}

VOID BehaviorLogInfo(const CHAR* format, ...)
{
    va_list args;
    va_start(args, format);
    BehaviorVLog("INF", format, args);
    va_end(args);
}

VOID BehaviorLogWarning(const CHAR* format, ...)
{
    va_list args;
    va_start(args, format);
    BehaviorVLog("WRN", format, args);
    va_end(args);
}

VOID BehaviorLogError(const CHAR* format, ...)
{
    va_list args;
    va_start(args, format);
    BehaviorVLog("ERR", format, args);
    va_end(args);
}

 /* ── 静态辅助函数原型 ── */
int kStrLen(const CHAR* s);
int kStrCmp(const CHAR* a, const CHAR* b);
int kStrNCmp(const CHAR* a, const CHAR* b, int n);
int kStrIStrLen(const CHAR* haystack, int hayLen, const CHAR* needle, int needleLen);
int kStrStrLen(const CHAR* haystack, int hayLen, const CHAR* needle, int needleLen);
int kStrEndsWith(const CHAR* str, const CHAR* suffix);
VOID kStrLowerCopy(CHAR* dst, int dstSize, const CHAR* src);
BOOLEAN IsKnownSystemProcessName(const CHAR* nameLower);
BOOLEAN isGenuineSystemProcess(int idx, const CHAR* imagePath);
VOID kStrCpy(CHAR* dst, int dstSize, const CHAR* src);
int kStrToInt64(const CHAR* str, INT64* out);

int findProc(INT64 pid);
static int findOrCreateProc(INT64 pid);
int findPidIndex(INT64 pid);
static int findOrCreatePidIndex(INT64 pid);
static VOID addIndicator(int idx, BA_INDICATOR id, const CHAR* evidence);
static VOID extractIndicators(const BA_STORED_EVENT* ev);
VOID BehaviorExtractProcessIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractFileIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractRegistryIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractMemoryIndicators(int idx, const BA_STORED_EVENT* ev);
VOID BehaviorExtractCrossCategoryIndicators(int idx, const BA_STORED_EVENT* ev);
static VOID collectChildIndicators(INT64 pid, DOUBLE* combined, int* distinctCnt, int* visited, int* visitedCnt);
static VOID cleanupStalePids(VOID);
static VOID EnumerateExistingProcesses(VOID);
INT64 baEtwTickMs(VOID);

/* 行为分析告警 work item 回调（生产级：挂起进程树 -> 弹窗 -> 终止/恢复） */
static VOID BehaviorAlertWorkItemRoutine(PVOID Context);



/* 内核模式浮点运算支持 */
int _fltused = 0;

/* 动态解析挂起/恢复 API
 * ZwSuspendProcess/ZwResumeProcess 在新版本 Windows 上通常不导出，
 * 因此优先尝试 PsSuspendProcess/PsResumeProcess（PEPROCESS 参数，Windows 8+ 导出），
 * 再尝试 NtSuspendProcess/NtResumeProcess（HANDLE 参数）作为 fallback。 */
static NTSTATUS (*g_pPsSuspendProcess)(PEPROCESS) = NULL;
static NTSTATUS (*g_pPsResumeProcess)(PEPROCESS) = NULL;
static NTSTATUS (*g_pNtSuspendProcess)(HANDLE) = NULL;
static NTSTATUS (*g_pNtResumeProcess)(HANDLE) = NULL;
static NTSTATUS (*g_pNtSuspendThread)(HANDLE) = NULL;
static NTSTATUS (*g_pNtGetContextThread)(HANDLE, PCONTEXT) = NULL;

static VOID ResolveBehaviorApis(VOID)
{
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, L"PsSuspendProcess");
    g_pPsSuspendProcess = (NTSTATUS(*)(PEPROCESS))MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"PsResumeProcess");
    g_pPsResumeProcess = (NTSTATUS(*)(PEPROCESS))MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"NtSuspendProcess");
    g_pNtSuspendProcess = (NTSTATUS(*)(HANDLE))MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"NtResumeProcess");
    g_pNtResumeProcess = (NTSTATUS(*)(HANDLE))MmGetSystemRoutineAddress(&name);

    RtlInitUnicodeString(&name, L"NtSuspendThread");
    g_pNtSuspendThread = (NTSTATUS(*)(HANDLE))MmGetSystemRoutineAddress(&name);

    /* NtGetContextThread 由 ntoskrnl 导出（KeGetContextThread 已从现代 WDK 移除），
     * 用于 trampoline 跳板检测的线程上下文 Rip 采样。 */
    RtlInitUnicodeString(&name, L"NtGetContextThread");
    g_pNtGetContextThread = (NTSTATUS(*)(HANDLE, PCONTEXT))MmGetSystemRoutineAddress(&name);

    DriverDbgPrint("[BA-API] PsSuspend=%p PsResume=%p NtSuspend=%p NtResume=%p NtSuspendThread=%p NtGetContextThread=%p\n",
        g_pPsSuspendProcess, g_pPsResumeProcess,
        g_pNtSuspendProcess, g_pNtResumeProcess,
        g_pNtSuspendThread, g_pNtGetContextThread);
}

/* 判断是否为浏览器可执行名（仅文件名），用于对浏览器进程应用更严格的告警门槛 */
static BOOLEAN IsBrowserExecutable(const CHAR* imagePath)
{
    const CHAR* name = imagePath;
    int i;

    if (!imagePath || !imagePath[0]) return FALSE;

    /* Extract filename after last slash */
    {
        int len = kStrLen(imagePath);
        for (i = len - 1; i >= 0; i--) {
            if (imagePath[i] == '\\' || imagePath[i] == '/') { name = imagePath + i + 1; break; }
        }
    }

    if (!name || !name[0]) return FALSE;

    {
        const CHAR* browsers[] = { "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "opera.exe", "brave.exe", "vivaldi.exe" };
        int bi;
        int nameLen = kStrLen(name);
        for (bi = 0; bi < (int)(sizeof(browsers)/sizeof(browsers[0])); bi++) {
            int blen = kStrLen(browsers[bi]);
            if (kStrIStrLen(name, nameLen, browsers[bi], blen)) return TRUE;
        }
    }
    return FALSE;
}


#define BA_REALTIME_THRESHOLD  100.0  /* 实时告警阈值（调试日志模式） */
#define BA_MAX_ALERTED_PIDS    64


/* ═══════════════════════════════════════════════════════════════════════════
 * 全局状态
 * ══════════════════════════════════════════════════════════════════════════ */

static INT64       g_baTickCounter = 0;
static BA_STORED_EVENT g_baHistory[BA_MAX_HISTORY];
static INT         g_baHistoryHead = 0;
static INT         g_baHistoryCount = 0;

BA_PROCESS_NODE g_baProcTree[BA_MAX_PROCESSES];
INT         g_baProcCount = 0;

INT64       g_baIndicatorPids[BA_MAX_PROCESSES];
INT         g_baPidIndicators[BA_MAX_PROCESSES][BA_MAX_INDICATORS];
INT         g_baIndicatorCount = 0;
ULONG       g_baPidSyscallTypes[BA_MAX_PROCESSES];  /* 每个进程的 syscall 类型位掩码 */

BA_EVIDENCE_ENTRY g_baEvidence[BA_MAX_PROCESSES];

/* ── 幽灵进程追踪：已退出进程的行为数据保留，供子进程回溯分析 ── */
typedef struct _BA_GHOST_PROCESS {
    INT64           pid;
    INT64           parentPid;
    CHAR            imagePath[BA_MAX_PATH];
    INT64           exitTick;           /* 退出时的 tick 计数 */
    INT             indicators[BA_MAX_INDICATORS]; /* 独立指标副本（避免共享数组被清零） */
    BOOLEAN         hasSuspiciousIndicators; /* 是否有可疑指标 */
} BA_GHOST_PROCESS, *PBA_GHOST_PROCESS;

static BA_GHOST_PROCESS g_baGhostProcesses[BA_MAX_GHOST_PROCESSES];
static INT g_baGhostCount = 0;

static BOOLEAN     g_baInitialized = FALSE;
static KSPIN_LOCK  g_baLock;

/* 行为检测总开关：由用户态通过 IOCTL_SET_BEHAVIOR_DETECTION_ENABLED 控制。
 * 默认禁用，启用后 BehaviorCheckAndAlert 才会评估威胁。 */
BOOLEAN            g_bBehaviorDetectionEnabled = FALSE;

static INT64   g_baAlertedPids[BA_MAX_ALERTED_PIDS];
static INT     g_baAlertedCount = 0;

/* ── 误报缓解全局状态 ── */
static BA_WHITELIST_ENTRY g_baWhitelist[BA_MAX_WHITELIST];
static INT g_baWhitelistCount = 0;
static KSPIN_LOCK g_baWhitelistLock;

static BA_EXCEPTION_ENTRY g_baExceptions[BA_MAX_EXCEPTIONS];
static INT g_baExceptionCount = 0;
static KSPIN_LOCK g_baExceptionLock;

static BA_TRUSTED_PRODUCTOR g_baTrustedProducers[BA_MAX_TRUSTED_PRODUCTORS];
static INT g_baTrustedProducerCount = 0;
static KSPIN_LOCK g_baTrustedProducerLock;

BA_SIGNED_PRODUCTOR g_baSignedProducers[BA_MAX_SIGNED_PRODUCTORS];
static INT g_baSignedProducerCount = 0;
static KSPIN_LOCK g_baSignedProducerLock;

static BA_RULE_SUPPRESSION g_baSuppressions[BA_MAX_RULE_SUPPRESSIONS];
static INT g_baSuppressionCount = 0;
static KSPIN_LOCK g_baSuppressionLock;

BA_PROCESS_REPUTATION g_baReputations[BA_MAX_PROCESSES];
static INT g_baReputationCount = 0;
static KSPIN_LOCK g_baReputationLock;

static BA_EVIDENCE_QUALITY g_baEvidenceQuality[BA_MAX_INDICATORS];
static BOOLEAN g_baEvidenceQualityInitialized = FALSE;
static KSPIN_LOCK g_baEvidenceQualityLock;

static BA_LOOKBACK_WINDOW g_baLookbackWindows[BA_MAX_LOOKBACK_WINDOWS];
static INT g_baLookbackWindowCount = 0;
static KSPIN_LOCK g_baLookbackWindowLock;

/* 脏PID跟踪：有新事件需要评估的PID位图/列表
 * 优化：定时器线程只评估脏PID，而非全量扫描所有进程
 * 注意：标记一个进程有新事件时，其根祖先也需要被标记（因为指标会向上聚合） */
static INT64   g_baDirtyPids[BA_MAX_PROCESSES];
static INT     g_baDirtyCount = 0;

/* 异步定时器线程（卡巴斯基思路：回调同步记录，定时器异步分析） */
static volatile LONG g_baTimerRunning = 0;
static KEVENT g_baTimerExitEvent;  /* 线程退出时设置，用于等待线程终止 */

/* ── 规则版本与状态管理 ── */
static ULONG  g_baRuleVersion = 1;
static ULONG  g_baRuleRevision = 0;
static BA_RULE_STATE g_baGlobalRuleState = BA_RS_ENABLED;

/* ── 规则性能统计 ── */
BA_RULE_STATS g_baRuleStats[BA_MAX_PROFILES] = {0};
KSPIN_LOCK g_baRuleStatsLock;

/* ── 异常检测基线 ── */
#define BA_MAX_BASELINES 2048
BA_BASELINE g_baBaselines[BA_MAX_BASELINES];
INT g_baBaselineCount = 0;
KSPIN_LOCK g_baBaselineLock;

/* ── 文件释放跟踪（环形缓冲区，堆分配）──
 * 记录每个进程创建的新文件（FILE_CREATED），用于威胁清除时删除。
 * 仅记录非系统目录的文件创建，减少开销。
 * 容量由 BA_MAX_DROPPED_FILES 决定，超出时覆盖前的记录通过
 * SendRollbackLogRecord 上报主程序持久化到磁盘（溢出丢磁盘）。 */
#define BA_MAX_DROPPED_FILES   2048                    /* 扩容：512 -> 2048 */
#define BA_DROPPED_PATH_LEN    512  /* WCHAR count */

typedef struct _BA_DROPPED_FILE {
    INT64    pid;
    WCHAR    path[BA_DROPPED_PATH_LEN];
    USHORT   pathLen;     /* actual length in WCHARs (not including null) */
    BOOLEAN  valid;
} BA_DROPPED_FILE;

static BA_DROPPED_FILE* g_baDroppedFiles = NULL;       /* 堆分配 */
static volatile LONG g_baDroppedFileIdx = 0;
static KSPIN_LOCK g_baDroppedFileLock;

/* ── 注册表操作回滚跟踪（环形缓冲区，堆分配）──
 * 记录每个进程对注册表值的修改/删除，并备份修改前原始值，
 * 供用户选择 Block 时回滚（删除新增值 / 恢复被修改值）。
 * 容量由 BA_MAX_REG_OPS 决定，超出时覆盖前的记录通过
 * SendRollbackLogRecord 上报主程序持久化到磁盘（溢出丢磁盘）。 */
static BA_REG_OP_RECORD* g_baRegOps = NULL;            /* 堆分配 */
static volatile LONG g_baRegOpIdx = 0;
static KSPIN_LOCK g_baRegOpLock;

/* 注册表回调重入保护深度计数器：驱动自身发起的注册表访问会触发回调重入，
 * >0 时回调跳过记录与检测。定义于 BehaviorAnalysis.c，RegistryCallback.c 中 extern 使用。 */
volatile LONG g_regDriverAccessDepth = 0;

/* wpathToAscii: 将 WCHAR 路径转换为 ASCII（定义于文件后部），
 * 供回滚记录溢出上报（BehaviorRecordDroppedFile / BehaviorRecordRegOp）提前使用。 */
static void wpathToAscii(const WCHAR* wpath, USHORT wlen, CHAR* out, int maxChars);

/* 进程树批量操作：同时挂起/恢复/终止的最大 PID 数 */
#define BA_MAX_TREE_PIDS   64

/* ── ETW Threat-Intelligence 内存事件缓存 ── */
#define BA_ETW_ALLOC_CACHE_SIZE     512
#define BA_ETW_WRITE_CACHE_SIZE     512
#define BA_ETW_ALERT_COOLDOWN_SIZE  256
#define BA_ETW_ALERT_COOLDOWN_MS    10000   /* 同类型告警 10 秒冷却 */
#define BA_ETW_WRITE_CHAIN_AGE_MS   5000    /* Write 与 Protect 之间最大间隔 5 秒 */

typedef struct _BA_ETW_ALLOC_RECORD {
    INT64   targetPid;
    INT64   baseAddress;
    INT64   regionSize;
    ULONG   originalProtection;
    INT64   tickMs;
    BOOLEAN valid;
} BA_ETW_ALLOC_RECORD;

static BA_ETW_ALLOC_RECORD g_baEtwAllocCache[BA_ETW_ALLOC_CACHE_SIZE];
static KSPIN_LOCK g_baEtwAllocCacheLock;

typedef struct _BA_ETW_WRITE_RECORD {
    INT64   targetPid;
    INT64   baseAddress;
    INT64   regionSize;
    INT64   tickMs;
    BOOLEAN valid;
} BA_ETW_WRITE_RECORD;

static BA_ETW_WRITE_RECORD g_baEtwWriteCache[BA_ETW_WRITE_CACHE_SIZE];
static KSPIN_LOCK g_baEtwWriteCacheLock;

typedef struct _BA_ETW_ALERT_COOLDOWN {
    INT64   sourcePid;
    INT64   targetPid;
    CHAR    alertType[64];
    INT64   tickMs;
    BOOLEAN valid;
} BA_ETW_ALERT_COOLDOWN;

static BA_ETW_ALERT_COOLDOWN g_baEtwAlertCooldown[BA_ETW_ALERT_COOLDOWN_SIZE];
static KSPIN_LOCK g_baEtwAlertCooldownLock;

/* ── PID 签名缓存（避免对同一进程重复调用 CI 验证） ── */
typedef struct _BA_SIG_CACHE_ENTRY {
    INT64   pid;
    BOOLEAN isSigned;
    BOOLEAN valid;
} BA_SIG_CACHE_ENTRY;
#define BA_SIG_CACHE_SIZE 2048  /* 大幅扩充：覆盖全部活跃进程 + 已退出进程的签名槽位，
                                 * 支撑签名降级回滚、未签名 DLL 侧加载检测与长时历史追溯 */
BA_SIG_CACHE_ENTRY g_baSigCache[BA_SIG_CACHE_SIZE];
KSPIN_LOCK g_baSigCacheLock;

/* 行为分析告警 work item 上下文（生产级：挂起/弹窗/终止/恢复/清文件） */
typedef struct _BEHAVIOR_ALERT_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    INT64   rootPid;
    CHAR    rootImagePath[BA_MAX_PATH];
    BEHAVIOR_DETECTED_RESPONSE alertInfo;
    INT64   treePids[BA_MAX_TREE_PIDS];
    int     treePidCount;
    BOOLEAN hasSystemProc;
} BEHAVIOR_ALERT_WORKITEM_CTX;

static BOOLEAN IsAlreadyAlerted(INT64 pid)
{
    KIRQL oldIrql = 0;
    int i;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    for (i = 0; i < g_baAlertedCount; i++) {
        if (g_baAlertedPids[i] == pid) { found = TRUE; break; }
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    return found;
}

static INT64 FindRootAncestor(INT64 pid);

/* 标记PID及其根祖先为脏状态（有新事件需要重新评估） */
static VOID markDirty(INT64 pid)
{
    int i;
    INT64 rootPid;

    /* 标记自身 */
    for (i = 0; i < g_baDirtyCount; i++) {
        if (g_baDirtyPids[i] == pid) return;
    }
    if (g_baDirtyCount < BA_MAX_PROCESSES) {
        g_baDirtyPids[g_baDirtyCount++] = pid;
    }

    /* 标记根祖先（因为进程树指标是向上聚合的） */
    rootPid = FindRootAncestor(pid);
    if (rootPid != 0 && rootPid != pid) {
        for (i = 0; i < g_baDirtyCount; i++) {
            if (g_baDirtyPids[i] == rootPid) return;
        }
        if (g_baDirtyCount < BA_MAX_PROCESSES) {
            g_baDirtyPids[g_baDirtyCount++] = rootPid;
        }
    }
}

/* 轻量级系统进程检查（基于路径，无需查询token）
 * 优化：在评估早期跳过Windows系统目录下的已知系统进程，
 *       减少不必要的威胁画像匹配开销 */
BOOLEAN isSystemProcessByPath(const CHAR* imagePath)
{
    CHAR lower[BA_MAX_PATH];
    const CHAR* fname = NULL;
    const CHAR* p;
    int inSystemDir;
    int isExplorerInWindows;

    if (imagePath == NULL || imagePath[0] == '\0') return FALSE;

    kStrLowerCopy(lower, BA_MAX_PATH, imagePath);

    /* 检查是否在系统目录下：System32 / SysWOW64 / SystemApps (UWP 系统应用) */
    inSystemDir = kStrStrLen(lower, kStrLen(lower), "\\windows\\system32\\", 18) ||
                  kStrStrLen(lower, kStrLen(lower), "\\windows\\syswow64\\", 19) ||
                  kStrStrLen(lower, kStrLen(lower), "\\windows\\systemapps\\", 20);

    /* explorer.exe 位于 C:\Windows 根目录，不在 System32 下，需要特殊处理 */
    isExplorerInWindows = kStrStrLen(lower, kStrLen(lower), "\\windows\\explorer.exe", 23);

    if (!inSystemDir && !isExplorerInWindows) {
        return FALSE;
    }

    p = lower;
    while (*p) {
        if (*p == '\\' || *p == '/') fname = p + 1;
        p++;
    }
    if (fname == NULL) fname = lower;

    return IsKnownSystemProcessName(fname);
}

/* ── isGenuineSystemProcess: 真正的系统进程判定 ──
 * 三重验证，防止病毒通过改名/投放冒充系统进程：
 *   1. 路径在系统目录（System32/SysWOW64/SystemApps）或 explorer.exe 在 \Windows
 *   2. 进程名在已知系统进程白名单中（IsKnownSystemProcessName）
 *   3. 进程运行在 SYSTEM SID 下（isSystemSidProcess，创建时预计算）
 *
 * 仅 isSystemProcessByPath() 仅验证 1+2，病毒若以管理员权限将恶意文件
 * 投放至 System32 并命名为 consent.exe 即可绕过。加入 SID 验证后，
 * 病毒还必须以 SYSTEM 身份运行，大幅提高攻击门槛。
 *
 * 注意：本函数在持锁状态下调用，仅读取 g_baProcTree[idx].isSystemSidProcess
 * 缓存值，不调用 SeQueryInformationToken（需 PASSIVE_LEVEL）。
 *
 * 重要：进程不在 proc tree 中时（idx < 0），保守返回 FALSE。
 * 如果 minifilter 文件事件在进程创建通知之前到达，此时不能仅凭路径+名称
 * 就判定为系统进程——病毒可以投放恶意文件到 System32 并命名为已知系统进程
 * 名来绕过检测。宁可误报，不可漏报。 */
BOOLEAN isGenuineSystemProcess(int idx, const CHAR* imagePath)
{
    if (imagePath == NULL || imagePath[0] == '\0') return FALSE;
    if (!isSystemProcessByPath(imagePath)) return FALSE;
    /* 进程在 proc tree 中：使用预计算的 SYSTEM SID 缓存（最可靠）。 */
    /* 进程不在 proc tree 中：无法验证 SID，保守返回 FALSE。
     * 如果 minifilter 文件事件在进程创建通知之前到达，idx < 0，
     * 此时不能仅凭路径+名称就判定为系统进程——病毒可以投放恶意文件到
     * System32 并命名为已知系统进程名来绕过检测。
     * 宁可误报，不可漏报。 */
    if (idx < 0 || idx >= BA_MAX_PROCESSES) return FALSE;
    return g_baProcTree[idx].isSystemSidProcess;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 指标基础分数
 * ══════════════════════════════════════════════════════════════════════════ */

const DOUBLE g_baIndicatorScores[BA_MAX_INDICATORS] = {
    15.0, 20.0, 10.0,  3.0,  /* 0-3:   ProcFrom* (UNSIGNED 降为 3.0) */
    15.0, 20.0, 50.0, 40.0,  /* 4-7:   FileCreateSystemDir/Driver/StartupExe/DropFromTemp (SYSTEM_DIR 35→15, DRIVER 40→20) */
    45.0, 40.0, 40.0, 70.0,  /* 8-11:  FileCreateDllHijack/EncryptedExt/RansomNote/DllSideLoad (侧载提升至70) */
    35.0, 30.0, 25.0, 30.0,  /* 12-15: FileBrowserCred/SelfDel/NetShare/InfAutorun */
    35.0, 45.0, 50.0,        /* 16-18: FileHostsModify/DiskRaw/ByovdDriver */
    25.0, 45.0, 50.0, 40.0,  /* 19-22: RegRunKey/Ifeo/Winlogon/Service */
    35.0, 30.0,              /* 23-24: RegShellOpen/ScheduledTask */
    30.0, 25.0, 50.0,        /* 25-27: MemSystemProcess(40→30)/RemoteThread(35→25)/Lsass — 降低单项权重防调试器误报 */
    50.0, 35.0, 30.0, 30.0,  /* 28-31: ProcKill/Vssadmin/Bcdedit/FakeUpdate */
    35.0, 20.0, 30.0, 35.0, 40.0,  /* 32-36: KeyboardHook/HiddenWindow/AppDataDll/C2Connect/BootExec */
    50.0, 50.0, 55.0, 60.0, 55.0,  /* 37-41: MassSystemDelete/MassRegDelete/BootSector/MbrWrite/CriticalKill */
    15.0,                            /* 42: ScriptInterpreter */
    60.0,                            /* 43: OfficeSpawnCmd */
    45.0,                            /* 44: CertutilDownload */
    40.0,                            /* 45: BitsadminTransfer */
    50.0,                            /* 46: NetUserModify */
    55.0,                            /* 47: SvchostAnomaly */
    30.0,                            /* 48: IcaclsModify */
    45.0,                            /* 49: TaskkillSecurity */
    35.0,                            /* 50: MsiexecSilentInstall */
    40.0,                            /* 51: WmiPersistence */
    55.0,                            /* 52: MemCrossProcessWrite — 跨进程写入（注入核心步骤，保留适中权重因调试器也触发） */
    100.0,                           /* 53: MemInjectionChain (write + remote thread) — 完整注入链，一击必杀 */
    100.0,                           /* 54: MemProcessHollowing (create suspended + write + thread) — 进程镂空，一击必杀 */
    /* dllmain.cpp 补充：高危系统操作 (55-58) */
    90.0,                            /* 55: ProcRaiseHardError — R3层蓝屏调用，正常程序从不触发 */
    85.0,                            /* 56: ProcSetCritical — 设置关键进程，正常程序从不触发 */
    90.0,                            /* 57: ProcApcInjection — 跨进程APC注入（T1055.004），提高权重确保一击必杀 */
    90.0,                            /* 58: ProcMapSection — 跨进程内存映射注入（T1055.012），提高权重确保一击必杀 */
    /* PoolParty Windows Thread Pool injection variants (59-66) */
    85.0,                            /* 59: PoolParty Factory: WorkerFactory start routine overwrite — 提高权重 */
    85.0,                            /* 60: PoolParty Work: TP_WORK insertion — 提高权重 */
    85.0,                            /* 61: PoolParty Wait: TP_WAIT insertion — 提高权重 */
    85.0,                            /* 62: PoolParty IO: TP_IO insertion — 提高权重 */
    85.0,                            /* 63: PoolParty ALPC: TP_ALPC insertion — 提高权重 */
    85.0,                            /* 64: PoolParty Job: TP_JOB insertion — 提高权重 */
    85.0,                            /* 65: PoolParty Direct: TP_DIRECT insertion — 提高权重 */
    85.0,                            /* 66: PoolParty Timer: TP_TIMER insertion — 提高权重 */
    /* ETW Threat-Intelligence injection indicators (67-74) */
    95.0,                            /* 67: Remote executable memory allocation — 远程可执行内存分配，注入核心步骤 */
    90.0,                            /* 68: Remote memory protected to executable — 远程内存保护为可执行，注入核心步骤 */
    55.0,                            /* 69: Remote virtual memory write — 提高权重但保留适中（调试器也触发） */
    85.0,                            /* 70: Remote APC insertion — 远程APC插入，注入核心步骤 */
    85.0,                            /* 71: Remote thread context manipulation — 远程线程上下文操纵，注入核心步骤 */
    85.0,                            /* 72: Remote executable mapped view — 远程可执行映射，注入核心步骤 */
    80.0,                            /* 73: Non-exec alloc later protected to exec — 分配后保护链 */
    80.0,                            /* 74: Write then protect to exec — 写入后保护链 */
    70.0,                            /* 75: DLL side-loading detected — 只要侧载就触发行为防护 */
    /* Additional execution indicators (76-83) */
    40.0,                            /* 76: Mshta execution */
    35.0,                            /* 77: Regsvr32 scriptlet execution */
    35.0,                            /* 78: Control Panel item execution */
    50.0,                            /* 79: Mavinject injection */
    40.0,                            /* 80: CMSTP INF execution */
    40.0,                            /* 81: Msdt troubleshooting pack execution */
    45.0,                            /* 82: Signed binary proxy execution */
    35.0,                            /* 83: AppLocker bypass candidate */
    /* Network / C2 indicators (84-88) */
    55.0,                            /* 84: Suspicious outbound C2 connection */
    20.0,                            /* 85: Outbound connection to uncommon/high port (noisy alone) */
    40.0,                            /* 86: Suspicious DNS query pattern */
    45.0,                            /* 87: Process with network activity + injection indicators */
    30.0,                            /* 88: Persistent/long-duration connection */
    /* Syscall evasion indicators (89-90) */
    60.0,                            /* 89: Direct syscall from non-ntdll memory */
    50.0,                            /* 90: Indirect syscall via ntdll from suspicious origin */
    /* Ntdll reload / unhook indicators (91-93) */
    70.0,                            /* 91: Ntdll unhook/reload detected */
    65.0,                            /* 92: Ntdll remap/base change detected */
    40.0,                            /* 93: Ntdll loaded from non-system path */
    60.0,                            /* 94: Bulk file write (ransomware encryption behavior) */
    /* DCOM lateral movement indicators (95-101) */
    60.0,                            /* 95: DCOM remote activation detected */
    80.0,                            /* 96: DCOM MMC20.Application ExecuteShellCommand */
    75.0,                            /* 97: DCOM ShellWindows/ShellBrowserWindow ShellExecute */
    65.0,                            /* 98: DCOM Excel.Application remote DDE/macro */
    60.0,                            /* 99: DCOM Outlook.Application CreateObject */
    50.0,                            /* 100: DCOM child process spawned */
    55.0,                            /* 101: DCOM WMI remote execution */
    /* Syscall 分类追踪指标 (102-122) */
    50.0,                            /* 102: NtAllocateVirtualMemory via syscall */
    50.0,                            /* 103: NtProtectVirtualMemory via syscall */
    55.0,                            /* 104: NtWriteVirtualMemory via syscall */
    55.0,                            /* 105: NtCreateThreadEx via syscall */
    50.0,                            /* 106: NtQueueApcThread via syscall */
    50.0,                            /* 107: NtMapViewOfSection via syscall */
    45.0,                            /* 108: NtOpenProcess via syscall */
    60.0,                            /* 109: 多类型 syscall 同时使用 (工具行为) */
    100.0,                           /* 110: Syscall 注入链: Alloc+Write+Protect+Thread — 完整注入链，一击必杀 */
    55.0,                            /* 111: NtReadVirtualMemory via syscall (LSASS dump) */
    85.0,                            /* 112: NtSetContextThread via syscall — 线程上下文操纵注入 */
    85.0,                            /* 113: NtResumeThread via syscall (空心化) — 空心化恢复执行 */
    60.0,                            /* 114: NtAdjustPrivilegesToken via syscall (提权) */
    55.0,                            /* 115: NtDuplicateObject via syscall (句柄窃取) */
    55.0,                            /* 116: NtCreateUserProcess via syscall (fork&run) */
    40.0,                            /* 117: NtQuerySystemInformation via syscall (枚举) */
    40.0,                            /* 118: NtQueryInformationProcess via syscall */
    40.0,                            /* 119: NtCreateSection via syscall */
    80.0,                            /* 120: Syscall LSASS 凭据窃取链 */
    80.0,                            /* 121: Syscall 令牌窃取链 */
    100.0,                           /* 122: Syscall 进程空心化链 — 完整空心化，一击必杀 */
    /* 扩展 syscall 指标 (123-135) */
    45.0,                            /* 123: NtSuspendThread via syscall */
    50.0,                            /* 124: NtGetContextThread via syscall */
    55.0,                            /* 125: NtTerminateProcess via syscall（杀安全软件） */
    45.0,                            /* 126: NtFlushInstructionCache via syscall */
    40.0,                            /* 127: NtCreateKey via syscall（注册表持久化） */
    40.0,                            /* 128: NtSetValueKey via syscall（注册表修改） */
    40.0,                            /* 129: NtCreateFile via syscall（文件投放） */
    40.0,                            /* 130: NtDeleteFile via syscall（文件清理） */
    65.0,                            /* 131: NtLoadDriver via syscall（BYOVD 驱动加载） */
    60.0,                            /* 132: NtCreateWorkerFactory via syscall（PoolParty 注入） */
    50.0,                            /* 133: NtCreateNamedPipeFile via syscall（C2 命名管道） */
    50.0,                            /* 134: NtSetInformationProcess via syscall（断链/关键进程） */
    75.0,                            /* 135: Syscall 持久化链: CreateKey+SetValueKey+CreateFile */
    /* 漏报修复新增指标 (136-139) */
    45.0,                            /* 136: Self VirtualProtect RW→RX (shellcode 执行) — 可疑进程门控 */
    40.0,                            /* 137: 伪系统目录创建无签名可执行文件 (C:\Drivers\<random>\ 等) */
    60.0,                            /* 138: taskkill 针对安全/系统管理工具（反取证行为） */
    50.0,                            /* 139: 批量注册表修改（Winkiller 持久化/破坏） */
    /* 关键证据指标 (140-145) */
    35.0,                            /* 140: 读取 TimeZoneInformation（VM 规避 T1497.003） */
    35.0,                            /* 141: 读取 BIOS 信息（VM 检测 T1497.001） */
    30.0,                            /* 142: 读取 Terminal Server 键（RDP 探测 T1021.001） */
    45.0,                            /* 143: 进程枚举批量（进程发现 T1057） */
    40.0,                            /* 144: 自身打开 VM_OPERATION（shellcode 前置 T1055） */
    70.0,                            /* 145: DLL Load via ROP（调用栈含非镜像返回地址 T1055.001） */
    /* ATT&CK 战术补充指标 (146-159)：覆盖 0% 覆盖率战术的关键行为 */
    55.0,                            /* 146: MotW Zone.Identifier ADS 读取（钓鱼附件 T1566.001） */
    50.0,                            /* 147: 已签名 EXE 加载未签名 DLL（供应链 T1195.002） */
    60.0,                            /* 148: HKCU\Classes\*\shell\open\command 劫持（UAC Bypass T1548.002） */
    65.0,                            /* 149: Token Impersonation 链（令牌窃取 T1134.001） */
    70.0,                            /* 150: CreateProcess with Token（提权创建 T1134.002） */
    85.0,                            /* 151: SAM/SYSTEM/SECURITY 配置文件读取（凭据转储 T1003.002） */
    75.0,                            /* 152: DS 恢复模式密码查询（DCSync 前置 T1003.006） */
    70.0,                            /* 153: DPAPI 主密钥文件读取（凭据存储 T1555） */
    80.0,                            /* 154: SECURITY\Policy\Secrets 读取（LSA Secrets T1003.004） */
    45.0,                            /* 155: net.exe user/group 账户枚举（账户发现 T1087） */
    35.0,                            /* 156: HARDWARE\DESCRIPTION 系统信息频次查询（系统发现 T1082） */
    55.0,                            /* 157: 非截图工具创建 .png/.bmp 至 temp（屏幕捕获 T1113） */
    50.0,                            /* 158: 批量 exe/dll 复制至暂存目录（数据暂存 T1074） */
    60.0,                            /* 159: shutdown.exe /s /r /t 0（系统关机/重启 T1529） */
    /* 浏览器 elevation_service 持久化检测 (160-161) */
    75.0,                            /* 160: 替换/投放 elevation_service DLL/EXE（T1574.002 DLL 侧加载 T1543.003） */
    70.0,                            /* 161: 修改 elevation_service CLSID/服务/Update Client 键（T1546.015/T1543.003） */
    /* 银狐家族分类低危指标 (162-163)：仅作家族归类辅助，权重极低不单独触发警报 */
    8.0,                             /* 162: 伪装目录投放可执行文件（银狐家族特征，低危仅归类） */
    8.0,                             /* 163: 临时目录随机文件名可执行文件（银狐家族特征，低危仅归类） */
    /* 注入防护强化指标 (164-167)：参考 Elastic Security shellcode thread 检测策略 */
    85.0,                            /* 164: 远程线程起始地址非镜像（shellcode 注入 T1055） */
    30.0,                            /* 165: 高风险父进程上下文加权（Office/脚本/LOLBin 注入操作） */
    90.0,                            /* 166: EDR-Freeze via WerFaultSecure（T1562.001）— 正常程序从不触发 */
    25.0,                            /* 167: 注入频率抑制（多次尝试，工具行为） */
    /* Trojan.SilverFox 指标 (168-169) */
    40.0,                            /* 168: 将文件设置为系统级隐藏属性（银狐家族 T1562.002） */
    10.0,                            /* 169: 图像文件内含PE可执行特征（银狐家族 T1566.001，降低权重避免临时文件误报） */
    /* Trojan.AVBypass 指标 (170-172) */
    60.0,                            /* 170: 修改 ETW 注册表禁用事件追踪（T1562.002） */
    65.0,                            /* 171: 修改 InstrumentationCallback 绕过监控（T1562.001） */
    70.0,                            /* 172: 直接 patch ETW 内核函数（T1562.002） */
    /* Trojan.Rootkit 指标 (173-174) */
    75.0,                            /* 173: 加载已知高危/漏洞驱动（BYOVD T1068） */
    55.0,                            /* 174: 创建高危驱动服务（Rootkit 持久化 T1547.001） */
    /* Trojan.Exploit 指标 (175-180) */
    50.0,                            /* 175: 分配可执行内存（shellcode 执行 T1055.003） */
    60.0,                            /* 176: 自身进程分配并执行可执行内存（自解密 shellcode T1055） */
    65.0,                            /* 177: 非系统进程将非MEM_IMAGE内存设为RWX（PAGE_EXECUTE_READWRITE） */
    60.0,                            /* 178: 非系统进程将非MEM_IMAGE内存设为只读可执行（PAGE_EXECUTE_READ） */
    20.0,                            /* 179: 文件重命名操作（T1036/T1222，低权重仅作为上下文） */
    85.0,                            /* 180: 检测到shellcode特征（深度多家族分析+沙盒模拟，评分制判定） */
    55.0,                            /* 181: 创建非标准后缀名的可执行文件（无正常后缀但有PE特征） */
    45.0,                            /* 182: 创建隐藏的可执行文件 */
    55.0,                            /* 183: 创建系统级隐藏的可执行文件 */
    50.0,                            /* 184: 同目录下存在可执行文件时创建隐藏的可执行文件 */
    30.0,                            /* 185: 未签名进程加载同目录未签名 DLL（侧载低分） */
    0.0                              /* 186: Invalid indicator (no score) */
};

/* 威胁画像已迁移至动态 TOML 规则 (rules/behavior/*.toml)，静态 profiles 已移除 */

/* ═══════════════════════════════════════════════════════════════════════════
 * 内核安全字符串工具函数
 * ══════════════════════════════════════════════════════════════════════════ */

int kStrLen(const CHAR* s)
{
    int n = 0;
    if (s == NULL) return 0;
    while (s[n] != '\0') n++;
    return n;
}

static void kStrCat(CHAR* dest, ULONG destSize, const CHAR* src)
{
    if (dest == NULL || src == NULL || destSize == 0) return;
    int destLen = 0;
    while (dest[destLen] != '\0' && destLen < (int)destSize - 1) destLen++;
    int srcIdx = 0;
    while (src[srcIdx] != '\0' && destLen + srcIdx < (int)destSize - 1) {
        dest[destLen + srcIdx] = src[srcIdx];
        srcIdx++;
    }
    dest[destLen + srcIdx] = '\0';
}

int kStrCmp(const CHAR* a, const CHAR* b)
{
    if (a == b) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int kStrNCmp(const CHAR* a, const CHAR* b, int n)
{
    int i;
    if (a == b) return 0;
    if (a == NULL) return -1;
    if (b == NULL) return 1;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return (unsigned char)a[i] - (unsigned char)b[i];
        if (a[i] == '\0') return 0;
    }
    return 0;
}

int kStrIStrLen(const CHAR* haystack, int hayLen, const CHAR* needle, int needleLen)
{
    int i, j;
    if (haystack == NULL || needle == NULL) return 0;
    if (needleLen == 0) return 0;
    if (hayLen < needleLen) return 0;

    for (i = 0; i <= hayLen - needleLen; i++) {
        int match = 1;
        for (j = 0; j < needleLen; j++) {
            CHAR hc = haystack[i + j];
            CHAR nc = needle[j];
            /* 大小写不敏感比较 */
            if (hc >= 'A' && hc <= 'Z') hc = (CHAR)(hc + 32);
            if (nc >= 'A' && nc <= 'Z') nc = (CHAR)(nc + 32);
            if (hc != nc) { match = 0; break; }
        }
        if (match) return 1;
    }
    return 0;
}

int kStrStrLen(const CHAR* haystack, int hayLen, const CHAR* needle, int needleLen)
{
    int i, j;
    if (haystack == NULL || needle == NULL) return 0;
    if (needleLen == 0) return 0;
    if (hayLen < needleLen) return 0;

    for (i = 0; i <= hayLen - needleLen; i++) {
        int match = 1;
        for (j = 0; j < needleLen; j++) {
            if (haystack[i + j] != needle[j]) { match = 0; break; }
        }
        if (match) return 1;
    }

    return 0;
}

/* kStrStr — 简易字符串查找（包装 kStrStrLen，自动计算长度） */
int kStrStr(const CHAR* haystack, const CHAR* needle)
{
    if (haystack == NULL || needle == NULL) return 0;
    return kStrStrLen(haystack, kStrLen(haystack), needle, kStrLen(needle));
}
int kStrEndsWith(const CHAR* str, const CHAR* suffix)
{
    int strLen, sufLen;
    if (str == NULL || suffix == NULL) return 0;
    strLen = kStrLen(str);
    sufLen = kStrLen(suffix);
    if (sufLen > strLen) return 0;
    return kStrCmp(str + strLen - sufLen, suffix) == 0;
}

VOID kStrLowerCopy(CHAR* dst, int dstSize, const CHAR* src)
{
    int i = 0;
    if (dst == NULL || src == NULL) return;
    while (i < dstSize - 1 && src[i] != '\0') {
        CHAR c = src[i];
        if (c >= 'A' && c <= 'Z') c = (CHAR)(c + 32);
        dst[i] = c;
        i++;
    }
    dst[i] = '\0';
}

/* ── IsKnownSystemProcessName: 判断进程短名是否为已知 Windows 系统进程 ──
 * 使用精确匹配（非子串匹配），避免 "mywinlogon.exe" 被误判为关键进程，
 * 也避免 "winlogon" 因子串而匹配不到 "winlogon.exe"。
 * 名称必须已转换为小写。
 * 非 static：供 ProcessCallback.c 等外部模块复用，避免维护两份白名单。 */
BOOLEAN IsKnownSystemProcessName(const CHAR* nameLower)
{
    static const CHAR* knownNames[] = {
        /* 核心系统关键进程（终止通常导致蓝屏或系统崩溃） */
        "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe", "explorer.exe",
        "dwm.exe", "fontdrvhost.exe", "conhost.exe", "dllhost.exe",
        "audiodg.exe", "spoolsv.exe",
        /* Windows 激活 / 许可证服务（sppsvc 会创建 SppExtComObj.exe 子进程） */
        "sppsvc.exe", "sppsextcomobj.exe", "sppsextcomobj.e",
        /* 内核/会话管理特殊进程名（无 .exe） */
        "system", "registry", "system idle process",
        /* 系统服务宿主与任务调度相关 */
        "taskhostw.exe", "taskhost.exe", "taskhostex.exe", "taskeng.exe",
        "schedule", "runtimebroker.exe", "backgroundtaskhost.exe",
        "wmiprvse.exe", "searchindexer.exe", "msmpeng.exe",
        /* Windows Search 相关进程（SearchProtocolHost 是 SearchIndexer 子进程） */
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
        "searchprotocolhost.ex",   /* PsGetProcessImageFileName 15字符截断 */
        "searchfilterhost.ex",     /* PsGetProcessImageFileName 15字符截断 */
        /* UWP / Shell / 桌面环境（同时加入 8.3 短名，因为 PsGetProcessImageFileName
         * 返回的是短名；长名用于路径已知场景，短名用于回调中仅能看到短名的场景） */
        "searchui.exe", "searchapp.exe", "searchapp.ex",   /* Windows 10/11 Search */
        "search~1.exe", "search~2.exe", "search~3.exe",    /* 8.3 短名：SearchApp/SearchProtocolHost/SearchFilterHost/SearchHost */
        "shellexperiencehost.exe", "startmenuexperiencehost.exe",
        "shelle~1.exe", "shelle~2.exe",                    /* ShellExperienceHost 8.3 */
        "startm~1.exe", "startm~2.exe",                    /* StartMenuExperienceHost 8.3 */
        "searchhost.exe", "textinputhost.exe", "lockapp.exe",
        "search~1.ex", "search~2.ex", "search~3.ex",      /* 15 字符截断形式 */
        "textin~1.exe", "textin~2.exe",                    /* TextInputHost 8.3 */
        "lockap~1.exe", "lockap~2.exe",                    /* LockApp 8.3 */
        "applicationframehost.exe", "shellExperiencehost.exe",
        "applic~1.exe", "applic~2.exe",                    /* ApplicationFrameHost 8.3 */
        "systemsettings.exe", "securityhealthservice.exe",
        "sihost.exe", "ctfmon.exe", "cortana.exe",
        /* Windows 更新 / 维护 */
        "tiworker.exe", "trustedinstaller.exe", "usocoreworker.exe",
        "usoclient.exe", "waasmedic.exe", "mousocoreworker.exe",
        "compattelrunner.exe", "updateassistant.exe",
        "windowsupdateelevatedinstaller.exe",
        "musnotification.exe", "musnotificationux.exe",
        /* 其他常见系统进程 */
        "taskbar.exe", "widgetservice.exe", "phoneexperiencehost.exe",
        "edgeupdate.exe", "microsoftedgeupdate.exe",
        "securesystem.exe", "sgrmbroker.exe", "mmcss.exe", "vmcompute.exe",
        /* Windows 错误报告与服务控制管理器相关进程（WerFault 需读取崩溃进程内存，
         * 若不加入白名单会被误报为 CriticalProcessHijack / 注入攻击） */
        "werfault.exe", "werfaultsecure.exe", "wermgr.exe",
        "servicehost.exe",
        /* UAC 同意进程：用户提权时由 svchost.exe 启动，位于 System32 下，
         * 会写系统目录/注册表/加载 Microsoft 共享 DLL，属于正常系统行为 */
        "consent.exe",
        /* 网络工具：ftp/telnet/ping/tracert/nslookup 等位于 System32 下的标准系统工具 */
        "ftp.exe",
        NULL
    };
    int i;

    if (nameLower == NULL || nameLower[0] == '\0') return FALSE;

    for (i = 0; knownNames[i] != NULL; i++) {
        if (kStrCmp(nameLower, knownNames[i]) == 0) return TRUE;
    }
    return FALSE;
}

VOID kStrCpy(CHAR* dst, int dstSize, const CHAR* src)
{
    int i = 0;
    if (dst == NULL || src == NULL) return;
    while (i < dstSize - 1 && src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

int kStrToInt64(const CHAR* str, INT64* out)
{
    INT64 value = 0;
    int sign = 1;
    int i = 0;
    if (str == NULL || out == NULL) return 0;
    if (str[i] == '-') { sign = -1; i++; }
    if (str[i] == '\0') return 0;
    while (str[i] != '\0') {
        if (str[i] < '0' || str[i] > '9') break;
        value = value * 10 + (str[i] - '0');
        i++;
    }
    *out = value * sign;
    return 1;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 脚本解释器检测
 * ══════════════════════════════════════════════════════════════════════════ */

static int IsScriptInterpreter(const CHAR* imagePath)
{
    static const CHAR* interpreters[] = {
        "powershell.exe", "pwsh.exe", "cmd.exe",
        "wscript.exe", "cscript.exe", "mshta.exe"
    };
    CHAR lower[BA_MAX_PATH];
    int i, len;
    if (imagePath == NULL) return 0;
    kStrLowerCopy(lower, BA_MAX_PATH, imagePath);
    len = kStrLen(lower);
    for (i = 0; i < (int)(sizeof(interpreters) / sizeof(interpreters[0])); i++) {
        int ilen = kStrLen(interpreters[i]);
        if (len >= ilen) {
            /* 匹配路径末尾的进程名 */
            if (kStrCmp(lower + len - ilen, interpreters[i]) == 0)
                return 1;
            /* 也匹配路径中包含该名称（如完整路径） */
            if (kStrStrLen(lower, len, interpreters[i], ilen))
                return 1;
        }
    }
    return 0;
}

/* 精确化浏览器路径检测，避免像 "edge" 这样的短子串导致误报 */
static int IsBrowserDirectory(const CHAR* dirLower, int dirLen)
{
    static const CHAR* patterns[] = {
        "google\\chrome\\user data",
        "\\chrome\\user data\\",
        "microsoft\\edge\\",
        "\\edge\\user data\\",
        "\\edge\\application\\",
        "mozilla\\firefox\\",
        "\\firefox\\profiles\\",
        "\\opera\\",
        "\\brave\\",
        "\\vivaldi\\",
        "\\chromium\\",
        "\\qqbrowser\\",
        "\\maxthon\\",
        "\\sogou\\",
        "\\360se\\"
    };
    int i;

    if (!dirLower || dirLen == 0) return 0;

    for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++) {
        int plen = kStrLen(patterns[i]);
        if (plen == 0) continue;
        if (kStrStrLen(dirLower, dirLen, patterns[i], plen)) return 1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 查找/创建函数
 * ══════════════════════════════════════════════════════════════════════════ */

int findProc(INT64 pid)
{
    int i;
    for (i = 0; i < g_baProcCount; i++) {
        if (g_baProcTree[i].pid == pid) return i;
    }
    return -1;
}

static int findOrCreateProc(INT64 pid)
{
    int idx = findProc(pid);
    if (idx >= 0) return idx;
    if (g_baProcCount >= BA_MAX_PROCESSES) return -1;
    idx = g_baProcCount++;
    RtlZeroMemory(&g_baProcTree[idx], sizeof(BA_PROCESS_NODE));
    g_baProcTree[idx].pid = pid;
    return idx;
}

int findPidIndex(INT64 pid)
{
    int i;
    for (i = 0; i < g_baIndicatorCount; i++) {
        if (g_baIndicatorPids[i] == pid) return i;
    }
    return -1;
}

static int findOrCreatePidIndex(INT64 pid)
{
    int idx = findPidIndex(pid);
    int i;
    if (idx >= 0) return idx;
    if (pid == 0) return -1;  /* 拒绝 PID 0（System Idle Process 不产生用户态事件） */
    if (g_baIndicatorCount >= BA_MAX_PROCESSES) return -1;
    idx = g_baIndicatorCount++;
    for (i = 0; i < BA_MAX_INDICATORS; i++) g_baPidIndicators[idx][i] = 0;
    g_baPidSyscallTypes[idx] = 0;
    g_baIndicatorPids[idx] = pid;
    return idx;
}

static VOID addIndicator(int idx, BA_INDICATOR id, const CHAR* evidence)
{
    int i;
    INT64 pid;
    if (idx < 0 || idx >= BA_MAX_PROCESSES) return;
    if (id < 0 || id >= BA_MAX_INDICATORS) return;
    g_baPidIndicators[idx][id]++;
    /* 证据去重：同一证据文本只记录一次，避免 ba scan 输出大量重复条目 */
    if (g_baEvidence[idx].count < BA_MAX_EVIDENCE) {
        for (i = 0; i < g_baEvidence[idx].count; i++) {
            if (kStrCmp(g_baEvidence[idx].items[i], evidence) == 0) return;
        }
        kStrCpy(g_baEvidence[idx].items[g_baEvidence[idx].count], 128, evidence);
        g_baEvidence[idx].count++;
    }

    /* 标记该PID及其根祖先为脏状态，定时器线程将重新评估
     * 优化：避免全量扫描所有进程，只评估有新事件的进程 */
    pid = g_baIndicatorPids[idx];
    if (pid != 0) {
        markDirty(pid);
    }
}

/* ── 判断源进程是否为受信任的 Windows 系统组件 ──
 * 用于排除系统进程间正常的父子操作（如 sppsvc.exe 创建 SppExtComObj.exe）
 * 被误判为 ProcessHollowing。
 *   1. 若路径包含 \Windows\System32\ 或 \Windows\SysWOW64\ 视为系统组件。
 *   2. 若路径仅为短名，匹配 IsKnownSystemProcessName 白名单。
 * 路径可能是 device 格式 \Device\HarddiskVolumeX\Windows\System32\...
 * 或 Win32 格式 C:\Windows\System32\...，也可能只是短名 sppsvc.exe。 */

/* 所有基于身份的白名单函数已被删除。这些函数通过进程名/路径跳过检测，
 * 是严重的安全漏洞——恶意程序只需将自身放入白名单目录即可完全绕过检测。
 *
 * 正确的做法是从行为逻辑上精细化指标（如访问掩码验证、父子关系分析、自操作过滤），
 * 而不是基于"谁"来跳过检测。isGenuineSystemProcess（需SYSTEM SID验证）保留作为
 * 真正的系统进程判定，用于区分真正的系统进程与冒名程序。 */



/* ═══════════════════════════════════════════════════════════════════════════
 * 指标提取 — 核心逻辑
 * ══════════════════════════════════════════════════════════════════════════ */

static VOID extractIndicators(const BA_STORED_EVENT* ev)
{
    int idx, imgLen, dirLen, fnameLen, procLen, i, regPathLen;
    int procIdx;
    CHAR imgLower[BA_MAX_PATH];
    CHAR dirLower[BA_MAX_PATH];
    CHAR fnameLower[BA_MAX_NAME];
    CHAR extLower[16];
    CHAR procLower[BA_MAX_NAME];
    int isSystemDir = 0, isDriversDir = 0, isStartupDir = 0, isCreate = 0;
    INT64 access;
    int hasCreateThrd, hasVMRead;

    if (ev == NULL) return;

    idx = findOrCreatePidIndex(ev->pid);
    if (idx < 0) return;

    /* ── 进程路径检查 ──
     * 优先使用进程树中存储的完整路径（ProcessCreateNotifyRoutine 通过
     * ZwQueryInformationProcess 获取），回调传入的 ev->imagePath 仅为短名 */
    procIdx = findProc(ev->pid);
    if (procIdx >= 0 && g_baProcTree[procIdx].imagePath[0]) {
        kStrLowerCopy(imgLower, BA_MAX_PATH, g_baProcTree[procIdx].imagePath);
    } else {
        kStrLowerCopy(imgLower, BA_MAX_PATH, ev->imagePath);
    }
    imgLen = kStrLen(imgLower);

    if (kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
        addIndicator(idx, BA_IND_PROC_FROM_TEMP_DIR, "Process from Temp");
    }
    if (kStrStrLen(imgLower, imgLen, "\\downloads\\", 11)) {
        addIndicator(idx, BA_IND_PROC_FROM_DOWNLOADS_DIR, "Process from Downloads");
    }
    if (kStrStrLen(imgLower, imgLen, "\\appdata\\", 9) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\temp\\", 20) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\programs\\", 24) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\microsoft\\", 25) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\roaming\\microsoft\\", 27) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\packages\\", 24)) {
        addIndicator(idx, BA_IND_PROC_FROM_APPDATA_DIR, "Process from AppData");
    }

    /* 脚本解释器检测（PowerShell/cmd/wscript等，用于识别脚本型威胁） */
    if (IsScriptInterpreter(imgLower)) {
        addIndicator(idx, BA_IND_PROC_SCRIPT_INTERPRETER, "Script interpreter process");
    }

    /* 隐藏窗口进程：仅对非系统进程生效。真正的系统进程（SYSTEM SID）如 taskhostw.exe 等
     * 即使路径包含关键词也不应以此作为威胁依据，避免误报。 */
    if (!isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrIStrLen(imgLower, imgLen, "hidden", 6) || kStrIStrLen(imgLower, imgLen, "silent", 6) ||
        kStrIStrLen(imgLower, imgLen, "stealth", 7) || kStrIStrLen(imgLower, imgLen, "invisible", 9) ||
        kStrIStrLen(imgLower, imgLen, "background", 10) || kStrIStrLen(imgLower, imgLen, "daemon", 6))) {
        addIndicator(idx, BA_IND_PROC_HIDDEN_WINDOW, "Hidden window process");
    }

    /* ── Memory 类别 ── */
    if (ev->category == BA_EC_Memory) {
        kStrLowerCopy(procLower, BA_MAX_NAME, ev->targetProcess);
        procLen = kStrLen(procLower);
        access = ev->desiredAccess;

        /* 生产级系统进程判定：isTargetSystemProcess 由 BehaviorRecordMemoryEvent
         * 在锁外（PASSIVE_LEVEL）通过 IsSystemProcessByEPROCESS → SeQueryInformationToken
         * 预计算。SeQueryInformationToken 仅允许在 PASSIVE_LEVEL 调用，不能在
         * 自旋锁持有的 DISPATCH_LEVEL 下执行，否则蓝屏 IRQL_NOT_LESS_OR_EQUAL。 */
        int isSysProc = ev->isTargetSystemProcess ? 1 : 0;
        int isLsassProc = 0;
        {
            /* 单独识别 lsass.exe：PsLookupProcessByProcessId 安全于 DISPATCH_LEVEL，
             * PsGetProcessImageFileName 最多 15 字符，lsass.exe 不会被截断。 */
            PEPROCESS targetProc = NULL;
            if (ev->targetPid != 0 &&
                NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ev->targetPid, &targetProc)))
            {
                if (targetProc != NULL) {
                    UCHAR* tgtName = PsGetProcessImageFileName(targetProc);
                    if (tgtName) {
                        CHAR lowerName[32] = {0};
                        int ni;
                        for (ni = 0; ni < 15 && tgtName[ni]; ni++) {
                            CHAR c = (CHAR)tgtName[ni];
                            if (c >= 'A' && c <= 'Z') c += 32;
                            lowerName[ni] = c;
                        }
                        lowerName[ni] = '\0';
                        if (kStrCmp(lowerName, "lsass.exe") == 0)
                            isLsassProc = 1;
                    }
                    ObDereferenceObject(targetProc);
                    targetProc = NULL;
                }
            }
        }

        hasCreateThrd = (access & 0x0002) != 0;
        hasVMRead     = (access & 0x0010) != 0;

        /* OPEN_SYSTEM_PROCESS: 仅当请求包含真正可疑的跨进程操作权限时才记录。
         * 纯查询类访问（QUERY_INFORMATION/QUERY_LIMITED）在 EDR/任务管理器中
         * 极为常见，不应作为注入指标。 */
        if (isSysProc &&
            (access & (0x0002 | 0x0008 | 0x0020 | 0x0040 | 0x0200 | 0x0800 | 0x0001)) != 0)
        {
            addIndicator(idx, BA_IND_MEM_OPEN_SYSTEM_PROCESS, "Open system process handle with suspicious access");
        }

        /* READ_LSASS: 严格限定目标为 lsass.exe 且含 VM_READ，减少其他系统进程
         * 正常内存查询导致的误报。 */
        if (isLsassProc && hasVMRead) {
            addIndicator(idx, BA_IND_MEM_READ_LSASS, "Read LSASS process memory");
        }

        /* MEM_OPEN_REMOTE_THREAD: 仅在目标为系统进程时标记为可疑
         * 对普通进程的远程线程由 INJECTION_CHAIN (VM_WRITE+THREAD) 覆盖
         * 避免调试器调试普通程序时误报 */
        if (hasCreateThrd && isSysProc) {
            addIndicator(idx, BA_IND_MEM_OPEN_REMOTE_THREAD, "Create remote thread in system process");
        }

        /* 互签检测：当源进程和目标进程均为已签名进程时，跨进程操作属于
         * 正常进程间通信，不应视为注入行为。此条件基于以下原则：
         * - 已签名进程（如 Microsoft、Adobe、Google 等发布的软件）不会执行
         *   未授权的代码注入操作
         * - 已签名进程间的跨进程操作是合法的 IPC（如调试器、性能监视器、
         *   浏览器多进程架构等）
         * - 注入是恶意软件（通常未签名）的典型行为，已签名进程不会执行注入 */
        BOOLEAN mutuallySigned = ev->isSigned && ev->targetIsSigned;

        /* 跨进程内存写入检测 (T1055)
         * PROCESS_VM_WRITE (0x0020) + PROCESS_VM_OPERATION (0x0008)
         * 是 WriteProcessMemory / NtProtectVirtualMemory 的前置权限。
         * 源PID == 目标PID 时说明是进程自操作，不是跨进程注入，跳过。
         * 父子进程间（父初始化子）的操作是正常进程创建行为，不是注入，跳过。
         * 互签进程间（双签名）的操作是正常 IPC，不是注入，跳过。
         * 注意：此处的"父子跳过"不适用于进程镂空（Process Hollowing），
         * 因为镂空本身就是父进程创建子进程后注入的模式，由下方独立检测。 */
        if ((access & 0x0020) && (access & 0x0008) && ev->pid != ev->targetPid && !ev->isParentChild && !mutuallySigned) {
            addIndicator(idx, BA_IND_MEM_CROSS_PROCESS_WRITE, "Cross-process memory write (VM_WRITE+VM_OPERATION)");

            /* 注入链检测: 跨进程写入 + 远程线程 = 经典 DLL/shellcode 注入 */
            if (hasCreateThrd) {
                addIndicator(idx, BA_IND_MEM_INJECTION_CHAIN, "Injection chain: cross-process write + remote thread");
            }
        }

        /* 进程镂空检测 (T1055.012)：独立于上述跨进程写入检测。
         * 镂空是父进程创建挂起子进程后注入攻击代码的特殊模式，必须发生在
         * 父子进程之间（ev->isParentChild == TRUE），与上述跨进程写入的
         * "父子跳过"逻辑不冲突——镂空是例外，需要单独检测。
         * 条件：父进程 + 写入权限 + 远程线程 + 读取权限 + 子进程创建后15秒内。
         * 15秒窗口排除运行中父子进程的正常交互，仅覆盖创建挂起瞬间的注入行为。 */
        if (ev->isParentChild && (access & 0x0020) && (access & 0x0008) &&
            hasCreateThrd && hasVMRead && ev->pid != ev->targetPid)
        {
            INT64 nowMs = baEtwTickMs();
            INT64 targetCreateMs = 0;
            int tgtIdx2 = findProc(ev->targetPid);
            if (tgtIdx2 >= 0) {
                targetCreateMs = g_baProcTree[tgtIdx2].createTickMs;
            }
            if (targetCreateMs != 0 && (nowMs - targetCreateMs) <= 15000) {
                addIndicator(idx, BA_IND_MEM_PROCESS_HOLLOWING, "Process hollowing: parent->child + write + thread + read (recently created)");
            }
        }

        /* ── dllmain.cpp 补充：高危系统操作检测 ── */

        /* 关键进程设置检测: PROCESS_SET_INFORMATION (0x0200)
         * 用于 NtSetInformationProcess(ProcessBreakOnTermination) / RtlSetProcessIsCritical
         * 正常程序极少请求此权限对其他进程操作 */
        if ((access & 0x0200) && !isSysProc) {
            addIndicator(idx, BA_IND_PROC_SET_CRITICAL, "Request PROCESS_SET_INFORMATION on remote process (potential critical flag set)");
        }

        /* APC注入检测: PROCESS_VM_OPERATION (0x0008) 但无 PROCESS_VM_WRITE (0x0020)
         * NtQueueApcThread 只需要 VM_OPERATION 权限，不需要 VM_WRITE
         * 组合 THREAD_SET_CONTEXT 也可能指示 APC 注入 */
        if ((access & 0x0008) && !(access & 0x0020) && hasCreateThrd && !isSysProc) {
            addIndicator(idx, BA_IND_PROC_APC_INJECTION, "APC injection: VM_OPERATION + remote thread without VM_WRITE");
        }

        /* 内存映射注入检测: PROCESS_VM_OPERATION (0x0008) + PROCESS_DUP_HANDLE (0x0040)
         * NtMapViewOfSection 通常通过 DuplicateHandle 复制段句柄到目标进程
         * 无 VM_WRITE 但有 VM_OPERATION + DUP_HANDLE 可能是映射注入 */
        if ((access & 0x0008) && (access & 0x0040) && !(access & 0x0020)) {
            addIndicator(idx, BA_IND_PROC_MAP_SECTION, "Map section injection: VM_OPERATION + DUP_HANDLE without VM_WRITE");
        }

        /* 安全进程检测：必须同时满足目标进程名匹配 AND 访问掩码包含终止相关权限。
         * 仅凭目标进程名匹配就标记为"企图终止安全进程"是严重误报源。
         * 正常程序（如任务管理器、性能监视器）可以合法打开安全进程的句柄进行
         * 信息查询（QUERY_INFORMATION/QUERY_LIMITED），这并不等于企图终止。
         * 正确的检测逻辑：目标进程名匹配安全产品 + 开放了实际终止所需权限位。
         * 终止权限：PROCESS_TERMINATE (0x0001) = 直接调用 TerminateProcess
         * 注入式终止：PROCESS_VM_WRITE (0x0020) + PROCESS_VM_OPERATION (0x0008) =
         *   WriteProcessMemory 注入 shellcode 间接终止
         * 远程线程注入：PROCESS_CREATE_THREAD (0x0002) + PROCESS_VM_OPERATION (0x0008) =
         *   CreateRemoteThread 创建线程执行终止代码
         * 排除 PROCESS_ALL_ACCESS (0x1FFFFF/0x1F0FFF)：全权限同样包含上述所有位，
         * 但普通系统工具也常使用 ALL_ACCESS 打开进程句柄，单凭 ALL_ACCESS 不足以
         * 判定为终止企图（由行为分析画像综合其他指标判定）。 */
        {
            static const CHAR* secProcs[] = {
                "avp.exe", "kavfs", "msmpeng.exe", "ekrn.exe", "bdagent.exe",
                "360tray.exe", "hipsdaemon.exe", "zhudongfangyu.exe",
                "avastui.exe", "avgui.exe", "mbam.exe", "mbamservice.exe",
                "nissrv.exe", "sophosav.exe", "mcshield.exe", "fsdfwd.exe",
                "fssm32.exe", "pccntmon.exe", "tmproxy.exe", "nsmdtr.exe",
                "wrsa.exe", "csfalconservice.exe", "cb.exe", "cylancesvc.exe",
                "sentinelone", "trendmicro", "comodo", "clamav.exe", "bytefence.exe",
                "savservice.exe", "sophosfs.exe", "hitmanpro.exe", "emsisoft.exe"
            };
            BOOLEAN hasTerminateAccess = (access & 0x0001) != 0;  /* PROCESS_TERMINATE */
            BOOLEAN hasWriteAndOper = (access & 0x0020) && (access & 0x0008);  /* VM_WRITE + VM_OPERATION */
            BOOLEAN hasCreateAndOper = (access & 0x0002) && (access & 0x0008);  /* CREATE_THREAD + VM_OPERATION */
            BOOLEAN isAllAccess = (access == 0x1FFFFF) || (access == 0x1F0FFF);  /* PROCESS_ALL_ACCESS */
            if (hasTerminateAccess || (hasWriteAndOper && !isAllAccess) || (hasCreateAndOper && !isAllAccess)) {
                for (i = 0; i < 33; i++) {
                    if (kStrStrLen(procLower, procLen, secProcs[i], kStrLen(secProcs[i]))) {
                        addIndicator(idx, BA_IND_PROC_KILL_SECURITY_PROCESS, "Attempt to terminate security process");
                        break;
                    }
                }
            }
        }

        if (ev->memOp == BA_MOP_SetWindowsHookEx) {
            addIndicator(idx, BA_IND_PROC_KEYBOARD_HOOK, "Keyboard hook");
        }

        /* ── PoolParty Windows Thread Pool injection detection ──
         * PoolParty abuses Windows Thread Pool APIs to execute shellcode in
         * target processes without creating remote threads. All variants
         * require cross-process memory operations (VM_WRITE/VM_OPERATION)
         * and/or handle duplication (DUP_HANDLE). We record them as distinct
         * memory-op events and tag the corresponding indicator.
         *
         * 受信任第三方软件（含 WindowsApps UWP 应用）的线程池操作是正常行为，
         * 跳过 PoolParty 检测以避免误报。
         * 源PID == 目标PID 时说明是进程自操作，不是注入，跳过。
         * 父子进程间（父初始化子）的操作是正常进程创建行为，不是 PoolParty 注入，跳过。
         * 互签进程间（双签名）的操作是正常 IPC，不是 PoolParty 注入，跳过。 */
        if (ev->pid != ev->targetPid &&
            !ev->isParentChild &&
            !mutuallySigned) {
        CHAR poolEvBuf[128];
        const CHAR* tgtName = ev->targetProcess[0] ? ev->targetProcess : "Unknown";
        /* Phase 4: 使用新的原子权限组合指标替代 8 个 PoolParty 变体 */
        if (ev->memOp == BA_MOP_VMWriteVMOperate) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.VMWrite+VMOperate.T1055 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_VM_WRITE_VM_OPERATE, poolEvBuf);
        }
        else if (ev->memOp == BA_MOP_VMOperCreateThread) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.VMOper+CreateThread.T1055 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_VM_OPER_CREATE_THREAD, poolEvBuf);
        }
        else if (ev->memOp == BA_MOP_VMOperDupHandle) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.VMOper+DupHandle.T1055 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_VM_OPER_DUP_HANDLE, poolEvBuf);
        }
        else if (ev->memOp == BA_MOP_PoolParty_HandleRequest) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.HandleRequest.0x0478 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_POOLPARTY_HANDLE_REQUEST, poolEvBuf);
        }
        } /* end trusted-source guard for PoolParty */

        /* ── ETW Threat-Intelligence memory operation indicators ── */
        if (ev->memOp == BA_MOP_RemoteAllocExecutable) {
            addIndicator(idx, BA_IND_MEM_ETW_REMOTE_ALLOC_EXECUTABLE,
                "Remote executable memory allocation (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_RemoteProtectExecutable) {
            addIndicator(idx, BA_IND_MEM_ETW_REMOTE_PROTECT_EXECUTABLE,
                "Remote memory protected to executable (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_RemoteWriteMemory) {
            addIndicator(idx, BA_IND_MEM_ETW_REMOTE_WRITE_MEMORY,
                "Remote virtual memory write (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_RemoteQueueApc) {
            addIndicator(idx, BA_IND_MEM_ETW_REMOTE_QUEUE_APC,
                "Remote APC insertion (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_RemoteSetThreadContext) {
            addIndicator(idx, BA_IND_MEM_ETW_REMOTE_SET_THREAD_CONTEXT,
                "Remote thread context manipulation (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_RemoteMapViewExecutable) {
            addIndicator(idx, BA_IND_MEM_ETW_REMOTE_MAP_VIEW_EXECUTABLE,
                "Remote executable section mapping (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_AllocToProtectChain) {
            addIndicator(idx, BA_IND_MEM_ETW_ALLOC_TO_PROTECT_CHAIN,
                "Shellcode pattern: RW alloc then RX/RWX protect (ETW TI)");
        }
        else if (ev->memOp == BA_MOP_WriteToProtectChain) {
            addIndicator(idx, BA_IND_MEM_ETW_WRITE_TO_PROTECT_CHAIN,
                "Shellcode pattern: write then RX/RWX protect (ETW TI)");
        }
    }

    /* ── Registry 类别 ── */
    if (ev->category == BA_EC_Registry) {
        if (ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey) {
            regPathLen = kStrLen(ev->regPath);
            if (kStrStrLen(ev->regPath, regPathLen, "CurrentVersion\\Run", 18) &&
                !kStrStrLen(imgLower, imgLen, "\\downloads\\", 11)) {
                addIndicator(idx, BA_IND_REG_MODIFY_RUN_KEY, "Modify Run key");
            }
            if (kStrStrLen(ev->regPath, regPathLen, "Image File Execution Options", 28) &&
                kStrCmp(ev->regValue, "Debugger") == 0) {
                addIndicator(idx, BA_IND_REG_MODIFY_IFEO_DEBUGGER, "IFEO Debugger hijack");
            }
            if (kStrStrLen(ev->regPath, regPathLen, "Winlogon", 8)) {
                addIndicator(idx, BA_IND_REG_MODIFY_WINLOGON, "Modify Winlogon key");
            }
            if (kStrStrLen(ev->regPath, regPathLen, "\\Services\\", 10) &&
                (ev->regOp == BA_ROP_CreateKey ||
                 (ev->regOp == BA_ROP_SetValue && kStrCmp(ev->regValue, "ImagePath") == 0)) &&
                kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
                addIndicator(idx, BA_IND_REG_CREATE_SERVICE, "Create/Modify service");
            }
            if (kStrStrLen(ev->regPath, regPathLen, "\\shell\\", 7) && kStrStrLen(ev->regPath, regPathLen, "\\command", 8)) {
                addIndicator(idx, BA_IND_REG_MODIFY_SHELL_OPEN, "Modify Shell command");
            }
            if (kStrStrLen(ev->regPath, regPathLen, "Schedule", 8) || kStrStrLen(ev->regPath, regPathLen, "Task Scheduler", 14) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Tasks\\", 7)) {
                /* 系统任务路径白名单：Windows 自身在 \Microsoft\Windows\ 下创建/更新计划任务，
                 * 由系统目录下的已知系统进程发起时视为正常行为，避免误报。
                 * 额外放行 Windows Update / Windows Defender / WaaSMedic 等系统组件任务路径。 */
                int isSystemTaskPath =
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\", 21) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\", 48) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows Defender\\", 28) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\UpdateOrchestrator\\", 39) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\WindowsUpdate\\", 35) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\WaaSMedic\\", 33) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\Autochk\\", 30) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\DiskCleanup\\", 34) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\DiskFootprint\\", 36) ||
                    kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\Maintenance\\", 34);
                if (!isSystemTaskPath || !isGenuineSystemProcess(procIdx, imgLower)) {
                    /* taskhostw.exe 是 Windows 任务计划程序宿主进程，创建计划任务是其
                     * 合法本职工作，无论操作的是系统任务还是第三方任务都不应告警。 */
                    if (!kStrIStrLen(imgLower, imgLen, "taskhostw.exe", 13)) {
                        addIndicator(idx, BA_IND_REG_SCHEDULED_TASK_CREATE, "Create scheduled task");
                    }
                }
            }
        }
    }

    /* ── File 类别 ── */
    if (ev->category == BA_EC_File) {
        isCreate = (ev->fileOp == BA_FOP_Create);

        kStrLowerCopy(dirLower, BA_MAX_PATH, ev->fileDir);
        dirLen = kStrLen(dirLower);
        isSystemDir = kStrStrLen(dirLower, dirLen, "\\windows\\system32", 17) || kStrStrLen(dirLower, dirLen, "\\windows\\syswow64", 17);
        isDriversDir = kStrStrLen(dirLower, dirLen, "\\windows\\system32\\drivers", 25) || kStrStrLen(dirLower, dirLen, "\\windows\\syswow64\\drivers", 25);
        isStartupDir = kStrStrLen(dirLower, dirLen, "\\startup", 8) || kStrStrLen(dirLower, dirLen, "\\start menu\\programs\\startup", 29);

        kStrLowerCopy(extLower, 16, ev->fileExt);
        kStrLowerCopy(fnameLower, BA_MAX_NAME, ev->fileName);
        fnameLen = kStrLen(fnameLower);

        /* 系统目录创建可执行/脚本文件：必须排除签名进程和真正系统进程，避免正常更新误报 */
        if (isCreate && isSystemDir && !ev->isSigned &&
            !isGenuineSystemProcess(procIdx, imgLower) &&
            (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 ||
                kStrCmp(extLower, ".sys") == 0 || kStrCmp(extLower, ".bat") == 0 ||
                kStrCmp(extLower, ".ps1") == 0 || kStrCmp(extLower, ".vbs") == 0 ||
                kStrCmp(extLower, ".js") == 0 || kStrCmp(extLower, ".cmd") == 0 ||
                kStrCmp(extLower, ".scr") == 0 || kStrCmp(extLower, ".com") == 0)) {
            addIndicator(idx, BA_IND_FILE_CREATE_SYSTEM_DIR, "Unsigned file written to system dir");
        }
        if (isCreate && isDriversDir && kStrCmp(extLower, ".sys") == 0 && !ev->isSigned) {
            addIndicator(idx, BA_IND_FILE_CREATE_DRIVER, "Unsigned driver written to drivers dir");
        }
        if (isCreate && isStartupDir && (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 || kStrCmp(extLower, ".bat") == 0)) {
            addIndicator(idx, BA_IND_FILE_CREATE_STARTUP_EXE, "Executable written to startup dir");
        }

        /* Temp → 系统目录：增加进程签名和系统进程检查，排除在线安装器/更新程序 */
        if (isCreate && isSystemDir && kStrStrLen(imgLower, imgLen, "\\temp\\", 6) &&
            !ev->isSigned && !isGenuineSystemProcess(procIdx, imgLower)) {
            addIndicator(idx, BA_IND_FILE_DROP_FROM_TEMP, "Temp process writes to system dir");
        }

        /* 假更新安装器 */
        if (!ev->isSigned && isCreate && kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
            static const CHAR* fakeNames[] = { "setup", "install", "update", "patch", "flash", "chrome", "firefox" };
            for (i = 0; i < 7; i++) {
                if (kStrIStrLen(imgLower, imgLen, fakeNames[i], kStrLen(fakeNames[i]))) {
                    addIndicator(idx, BA_IND_PROC_FAKE_UPDATE_INSTALLER, "Fake update installer");
                    break;
                }
            }
        }

        /* DLL 劫持检测：改为检查应用程序目录下释放常见劫持目标（系统目录写入无法实现劫持） */
        if (isCreate && !ev->isSigned && kStrCmp(extLower, ".dll") == 0) {
            static const CHAR* hijackTargets[] = { "version.dll", "mscoree.dll", "dxgi.dll", "d3d9.dll", "winmm.dll" };
            int isAppDir = !kStrStrLen(dirLower, dirLen, "\\windows\\", 9); // 非系统目录
            if (isAppDir) {
                for (i = 0; i < 5; i++) {
                    SIZE_T targetLen = kStrLen(hijackTargets[i]);
                    if (fnameLen == targetLen && kStrCmp(fnameLower, hijackTargets[i]) == 0) {
                        addIndicator(idx, BA_IND_FILE_CREATE_DLL_HIJACK, "Potential DLL hijack target written");
                        break;
                    }
                }
            }
        }

        /* 加密扩展名 */
        {
            static const CHAR* cryptExts[] = {
                ".encrypted", ".lockbit", ".crypt", ".wncry", ".wcry", ".locked",
                ".cryptolocker", ".cerber", ".zepto", ".odin", ".thor", ".potato",
                ".crab", ".dharma", ".phobos", ".ryuk", ".conti", ".revil", ".sodinokibi",
                ".maze", ".ekans", ".netwalker", ".dark", ".enc", ".crypted",
                ".xxx", ".ttt", ".micro", ".zzz", ".lock", ".blackbyte", ".hive",
                ".avaddon", ".avos", ".darkbit", ".haron", ".medusa", ".play", ".royal",
                ".akira", ".blacksuit", ".blackcat", ".clop", ".exx", ".mamba", ".moisha",
                ".pysa", ".ragnar", ".djvu", ".karma", ".wallet", ".none", ".babuk",
                ".lorenz", ".ransom", ".koko", ".nephilim", ".payme", ".spook"
            };
            for (i = 0; i < (int)(sizeof(cryptExts) / sizeof(cryptExts[0])); i++) {
                if (kStrCmp(extLower, cryptExts[i]) == 0) {
                    addIndicator(idx, BA_IND_FILE_ENCRYPTED_EXTENSION, "Encrypted extension");
                    break;
                }
            }
        }

        /* 勒索通知：仅 Create/Write 操作，且排除过于宽泛的通用词
         * 真正的勒索软件会创建含"ransom/payment/家族名"的说明文件 */
        if ((ev->fileOp == BA_FOP_Create || ev->fileOp == BA_FOP_Write) &&
            !isGenuineSystemProcess(procIdx, imgLower)) {
            /* 高特异性勒索关键词：家族名、支付相关、明确勒索意图 */
            static const CHAR* ransomKeywords[] = {
                "ransom", "ransom_note", "ransomware", "pay_ransom",
                "@wanadecryptor", "@please_read_me", "lockbit",
                "conti", "contiremote", "revil", "sodinokibi",
                "hakitzu", "clop", "akira", "blackbyte", "hive",
                "darktrace_readme", "_locked", "_encrypted",
                "de_crypt_recover", "ALLYOURFILES",
                "bitcoin", "monero",
                "nemty", "medusa",
                "decrypted_file", "readme_ransom",
                0
            };
            BOOLEAN ransomDetected = FALSE;
            for (i = 0; ransomKeywords[i] != 0; i++) {
                if (kStrIStrLen(fnameLower, fnameLen, ransomKeywords[i], kStrLen(ransomKeywords[i]))) {
                    addIndicator(idx, BA_IND_FILE_RANSOM_NOTE, "Ransom note file");
                    ransomDetected = TRUE;
                    break;
                }
            }
            /* 兜底：宽泛词仅在配合加密扩展名时才触发 */
            if (!ransomDetected) {
                static const CHAR* broadNotes[] = {
                    "readme", "decrypt", "restore", "recover",
                    "how_to_decrypt", "your_files", "payment",
                    "_readme", "_decrypt", "_restore", "_recover",
                    "instructions", "how_to_restore", "contact",
                    "decryptor", "decrypt_info", "decryption",
                    "what_happened", "all_your_files", "data_restore",
                    "unlock_files", "recovery_key", "restore_files",
                    "how_to_recover", "recovery_info", "unlock_instructions",
                    "helprecover", "encrypt_info", "encfile",
                    "readme_lock", "readme_info", "decryption_info",
                    "help_restore", "help_decrypt"
                };
                int hasEncryptedExt = kStrCmp(extLower, ".encrypted") == 0 ||
                    kStrCmp(extLower, ".lockbit") == 0 ||
                    kStrCmp(extLower, ".crypt") == 0 ||
                    kStrCmp(extLower, ".wncry") == 0 ||
                    kStrCmp(extLower, ".locked") == 0 ||
                    kStrCmp(extLower, ".exe") == 0;
                if (hasEncryptedExt) {
                    for (i = 0; i < (int)(sizeof(broadNotes)/sizeof(broadNotes[0])); i++) {
                        if (kStrIStrLen(fnameLower, fnameLen, broadNotes[i], kStrLen(broadNotes[i]))) {
                            addIndicator(idx, BA_IND_FILE_RANSOM_NOTE, "Ransom note file (broad match with encrypted ext)");
                            break;
                        }
                    }
                }
            }
        }

        /* SelfLoading / DLL 侧加载检测 */
        if (isCreate && kStrCmp(extLower, ".dll") == 0 && !ev->isSigned) {
            int isSelfLoad = 0;
            int lastSep = -1;
            const CHAR* dllPath = ev->filePath;
            CHAR evBuf[128];

            for (i = imgLen - 1; i >= 0; i--) {
                if (imgLower[i] == '\\') { lastSep = i; break; }
            }
            if (lastSep > 0 && dirLen == lastSep && kStrNCmp(dirLower, imgLower, lastSep) == 0) {
                isSelfLoad = 1;
            }

            int inSuspiciousDllDir = kStrStrLen(dirLower, dirLen, "program files", 13) ||
                kStrStrLen(dirLower, dirLen, "appdata", 7) ||
                kStrStrLen(dirLower, dirLen, "temp", 4) ||
                kStrStrLen(dirLower, dirLen, "downloads", 9);
            int isWindowsAppsDir = kStrStrLen(dirLower, dirLen, "\\windowsapps\\", 13);

            /* 来源可疑：仅当进程来自 Temp/Downloads/AppData/ProgramData 等位置 */
            int sourceIsSuspicious = kStrStrLen(imgLower, imgLen, "\\temp\\", 6) ||
                kStrStrLen(imgLower, imgLen, "\\downloads\\", 11) ||
                kStrStrLen(imgLower, imgLen, "\\appdata\\", 9) ||
                kStrStrLen(imgLower, imgLen, "\\programdata\\", 13);

            /* SelfLoading：进程在自己的目录创建 DLL，且来源可疑，且未签名 */
            if (isSelfLoad && sourceIsSuspicious &&
                !isGenuineSystemProcess(procIdx, imgLower)) {
                if (g_baPidIndicators[idx][BA_IND_FILE_SELF_LOADING] == 0) {
                    int pathLen = kStrLen(dllPath);
                    if (pathLen > 100) dllPath += (pathLen - 100);
                    RtlStringCbPrintfA(evBuf, sizeof(evBuf), "SelfLoading DLL: %s", dllPath);
                    addIndicator(idx, BA_IND_FILE_SELF_LOADING, evBuf);
                }
            }
            /* DLL 侧加载：排除已知软件目录、安全产品、硬件厂商、系统 DLL 名 */
            else if (inSuspiciousDllDir &&
                !isWindowsAppsDir &&
                !isGenuineSystemProcess(procIdx, imgLower)) {
                int dllPathLen = kStrLen(dllPath);
                int isKnownOfficeDll = kStrIStrLen(dllPath, dllPathLen, "kingsoft\\wps office", 19) ||
                    kStrIStrLen(dllPath, dllPathLen, "microsoft office", 16) ||
                    kStrIStrLen(dllPath, dllPathLen, "libreoffice", 11) ||
                    kStrIStrLen(dllPath, dllPathLen, "adobe", 5) ||
                    kStrIStrLen(dllPath, dllPathLen, "mozilla firefox", 15) ||
                    kStrIStrLen(dllPath, dllPathLen, "google\\chrome", 13) ||
                    kStrIStrLen(dllPath, dllPathLen, "blender", 7) ||
                    kStrIStrLen(dllPath, dllPathLen, "gimp", 4) ||
                    kStrIStrLen(dllPath, dllPathLen, "git", 3);
                int isSecurityProductDir = kStrStrLen(dirLower, dirLen, "\\360\\", 5) ||
                    kStrStrLen(dirLower, dirLen, "\\360safe\\", 9) ||
                    kStrStrLen(dirLower, dirLen, "\\360sd\\", 8) ||
                    kStrStrLen(dirLower, dirLen, "\\360scan\\", 10) ||
                    kStrStrLen(dirLower, dirLen, "\\windows defender\\", 19) ||
                    kStrStrLen(dirLower, dirLen, "\\kaspersky lab\\", 16);
                int isHardwareVendorDir = kStrStrLen(dirLower, dirLen, "\\nvidia corporation\\", 20) ||
                    kStrStrLen(dirLower, dirLen, "\\nvidia\\", 9);
                int isKnownWindowsSysDll = kStrCmp(fnameLower, "wininet.dll") == 0 ||
                    kStrCmp(fnameLower, "winhttp.dll") == 0 ||
                    kStrCmp(fnameLower, "urlmon.dll") == 0 ||
                    kStrCmp(fnameLower, "dnsapi.dll") == 0 ||
                    kStrCmp(fnameLower, "sensapi.dll") == 0 ||
                    kStrCmp(fnameLower, "cryptnet.dll") == 0 ||
                    kStrCmp(fnameLower, "msxml3.dll") == 0 ||
                    kStrCmp(fnameLower, "msxml6.dll") == 0 ||
                    kStrCmp(fnameLower, "iphlpapi.dll") == 0 ||
                    kStrCmp(fnameLower, "winnsi.dll") == 0 ||
                    kStrCmp(fnameLower, "uxtheme.dll") == 0 ||
                    kStrCmp(fnameLower, "dwmapi.dll") == 0 ||
                    kStrCmp(fnameLower, "winmm.dll") == 0;
                if (!isKnownOfficeDll && !isSecurityProductDir && !isHardwareVendorDir &&
                    !isKnownWindowsSysDll) {
                    if (g_baPidIndicators[idx][BA_IND_FILE_DLL_SIDE_LOAD] == 0) {
                        int pathLen = dllPathLen;
                        if (pathLen > 100) dllPath += (pathLen - 100);
                        RtlStringCbPrintfA(evBuf, sizeof(evBuf), "DLL side-load: %s", dllPath);
                        addIndicator(idx, BA_IND_FILE_DLL_SIDE_LOAD, evBuf);
                    }
                }
            }
        }

        /* 浏览器凭据 */
        if (IsBrowserDirectory(dirLower, dirLen)) {
            if (kStrIStrLen(fnameLower, fnameLen, "login data", 10) || kStrIStrLen(fnameLower, fnameLen, "cookies", 7) ||
                kStrIStrLen(fnameLower, fnameLen, "web data", 8) || kStrIStrLen(fnameLower, fnameLen, "key4.db", 7) ||
                kStrIStrLen(fnameLower, fnameLen, "logins.json", 11)) {
                addIndicator(idx, BA_IND_FILE_BROWSER_CRED_TARGET, "Browser credential target");
            }
        }

        /* 未签名可执行文件创建 */
        {
            int isSameDirAsProcess = 0;
            {
                int lastImgSep = -1, di;
                for (di = imgLen - 1; di >= 0; di--) {
                    if (imgLower[di] == '\\') { lastImgSep = di; break; }
                }
                if (lastImgSep > 0 && dirLen == lastImgSep &&
                    kStrNCmp(dirLower, imgLower, lastImgSep) == 0)
                    isSameDirAsProcess = 1;
            }
            if (!ev->isSigned && isCreate &&
                !isGenuineSystemProcess(procIdx, imgLower) &&
                !isSameDirAsProcess &&
                ev->isPeFile &&
                (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 || kStrCmp(extLower, ".sys") == 0 || kStrCmp(extLower, ".bat") == 0 || kStrCmp(extLower, ".ps1") == 0)) {
                addIndicator(idx, BA_IND_PROC_UNSIGNED, "Process creates unsigned executable");
            }
        }

        /* 自删除 */
        if (ev->fileOp == BA_FOP_Delete && ev->imagePath[0]) {
            CHAR selfLower[BA_MAX_PATH];
            CHAR fileLower[BA_MAX_PATH];
            kStrLowerCopy(selfLower, BA_MAX_PATH, ev->imagePath);
            kStrLowerCopy(fileLower, BA_MAX_PATH, ev->filePath);
            if (kStrEndsWith(fileLower, selfLower)) {
                addIndicator(idx, BA_IND_FILE_SELF_DELETE, "Self-delete");
            }
        }

        /* 网络共享 */
        if (isCreate && kStrStrLen(dirLower, dirLen, "\\\\", 2) && (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0)) {
            addIndicator(idx, BA_IND_FILE_NETWORK_SHARE, "Network share propagation");
        }

        /* autorun.inf */
        if (isCreate && kStrCmp(fnameLower, "autorun.inf") == 0) {
            addIndicator(idx, BA_IND_FILE_INF_AUTORUN, "autorun.inf created");
        }

        /* hosts */
        if (ev->fileOp == BA_FOP_Modify && kStrStrLen(dirLower, dirLen, "\\drivers\\etc", 12) && kStrCmp(fnameLower, "hosts") == 0) {
            addIndicator(idx, BA_IND_FILE_HOSTS_MODIFY, "hosts file modified");
        }

        /* 通用文件重命名：仅对非系统进程记录，用于追踪伪装/覆盖行为（T1036/T1222） */
        if (ev->fileOp == BA_FOP_Modify && !isGenuineSystemProcess(procIdx, imgLower)) {
            addIndicator(idx, BA_IND_FILE_RENAME, "File rename detected");
        }

        /* 磁盘原始访问：依赖于采集层能否收到 PhysicalDrive 路径，实际可能不触发，保留用于内核事件 */
        if (kStrIStrLen(dirLower, dirLen, "physicaldrive", 13)) {
            addIndicator(idx, BA_IND_FILE_DISK_RAW_ACCESS, "Disk raw access");
        }

        /* BYOVD 驱动：仅创建/写入时触发，避免读取备份文件误报 */
        if (isCreate) {
            static const CHAR* byovdDrivers[] = {
                "rtcore64.sys", "gdrv.sys", "atillk64.sys", "kprocesshacker.sys",
                "capcom.sys", "winring0.sys", "dbk64.sys", "bs_dpl.sys",
                "amp.sys", "speedfan.sys", "vmxdrv.sys", "asrdrv106.sys",
                "atszio.sys", "cpuz_x64.sys", "eoploaddriver.sys", "gmer.sys",
                "lha.sys", "mimikatz.sys", "mhyprot.sys", "mhyprot2.sys",
                "mhyprotec.sys", "ncpl.sys", "nvoclock.sys", "pcileech.sys",
                "phymem.sys", "physmem.sys", "piddrv.sys", "piddrv64.sys",
                "processhacker.sys", "rweverything.sys", "secreal.sys",
                "semav6msr64.sys", "truesight.sys", "viragt64.sys", "vuln.sys",
                "winio.sys", "winio64.sys", "zenaidrv.sys"
            };
            for (i = 0; i < 38; i++) {
                if (kStrCmp(fnameLower, byovdDrivers[i]) == 0) {
                    addIndicator(idx, BA_IND_FILE_BYOVD_DRIVER_LOAD, "BYOVD vulnerable driver");
                    break;
                }
            }
        }

        /* AppData DLL 投放：增加常见大型应用排除，降低误报 */
        if (isCreate && kStrCmp(extLower, ".dll") == 0 && !ev->isSigned &&
            kStrStrLen(dirLower, dirLen, "\\appdata\\", 9)) {
            int isKnownApp = kStrIStrLen(dirLower, dirLen, "\\discord\\", 9) ||
                kStrIStrLen(dirLower, dirLen, "\\slack\\", 7) ||
                kStrIStrLen(dirLower, dirLen, "\\teams\\", 7) ||
                kStrIStrLen(dirLower, dirLen, "\\zoom\\", 6) ||
                kStrIStrLen(dirLower, dirLen, "\\mozilla\\", 9) ||
                kStrIStrLen(dirLower, dirLen, "\\google\\chrome\\", 14);
            if (!isKnownApp && !isGenuineSystemProcess(procIdx, imgLower)) {
                addIndicator(idx, BA_IND_FILE_APPDATA_DLL, "AppData directory DLL drop");
            }
        }

        /* C2 通信特征：文件事件不应直接标记 C2，移除该检测。如需检测，应基于网络连接事件。 */

        /* Boot Execute 持久化 */
        if (isCreate && (kStrStrLen(dirLower, dirLen, "\\boot\\", 6) || kStrStrLen(dirLower, dirLen, "\\efi\\", 5) ||
            kStrStrLen(dirLower, dirLen, "\\recovery\\", 10) || kStrIStrLen(fnameLower, fnameLen, "bootexecute", 11))) {
            addIndicator(idx, BA_IND_FILE_BOOT_EXECUTE, "BootExecute persistence");
        }
    }

    /* ── 子进程行为继承 (vssadmin, bcdedit) ──
     * 仅当父进程来自可疑位置或伪造系统工具路径时才标记，避免系统工具正常使用误报 */
    {
        int isVssadmin = kStrIStrLen(imgLower, imgLen, "vssadmin.exe", 12);
        int isBcdedit   = kStrIStrLen(imgLower, imgLen, "bcdedit.exe", 11);
        if (isVssadmin || isBcdedit) {
            int isSuspiciousContext = 0;
            /* 检测1: 父进程来自Temp/Downloads/AppData */
            {
                /* procIdx 已在函数顶部赋值，无需重复声明 */
                if (procIdx >= 0) {
                    INT64 parentPid = g_baProcTree[procIdx].parentPid;
                    if (parentPid != 0) {
                        int parentIdx = findProc(parentPid);
                        if (parentIdx >= 0) {
                            CHAR parentLower[BA_MAX_PATH];
                            kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                            int parentLen = kStrLen(parentLower);
                            if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                                kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                                kStrStrLen(parentLower, parentLen, "\\appdata\\", 9)) {
                                isSuspiciousContext = 1;
                            }
                        }
                    }
                }
            }
            /* 检测2: 伪造系统工具 (不在System32/SysWOW64中) */
            if (!kStrStrLen(imgLower, imgLen, "\\windows\\system32\\", 17) &&
                !kStrStrLen(imgLower, imgLen, "\\windows\\syswow64\\", 17)) {
                isSuspiciousContext = 1;
            }
            /* 检测3: 父进程为脚本解释器 (PowerShell/cmd调用系统工具) */
            {
                /* procIdx 已在函数顶部赋值，无需重复声明 */
                if (procIdx >= 0) {
                    INT64 parentPid = g_baProcTree[procIdx].parentPid;
                    if (parentPid != 0) {
                        int parentIdx = findProc(parentPid);
                        if (parentIdx >= 0) {
                            if (IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                                isSuspiciousContext = 1;
                            }
                        }
                    }
                }
            }
            if (isSuspiciousContext) {
                if (isVssadmin) {
                    addIndicator(idx, BA_IND_PROC_VSSADMIN_SHADOW_DELETE, "vssadmin shadow delete (suspicious context)");
                }
                if (isBcdedit) {
                    addIndicator(idx, BA_IND_PROC_BCDEDIT_RECOVERY_DISABLE, "bcdedit recovery disable (suspicious context)");
                }
            }
        }
    }

    /* ── Winkiller 专用指标提取 ── */

    /* 大规模文件删除：系统目录中删除文件（不限进程来源，防脚本型攻击） */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Delete &&
        isSystemDir) {
        addIndicator(idx, BA_IND_FILE_MASS_SYSTEM_DELETE, "Mass file deletion in system directory");
    }

    /* 大规模注册表删除：真正的系统进程（SYSTEM SID）清理临时/配置键是正常行为，
     * 冒名病毒即使投放至 System32 也无法以 SYSTEM 身份运行，会被此检查拦截。 */
    if (ev->category == BA_EC_Registry &&
        (ev->regOp == BA_ROP_DeleteKey || ev->regOp == BA_ROP_DeleteValue) &&
        !isGenuineSystemProcess(procIdx, imgLower)) {
        addIndicator(idx, BA_IND_REG_MASS_DELETE, "Mass registry key/value deletion");
    }

    /* 启动扇区 / MBR 写入 — 必须来自可疑位置才标记（避免 diskpart/disk utility 等正常工具的误报） */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Write) {
        int pathLen = kStrLen(ev->filePath);
        int isRawDisk = (kStrIStrLen(ev->filePath, pathLen, "physicaldrive", 13) ||
                         kStrIStrLen(ev->filePath, pathLen, "\\device\\harddisk", 16) ||
                         kStrIStrLen(ev->filePath, pathLen, "harddisk0", 9));
        if (isRawDisk) {
            /* 检查进程是否来自可疑位置 */
            int isSuspicious = (kStrIStrLen(imgLower, imgLen, "\\temp\\", 6) ||
                               kStrIStrLen(imgLower, imgLen, "\\downloads\\", 12) ||
                               kStrIStrLen(imgLower, imgLen, "\\appdata\\", 10) ||
                               kStrIStrLen(imgLower, imgLen, "\\desktop\\", 10));
            if (isSuspicious) {
                addIndicator(idx, BA_IND_FILE_BOOT_SECTOR, "Boot sector / physical disk access");
                if (kStrIStrLen(ev->filePath, pathLen, "physicaldrive", 13)) {
                    addIndicator(idx, BA_IND_DISK_MBR_WRITE, "MBR write attempt");
                }
            }
        }
    }

    /* 结束关键系统进程 */
    if (ev->category == BA_EC_Memory) {
        static const CHAR* criticalProcs[] = {
            "csrss.exe", "wininit.exe", "smss.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe"
        };
        access = ev->desiredAccess;
        int hasTerminate = (access & 0x0001) != 0;  /* PROCESS_TERMINATE */
        if (hasTerminate) {
            int cp;
            for (cp = 0; cp < 7; cp++) {
                if (kStrCmp(procLower, criticalProcs[cp]) == 0) {
                    addIndicator(idx, BA_IND_PROC_CRITICAL_PROCESS_KILL, "Attempt to terminate critical system process");
                    break;
                }
            }
        }
    }

    /* -- Command-line context indicators -- */

    /* Office app spawning cmd/powershell */
    if (ev->category == BA_EC_Process) {
        /* Check if this is an Office application spawning cmd/powershell */
        static const CHAR* officeApps[] = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "visio.exe", "publisher.exe"};
        int isOffice = 0;
        int o;
        for (o = 0; o < 6; o++) {
            if (kStrIStrLen(imgLower, imgLen, officeApps[o], kStrLen(officeApps[o]))) {
                isOffice = 1;
                break;
            }
        }
        if (isOffice) {
            /* Check if child process is cmd/powershell - look at process tree */
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                /* Check children for cmd/powershell */
                int ci;
                for (ci = 0; ci < g_baProcTree[procIdx].childCount; ci++) {
                    int childProcIdx = findProc(g_baProcTree[procIdx].childPids[ci]);
                    if (childProcIdx >= 0) {
                        CHAR childLower[BA_MAX_PATH];
                        kStrLowerCopy(childLower, BA_MAX_PATH, g_baProcTree[childProcIdx].imagePath);
                        int childLen = kStrLen(childLower);
                        if (kStrIStrLen(childLower, childLen, "cmd.exe", 7) ||
                            kStrIStrLen(childLower, childLen, "powershell.exe", 14) ||
                            kStrIStrLen(childLower, childLen, "wscript.exe", 11) ||
                            kStrIStrLen(childLower, childLen, "cscript.exe", 11) ||
                            kStrIStrLen(childLower, childLen, "mshta.exe", 9)) {
                            addIndicator(idx, BA_IND_OFFICE_SPAWN_CMD, "Office app spawning script interpreter");
                            break;
                        }
                    }
                }
            }
        }
    }

    /* certutil download pattern */
    if (ev->category == BA_EC_Process) {
        int isCertutil = kStrIStrLen(imgLower, imgLen, "certutil.exe", 12);
        if (isCertutil) {
            /* Check parent for suspicious context */
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            kStrStrLen(parentLower, parentLen, "\\appdata\\", 9) ||
                            IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_CERTUTIL_DOWNLOAD, "certutil from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* bitsadmin transfer pattern */
    if (ev->category == BA_EC_Process) {
        int isBitsadmin = kStrIStrLen(imgLower, imgLen, "bitsadmin.exe", 13);
        if (isBitsadmin) {
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            kStrStrLen(parentLower, parentLen, "\\appdata\\", 9) ||
                            IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_BITSADMIN_TRANSFER, "bitsadmin from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* net.exe user manipulation */
    if (ev->category == BA_EC_Process) {
        int isNet = (kStrIStrLen(imgLower, imgLen, "net.exe", 7) ||
                     kStrIStrLen(imgLower, imgLen, "net1.exe", 8));
        if (isNet) {
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_NET_USER_MODIFY, "net.exe from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* svchost anomaly: wrong parent (not services.exe) */
    if (ev->category == BA_EC_Process) {
        int isSvchost = kStrIStrLen(imgLower, imgLen, "svchost.exe", 11);
        if (isSvchost) {
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        /* svchost parent should be services.exe */
                        if (!kStrIStrLen(parentLower, parentLen, "services.exe", 12) &&
                            !kStrIStrLen(parentLower, parentLen, "svchost.exe", 11)) {
                            addIndicator(idx, BA_IND_SVCHOST_ANOMALY, "svchost.exe with anomalous parent");
                        }
                    }
                }
            }
        }
    }

    /* icacls permission modification from suspicious context */
    if (ev->category == BA_EC_Process) {
        int isIcacls = kStrIStrLen(imgLower, imgLen, "icacls.exe", 10);
        if (isIcacls) {
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        if (IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_ICACLS_MODIFY, "icacls from script interpreter");
                        }
                    }
                }
            }
        }
    }

    /* taskkill targeting security/system management tools（反取证行为）
     * 仅当 taskkill 目标为安全工具/系统管理工具时才触发指标，
     * 避免管理员正常使用 taskkill 产生的误报。
     * 通过解析命令行 /IM 参数获取目标进程名。 */
    if (ev->category == BA_EC_Process) {
        int isTaskkill = kStrIStrLen(imgLower, imgLen, "taskkill.exe", 12);
        if (isTaskkill && procIdx >= 0) {
            const CHAR* cmdLine = g_baProcTree[procIdx].commandLine;
            if (cmdLine != NULL && cmdLine[0] != '\0') {
                int cmdLen = kStrLen(cmdLine);
                /* 安全工具/系统管理工具目标列表 */
                static const CHAR* secTargets[] = {
                    "taskmgr.exe", "regedit.exe", "msconfig.exe", "procmon.exe",
                    "procexp.exe", "procexp64.exe", "autoruns.exe", "wireshark.exe",
                    "cmd.exe", "powershell.exe", "conhost.exe",
                    "360tray.exe", "360sd.exe", "zhudongfangyu.exe",
                    "msmpeng.exe", "msmpsvc.exe", "mpcmdrun.exe",
                    "avp.exe", "kavfs.exe", "avgsvc.exe", "avguard.exe",
                    "mcshield.exe", "tmlisten.exe", "bin.exe",
                    "hipstray.exe", "hipsdaemon.exe", "hipsmain.exe",
                    "wsctrl.exe", "usysdiag.exe",
                    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe"
                };
                int tki;
                for (tki = 0; tki < (int)(sizeof(secTargets) / sizeof(secTargets[0])); tki++) {
                    if (kStrIStrLen(cmdLine, cmdLen, secTargets[tki], kStrLen(secTargets[tki]))) {
                        CHAR evBuf[160];
                        RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                            "taskkill targeting security/system tool: %s", secTargets[tki]);
                        addIndicator(idx, BA_IND_PROC_TASKKILL_SECURITY_TOOL, evBuf);
                        /* 同时设置旧版指标，保持与历史威胁画像的兼容性 */
                        addIndicator(idx, BA_IND_TASKKILL_SECURITY, evBuf);
                        break;
                    }
                }
            }
        }
    }

    /* msiexec silent install from suspicious context */
    if (ev->category == BA_EC_Process) {
        int isMsiexec = kStrIStrLen(imgLower, imgLen, "msiexec.exe", 11);
        if (isMsiexec) {
            /* procIdx 已在函数顶部赋值，无需重复声明 */
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            kStrStrLen(parentLower, parentLen, "\\appdata\\", 9)) {
                            addIndicator(idx, BA_IND_MSIEXEC_SILENT_INSTALL, "msiexec from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* WMI persistence: writing to WMI repository */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Write) {
        int dirLen2 = kStrLen(dirLower);
        if (kStrStrLen(dirLower, dirLen2, "wbem\\repository", 15) ||
            kStrStrLen(dirLower, dirLen2, "wbem\\autorecovery", 17)) {
            if (!ev->isSigned) {
                addIndicator(idx, BA_IND_WMI_PERSISTENCE, "WMI repository modification");
            }
        }
    }

    /* ── Trojan.SilverFox: 文件隐藏 + 图片内嵌PE ── */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Create) {
        /* BA_IND_FILE_SET_SYSTEM_HIDDEN: 将文件设置为系统级隐藏属性
         * 通过注册表修改文件关联或ADS写入实现隐藏，此处检测对 .lnk/.url 等
         * 快捷方式文件的创建（银狐常用隐藏技术） */
        if (!ev->isSigned && !isGenuineSystemProcess(procIdx, imgLower)) {
            if (kStrCmp(extLower, ".lnk") == 0 || kStrCmp(extLower, ".url") == 0 ||
                kStrCmp(extLower, ".scr") == 0) {
                addIndicator(idx, BA_IND_FILE_SET_SYSTEM_HIDDEN, "Create hidden-attribute file (SilverFox)");
            }
        }
        /* BA_IND_FILE_PE_IN_IMAGE: 图像文件内含PE可执行特征
         * 银狐家族常用技术：将恶意载荷嵌入 jpg/png/bmp 文件头部 */
        if (!ev->isSigned && !isGenuineSystemProcess(procIdx, imgLower)) {
            if (kStrCmp(extLower, ".jpg") == 0 || kStrCmp(extLower, ".jpeg") == 0 ||
                kStrCmp(extLower, ".png") == 0 || kStrCmp(extLower, ".bmp") == 0 ||
                kStrCmp(extLower, ".gif") == 0 || kStrCmp(extLower, ".tif") == 0 ||
                kStrCmp(extLower, ".tiff") == 0) {
                /* 图像文件创建本身不直接触发，需通过写事件检测PE特征
                 * 此处仅记录图像文件创建事件供后续写分析 */
                addIndicator(idx, BA_IND_FILE_PE_IN_IMAGE, "Image file created (potential PE steganography)");
            }
        }
    }

    /* ── 新文件指标：非正常后缀可执行 / 隐藏可执行文件 ── */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Create && !isGenuineSystemProcess(procIdx, imgLower)) {
        UCHAR attrs = ev->fileAttributes;
        BOOLEAN isPe = ev->isPeFile;
        int newDirLen = (ev->fileDir[0] != '\0') ? kStrLen(ev->fileDir) : 0;
        /* BA_IND_FILE_INVALID_EXT_EXE: 创建非标准后缀名的可执行文件（文件头为PE但后缀非dll/exe/sys/com） */
        if (isCreate && isPe && !ev->isSigned) {
            BOOLEAN isNormalExt = (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 ||
                                   kStrCmp(extLower, ".sys") == 0 || kStrCmp(extLower, ".com") == 0);
            if (!isNormalExt) {
                addIndicator(idx, BA_IND_FILE_INVALID_EXT_EXE, "Created executable with non-standard extension");
            }
        }
        /* BA_IND_FILE_HIDDEN_EXE: 创建隐藏的可执行文件（PE头验证） */
        if (isCreate && isPe && (attrs & FILE_ATTRIBUTE_HIDDEN) && !ev->isSigned) {
            addIndicator(idx, BA_IND_FILE_HIDDEN_EXE, "Created hidden executable file");
        }
        /* BA_IND_FILE_SYSTEM_HIDDEN_EXE: 创建系统级隐藏的可执行文件（PE头验证） */
        if (isCreate && isPe && (attrs & FILE_ATTRIBUTE_SYSTEM) && !ev->isSigned) {
            addIndicator(idx, BA_IND_FILE_SYSTEM_HIDDEN_EXE, "Created system-hidden executable file");
        }
        /* BA_IND_FILE_HIDDEN_EXE_WITH_SIBLING: 同目录下存在可执行文件时创建隐藏的可执行文件（PE头验证） */
        if (isCreate && isPe && (attrs & FILE_ATTRIBUTE_HIDDEN) && !ev->isSigned && newDirLen > 0) {
            int foundSibling = 0;
            int lookback = g_baHistoryCount < 500 ? g_baHistoryCount : 500;
            for (i = 0; i < lookback; i++) {
                int histIdx = (g_baHistoryHead - 1 - i + BA_MAX_HISTORY) % BA_MAX_HISTORY;
                BA_STORED_EVENT* hEv = &g_baHistory[histIdx];
                if (hEv->category != BA_EC_File || hEv->fileOp != BA_FOP_Create) continue;
                if (hEv->pid == ev->pid) continue;
                int hDirLen = kStrLen(hEv->fileDir);
                if (hDirLen != newDirLen) continue;
                if (kStrNCmp(hEv->fileDir, ev->fileDir, newDirLen) != 0) continue;
                if (hEv->isPeFile) {
                    foundSibling = 1;
                    break;
                }
            }
            if (foundSibling) {
                addIndicator(idx, BA_IND_FILE_HIDDEN_EXE_WITH_SIBLING, "Created hidden executable alongside visible executable");
            }
        }
    }

    /* ── Trojan.AVBypass: ETW/InstrumentationCallback 绕过 ── */
    if (g_bAVBypassEnabled && ev->category == BA_EC_Registry) {
        regPathLen = kStrLen(ev->regPath);
        /* BA_IND_REG_ETW_PATCH: 修改 ETW 注册表禁用事件追踪 */
        if ((ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey) &&
            !isGenuineSystemProcess(procIdx, imgLower)) {
            if (kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\CurrentVersion\\ETW\\", 47) ||
                kStrStrLen(ev->regPath, regPathLen, "Providers\\Microsoft-Windows-Security-Auditing", 46) ||
                kStrStrLen(ev->regPath, regPathLen, "Providers\\Microsoft-Windows-PowerShell", 39) ||
                kStrStrLen(ev->regPath, regPathLen, "Providers\\Microsoft-Windows-Wininit", 36)) {
                addIndicator(idx, BA_IND_REG_ETW_PATCH, "Modify ETW registry (AV bypass T1562.002)");
            }
        }
        /* BA_IND_REG_INSTRUMENTATION_CALLBACK: 修改 InstrumentationCallback */
        if ((ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey) &&
            !isGenuineSystemProcess(procIdx, imgLower)) {
            if (kStrStrLen(ev->regPath, regPathLen, "InstrumentationCallback", 24) ||
                kStrStrLen(ev->regPath, regPathLen, "Instrumentation", 15)) {
                addIndicator(idx, BA_IND_REG_INSTRUMENTATION_CALLBACK, "Modify InstrumentationCallback (AV bypass T1562.001)");
            }
        }
    }

    /* ── Trojan.Rootkit: 高危驱动加载 ── */
    if (ev->category == BA_EC_Registry) {
        regPathLen = kStrLen(ev->regPath);
        /* BA_IND_REG_DRIVER_SERVICE_CREATE: 创建高危驱动服务 */
        if ((ev->regOp == BA_ROP_CreateKey || ev->regOp == BA_ROP_SetValue) &&
            kStrStrLen(ev->regPath, regPathLen, "\\Services\\", 10) &&
            !isGenuineSystemProcess(procIdx, imgLower)) {
            /* 检查是否为 .sys 驱动服务 */
            if (kStrStrLen(imgLower, imgLen, "\\temp\\", 6) || kStrStrLen(imgLower, imgLen, "\\downloads\\", 11)) {
                addIndicator(idx, BA_IND_REG_DRIVER_SERVICE_CREATE, "Create high-risk driver service (Rootkit T1547.001)");
            }
        }
    }

    /* ── Trojan.Exploit: 可执行内存分配与执行 ── */
    if (ev->category == BA_EC_Memory) {
        /* BA_IND_MEM_ALLOC_EXECUTE: 分配可执行内存（自身 shellcode 解密执行） */
        if (ev->memOp == BA_MOP_RemoteAllocExecutable || ev->memOp == BA_MOP_AllocToProtectChain) {
            if (ev->pid == ev->targetPid || ev->targetPid == 0) {
                /* 自身进程分配可执行内存 */
                addIndicator(idx, BA_IND_MEM_ALLOC_EXECUTE_SELF, "Self alloc executable memory (shellcode T1055)");
            } else {
                addIndicator(idx, BA_IND_MEM_ALLOC_EXECUTE, "Alloc executable memory (T1055.003)");
            }
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 模块化指标提取实现
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── BehaviorExtractProcessIndicators ── */
VOID BehaviorExtractProcessIndicators(int idx, const BA_STORED_EVENT* ev)
{
    int imgLen;
    CHAR imgLower[BA_MAX_PATH];
    int procIdx;

    if (idx < 0 || ev == NULL) return;

    procIdx = findProc(ev->pid);
    if (procIdx >= 0 && g_baProcTree[procIdx].imagePath[0]) {
        kStrLowerCopy(imgLower, BA_MAX_PATH, g_baProcTree[procIdx].imagePath);
    } else {
        kStrLowerCopy(imgLower, BA_MAX_PATH, ev->imagePath);
    }
    imgLen = kStrLen(imgLower);

    if (kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
        addIndicator(idx, BA_IND_PROC_FROM_TEMP_DIR, "Process from Temp");
    }
    if (kStrStrLen(imgLower, imgLen, "\\downloads\\", 11)) {
        addIndicator(idx, BA_IND_PROC_FROM_DOWNLOADS_DIR, "Process from Downloads");
    }
    if (kStrStrLen(imgLower, imgLen, "\\appdata\\", 9) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\temp\\", 20) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\programs\\", 24) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\microsoft\\", 25) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\roaming\\microsoft\\", 27) &&
        !kStrStrLen(imgLower, imgLen, "\\appdata\\local\\packages\\", 24)) {
        addIndicator(idx, BA_IND_PROC_FROM_APPDATA_DIR, "Process from AppData");
    }

    if (IsScriptInterpreter(imgLower)) {
        addIndicator(idx, BA_IND_PROC_SCRIPT_INTERPRETER, "Script interpreter process");
    }

    if (!isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrIStrLen(imgLower, imgLen, "hidden", 6) || kStrIStrLen(imgLower, imgLen, "silent", 6) ||
        kStrIStrLen(imgLower, imgLen, "stealth", 7) || kStrIStrLen(imgLower, imgLen, "invisible", 9) ||
        kStrIStrLen(imgLower, imgLen, "background", 10) || kStrIStrLen(imgLower, imgLen, "daemon", 6))) {
        addIndicator(idx, BA_IND_PROC_HIDDEN_WINDOW, "Hidden window process");
    }
    if (kStrIStrLen(imgLower, imgLen, "rundll32.exe", 12) ||
        kStrIStrLen(imgLower, imgLen, "regsvr32.exe", 12) ||
        kStrIStrLen(imgLower, imgLen, "mshta.exe", 9)) {
        addIndicator(idx, BA_IND_SIGNED_BINARY_PROXY, "Signed binary proxy execution candidate");
    }

    /* T1218 mshta execution */
    if (kStrIStrLen(imgLower, imgLen, "mshta.exe", 9)) {
        addIndicator(idx, BA_IND_MSHTA_EXECUTION, "Mshta script execution");
    }

    /* T1218.003 regsvr32 scriptlet execution */
    if (kStrIStrLen(imgLower, imgLen, "regsvr32.exe", 12)) {
        addIndicator(idx, BA_IND_REGSVR32_EXECUTION, "Regsvr32 scriptlet execution");
    }

    /* T1218.002 control panel item execution */
    if (kStrIStrLen(imgLower, imgLen, ".cpl", 4)) {
        addIndicator(idx, BA_IND_CONTROL_PANEL_ITEM, "Control Panel item execution");
    }

    /* T1055 mavinject injection */
    if (kStrIStrLen(imgLower, imgLen, "mavinject.exe", 13)) {
        addIndicator(idx, BA_IND_MAVINJECT_INJECTION, "Mavinject remote injection");
    }

    /* T1218.003 CMSTP INF execution */
    if (kStrIStrLen(imgLower, imgLen, "cmstp.exe", 8)) {
        addIndicator(idx, BA_IND_CMSTP_EXECUTION, "CMSTP INF script execution");
    }

    /* T1218 msdt troubleshooting pack execution */
    if (kStrIStrLen(imgLower, imgLen, "msdt.exe", 8)) {
        addIndicator(idx, BA_IND_MSDT_EXECUTION, "Msdt troubleshooting pack execution");
    }

    /* AppLocker / application whitelisting bypass */
    if (kStrStrLen(imgLower, imgLen, "\\appdata\\", 9) &&
        (kStrIStrLen(imgLower, imgLen, ".exe", 4) || kStrIStrLen(imgLower, imgLen, ".dll", 4))) {
        addIndicator(idx, BA_IND_APPLOCKER_BYPASS, "AppLocker bypass candidate from AppData");
    }
}

/* ── BehaviorExtractRegistryIndicators ── */
VOID BehaviorExtractRegistryIndicators(int idx, const BA_STORED_EVENT* ev)
{
    int regPathLen;
    int imgLen;
    CHAR imgLower[BA_MAX_PATH];
    int procIdx;

    if (idx < 0 || ev == NULL || ev->category != BA_EC_Registry) return;

    procIdx = findProc(ev->pid);
    if (procIdx >= 0 && g_baProcTree[procIdx].imagePath[0]) {
        kStrLowerCopy(imgLower, BA_MAX_PATH, g_baProcTree[procIdx].imagePath);
    } else {
        kStrLowerCopy(imgLower, BA_MAX_PATH, ev->imagePath);
    }
    imgLen = kStrLen(imgLower);

    if (ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey) {
        regPathLen = kStrLen(ev->regPath);
        if (kStrStrLen(ev->regPath, regPathLen, "CurrentVersion\\Run", 18) &&
            !kStrStrLen(imgLower, imgLen, "\\downloads\\", 11)) {
            addIndicator(idx, BA_IND_REG_MODIFY_RUN_KEY, "Modify Run key");
        }
        if (kStrStrLen(ev->regPath, regPathLen, "Image File Execution Options", 28) &&
            kStrCmp(ev->regValue, "Debugger") == 0) {
            addIndicator(idx, BA_IND_REG_MODIFY_IFEO_DEBUGGER, "IFEO Debugger hijack");
        }
        if (kStrStrLen(ev->regPath, regPathLen, "Winlogon", 8) &&
            !isGenuineSystemProcess(procIdx, imgLower)) {
            addIndicator(idx, BA_IND_REG_MODIFY_WINLOGON, "Modify Winlogon key");
        }
        if (kStrStrLen(ev->regPath, regPathLen, "\\Services\\", 10) &&
            (ev->regOp == BA_ROP_CreateKey ||
             (ev->regOp == BA_ROP_SetValue && kStrCmp(ev->regValue, "ImagePath") == 0)) &&
            kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
            addIndicator(idx, BA_IND_REG_CREATE_SERVICE, "Create/Modify service");
        }
        if (kStrStrLen(ev->regPath, regPathLen, "\\shell\\", 7) && kStrStrLen(ev->regPath, regPathLen, "\\command", 8)) {
            addIndicator(idx, BA_IND_REG_MODIFY_SHELL_OPEN, "Modify Shell command");
        }
        if (kStrStrLen(ev->regPath, regPathLen, "Schedule", 8) || kStrStrLen(ev->regPath, regPathLen, "Task Scheduler", 14) ||
            kStrStrLen(ev->regPath, regPathLen, "\\Tasks\\", 7)) {
            int isSystemTaskPath =
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\", 21) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\", 48) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows Defender\\", 28) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\UpdateOrchestrator\\", 39) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\WindowsUpdate\\", 35) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\WaaSMedic\\", 33) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\Autochk\\", 30) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\DiskCleanup\\", 34) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\DiskFootprint\\", 36) ||
                kStrStrLen(ev->regPath, regPathLen, "\\Microsoft\\Windows\\Maintenance\\", 34);
            if (!isSystemTaskPath || !isGenuineSystemProcess(procIdx, imgLower)) {
                /* taskhostw.exe 是 Windows 任务计划程序宿主进程，创建计划任务是其
                 * 合法本职工作，无论操作的是系统任务还是第三方任务都不应告警。 */
                if (!kStrIStrLen(imgLower, imgLen, "taskhostw.exe", 13)) {
                    addIndicator(idx, BA_IND_REG_SCHEDULED_TASK_CREATE, "Create scheduled task");
                }
            }
        }
    }

    /* 批量注册表修改检测（Winkiller 持久化/破坏行为）：
     * 遍历环形缓冲区中最近的事件，统计同一进程的注册表 SetValue/CreateKey 事件数量。
     * 在短时间内大量修改注册表是 Winkiller/持久化攻击的典型行为。
     * 真正的系统进程（SYSTEM SID）正常注册表操作不触发。
     * 参考 BA_IND_FILE_BULK_WRITE 的实现模式。 */
    if (!isGenuineSystemProcess(procIdx, imgLower) &&
        (ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey))
    {
        int bulkRegCount = 1;
        int scanCount = (g_baHistoryCount < 200) ? g_baHistoryCount : 200;
        int startIdx = (g_baHistoryHead - 1 + BA_MAX_HISTORY) % BA_MAX_HISTORY;
        int histI;

        for (histI = 0; histI < scanCount; histI++) {
            int histIdx = (startIdx - histI + BA_MAX_HISTORY) % BA_MAX_HISTORY;
            BA_STORED_EVENT* histEv = &g_baHistory[histIdx];
            if (histEv->pid != ev->pid) continue;
            if (histEv->category != BA_EC_Registry) continue;
            if (histEv->regOp != BA_ROP_SetValue && histEv->regOp != BA_ROP_CreateKey) continue;
            bulkRegCount++;
        }

        /* 阈值 20：正常软件安装最多修改十几项注册表，
         * Winkiller/批量持久化通常在短时间内修改数十项以上 */
        if (bulkRegCount >= 20) {
            CHAR evBuf[128];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Mass registry modification: %d keys/values in short window", bulkRegCount);
            addIndicator(idx, BA_IND_REG_MASS_MODIFY, evBuf);
        }
    }

    /* ── VM/RDP 探测检测（关键证据指标 #11-13）──
     * 恶意软件在运行前会读取特定注册表键来判断是否运行在虚拟机/沙箱中，
     * 或探测终端服务（RDP）环境。这些读取操作是纯 R0 可检测的关键证据。
     * 仅对非系统进程、非受信任进程触发。 */
    if (ev->regOp == BA_ROP_QueryValue &&
        !isGenuineSystemProcess(procIdx, imgLower))
    {
        regPathLen = kStrLen(ev->regPath);

        /* #11: 读取 TimeZoneInformation（VM 时区规避 T1497.003） */
        if (kStrStrLen(ev->regPath, regPathLen,
            "CurrentControlSet\\Control\\TimeZoneInformation", 48) ||
            kStrStrLen(ev->regPath, regPathLen,
            "Control\\TimeZoneInformation", 28))
        {
            addIndicator(idx, BA_IND_REG_VM_TZ_QUERY,
                "Read TimeZoneInformation registry key (VM/sandbox evasion)");
        }

        /* #12: 读取 BIOS 信息（VM 检测 T1497.001） */
        if (kStrStrLen(ev->regPath, regPathLen,
            "HARDWARE\\DESCRIPTION\\System\\BIOS", 32) ||
            kStrStrLen(ev->regPath, regPathLen,
            "HARDWARE\\DESCRIPTION\\System", 28))
        {
            addIndicator(idx, BA_IND_REG_VM_BIOS_QUERY,
                "Read BIOS registry key (VM detection)");
        }

        /* #13: 读取 Terminal Server 键（RDP 探测 T1021.001） */
        if (kStrStrLen(ev->regPath, regPathLen,
            "Control\\Terminal Server", 22) ||
            kStrStrLen(ev->regPath, regPathLen,
            "CurrentControlSet\\Control\\Terminal Server", 42))
        {
            addIndicator(idx, BA_IND_REG_TS_KEY_READ,
                "Read Terminal Server registry key (RDP probing)");
        }
    }

    /* ── ATT&CK 战术补充：注册表型检测（覆盖 0% 战术）── */

    /* T1548.002 UAC Bypass：HKCU\Software\Classes\*\shell\open\command 劫持
     * fodhelper.exe/eventvwr.exe/dccw.exe 等自动提升程序会读取 HKCU 下的
     * Classes\*\shell\open\command 键，恶意软件在此植入恶意命令实现 UAC Bypass。
     * 仅非系统进程触发。 */
    if ((ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey) &&
        !isGenuineSystemProcess(procIdx, imgLower))
    {
        regPathLen = kStrLen(ev->regPath);
        if (kStrStrLen(ev->regPath, regPathLen, "Software\\Classes\\", 17) &&
            kStrStrLen(ev->regPath, regPathLen, "\\shell\\open\\command", 20) &&
            (kStrCmp(ev->regValue, "command") == 0 || kStrCmp(ev->regValue, "") == 0 ||
             kStrIStrLen(ev->regPath, regPathLen, "ms-settings", 11) ||
             kStrIStrLen(ev->regPath, regPathLen, "mscfile", 7) ||
             kStrIStrLen(ev->regPath, regPathLen, "exefile", 7)))
        {
            addIndicator(idx, BA_IND_REG_UAC_BYPASS_CLASSES,
                "HKCU Classes shell\\open\\command hijack (UAC Bypass fodhelper/eventvwr)");
        }
    }

    /* T1003.006 DCSync 前置：读取 DS 恢复模式密码 / DSRM
     * 恶意软件在执行 DCSync 前会查询 LSA 策略与 DSRM 密码配置。
     * 读取 SECURITY\Policy\Secrets 或 DS 相关键的非系统进程触发。 */
    if (ev->regOp == BA_ROP_QueryValue &&
        !isGenuineSystemProcess(procIdx, imgLower))
    {
        regPathLen = kStrLen(ev->regPath);
        /* DCSync 前置：读取 LSA 策略中的 DS 恢复密码配置 */
        if (kStrStrLen(ev->regPath, regPathLen, "Policy\\Secrets", 14) ||
            kStrStrLen(ev->regPath, regPathLen, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 36) ||
            kStrStrLen(ev->regPath, regPathLen, "DSRestoreAdminPassword", 22) ||
            kStrStrLen(ev->regPath, regPathLen, "SYSTEM\\CurrentControlSet\\Control\\Lsa\\DSRMAdminLogonBehavior", 56))
        {
            addIndicator(idx, BA_IND_REG_DS_REPLICATION_QUERY,
                "Query DS restoration/DSRM password key (DCSync prerequisite)");
        }
    }

    /* T1003.004 LSA Secrets 提取：读取 SECURITY\Policy\Secrets
     * SECURITY\Policy\Secrets 存放 LSA Secrets，包含服务账号密码等敏感信息。
     * SetValue/DeleteValue 操作也触发（恶意软件可能修改 LSA Secrets）。 */
    if (!isGenuineSystemProcess(procIdx, imgLower))
    {
        regPathLen = kStrLen(ev->regPath);
        if (kStrStrLen(ev->regPath, regPathLen, "\\REGISTRY\\MACHINE\\SECURITY\\Policy\\Secrets", 41) ||
            kStrStrLen(ev->regPath, regPathLen, "SECURITY\\Policy\\Secrets", 23))
        {
            CHAR evBuf[128];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Access LSA Secrets key: %s (op=%d)", ev->regValue, (int)ev->regOp);
            addIndicator(idx, BA_IND_REG_LSA_SECRETS_QUERY, evBuf);
        }
    }

    /* T1082 系统信息发现：读取 HARDWARE\DESCRIPTION\System 频次
     * 与 BA_IND_REG_VM_BIOS_QUERY 互补，但此处额外统计频次以识别批量系统信息枚举。
     * 仅对非系统进程、非受信任进程触发，统计 60s 内查询次数。 */
    if (ev->regOp == BA_ROP_QueryValue &&
        !isGenuineSystemProcess(procIdx, imgLower))
    {
        regPathLen = kStrLen(ev->regPath);
        if (kStrStrLen(ev->regPath, regPathLen, "HARDWARE\\DESCRIPTION\\System", 28) ||
            kStrStrLen(ev->regPath, regPathLen, "HARDWARE\\DEVICEMAP", 18) ||
            kStrStrLen(ev->regPath, regPathLen, "SYSTEM\\CurrentControlSet\\Control\\ComputerName", 47))
        {
            /* 统计同一进程在历史中查询系统信息键的次数 */
            int sysInfoQueryCount = 1;
            int scanCount = (g_baHistoryCount < 200) ? g_baHistoryCount : 200;
            int startIdx = (g_baHistoryHead - 1 + BA_MAX_HISTORY) % BA_MAX_HISTORY;
            int histI;
            for (histI = 0; histI < scanCount; histI++) {
                int histIdx = (startIdx - histI + BA_MAX_HISTORY) % BA_MAX_HISTORY;
                BA_STORED_EVENT* histEv = &g_baHistory[histIdx];
                if (histEv->pid != ev->pid) continue;
                if (histEv->category != BA_EC_Registry) continue;
                if (histEv->regOp != BA_ROP_QueryValue) continue;
                {
                    int histRegLen = kStrLen(histEv->regPath);
                    if (kStrStrLen(histEv->regPath, histRegLen, "HARDWARE\\DESCRIPTION\\System", 28) ||
                        kStrStrLen(histEv->regPath, histRegLen, "HARDWARE\\DEVICEMAP", 18) ||
                        kStrStrLen(histEv->regPath, histRegLen, "SYSTEM\\CurrentControlSet\\Control\\ComputerName", 47))
                    {
                        sysInfoQueryCount++;
                    }
                }
            }
            if (sysInfoQueryCount >= 3) {
                CHAR evBuf[128];
                RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                    "System info discovery: %d hardware/system queries", sysInfoQueryCount);
                addIndicator(idx, BA_IND_REG_SYSTEM_INFO_DISCOVERY, evBuf);
            }
        }
    }

    /* ── 浏览器 elevation_service 持久化检测（注册表层 T1546.015/T1543.003）──
     * Chromium 系浏览器（Chrome/Edge/Brave）的 elevation_service 通过 COM/服务方式
     * 被调用，攻击者通过修改 CLSID 指向、服务 BinaryPathName 或 Update Client 配置
     * 实现 elevation_service 持久化劫持。
     *
     * 检测路径（三类关键注册表）：
     *   1. CLSID 劫持：HKLM\SOFTWARE\Classes\CLSID\{708860E0-F641-4611-8B7C-5D6B5D6A6C5E}
     *      （Chrome ElevationService 的 CLSID）
     *   2. 服务配置：HKLM\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService
     *      或 MicrosoftEdgeElevationService
     *   3. Update Client：HKLM\SOFTWARE\Google\Update\Clients\{8A69D345-D564-463C-AFF1-A69D4E410DC5}
     *      或 HKLM\SOFTWARE\Microsoft\EdgeUpdate\Clients\{56EB18F8-B008-4CBD-B6D2-8C97FE7E7568}
     *
     * 仅 SetValue/CreateKey/DeleteKey 操作触发（QueryValue 不触发）。
     * 排除受信任第三方进程（浏览器自身更新机制已不再区分受信任第三方）。
     */
    if ((ev->regOp == BA_ROP_SetValue || ev->regOp == BA_ROP_CreateKey ||
         ev->regOp == BA_ROP_DeleteKey || ev->regOp == BA_ROP_DeleteValue) &&
        !isGenuineSystemProcess(procIdx, imgLower))
    {
        regPathLen = kStrLen(ev->regPath);

        /* #1: Chrome ElevationService CLSID 劫持
         * {708860E0-F641-4611-8B7C-5D6B5D6A6C5E} 为 Chrome ElevationService 已知 CLSID */
        if (kStrStrLen(ev->regPath, regPathLen, "Classes\\CLSID\\{708860E0-F641-4611-8B7C-5D6B5D6A6C5E}", 64) ||
            kStrStrLen(ev->regPath, regPathLen, "Classes\\CLSID\\{708860E0-", 26) ||
            kStrStrLen(ev->regPath, regPathLen, "Wow6432Node\\Classes\\CLSID\\{708860E0-", 37))
        {
            addIndicator(idx, BA_IND_REG_ELEVATION_SERVICE_HIJACK,
                "Hijack Chrome ElevationService CLSID {708860E0-...} (T1546.015)");
        }
        /* #2: ElevationService 服务配置修改（含其他浏览器/扩展） */
        else if (kStrStrLen(ev->regPath, regPathLen, "Services\\GoogleChromeElevationService", 37) ||
                 kStrStrLen(ev->regPath, regPathLen, "Services\\MicrosoftEdgeElevationService", 38) ||
                 kStrStrLen(ev->regPath, regPathLen, "Services\\BraveElevationService", 30) ||
                 /* 通用模式：任何含 ElevationService 的服务注册表修改 */
                 kStrStrLen(ev->regPath, regPathLen, "Services\\ElevationService", 25) ||
                 kStrStrLen(ev->regPath, regPathLen, "Services\\Elevation", 19))
        {
            addIndicator(idx, BA_IND_REG_ELEVATION_SERVICE_HIJACK,
                "Modify Chromium ElevationService service registry (T1543.003)");
        }
        /* #3: Google Update / Microsoft EdgeUpdate Client 配置修改
         * {8A69D345-D564-463C-AFF1-A69D4E410DC5} = Chrome
         * {56EB18F8-B008-4CBD-B6D2-8C97FE7E7568} = Edge
         * 修改 cmd 或 LauncherPath 值可用于劫持调用链 */
        else if ((kStrStrLen(ev->regPath, regPathLen, "Google\\Update\\Clients\\", 22) &&
                  kStrStrLen(ev->regPath, regPathLen, "8A69D345-D564-463C-AFF1-A69D4E410DC5", 37)) ||
                 (kStrStrLen(ev->regPath, regPathLen, "Microsoft\\EdgeUpdate\\Clients\\", 29) &&
                  kStrStrLen(ev->regPath, regPathLen, "56EB18F8-B008-4CBD-B6D2-8C97FE7E7568", 37)))
        {
            addIndicator(idx, BA_IND_REG_ELEVATION_SERVICE_HIJACK,
                "Modify Chromium Update Client registry (elevation_service persistence)");
        }
        /* #4: 通用 ElevationService 相关注册表路径检测（兜底） */
        else if (kStrStrLen(ev->regPath, regPathLen, "ElevationService", 16) ||
                 kStrStrLen(ev->regPath, regPathLen, "elevation_service", 17))
        {
            addIndicator(idx, BA_IND_REG_ELEVATION_SERVICE_HIJACK,
                "Suspicious ElevationService registry modification (T1543.003)");
        }
    }
}

/* ── BehaviorExtractFileIndicators ── */
VOID BehaviorExtractFileIndicators(int idx, const BA_STORED_EVENT* ev)
{
    int imgLen;
    int procIdx;
    CHAR imgLower[BA_MAX_PATH];
    CHAR dirLower[BA_MAX_PATH];
    CHAR fnameLower[BA_MAX_NAME];
    CHAR extLower[16];
    int dirLen, fnameLen;
    int isSystemDir = 0, isDriversDir = 0, isStartupDir = 0, isCreate = 0;
    int i;

    if (idx < 0 || ev == NULL || ev->category != BA_EC_File) return;

    procIdx = findProc(ev->pid);
    if (procIdx >= 0 && g_baProcTree[procIdx].imagePath[0]) {
        kStrLowerCopy(imgLower, BA_MAX_PATH, g_baProcTree[procIdx].imagePath);
    } else {
        kStrLowerCopy(imgLower, BA_MAX_PATH, ev->imagePath);
    }
    imgLen = kStrLen(imgLower);

    isCreate = (ev->fileOp == BA_FOP_Create);

    kStrLowerCopy(dirLower, BA_MAX_PATH, ev->fileDir);
    dirLen = kStrLen(dirLower);
    isSystemDir  = kStrStrLen(dirLower, dirLen, "\\windows\\system32", 17) || kStrStrLen(dirLower, dirLen, "\\windows\\syswow64", 17);
    isDriversDir = kStrStrLen(dirLower, dirLen, "\\windows\\system32\\drivers", 25) || kStrStrLen(dirLower, dirLen, "\\windows\\syswow64\\drivers", 25);
    isStartupDir = kStrStrLen(dirLower, dirLen, "\\startup", 8) || kStrStrLen(dirLower, dirLen, "\\start menu\\programs\\startup", 29);

    kStrLowerCopy(extLower, 16, ev->fileExt);
    kStrLowerCopy(fnameLower, BA_MAX_NAME, ev->fileName);
    fnameLen = kStrLen(fnameLower);

    /* 系统目录创建：真正的系统进程（SYSTEM SID）写入是正常行为，
     * 冒名病毒即使投放至 System32 也无法以 SYSTEM 身份运行。
     * 仅检查可执行/脚本扩展名，避免 .log/.tmp/.dat 等正常文件误报。 */
    if (isCreate && isSystemDir && !ev->isSigned &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 ||
         kStrCmp(extLower, ".sys") == 0 || kStrCmp(extLower, ".bat") == 0 ||
         kStrCmp(extLower, ".ps1") == 0 || kStrCmp(extLower, ".vbs") == 0 ||
         kStrCmp(extLower, ".js") == 0 || kStrCmp(extLower, ".cmd") == 0 ||
         kStrCmp(extLower, ".scr") == 0 || kStrCmp(extLower, ".com") == 0)) {
        addIndicator(idx, BA_IND_FILE_CREATE_SYSTEM_DIR, "Unsigned file written to system dir");
    }
    if (isCreate && isDriversDir && kStrCmp(extLower, ".sys") == 0 && !ev->isSigned) {
        addIndicator(idx, BA_IND_FILE_CREATE_DRIVER, "Unsigned driver written to drivers dir");
    }
    /* 伪系统目录检测：C:\Drivers\<随机子目录>\ 等根目录伪造的系统目录。
     * 病毒常在 C:\Drivers\Mu8989\ 等非标准目录投放可执行文件以伪装系统驱动目录。
     * 仅检测无签名可执行文件（.exe/.dll/.sys），已签名硬件厂商驱动不触发。
     * 排除 \windows\system32\drivers（已由 isDriversDir 覆盖）。 */
    if (isCreate && !ev->isSigned &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 ||
         kStrCmp(extLower, ".sys") == 0) &&
        (kStrStrLen(dirLower, dirLen, "c:\\drivers\\", 11) ||
         kStrStrLen(dirLower, dirLen, "\\drivers\\", 9)) &&
        !kStrStrLen(dirLower, dirLen, "\\windows\\system32\\drivers", 25) &&
        !kStrStrLen(dirLower, dirLen, "\\windows\\syswow64\\drivers", 25)) {
        addIndicator(idx, BA_IND_FILE_CREATE_FAKE_SYS_DIR, "Unsigned executable in fake system driver directory");
    }
    if (isCreate && isStartupDir && (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 || kStrCmp(extLower, ".bat") == 0)) {
        addIndicator(idx, BA_IND_FILE_CREATE_STARTUP_EXE, "Executable written to startup dir");
    }

    if (isCreate && isSystemDir && kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
        addIndicator(idx, BA_IND_FILE_DROP_FROM_TEMP, "Temp process writes to system dir");
    }

    if (!ev->isSigned && isCreate && kStrStrLen(imgLower, imgLen, "\\temp\\", 6)) {
        static const CHAR* fakeNames[] = {"setup", "install", "update", "patch", "flash", "chrome", "firefox"};
        for (i = 0; i < 7; i++) {
            if (kStrIStrLen(imgLower, imgLen, fakeNames[i], kStrLen(fakeNames[i]))) {
                addIndicator(idx, BA_IND_PROC_FAKE_UPDATE_INSTALLER, "Fake update installer");
                break;
            }
        }
    }

    if (isCreate && isSystemDir && kStrCmp(extLower, ".dll") == 0 && !ev->isSigned) {
        static const CHAR* knownDlls[] = {"ntdll.dll", "kernel32.dll", "user32.dll", "comctl32.dll",
                                            "ntdll", "kernel32", "user32", "comctl32"};
        for (i = 0; i < 8; i++) {
            if (kStrStrLen(fnameLower, fnameLen, knownDlls[i], kStrLen(knownDlls[i]))) {
                addIndicator(idx, BA_IND_FILE_CREATE_DLL_HIJACK, "DLL hijack");
                break;
            }
        }
    }

    {
        static const CHAR* cryptExts[] = {
            ".encrypted", ".lockbit", ".crypt", ".wncry", ".wcry", ".locked",
            ".cryptolocker", ".cerber", ".zepto", ".odin", ".thor", ".potato",
            ".crab", ".dharma", ".phobos", ".ryuk", ".conti", ".revil", ".sodinokibi",
            ".maze", ".ekans", ".netwalker", ".dark", ".enc", ".crypted",
            ".xxx", ".ttt", ".micro", ".zzz", ".lock", ".blackbyte", ".hive",
            ".avaddon", ".avos", ".darkbit", ".haron", ".medusa", ".play", ".royal",
            ".akira", ".blacksuit", ".blackcat", ".clop", ".exx", ".mamba", ".moisha",
            ".pysa", ".ragnar", ".djvu", ".karma", ".wallet", ".none", ".babuk",
            ".lorenz", ".ransom", ".koko", ".nephilim", ".payme", ".spook"
        };
        for (i = 0; i < (int)(sizeof(cryptExts) / sizeof(cryptExts[0])); i++) {
            if (!isGenuineSystemProcess(procIdx, imgLower) && kStrCmp(extLower, cryptExts[i]) == 0) {
                addIndicator(idx, BA_IND_FILE_ENCRYPTED_EXTENSION, "Encrypted extension");
                break;
            }
        }
    }

    /* 勒索通知：仅 Create/Write 操作，排除过于宽泛的通用词 */
    if ((ev->fileOp == BA_FOP_Create || ev->fileOp == BA_FOP_Write) &&
        !isGenuineSystemProcess(procIdx, imgLower)) {
        static const CHAR* ransomKeywords[] = {
            "ransom", "ransom_note", "ransomware", "pay_ransom",
            "@wanadecryptor", "@please_read_me", "lockbit",
            "conti", "contiremote", "revil", "sodinokibi",
            "hakitzu", "clop", "akira", "blackbyte", "hive",
            "darktrace_readme", "_locked", "_encrypted",
            "de_crypt_recover", "ALLYOURFILES",
            "bitcoin", "monero",
            "nemty", "medusa",
            "decrypted_file", "readme_ransom",
            0
        };
        BOOLEAN ransomDetected = FALSE;
        for (i = 0; ransomKeywords[i] != 0; i++) {
            if (kStrIStrLen(fnameLower, fnameLen, ransomKeywords[i], kStrLen(ransomKeywords[i]))) {
                addIndicator(idx, BA_IND_FILE_RANSOM_NOTE, "Ransom note file");
                ransomDetected = TRUE;
                break;
            }
        }
        if (!ransomDetected) {
            static const CHAR* broadNotes[] = {
                "readme", "decrypt", "restore", "recover",
                "how_to_decrypt", "your_files", "payment",
                "_readme", "_decrypt", "_restore", "_recover",
                "instructions", "how_to_restore", "contact",
                "decryptor", "decrypt_info", "decryption",
                "what_happened", "all_your_files", "data_restore",
                "unlock_files", "recovery_key", "restore_files",
                "how_to_recover", "recovery_info", "unlock_instructions",
                "helprecover", "encrypt_info", "encfile",
                "readme_lock", "readme_info", "decryption_info",
                "help_restore", "help_decrypt"
            };
            int hasEncryptedExt = kStrCmp(extLower, ".encrypted") == 0 ||
                kStrCmp(extLower, ".lockbit") == 0 ||
                kStrCmp(extLower, ".crypt") == 0 ||
                kStrCmp(extLower, ".wncry") == 0 ||
                kStrCmp(extLower, ".locked") == 0 ||
                kStrCmp(extLower, ".exe") == 0;
            if (hasEncryptedExt) {
                for (i = 0; i < (int)(sizeof(broadNotes)/sizeof(broadNotes[0])); i++) {
                    if (kStrIStrLen(fnameLower, fnameLen, broadNotes[i], kStrLen(broadNotes[i]))) {
                        addIndicator(idx, BA_IND_FILE_RANSOM_NOTE, "Ransom note file (broad match with encrypted ext)");
                        break;
                    }
                }
            }
        }
    }

    if (isCreate && kStrCmp(extLower, ".dll") == 0 && !ev->isSigned) {
        int isSelfLoad = 0;
        int lastSep = -1;
        int pathLen = 0;
        const CHAR* dllPath = ev->filePath;
        CHAR evBuf[128];

        for (i = imgLen - 1; i >= 0; i--) {
            if (imgLower[i] == '\\') { lastSep = i; break; }
        }
        if (lastSep > 0 && dirLen == lastSep && kStrNCmp(dirLower, imgLower, lastSep) == 0) {
            isSelfLoad = 1;
        }

        int inSuspiciousDllDir = kStrStrLen(dirLower, dirLen, "program files", 13) ||
                                 kStrStrLen(dirLower, dirLen, "appdata", 7) ||
                                 kStrStrLen(dirLower, dirLen, "temp", 4) ||
                                 kStrStrLen(dirLower, dirLen, "downloads", 9);

        int sourceIsSuspicious = kStrStrLen(imgLower, imgLen, "\\temp\\", 6) ||
                                 kStrStrLen(imgLower, imgLen, "\\downloads\\", 11) ||
                                 kStrStrLen(imgLower, imgLen, "\\appdata\\", 9) ||
                                 kStrStrLen(imgLower, imgLen, "\\programdata\\", 13) ||
                                 !ev->isSigned;

        if (isSelfLoad && sourceIsSuspicious && !isGenuineSystemProcess(procIdx, imgLower)) {
            pathLen = kStrLen(dllPath);
            if (pathLen > 100) dllPath += (pathLen - 100);
            RtlStringCbPrintfA(evBuf, sizeof(evBuf), "SelfLoading DLL: %s", dllPath);
            addIndicator(idx, BA_IND_FILE_SELF_LOADING, evBuf);
        }
        else if (inSuspiciousDllDir && !ev->isSigned)
        {
            /* WindowsApps 目录是 UWP 应用正常 DLL 加载位置，排除。
             *
             * 真正的系统进程（SYSTEM SID 验证）加载 Shell 扩展/输入法 DLL 是正常行为
             * （如 consent.exe 加载 \microsoft shared\ink\tiptsf.dll）。
             * 仅 isSystemProcessByPath 不够：病毒可命名 consent.exe 投放至 System32，
             * 但无法以 SYSTEM 身份运行。使用 isGenuineSystemProcess 三重验证。 */
            int isWindowsAppsDir = kStrStrLen(dirLower, dirLen, "\\windowsapps\\", 13);
            int dllPathLen = kStrLen(dllPath);
            int isKnownOfficeDll = kStrIStrLen(dllPath, dllPathLen, "kingsoft\\wps office", 19) ||
                                   kStrIStrLen(dllPath, dllPathLen, "microsoft office", 16) ||
                                   kStrIStrLen(dllPath, dllPathLen, "libreoffice", 11);
            int isSecurityProductDir = kStrStrLen(dirLower, dirLen, "\\360safe\\", 9) ||
                                       kStrStrLen(dirLower, dirLen, "\\360sd\\", 8) ||
                                       kStrStrLen(dirLower, dirLen, "\\360scan\\", 10) ||
                                       kStrStrLen(dirLower, dirLen, "\\windows defender\\", 19) ||
                                       kStrStrLen(dirLower, dirLen, "\\kaspersky lab\\", 16);
            int isHardwareVendorDir = kStrStrLen(dirLower, dirLen, "\\nvidia corporation\\", 20) ||
                                       kStrStrLen(dirLower, dirLen, "\\nvidia\\", 9);
            if (!isWindowsAppsDir && !isGenuineSystemProcess(procIdx, imgLower) &&
                !isKnownOfficeDll && !isSecurityProductDir && !isHardwareVendorDir) {
                pathLen = dllPathLen;
                if (pathLen > 100) dllPath += (pathLen - 100);
                RtlStringCbPrintfA(evBuf, sizeof(evBuf), "DLL side-load: %s", dllPath);
                addIndicator(idx, BA_IND_FILE_DLL_SIDE_LOAD, evBuf);
            }
        }
    }

    if (IsBrowserDirectory(dirLower, dirLen)) {
        if (kStrIStrLen(fnameLower, fnameLen, "login data", 10) || kStrIStrLen(fnameLower, fnameLen, "cookies", 7) ||
            kStrIStrLen(fnameLower, fnameLen, "web data", 8) || kStrIStrLen(fnameLower, fnameLen, "key4.db", 7) ||
            kStrIStrLen(fnameLower, fnameLen, "logins.json", 11)) {
            addIndicator(idx, BA_IND_FILE_BROWSER_CRED_TARGET, "Browser credential target");
        }
    }

    /* 未签名可执行文件创建：仅检查可执行/脚本扩展名，真正的系统进程（SYSTEM SID）正常操作不标记 */
    if (!ev->isSigned && isCreate &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0 ||
         kStrCmp(extLower, ".sys") == 0 || kStrCmp(extLower, ".bat") == 0 ||
         kStrCmp(extLower, ".ps1") == 0 || kStrCmp(extLower, ".vbs") == 0 ||
         kStrCmp(extLower, ".js") == 0 || kStrCmp(extLower, ".cmd") == 0 ||
         kStrCmp(extLower, ".scr") == 0 || kStrCmp(extLower, ".com") == 0)) {
        /* 签名可信度减免：已签名进程创建的文件不标记为未签名 */
        if (CiIsPidSigned(ev->pid)) {
            /* 可信进程创建的文件，不标记 BA_IND_PROC_UNSIGNED */
        } else {
            addIndicator(idx, BA_IND_PROC_UNSIGNED, "Process creates unsigned executable");
        }
    }

    if (ev->fileOp == BA_FOP_Delete && ev->imagePath[0]) {
        CHAR selfLower[BA_MAX_PATH];
        CHAR fileLower[BA_MAX_PATH];
        kStrLowerCopy(selfLower, BA_MAX_PATH, ev->imagePath);
        kStrLowerCopy(fileLower, BA_MAX_PATH, ev->filePath);
        if (kStrEndsWith(fileLower, selfLower)) {
            addIndicator(idx, BA_IND_FILE_SELF_DELETE, "Self-delete");
        }
    }

    if (isCreate && kStrStrLen(dirLower, dirLen, "\\\\", 2) && (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0)) {
        addIndicator(idx, BA_IND_FILE_NETWORK_SHARE, "Network share propagation");
    }

    if (isCreate && kStrCmp(fnameLower, "autorun.inf") == 0) {
        addIndicator(idx, BA_IND_FILE_INF_AUTORUN, "autorun.inf created");
    }

    if (ev->fileOp == BA_FOP_Modify && kStrStrLen(dirLower, dirLen, "\\drivers\\etc", 12) && kStrCmp(fnameLower, "hosts") == 0) {
        addIndicator(idx, BA_IND_FILE_HOSTS_MODIFY, "hosts file modified");
    }

    /* 通用文件重命名：仅对非系统进程记录，用于追踪伪装/覆盖行为（T1036/T1222） */
    if (ev->fileOp == BA_FOP_Modify && !isGenuineSystemProcess(procIdx, imgLower)) {
        addIndicator(idx, BA_IND_FILE_RENAME, "File rename detected");
    }

    if (kStrIStrLen(dirLower, dirLen, "physicaldrive", 13)) {
        addIndicator(idx, BA_IND_FILE_DISK_RAW_ACCESS, "Disk raw access");
    }

    {
        static const CHAR* byovdDrivers[] = {
            "rtcore64.sys", "gdrv.sys", "atillk64.sys", "kprocesshacker.sys",
            "capcom.sys", "winring0.sys", "dbk64.sys", "bs_dpl.sys",
            "amp.sys", "speedfan.sys", "vmxdrv.sys", "asrdrv106.sys",
            "atszio.sys", "cpuz_x64.sys", "eoploaddriver.sys", "gmer.sys",
            "lha.sys", "mimikatz.sys", "mhyprot.sys", "mhyprot2.sys",
            "mhyprotec.sys", "ncpl.sys", "nvoclock.sys", "pcileech.sys",
            "phymem.sys", "physmem.sys", "piddrv.sys", "piddrv64.sys",
            "processhacker.sys", "rweverything.sys", "secreal.sys",
            "semav6msr64.sys", "truesight.sys", "viragt64.sys", "vuln.sys",
            "winio.sys", "winio64.sys", "zenaidrv.sys"
        };
        for (i = 0; i < 38; i++) {
            if (kStrCmp(fnameLower, byovdDrivers[i]) == 0) {
                addIndicator(idx, BA_IND_FILE_BYOVD_DRIVER_LOAD, "BYOVD vulnerable driver");
                break;
            }
        }
    }

    if (isCreate && kStrCmp(extLower, ".dll") == 0 && !ev->isSigned &&
        kStrStrLen(dirLower, dirLen, "\\appdata\\", 9)) {
        int isKnownApp = kStrIStrLen(dirLower, dirLen, "\\discord\\", 9) ||
            kStrIStrLen(dirLower, dirLen, "\\slack\\", 7) ||
            kStrIStrLen(dirLower, dirLen, "\\teams\\", 7) ||
            kStrIStrLen(dirLower, dirLen, "\\zoom\\", 6) ||
            kStrIStrLen(dirLower, dirLen, "\\mozilla\\", 9) ||
            kStrIStrLen(dirLower, dirLen, "\\google\\chrome\\", 14);
        if (!isKnownApp && !isGenuineSystemProcess(procIdx, imgLower)) {
            addIndicator(idx, BA_IND_FILE_APPDATA_DLL, "AppData directory DLL drop");
        }
    }

    if ((kStrStrLen(dirLower, dirLen, "\\tor\\", 5) || kStrStrLen(dirLower, dirLen, "\\i2p\\", 5) ||
        kStrIStrLen(fnameLower, fnameLen, "c2_", 3) || kStrIStrLen(fnameLower, fnameLen, "beacon", 6) ||
        kStrIStrLen(fnameLower, fnameLen, "stager", 6) || kStrIStrLen(fnameLower, fnameLen, "payload", 7) ||
        kStrIStrLen(fnameLower, fnameLen, "shellcode", 9))) {
        addIndicator(idx, BA_IND_NETWORK_C2_CONNECT, "C2 communication indicator");
    }

    if (isCreate && (kStrStrLen(dirLower, dirLen, "\\boot\\", 6) || kStrStrLen(dirLower, dirLen, "\\efi\\", 5) ||
        kStrStrLen(dirLower, dirLen, "\\recovery\\", 10) || kStrIStrLen(fnameLower, fnameLen, "bootexecute", 11))) {
        addIndicator(idx, BA_IND_FILE_BOOT_EXECUTE, "BootExecute persistence");
    }

    /* 批量文件写入检测（勒索软件加密行为）：
     * 遍历环形缓冲区中最近的事件，统计同一进程的文件写入/修改事件数量。
     * 在短时间内修改大量文件是勒索软件的典型行为。
     * 此检测在持有 g_baLock 自旋锁状态下执行，限制扫描数量避免性能问题。 */
    if (ev->fileOp == BA_FOP_Write || ev->fileOp == BA_FOP_Create ||
        ev->fileOp == BA_FOP_Modify || ev->fileOp == BA_FOP_Delete)
    {
        int bulkCount = 1;
        int scanCount = (g_baHistoryCount < 150) ? g_baHistoryCount : 150;
        int startIdx = (g_baHistoryHead - 1 + BA_MAX_HISTORY) % BA_MAX_HISTORY;
        int histI;

        for (histI = 0; histI < scanCount; histI++)
        {
            int histIdx = (startIdx - histI + BA_MAX_HISTORY) % BA_MAX_HISTORY;
            BA_STORED_EVENT* histEv = &g_baHistory[histIdx];
            if (histEv->pid != ev->pid) continue;
            if (histEv->category != BA_EC_File) continue;
            if (histEv->fileOp != BA_FOP_Write && histEv->fileOp != BA_FOP_Create &&
                histEv->fileOp != BA_FOP_Modify && histEv->fileOp != BA_FOP_Delete) continue;
            bulkCount++;
        }

        if (bulkCount >= 15)
        {
            addIndicator(idx, BA_IND_FILE_BULK_WRITE, "Bulk file modification (possible ransomware encryption)");
        }
    }

    /* ── ATT&CK 战术补充：文件路径型检测（覆盖 0% 战术）── */

    /* T1566.001 钓鱼附件：读取 Zone.Identifier ADS（Mark of the Web）
     * MotW 是 Windows 对来自互联网文件的标记，恶意软件读取此 ADS 以
     * 检测是否被标记并规避。仅非系统进程触发。 */
    {
        int filePathLen = kStrLen(ev->filePath);
        if (filePathLen > 0 &&
            !isGenuineSystemProcess(procIdx, imgLower) &&
            (kStrIStrLen(ev->filePath, filePathLen, ":zone.identifier", 17) ||
             kStrIStrLen(ev->filePath, filePathLen, ":zoneid", 7))) {
            addIndicator(idx, BA_IND_FILE_MOTW_ZONE_IDENTIFIER,
                "Read Mark of the Web Zone.Identifier ADS (phishing attachment check)");
        }
    }

    /* T1195.002 供应链攻击：已签名 EXE 加载未签名 DLL
     * 与 FILE_DLL_SIDE_LOAD 互补：当源进程在系统目录/Program Files 但 DLL 未签名时触发。
     * 真正的系统进程（SYSTEM SID）不触发。 */
    if (isCreate && kStrCmp(extLower, ".dll") == 0 && !ev->isSigned &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrStrLen(imgLower, imgLen, "\\program files\\", 15) ||
         kStrStrLen(imgLower, imgLen, "\\windows\\system32\\", 18) ||
         kStrStrLen(imgLower, imgLen, "\\windows\\syswow64\\", 18))) {
        addIndicator(idx, BA_IND_FILE_DLL_UNSIGNED_CHAIN,
            "Signed host EXE loads unsigned DLL (supply chain risk)");
    }

    /* T1003.002 SAM 凭据转储：读取 SAM/SYSTEM/SECURITY 配置文件
     * 这些文件包含 Windows 凭据哈希，恶意软件通过复制或读取这些文件进行凭据转储。
     * 真正的系统进程（如 smss.exe/winlogon.exe 在正常启动时）不触发。 */
    {
        int filePathLen = kStrLen(ev->filePath);
        if (filePathLen > 0 &&
            !isGenuineSystemProcess(procIdx, imgLower) &&
            kStrStrLen(dirLower, dirLen, "\\windows\\system32\\config", 25) &&
            (kStrCmp(fnameLower, "sam") == 0 || kStrCmp(fnameLower, "system") == 0 ||
             kStrCmp(fnameLower, "security") == 0 || kStrCmp(fnameLower, "software") == 0)) {
            CHAR evBuf[128];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Read credential hive file: %s", fnameLower);
            addIndicator(idx, BA_IND_FILE_SAM_HIVE_READ, evBuf);
        }
    }

    /* T1555 DPAPI 凭据存储：读取 DPAPI 主密钥文件
     * %APPDATA%\Microsoft\Protect\<SID>\ 目录存放 DPAPI 主密钥，
     * 恶意软件读取此目录以解密浏览器/邮件等凭据。 */
    {
        int dpapiPath = kStrStrLen(dirLower, dirLen, "\\microsoft\\protect\\", 19) ||
                        kStrStrLen(dirLower, dirLen, "\\appdata\\roaming\\microsoft\\protect", 35);
        if (dpapiPath && !isGenuineSystemProcess(procIdx, imgLower)) {
            addIndicator(idx, BA_IND_FILE_DPAPI_MASTER_KEY,
                "Read DPAPI master key directory (credential store access)");
        }
    }

    /* T1113 屏幕捕获：非截图工具在 temp/appdata 创建 .png/.bmp 文件
     * 排除系统自带截图工具（SnippingTool/SnippingTool.exe）和已知截图软件。 */
    if (isCreate &&
        (kStrCmp(extLower, ".png") == 0 || kStrCmp(extLower, ".bmp") == 0 ||
         kStrCmp(extLower, ".jpg") == 0 || kStrCmp(extLower, ".jpeg") == 0) &&
        (kStrStrLen(dirLower, dirLen, "\\temp\\", 6) ||
         kStrStrLen(dirLower, dirLen, "\\appdata\\", 9) ||
         kStrStrLen(dirLower, dirLen, "\\downloads\\", 11)) &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        !kStrIStrLen(imgLower, imgLen, "snippingtool", 12) &&
        !kStrIStrLen(imgLower, imgLen, "screenclip", 10) &&
        !kStrIStrLen(imgLower, imgLen, "snipaste", 8) &&
        !kStrIStrLen(imgLower, imgLen, "sharex", 6)) {
        addIndicator(idx, BA_IND_FILE_SCREEN_CAPTURE,
            "Screenshot image created in temp/appdata by non-screenshot tool");
    }

    /* T1074 数据暂存：短时间内批量复制 exe/dll 至暂存目录
     * 统计同一进程在 temp/appdata 目录下创建的可执行文件数量。
     * 正常软件安装通常不会批量投放多个 exe/dll 到暂存目录。 */
    if (isCreate &&
        (kStrStrLen(dirLower, dirLen, "\\temp\\", 6) ||
         kStrStrLen(dirLower, dirLen, "\\appdata\\", 9) ||
         kStrStrLen(dirLower, dirLen, "\\downloads\\", 11)) &&
        (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0) &&
        !isGenuineSystemProcess(procIdx, imgLower))
    {
        int stagedCount = 1;
        int scanCount = (g_baHistoryCount < 200) ? g_baHistoryCount : 200;
        int startIdx = (g_baHistoryHead - 1 + BA_MAX_HISTORY) % BA_MAX_HISTORY;
        int histI;
        for (histI = 0; histI < scanCount; histI++) {
            int histIdx = (startIdx - histI + BA_MAX_HISTORY) % BA_MAX_HISTORY;
            BA_STORED_EVENT* histEv = &g_baHistory[histIdx];
            if (histEv->pid != ev->pid) continue;
            if (histEv->category != BA_EC_File) continue;
            if (histEv->fileOp != BA_FOP_Create && histEv->fileOp != BA_FOP_Modify) continue;
            {
                CHAR histExt[16];
                kStrLowerCopy(histExt, 16, histEv->fileExt);
                if (kStrCmp(histExt, ".exe") == 0 || kStrCmp(histExt, ".dll") == 0) {
                    CHAR histDir[BA_MAX_PATH];
                    int histDirLen;
                    kStrLowerCopy(histDir, BA_MAX_PATH, histEv->fileDir);
                    histDirLen = kStrLen(histDir);
                    if (kStrStrLen(histDir, histDirLen, "\\temp\\", 6) ||
                        kStrStrLen(histDir, histDirLen, "\\appdata\\", 9) ||
                        kStrStrLen(histDir, histDirLen, "\\downloads\\", 11)) {
                        stagedCount++;
                    }
                }
            }
        }
        if (stagedCount >= 5) {
            CHAR evBuf[128];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Batch executable staging: %d files in temp/appdata", stagedCount);
            addIndicator(idx, BA_IND_FILE_DATA_STAGED, evBuf);
        }
    }

    /* ── 浏览器 elevation_service 持久化检测（文件层 T1574.002/T1543.003）──
     * Chromium 系浏览器（Chrome/Edge/Brave）的 elevation_service.exe 是恶意软件
     * 常用持久化目标，攻击者通过替换 EXE 或投放侧加载 DLL 实现持久化。
     *
     * 检测路径（安装目录下 elevation_service 或 Installers 子目录）：
     *   Chrome: \Google\Chrome\Application\<ver>\elevation_service.exe
     *   Edge:   \Microsoft\Edge\Application\<ver>\elevation_service.exe
     *   Brave:  \BraveSoftware\Brave-Browser\Application\<ver>\elevation_service.exe
     *
     * 触发条件：
     *   1. 文件创建/修改操作
     *   2. 目标路径位于浏览器 Application\*\ 目录
     *   3. 文件名为 elevation_service.exe（EXE 替换）
     *      或 elevation_service.exe 常用侧加载 DLL（version.dll/chrome_elf.dll 等）
     *   4. 排除受信任第三方进程（浏览器自身更新机制已不再区分）
     */
    if (isCreate &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0) &&
        (kStrStrLen(dirLower, dirLen, "\\google\\chrome\\application\\", 27) ||
         kStrStrLen(dirLower, dirLen, "\\microsoft\\edge\\application\\", 29) ||
         kStrStrLen(dirLower, dirLen, "\\bravesoftware\\brave-browser\\application\\", 41)))
    {
        /* 匹配 elevation_service.exe 本体替换 */
        int isElevationExe = (kStrCmp(fnameLower, "elevation_service.exe") == 0);
        /* 匹配 elevation_service 常用侧加载 DLL
         * chrome_elf.dll: Chrome/Edge 核心加载 DLL，替换即劫持
         * version.dll:    Chromium 已知侧加载目标（签名校验弱）
         * elevation_service.exe 相同目录的其他无签名 DLL 也视为可疑 */
        int isSideLoadDll = (kStrCmp(fnameLower, "chrome_elf.dll") == 0 ||
                             kStrCmp(fnameLower, "version.dll") == 0 ||
                             kStrCmp(fnameLower, "elevation_service.dll") == 0);

        if (isElevationExe || isSideLoadDll) {
            CHAR evBuf[256];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Chromium elevation_service hijack: %s in browser Application dir (%s)",
                isElevationExe ? "EXE replace" : "DLL side-load",
                fnameLower);
            addIndicator(idx, BA_IND_FILE_ELEVATION_SERVICE_HIJACK, evBuf);
        }
    }

    /* ── 银狐家族分类低危指标（仅作家族归类，不单独触发警报）──
     * 银狐木马典型行为特征：在伪装目录投放可执行文件 + 随机文件名。
     * 这些指标权重极低（8.0），单独不足以触发威胁警报，
     * 但当综合行为分析判定为病毒时，用于将威胁归类为 SilverFox 家族。
     *
     * 检测两类特征：
     *   1. 伪装目录投放：在 temp/appdata/c:\drivers 等非标准目录创建可执行文件
     *   2. 随机文件名可执行文件：临时目录中文件名符合随机生成模式（如 8位以上字母数字混合）
     */
    if (isCreate &&
        !isGenuineSystemProcess(procIdx, imgLower) &&
        (kStrCmp(extLower, ".exe") == 0 || kStrCmp(extLower, ".dll") == 0))
    {
        /* #1: 伪装目录投放可执行文件
         * 银狐常在以下目录投放载荷：
         *   - %TEMP%\<随机目录>\
         *   - %APPDATA%\<随机目录>\
         *   - C:\Drivers\<随机目录>\（伪装系统驱动目录）
         *   - %LOCALAPPDATA%\<随机目录>\
         * 排除标准系统目录（System32/SysWOW64）和 Program Files。 */
        int isFakeDir = 0;
        if ((kStrStrLen(dirLower, dirLen, "\\temp\\", 6) ||
             kStrStrLen(dirLower, dirLen, "\\appdata\\", 9) ||
             kStrStrLen(dirLower, dirLen, "\\local\\", 7) ||
             kStrStrLen(dirLower, dirLen, "c:\\drivers\\", 11) ||
             kStrStrLen(dirLower, dirLen, "\\drivers\\", 9)) &&
            !kStrStrLen(dirLower, dirLen, "\\windows\\system32\\drivers", 25) &&
            !kStrStrLen(dirLower, dirLen, "\\windows\\syswow64\\drivers", 25) &&
            !kStrStrLen(dirLower, dirLen, "\\program files\\", 15) &&
            !kStrStrLen(dirLower, dirLen, "\\program files (x86)\\", 21))
        {
            isFakeDir = 1;
        }

        if (isFakeDir) {
            addIndicator(idx, BA_IND_FILE_FAKE_DIR_DROP,
                "Executable dropped to fake directory (temp/appdata/drivers)");
        }

        /* #2: 随机文件名可执行文件检测
         * 银狐常用随机生成的文件名（如 a1b2c3d4.exe、xj7k9m2.exe）。
         * 检测规则：
         *   - 文件名长度 6-12 字符（不含扩展名）
         *   - 包含数字和字母混合（随机生成特征）
         *   - 无明显语义单词（排除 setup/update/patch 等正常文件名）
         *   - 位于临时/伪装目录 */
        if (isFakeDir && fnameLen >= 6) {
            /* 去除扩展名后的文件名长度 */
            int baseNameLen = fnameLen;
            if (kStrCmp(extLower, ".exe") == 0) baseNameLen -= 4;
            else if (kStrCmp(extLower, ".dll") == 0) baseNameLen -= 4;

            if (baseNameLen >= 6 && baseNameLen <= 12) {
                int hasDigit = 0, hasAlpha = 0, hasOther = 0;
                int ci;
                /* 排除常见正常文件名 */
                static const CHAR* normalNames[] = {
                    "setup", "install", "update", "patch", "flash", "chrome",
                    "firefox", "edge", "brave", "config", "version", "helper",
                    "service", "launcher", "stub", "core", "main", "run"
                };
                int isNormalName = 0;
                for (ci = 0; ci < 18; ci++) {
                    if (kStrIStrLen(fnameLower, fnameLen, normalNames[ci], kStrLen(normalNames[ci]))) {
                        isNormalName = 1;
                        break;
                    }
                }

                if (!isNormalName) {
                    /* 统计字符类型：随机文件名通常字母+数字混合 */
                    for (ci = 0; ci < baseNameLen; ci++) {
                        CHAR c = fnameLower[ci];
                        if (c >= 'a' && c <= 'z') hasAlpha = 1;
                        else if (c >= '0' && c <= '9') hasDigit = 1;
                        else hasOther = 1;  /* 下划线/连字符等 */
                    }
                    /* 字母+数字混合且无明显语义 = 随机文件名特征 */
                    if (hasAlpha && hasDigit && !hasOther) {
                        addIndicator(idx, BA_IND_FILE_TEMP_RANDOM_NAME_EXE,
                            "Random-named executable in temp/fake dir (SilverFox family trait)");
                    }
                }
            }
        }
    }
}

/* ── BehaviorExtractMemoryIndicators ── */
VOID BehaviorExtractMemoryIndicators(int idx, const BA_STORED_EVENT* ev)
{
    CHAR procLower[BA_MAX_NAME];
    CHAR srcLower[BA_MAX_PATH];  /* 必须用 BA_MAX_PATH：ev->imagePath 是15字符短名，
                                  * 需要从 g_baProcTree 获取完整路径才能匹配目录白名单 */
    int procLen;
    INT64 access;
    int hasCreateThrd, hasVMRead;
    int isLsassProc = 0;
    int i;
    int procIdx;

    if (idx < 0 || ev == NULL || ev->category != BA_EC_Memory) return;

    kStrLowerCopy(procLower, BA_MAX_NAME, ev->targetProcess);

    /* 优先使用进程树中的完整路径（与 extractIndicators/BehaviorExtractFileIndicators 一致），
     * ev->imagePath 仅为 PsGetProcessImageFileName 返回的15字符短名，
     * 无法匹配 \windowsapps\ 等目录白名单导致误报 */
    procIdx = findProc(ev->pid);
    if (procIdx >= 0 && g_baProcTree[procIdx].imagePath[0]) {
        kStrLowerCopy(srcLower, BA_MAX_PATH, g_baProcTree[procIdx].imagePath);
    } else {
        kStrLowerCopy(srcLower, BA_MAX_PATH, ev->imagePath);
    }
    procLen = kStrLen(procLower);
    access = ev->desiredAccess;

    /* isTargetSystemProcess 由 BehaviorRecordMemoryEvent 在锁外（PASSIVE_LEVEL）
     * 通过 IsSystemProcessByEPROCESS → SeQueryInformationToken 预计算。
     * SeQueryInformationToken 仅允许在 PASSIVE_LEVEL 调用。 */
    int isSysProc = ev->isTargetSystemProcess ? 1 : 0;

    /* lsass.exe 检测：PsLookupProcessByProcessId 安全于 DISPATCH_LEVEL */
    {
        PEPROCESS targetProc = NULL;
        if (ev->targetPid != 0 &&
            NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ev->targetPid, &targetProc)))
        {
            if (targetProc != NULL) {
                UCHAR* tgtName = PsGetProcessImageFileName(targetProc);
                if (tgtName) {
                    CHAR lowerName[32] = {0};
                    int ni;
                    for (ni = 0; ni < 15 && tgtName[ni]; ni++) {
                        CHAR c = (CHAR)tgtName[ni];
                        if (c >= 'A' && c <= 'Z') c += 32;
                        lowerName[ni] = c;
                    }
                    lowerName[ni] = '\0';
                    if (kStrCmp(lowerName, "lsass.exe") == 0)
                        isLsassProc = 1;
                }
                ObDereferenceObject(targetProc);
            }
        }
    }

    hasCreateThrd = (access & 0x0002) != 0;
    hasVMRead     = (access & 0x0010) != 0;

    /* ── #14: 进程枚举批量检测（进程发现 T1057）──
     * 统计 60 秒内同一源进程打开其他进程 PROCESS_QUERY_INFORMATION 句柄的次数。
     * 正常程序偶尔枚举进程，恶意软件在短时间内大量枚举（≥5 次）。
     * 仅对非系统进程、非受信任进程触发。 */
    if ((access & 0x0400) != 0 && /* PROCESS_QUERY_INFORMATION */
        ev->targetPid != ev->pid)
    {
        INT64 nowMs = baEtwTickMs();
        int enumCount = 1;
        int scanCnt = (g_baHistoryCount < 200) ? g_baHistoryCount : 200;
        int startI = (g_baHistoryHead - 1 + BA_MAX_HISTORY) % BA_MAX_HISTORY;
        int hi;
        for (hi = 0; hi < scanCnt; hi++) {
            int hIdx = (startI - hi + BA_MAX_HISTORY) % BA_MAX_HISTORY;
            BA_STORED_EVENT* hEv = &g_baHistory[hIdx];
            if (hEv->pid != ev->pid) continue;
            if (hEv->category != BA_EC_Memory) continue;
            if (hEv->targetPid == ev->pid) continue; /* 跳过自身 */
            if ((hEv->desiredAccess & 0x0400) == 0) continue; /* 仅统计 QUERY_INFO */
            if (nowMs - hEv->tick > 60000) break; /* 60 秒窗口 */
            enumCount++;
        }
        if (enumCount >= 5) {
            CHAR evBuf[128];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Batch process enumeration: %d processes queried in 60s", enumCount);
            addIndicator(idx, BA_IND_MEM_PROCESS_ENUM_BATCH, evBuf);
        }
    }

    /* ── #15: 自身打开 PROCESS_VM_OPERATION（shellcode RW→RX 前置 T1055）──
     * 进程对自身打开 PROCESS_VM_OPERATION 句柄，是 NtProtectVirtualMemory
     * 修改自身内存保护（RW→RX）的前置条件。正常程序极少这样做。
     * 仅对非系统进程、非受信任进程、来自可疑目录的进程触发。 */
    if (ev->targetPid == ev->pid &&
        (access & 0x0008) != 0 /* PROCESS_VM_OPERATION */)
    {
        CHAR imgPathLower[BA_MAX_PATH];
        kStrLowerCopy(imgPathLower, BA_MAX_PATH, ev->imagePath);
        int imgPLen = kStrLen(imgPathLower);
        /* 仅对来自可疑目录的进程触发 */
        if (kStrStrLen(imgPathLower, imgPLen, "\\temp\\", 6) ||
            kStrStrLen(imgPathLower, imgPLen, "\\desktop\\", 9) ||
            kStrStrLen(imgPathLower, imgPLen, "\\downloads\\", 11) ||
            kStrStrLen(imgPathLower, imgPLen, "\\appdata\\local\\temp\\", 21))
        {
            addIndicator(idx, BA_IND_MEM_SELF_VM_OPERATION_OPEN,
                "Self-open PROCESS_VM_OPERATION from suspicious directory (shellcode RW->RX prerequisite)");
        }
    }

    /* ── #16: DLL Load via ROP（调用栈含非镜像返回地址 T1055.001）──
     * 由 LoadImageNotifyRoutine 中的 DetectDllLoadViaRop 检测到后，
     * 通过 BehaviorRecordMemoryEvent(BA_MOP_DllLoadViaRop) 记录。
     * 此处提取指标并计入威胁画像。 */
    if (ev->memOp == BA_MOP_DllLoadViaRop)
    {
        CHAR evBuf[160];
        RtlStringCbPrintfA(evBuf, sizeof(evBuf),
            "DLL load via ROP: %s (return address in non-image memory)", ev->targetProcess);
        addIndicator(idx, BA_IND_IMG_LOAD_VIA_ROP, evBuf);
    }

    if (isSysProc &&
        (access & (0x0002 | 0x0008 | 0x0020 | 0x0040 | 0x0200 | 0x0800 | 0x0001)) != 0)
    {
        addIndicator(idx, BA_IND_MEM_OPEN_SYSTEM_PROCESS, "Open system process handle with suspicious access");
    }

    if (isLsassProc && hasVMRead) {
        addIndicator(idx, BA_IND_MEM_READ_LSASS, "Read LSASS process memory");
    }

    if (hasCreateThrd && isSysProc) {
        addIndicator(idx, BA_IND_MEM_OPEN_REMOTE_THREAD, "Create remote thread in system process");
    }

    /* 互签检测：当源进程和目标进程均为已签名进程时，跨进程操作属于
     * 正常进程间通信，不应视为注入行为。 */
    BOOLEAN mutuallySigned = ev->isSigned && ev->targetIsSigned;

    /* 跨进程内存写入检测 (T1055)：
     * 源PID == 目标PID 时说明是进程自操作，不是跨进程注入，跳过。
     * 父子进程间（父初始化子）的操作是正常进程创建行为，不是注入，跳过。
     * 互签进程间（双签名）的操作是正常 IPC，不是注入，跳过。
     * 注意：此处的"父子跳过"不适用于进程镂空（Process Hollowing），
     * 因为镂空本身就是父进程创建子进程后注入的模式，由下方独立检测。 */
    if ((access & 0x0020) && (access & 0x0008) && ev->pid != ev->targetPid && !ev->isParentChild && !mutuallySigned) {
        addIndicator(idx, BA_IND_MEM_CROSS_PROCESS_WRITE, "Cross-process memory write (VM_WRITE+VM_OPERATION)");

        if (hasCreateThrd) {
            addIndicator(idx, BA_IND_MEM_INJECTION_CHAIN, "Injection chain: cross-process write + remote thread");
        }
    }

    /* 进程镂空检测 (T1055.012)：独立于上述跨进程写入检测。
     * 镂空是父进程创建挂起子进程后注入攻击代码的特殊模式，必须发生在
     * 父子进程之间（ev->isParentChild == TRUE），与上述跨进程写入的
     * "父子跳过"逻辑不冲突——镂空是例外，需要单独检测。
     * 条件：父进程 + 写入权限 + 远程线程 + 读取权限 + 子进程创建后15秒内。 */
    if (ev->isParentChild && (access & 0x0020) && (access & 0x0008) &&
        hasCreateThrd && hasVMRead && ev->pid != ev->targetPid)
    {
        INT64 nowMs = baEtwTickMs();
        INT64 targetCreateMs = 0;
        int tgtIdx2 = findProc(ev->targetPid);
        if (tgtIdx2 >= 0) {
            targetCreateMs = g_baProcTree[tgtIdx2].createTickMs;
        }
        if (targetCreateMs != 0 && (nowMs - targetCreateMs) <= 15000) {
            addIndicator(idx, BA_IND_MEM_PROCESS_HOLLOWING, "Process hollowing: parent->child + write + thread + read (recently created)");
        }
    }

    if ((access & 0x0200) && !isSysProc) {
        addIndicator(idx, BA_IND_PROC_SET_CRITICAL, "Request PROCESS_SET_INFORMATION on remote process (potential critical flag set)");
    }

    if ((access & 0x0008) && !(access & 0x0020) && hasCreateThrd && !isSysProc) {
        addIndicator(idx, BA_IND_PROC_APC_INJECTION, "APC injection: VM_OPERATION + remote thread without VM_WRITE");
    }

    if ((access & 0x0008) && (access & 0x0040) && !(access & 0x0020)) {
        addIndicator(idx, BA_IND_PROC_MAP_SECTION, "Map section injection: VM_OPERATION + DUP_HANDLE without VM_WRITE");
    }

    /* 安全进程检测：必须同时满足目标进程名匹配 AND 访问掩码包含终止相关权限。
     * 仅凭目标进程名匹配就标记为"企图终止安全进程"是严重误报源。
     * 此修复与 extractIndicators 中的安全进程检测逻辑同步。 */
    {
        static const CHAR* secProcs[] = {
            "avp.exe", "kavfs", "msmpeng.exe", "ekrn.exe", "bdagent.exe",
            "360tray.exe", "hipsdaemon.exe", "zhudongfangyu.exe",
            "avastui.exe", "avgui.exe", "mbam.exe", "mbamservice.exe",
            "nissrv.exe", "sophosav.exe", "mcshield.exe", "fsdfwd.exe",
            "fssm32.exe", "pccntmon.exe", "tmproxy.exe", "nsmdtr.exe",
            "wrsa.exe", "csfalconservice.exe", "cb.exe", "cylancesvc.exe",
            "sentinelone", "trendmicro", "comodo", "clamav.exe", "bytefence.exe",
            "savservice.exe", "sophosfs.exe", "hitmanpro.exe", "emsisoft.exe"
        };
        BOOLEAN hasTerminateAccess = (access & 0x0001) != 0;  /* PROCESS_TERMINATE */
        BOOLEAN hasWriteAndOper = (access & 0x0020) && (access & 0x0008);  /* VM_WRITE + VM_OPERATION */
        BOOLEAN hasCreateAndOper = (access & 0x0002) && (access & 0x0008);  /* CREATE_THREAD + VM_OPERATION */
        BOOLEAN isAllAccess = (access == 0x1FFFFF) || (access == 0x1F0FFF);  /* PROCESS_ALL_ACCESS */
        if (hasTerminateAccess || (hasWriteAndOper && !isAllAccess) || (hasCreateAndOper && !isAllAccess)) {
            for (i = 0; i < 33; i++) {
                if (kStrStrLen(procLower, procLen, secProcs[i], kStrLen(secProcs[i]))) {
                    addIndicator(idx, BA_IND_PROC_KILL_SECURITY_PROCESS, "Attempt to terminate security process");
                    break;
                }
            }
        }
    }

    if (ev->memOp == BA_MOP_SetWindowsHookEx) {
        addIndicator(idx, BA_IND_PROC_KEYBOARD_HOOK, "Keyboard hook");
    }

    /* PoolParty 注入检测：源PID == 目标PID 时说明是进程自操作，不是注入。
     * 父子进程间（父初始化子）的操作是正常进程创建行为，不是 PoolParty 注入，跳过。
     * 互签进程间（双签名）的操作是正常 IPC，不是 PoolParty 注入，跳过。
     * Phase 4: 使用原子权限组合替代 8 个变体分类 */
    if (ev->pid != ev->targetPid && !ev->isParentChild && !mutuallySigned) {
        CHAR poolEvBuf[128];
        const CHAR* tgtName = ev->targetProcess[0] ? ev->targetProcess : "Unknown";
        if (ev->memOp == BA_MOP_VMWriteVMOperate) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.VMWriteVMOperate.T1055 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_VM_WRITE_VM_OPERATE, poolEvBuf);
        }
        else if (ev->memOp == BA_MOP_VMOperCreateThread) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.VMOperCreateThread.T1055 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_VM_OPER_CREATE_THREAD, poolEvBuf);
        }
        else if (ev->memOp == BA_MOP_VMOperDupHandle) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.VMOperDupHandle.T1055 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_VM_OPER_DUP_HANDLE, poolEvBuf);
        }
        else if (ev->memOp == BA_MOP_PoolParty_HandleRequest) {
            RtlStringCbPrintfA(poolEvBuf, sizeof(poolEvBuf),
                "DefenseEvasion/Injection:PoolParty.HandleRequest.0x0478 -> %s (PID=%lld)",
                tgtName, ev->targetPid);
            addIndicator(idx, BA_IND_MEM_POOLPARTY_HANDLE_REQUEST, poolEvBuf);
        }
    }

    if (ev->memOp == BA_MOP_RemoteAllocExecutable) {
        addIndicator(idx, BA_IND_MEM_ETW_REMOTE_ALLOC_EXECUTABLE,
            "Remote executable memory allocation (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_RemoteProtectExecutable) {
        addIndicator(idx, BA_IND_MEM_ETW_REMOTE_PROTECT_EXECUTABLE,
            "Remote memory protected to executable (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_RemoteWriteMemory) {
        addIndicator(idx, BA_IND_MEM_ETW_REMOTE_WRITE_MEMORY,
            "Remote virtual memory write (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_RemoteQueueApc) {
        addIndicator(idx, BA_IND_MEM_ETW_REMOTE_QUEUE_APC,
            "Remote APC insertion (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_RemoteSetThreadContext) {
        addIndicator(idx, BA_IND_MEM_ETW_REMOTE_SET_THREAD_CONTEXT,
            "Remote thread context manipulation (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_RemoteMapViewExecutable) {
        addIndicator(idx, BA_IND_MEM_ETW_REMOTE_MAP_VIEW_EXECUTABLE,
            "Remote executable section mapping (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_AllocToProtectChain) {
        addIndicator(idx, BA_IND_MEM_ETW_ALLOC_TO_PROTECT_CHAIN,
            "Shellcode pattern: RW alloc then RX/RWX protect (ETW TI)");
    }
    else if (ev->memOp == BA_MOP_WriteToProtectChain) {
        addIndicator(idx, BA_IND_MEM_ETW_WRITE_TO_PROTECT_CHAIN,
            "Shellcode pattern: write then RX/RWX protect (ETW TI)");
    }

    /* ── #17: 远程线程起始地址非镜像内存检测（shellcode 注入 T1055）──
     * 参考 Elastic Security shellcode thread 检测策略：
     * PsSetCreateThreadNotifyRoutine 回调中获取远程线程起始地址，
     * 通过 BehaviorCheckStartAddressUnbacked 检查是否落在非镜像可执行内存
     * （MEM_COMMIT + PAGE_EXECUTE_* + 非 MEM_IMAGE）。
     * 非镜像可执行内存中的线程起始地址 = shellcode 注入的强证据。 */
    if (ev->memOp == BA_MOP_RemoteThreadUnbacked &&
        ev->threadStartAddr != NULL)
    {
        CHAR evBuf[256];
        BOOLEAN isExec = FALSE;
        BOOLEAN unbackedExec = BehaviorCheckStartAddressUnbacked(
            ev->targetPid, ev->threadStartAddr, &isExec);

        if (unbackedExec)
        {
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "Remote thread start address 0x%p in unbacked executable memory (shellcode injection T1055)",
                ev->threadStartAddr);
            addIndicator(idx, BA_IND_MEM_THREAD_START_UNBACKED, evBuf);
        }
        else
        {
            DriverDbgPrint("[BA-MEM] Remote thread start address 0x%p: %s\n",
                ev->threadStartAddr,
                isExec ? "in loaded module (legitimate)" : "not executable or unknown");
        }
    }

    /* ── #18: 高风险父进程上下文加权（Office/脚本/LOLBin 发起注入操作）──
     * 参考 Elastic Security 规则：
     *   - Suspicious Process Creation CallTrace
     *   - Suspicious Process Access via Direct System Call
     * 当父进程是 Office/脚本引擎/浏览器/LOLBin 时，子进程的注入操作更可疑。
     * 此指标不单独触发告警，仅作为上下文加权。 */
    {
        int currentIdx = findProc(ev->pid);
        if (currentIdx >= 0 && g_baProcTree[currentIdx].parentPid != 0)
        {
            /* 查找父进程的进程树条目 */
            int parentTreeIdx = findProc(g_baProcTree[currentIdx].parentPid);
            if (parentTreeIdx >= 0 && g_baProcTree[parentTreeIdx].imagePath[0])
            {
                CHAR parentNameLower[BA_MAX_PATH];
                kStrLowerCopy(parentNameLower, BA_MAX_PATH,
                    g_baProcTree[parentTreeIdx].imagePath);
                if (kStrStr(parentNameLower, "winword.exe") ||
                    kStrStr(parentNameLower, "excel.exe") ||
                    kStrStr(parentNameLower, "outlook.exe") ||
                    kStrStr(parentNameLower, "powerpnt.exe") ||
                    kStrStr(parentNameLower, "cscript.exe") ||
                    kStrStr(parentNameLower, "wscript.exe") ||
                    kStrStr(parentNameLower, "rundll32.exe") ||
                    kStrStr(parentNameLower, "regsvr32.exe") ||
                    kStrStr(parentNameLower, "mshta.exe") ||
                    kStrStr(parentNameLower, "wmic.exe") ||
                    kStrStr(parentNameLower, "cmstp.exe") ||
                    kStrStr(parentNameLower, "msxsl.exe") ||
                    kStrStr(parentNameLower, "powershell.exe") ||
                    kStrStr(parentNameLower, "pwsh.exe") ||
                    kStrStr(parentNameLower, "msedge.exe") ||
                    kStrStr(parentNameLower, "chrome.exe") ||
                    kStrStr(parentNameLower, "firefox.exe") ||
                    kStrStr(parentNameLower, "explorer.exe"))
                {
                    addIndicator(idx, BA_IND_PROC_HIGH_RISK_PARENT,
                        "High-risk parent context: Office/script/LOLBin/browser");
                }
            }
        }
    }

    /* ── #19: 注入频率抑制（同一源进程短时间多次注入尝试）──
     * 参考 Elastic Security 策略：
     *   - Low Occurrence Rate of CreateRemoteThread by Source Process
     * 统计 60 秒内同一源进程的远程线程创建/跨进程写入次数，
     * 超过阈值（6 次）时记录频率抑制指标，辅助判定工具行为。 */
    if (ev->pid != ev->targetPid && /* 跨进程操作 */
        (ev->memOp == BA_MOP_HandleCreate || ev->memOp == BA_MOP_HandleDuplicate))
    {
        INT64 nowMs = baEtwTickMs();
        int injectCount = 1;
        int scanCnt = (g_baHistoryCount < 300) ? g_baHistoryCount : 300;
        int startI = (g_baHistoryHead - 1 + BA_MAX_HISTORY) % BA_MAX_HISTORY;
        int hi;
        for (hi = 0; hi < scanCnt; hi++) {
            int hIdx = (startI - hi + BA_MAX_HISTORY) % BA_MAX_HISTORY;
            BA_STORED_EVENT* hEv = &g_baHistory[hIdx];
            if (hEv->pid != ev->pid) continue;
            if (hEv->category != BA_EC_Memory) continue;
            if (hEv->pid == hEv->targetPid) continue; /* 跳过自身 */
            if (nowMs - hEv->tick > 60000) break; /* 60 秒窗口 */
            if (hEv->memOp == BA_MOP_HandleCreate || hEv->memOp == BA_MOP_HandleDuplicate)
                injectCount++;
        }
        if (injectCount >= 12) {
            CHAR evBuf[128];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "High injection frequency: %d cross-process handle operations in 60s", injectCount);
            addIndicator(idx, BA_IND_MEM_INJECTION_RATE_LIMIT, evBuf);
        }
    }
}

/* ── BehaviorExtractCrossCategoryIndicators ── */
VOID BehaviorExtractCrossCategoryIndicators(int idx, const BA_STORED_EVENT* ev)
{
    int imgLen;
    CHAR imgLower[BA_MAX_PATH];
    CHAR dirLower[BA_MAX_PATH];
    int dirLen;
    int procIdx;
    int i;

    if (idx < 0 || ev == NULL) return;

    procIdx = findProc(ev->pid);
    if (procIdx >= 0 && g_baProcTree[procIdx].imagePath[0]) {
        kStrLowerCopy(imgLower, BA_MAX_PATH, g_baProcTree[procIdx].imagePath);
    } else {
        kStrLowerCopy(imgLower, BA_MAX_PATH, ev->imagePath);
    }
    imgLen = kStrLen(imgLower);

    /* ── 子进程行为继承 (vssadmin, bcdedit) ── */
    {
        int isVssadmin = kStrIStrLen(imgLower, imgLen, "vssadmin.exe", 12);
        int isBcdedit   = kStrIStrLen(imgLower, imgLen, "bcdedit.exe", 11);
        if (isVssadmin || isBcdedit) {
            int isSuspiciousContext = 0;
            {
                if (procIdx >= 0) {
                    INT64 parentPid = g_baProcTree[procIdx].parentPid;
                    if (parentPid != 0) {
                        int parentIdx = findProc(parentPid);
                        if (parentIdx >= 0) {
                            CHAR parentLower[BA_MAX_PATH];
                            kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                            int parentLen = kStrLen(parentLower);
                            if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                                kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                                kStrStrLen(parentLower, parentLen, "\\appdata\\", 9)) {
                                isSuspiciousContext = 1;
                            }
                        }
                    }
                }
            }
            if (!kStrStrLen(imgLower, imgLen, "\\windows\\system32\\", 17) &&
                !kStrStrLen(imgLower, imgLen, "\\windows\\syswow64\\", 17)) {
                isSuspiciousContext = 1;
            }
            {
                if (procIdx >= 0) {
                    INT64 parentPid = g_baProcTree[procIdx].parentPid;
                    if (parentPid != 0) {
                        int parentIdx = findProc(parentPid);
                        if (parentIdx >= 0) {
                            if (IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                                isSuspiciousContext = 1;
                            }
                        }
                    }
                }
            }
            if (isSuspiciousContext) {
                if (isVssadmin) {
                    addIndicator(idx, BA_IND_PROC_VSSADMIN_SHADOW_DELETE, "vssadmin shadow delete (suspicious context)");
                }
                if (isBcdedit) {
                    addIndicator(idx, BA_IND_PROC_BCDEDIT_RECOVERY_DISABLE, "bcdedit recovery disable (suspicious context)");
                }
            }
        }
    }

    /* ── Winkiller 专用指标提取 ── */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Delete) {
        kStrLowerCopy(dirLower, BA_MAX_PATH, ev->fileDir);
        dirLen = kStrLen(dirLower);
        int isSystemDir = kStrStrLen(dirLower, dirLen, "\\windows\\system32", 17) || kStrStrLen(dirLower, dirLen, "\\windows\\syswow64", 17);
        if (isSystemDir) {
            addIndicator(idx, BA_IND_FILE_MASS_SYSTEM_DELETE, "Mass file deletion in system directory");
        }
    }

    if (ev->category == BA_EC_Registry &&
        (ev->regOp == BA_ROP_DeleteKey || ev->regOp == BA_ROP_DeleteValue) &&
        !isGenuineSystemProcess(procIdx, imgLower)) {
        addIndicator(idx, BA_IND_REG_MASS_DELETE, "Mass registry key/value deletion");
    }

    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Write) {
        int pathLen = kStrLen(ev->filePath);
        int isRawDisk = (kStrIStrLen(ev->filePath, pathLen, "physicaldrive", 13) ||
                         kStrIStrLen(ev->filePath, pathLen, "\\device\\harddisk", 16) ||
                         kStrIStrLen(ev->filePath, pathLen, "harddisk0", 9));
        if (isRawDisk) {
            int isSuspicious = (kStrIStrLen(imgLower, imgLen, "\\temp\\", 6) ||
                               kStrIStrLen(imgLower, imgLen, "\\downloads\\", 12) ||
                               kStrIStrLen(imgLower, imgLen, "\\appdata\\", 10) ||
                               kStrIStrLen(imgLower, imgLen, "\\desktop\\", 10));
            if (isSuspicious) {
                addIndicator(idx, BA_IND_FILE_BOOT_SECTOR, "Boot sector / physical disk access");
                if (kStrIStrLen(ev->filePath, pathLen, "physicaldrive", 13)) {
                    addIndicator(idx, BA_IND_DISK_MBR_WRITE, "MBR write attempt");
                }
            }
        }
    }

    if (ev->category == BA_EC_Memory) {
        static const CHAR* criticalProcs[] = {
            "csrss.exe", "wininit.exe", "smss.exe", "winlogon.exe",
            "services.exe", "lsass.exe", "svchost.exe"
        };
        INT64 access = ev->desiredAccess;
        int hasTerminate = (access & 0x0001) != 0;
        if (hasTerminate) {
            for (i = 0; i < 7; i++) {
                if (kStrCmp(imgLower, criticalProcs[i]) == 0) {
                    addIndicator(idx, BA_IND_PROC_CRITICAL_PROCESS_KILL, "Attempt to terminate critical system process");
                    break;
                }
            }
        }
    }

    /* Office app spawning cmd/powershell */
    if (ev->category == BA_EC_Process) {
        static const CHAR* officeApps[] = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "visio.exe", "publisher.exe"};
        int isOffice = 0;
        for (i = 0; i < 6; i++) {
            if (kStrIStrLen(imgLower, imgLen, officeApps[i], kStrLen(officeApps[i]))) {
                isOffice = 1;
                break;
            }
        }
        if (isOffice) {
            if (procIdx >= 0) {
                int ci;
                for (ci = 0; ci < g_baProcTree[procIdx].childCount; ci++) {
                    int childProcIdx = findProc(g_baProcTree[procIdx].childPids[ci]);
                    if (childProcIdx >= 0) {
                        CHAR childLower[BA_MAX_PATH];
                        kStrLowerCopy(childLower, BA_MAX_PATH, g_baProcTree[childProcIdx].imagePath);
                        int childLen = kStrLen(childLower);
                        if (kStrIStrLen(childLower, childLen, "cmd.exe", 7) ||
                            kStrIStrLen(childLower, childLen, "powershell.exe", 14) ||
                            kStrIStrLen(childLower, childLen, "wscript.exe", 11) ||
                            kStrIStrLen(childLower, childLen, "cscript.exe", 11) ||
                            kStrIStrLen(childLower, childLen, "mshta.exe", 9)) {
                            addIndicator(idx, BA_IND_OFFICE_SPAWN_CMD, "Office app spawning script interpreter");
                            break;
                        }
                    }
                }
            }
        }
    }

    /* certutil download pattern */
    if (ev->category == BA_EC_Process) {
        int isCertutil = kStrIStrLen(imgLower, imgLen, "certutil.exe", 12);
        if (isCertutil) {
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            kStrStrLen(parentLower, parentLen, "\\appdata\\", 9) ||
                            IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_CERTUTIL_DOWNLOAD, "certutil from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* bitsadmin transfer pattern */
    if (ev->category == BA_EC_Process) {
        int isBitsadmin = kStrIStrLen(imgLower, imgLen, "bitsadmin.exe", 13);
        if (isBitsadmin) {
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            kStrStrLen(parentLower, parentLen, "\\appdata\\", 9) ||
                            IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_BITSADMIN_TRANSFER, "bitsadmin from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* net.exe user manipulation */
    if (ev->category == BA_EC_Process) {
        int isNet = (kStrIStrLen(imgLower, imgLen, "net.exe", 7) ||
                     kStrIStrLen(imgLower, imgLen, "net1.exe", 8));
        if (isNet) {
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_NET_USER_MODIFY, "net.exe from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* svchost anomaly: wrong parent (not services.exe) */
    if (ev->category == BA_EC_Process) {
        int isSvchost = kStrIStrLen(imgLower, imgLen, "svchost.exe", 11);
        if (isSvchost) {
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (!kStrIStrLen(parentLower, parentLen, "services.exe", 12) &&
                            !kStrIStrLen(parentLower, parentLen, "svchost.exe", 11)) {
                            addIndicator(idx, BA_IND_SVCHOST_ANOMALY, "svchost.exe with anomalous parent");
                        }
                    }
                }
            }
        }
    }

    /* icacls permission modification from suspicious context */
    if (ev->category == BA_EC_Process) {
        int isIcacls = kStrIStrLen(imgLower, imgLen, "icacls.exe", 10);
        if (isIcacls) {
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        if (IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                            addIndicator(idx, BA_IND_ICACLS_MODIFY, "icacls from script interpreter");
                        }
                    }
                }
            }
        }
    }

    /* taskkill targeting security/system management tools（反取证行为）
     * 仅当 taskkill 目标为安全工具/系统管理工具时才触发指标，
     * 避免管理员正常使用 taskkill 产生的误报。
     * 通过解析命令行 /IM 参数获取目标进程名。 */
    if (ev->category == BA_EC_Process) {
        int isTaskkill = kStrIStrLen(imgLower, imgLen, "taskkill.exe", 12);
        if (isTaskkill && procIdx >= 0) {
            const CHAR* cmdLine = g_baProcTree[procIdx].commandLine;
            if (cmdLine != NULL && cmdLine[0] != '\0') {
                int cmdLen = kStrLen(cmdLine);
                /* 安全工具/系统管理工具目标列表 */
                static const CHAR* secTargets[] = {
                    "taskmgr.exe", "regedit.exe", "msconfig.exe", "procmon.exe",
                    "procexp.exe", "procexp64.exe", "autoruns.exe", "wireshark.exe",
                    "cmd.exe", "powershell.exe", "conhost.exe",
                    "360tray.exe", "360sd.exe", "zhudongfangyu.exe",
                    "msmpeng.exe", "msmpsvc.exe", "mpcmdrun.exe",
                    "avp.exe", "kavfs.exe", "avgsvc.exe", "avguard.exe",
                    "mcshield.exe", "tmlisten.exe", "bin.exe",
                    "hipstray.exe", "hipsdaemon.exe", "hipsmain.exe",
                    "wsctrl.exe", "usysdiag.exe",
                    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe"
                };
                int tki;
                for (tki = 0; tki < (int)(sizeof(secTargets) / sizeof(secTargets[0])); tki++) {
                    if (kStrIStrLen(cmdLine, cmdLen, secTargets[tki], kStrLen(secTargets[tki]))) {
                        CHAR evBuf[160];
                        RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                            "taskkill targeting security/system tool: %s", secTargets[tki]);
                        addIndicator(idx, BA_IND_PROC_TASKKILL_SECURITY_TOOL, evBuf);
                        /* 同时设置旧版指标，保持与历史威胁画像的兼容性 */
                        addIndicator(idx, BA_IND_TASKKILL_SECURITY, evBuf);
                        break;
                    }
                }
            }
        }
    }

    /* msiexec silent install from suspicious context */
    if (ev->category == BA_EC_Process) {
        int isMsiexec = kStrIStrLen(imgLower, imgLen, "msiexec.exe", 11);
        if (isMsiexec) {
            if (procIdx >= 0) {
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid != 0) {
                    int parentIdx = findProc(parentPid);
                    if (parentIdx >= 0) {
                        CHAR parentLower[BA_MAX_PATH];
                        kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                        int parentLen = kStrLen(parentLower);
                        if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                            kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                            kStrStrLen(parentLower, parentLen, "\\appdata\\", 9)) {
                            addIndicator(idx, BA_IND_MSIEXEC_SILENT_INSTALL, "msiexec from suspicious context");
                        }
                    }
                }
            }
        }
    }

    /* WMI persistence: writing to WMI repository */
    if (ev->category == BA_EC_File && ev->fileOp == BA_FOP_Write) {
        kStrLowerCopy(dirLower, BA_MAX_PATH, ev->fileDir);
        dirLen = kStrLen(dirLower);
        if (kStrStrLen(dirLower, dirLen, "wbem\\repository", 15) ||
            kStrStrLen(dirLower, dirLen, "wbem\\autorecovery", 17)) {
            if (!ev->isSigned) {
                addIndicator(idx, BA_IND_WMI_PERSISTENCE, "WMI repository modification");
            }
        }
    }

    /* ── ATT&CK 战术补充：进程/内存型检测（覆盖 0% 战术）── */

    /* T1134.001 Token Impersonation/Theft：OpenProcess(TOKEN_DUPLICATE) 系统进程
     * 令牌窃取链：恶意软件打开系统进程获取 TOKEN_DUPLICATE 权限以复制令牌提权。
     * 与 BA_IND_MEM_OPEN_SYSTEM_PROCESS 互补，但此处聚焦 TOKEN_DUPLICATE 权限位。 */
    if (ev->category == BA_EC_Memory)
    {
        INT64 access = ev->desiredAccess;
        /* TOKEN_DUPLICATE = 0x0002, TOKEN_ADJUST_PRIVILEGES = 0x0020, TOKEN_ASSIGN_PRIMARY = 0x0001 */
        int hasTokenDuplicate = (access & 0x0002) != 0;
        int hasTokenAdjustPriv = (access & 0x0020) != 0;
        int hasTokenAssignPrimary = (access & 0x0001) != 0;
        if ((hasTokenDuplicate || hasTokenAssignPrimary) &&
            (hasTokenAdjustPriv || (access & 0x000F) == 0x000F) &&
            ev->isTargetSystemProcess) {
            addIndicator(idx, BA_IND_MEM_TOKEN_IMPERSONATION,
                "Token impersonation: OpenProcess(TOKEN_DUPLICATE|ADJUST_PRIVILEGES) on system process");
        }
    }

    /* T1134.002 Create Process with Token：提权子进程 + 令牌操作链
     * 检测：进程创建事件中，子进程为 cmd.exe/powershell.exe 且父进程已有令牌操作指标。
     * 这表明父进程可能通过 CreateProcessAsUser/withToken 创建提权子进程。 */
    if (ev->category == BA_EC_Process && procIdx >= 0) {
        int isShellChild = (kStrIStrLen(imgLower, imgLen, "cmd.exe", 7) ||
                           kStrIStrLen(imgLower, imgLen, "powershell.exe", 14));
        if (isShellChild) {
            INT64 parentPid = g_baProcTree[procIdx].parentPid;
            if (parentPid != 0) {
                int parentIdx = findProc(parentPid);
                if (parentIdx >= 0) {
                    int parentIndIdx = findPidIndex(parentPid);
                    if (parentIndIdx >= 0) {
                        /* 检查父进程是否已有令牌窃取或系统进程打开指标 */
                        if (g_baPidIndicators[parentIndIdx][BA_IND_MEM_TOKEN_IMPERSONATION] > 0 ||
                            g_baPidIndicators[parentIndIdx][BA_IND_MEM_OPEN_SYSTEM_PROCESS] > 0 ||
                            g_baPidIndicators[parentIndIdx][BA_IND_SYSCALL_TOKEN_STEAL_CHAIN] > 0) {
                            CHAR parentLower[BA_MAX_PATH];
                            int parentLen;
                            kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                            parentLen = kStrLen(parentLower);
                            /* 排除 services.exe/wininit.exe 等合法系统父进程 */
                            if (!kStrIStrLen(parentLower, parentLen, "services.exe", 12) &&
                                !kStrIStrLen(parentLower, parentLen, "wininit.exe", 11) &&
                                !kStrIStrLen(parentLower, parentLen, "svchost.exe", 11) &&
                                !isGenuineSystemProcess(parentIdx, parentLower)) {
                                addIndicator(idx, BA_IND_PROC_CREATE_WITH_TOKEN,
                                    "CreateProcess with token: shell child spawned after token manipulation");
                            }
                        }
                    }
                }
            }
        }
    }

    /* T1087 账户发现：net.exe user/group/localgroup + whoami 从可疑上下文
     * 与 BA_IND_NET_USER_MODIFY 互补：NET_USER_MODIFY 仅检测 user add/delete，
     * 此处检测 user/group/localgroup 查询（只读枚举）与 whoami 调用。 */
    if (ev->category == BA_EC_Process && procIdx >= 0) {
        int isNet = (kStrIStrLen(imgLower, imgLen, "net.exe", 7) ||
                     kStrIStrLen(imgLower, imgLen, "net1.exe", 8));
        int isWhoami = kStrIStrLen(imgLower, imgLen, "whoami.exe", 10);
        if (isNet || isWhoami) {
            INT64 parentPid = g_baProcTree[procIdx].parentPid;
            if (parentPid != 0) {
                int parentIdx = findProc(parentPid);
                if (parentIdx >= 0) {
                    CHAR parentLower[BA_MAX_PATH];
                    int parentLen;
                    kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                    parentLen = kStrLen(parentLower);
                    if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                        kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                        kStrStrLen(parentLower, parentLen, "\\appdata\\", 9) ||
                        IsScriptInterpreter(g_baProcTree[parentIdx].imagePath)) {
                        if (isNet) {
                            /* 检查命令行是否包含枚举子命令（user/group/localgroup/view） */
                            const CHAR* cmdLine = g_baProcTree[procIdx].commandLine;
                            if (cmdLine != NULL && cmdLine[0] != '\0') {
                                int cmdLen = kStrLen(cmdLine);
                                if (kStrIStrLen(cmdLine, cmdLen, " user", 5) ||
                                    kStrIStrLen(cmdLine, cmdLen, " group", 6) ||
                                    kStrIStrLen(cmdLine, cmdLen, " localgroup", 11) ||
                                    kStrIStrLen(cmdLine, cmdLen, " view", 5) ||
                                    kStrIStrLen(cmdLine, cmdLen, " accounts", 9)) {
                                    addIndicator(idx, BA_IND_PROC_ACCOUNT_DISCOVERY,
                                        "net.exe account enumeration from suspicious context");
                                }
                            }
                        }
                        if (isWhoami) {
                            addIndicator(idx, BA_IND_PROC_ACCOUNT_DISCOVERY,
                                "whoami.exe from suspicious context (account discovery)");
                        }
                    }
                }
            }
        }
    }

    /* T1529 系统关机/重启：shutdown.exe /s /r /t 0 /f
     * 恶意软件通过关机/重启中断取证或造成影响。
     * 仅从可疑上下文（temp/appdata/脚本父进程）触发的 shutdown 才告警。 */
    if (ev->category == BA_EC_Process && procIdx >= 0) {
        int isShutdown = kStrIStrLen(imgLower, imgLen, "shutdown.exe", 12);
        if (isShutdown) {
            INT64 parentPid = g_baProcTree[procIdx].parentPid;
            if (parentPid != 0) {
                int parentIdx = findProc(parentPid);
                if (parentIdx >= 0) {
                    CHAR parentLower[BA_MAX_PATH];
                    int parentLen;
                    kStrLowerCopy(parentLower, BA_MAX_PATH, g_baProcTree[parentIdx].imagePath);
                    parentLen = kStrLen(parentLower);
                    if (kStrStrLen(parentLower, parentLen, "\\temp\\", 6) ||
                        kStrStrLen(parentLower, parentLen, "\\downloads\\", 11) ||
                        kStrStrLen(parentLower, parentLen, "\\appdata\\", 9) ||
                        IsScriptInterpreter(g_baProcTree[parentIdx].imagePath) ||
                        !isGenuineSystemProcess(parentIdx, parentLower)) {
                        const CHAR* cmdLine = g_baProcTree[procIdx].commandLine;
                        if (cmdLine != NULL && cmdLine[0] != '\0') {
                            int cmdLen = kStrLen(cmdLine);
                            /* /s (关机), /r (重启), /t 0 (无延迟), /f (强制) */
                            if (kStrIStrLen(cmdLine, cmdLen, " /s", 3) ||
                                kStrIStrLen(cmdLine, cmdLen, " /r", 3) ||
                                kStrIStrLen(cmdLine, cmdLen, "-s", 2) ||
                                kStrIStrLen(cmdLine, cmdLen, "-r", 2)) {
                                addIndicator(idx, BA_IND_PROC_SYSTEM_SHUTDOWN,
                                    "shutdown.exe /s or /r from suspicious context");
                            }
                        }
                    }
                }
            }
        }
    }
}

static VOID collectChildIndicators(INT64 pid, DOUBLE* combined, int* distinctCnt,
                                    int* visited, int* visitedCnt)
{
    int pidx, vi, ci;
    INT64 childPid;
    int childIdx, i, cnt;

    pidx = findProc(pid);
    if (pidx < 0) return;

    for (vi = 0; vi < *visitedCnt; vi++) {
        if (visited[vi] == pidx) return;
    }
    if (*visitedCnt < BA_MAX_PROCESSES) visited[(*visitedCnt)++] = pidx;

    for (ci = 0; ci < g_baProcTree[pidx].childCount; ci++) {
        childPid = g_baProcTree[pidx].childPids[ci];
        childIdx = findPidIndex(childPid);
        if (childIdx >= 0) {
            KFLOATING_SAVE floatSave;
            NTSTATUS floatStatus = KeSaveFloatingPointState(&floatSave);
            if (!NT_SUCCESS(floatStatus)) continue;
            __try {
                for (i = 0; i < BA_MAX_INDICATORS; i++) {
                    cnt = g_baPidIndicators[childIdx][i];
                    if (cnt > 0 && combined[i] == 0.0) {
                        combined[i] = BehaviorGetIndicatorBaseScore((BA_INDICATOR)i) * (cnt > 2 ? 2.0 : (DOUBLE)cnt);
                        (*distinctCnt)++;
                    }
                }
            } __finally {
                KeRestoreFloatingPointState(&floatSave);
            }
        }
        collectChildIndicators(childPid, combined, distinctCnt, visited, visitedCnt);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 清理已退出进程
 * ══════════════════════════════════════════════════════════════════════════ */

static VOID cleanupStalePids(VOID)
{
    int i, newCount = 0;
    int j;
    for (i = 0; i < g_baIndicatorCount; i++) {
        INT64 pid = g_baIndicatorPids[i];
        if (findProc(pid) >= 0) {
            g_baIndicatorPids[newCount] = pid;
            if (newCount != i) {
                for (j = 0; j < BA_MAX_INDICATORS; j++) {
                    g_baPidIndicators[newCount][j] = g_baPidIndicators[i][j];
                    g_baPidIndicators[i][j] = 0;
                }
                g_baEvidence[newCount] = g_baEvidence[i];
                g_baEvidence[i].count = 0;
            }
            newCount++;
        }
    }
    g_baIndicatorCount = newCount;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 公开 API
 * ══════════════════════════════════════════════════════════════════════════ */

VOID BehaviorAnalysisInit()
{
    KIRQL oldIrql = 0;

    if (g_baInitialized) return;

    KeInitializeSpinLock(&g_baLock);
    KeInitializeSpinLock(&g_baEtwAllocCacheLock);
    KeInitializeSpinLock(&g_baEtwWriteCacheLock);
    KeInitializeSpinLock(&g_baEtwAlertCooldownLock);
    KeInitializeSpinLock(&g_baRuleStatsLock);
    KeInitializeSpinLock(&g_baBaselineLock);
    KeInitializeSpinLock(&g_baSigCacheLock);
    RtlZeroMemory(g_baEtwAllocCache, sizeof(g_baEtwAllocCache));
    RtlZeroMemory(g_baEtwWriteCache, sizeof(g_baEtwWriteCache));
    RtlZeroMemory(g_baEtwAlertCooldown, sizeof(g_baEtwAlertCooldown));
    RtlZeroMemory(g_baSigCache, sizeof(g_baSigCache));
    RtlZeroMemory(g_baRuleStats, sizeof(g_baRuleStats));
    RtlZeroMemory(g_baBaselines, sizeof(g_baBaselines));

    /* 初始化误报缓解全局状态 */
    KeInitializeSpinLock(&g_baWhitelistLock);
    KeInitializeSpinLock(&g_baExceptionLock);
    KeInitializeSpinLock(&g_baTrustedProducerLock);
    KeInitializeSpinLock(&g_baSignedProducerLock);
    KeInitializeSpinLock(&g_baSuppressionLock);
    KeInitializeSpinLock(&g_baReputationLock);
    KeInitializeSpinLock(&g_baEvidenceQualityLock);
    KeInitializeSpinLock(&g_baLookbackWindowLock);
    RtlZeroMemory(g_baWhitelist, sizeof(g_baWhitelist));
    RtlZeroMemory(g_baExceptions, sizeof(g_baExceptions));
    RtlZeroMemory(g_baTrustedProducers, sizeof(g_baTrustedProducers));
    RtlZeroMemory(g_baSignedProducers, sizeof(g_baSignedProducers));
    RtlZeroMemory(g_baSuppressions, sizeof(g_baSuppressions));
    RtlZeroMemory(g_baReputations, sizeof(g_baReputations));
    RtlZeroMemory(g_baEvidenceQuality, sizeof(g_baEvidenceQuality));
    RtlZeroMemory(g_baLookbackWindows, sizeof(g_baLookbackWindows));
    g_baWhitelistCount = 0;
    g_baExceptionCount = 0;
    g_baTrustedProducerCount = 0;
    g_baSignedProducerCount = 0;
    g_baSuppressionCount = 0;
    g_baReputationCount = 0;
    g_baEvidenceQualityInitialized = FALSE;
    g_baLookbackWindowCount = 0;

    KeAcquireSpinLock(&g_baLock, &oldIrql);
    RtlZeroMemory(g_baHistory, sizeof(g_baHistory));
    RtlZeroMemory(g_baProcTree, sizeof(g_baProcTree));
    RtlZeroMemory(g_baIndicatorPids, sizeof(g_baIndicatorPids));
    RtlZeroMemory(g_baPidIndicators, sizeof(g_baPidIndicators));
    RtlZeroMemory(g_baPidSyscallTypes, sizeof(g_baPidSyscallTypes));
    RtlZeroMemory(g_baEvidence, sizeof(g_baEvidence));
    g_baTickCounter = 0;
    g_baHistoryHead = 0;
    g_baHistoryCount = 0;
    g_baProcCount = 0;
    g_baIndicatorCount = 0;
    g_baInitialized = TRUE;
    /* 行为检测默认禁用，需用户显式开启 */
    g_bBehaviorDetectionEnabled = FALSE;
    KeReleaseSpinLock(&g_baLock, oldIrql);

    /* 初始化文件释放跟踪（堆分配） */
    KeInitializeSpinLock(&g_baDroppedFileLock);
    if (g_baDroppedFiles == NULL) {
        g_baDroppedFiles = (BA_DROPPED_FILE*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(BA_DROPPED_FILE) * BA_MAX_DROPPED_FILES, 'baDF');
    }
    if (g_baDroppedFiles != NULL)
        RtlZeroMemory(g_baDroppedFiles, sizeof(BA_DROPPED_FILE) * BA_MAX_DROPPED_FILES);
    g_baDroppedFileIdx = 0;

    /* 初始化注册表操作回滚跟踪（堆分配） */
    KeInitializeSpinLock(&g_baRegOpLock);
    if (g_baRegOps == NULL) {
        g_baRegOps = (BA_REG_OP_RECORD*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(BA_REG_OP_RECORD) * BA_MAX_REG_OPS, 'baRO');
    }
    if (g_baRegOps != NULL)
        RtlZeroMemory(g_baRegOps, sizeof(BA_REG_OP_RECORD) * BA_MAX_REG_OPS);
    g_baRegOpIdx = 0;
    g_regDriverAccessDepth = 0;

    /* 动态解析内核 API */
    ResolveBehaviorApis();

    BehaviorLogInfo("Initialized, rule version=%lu", g_baRuleVersion);
}

/* ── BehaviorSetDetectionEnabled: 用户态开关控制行为检测总开关 ── */
VOID BehaviorSetDetectionEnabled(BOOLEAN enabled)
{
    g_bBehaviorDetectionEnabled = enabled ? TRUE : FALSE;
    DriverDbgPrint("[BA-CTRL] Behavior detection %s\n",
        g_bBehaviorDetectionEnabled ? "ENABLED" : "DISABLED");
}

/* ── EnumerateExistingProcesses: 驱动加载时枚举已有进程，补充进程树 ──
 * ProcessCreateNotifyRoutine 只能捕获新进程，已在运行的进程不会被回调。
 * 本函数遍历所有 PID，获取完整路径并加入进程树，解决路径 Unknown 问题。 */
static VOID EnumerateExistingProcesses(VOID)
{
    INT64 pid;
    PEPROCESS process = NULL;
    int count = 0;

    /* 遍历 PID 空间（Windows PID 为 4 的倍数，最大约 65536） */
    for (pid = 4; pid < 0x10000; pid += 4) {
        HANDLE hProcess = NULL;
        PUNICODE_STRING imagePathInfo = NULL;
        BOOLEAN processHeld = FALSE;

        __try {
            if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process)))
                continue;
            processHeld = TRUE;

            /* 通过 ObOpenObjectByPointer 获取内核句柄，ZwQueryInformationProcess 需要 HANDLE */
            {
                /* 需要 PROCESS_QUERY_LIMITED_INFORMATION 才能查询 ProcessImageFileName，
                 * 访问权限为 0 会导致 ZwQueryInformationProcess 返回 STATUS_ACCESS_DENIED，
                 * 从而回退到 PsGetProcessImageFileName 短名，造成告警中进程路径截断。 */
                NTSTATUS obStatus = ObOpenObjectByPointer(
                    process, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProcess);
                ObDereferenceObject(process);
                processHeld = FALSE;
                if (!NT_SUCCESS(obStatus)) continue;
            }

            {
                CHAR fullPath[BA_MAX_PATH] = {0};
                INT64 parentPid = 0;
                ULONG returnLength;

                /* 获取父进程 PID（ProcessBasicInformation）*/
                {
                    PROCESS_BASIC_INFORMATION pbi;
                    RtlZeroMemory(&pbi, sizeof(pbi));
                    if (NT_SUCCESS(ZwQueryInformationProcess(
                            hProcess, ProcessBasicInformation,
                            &pbi, sizeof(pbi), &returnLength))) {
                        parentPid = (INT64)pbi.InheritedFromUniqueProcessId;
                    }
                }

                NTSTATUS queryStatus = ZwQueryInformationProcess(
                    hProcess, ProcessImageFileName, NULL, 0, &returnLength);
                if (!NT_SUCCESS(queryStatus) && returnLength > 0) {
                    imagePathInfo = (PUNICODE_STRING)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, returnLength, 'HtP');
                    if (imagePathInfo) {
                        queryStatus = ZwQueryInformationProcess(
                            hProcess, ProcessImageFileName,
                            imagePathInfo, returnLength, &returnLength);
                        if (NT_SUCCESS(queryStatus) && imagePathInfo->Buffer) {
                            int wlen = (int)(imagePathInfo->Length / sizeof(WCHAR));
                            if (wlen >= BA_MAX_PATH) wlen = BA_MAX_PATH - 1;
                            int i;
                            /* 直接截取低字节，不用 & 0x7F（会丢失非ASCII字符高位导致乱码） */
                            for (i = 0; i < wlen; i++)
                                fullPath[i] = (CHAR)imagePathInfo->Buffer[i];
                            fullPath[wlen] = '\0';
                        }
                    }
                }

                /* 后备：短名
                 * 注意：process 引用已在 ObOpenObjectByPointer 之后释放，
                 * 必须重新 PsLookupProcessByProcessId 才能安全使用 PsGetProcessImageFileName */
                if (fullPath[0] == '\0') {
                    PEPROCESS procForShortName = NULL;
                    if (NT_SUCCESS(PsLookupProcessByProcessId(
                            (HANDLE)(ULONG_PTR)pid, &procForShortName))) {
                        UCHAR* imageName = PsGetProcessImageFileName(procForShortName);
                        if (imageName) {
                            int i;
                            /* PsGetProcessImageFileName 最多15字符，可能无null终止符 */
                            for (i = 0; i < 15 && imageName[i]; i++)
                                fullPath[i] = (CHAR)imageName[i];
                            fullPath[i] = '\0';
                        }
                        ObDereferenceObject(procForShortName);
                    }
                }

                if (fullPath[0] != '\0') {
                    BehaviorRecordProcessCreate(pid, parentPid, fullPath, NULL);
                    count++;
                }
            }
        } __finally {
            if (imagePathInfo != NULL) {
                ExFreePool(imagePathInfo);
            }
            if (hProcess != NULL) {
                ZwClose(hProcess);
            }
            if (processHeld) {
                ObDereferenceObject(process);
            }
        }
    }

    DriverDbgPrint("BehaviorAnalysis: Enumerated %d existing processes\n", count);
}

VOID BehaviorAnalysisCleanup()
{
    KIRQL oldIrql = 0;

    if (!g_baInitialized) return;

    KeAcquireSpinLock(&g_baLock, &oldIrql);
    RtlZeroMemory(g_baHistory, sizeof(g_baHistory));
    RtlZeroMemory(g_baProcTree, sizeof(g_baProcTree));
    RtlZeroMemory(g_baIndicatorPids, sizeof(g_baIndicatorPids));
    RtlZeroMemory(g_baPidIndicators, sizeof(g_baPidIndicators));
    RtlZeroMemory(g_baPidSyscallTypes, sizeof(g_baPidSyscallTypes));
    RtlZeroMemory(g_baEvidence, sizeof(g_baEvidence));
    g_baTickCounter = 0;
    g_baHistoryHead = 0;
    g_baHistoryCount = 0;
    g_baProcCount = 0;
    g_baIndicatorCount = 0;
    g_baAlertedCount = 0;
    g_baInitialized = FALSE;
    KeReleaseSpinLock(&g_baLock, oldIrql);

    /* Clear dropped files tracking（堆分配，直接释放） */
    {
        KIRQL oldIrql2;
        KeAcquireSpinLock(&g_baDroppedFileLock, &oldIrql2);
        if (g_baDroppedFiles != NULL) {
            ExFreePoolWithTag(g_baDroppedFiles, 'baDF');
            g_baDroppedFiles = NULL;
        }
        g_baDroppedFileIdx = 0;
        KeReleaseSpinLock(&g_baDroppedFileLock, oldIrql2);
    }

    /* Clear registry rollback tracking（堆分配，直接释放） */
    {
        KIRQL oldIrql2;
        KeAcquireSpinLock(&g_baRegOpLock, &oldIrql2);
        if (g_baRegOps != NULL) {
            ExFreePoolWithTag(g_baRegOps, 'baRO');
            g_baRegOps = NULL;
        }
        g_baRegOpIdx = 0;
        KeReleaseSpinLock(&g_baRegOpLock, oldIrql2);
    }

    DriverDbgPrint("BehaviorAnalysis: Cleaned up\n");
}

VOID BehaviorRecordProcessCreate(INT64 pid, INT64 parentPid, const CHAR* imagePath, const CHAR* commandLine)
{
    KIRQL oldIrql = 0;
    int idx;
    BOOLEAN isSystemSid = FALSE;

    if (imagePath == NULL)
        return;

    if (!g_baInitialized) return;

    /* 在锁外（PASSIVE_LEVEL）查询进程是否运行在 SYSTEM SID 下。
     * 此信息用于后续 isGenuineSystemProcess() 判定，区分真正系统进程与冒名病毒。
     * 病毒可命名为 consent.exe 并投放至 System32，但无法以 SYSTEM 身份运行。 */
    {
        PEPROCESS proc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc)) && proc != NULL) {
            isSystemSid = IsSystemProcessByEPROCESS(proc);
            ObDereferenceObject(proc);
        }
    }

    KeAcquireSpinLock(&g_baLock, &oldIrql);

    idx = findOrCreateProc(pid);
    if (idx >= 0) {
        kStrCpy(g_baProcTree[idx].imagePath, BA_MAX_PATH, imagePath);
        g_baProcTree[idx].parentPid = parentPid;
        g_baProcTree[idx].createTickMs = baEtwTickMs();
        g_baProcTree[idx].isSystemSidProcess = isSystemSid;

        /* 存储命令行（可为 NULL），用于 taskkill 目标检测等 */
        if (commandLine != NULL && commandLine[0] != '\0') {
            kStrCpy(g_baProcTree[idx].commandLine, BA_MAX_CMDLINE, commandLine);
        } else {
            g_baProcTree[idx].commandLine[0] = '\0';
        }

        /* 建立父子关系 */
        if (parentPid != 0) {
            int pidx = findProc(parentPid);
            if (pidx >= 0 && g_baProcTree[pidx].childCount < BA_MAX_CHILDREN) {
                g_baProcTree[pidx].childPids[g_baProcTree[pidx].childCount++] = pid;
            }
        }
    }

    KeReleaseSpinLock(&g_baLock, oldIrql);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 无签名脚本宿主独立检测通道
 * ═══════════════════════════════════════════════════════════════════════════ */

// 大小写不敏感字符串比较（ANSI）
static BOOLEAN CompareNoCase(const CHAR* a, const CHAR* b)
{
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return FALSE;
        a++;
        b++;
    }
    return (*a == *b);
}

// 前向声明（实际定义在本文件后面）
static void SuspendProcessTree(INT64* treePids, int treePidCount);
static void ResumeProcessTree(INT64* treePids, int treePidCount);
static void TerminateProcessTree(INT64* treePids, int treePidCount);

// 脚本宿主可执行文件名（短名，用于快速匹配）
static BOOLEAN IsScriptHostImageName(const CHAR* imageName)
{
    if (imageName == NULL || imageName[0] == '\0')
        return FALSE;

    const CHAR* scriptHosts[] = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe",
        "cscript.exe", "wscript.exe", "msbuild.exe", "dotnet.exe"
    };
    int count = sizeof(scriptHosts) / sizeof(scriptHosts[0]);

    for (int i = 0; i < count; i++) {
        if (CompareNoCase(imageName, scriptHosts[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

// 检查路径是否在系统目录（短名匹配）
static BOOLEAN IsSystemDirectoryPathA(const CHAR* imagePath)
{
    if (imagePath == NULL || imagePath[0] == '\0')
        return FALSE;

    // 转换为小写比较
    CHAR lowerPath[BA_MAX_PATH];
    int i;
    for (i = 0; i < BA_MAX_PATH - 1 && imagePath[i]; i++) {
        lowerPath[i] = (CHAR)tolower((unsigned char)imagePath[i]);
    }
    lowerPath[i] = '\0';

    // 检查是否在 System32 或 SysWOW64
    if (strstr(lowerPath, "\\system32\\") != NULL)
        return TRUE;
    if (strstr(lowerPath, "\\syswow64\\") != NULL)
        return TRUE;
    if (strstr(lowerPath, "\\windows\\") != NULL)
        return TRUE;

    return FALSE;
}

// 检查父进程是否是系统进程（通过 SID）
static BOOLEAN IsParentSystemProcess(INT64 parentPid)
{
    if (parentPid <= 0)
        return FALSE;

    PEPROCESS parentProc = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)parentPid, &parentProc)))
        return FALSE;

    BOOLEAN isSystem = IsSystemProcessByEPROCESS(parentProc);
    ObDereferenceObject(parentProc);
    return isSystem;
}

// 无签名脚本宿主告警 work item 上下文
typedef struct _UNSIGNED_SCRIPT_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    INT64 pid;
    INT64 parentPid;
    CHAR imagePath[BA_MAX_PATH];
    CHAR imageName[64];
    CHAR threatClass[128];
    CHAR description[256];
} UNSIGNED_SCRIPT_WORKITEM_CTX, *PUNSIGNED_SCRIPT_WORKITEM_CTX;

// 无签名脚本宿主告警 work item 回调（在系统线程中执行）
static VOID UnsignedScriptAlertWorkItemRoutine(PVOID Context)
{
    PUNSIGNED_SCRIPT_WORKITEM_CTX ctx = (PUNSIGNED_SCRIPT_WORKITEM_CTX)Context;
    INT64 treePids[BA_MAX_TREE_PIDS];
    int treePidCount = 0;

    if (ctx == NULL) return;

    __try {
        DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Unsigned script host alert work item started for PID=%lld Name=%s\n",
            ctx->pid, ctx->imageName);

        /* 收集进程树 PID */
        {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_baLock, &oldIrql);
            int idx = findProc(ctx->pid);
            if (idx >= 0) {
                treePids[0] = ctx->pid;
                treePidCount = 1;
                for (int i = 0; i < g_baProcTree[idx].childCount && treePidCount < BA_MAX_TREE_PIDS; i++) {
                    treePids[treePidCount++] = g_baProcTree[idx].childPids[i];
                }
            }
            KeReleaseSpinLock(&g_baLock, oldIrql);
        }

        /* 检查是否包含系统进程 */
        BOOLEAN hasSystemProc = FALSE;
        for (int i = 0; i < treePidCount; i++) {
            KIRQL oldIrql;
            KeAcquireSpinLock(&g_baLock, &oldIrql);
            int idx = findProc(treePids[i]);
            if (idx >= 0 && g_baProcTree[idx].isSystemSidProcess) {
                hasSystemProc = TRUE;
            }
            KeReleaseSpinLock(&g_baLock, oldIrql);
            if (hasSystemProc) break;
        }

        if (hasSystemProc) {
            DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Skipping: system process in tree (PID=%lld)\n", ctx->pid);
            goto Cleanup;
        }

        /* 步骤1: 挂起进程树 */
        SuspendProcessTree(treePids, treePidCount);

        /* 用户态可见日志 */
        {
            CHAR suspLogMsg[400];
            RtlStringCbPrintfA(suspLogMsg, sizeof(suspLogMsg),
                "[无签名脚本宿主-挂起] 检测到无签名脚本宿主已挂起进程树: 根PID=%lld 名称=%s 威胁=%s",
                ctx->pid, ctx->imageName, ctx->threatClass);
            SendInjectionLog(suspLogMsg);
        }

        /* 步骤2: 弹窗等待用户决策 */
        NTSTATUS userResponse = AskClientForBehaviorResponse(
            (INT)ctx->pid,
            ctx->imagePath,
            ctx->threatClass,
            ctx->description,
            0.85,  // 高置信度（无签名 + 非系统父进程）
            NULL);

        DriverDbgPrint("[BA-UNSIGNED-SCRIPT] User response for PID=%lld: 0x%X (%s)\n",
            ctx->pid, userResponse,
            (userResponse == STATUS_ACCESS_DENIED) ? "BLOCK" : "ALLOW");

        /* 步骤3: 根据用户决策执行 BLOCK 或 ALLOW */
        if (userResponse == STATUS_ACCESS_DENIED)
        {
            /* 用户态可见日志：用户选择阻止，正在终止进程树 */
            {
                CHAR blockLogMsg[400];
                RtlStringCbPrintfA(blockLogMsg, sizeof(blockLogMsg),
                    "[无签名脚本宿主-阻止] 用户选择阻止，正在终止进程树: 根PID=%lld 名称=%s",
                    ctx->pid, ctx->imageName);
                SendInjectionLog(blockLogMsg);
            }

            /* BLOCK: 终止进程树 */
            TerminateProcessTree(treePids, treePidCount);
        }
        else
        {
            /* 用户态可见日志：用户选择放行，正在恢复进程树 */
            {
                CHAR allowLogMsg[400];
                RtlStringCbPrintfA(allowLogMsg, sizeof(allowLogMsg),
                    "[无签名脚本宿主-放行] 用户选择放行，正在恢复进程树: 根PID=%lld 名称=%s",
                    ctx->pid, ctx->imageName);
                SendInjectionLog(allowLogMsg);
            }

            /* ALLOW: 恢复进程树 */
            ResumeProcessTree(treePids, treePidCount);
        }

        DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Unsigned script host alert work item completed for PID=%lld\n", ctx->pid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Exception caught in UnsignedScriptAlertWorkItemRoutine for PID=%lld\n",
            ctx ? ctx->pid : 0);

        /* 异常路径恢复进程树 */
        if (ctx != NULL && treePidCount > 0) {
            ResumeProcessTree(treePids, treePidCount);
        }
    }

Cleanup:
    if (ctx != NULL) {
        ExFreePool(ctx);
    }
}

/* ── BehaviorCheckUnsignedScriptHost: 无签名脚本宿主独立检测通道 ──
 * 触发条件：
 *   1. 进程名是脚本宿主（cmd/powershell/cscript/wscript/mshta/dotnet/pwsh）
 *   2. 进程路径不在系统目录（非官方签名版本）
 *   3. 父进程不是系统进程（非系统/服务启动）
 * 检测策略：
 *   - 独立通道，不依赖现有行为分析引擎的阈值
 *   - 降低阈值，更激进地检测威胁
 *   - 发现威胁后立即 suspend 进程树并发送通知
 */
VOID BehaviorCheckUnsignedScriptHost(INT64 pid, INT64 parentPid, const CHAR* imagePath)
{
    UNSIGNED_SCRIPT_WORKITEM_CTX* ctx = NULL;
    CHAR imageName[64] = {0};
    int i;

    if (imagePath == NULL || imagePath[0] == '\0')
        return;

    if (!g_baInitialized) return;

    /* 白名单放行 */
    if (WhitelistCheckByPid(pid) == 1)
        return;

    /* 提取短名 */
    {
        const CHAR* p = imagePath;
        const CHAR* lastSlash = NULL;
        while (*p) {
            if (*p == '\\' || *p == '/') lastSlash = p;
            p++;
        }
        p = lastSlash ? lastSlash + 1 : imagePath;
        for (i = 0; i < 63 && p[i]; i++) {
            imageName[i] = p[i];
        }
        imageName[i] = '\0';
    }

    /* 检查是否是脚本宿主 */
    if (!IsScriptHostImageName(imageName))
        return;

    /* 检查是否在系统目录 */
    if (IsSystemDirectoryPathA(imagePath))
        return;

    /* 检查父进程是否是系统进程 */
    if (IsParentSystemProcess(parentPid))
        return;

    /* 所有条件满足：无签名脚本宿主，由非系统进程启动 */
    DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Detected unsigned script host: PID=%lld Name=%s Path=%s ParentPID=%lld\n",
        pid, imageName, imagePath, parentPid);

    /* 分配 work item 上下文 */
    ctx = (PUNSIGNED_SCRIPT_WORKITEM_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(UNSIGNED_SCRIPT_WORKITEM_CTX), 'uShA');
    if (ctx == NULL) {
        DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Failed to allocate work item context\n");
        return;
    }

    RtlZeroMemory(ctx, sizeof(UNSIGNED_SCRIPT_WORKITEM_CTX));
    ctx->pid = pid;
    ctx->parentPid = parentPid;
    kStrCpy(ctx->imagePath, BA_MAX_PATH, imagePath);
    kStrCpy(ctx->imageName, sizeof(ctx->imageName), imageName);
    RtlStringCbCopyA(ctx->threatClass, sizeof(ctx->threatClass),
        "Behavior/UnsignedScriptHost");
    RtlStringCbPrintfA(ctx->description, sizeof(ctx->description),
        "Unsigned script host executed from non-system location by non-system parent: %s (ParentPID=%lld)",
        imagePath, parentPid);

    ExInitializeWorkItem(&ctx->WorkItem, UnsignedScriptAlertWorkItemRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);

    DriverDbgPrint("[BA-UNSIGNED-SCRIPT] Queued alert work item for PID=%lld\n", pid);
}

/* ── BehaviorRecordProcessExit: 进程退出时清理进程树 ── */
VOID BehaviorRecordProcessExit(INT64 pid)
{
    KIRQL oldIrql = 0;
    int idx;

    if (!g_baInitialized) return;

    KeAcquireSpinLock(&g_baLock, &oldIrql);

    idx = findProc(pid);
    if (idx >= 0) {
        INT64 parentPid = g_baProcTree[idx].parentPid;
        CHAR savedPath[BA_MAX_PATH] = {0};
        BOOLEAN hasSuspicious = FALSE;

        /* 保存进程路径 */
        if (g_baProcTree[idx].imagePath[0]) {
            kStrCpy(savedPath, BA_MAX_PATH, g_baProcTree[idx].imagePath);
        }

        /* 检查该进程是否有可疑指标，决定是否保留到幽灵追踪 */
        {
            int pidIdx = findPidIndex(pid);
            if (pidIdx >= 0) {
                int i;
                for (i = 0; i < BA_MAX_INDICATORS; i++) {
                    if (g_baPidIndicators[pidIdx][i] > 0) {
                        hasSuspicious = TRUE;
                        break;
                    }
                }

                /* 如果有可疑指标，保留到幽灵进程追踪（不立即清除） */
                if (hasSuspicious && g_baGhostCount < BA_MAX_GHOST_PROCESSES) {
                    /* 查找是否已有该PID的幽灵条目 */
                    int ghostIdx = -1;
                    for (i = 0; i < g_baGhostCount; i++) {
                        if (g_baGhostProcesses[i].pid == pid) {
                            ghostIdx = i;
                            break;
                        }
                    }
                    if (ghostIdx < 0 && g_baGhostCount < BA_MAX_GHOST_PROCESSES) {
                        ghostIdx = g_baGhostCount++;
                    }
                    if (ghostIdx >= 0) {
                        g_baGhostProcesses[ghostIdx].pid = pid;
                        g_baGhostProcesses[ghostIdx].parentPid = parentPid;
                        kStrCpy(g_baGhostProcesses[ghostIdx].imagePath, BA_MAX_PATH, savedPath);
                        g_baGhostProcesses[ghostIdx].exitTick = g_baTickCounter;
                        g_baGhostProcesses[ghostIdx].hasSuspiciousIndicators = TRUE;
                        /* 复制指标数据到幽灵进程独立存储（不依赖共享数组） */
                        for (i = 0; i < BA_MAX_INDICATORS; i++) {
                            g_baGhostProcesses[ghostIdx].indicators[i] = g_baPidIndicators[pidIdx][i];
                        }
                    }
                }

                /* 清理活跃进程树中的指标（幽灵追踪保留副本） */
                for (i = 0; i < BA_MAX_INDICATORS; i++) g_baPidIndicators[pidIdx][i] = 0;
                g_baPidSyscallTypes[pidIdx] = 0;
                g_baEvidence[pidIdx].count = 0;
                g_baIndicatorPids[pidIdx] = 0;
            }
        }

        /* 从父进程的子进程列表中移除 */
        if (parentPid != 0) {
            int pidx = findProc(parentPid);
            if (pidx >= 0) {
                int ci;
                for (ci = 0; ci < g_baProcTree[pidx].childCount; ci++) {
                    if (g_baProcTree[pidx].childPids[ci] == pid) {
                        g_baProcTree[pidx].childPids[ci] =
                            g_baProcTree[pidx].childPids[g_baProcTree[pidx].childCount - 1];
                        g_baProcTree[pidx].childCount--;
                        break;
                    }
                }
            }
        }

        /* 标记进程为已退出（保留路径供回溯） */
        g_baProcTree[idx].pid = 0;
        g_baProcTree[idx].childCount = 0;
        RtlZeroMemory(g_baProcTree[idx].childPids, sizeof(g_baProcTree[idx].childPids));
        g_baProcCount--;
    }

    cleanupStalePids();

    KeReleaseSpinLock(&g_baLock, oldIrql);

    /* 清理该PID的响应缓存，防止PID复用时继承旧决策 */
    ResponseCacheRemovePid((HANDLE)(ULONG_PTR)pid);

    /* 清理该PID的签名缓存，防止PID复用时继承旧签名状态 */
    {
        KIRQL sigIrql;
        int si;
        KeAcquireSpinLock(&g_baSigCacheLock, &sigIrql);
        for (si = 0; si < BA_SIG_CACHE_SIZE; si++) {
            if (g_baSigCache[si].valid && g_baSigCache[si].pid == pid) {
                g_baSigCache[si].valid = FALSE;
                break;
            }
        }
        KeReleaseSpinLock(&g_baSigCacheLock, sigIrql);
    }
    
    /* 清理该PID的进程信誉数据 */
    /* 注意：不立即删除，保留一段时间以支持PID复用检测 */
}

VOID BehaviorRecordFileEvent(
    INT64 pid, const CHAR* imagePath,
    const CHAR* filePath, const CHAR* fileDir, const CHAR* fileName, const CHAR* fileExt,
    BA_FILE_OP fileOp, BOOLEAN isSigned, UCHAR fileAttributes, BOOLEAN isPeFile)
{
    KIRQL oldIrql = 0;
    BA_STORED_EVENT* ev;

    if (!g_baInitialized) return;

    /* 行为检测总开关关闭时不记录事件，减少误报与开销 */
    if (!g_bBehaviorDetectionEnabled) return;

    /* 跳过受信任主程序 PID：防止主程序自身操作被记录为可疑行为 */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pid == g_TrustedMainPid)
        return;

    /* 白名单放行 */
    if (WhitelistCheckByPid(pid) == 1)
        return;

    KeAcquireSpinLock(&g_baLock, &oldIrql);

    /* 存入环形缓冲 */
    ev = &g_baHistory[g_baHistoryHead];
    RtlZeroMemory(ev, sizeof(BA_STORED_EVENT));
    ev->tick     = g_baTickCounter++;
    ev->pid      = pid;
    ev->category = BA_EC_File;
    kStrCpy(ev->imagePath, BA_MAX_PATH, imagePath);
    kStrCpy(ev->filePath, BA_MAX_PATH, filePath ? filePath : "");
    kStrCpy(ev->fileDir, BA_MAX_PATH, fileDir ? fileDir : "");
    kStrCpy(ev->fileName, BA_MAX_NAME, fileName ? fileName : "");
    kStrCpy(ev->fileExt, 16, fileExt ? fileExt : "");
    ev->fileOp   = fileOp;
    ev->isSigned = isSigned;
    ev->fileAttributes = fileAttributes;
    ev->isPeFile = isPeFile;

    /* 快照父 PID：进程树不可信（中间进程已退出）时，事件记录中的 parentPid
     * 是追溯祖先链至 explorer 的唯一可靠依据。 */
    {
        int procIdx = findProc(pid);
        if (procIdx >= 0)
            ev->parentPid = g_baProcTree[procIdx].parentPid;
    }

    g_baHistoryHead = (g_baHistoryHead + 1) % BA_MAX_HISTORY;
    if (g_baHistoryCount < BA_MAX_HISTORY) g_baHistoryCount++;

    /* 提取指标 */
    extractIndicators(ev);

    KeReleaseSpinLock(&g_baLock, oldIrql);
}

VOID BehaviorRecordRegistryEvent(
    INT64 pid, const CHAR* imagePath,
    const CHAR* regPath, const CHAR* regValue,
    BA_REG_OP regOp)
{
    KIRQL oldIrql = 0;
    BA_STORED_EVENT* ev;

    if (!g_baInitialized) return;

    /* 行为检测总开关关闭时不记录事件 */
    if (!g_bBehaviorDetectionEnabled) return;

    /* 跳过受信任主程序 PID */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pid == g_TrustedMainPid)
        return;

    /* 白名单放行 */
    if (WhitelistCheckByPid(pid) == 1)
        return;

    KeAcquireSpinLock(&g_baLock, &oldIrql);

    ev = &g_baHistory[g_baHistoryHead];
    RtlZeroMemory(ev, sizeof(BA_STORED_EVENT));
    ev->tick     = g_baTickCounter++;
    ev->pid      = pid;
    ev->category = BA_EC_Registry;
    kStrCpy(ev->imagePath, BA_MAX_PATH, imagePath);
    kStrCpy(ev->regPath, BA_MAX_PATH, regPath ? regPath : "");
    kStrCpy(ev->regValue, BA_MAX_NAME, regValue ? regValue : "");
    ev->regOp    = regOp;

    /* 快照父 PID，供回滚时追溯祖先链（进程树不可信时的可靠依据） */
    {
        int procIdx = findProc(pid);
        if (procIdx >= 0)
            ev->parentPid = g_baProcTree[procIdx].parentPid;
    }

    g_baHistoryHead = (g_baHistoryHead + 1) % BA_MAX_HISTORY;
    if (g_baHistoryCount < BA_MAX_HISTORY) g_baHistoryCount++;

    extractIndicators(ev);

    KeReleaseSpinLock(&g_baLock, oldIrql);
}

/* ── 辅助函数：从缓存查找进程签名状态 ── */
BOOLEAN BaSigCacheLookup(INT64 pid, BOOLEAN* isSigned)
{
    KIRQL oldIrql;
    int i;
    BOOLEAN found = FALSE;
    KeAcquireSpinLock(&g_baSigCacheLock, &oldIrql);
    for (i = 0; i < BA_SIG_CACHE_SIZE; i++) {
        if (g_baSigCache[i].valid && g_baSigCache[i].pid == pid) {
            *isSigned = g_baSigCache[i].isSigned;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_baSigCacheLock, oldIrql);
    return found;
}

/* ── 辅助函数：向缓存写入进程签名状态 ── */
static VOID BaSigCacheAdd(INT64 pid, BOOLEAN isSigned)
{
    KIRQL oldIrql;
    int i, oldestIdx = 0;
    KeAcquireSpinLock(&g_baSigCacheLock, &oldIrql);
    /* 查找已有条目或空闲槽位 */
    for (i = 0; i < BA_SIG_CACHE_SIZE; i++) {
        if (!g_baSigCache[i].valid) {
            oldestIdx = i;
            break;
        }
        if (g_baSigCache[i].pid == pid) {
            g_baSigCache[i].isSigned = isSigned;
            g_baSigCache[i].valid = TRUE;
            KeReleaseSpinLock(&g_baSigCacheLock, oldIrql);
            return;
        }
    }
    /* 没有空闲槽位，覆盖第一个 */
    g_baSigCache[oldestIdx].pid = pid;
    g_baSigCache[oldestIdx].isSigned = isSigned;
    g_baSigCache[oldestIdx].valid = TRUE;
    KeReleaseSpinLock(&g_baSigCacheLock, oldIrql);
}

/* ── BaIsMsiexecPid: 判断 PID 是否属于 msiexec.exe（可信审查用）──
 * msiexec.exe 本身带微软签名，但可能被攻击者用于执行恶意 MSI（T1218），
 * 因此即使签名有效也不视为可信进程，使其释放/修改行为进入行为检测。
 * 仅在确认进程已签名时调用，避免不必要的进程查找开销。 */
static BOOLEAN BaIsMsiexecPid(INT64 pid)
{
    PEPROCESS proc = NULL;
    UCHAR* name = NULL;
    BOOLEAN isMsiexec = FALSE;

    if (pid <= 0)
        return FALSE;

    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc)) || proc == NULL)
        return FALSE;

    __try {
        INT i;
        /* PsGetProcessImageFileName 返回 8.3 短名，通常为大写（如 "MSIEXEC.EXE"） */
        name = PsGetProcessImageFileName(proc);
        if (name != NULL) {
            static const CHAR target[] = "msiexec.exe";
            for (i = 0; target[i] != '\0'; i++) {
                CHAR c = (CHAR)name[i];
                if (c == '\0') break;                 /* name 提前结束 */
                if (c >= 'A' && c <= 'Z') c = (CHAR)(c + 32);
                if (c != target[i]) break;
            }
            if (target[i] == '\0' && name[i] == '\0')
                isMsiexec = TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        isMsiexec = FALSE;
    }

    ObDereferenceObject(proc);
    return isMsiexec;
}

/* ── ci_verify.h 实现：通过缓存表检查进程是否可信 ── */
BOOLEAN CiIsPidSigned(INT64 pid)
{
    BOOLEAN isSigned = FALSE;
    if (pid == 0) return FALSE;
    return BaSigCacheLookup(pid, &isSigned) && isSigned;
}

/* ── ci_verify.h 实现：记录进程主镜像签名状态到缓存表 ── */
VOID CiRecordProcessSignature(INT64 pid, BOOLEAN isSigned)
{
    if (pid == 0) return;
    /* 可信审查：msiexec.exe 可能被用于执行恶意 MSI（T1218），
     * 即使其本身带微软签名也不视为可信进程，使释放/修改行为进入行为检测 */
    if (isSigned && BaIsMsiexecPid(pid))
        isSigned = FALSE;
    BaSigCacheAdd(pid, isSigned);
}

/* ── ci_verify.h 实现：同目录未签名 DLL 降级进程签名状态 ──
 * 当签名进程加载了与其 EXE 同目录的未签名 DLL 时，标记该进程为不可信。
 * 使用"降级"而非"覆盖"策略：若已标记为不可信则保持不变，否则降为 FALSE。 */
VOID BaMarkPidUnsignedDueToSideLoad(INT64 pid, const CHAR* dllPath)
{
    if (pid == 0) return;
    BOOLEAN currentSigned = FALSE;
    BOOLEAN existed = BaSigCacheLookup(pid, &currentSigned);
    if (existed && currentSigned)
    {
        /* 原来可信，因同目录未签名 DLL 而降级 */
        BaSigCacheAdd(pid, FALSE);
        DriverDbgPrint("[SIDE-LOAD] PID=%lld marked unsigned due to same-dir unsigned DLL: %s\n",
            pid, dllPath ? dllPath : "Unknown");
    }
    else if (!existed)
    {
        /* 缓存未命中（进程刚启动，EXE 签名尚未记录），直接写入不可信 */
        BaSigCacheAdd(pid, FALSE);
        DriverDbgPrint("[SIDE-LOAD] PID=%lld not in cache, marked unsigned due to same-dir DLL: %s\n",
            pid, dllPath ? dllPath : "Unknown");
    }
    /* 已标记为不可信则无需重复处理 */
}

/* ── 记录 DLL 侧载指标（同目录未签名 DLL）──
 * 签名进程加载未签名 DLL：BA_IND_FILE_DLL_SIDE_LOAD（标准分 70）
 * 未签名进程加载未签名 DLL：BA_IND_FILE_DLL_SIDE_LOAD_UNSIGNED（低分 30）
 * 由 LoadImageNotifyRoutine 中的 DLL 扫描在 PASSIVE_LEVEL 工作项中调用。 */
VOID BehaviorRecordDllSideLoad(INT64 pid, const CHAR* dllPath, BOOLEAN processSigned)
{
    CHAR evBuf[128];
    const CHAR* p;
    int pathLen;
    INT idx;

    if (pid == 0) return;
    if (!g_baInitialized || !g_bBehaviorDetectionEnabled) return;

    idx = findOrCreatePidIndex(pid);
    if (idx < 0) return;

    pathLen = dllPath ? kStrLen(dllPath) : 0;
    p = dllPath ? dllPath : "Unknown";
    if (pathLen > 100) p += (pathLen - 100);
    RtlStringCbPrintfA(evBuf, sizeof(evBuf), "DLL side-load: %s", p);

    if (processSigned)
    {
        addIndicator(idx, BA_IND_FILE_DLL_SIDE_LOAD, evBuf);
        DriverDbgPrint("[SIDE-LOAD] PID=%lld signed host loads unsigned DLL, indicator=%d\n", pid, BA_IND_FILE_DLL_SIDE_LOAD);
    }
    else
    {
        addIndicator(idx, BA_IND_FILE_DLL_SIDE_LOAD_UNSIGNED, evBuf);
        DriverDbgPrint("[SIDE-LOAD] PID=%lld unsigned host loads unsigned DLL, indicator=%d (low score)\n", pid, BA_IND_FILE_DLL_SIDE_LOAD_UNSIGNED);
    }
}

/* ── 辅助函数：通过 CI.dll 验证进程镜像签名 ──
 * 打开进程镜像文件，调用 CiVerifyFileObject 验证数字签名。
 * 必须在 PASSIVE_LEVEL 调用（CiValidateFileObject 要求 IRQL <= PASSIVE_LEVEL）。
 * 使用 PID 缓存避免重复验证。 */
BOOLEAN BaIsProcessSigned(INT64 pid)
{
    PEPROCESS proc = NULL;
    HANDLE procHandle = NULL;
    HANDLE fileHandle = NULL;
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status;
    BOOLEAN isSigned = FALSE;
    ULONG retLen = 0;
    PUNICODE_STRING imagePathUni = NULL;

    if (pid == 0) return FALSE;

    /* 查缓存 */
    if (BaSigCacheLookup(pid, &isSigned))
        return isSigned;

    /* 1. 获取 PEPROCESS */
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &proc)))
        return FALSE;

    /* 2. 打开进程句柄（需要 PROCESS_QUERY_LIMITED_INFORMATION 查询镜像路径） */
    status = ObOpenObjectByPointer(
        proc, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &procHandle);
    ObDereferenceObject(proc);
    if (!NT_SUCCESS(status) || procHandle == NULL)
        return FALSE;

    /* 3. 查询进程镜像路径（第一次调用获取长度） */
    status = ZwQueryInformationProcess(procHandle, ProcessImageFileName, NULL, 0, &retLen);
    if (status != STATUS_INFO_LENGTH_MISMATCH || retLen == 0) {
        ZwClose(procHandle);
        return FALSE;
    }

    imagePathUni = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, retLen, 'BaSI');
    if (imagePathUni == NULL) {
        ZwClose(procHandle);
        return FALSE;
    }

    status = ZwQueryInformationProcess(procHandle, ProcessImageFileName,
                                       imagePathUni, retLen, &retLen);
    ZwClose(procHandle);
    if (!NT_SUCCESS(status) || imagePathUni->Buffer == NULL || imagePathUni->Length == 0) {
        ExFreePoolWithTag(imagePathUni, 'BaSI');
        return FALSE;
    }

    /* 4. 打开镜像文件 */
    {
        OBJECT_ATTRIBUTES objAttr;
        IO_STATUS_BLOCK ioStatus;
        InitializeObjectAttributes(&objAttr, imagePathUni,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        status = IoCreateFileEx(
            &fileHandle,
            FILE_READ_DATA | SYNCHRONIZE,
            &objAttr,
            &ioStatus,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL, 0,
            CreateFileTypeNone, NULL,
            IO_FORCE_ACCESS_CHECK, NULL);
    }

    ExFreePoolWithTag(imagePathUni, 'BaSI');

    if (!NT_SUCCESS(status) || fileHandle == NULL)
        return FALSE;

    /* 5. 获取 FILE_OBJECT */
    status = ObReferenceObjectByHandle(
        fileHandle, FILE_READ_DATA, *IoFileObjectType, KernelMode,
        (PVOID*)&fileObject, NULL);
    if (NT_SUCCESS(status) && fileObject) {
        /* 6. 调用 CI.dll 验证签名 */
        status = CiVerifyFileObject(fileObject, &isSigned);
        ObDereferenceObject(fileObject);
    }

    ZwClose(fileHandle);

    /* 可信审查：msiexec.exe 不视为可信进程（可能执行恶意 MSI），
     * 覆盖驱动加载前已运行的 msiexec 的缓存未命中路径 */
    if (isSigned && BaIsMsiexecPid(pid))
        isSigned = FALSE;

    /* 缓存结果 */
    BaSigCacheAdd(pid, isSigned);
    return isSigned;
}

VOID BehaviorRecordMemoryEvent(
    INT64 pid, const CHAR* imagePath,
    const CHAR* targetProcess, INT64 targetPid, INT64 desiredAccess,
    BA_MEM_OP memOp,
    BOOLEAN isParentChild,
    PVOID threadStartAddr)
{
    KIRQL oldIrql = 0;
    BA_STORED_EVENT* ev;

    if (!g_baInitialized) return;

    /* 行为检测总开关关闭时不记录事件，减少误报与开销 */
    if (!g_bBehaviorDetectionEnabled) return;

    /* 跳过受信任主程序 PID：防止主程序对子进程的 OpenProcess/注入被记录 */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pid == g_TrustedMainPid)
        return;

    /* 白名单放行 */
    if (WhitelistCheckByPid(pid) == 1)
        return;

    /* ── 锁外（PASSIVE_LEVEL）预计算源/目标进程签名状态和 SYSTEM 状态 ──
     * 签名状态：通过 CI.dll (CiVerifyFileObject) 验证进程镜像的数字签名。
     *   CiValidateFileObject 要求 IRQL <= PASSIVE_LEVEL，必须在锁外调用。
     *   使用 PID 缓存避免重复验证开销。
     * 目标进程 SYSTEM 状态：通过 SeQueryInformationToken 查询。
     * 所有预计算在锁外完成，避免在 DISPATCH_LEVEL 调用可分页代码。 */
    {
        BOOLEAN srcIsSigned = FALSE;
        BOOLEAN targetIsSystem = FALSE;
        BOOLEAN targetIsSigned = FALSE;

        /* 源进程签名验证：通过 CI.dll 验证 */
        srcIsSigned = BaIsProcessSigned(pid);

        /* 目标进程签名验证：通过 CI.dll 验证 */
        if (targetPid != 0) {
            targetIsSigned = BaIsProcessSigned(targetPid);
        }

        /* 目标进程 SYSTEM 状态 */
        if (targetPid != 0) {
            PEPROCESS targetProc = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)targetPid, &targetProc))) {
                if (targetProc != NULL) {
                    targetIsSystem = IsSystemProcessByEPROCESS(targetProc);
                    ObDereferenceObject(targetProc);
                }
            }
        }

        KeAcquireSpinLock(&g_baLock, &oldIrql);

        /* 调用者未标明父子关系时，从进程树推断。
         * 这对 ETW TI 事件尤其重要，因为 ETW 回调无法直接得知源/目标是否为父子。 */
        if (!isParentChild && targetPid != 0) {
            int tgtIdx = findProc(targetPid);
            if (tgtIdx >= 0 && g_baProcTree[tgtIdx].parentPid == pid) {
                isParentChild = TRUE;
            }
        }

        ev = &g_baHistory[g_baHistoryHead];
        RtlZeroMemory(ev, sizeof(BA_STORED_EVENT));
        ev->tick     = g_baTickCounter++;
        ev->pid      = pid;
        ev->category = BA_EC_Memory;
        kStrCpy(ev->imagePath, BA_MAX_PATH, imagePath);
        kStrCpy(ev->targetProcess, BA_MAX_NAME, targetProcess ? targetProcess : "");
        ev->targetPid    = targetPid;
        ev->desiredAccess = desiredAccess;
        ev->memOp        = memOp;
        ev->isParentChild = isParentChild;
        ev->isTargetSystemProcess = targetIsSystem;
        ev->isSigned    = srcIsSigned;
        ev->targetIsSigned = targetIsSigned;
        ev->threadStartAddr = threadStartAddr;

        /* 快照父 PID，供回滚时追溯祖先链（进程树不可信时的可靠依据） */
        {
            int procIdx = findProc(pid);
            if (procIdx >= 0)
                ev->parentPid = g_baProcTree[procIdx].parentPid;
        }

        g_baHistoryHead = (g_baHistoryHead + 1) % BA_MAX_HISTORY;
        if (g_baHistoryCount < BA_MAX_HISTORY) g_baHistoryCount++;

        extractIndicators(ev);

        KeReleaseSpinLock(&g_baLock, oldIrql);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ETW Threat-Intelligence 内存事件处理
 * 由用户态 ETW Consumer 通过 IOCTL_BEHAVIOR_ETW_MEMORY_EVENT 下发。
 * 这里实现生产级 EDR 的核心注入内存检测：
 *   1. 远程分配可执行内存 (RX/RWX/WX/X) -> 直接实时告警
 *   2. 远程非可执行分配 (RW) -> 记录到地址缓存，供后续 ProtectVM 链式检测
 *   3. 远程 ProtectVM 到可执行 -> 检查缓存，命中则标记 shellcode 链式指标
 *   4. 远程 WriteVM / QueueApc / SetThreadContext / MapView -> 记录行为指标
 *   5. WriteVM -> ProtectVM(Exec) 链式检测：捕捉写入 shellcode 后改保护属性的模式
 *   6. Alert cooldown：同一 (source, target, type) 在冷却期内只弹一次窗，避免轰炸
 * ══════════════════════════════════════════════════════════════════════════ */

INT64 baEtwTickMs()
{
    LARGE_INTEGER freq;
    LARGE_INTEGER count = KeQueryPerformanceCounter(&freq);
    if (freq.QuadPart == 0) return 0;
    return (INT64)(count.QuadPart * 1000LL / freq.QuadPart);
}

static BOOLEAN baEtwIsExecutableProtection(ULONG protection)
{
    return (protection == PAGE_EXECUTE ||
            protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY);
}

static BOOLEAN baEtwIsWritableExecutableProtection(ULONG protection)
{
    return (protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY);
}

static BOOLEAN baEtwIsNonSystemExecutableProtection(ULONG protection)
{
    /* 检测非系统进程的异常可执行内存操作，包括只读可执行(PAGE_EXECUTE_READ) */
    return (protection == PAGE_EXECUTE_READ ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_EXECUTE_WRITECOPY);
}

static BOOLEAN baEtwIsWritableProtection(ULONG protection)
{
    return (protection == PAGE_READWRITE ||
            protection == PAGE_EXECUTE_READWRITE ||
            protection == PAGE_WRITECOPY ||
            protection == PAGE_EXECUTE_WRITECOPY);
}

static VOID baEtwRecordAlloc(INT64 targetPid, INT64 baseAddress, INT64 regionSize, ULONG protection)
{
    KIRQL oldIrql = 0;
    INT64 oldestTick = 0x7FFFFFFFFFFFFFFFLL;
    INT oldestIdx = 0;
    INT i;
    INT64 nowMs = baEtwTickMs();

    KeAcquireSpinLock(&g_baEtwAllocCacheLock, &oldIrql);

    /* 查找是否已有同 (targetPid, baseAddress) 记录，更新它 */
    for (i = 0; i < BA_ETW_ALLOC_CACHE_SIZE; i++) {
        if (g_baEtwAllocCache[i].valid &&
            g_baEtwAllocCache[i].targetPid == targetPid &&
            g_baEtwAllocCache[i].baseAddress == baseAddress) {
            g_baEtwAllocCache[i].regionSize = regionSize;
            g_baEtwAllocCache[i].originalProtection = protection;
            g_baEtwAllocCache[i].tickMs = nowMs;
            KeReleaseSpinLock(&g_baEtwAllocCacheLock, oldIrql);
            return;
        }
    }

    /* 找空位或最旧的条目 */
    for (i = 0; i < BA_ETW_ALLOC_CACHE_SIZE; i++) {
        if (!g_baEtwAllocCache[i].valid) {
            oldestIdx = i;
            break;
        }
        if (g_baEtwAllocCache[i].tickMs < oldestTick) {
            oldestTick = g_baEtwAllocCache[i].tickMs;
            oldestIdx = i;
        }
    }

    g_baEtwAllocCache[oldestIdx].valid = TRUE;
    g_baEtwAllocCache[oldestIdx].targetPid = targetPid;
    g_baEtwAllocCache[oldestIdx].baseAddress = baseAddress;
    g_baEtwAllocCache[oldestIdx].regionSize = regionSize;
    g_baEtwAllocCache[oldestIdx].originalProtection = protection;
    g_baEtwAllocCache[oldestIdx].tickMs = nowMs;

    KeReleaseSpinLock(&g_baEtwAllocCacheLock, oldIrql);
}

static BOOLEAN baEtwFindAndRemoveAlloc(INT64 targetPid, INT64 baseAddress, ULONG* originalProtection)
{
    KIRQL oldIrql = 0;
    INT i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_baEtwAllocCacheLock, &oldIrql);
    for (i = 0; i < BA_ETW_ALLOC_CACHE_SIZE; i++) {
        if (g_baEtwAllocCache[i].valid &&
            g_baEtwAllocCache[i].targetPid == targetPid &&
            g_baEtwAllocCache[i].baseAddress == baseAddress) {
            if (originalProtection)
                *originalProtection = g_baEtwAllocCache[i].originalProtection;
            g_baEtwAllocCache[i].valid = FALSE;
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_baEtwAllocCacheLock, oldIrql);
    return found;
}

static VOID baEtwRecordWrite(INT64 targetPid, INT64 baseAddress, INT64 regionSize)
{
    KIRQL oldIrql = 0;
    INT64 oldestTick = 0x7FFFFFFFFFFFFFFFLL;
    INT oldestIdx = 0;
    INT i;
    INT64 nowMs = baEtwTickMs();

    KeAcquireSpinLock(&g_baEtwWriteCacheLock, &oldIrql);

    for (i = 0; i < BA_ETW_WRITE_CACHE_SIZE; i++) {
        if (g_baEtwWriteCache[i].valid &&
            g_baEtwWriteCache[i].targetPid == targetPid &&
            g_baEtwWriteCache[i].baseAddress == baseAddress) {
            g_baEtwWriteCache[i].regionSize = regionSize;
            g_baEtwWriteCache[i].tickMs = nowMs;
            KeReleaseSpinLock(&g_baEtwWriteCacheLock, oldIrql);
            return;
        }
    }

    for (i = 0; i < BA_ETW_WRITE_CACHE_SIZE; i++) {
        if (!g_baEtwWriteCache[i].valid) {
            oldestIdx = i;
            break;
        }
        if (g_baEtwWriteCache[i].tickMs < oldestTick) {
            oldestTick = g_baEtwWriteCache[i].tickMs;
            oldestIdx = i;
        }
    }

    g_baEtwWriteCache[oldestIdx].valid = TRUE;
    g_baEtwWriteCache[oldestIdx].targetPid = targetPid;
    g_baEtwWriteCache[oldestIdx].baseAddress = baseAddress;
    g_baEtwWriteCache[oldestIdx].regionSize = regionSize;
    g_baEtwWriteCache[oldestIdx].tickMs = nowMs;

    KeReleaseSpinLock(&g_baEtwWriteCacheLock, oldIrql);
}

/* 检查最近是否对 [targetPid] 的 [addr, addr+size) 区间执行过 WriteVM */
static BOOLEAN baEtwFindRecentWrite(INT64 targetPid, INT64 baseAddress, INT64 regionSize)
{
    KIRQL oldIrql = 0;
    INT i;
    BOOLEAN found = FALSE;
    INT64 nowMs = baEtwTickMs();
    INT64 endAddr = baseAddress + regionSize;

    KeAcquireSpinLock(&g_baEtwWriteCacheLock, &oldIrql);
    for (i = 0; i < BA_ETW_WRITE_CACHE_SIZE; i++) {
        if (!g_baEtwWriteCache[i].valid)
            continue;
        if (g_baEtwWriteCache[i].targetPid != targetPid)
            continue;
        if (nowMs - g_baEtwWriteCache[i].tickMs > BA_ETW_WRITE_CHAIN_AGE_MS) {
            g_baEtwWriteCache[i].valid = FALSE;
            continue;
        }
        /* 地址范围重叠即视为同一次写入 */
        INT64 writeEnd = g_baEtwWriteCache[i].baseAddress + g_baEtwWriteCache[i].regionSize;
        if (g_baEtwWriteCache[i].baseAddress < endAddr && writeEnd > baseAddress) {
            g_baEtwWriteCache[i].valid = FALSE; /* 命中后清除，避免重复触发 */
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_baEtwWriteCacheLock, oldIrql);
    return found;
}

/* 告警冷却：同 (source, target, type) 在窗口期内不再重复弹窗，仅记录指标 */
static BOOLEAN baEtwShouldAlert(INT64 sourcePid, INT64 targetPid, const CHAR* alertType)
{
    KIRQL oldIrql = 0;
    INT i;
    INT64 nowMs = baEtwTickMs();
    INT64 oldestTick = 0x7FFFFFFFFFFFFFFFLL;
    INT oldestIdx = 0;
    BOOLEAN shouldAlert = TRUE;

    KeAcquireSpinLock(&g_baEtwAlertCooldownLock, &oldIrql);

    /* 清理过期条目并查找是否已有冷却记录 */
    for (i = 0; i < BA_ETW_ALERT_COOLDOWN_SIZE; i++) {
        if (g_baEtwAlertCooldown[i].valid &&
            g_baEtwAlertCooldown[i].sourcePid == sourcePid &&
            g_baEtwAlertCooldown[i].targetPid == targetPid &&
            kStrCmp(g_baEtwAlertCooldown[i].alertType, alertType) == 0) {
            if (nowMs - g_baEtwAlertCooldown[i].tickMs < BA_ETW_ALERT_COOLDOWN_MS) {
                shouldAlert = FALSE;
            } else {
                g_baEtwAlertCooldown[i].tickMs = nowMs;
            }
            KeReleaseSpinLock(&g_baEtwAlertCooldownLock, oldIrql);
            return shouldAlert;
        }
    }

    /* 未找到，新增冷却记录 */
    for (i = 0; i < BA_ETW_ALERT_COOLDOWN_SIZE; i++) {
        if (!g_baEtwAlertCooldown[i].valid) {
            oldestIdx = i;
            break;
        }
        if (g_baEtwAlertCooldown[i].tickMs < oldestTick) {
            oldestTick = g_baEtwAlertCooldown[i].tickMs;
            oldestIdx = i;
        }
    }

    g_baEtwAlertCooldown[oldestIdx].valid = TRUE;
    g_baEtwAlertCooldown[oldestIdx].sourcePid = sourcePid;
    g_baEtwAlertCooldown[oldestIdx].targetPid = targetPid;
    kStrCpy(g_baEtwAlertCooldown[oldestIdx].alertType,
            sizeof(g_baEtwAlertCooldown[oldestIdx].alertType),
            alertType ? alertType : "");
    g_baEtwAlertCooldown[oldestIdx].tickMs = nowMs;

    KeReleaseSpinLock(&g_baEtwAlertCooldownLock, oldIrql);
    return TRUE;
}

static VOID baEtwGetProcessNameByPid(INT64 pid, CHAR* outName, INT outSize)
{
    PEPROCESS process = NULL;
    if (outName == NULL || outSize <= 0) return;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process))) {
        kStrCpy(outName, outSize, "unknown");
        return;
    }

    if (process == NULL) {
        kStrCpy(outName, outSize, "unknown");
        return;
    }

    __try {
        UCHAR* shortName = PsGetProcessImageFileName(process);
        if (shortName) {
            int i;
            for (i = 0; i < outSize - 1 && shortName[i]; i++) {
                outName[i] = (CHAR)shortName[i];
            }
            outName[i] = '\0';
        } else {
            kStrCpy(outName, outSize, "unknown");
        }
    } __finally {
        ObDereferenceObject(process);
    }
}

/* 检查 sourcePid 是否为 targetPid 的父进程（放行正常进程创建） */
static BOOLEAN baEtwIsParentChild(INT64 sourcePid, INT64 targetPid)
{
    BOOLEAN result = FALSE;
    KIRQL oldIrql = 0;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    {
        int tgtIdx = findProc(targetPid);
        if (tgtIdx >= 0 && g_baProcTree[tgtIdx].parentPid == sourcePid)
            result = TRUE;
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    return result;
}



/* ── BaIsWhitelisted: 检查进程是否在白名单中 ──
 * 参考 Elastic Security detection-rules：
 * - 支持精确匹配和模糊匹配
 * - 支持路径模式匹配
 * - 自动识别安全产品路径 */
static BOOLEAN BaIsWhitelisted(const CHAR* imagePath)
{
    KIRQL oldIrql = 0;
    INT i;
    BOOLEAN found = FALSE;
    int pathLen;

    if (imagePath == NULL || imagePath[0] == '\0')
        return FALSE;

    pathLen = kStrLen(imagePath);

    KeAcquireSpinLock(&g_baWhitelistLock, &oldIrql);
    for (i = 0; i < g_baWhitelistCount; i++) {
        const CHAR* whitelistEntry = g_baWhitelist[i].ImagePath;
        int entryLen = kStrLen(whitelistEntry);

        /* 精确匹配 */
        if (kStrCmp(whitelistEntry, imagePath) == 0) {
            found = TRUE;
            break;
        }

        /* 模糊匹配（子串） */
        if (kStrStrLen(imagePath, pathLen, whitelistEntry, entryLen) != -1) {
            found = TRUE;
            break;
        }

        /* 反向模糊匹配 */
        if (kStrStrLen(whitelistEntry, entryLen, imagePath, pathLen) != -1) {
            found = TRUE;
            break;
        }

        /* 路径模式匹配（检查是否以白名单条目结尾） */
        if (pathLen >= entryLen) {
            const CHAR* pathEnd = imagePath + pathLen - entryLen;
            if (kStrCmp(pathEnd, whitelistEntry) == 0) {
                found = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_baWhitelistLock, oldIrql);

    return found;
}

/* ── BaCheckException: 检查规则例外 ──
 * 参考 Elastic Security detection-rules：
 * - 支持精确匹配和模糊匹配
 * - 检查例外是否过期
 * - 支持条件匹配 */
static BOOLEAN BaCheckException(ULONG ruleId, const CHAR* imagePath)
{
    KIRQL oldIrql = 0;
    INT i;
    BOOLEAN exceptionFound = FALSE;
    INT64 nowMs;

    if (imagePath == NULL || imagePath[0] == '\0')
        return FALSE;

    nowMs = baEtwTickMs();

    KeAcquireSpinLock(&g_baExceptionLock, &oldIrql);
    for (i = 0; i < g_baExceptionCount; i++) {
        if (g_baExceptions[i].RuleId == ruleId &&
            g_baExceptions[i].Active) {
            
            /* 检查例外是否过期 */
            if (g_baExceptions[i].ExpireTickMs > 0 && nowMs > g_baExceptions[i].ExpireTickMs) {
                continue;
            }
            
            /* 精确匹配 */
            if (kStrCmp(g_baExceptions[i].ImagePath, imagePath) == 0) {
                exceptionFound = TRUE;
                break;
            }
            
            /* 模糊匹配 */
            if (kStrStrLen(imagePath, kStrLen(imagePath), 
                g_baExceptions[i].ImagePath, kStrLen(g_baExceptions[i].ImagePath)) != -1) {
                exceptionFound = TRUE;
                break;
            }
            
            /* 条件匹配（如果例外包含条件字符串） */
            if (g_baExceptions[i].Condition[0] != '\0') {
                if (kStrStrLen(imagePath, kStrLen(imagePath),
                    g_baExceptions[i].Condition, kStrLen(g_baExceptions[i].Condition)) != -1) {
                    exceptionFound = TRUE;
                    break;
                }
            }
        }
    }
    KeReleaseSpinLock(&g_baExceptionLock, oldIrql);

    return exceptionFound;
}

/* ── BaIsRuleSuppressed: 检查规则是否被抑制 ──
 * 参考 Elastic Security detection-rules：
 * - 检查抑制是否过期
 * - 支持时间窗口抑制
 * - 支持进程级和规则级抑制 */
static BOOLEAN BaIsRuleSuppressed(ULONG ruleId, INT64 pid)
{
    KIRQL oldIrql = 0;
    INT i;
    BOOLEAN suppressed = FALSE;
    INT64 nowMs;

    nowMs = baEtwTickMs();

    KeAcquireSpinLock(&g_baSuppressionLock, &oldIrql);
    for (i = 0; i < g_baSuppressionCount; i++) {
        if (g_baSuppressions[i].RuleId == ruleId) {
            
            /* 检查抑制是否过期 */
            if (g_baSuppressions[i].EndTickMs > 0 && nowMs > g_baSuppressions[i].EndTickMs) {
                continue;
            }
            
            /* PID匹配 */
            if (g_baSuppressions[i].Pid == pid) {
                suppressed = TRUE;
                BehaviorLogDebug("Rule %lu suppressed for PID %lld until %lld (reason: %s)",
                    ruleId, pid, g_baSuppressions[i].EndTickMs, g_baSuppressions[i].Reason);
                break;
            }
            
            /* 进程树抑制（检查是否为同一进程树） */
            if (g_baSuppressions[i].Pid == 0) {
                suppressed = TRUE;
                BehaviorLogDebug("Rule %lu suppressed for entire process tree (reason: %s)",
                    ruleId, g_baSuppressions[i].Reason);
                break;
            }
        }
    }
    KeReleaseSpinLock(&g_baSuppressionLock, oldIrql);

    return suppressed;
}



/* ── BaAddWhitelistEntry: 添加白名单条目 ── */
static NTSTATUS BaAddWhitelistEntry(const BA_WHITELIST_ENTRY* entry)
{
    KIRQL oldIrql = 0;

    if (entry == NULL || entry->ImagePath[0] == '\0')
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_baWhitelistLock, &oldIrql);
    if (g_baWhitelistCount >= BA_MAX_WHITELIST) {
        KeReleaseSpinLock(&g_baWhitelistLock, oldIrql);
        return STATUS_NO_MEMORY;
    }

    RtlCopyMemory(&g_baWhitelist[g_baWhitelistCount], entry, sizeof(BA_WHITELIST_ENTRY));
    g_baWhitelistCount++;
    KeReleaseSpinLock(&g_baWhitelistLock, oldIrql);

    BehaviorLogInfo("Whitelist entry added: %s", entry->ImagePath);
    return STATUS_SUCCESS;
}

/* ── BaAddException: 添加规则例外 ── */
static NTSTATUS BaAddException(const BA_EXCEPTION_ENTRY* exception)
{
    KIRQL oldIrql = 0;

    if (exception == NULL || exception->ImagePath[0] == '\0')
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_baExceptionLock, &oldIrql);
    if (g_baExceptionCount >= BA_MAX_EXCEPTIONS) {
        KeReleaseSpinLock(&g_baExceptionLock, oldIrql);
        return STATUS_NO_MEMORY;
    }

    RtlCopyMemory(&g_baExceptions[g_baExceptionCount], exception, sizeof(BA_EXCEPTION_ENTRY));
    g_baExceptionCount++;
    KeReleaseSpinLock(&g_baExceptionLock, oldIrql);

    BehaviorLogInfo("Exception added for rule %lu: %s", exception->RuleId, exception->ImagePath);
    return STATUS_SUCCESS;
}

/* ── BaSuppressRule: 抑制规则 ── */
static NTSTATUS BaSuppressRule(ULONG ruleId, INT64 pid, INT64 durationMs, const CHAR* reason)
{
    KIRQL oldIrql = 0;

    KeAcquireSpinLock(&g_baSuppressionLock, &oldIrql);
    if (g_baSuppressionCount >= BA_MAX_RULE_SUPPRESSIONS) {
        KeReleaseSpinLock(&g_baSuppressionLock, oldIrql);
        return STATUS_NO_MEMORY;
    }

    g_baSuppressions[g_baSuppressionCount].RuleId = ruleId;
    g_baSuppressions[g_baSuppressionCount].Pid = pid;
    g_baSuppressions[g_baSuppressionCount].StartTickMs = baEtwTickMs();
    g_baSuppressions[g_baSuppressionCount].EndTickMs = baEtwTickMs() + durationMs;
    if (reason != NULL)
        kStrCpy(g_baSuppressions[g_baSuppressionCount].Reason, 256, reason);
    else
        g_baSuppressions[g_baSuppressionCount].Reason[0] = '\0';

    g_baSuppressionCount++;
    KeReleaseSpinLock(&g_baSuppressionLock, oldIrql);

    BehaviorLogInfo("Rule %lu suppressed for PID %lld, duration %lld ms", ruleId, pid, durationMs);
    return STATUS_SUCCESS;
}

/* ── BehaviorAddWhitelistEntry: 公开API - 添加白名单条目 ── */
NTSTATUS BehaviorAddWhitelistEntry(const BA_WHITELIST_ENTRY* entry)
{
    return BaAddWhitelistEntry(entry);
}

/* ── BehaviorRemoveWhitelistEntry: 公开API - 移除白名单条目 ── */
NTSTATUS BehaviorRemoveWhitelistEntry(const CHAR* imagePath)
{
    KIRQL oldIrql = 0;
    INT i;

    if (imagePath == NULL || imagePath[0] == '\0')
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_baWhitelistLock, &oldIrql);
    for (i = 0; i < g_baWhitelistCount; i++) {
        if (kStrCmp(g_baWhitelist[i].ImagePath, imagePath) == 0) {
            if (i < g_baWhitelistCount - 1)
                RtlCopyMemory(&g_baWhitelist[i], &g_baWhitelist[i + 1],
                    sizeof(BA_WHITELIST_ENTRY) * (g_baWhitelistCount - i - 1));
            g_baWhitelistCount--;
            KeReleaseSpinLock(&g_baWhitelistLock, oldIrql);
            BehaviorLogInfo("Whitelist entry removed: %s", imagePath);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_baWhitelistLock, oldIrql);

    return STATUS_NOT_FOUND;
}

/* ── BehaviorIsWhitelisted: 公开API - 检查是否在白名单中 ── */
BOOLEAN BehaviorIsWhitelisted(const CHAR* imagePath)
{
    return BaIsWhitelisted(imagePath);
}

/* ── BehaviorAddException: 公开API - 添加规则例外 ── */
NTSTATUS BehaviorAddException(const BA_EXCEPTION_ENTRY* exception)
{
    return BaAddException(exception);
}

/* ── BehaviorRemoveException: 公开API - 移除规则例外 ── */
NTSTATUS BehaviorRemoveException(ULONG ruleId, const CHAR* imagePath)
{
    KIRQL oldIrql = 0;
    INT i;

    KeAcquireSpinLock(&g_baExceptionLock, &oldIrql);
    for (i = 0; i < g_baExceptionCount; i++) {
        if (g_baExceptions[i].RuleId == ruleId &&
            kStrCmp(g_baExceptions[i].ImagePath, imagePath) == 0) {
            if (i < g_baExceptionCount - 1)
                RtlCopyMemory(&g_baExceptions[i], &g_baExceptions[i + 1],
                    sizeof(BA_EXCEPTION_ENTRY) * (g_baExceptionCount - i - 1));
            g_baExceptionCount--;
            KeReleaseSpinLock(&g_baExceptionLock, oldIrql);
            BehaviorLogInfo("Exception removed for rule %lu: %s", ruleId, imagePath);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_baExceptionLock, oldIrql);

    return STATUS_NOT_FOUND;
}

/* ── BehaviorCheckException: 公开API - 检查规则例外 ── */
BOOLEAN BehaviorCheckException(ULONG ruleId, const CHAR* imagePath)
{
    return BaCheckException(ruleId, imagePath);
}

/* ── BehaviorSuppressRule: 公开API - 抑制规则 ── */
NTSTATUS BehaviorSuppressRule(ULONG ruleId, INT64 pid, INT64 durationMs, const CHAR* reason)
{
    return BaSuppressRule(ruleId, pid, durationMs, reason);
}

/* ── BehaviorIsRuleSuppressed: 公开API - 检查规则是否被抑制 ── */
BOOLEAN BehaviorIsRuleSuppressed(ULONG ruleId, INT64 pid)
{
    return BaIsRuleSuppressed(ruleId, pid);
}

/* ── BehaviorUpdateProcessReputation: 公开API - 更新进程信誉 ── */
NTSTATUS BehaviorUpdateProcessReputation(INT64 pid, const CHAR* imagePath, DOUBLE score)
{
    KIRQL oldIrql = 0;
    INT i;
    BOOLEAN found = FALSE;

    if (pid == 0 || imagePath == NULL || imagePath[0] == '\0')
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_baReputationLock, &oldIrql);
    for (i = 0; i < g_baReputationCount; i++) {
        if (g_baReputations[i].Pid == pid) {
            found = TRUE;
            g_baReputations[i].ReputationScore = score;
            if (g_baReputations[i].ReputationScore > 1.0)
                g_baReputations[i].ReputationScore = 1.0;
            if (g_baReputations[i].ReputationScore < 0.0)
                g_baReputations[i].ReputationScore = 0.0;
            g_baReputations[i].LastUpdatedTickMs = baEtwTickMs();
            break;
        }
    }

    if (!found && g_baReputationCount < BA_MAX_PROCESSES) {
        i = g_baReputationCount++;
        RtlZeroMemory(&g_baReputations[i], sizeof(BA_PROCESS_REPUTATION));
        g_baReputations[i].Pid = pid;
        kStrCpy(g_baReputations[i].ImagePath, BA_MAX_PATH, imagePath);
        g_baReputations[i].ReputationScore = score;
        g_baReputations[i].FirstSeenTickMs = baEtwTickMs();
        g_baReputations[i].LastUpdatedTickMs = baEtwTickMs();
    }
    KeReleaseSpinLock(&g_baReputationLock, oldIrql);

    return STATUS_SUCCESS;
}

/* 检查源/目标进程是否为系统关键进程：系统组件之间的正常内存操作放行 */
static BOOLEAN baEtwIsSystemProcessByPid(INT64 pid)
{
    BOOLEAN result = FALSE;
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process)))
        return FALSE;

    result = IsCriticalSystemProcess(process);
    ObDereferenceObject(process);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
/* ═══════════════════════════════════════════════════════════════════════════
 * x86-64 Shellcode 静态模拟器 (Static Execution Simulator)
 * 模拟执行机器码，追踪寄存器状态和内存访问，还原混淆的shellcode行为
 * 支持: Indirect Syscall, Hell's Gate, PIC, API Hashing, XOR解密, NOP sled
 * 误报控制: 必须检测到真实的行为模式(如syscall调用/PEB访问/内存解密)才判定
 * ═══════════════════════════════════════════════════════════════════════════ */

#define BA_SC_MAX_INSTRUCTIONS  128
#define BA_SC_MAX_STACK         32
#define BA_SC_SCORE_THRESHOLD   35

/* ── 寄存器状态 (x86-64 通用寄存器) ── */
typedef struct _BA_SC_REGS {
    INT64 rax, rcx, rdx, rbx;
    INT64 rsp, rbp, rsi, rdi;
    INT64 r8,  r9,  r10, r11;
    INT64 r12, r13, r14, r15;
} BA_SC_REGS;

/* ── 模拟器上下文 ── */
typedef struct _BA_SC_CTX {
    const UCHAR* code;
    ULONG        codeSize;
    ULONG        rip;
    BA_SC_REGS   regs;
    INT64        stack[BA_SC_MAX_STACK];
    INT          sp;
    BOOLEAN      hitSyscall;
    BOOLEAN      pebAccess;
    BOOLEAN      moduleWalk;
    BOOLEAN      exportParse;
    BOOLEAN      xorDecrypt;
    BOOLEAN      hasNopSled;
    BOOLEAN      hasInt3Seq;
    BOOLEAN      indirectCall;
    BOOLEAN      selfModifying;
    BOOLEAN      stackOverflow;
    INT32        score;
    CHAR         families[192];
    CHAR         techniques[256];
    INT          instCount;
} BA_SC_CTX;

/* ── Shellcode检测结果 ── */
typedef struct _BA_SC_RESULT {
    INT32    score;
    INT32    featureCount;
    CHAR     families[192];
    CHAR     techniques[256];
} BA_SC_RESULT, *PBA_SC_RESULT;

/* ── 小端读取 ── */
static UINT32 baScReadU32(const UCHAR* p) { return (UINT32)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24)); }
static INT32  baScReadI32(const UCHAR* p) { return (INT32)baScReadU32(p); }

/* ── 寄存器访问 ── */
static INT64 baScGetReg(BA_SC_REGS* r, INT idx)
{
    idx &= 0xF;
    switch (idx) {
        case 0: return r->rax; case 1: return r->rcx; case 2: return r->rdx;
        case 3: return r->rbx; case 4: return r->rsp; case 5: return r->rbp;
        case 6: return r->rsi; case 7: return r->rdi; case 8: return r->r8;
        case 9: return r->r9;  case 10: return r->r10; case 11: return r->r11;
        case 12: return r->r12; case 13: return r->r13; case 14: return r->r14;
        case 15: return r->r15; default: return 0;
    }
}
static VOID baScSetReg(BA_SC_REGS* r, INT idx, INT64 val)
{
    idx &= 0xF;
    switch (idx) {
        case 0: r->rax = val; break; case 1: r->rcx = val; break;
        case 2: r->rdx = val; break; case 3: r->rbx = val; break;
        case 4: r->rsp = val; break; case 5: r->rbp = val; break;
        case 6: r->rsi = val; break; case 7: r->rdi = val; break;
        case 8: r->r8 = val; break; case 9: r->r9 = val; break;
        case 10: r->r10 = val; break; case 11: r->r11 = val; break;
        case 12: r->r12 = val; break; case 13: r->r13 = val; break;
        case 14: r->r14 = val; break; case 15: r->r15 = val; break;
    }
}

static VOID baScSimPush(BA_SC_CTX* ctx, INT64 val)
{
    if (ctx->sp >= BA_SC_MAX_STACK - 1) { ctx->stackOverflow = TRUE; return; }
    ctx->sp++; ctx->stack[ctx->sp] = val;
}
static INT64 baScSimPop(BA_SC_CTX* ctx)
{
    if (ctx->sp < 0) return 0;
    return ctx->stack[ctx->sp--];
}

/* ── 从ModRM解析有效地址（简化版，处理SIB） ── */
static INT64 baScResolveModRMAddr(const UCHAR* code, ULONG rip, UCHAR modrm,
                                   BOOLEAN is64, BOOLEAN rexW, BOOLEAN rexR,
                                   BA_SC_REGS* regs)
{
    UNREFERENCED_PARAMETER(is64);
    UNREFERENCED_PARAMETER(rexR);
    UNREFERENCED_PARAMETER(regs);
    UNREFERENCED_PARAMETER(code);
    UNREFERENCED_PARAMETER(rip);
    
    /* 简化版本：当前函数主要用于占位，实际检测在模拟器主循环中完成 */
    UNREFERENCED_PARAMETER(modrm);
    UNREFERENCED_PARAMETER(rexW);
    
    return 0;
}

/* ── 主模拟器 ── */
static VOID baScSimulateExecute(const UCHAR* code, ULONG codeSize, BA_SC_CTX* ctx)
{
    if (!code || codeSize == 0 || !ctx) return;

    RtlZeroMemory(ctx, sizeof(BA_SC_CTX));
    ctx->code = code;
    ctx->codeSize = codeSize;
    ctx->sp = -1;
    ctx->instCount = 0;

    ULONG rip = 0;

    while (rip < codeSize && ctx->instCount < BA_SC_MAX_INSTRUCTIONS) {
        ctx->rip = rip;
        ctx->instCount++;

        UCHAR opcode = code[rip];
        BOOLEAN is64 = FALSE;
        UCHAR rex = 0;

        /* REX前缀 */
        if (opcode >= 0x40 && opcode <= 0x4F) {
            rex = opcode;
            is64 = (rex & 0x8);
            if (++rip >= codeSize) break;
            opcode = code[rip];
        }

        /* ── syscall/sysret ── */
        if (opcode == 0x0F && rip + 1 < codeSize) {
            UCHAR op2 = code[rip + 1];
            if (op2 == 0x05) { /* syscall */
                ctx->hitSyscall = TRUE;
                ctx->score += 15;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "Syscall ");
                kStrCat(ctx->families, sizeof(ctx->families), "IndirectSyscall/SysWhispers ");
                rip += 2; continue;
            }
            if (op2 == 0x30 || op2 == 0x32) { /* rdmsr/wrmsr */
                ctx->score += 8;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "MSR_Access ");
                rip += 2; continue;
            }
            if (op2 == 0xA2) { /* cpuid */
                ctx->score += 6;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "CPUID ");
                rip += 2; continue;
            }
            /* 0F 1F = NOP多字节 (不加分) */
            rip += 2; continue;
        }

        /* ── PUSH/POP (0x50-0x5F) ── */
        if (opcode >= 0x50 && opcode <= 0x5F) {
            INT reg = opcode - 0x50;
            if (rex & 0x4) reg |= 8;
            if (reg <= 7) baScSimPush(ctx, baScGetReg(&ctx->regs, reg));
            else          baScSetReg(&ctx->regs, reg, baScSimPop(ctx));
            rip++; continue;
        }

        /* ── RET ── */
        if (opcode == 0xC3) {
            INT64 retAddr = baScSimPop(ctx);
            if (retAddr > 0 && retAddr < (INT64)codeSize) {
                rip = (ULONG)retAddr; continue;
            }
            break;
        }
        if (opcode == 0xC2 || opcode == 0xCA) { rip += 3; continue; }

        /* ── JMP/JCC ── */
        if (opcode == 0xE9 && rip + 4 < codeSize) {
            rip = (ULONG)(rip + 5 + baScReadI32(code + rip + 1)); continue;
        }
        if (opcode == 0xEB && rip + 1 < codeSize) {
            rip += 2 + (INT8)code[rip + 1]; continue;
        }
        if (opcode >= 0x70 && opcode <= 0x7F && rip + 1 < codeSize) {
            rip += 2 + (INT8)code[rip + 1]; continue;
        }

        /* ── CALL rel32 ── */
        if (opcode == 0xE8 && rip + 4 < codeSize) {
            INT32 disp = baScReadI32(code + rip + 1);
            INT64 target = (INT64)rip + 5 + disp;
            baScSimPush(ctx, (INT64)rip + 5);
            if (target >= 0 && target < (INT64)codeSize) {
                rip = (ULONG)target;
            } else {
                ctx->indirectCall = TRUE;
                ctx->score += 3;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "Ext_Call ");
                rip += 5;
            }
            continue;
        }

        /* ── MOV imm → reg (B8-BF) ── */
        if (opcode >= 0xB8 && opcode <= 0xBF) {
            INT reg = opcode - 0xB8;
            if (rex & 0x4) reg |= 8;
            if (is64) {
                if (rip + 8 >= codeSize) break;
                baScSetReg(&ctx->regs, reg,
                    ((INT64)baScReadU32(code + rip + 1)) |
                    (((INT64)baScReadU32(code + rip + 5)) << 32));
                rip += 9;
            } else {
                if (rip + 4 >= codeSize) break;
                baScSetReg(&ctx->regs, reg, baScReadU32(code + rip + 1));
                rip += 5;
            }
            continue;
        }

        /* ── 辅助: 解析ModRM获取mod/rm/reg字段 ── */
        {
            /* 提取通用ModRM处理逻辑到下面 */
        }

        /* ── MOV r/m, r (88/89) & MOV r, r/m (8A/8B) ── */
        if ((opcode == 0x88 || opcode == 0x89 || opcode == 0x8A || opcode == 0x8B) && rip + 1 < codeSize) {
            UCHAR modrm = code[rip + 1];
            UCHAR mod = (modrm >> 6) & 3;
            UCHAR rm = modrm & 7;
            UCHAR reg = (modrm >> 3) & 7;
            if (rex & 0x1) rm |= 8;
            if (rex & 0x2) reg |= 8;

            /* PEB访问检测: gs:[0x60] = 64 48 8B 04 25 60 00 00 00 */
            if (opcode == 0x8B && rex == 0x48 && mod == 0 && rm == 5) {
                if (rip + 5 < codeSize && baScReadU32(code + rip + 3) == 0x60) {
                    ctx->pebAccess = TRUE;
                    ctx->score += 15;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "PEB_Access ");
                    kStrCat(ctx->families, sizeof(ctx->families), "HellsGate/HalosGate ");
                }
            }

            /* PEB->Ldr 偏移检测 */
            if (opcode == 0x8B && mod != 3) {
                INT32 disp = 0;
                BOOLEAN hasSib = (rm == 4 && mod != 0);
                if (hasSib && rip + 2 < codeSize) {
                    /* SIB字节跳过，位移从更后面读 */
                    UCHAR sib = code[rip + 2];
                    UCHAR baseSib = (sib >> 3) & 7;
                    if (rex & 0x1) baseSib |= 8;
                    if (baseSib != 5 || mod != 0) {
                        /* 有基寄存器，跳过SIB后读disp */
                        if (mod == 1) disp = (INT8)code[rip + 3];
                        else if (mod == 2) disp = baScReadI32(code + rip + 3);
                    }
                } else {
                    if (mod == 1) disp = (INT8)code[rip + 2];
                    else if (mod == 2) disp = baScReadI32(code + rip + 2);
                }
                if (disp == 0x18 || disp == 0x20 || disp == 0x28 || disp == 0x30 || disp == 0x38) {
                    ctx->moduleWalk = TRUE;
                    ctx->score += 10;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "ModuleWalk ");
                }
                if (disp == 0x3C || disp == 0x88) {
                    ctx->exportParse = TRUE;
                    ctx->score += 10;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "Export_Parse ");
                    kStrCat(ctx->families, sizeof(ctx->families), "HellsGate/HalosGate/Tartarus ");
                }
            }

            /* 自修改代码: 写内存到代码段附近(不是栈/堆) */
            if ((opcode == 0x88 || opcode == 0x89) && mod != 3) {
                /* 只有当目标地址接近当前代码位置时才认为是自修改 */
                INT64 writeAddr = baScGetReg(&ctx->regs, rm);
                if (writeAddr >= 0 && writeAddr < (INT64)codeSize) {
                    ctx->selfModifying = TRUE;
                    ctx->score += 4;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "SelfModifying ");
                }
            }

            /* 正常MOV模拟 */
            if (opcode == 0x8A || opcode == 0x8B) {
                INT64 src = (mod == 3) ? baScGetReg(&ctx->regs, rm) : -1LL;
                baScSetReg(&ctx->regs, reg, src);
            } else {
                if (mod == 3) baScSetReg(&ctx->regs, rm, baScGetReg(&ctx->regs, reg));
            }

            /* 计算指令长度，处理SIB */
            rip += 2;
            BOOLEAN hasSib2 = (rm == 4 && mod != 0);
            if (hasSib2) rip++; /* skip SIB byte */
            if (mod == 0 && rm == 5) rip += 4;
            else if (mod == 1) rip++;
            else if (mod == 2) rip += 4;
            continue;
        }

        /* ── LEA (8D) ── */
        if (opcode == 0x8D && rip + 1 < codeSize) {
            UCHAR modrm = code[rip + 1];
            UCHAR reg = (modrm >> 3) & 7;
            if (rex & 0x2) reg |= 8;
            UCHAR mod = (modrm >> 6) & 3;
            UCHAR rm = modrm & 7;
            if (rex & 0x1) rm |= 8;
            INT64 addr = 0;
            BOOLEAN hasSibLea = (rm == 4 && mod != 0);
            if (hasSibLea) rip++; /* skip SIB */
            if (mod == 0 && rm == 5 && is64) {
                addr = (rip + 5) + baScReadI32(code + rip + 2);
                ctx->score += 3;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "RIP_LEA ");
            } else if (mod == 1) {
                addr = baScGetReg(&ctx->regs, rm) + (INT8)code[rip + (hasSibLea ? 3 : 2)];
            } else if (mod == 2) {
                addr = baScGetReg(&ctx->regs, rm) + baScReadI32(code + rip + (hasSibLea ? 3 : 2));
            } else if (mod == 3) {
                addr = baScGetReg(&ctx->regs, rm);
            }
            baScSetReg(&ctx->regs, reg, addr);
            rip += 2 + (hasSibLea ? 1 : 0);
            if (mod == 0 && rm == 5) rip += 4;
            else if (mod == 1) rip++;
            else if (mod == 2) rip += 4;
            continue;
        }

        /* ── XOR (31/33/34/35) ── */
        if (opcode == 0x31 || opcode == 0x33) {
            if (rip + 1 < codeSize) {
                UCHAR modrm = code[rip + 1];
                UCHAR rm = modrm & 7, reg = (modrm >> 3) & 7;
                if (rex & 0x1) rm |= 8;
                if (rex & 0x2) reg |= 8;
                INT64 a = baScGetReg(&ctx->regs, rm);
                INT64 b = baScGetReg(&ctx->regs, reg);
                baScSetReg(&ctx->regs, rm, a ^ b);
                if (a == b) {
                    ctx->score += 2;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "Xor_Clear ");
                } else {
                    ctx->xorDecrypt = TRUE;
                    ctx->score += 3;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "XOR_Decrypt ");
                }
            }
            rip += 2; continue;
        }
        if (opcode == 0x35 && rip + 4 < codeSize) {
            INT32 imm = baScReadI32(code + rip + 1);
            ctx->regs.rax ^= imm;
            ctx->xorDecrypt = TRUE;
            ctx->score += 3;
            kStrCat(ctx->techniques, sizeof(ctx->techniques), "XOR_Decrypt ");
            rip += 5; continue;
        }
        if (opcode == 0x34 && rip + 1 < codeSize) {
            ctx->regs.rax ^= code[rip + 1];
            rip += 2; continue;
        }

        /* ── ADD/SUB (01/03/29/2B) ── */
        if (opcode == 0x01 || opcode == 0x03 || opcode == 0x29 || opcode == 0x2B) {
            if (rip + 1 < codeSize) {
                UCHAR modrm = code[rip + 1];
                UCHAR rm = modrm & 7, reg = (modrm >> 3) & 7;
                if (rex & 0x1) rm |= 8;
                if (rex & 0x2) reg |= 8;
                INT64 a = baScGetReg(&ctx->regs, rm);
                INT64 b = baScGetReg(&ctx->regs, reg);
                INT64 result = (opcode == 0x01 || opcode == 0x03) ? (a + b) : (a - b);
                if (opcode == 0x01 || opcode == 0x29) baScSetReg(&ctx->regs, rm, result);
                else                                   baScSetReg(&ctx->regs, reg, result);
            }
            rip += 2; continue;
        }

        /* ── INC/DEC/CALL/JMP r/m (FF) ── */
        if (opcode == 0xFF && rip + 1 < codeSize) {
            UCHAR modrm = code[rip + 1];
            UCHAR mod = (modrm >> 6) & 3;
            UCHAR rm = modrm & 7;
            UCHAR reg = (modrm >> 3) & 7;
            if (rex & 0x1) rm |= 8;
            if (reg == 0 || reg == 1) { /* inc/dec */
                INT64 v = baScGetReg(&ctx->regs, rm);
                baScSetReg(&ctx->regs, rm, v + (reg == 0 ? 1 : -1));
            } else if (reg == 2 || reg == 3) { /* call */
                if (mod == 3) {
                    ctx->indirectCall = TRUE;
                    ctx->score += 8;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "Indirect_Call_Reg ");
                }
            } else if (reg == 4 || reg == 5) { /* jmp */
                if (mod == 3) {
                    INT64 v = baScGetReg(&ctx->regs, rm);
                    if (v >= 0 && v < (INT64)codeSize) { rip = (ULONG)v; continue; }
                }
            } else if (reg == 6 || reg == 7) { /* call/jmp mem */
                ctx->indirectCall = TRUE;
                ctx->score += 8;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "Indirect_Call_Mem ");
            }
            rip += 2; continue;
        }

        /* ── IMUL (69/6B) — API hashing核心 ── */
        if (opcode == 0x69 && rip + 5 < codeSize) {
            UCHAR modrm = code[rip + 1];
            UCHAR rm = modrm & 7, reg = (modrm >> 3) & 7;
            if (rex & 0x1) rm |= 8;
            if (rex & 0x2) reg |= 8;
            INT64 a = baScGetReg(&ctx->regs, rm);
            INT64 imm = baScReadI32(code + rip + 2);
            baScSetReg(&ctx->regs, reg, a * imm);
            ctx->score += 4;
            kStrCat(ctx->techniques, sizeof(ctx->techniques), "IMUL_HashOp ");
            rip += 6; continue;
        }
        if (opcode == 0x6B && rip + 2 < codeSize) {
            UCHAR modrm = code[rip + 1];
            UCHAR rm = modrm & 7, reg = (modrm >> 3) & 7;
            if (rex & 0x1) rm |= 8;
            if (rex & 0x2) reg |= 8;
            INT64 a = baScGetReg(&ctx->regs, rm);
            INT64 imm = (INT8)code[rip + 2];
            baScSetReg(&ctx->regs, reg, a * imm);
            ctx->score += 4;
            kStrCat(ctx->techniques, sizeof(ctx->techniques), "IMUL_HashOp ");
            rip += 3; continue;
        }

        /* ── ROL/ROR (C1) ── */
        if (opcode == 0xC1 && rip + 2 < codeSize) {
            UCHAR modrm = code[rip + 1];
            UCHAR rm = modrm & 7;
            if (rex & 0x1) rm |= 8;
            UCHAR op = (modrm >> 3) & 7;
            UCHAR cnt = code[rip + 2];
            if (op == 0 || op == 1) {
                INT64 v = baScGetReg(&ctx->regs, rm);
                if (cnt > 0 && cnt <= 64) {
                    if (op == 0) v = (v << cnt) | (v >> (64 - cnt));
                    else         v = (v >> cnt) | (v << (64 - cnt));
                }
                baScSetReg(&ctx->regs, rm, v);
                ctx->score += 3;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "Rotate_Op ");
            }
            rip += 3; continue;
        }

        /* ── NOP (90) ── */
        if (opcode == 0x90) {
            if (!ctx->hasNopSled) {
                ULONG nopCount = 1;
                while (rip + 1 < codeSize && code[rip + 1] == 0x90) { nopCount++; rip++; }
                if (nopCount >= 6) {
                    ctx->hasNopSled = TRUE;
                    ctx->score += 8;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "NOP_Sled ");
                    kStrCat(ctx->families, sizeof(ctx->families), "Generic ");
                }
            }
            rip++; continue;
        }

        /* ── INT3 (CC) ── */
        if (opcode == 0xCC) {
            if (!ctx->hasInt3Seq) {
                ULONG int3Count = 1;
                while (rip + 1 < codeSize && code[rip + 1] == 0xCC) { int3Count++; rip++; }
                if (int3Count >= 3) {
                    ctx->hasInt3Seq = TRUE;
                    ctx->score += 6;
                    kStrCat(ctx->techniques, sizeof(ctx->techniques), "INT3_Seq ");
                }
            }
            rip++; continue;
        }

        /* ── REP prefix ── */
        if (opcode == 0xF3 && rip + 1 < codeSize) {
            UCHAR next = code[rip + 1];
            if (next == 0xAE) { /* repnz scasb */
                ctx->score += 3;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "StringSearch ");
            } else if (next == 0xA5) { /* rep movsq */
                ctx->score += 5;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "MemCopy_RepMovs ");
            }
            rip += 2; continue;
        }

        /* ── PUSH imm (68/6A) ── */
        if (opcode == 0x68 && rip + 4 < codeSize) {
            baScSimPush(ctx, baScReadI32(code + rip + 1));
            rip += 5; continue;
        }
        if (opcode == 0x6A && rip + 1 < codeSize) {
            baScSimPush(ctx, (INT8)code[rip + 1]);
            rip += 2; continue;
        }

        /* ── CMP eax, imm32 (3D) — 仅在API hash上下文中加分 ── */
        if (opcode == 0x3D && rip + 4 < codeSize) {
            /* 仅在已有模块遍历或导出解析时，cmp才可能是hash比较 */
            if (ctx->moduleWalk || ctx->exportParse) {
                ctx->score += 2;
                kStrCat(ctx->techniques, sizeof(ctx->techniques), "Hash_Compare ");
            }
            rip += 5; continue;
        }

        /* ── 未识别指令: 跳过 ── */
        rip++;
        if (opcode == 0x0F && rip < codeSize) rip++;
        continue;
    }

    /* ── 后处理 ── */
    if (ctx->hitSyscall && !ctx->pebAccess) {
        ctx->score += 5;
        kStrCat(ctx->techniques, sizeof(ctx->techniques), "DirectSyscall ");
    }
    if (ctx->xorDecrypt) {
        ctx->score += 5;
        kStrCat(ctx->families, sizeof(ctx->families), "EncryptedPayload ");
    }
    if (ctx->stackOverflow) {
        /* 栈溢出是危险信号，但不直接加分 */
    }
}

/* ── 主入口 ── */
static BOOLEAN baDetectShellcodeFeatures(const UCHAR* data, ULONG size, PBA_SC_RESULT result)
{
    if (data == NULL || size < 8 || result == NULL)
        return FALSE;

    BA_SC_CTX ctx;
    baScSimulateExecute(data, size, &ctx);

    result->score = ctx.score;
    result->featureCount = 0;

    if (ctx.hitSyscall)     result->featureCount++;
    if (ctx.pebAccess)      result->featureCount++;
    if (ctx.moduleWalk)     result->featureCount++;
    if (ctx.exportParse)    result->featureCount++;
    if (ctx.indirectCall)   result->featureCount++;
    if (ctx.hasNopSled)     result->featureCount++;
    if (ctx.hasInt3Seq)     result->featureCount++;
    if (ctx.xorDecrypt)     result->featureCount++;
    if (ctx.selfModifying)  result->featureCount++;

    kStrCat(result->families, sizeof(result->families), ctx.families);
    kStrCat(result->techniques, sizeof(result->techniques), ctx.techniques);

    /* 判定: 评分阈值 + 特征数要求 */
    if (ctx.score >= BA_SC_SCORE_THRESHOLD && result->featureCount >= 2)
        return TRUE;
    if (ctx.score >= 30 && result->featureCount >= 3)
        return TRUE;

    return FALSE;
}

VOID BehaviorHandleEtwMemoryEvent(PETW_MEMORY_EVENT_DATA pEvent)
{
    CHAR callerName[64] = {0};
    CHAR targetName[64] = {0};
    BOOLEAN isExecutable = FALSE;

    if (pEvent == NULL)
        return;

    __try {

    if (!g_baInitialized)
        return;

    if (!g_bBehaviorDetectionEnabled)
        return;

    /* 跳过 PID 0 */
    if (pEvent->CallerPid == 0)
        return;

    /* 跳过受信任主程序 PID（在自身操作检测之前，避免误报主程序） */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pEvent->CallerPid == g_TrustedMainPid)
        return;

    /* 白名单放行（在自身操作检测之前，避免误报白名单进程） */
    if (WhitelistCheckByPid(pEvent->CallerPid) == 1)
        return;

    /* ── Self-VirtualProtect (RW→RX) 检测 ──
     * 自身操作的 ProtectVM 不一定是恶意（JIT 编译器、.NET CLR 等合法场景），
     * 但非受信任进程对自身内存执行 RW→RX 是典型的 shellcode/载荷解密行为。
     * 在此处检测后 return，不影响后续远程注入检测逻辑。 */
    if (pEvent->TargetPid != 0 && pEvent->CallerPid == pEvent->TargetPid)
    {
        /* 仅检测 ProtectVM 事件（EventId 2=remote, 22=kernel caller） */
        if ((pEvent->EventId == 2 || pEvent->EventId == 22) &&
            baEtwIsExecutableProtection(pEvent->Protection))
        {
            baEtwGetProcessNameByPid(pEvent->CallerPid, callerName, sizeof(callerName));

            /* 排除受信任开发者工具/安全软件/第三方软件（JIT 编译器等合法场景）
             * 已删除，不再区分受信任进程。 */
            if (!baEtwIsSystemProcessByPid(pEvent->CallerPid))
            {
                INT32 idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
                if (idx >= 0)
                {
                    CHAR evBuf[200];
                    RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                        "Self-VirtualProtect to executable (RW->RX): addr=0x%llX size=0x%llX prot=0x%X",
                        (unsigned long long)pEvent->BaseAddress,
                        (unsigned long long)pEvent->RegionSize,
                        pEvent->Protection);
                    addIndicator(idx, BA_IND_MEM_SELF_PROTECT_EXECUTABLE, evBuf);
                    // 额外检测：非系统进程将非MEM_IMAGE内存设为RWX（PAGE_EXECUTE_READWRITE）
                    if (baEtwIsWritableExecutableProtection(pEvent->Protection))
                    {
                        if (!BehaviorIsAddressInLoadedModule(pEvent->CallerPid, (PVOID)(ULONG_PTR)pEvent->BaseAddress)) {
                            addIndicator(idx, BA_IND_MEM_NONSYSTEM_RWX,
                                evBuf);
                            /* 非系统进程将非镜像内存改为 RWX = 典型 shellcode/载荷解密行为，
                             * 立即触发实时告警（挂起进程 + 用户决策） */
                            BehaviorHandleInjectionAlertAsync(
                                (INT64)(ULONG_PTR)pEvent->CallerPid, callerName,
                                (INT64)(ULONG_PTR)pEvent->CallerPid, callerName,
                                "MemoryProtection/SelfProtectRWX.T1055", 0, NULL);
                        }
                    }
                    // 额外检测：非系统进程将内存设为只读可执行（PAGE_EXECUTE_READ）
                    else if (pEvent->Protection == PAGE_EXECUTE_READ)
                    {
                        addIndicator(idx, BA_IND_MEM_NONSYSTEM_EXEC_READ, evBuf);
                        /* 非系统进程将内存改为 EXECUTE_READ = 运行时代码生成/载荷解密执行，
                         * 无论地址是否在已加载镜像内，均为可疑行为，立即触发实时告警。 */
                        BehaviorHandleInjectionAlertAsync(
                            (INT64)(ULONG_PTR)pEvent->CallerPid, callerName,
                            (INT64)(ULONG_PTR)pEvent->CallerPid, callerName,
                            "MemoryProtection/SelfProtectExecRead.T1055", 0, NULL);
                    }
                    /* Shellcode深度检测：分析被保护内存的内容 */
                    if (pEvent->PayloadSize >= 8) {
                        BA_SC_RESULT scResult;
                        ULONG payloadSize = pEvent->PayloadSize < 256 ? pEvent->PayloadSize : 256;
                        if (baDetectShellcodeFeatures(pEvent->Payload, payloadSize, &scResult)) {
                            CHAR scEv[512] = {0};
                            RtlStringCbPrintfA(scEv, sizeof(scEv),
                                "Shellcode in self-protect [score=%d feat=%d]: %s %s",
                                scResult.score, scResult.featureCount,
                                scResult.families, scResult.techniques);
                            addIndicator(idx, BA_IND_MEM_SHELLCODE_DETECTED, scEv);
                            DriverDbgPrint("[BA-SHELLCODE] Self-protect PID=%lld addr=0x%llX score=%d tech=%s\n",
                                pEvent->CallerPid, pEvent->BaseAddress,
                                scResult.score, scResult.techniques);
                        }
                    }
                    DriverDbgPrint("[BA-ETW] Self-VirtualProtect RX: PID=%lld Name=%s addr=0x%llX prot=0x%X\n",
                        (ULONG)(ULONG_PTR)pEvent->CallerPid, callerName,
                        (unsigned long long)pEvent->BaseAddress, pEvent->Protection);
                }
            }
        }
        /* 自身操作：检测完 VirtualProtect 后 return，跳过远程注入检测 */
        return;
    }

    /* 父子进程放行（正常进程创建会触发对子进程的内存操作） */
    if (pEvent->TargetPid != 0 && baEtwIsParentChild(pEvent->CallerPid, pEvent->TargetPid))
        return;

    /* 源进程为系统关键进程时通常不是恶意注入（减少误报） */
    if (baEtwIsSystemProcessByPid(pEvent->CallerPid))
        return;

    /* 目标进程为系统关键进程时，合法程序（调试器/系统组件）常访问，放行 */
    if (pEvent->TargetPid != 0 && baEtwIsSystemProcessByPid(pEvent->TargetPid))
        return;

    baEtwGetProcessNameByPid(pEvent->CallerPid, callerName, sizeof(callerName));
    if (pEvent->TargetPid != 0) {
        baEtwGetProcessNameByPid(pEvent->TargetPid, targetName, sizeof(targetName));
    }

    /* 受信任的开发者工具/安全软件/第三方软件放行 - 已删除，不再区分受信任进程。
     * 保留系统进程放行逻辑。 */
    DriverDbgPrint("[ETW-TI] Event=%u Caller=%s(PID:%lld) Target=%s(PID:%lld) Addr=0x%llX Size=0x%llX Prot=0x%X\n",
        pEvent->EventId, callerName, pEvent->CallerPid,
        targetName[0] ? targetName : "self", pEvent->TargetPid,
        pEvent->BaseAddress, pEvent->RegionSize, pEvent->Protection);

    /* 统一判断当前内存操作的保护属性是否为可执行 */
    isExecutable = baEtwIsExecutableProtection(pEvent->Protection);

    switch (pEvent->EventId)
    {
    case 1:  /* ALLOCVM_REMOTE */
    case 21: /* ALLOCVM_REMOTE_KERNEL_CALLER */
        if (isExecutable) {
            /* 远程分配可执行内存：仅记录行为指标，由行为分析引擎综合研判，
             * 避免 JIT/调试器等合法场景误报。 */
            BehaviorRecordMemoryEvent(
                pEvent->CallerPid, callerName,
                targetName, pEvent->TargetPid, 0,
                BA_MOP_RemoteAllocExecutable,
                FALSE,
                NULL);
        } else if (baEtwIsWritableProtection(pEvent->Protection)) {
            /* 可写非可执行：记录到地址缓存，供后续 ProtectVM 链式检测，不弹窗 */
            baEtwRecordAlloc(pEvent->TargetPid, pEvent->BaseAddress,
                pEvent->RegionSize, pEvent->Protection);
        }
        break;

    case 2:  /* PROTECTVM_REMOTE */
    case 22: /* PROTECTVM_REMOTE_KERNEL_CALLER */
        if (isExecutable) {
            ULONG originalProtection = 0;
            BOOLEAN wasRecorded = baEtwFindAndRemoveAlloc(
                pEvent->TargetPid, pEvent->BaseAddress, &originalProtection);
            BOOLEAN hasChain = FALSE;

            if (wasRecorded && !baEtwIsExecutableProtection(originalProtection)) {
                /* 典型的 shellcode 模式：RW 分配 -> RX/RWX 保护 */
                BehaviorRecordMemoryEvent(
                    pEvent->CallerPid, callerName,
                    targetName, pEvent->TargetPid, 0,
                    BA_MOP_AllocToProtectChain,
                    FALSE,
                    NULL);
                hasChain = TRUE;
            }

            /* Write -> Protect(Exec) 链式检测 */
            if (baEtwFindRecentWrite(pEvent->TargetPid, pEvent->BaseAddress, pEvent->RegionSize)) {
                BehaviorRecordMemoryEvent(
                    pEvent->CallerPid, callerName,
                    targetName, pEvent->TargetPid, 0,
                    BA_MOP_WriteToProtectChain,
                    FALSE,
                    NULL);
                hasChain = TRUE;
            }

            /* 仅在检测到链式行为（RW->RX 或 Write->RX）时才实时告警，
             * 避免合法 JIT/调试器的正常内存保护修改被误报。 */
            if (hasChain) {
                if (baEtwShouldAlert(pEvent->CallerPid, pEvent->TargetPid,
                    "DefenseEvasion/Injection:RemoteProtectExecutable.T1055")) {
                    BehaviorHandleInjectionAlertAsync(
                        pEvent->CallerPid, callerName,
                        pEvent->TargetPid, targetName,
                        "DefenseEvasion/Injection:RemoteProtectExecutable.T1055", 0, NULL);
                }
            }
            /* 只有真正改为可执行保护时才记录 executable 指标 */
            BehaviorRecordMemoryEvent(
                pEvent->CallerPid, callerName,
                targetName, pEvent->TargetPid, 0,
                BA_MOP_RemoteProtectExecutable,
                FALSE,
                NULL);

            /* 非系统进程将非MEM_IMAGE内存设为可执行（包括RWX和只读可执行） */
            if (!baEtwIsSystemProcessByPid(pEvent->CallerPid) &&
                baEtwIsNonSystemExecutableProtection(pEvent->Protection))
            {
                if (!BehaviorIsAddressInLoadedModule(pEvent->TargetPid, (PVOID)(ULONG_PTR)pEvent->BaseAddress))
                {
                    INT32 idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
                    if (idx >= 0) {
                        CHAR evBuf[200];
                        if (baEtwIsWritableExecutableProtection(pEvent->Protection)) {
                            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                                "Remote-ProtectVM to RWX: target=0x%llX prot=0x%X",
                                (unsigned long long)pEvent->BaseAddress,
                                pEvent->Protection);
                            addIndicator(idx, BA_IND_MEM_NONSYSTEM_RWX, evBuf);
                        } else if (pEvent->Protection == PAGE_EXECUTE_READ) {
                            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                                "Remote-ProtectVM to ExecRead: target=0x%llX prot=0x%X",
                                (unsigned long long)pEvent->BaseAddress,
                                pEvent->Protection);
                            addIndicator(idx, BA_IND_MEM_NONSYSTEM_EXEC_READ, evBuf);
                        }
                    }
                }
            }

            /* Shellcode深度检测：分析被保护内存的内容 */
            if (pEvent->PayloadSize >= 8) {
                INT32 idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
                if (idx >= 0) {
                    BA_SC_RESULT scResult;
                    ULONG payloadSize = pEvent->PayloadSize < 256 ? pEvent->PayloadSize : 256;
                    if (baDetectShellcodeFeatures(pEvent->Payload, payloadSize, &scResult)) {
                        CHAR scEv[512] = {0};
                        RtlStringCbPrintfA(scEv, sizeof(scEv),
                            "Shellcode in remote-protect [score=%d feat=%d]: %s %s",
                            scResult.score, scResult.featureCount,
                            scResult.families, scResult.techniques);
                        addIndicator(idx, BA_IND_MEM_SHELLCODE_DETECTED, scEv);
                        DriverDbgPrint("[BA-SHELLCODE] Remote-protect PID=%lld target=0x%llX score=%d tech=%s\n",
                            pEvent->CallerPid, pEvent->BaseAddress,
                            scResult.score, scResult.techniques);
                    }
                }
            }
        }
        break;

    case 14: /* WRITEVM_REMOTE */
        baEtwRecordWrite(pEvent->TargetPid, pEvent->BaseAddress, pEvent->RegionSize);
        {
            /* 直接记录带 payload 的指标证据，方便告警展示 shellcode 前 60 字节（HEX 120 字符） */
            int idx = findOrCreatePidIndex(pEvent->CallerPid);
            if (idx >= 0) {
                CHAR evBuf[256] = { 0 };
                int used = 0;
                evBuf[used++] = 'W';
                evBuf[used++] = ':';
                if (pEvent->PayloadSize > 0) {
                    ULONG cap = pEvent->PayloadSize < 60 ? pEvent->PayloadSize : 60;
                    ULONG i;
                    for (i = 0; i < cap && (used + 2) < (int)sizeof(evBuf); i++) {
                        RtlStringCbPrintfA(evBuf + used, sizeof(evBuf) - used, "%02X", pEvent->Payload[i]);
                        used += 2;
                    }
                } else {
                    RtlStringCbCopyA(evBuf + used, sizeof(evBuf) - used, "N/A");
                }
                addIndicator(idx, BA_IND_MEM_ETW_REMOTE_WRITE_MEMORY, evBuf);
                
                /* Shellcode深度检测：分析写入的内存内容 */
                if (pEvent->PayloadSize >= 8) {
                    BA_SC_RESULT scResult;
                    ULONG payloadSize = pEvent->PayloadSize < 256 ? pEvent->PayloadSize : 256;
                    if (baDetectShellcodeFeatures(pEvent->Payload, payloadSize, &scResult)) {
                        CHAR shellcodeEvidence[512] = {0};
                        RtlStringCbPrintfA(shellcodeEvidence, sizeof(shellcodeEvidence),
                            "Shellcode [score=%d features=%d]: %s %s",
                            scResult.score, scResult.featureCount,
                            scResult.families, scResult.techniques);
                        addIndicator(idx, BA_IND_MEM_SHELLCODE_DETECTED, shellcodeEvidence);
                        DriverDbgPrint("[BA-SHELLCODE] PID=%lld addr=0x%llX score=%d features=%d tech=%s\n",
                            pEvent->CallerPid, pEvent->BaseAddress,
                            scResult.score, scResult.featureCount, scResult.techniques);
                    }
                }
            }
        }
        break;

    case 4:  /* QUEUEUSERAPC_REMOTE */
        BehaviorRecordMemoryEvent(
            pEvent->CallerPid, callerName,
            targetName, pEvent->TargetPid, 0,
            BA_MOP_RemoteQueueApc,
            FALSE,
            NULL);
        break;

    case 5:  /* SETTHREADCONTEXT_REMOTE */
        BehaviorRecordMemoryEvent(
            pEvent->CallerPid, callerName,
            targetName, pEvent->TargetPid, 0,
            BA_MOP_RemoteSetThreadContext,
            FALSE,
            NULL);
        break;

    case 3:  /* MAPVIEW_REMOTE */
    case 23: /* MAPVIEW_REMOTE_KERNEL_CALLER */
        if (isExecutable) {
            /* 远程映射可执行内存：仅记录行为指标，由行为分析引擎综合研判，
             * 避免合法共享内存/模块映射被误报。 */
            BehaviorRecordMemoryEvent(
                pEvent->CallerPid, callerName,
                targetName, pEvent->TargetPid, 0,
                BA_MOP_RemoteMapViewExecutable,
                FALSE,
                NULL);
        }
        break;
    }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[BA-ETW-MEMORY] Exception caught, dropping event\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorHandleEtwNetworkEvent — 处理 ETW 网络事件用于 C2 检测
 *
 * 用户态 ETW Network Consumer 通过 IOCTL_BEHAVIOR_ETW_NETWORK_EVENT 下发
 * Microsoft-Windows-TCPIP 的网络连接事件，这里进行 C2 行为分析。
 * ═══════════════════════════════════════════════════════════════════════════ */
VOID BehaviorHandleEtwNetworkEvent(PETW_NETWORK_EVENT_DATA pEvent)
{
    CHAR callerName[64] = {0};
    CHAR remoteAddrStr[64] = {0};

    if (pEvent == NULL)
        return;

    __try {

    if (!g_baInitialized)
        return;

    if (!g_bBehaviorDetectionEnabled)
        return;

    /* 跳过 PID 0 */
    if (pEvent->CallerPid == 0)
        return;

    /* 跳过受信任主程序 PID */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pEvent->CallerPid == g_TrustedMainPid)
        return;

    /* 白名单放行 */
    if (WhitelistCheckByPid((INT64)(ULONG_PTR)pEvent->CallerPid) == 1)
        return;

    /* 系统进程放行 */
    if (baEtwIsSystemProcessByPid((INT64)(ULONG_PTR)pEvent->CallerPid))
        return;

    /* 获取源进程名称 */
    baEtwGetProcessNameByPid((INT64)(ULONG_PTR)pEvent->CallerPid, callerName, sizeof(callerName));

    /* 格式化远程地址 */
    if (pEvent->RemoteAddressType == 0 && pEvent->RemotePort != 0) {
        /* IPv4 */
        RtlStringCbPrintfA(remoteAddrStr, sizeof(remoteAddrStr), "%u.%u.%u.%u:%u",
            pEvent->RemoteAddress[0], pEvent->RemoteAddress[1],
            pEvent->RemoteAddress[2], pEvent->RemoteAddress[3],
            pEvent->RemotePort);
    } else if (pEvent->RemoteAddressType == 1 && pEvent->RemotePort != 0) {
        RtlStringCbCopyA(remoteAddrStr, sizeof(remoteAddrStr), "[IPv6]:");
        RtlStringCbCatA(remoteAddrStr, sizeof(remoteAddrStr), "unknown");
    }

    DriverDbgPrint("[ETW-NET] Event=%u Caller=%s(PID:%lld) Addr=%s Proto=%u Outbound=%u\n",
        pEvent->EventId, callerName, (ULONG)(ULONG_PTR)pEvent->CallerPid,
        remoteAddrStr[0] ? remoteAddrStr : "unknown",
        pEvent->Protocol, pEvent->IsOutbound);

    /* DNS 查询可疑性检测（EventId == 4）
     * 若源进程带有注入/脚本/可疑来源等上下文，则标记为可疑 DNS 行为 */
    if (pEvent->EventId == 4) {
        int idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
        if (idx >= 0) {
            BOOLEAN hasSuspiciousContext = FALSE;
            for (int i = 0; i < BA_MAX_INDICATORS; i++) {
                if (g_baPidIndicators[idx][i] > 0) {
                    BA_INDICATOR ind = (BA_INDICATOR)i;
                    if (ind == BA_IND_PROC_SCRIPT_INTERPRETER ||
                        ind == BA_IND_PROC_FROM_TEMP_DIR ||
                        ind == BA_IND_PROC_FROM_APPDATA_DIR ||
                        ind == BA_IND_PROC_UNSIGNED ||
                        ind == BA_IND_MEM_CROSS_PROCESS_WRITE ||
                        ind == BA_IND_MEM_INJECTION_CHAIN ||
                        ind == BA_IND_MEM_PROCESS_HOLLOWING ||
                        ind == BA_IND_PROC_APC_INJECTION ||
                        ind == BA_IND_PROC_MAP_SECTION) {
                        hasSuspiciousContext = TRUE;
                        break;
                    }
                }
            }
            if (hasSuspiciousContext) {
                CHAR evidence[128] = {0};
                RtlStringCbPrintfA(evidence, sizeof(evidence), "DNS:%s", remoteAddrStr);
                addIndicator(idx, BA_IND_NET_SUSPICIOUS_DNS, evidence);
            }
        }
    }

    /* C2 检测逻辑 */
    {
        BOOLEAN isSuspicious = FALSE;
        BOOLEAN isKnownBadPort = FALSE;
        BOOLEAN isHighPort = FALSE;

        /* 已知 C2 常见端口（可扩展为动态黑名单） */
        static const USHORT s_c2Ports[] = {
            4444, 5555, 6666, 7777, 8888, 9999,  /* 常见反向 shell */
            1234, 12345, 23456, 31337,            /* 常见后门 */
            4445, 4446, 4447,                      /* Cobalt Strike */
            8080, 8443, 9001, 9030,               /* 常见 C2 over HTTP/S */
            53, 137, 138, 139,                    /* DNS/SMB 滥用 */
            0
        };
        static const USHORT s_safeHighPorts[] = {
            49152, 49153, 49154, 49155,  /* Windows RPC */
            5357, 5358,                   /* WSDAPI */
            0
        };

        /* 检查是否为已知 C2 端口 */
        for (int i = 0; s_c2Ports[i] != 0; i++) {
            if (pEvent->RemotePort == s_c2Ports[i]) {
                isKnownBadPort = TRUE;
                break;
            }
        }

        /* 检查是否为安全高端口（Windows 系统动态端口范围 49152-65535 中的特定端口） */
        if (pEvent->RemotePort >= 1024 && pEvent->RemotePort < 49152) {
            isHighPort = TRUE;
        }

        /* 判断条件：
         * 1. 出站连接到已知 C2 端口
         * 2. 非系统进程连接到高危端口
         * 3. 与注入指标关联的进程发起网络连接 */
        if (pEvent->IsOutbound && isKnownBadPort) {
            isSuspicious = TRUE;
        } else if (pEvent->IsOutbound && isHighPort) {
            /* 检查该进程是否已有注入行为指标 */
            int idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
            if (idx >= 0) {
                /* 检查是否有注入相关指标 */
                for (int i = 0; i < BA_MAX_INDICATORS; i++) {
                    if (g_baPidIndicators[idx][i] > 0) {
                        BA_INDICATOR ind = (BA_INDICATOR)i;
                        if (ind == BA_IND_MEM_CROSS_PROCESS_WRITE ||
                            ind == BA_IND_MEM_INJECTION_CHAIN ||
                            ind == BA_IND_MEM_PROCESS_HOLLOWING ||
                            ind == BA_IND_MEM_ETW_REMOTE_ALLOC_EXECUTABLE ||
                            ind == BA_IND_MEM_ETW_REMOTE_PROTECT_EXECUTABLE ||
                            ind == BA_IND_MEM_ETW_REMOTE_WRITE_MEMORY ||
                            ind == BA_IND_PROC_APC_INJECTION ||
                            ind == BA_IND_PROC_MAP_SECTION) {
                            isSuspicious = TRUE;
                            break;
                        }
                    }
                }
            }
        }

        if (isSuspicious) {
            /* 记录 C2 连接指标 */
            int idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
            if (idx >= 0) {
                CHAR evidence[128] = {0};
                RtlStringCbPrintfA(evidence, sizeof(evidence), "C2:%s", remoteAddrStr);
                addIndicator(idx, BA_IND_NET_C2_CONNECT, evidence);
                /* 同时补充旧版 NETWORK_C2_CONNECT 指标，保持对历史画像的兼容性，提升检出率 */
                addIndicator(idx, BA_IND_NETWORK_C2_CONNECT, evidence);
            }

            DriverDbgPrint("[ETW-NET] C2 connection detected: %s (PID:%lld) -> %s\n",
                callerName, (ULONG)(ULONG_PTR)pEvent->CallerPid, remoteAddrStr);

            /* 实时告警 */
            BehaviorHandleInjectionAlertAsync(
                (INT64)(ULONG_PTR)pEvent->CallerPid, callerName,
                0, "remote",
                "CommandAndControl/C2Connection.T1102", 0, NULL);
        }

        /* DoH (DNS over HTTPS) C2 通信检测：
         * 病毒常通过 DoH 隐藏 C2 通信（如 dns.alidns.com/dns-query）。
         * 检测条件（全部满足才触发，确保低误报）：
         *   1. 出站 TCP 连接（EventId == 1）
         *   2. 目标端口为 443（HTTPS）
         *   3. 目标 IP 为已知 DoH provider（223.5.5.5, 8.8.8.8, 1.1.1.1, 9.9.9.9 等）
         *   4. 进程已有可疑指标（FROM_TEMP/UNSIGNED/INJECTION 等）— 浏览器/系统服务已被前面过滤
         * 注意：此检测需要 R3 ETW consumer 实现（IOCTL_BEHAVIOR_ETW_NETWORK_EVENT）才能生效。 */
        if (!isSuspicious && pEvent->EventId == 1 && pEvent->IsOutbound &&
            pEvent->RemotePort == 443 && pEvent->RemoteAddressType == 0)
        {
            /* 已知 DoH provider IPv4 地址 */
            static const UCHAR dohIPs[][4] = {
                {223, 5, 5, 5},     /* dns.alidns.com (AliDNS) */
                {223, 6, 6, 6},     /* dns.alidns.com (AliDNS) */
                {8, 8, 8, 8},       /* dns.google */
                {8, 8, 4, 4},       /* dns.google */
                {1, 1, 1, 1},       /* cloudflare-dns.com */
                {1, 0, 0, 1},       /* cloudflare-dns.com */
                {9, 9, 9, 9},       /* dns.quad9.net */
                {149, 112, 112, 112}, /* dns.quad9.net */
                {208, 67, 222, 222},  /* doh.opendns.com */
                {208, 67, 220, 220},  /* doh.opendns.com */
            };
            BOOLEAN isDoHIP = FALSE;
            int di;
            for (di = 0; di < (int)(sizeof(dohIPs) / sizeof(dohIPs[0])); di++) {
                if (pEvent->RemoteAddress[0] == dohIPs[di][0] &&
                    pEvent->RemoteAddress[1] == dohIPs[di][1] &&
                    pEvent->RemoteAddress[2] == dohIPs[di][2] &&
                    pEvent->RemoteAddress[3] == dohIPs[di][3]) {
                    isDoHIP = TRUE;
                    break;
                }
            }

            if (isDoHIP) {
                int idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
                if (idx >= 0) {
                    BOOLEAN hasSuspiciousContext = FALSE;
                    int sci;
                    for (sci = 0; sci < BA_MAX_INDICATORS; sci++) {
                        if (g_baPidIndicators[idx][sci] > 0) {
                            BA_INDICATOR ind = (BA_INDICATOR)sci;
                            if (ind == BA_IND_PROC_SCRIPT_INTERPRETER ||
                                ind == BA_IND_PROC_FROM_TEMP_DIR ||
                                ind == BA_IND_PROC_FROM_APPDATA_DIR ||
                                ind == BA_IND_PROC_UNSIGNED ||
                                ind == BA_IND_MEM_CROSS_PROCESS_WRITE ||
                                ind == BA_IND_MEM_INJECTION_CHAIN ||
                                ind == BA_IND_MEM_PROCESS_HOLLOWING ||
                                ind == BA_IND_PROC_APC_INJECTION ||
                                ind == BA_IND_PROC_MAP_SECTION ||
                                ind == BA_IND_MEM_SELF_PROTECT_EXECUTABLE) {
                                hasSuspiciousContext = TRUE;
                                break;
                            }
                        }
                    }
                    if (hasSuspiciousContext) {
                        CHAR evidence[128] = {0};
                        RtlStringCbPrintfA(evidence, sizeof(evidence),
                            "DoH C2:%s (DNS over HTTPS to known DoH provider)",
                            remoteAddrStr);
                        addIndicator(idx, BA_IND_NET_SUSPICIOUS_DNS, evidence);
                        addIndicator(idx, BA_IND_NET_C2_CONNECT, evidence);
                        addIndicator(idx, BA_IND_NETWORK_C2_CONNECT, evidence);

                        DriverDbgPrint("[ETW-NET] DoH C2 detected: %s (PID:%lld) -> %s\n",
                            callerName, (ULONG)(ULONG_PTR)pEvent->CallerPid, remoteAddrStr);
                    }
                }
            }
        }

        /* 非C2但出站到高端口的可疑网络活动（原 else if 分支，改为独立 if 保持逻辑等价） */
        if (!isSuspicious && pEvent->IsOutbound && isHighPort) {
            /* 记录为可疑网络活动，但不立即告警 */
            int idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
            if (idx >= 0) {
                CHAR evidence[128] = {0};
                RtlStringCbPrintfA(evidence, sizeof(evidence), "NET:%s", remoteAddrStr);
                addIndicator(idx, BA_IND_NET_UNKNOWN_PORT, evidence);
            }
        }

        /* 注入进程的网络活动：记录 NET_PROCESS_NETWORK 指标 */
        if (pEvent->IsOutbound) {
            int idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
            if (idx >= 0) {
                BOOLEAN hasInjectionIndicator = FALSE;
                for (int i = 0; i < BA_MAX_INDICATORS; i++) {
                    if (g_baPidIndicators[idx][i] > 0) {
                        BA_INDICATOR ind = (BA_INDICATOR)i;
                        if (ind == BA_IND_MEM_CROSS_PROCESS_WRITE ||
                            ind == BA_IND_MEM_INJECTION_CHAIN ||
                            ind == BA_IND_MEM_PROCESS_HOLLOWING ||
                            ind == BA_IND_MEM_ETW_REMOTE_ALLOC_EXECUTABLE ||
                            ind == BA_IND_MEM_ETW_REMOTE_PROTECT_EXECUTABLE ||
                            ind == BA_IND_MEM_ETW_REMOTE_WRITE_MEMORY ||
                            ind == BA_IND_PROC_APC_INJECTION ||
                            ind == BA_IND_PROC_MAP_SECTION ||
                            ind == BA_IND_MEM_ETW_REMOTE_QUEUE_APC ||
                            ind == BA_IND_MEM_ETW_REMOTE_SET_THREAD_CONTEXT ||
                            ind == BA_IND_MEM_ETW_REMOTE_MAP_VIEW_EXECUTABLE) {
                            hasInjectionIndicator = TRUE;
                            break;
                        }
                    }
                }
                if (hasInjectionIndicator) {
                    CHAR evidence[128] = {0};
                    RtlStringCbPrintfA(evidence, sizeof(evidence), "InjectNet:%s", remoteAddrStr);
                    addIndicator(idx, BA_IND_NET_PROCESS_NETWORK, evidence);
                }
            }
        }
    }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[BA-ETW-NETWORK] Exception caught, dropping event\n");
    }
}

/* ============================================================================
 * ETW syscall 事件处理：检测 direct / indirect syscall
 * 用户态 ETW Consumer 订阅 Microsoft-Windows-Kernel-Syscall 或
 * Microsoft-Windows-Threat-Intelligence 带 call stack 的事件，
 * 解析出返回地址、syscall 指令地址、调用来源模块后下发给驱动。
 * ========================================================================== */
/* ── 常用 Windows syscall 号映射表（Win10 1507-22H2 / Win11 21H2-24H2）
 * 同一 syscall 在不同 build 中号码不同，均列入。多个版本覆盖确保广谱检出力。
 * 共 20 类 syscall，覆盖注入/凭据/提权/进程操作/信息查询等攻击面。 */
static const ULONG g_SyscallAllocVmNums[]       = { 0x18, 0x19, 0 };
static const ULONG g_SyscallProtectVmNums[]     = { 0x50, 0x4F, 0x4E, 0x4D, 0 };
static const ULONG g_SyscallWriteVmNums[]       = { 0x3A, 0x39, 0x38, 0 };
static const ULONG g_SyscallReadVmNums[]        = { 0x3F, 0x3E, 0x3D, 0 };
static const ULONG g_SyscallCreateThreadNums[]  = { 0xC1, 0xC0, 0xBF, 0xBE, 0 };
static const ULONG g_SyscallQueueApcNums[]      = { 0x45, 0x44, 0x43, 0 };
static const ULONG g_SyscallMapViewNums[]       = { 0x28, 0x27, 0x26, 0 };
static const ULONG g_SyscallOpenProcessNums[]   = { 0x26, 0x25, 0x24, 0 };
static const ULONG g_SyscallSetContextNums[]    = { 0x13, 0x12, 0x11, 0 };
static const ULONG g_SyscallResumeThreadNums[]  = { 0x52, 0x51, 0x50, 0x4F, 0 };
static const ULONG g_SyscallTokenManipNums[]    = { 0x40, 0x3F, 0x3E, 0 };  /* AdjustPrivilegesToken */
static const ULONG g_SyscallHandleDupNums[]     = { 0x42, 0x41, 0x40, 0 };  /* DuplicateObject */
static const ULONG g_SyscallCreateProcessNums[] = { 0xB9, 0xB8, 0xB7, 0 };  /* CreateUserProcess */
static const ULONG g_SyscallQuerySysInfoNums[]  = { 0x33, 0x32, 0x31, 0 };
static const ULONG g_SyscallQueryProcessNums[]  = { 0x19, 0x18, 0x17, 0 };
static const ULONG g_SyscallCreateSectionNums[] = { 0x4A, 0x49, 0x48, 0 };
static const ULONG g_SyscallUnmapViewNums[]     = { 0x2A, 0x29, 0x28, 0 };  /* UnmapViewOfSection（空心化） */
/* 扩展 syscall 号列表：覆盖 Win10 1507-22H2 / Win11 21H2-24H2
 * syscall 号随 Windows 构建递增（每个新版本 +1），此处列出每个版本的范围。
 * 格式: { Win10_1507, Win10_1511, ..., Win11_24H2, 0 }   */
static const ULONG g_SyscallSuspendThreadNums[]  = { 0x6E, 0x6D, 0x6C, 0 };  /* NtSuspendThread */
static const ULONG g_SyscallGetContextNums[]      = { 0x88, 0x87, 0x86, 0 };  /* NtGetContextThread */
static const ULONG g_SyscallTerminateProcessNums[]= { 0x2C, 0x2B, 0x2A, 0x29, 0 };  /* NtTerminateProcess */
static const ULONG g_SyscallFlushInstCacheNums[]  = { 0x61, 0x60, 0x5F, 0 };  /* NtFlushInstructionCache */
static const ULONG g_SyscallCreateKeyNums[]       = { 0x1D, 0x1C, 0x1B, 0 };  /* NtCreateKey */
static const ULONG g_SyscallSetValueKeyNums[]     = { 0x5D, 0x5C, 0x5B, 0 };  /* NtSetValueKey */
static const ULONG g_SyscallCreateFileNums[]      = { 0x55, 0x54, 0x53, 0 };  /* NtCreateFile */
static const ULONG g_SyscallDeleteFileNums[]      = { 0x34, 0x33, 0x32, 0 };  /* NtDeleteFile */
static const ULONG g_SyscallLoadDriverNums[]      = { 0xA0, 0x9F, 0x9E, 0 };  /* NtLoadDriver */
static const ULONG g_SyscallWorkerFactoryNums[]   = { 0xD2, 0xD1, 0xD0, 0 };  /* NtCreateWorkerFactory */
static const ULONG g_SyscallCreateNamedPipeNums[] = { 0x83, 0x82, 0x81, 0 };  /* NtCreateNamedPipeFile */
static const ULONG g_SyscallSetInfoProcessNums[]  = { 0x1C, 0x1B, 0x1A, 0 };  /* NtSetInformationProcess */

/* 检查 syscall 号是否在给定列表中 */
static BOOLEAN SyscallNumInList(ULONG syscallNum, const ULONG* list)
{
    while (*list != 0) {
        if (syscallNum == *list) return TRUE;
        list++;
    }
    return FALSE;
}

/* 跟踪每个进程的 syscall 类型使用位掩码，用于检测多类型 syscall 组合
 * 使用 32-bit 位掩码，支持最多 32 种 syscall 类型 */
#define SYSCALL_TYPE_ALLOC            0x00000001
#define SYSCALL_TYPE_PROTECT          0x00000002
#define SYSCALL_TYPE_WRITE            0x00000004
#define SYSCALL_TYPE_READ             0x00000008
#define SYSCALL_TYPE_CREATE_THREAD    0x00000010
#define SYSCALL_TYPE_QUEUE_APC        0x00000020
#define SYSCALL_TYPE_MAP_VIEW         0x00000040
#define SYSCALL_TYPE_OPEN_PROCESS     0x00000080
#define SYSCALL_TYPE_SET_CONTEXT      0x00000100
#define SYSCALL_TYPE_RESUME_THREAD    0x00000200
#define SYSCALL_TYPE_TOKEN_MANIP      0x00000400
#define SYSCALL_TYPE_HANDLE_DUP       0x00000800
#define SYSCALL_TYPE_CREATE_PROCESS   0x00001000
#define SYSCALL_TYPE_QUERY_SYSINFO    0x00002000
#define SYSCALL_TYPE_QUERY_PROCESS    0x00004000
#define SYSCALL_TYPE_CREATE_SECTION   0x00008000
#define SYSCALL_TYPE_UNMAP_VIEW       0x00010000
#define SYSCALL_TYPE_SUSPEND_THREAD   0x00020000  /* NtSuspendThread - 空心化/注入前暂停 */
#define SYSCALL_TYPE_GET_CONTEXT      0x00040000  /* NtGetContextThread - shellcode 注入 */
#define SYSCALL_TYPE_TERMINATE_PROC   0x00080000  /* NtTerminateProcess - 杀安全软件 */
#define SYSCALL_TYPE_FLUSH_INST_CACHE 0x00100000  /* NtFlushInstructionCache - shellcode 执行前 */
#define SYSCALL_TYPE_CREATE_KEY       0x00200000  /* NtCreateKey - 注册表持久化 */
#define SYSCALL_TYPE_SET_VALUE_KEY    0x00400000  /* NtSetValueKey - 注册表修改 */
#define SYSCALL_TYPE_CREATE_FILE      0x00800000  /* NtCreateFile - 文件投放 */
#define SYSCALL_TYPE_DELETE_FILE      0x01000000  /* NtDeleteFile - 文件清理/自删除 */
#define SYSCALL_TYPE_LOAD_DRIVER      0x02000000  /* NtLoadDriver - BYOVD 驱动加载 */
#define SYSCALL_TYPE_WORKER_FACTORY   0x04000000  /* NtCreateWorkerFactory - PoolParty 注入 */
#define SYSCALL_TYPE_CREATE_NAMED_PIPE 0x08000000 /* NtCreateNamedPipeFile - C2 命名管道 */
#define SYSCALL_TYPE_SET_INFO_PROCESS 0x10000000  /* NtSetInformationProcess - 进程断链/关键进程 */

/* 统计位掩码中置位的数量 */
static ULONG PopCount(ULONG mask)
{
    ULONG count = 0;
    while (mask) { count += (mask & 1); mask >>= 1; }
    return count;
}

VOID BehaviorHandleEtwSyscallEvent(PETW_SYSCALL_EVENT_DATA pEvent)
{
    BA_INDICATOR indicator;
    CHAR evidence[256] = {0};
    CHAR callerName[64] = {0};
    int idx;
    BA_THREAT_RESULT* pResult = NULL;   /* 堆分配：BA_MAX_EVIDENCE=64 后约 9.4KB，避免内核栈溢出 */
    BOOLEAN isSyscallBypass = FALSE;
    ULONG syscallTypeBit = 0;

    if (pEvent == NULL) {
        return;
    }

    __try {
        if (pEvent->CallerPid == 0) {
            return;
        }

        /* 复制进程名 */
        RtlStringCbCopyNA(callerName, sizeof(callerName),
                          pEvent->ProcessName, sizeof(pEvent->ProcessName) - 1);

        /* ── 误报抑制：受信任进程白名单 ──
         * 1. 系统关键进程（csrss/smss/lsass/wininit/winlogon/services/svchost）直接放行
         * 2. 受信任的开发者工具（Visual Studio、JetBrains 等）放行
         * 3. 受信任的安全产品（杀软/EDR 自身）放行
         * 4. 受信任的第三方软件（M365 Copilot、Edge WebView2 等）放行
         * 5. 系统目录下的进程（System32/SysWOW64）仅当 syscall 指令在合法模块中时放行 */
        if (callerName[0] != '\0') {
            _strlwr(callerName);

            /* 系统关键进程：直接放行 */
            if (strstr(callerName, "csrss.exe") ||
                strstr(callerName, "smss.exe") ||
                strstr(callerName, "lsass.exe") ||
                strstr(callerName, "wininit.exe") ||
                strstr(callerName, "winlogon.exe") ||
                strstr(callerName, "services.exe") ||
                strstr(callerName, "system") ||
                strstr(callerName, "idle")) {
                return;
            }

            /* 受信任的开发者工具/安全软件/第三方软件：放行 - 已删除，不再区分受信任进程。 */

            /* svchost.exe 有合法场景使用 direct syscall（如 RPC 转发），
             * 仅当 syscall 指令在合法模块中时才放行 */
            if (strstr(callerName, "svchost.exe")) {
                CHAR instMod[64] = {0};
                RtlStringCbCopyA(instMod, sizeof(instMod), pEvent->SyscallInstructionModule);
                _strlwr(instMod);
                if (strstr(instMod, "ntdll.dll") ||
                    strstr(instMod, "win32u.dll") ||
                    strstr(instMod, "wow64.dll")) {
                    return;
                }
            }
        }

        idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->CallerPid);
        if (idx < 0) {
            return;
        }

        /* 判断 direct / indirect syscall（用于检测绕过 R3 用户态 Hook）
         * Windows 中合法的 syscall 指令不只存在于 ntdll.dll，还包括 win32u.dll、
         * wow64.dll、wow64cpu.dll、wow64win.dll 等，因此不能简单用"是否在 ntdll"判断。
         * Direct:   syscall 指令本身不在任何合法 syscall 模块中。
         * Indirect: syscall 指令在合法模块中，但调用者不在合法 syscall 模块，也不在
         *           kernelbase/kernel32/user32/gdi32 等正常调用 syscall 的系统 DLL 中，
         *           即攻击者 jmp/call 到合法模块的 syscall 指令以绕过 Hook。 */
        CHAR hookFlag[16] = {0};
        if (pEvent->IsHookedSyscall) {
            RtlStringCbCopyA(hookFlag, sizeof(hookFlag), "HookBypass");
        } else {
            RtlStringCbCopyA(hookFlag, sizeof(hookFlag), "-");
        }

        if (pEvent->IsDirectSyscall) {
            indicator = BA_IND_MEM_DIRECT_SYSCALL;
            RtlStringCbPrintfA(evidence, sizeof(evidence),
                "DirectSyscall[%s] PID:%lld Num:0x%X Ret:%p Inst:%p InstMod:%s",
                hookFlag, pEvent->CallerPid, pEvent->SyscallNumber,
                (PVOID)(ULONG_PTR)pEvent->ReturnAddress,
                (PVOID)(ULONG_PTR)pEvent->SyscallInstructionAddress,
                pEvent->SyscallInstructionModule);
            isSyscallBypass = TRUE;
        } else if (pEvent->IsIndirectSyscall) {
            indicator = BA_IND_MEM_INDIRECT_SYSCALL;
            RtlStringCbPrintfA(evidence, sizeof(evidence),
                "IndirectSyscall[%s] PID:%lld Num:0x%X Ret:%p Inst:%p InstMod:%s Origin:%p",
                hookFlag, pEvent->CallerPid, pEvent->SyscallNumber,
                (PVOID)(ULONG_PTR)pEvent->ReturnAddress,
                (PVOID)(ULONG_PTR)pEvent->SyscallInstructionAddress,
                pEvent->SyscallInstructionModule,
                (PVOID)(ULONG_PTR)pEvent->CallOriginAddress);
            isSyscallBypass = TRUE;
        } else {
            /* 用户态未做预判定，驱动侧根据模块名做兜底判断 */
            CHAR instModule[64] = {0};
            CHAR callerModule[64] = {0};
            RtlStringCbCopyA(instModule, sizeof(instModule), pEvent->SyscallInstructionModule);
            RtlStringCbCopyA(callerModule, sizeof(callerModule), pEvent->ReturnAddressModule);
            _strlwr(instModule);
            _strlwr(callerModule);

            BOOLEAN instIsLegit = (strstr(instModule, "ntdll.dll") != NULL ||
                                strstr(instModule, "win32u.dll") != NULL ||
                                strstr(instModule, "wow64.dll") != NULL ||
                                strstr(instModule, "wow64cpu.dll") != NULL ||
                                strstr(instModule, "wow64win.dll") != NULL);
            BOOLEAN callerIsLegit = (strstr(callerModule, "ntdll.dll") != NULL ||
                                  strstr(callerModule, "win32u.dll") != NULL ||
                                  strstr(callerModule, "kernel32.dll") != NULL ||
                                  strstr(callerModule, "kernelbase.dll") != NULL ||
                                  strstr(callerModule, "user32.dll") != NULL ||
                                  strstr(callerModule, "gdi32.dll") != NULL ||
                                  strstr(callerModule, "gdiplus.dll") != NULL ||
                                  strstr(callerModule, "advapi32.dll") != NULL ||
                                  strstr(callerModule, "shell32.dll") != NULL ||
                                  strstr(callerModule, "combase.dll") != NULL ||
                                  strstr(callerModule, "rpcrt4.dll") != NULL ||
                                  strstr(callerModule, "crypt32.dll") != NULL ||
                                  strstr(callerModule, "ucrtbase.dll") != NULL ||
                                  strstr(callerModule, "msvcrt.dll") != NULL ||
                                  strstr(callerModule, "wow64.dll") != NULL ||
                                  strstr(callerModule, "wow64cpu.dll") != NULL ||
                                  strstr(callerModule, "wow64win.dll") != NULL);

            if (!instIsLegit) {
                indicator = BA_IND_MEM_DIRECT_SYSCALL;
                RtlStringCbPrintfA(evidence, sizeof(evidence),
                    "DirectSyscall[%s] PID:%lld Num:0x%X Ret:%p InstMod:%s",
                    hookFlag, pEvent->CallerPid, pEvent->SyscallNumber,
                    (PVOID)(ULONG_PTR)pEvent->ReturnAddress,
                    pEvent->SyscallInstructionModule);
                isSyscallBypass = TRUE;
            } else if (instIsLegit && pEvent->CallOriginAddress != 0 && !callerIsLegit) {
                /* syscall 指令在合法模块，但调用来源不在合法模块：indirect */
                indicator = BA_IND_MEM_INDIRECT_SYSCALL;
                RtlStringCbPrintfA(evidence, sizeof(evidence),
                    "IndirectSyscall[%s] PID:%lld Num:0x%X Ret:%p InstMod:%s Origin:%p",
                    hookFlag, pEvent->CallerPid, pEvent->SyscallNumber,
                    (PVOID)(ULONG_PTR)pEvent->ReturnAddress,
                    pEvent->SyscallInstructionModule,
                    (PVOID)(ULONG_PTR)pEvent->CallOriginAddress);
                isSyscallBypass = TRUE;
            } else {
                return;
            }
        }

        addIndicator(idx, indicator, evidence);

        /* ── Syscall 分类追踪：解析 syscall 号，增加细粒度指标 ── */
        if (isSyscallBypass)
        {
            const CHAR* typeName = "Unknown";

            /* 检查 17 类 syscall 号，匹配时添加对应指标和位掩码 */
            if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallAllocVmNums)) {
                syscallTypeBit = SYSCALL_TYPE_ALLOC;
                typeName = "NtAllocVM";
                addIndicator(idx, BA_IND_SYSCALL_ALLOC_VM, "Direct/Indirect NtAllocateVirtualMemory");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallProtectVmNums)) {
                syscallTypeBit = SYSCALL_TYPE_PROTECT;
                typeName = "NtProtectVM";
                addIndicator(idx, BA_IND_SYSCALL_PROTECT_VM, "Direct/Indirect NtProtectVirtualMemory");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallWriteVmNums)) {
                syscallTypeBit = SYSCALL_TYPE_WRITE;
                typeName = "NtWriteVM";
                addIndicator(idx, BA_IND_SYSCALL_WRITE_VM, "Direct/Indirect NtWriteVirtualMemory");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallReadVmNums)) {
                syscallTypeBit = SYSCALL_TYPE_READ;
                typeName = "NtReadVM";
                addIndicator(idx, BA_IND_SYSCALL_READ_VM, "Direct/Indirect NtReadVirtualMemory");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallCreateThreadNums)) {
                syscallTypeBit = SYSCALL_TYPE_CREATE_THREAD;
                typeName = "NtCreateThread";
                addIndicator(idx, BA_IND_SYSCALL_CREATE_THREAD, "Direct/Indirect NtCreateThreadEx");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallQueueApcNums)) {
                syscallTypeBit = SYSCALL_TYPE_QUEUE_APC;
                typeName = "NtQueueApc";
                addIndicator(idx, BA_IND_SYSCALL_QUEUE_APC, "Direct/Indirect NtQueueApcThread");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallMapViewNums)) {
                syscallTypeBit = SYSCALL_TYPE_MAP_VIEW;
                typeName = "NtMapView";
                addIndicator(idx, BA_IND_SYSCALL_MAP_VIEW, "Direct/Indirect NtMapViewOfSection");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallOpenProcessNums)) {
                syscallTypeBit = SYSCALL_TYPE_OPEN_PROCESS;
                typeName = "NtOpenProc";
                addIndicator(idx, BA_IND_SYSCALL_OPEN_PROCESS, "Direct/Indirect NtOpenProcess");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallSetContextNums)) {
                syscallTypeBit = SYSCALL_TYPE_SET_CONTEXT;
                typeName = "NtSetCtx";
                addIndicator(idx, BA_IND_SYSCALL_SET_CONTEXT, "Direct/Indirect NtSetContextThread");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallResumeThreadNums)) {
                syscallTypeBit = SYSCALL_TYPE_RESUME_THREAD;
                typeName = "NtResume";
                addIndicator(idx, BA_IND_SYSCALL_RESUME_THREAD, "Direct/Indirect NtResumeThread");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallTokenManipNums)) {
                syscallTypeBit = SYSCALL_TYPE_TOKEN_MANIP;
                typeName = "NtToken";
                addIndicator(idx, BA_IND_SYSCALL_TOKEN_MANIP, "Direct/Indirect NtAdjustPrivilegesToken");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallHandleDupNums)) {
                syscallTypeBit = SYSCALL_TYPE_HANDLE_DUP;
                typeName = "NtDupObj";
                addIndicator(idx, BA_IND_SYSCALL_HANDLE_DUP, "Direct/Indirect NtDuplicateObject");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallCreateProcessNums)) {
                syscallTypeBit = SYSCALL_TYPE_CREATE_PROCESS;
                typeName = "NtCreateProc";
                addIndicator(idx, BA_IND_SYSCALL_CREATE_PROCESS, "Direct/Indirect NtCreateUserProcess");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallQuerySysInfoNums)) {
                syscallTypeBit = SYSCALL_TYPE_QUERY_SYSINFO;
                typeName = "NtQuerySys";
                addIndicator(idx, BA_IND_SYSCALL_QUERY_SYSINFO, "Direct/Indirect NtQuerySystemInformation");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallQueryProcessNums)) {
                syscallTypeBit = SYSCALL_TYPE_QUERY_PROCESS;
                typeName = "NtQueryProc";
                addIndicator(idx, BA_IND_SYSCALL_QUERY_PROCESS, "Direct/Indirect NtQueryInformationProcess");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallCreateSectionNums)) {
                syscallTypeBit = SYSCALL_TYPE_CREATE_SECTION;
                typeName = "NtCreateSec";
                addIndicator(idx, BA_IND_SYSCALL_CREATE_SECTION, "Direct/Indirect NtCreateSection");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallUnmapViewNums)) {
                syscallTypeBit = SYSCALL_TYPE_UNMAP_VIEW;
                typeName = "NtUnmap";
                /* UnmapViewOfSection 单独出现不一定是恶意行为，仅记录位掩码不单独添加指标，
                 * 但在组合链检测中会使用 */
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallSuspendThreadNums)) {
                syscallTypeBit = SYSCALL_TYPE_SUSPEND_THREAD;
                typeName = "NtSuspend";
                addIndicator(idx, BA_IND_SYSCALL_SUSPEND_THREAD, "Direct/Indirect NtSuspendThread");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallGetContextNums)) {
                syscallTypeBit = SYSCALL_TYPE_GET_CONTEXT;
                typeName = "NtGetCtx";
                addIndicator(idx, BA_IND_SYSCALL_GET_CONTEXT, "Direct/Indirect NtGetContextThread");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallTerminateProcessNums)) {
                syscallTypeBit = SYSCALL_TYPE_TERMINATE_PROC;
                typeName = "NtTerminate";
                addIndicator(idx, BA_IND_SYSCALL_TERMINATE_PROCESS, "Direct/Indirect NtTerminateProcess");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallFlushInstCacheNums)) {
                syscallTypeBit = SYSCALL_TYPE_FLUSH_INST_CACHE;
                typeName = "NtFlushIC";
                addIndicator(idx, BA_IND_SYSCALL_FLUSH_INST_CACHE, "Direct/Indirect NtFlushInstructionCache");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallCreateKeyNums)) {
                syscallTypeBit = SYSCALL_TYPE_CREATE_KEY;
                typeName = "NtCreateKey";
                addIndicator(idx, BA_IND_SYSCALL_CREATE_KEY, "Direct/Indirect NtCreateKey");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallSetValueKeyNums)) {
                syscallTypeBit = SYSCALL_TYPE_SET_VALUE_KEY;
                typeName = "NtSetVal";
                addIndicator(idx, BA_IND_SYSCALL_SET_VALUE_KEY, "Direct/Indirect NtSetValueKey");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallCreateFileNums)) {
                syscallTypeBit = SYSCALL_TYPE_CREATE_FILE;
                typeName = "NtCreateFile";
                addIndicator(idx, BA_IND_SYSCALL_CREATE_FILE, "Direct/Indirect NtCreateFile");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallDeleteFileNums)) {
                syscallTypeBit = SYSCALL_TYPE_DELETE_FILE;
                typeName = "NtDeleteFile";
                addIndicator(idx, BA_IND_SYSCALL_DELETE_FILE, "Direct/Indirect NtDeleteFile");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallLoadDriverNums)) {
                syscallTypeBit = SYSCALL_TYPE_LOAD_DRIVER;
                typeName = "NtLoadDrv";
                addIndicator(idx, BA_IND_SYSCALL_LOAD_DRIVER, "Direct/Indirect NtLoadDriver");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallWorkerFactoryNums)) {
                syscallTypeBit = SYSCALL_TYPE_WORKER_FACTORY;
                typeName = "NtWorkerFac";
                addIndicator(idx, BA_IND_SYSCALL_WORKER_FACTORY, "Direct/Indirect NtCreateWorkerFactory");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallCreateNamedPipeNums)) {
                syscallTypeBit = SYSCALL_TYPE_CREATE_NAMED_PIPE;
                typeName = "NtNamedPipe";
                addIndicator(idx, BA_IND_SYSCALL_CREATE_NAMED_PIPE, "Direct/Indirect NtCreateNamedPipeFile");
            } else if (SyscallNumInList(pEvent->SyscallNumber, g_SyscallSetInfoProcessNums)) {
                syscallTypeBit = SYSCALL_TYPE_SET_INFO_PROCESS;
                typeName = "NtSetInfoProc";
                addIndicator(idx, BA_IND_SYSCALL_SET_INFO_PROCESS, "Direct/Indirect NtSetInformationProcess");
            }

            if (syscallTypeBit != 0) {
                g_baPidSyscallTypes[idx] |= syscallTypeBit;

                ULONG mask = g_baPidSyscallTypes[idx];
                ULONG typeCount = PopCount(mask);

                /* ── 多类型 syscall 检测 ── */
                if (typeCount >= 3) {
                    addIndicator(idx, BA_IND_SYSCALL_MULTI_TYPE,
                        "Multiple syscall types used (indicates tool usage)");
                }

                /* ── Syscall 注入链：Alloc + Write + Protect + CreateThread ── */
                ULONG injectionMask = SYSCALL_TYPE_ALLOC | SYSCALL_TYPE_WRITE |
                                      SYSCALL_TYPE_PROTECT | SYSCALL_TYPE_CREATE_THREAD;
                if ((mask & injectionMask) == injectionMask) {
                    addIndicator(idx, BA_IND_SYSCALL_INJECTION_CHAIN,
                        "Syscall injection chain: AllocVM+WriteVM+ProtectVM+CreateThread");
                }

                /* ── Syscall LSASS 凭据窃取链：OpenProcess + ReadVM + MapView ── */
                ULONG lsassChainMask = SYSCALL_TYPE_OPEN_PROCESS | SYSCALL_TYPE_READ |
                                       SYSCALL_TYPE_MAP_VIEW;
                if ((mask & lsassChainMask) == lsassChainMask) {
                    addIndicator(idx, BA_IND_SYSCALL_READ_LSASS_CHAIN,
                        "Syscall LSASS chain: OpenProcess+ReadVM+MapView (credential dump)");
                    DriverDbgPrint("[BA-ETW-SYSCALL] LSASS credential dump chain detected in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── Syscall 令牌窃取链：OpenProcess + DuplicateObject + TokenManip ── */
                ULONG tokenStealMask = SYSCALL_TYPE_OPEN_PROCESS | SYSCALL_TYPE_HANDLE_DUP |
                                       SYSCALL_TYPE_TOKEN_MANIP;
                if ((mask & tokenStealMask) == tokenStealMask) {
                    addIndicator(idx, BA_IND_SYSCALL_TOKEN_STEAL_CHAIN,
                        "Syscall token steal chain: OpenProcess+DuplicateObject+AdjustToken");
                    DriverDbgPrint("[BA-ETW-SYSCALL] Token steal chain detected in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── Syscall 进程空心化：CreateProcess + Suspend + Unmap + Write + Resume ── */
                ULONG hollowMask = SYSCALL_TYPE_CREATE_PROCESS | SYSCALL_TYPE_SUSPEND_THREAD |
                                   SYSCALL_TYPE_UNMAP_VIEW | SYSCALL_TYPE_WRITE | SYSCALL_TYPE_RESUME_THREAD;
                if ((mask & hollowMask) == hollowMask) {
                    addIndicator(idx, BA_IND_SYSCALL_PROCESS_HOLLOW,
                        "Syscall process hollowing: CreateSuspended+Suspend+Unmap+Write+Resume");
                    DriverDbgPrint("[BA-ETW-SYSCALL] Process hollowing chain detected in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── SetContext + Resume 注入（经典 SetThreadContext 注入）── */
                ULONG setCtxMask = SYSCALL_TYPE_SET_CONTEXT | SYSCALL_TYPE_RESUME_THREAD;
                if ((mask & setCtxMask) == setCtxMask) {
                    DriverDbgPrint("[BA-ETW-SYSCALL] SetThreadContext+Resume injection detected in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── Suspend + GetContext + SetContext + Resume（Shellcode 注入经典流程）── */
                ULONG shellcodeInjMask = SYSCALL_TYPE_SUSPEND_THREAD | SYSCALL_TYPE_GET_CONTEXT |
                                         SYSCALL_TYPE_SET_CONTEXT | SYSCALL_TYPE_RESUME_THREAD;
                if ((mask & shellcodeInjMask) == shellcodeInjMask) {
                    DriverDbgPrint("[BA-ETW-SYSCALL] Suspend+GetCtx+SetCtx+Resume shellcode injection in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── Syscall 持久化链：CreateKey + SetValueKey + CreateFile ── */
                ULONG persistenceMask = SYSCALL_TYPE_CREATE_KEY | SYSCALL_TYPE_SET_VALUE_KEY |
                                        SYSCALL_TYPE_CREATE_FILE;
                if ((mask & persistenceMask) == persistenceMask) {
                    addIndicator(idx, BA_IND_SYSCALL_PERSISTENCE_CHAIN,
                        "Syscall persistence chain: CreateKey+SetValueKey+CreateFile");
                    DriverDbgPrint("[BA-ETW-SYSCALL] Persistence chain detected in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── BYOVD 链：LoadDriver + CreateFile（驱动加载 + 文件投放）── */
                ULONG byovdMask = SYSCALL_TYPE_LOAD_DRIVER | SYSCALL_TYPE_CREATE_FILE;
                if ((mask & byovdMask) == byovdMask) {
                    DriverDbgPrint("[BA-ETW-SYSCALL] BYOVD chain: LoadDriver+CreateFile in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── C2 命名管道 + 进程操作：NamedPipe + OpenProcess + CreateThread ── */
                ULONG c2PipeMask = SYSCALL_TYPE_CREATE_NAMED_PIPE | SYSCALL_TYPE_OPEN_PROCESS |
                                   SYSCALL_TYPE_CREATE_THREAD;
                if ((mask & c2PipeMask) == c2PipeMask) {
                    DriverDbgPrint("[BA-ETW-SYSCALL] C2 named pipe + injection chain in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }

                /* ── 进程断链 + 文件投放：SetInfoProcess + CreateFile + DeleteFile ── */
                ULONG breakChainMask = SYSCALL_TYPE_SET_INFO_PROCESS | SYSCALL_TYPE_CREATE_FILE |
                                       SYSCALL_TYPE_DELETE_FILE;
                if ((mask & breakChainMask) == breakChainMask) {
                    DriverDbgPrint("[BA-ETW-SYSCALL] Process break chain + file ops in %s (PID:%lld)\n",
                        callerName, pEvent->CallerPid);
                }
            }

            DriverDbgPrint("[BA-ETW-SYSCALL] %s Num:0x%X(%s) in %s (PID:%lld) Mask:0x%X\n",
                (indicator == BA_IND_MEM_DIRECT_SYSCALL) ? "DirectSyscall" : "IndirectSyscall",
                pEvent->SyscallNumber, typeName,
                callerName, pEvent->CallerPid, g_baPidSyscallTypes[idx]);
        }

        /* 触发 behavior 评估，若命中画像则实时告警 */
        pResult = (BA_THREAT_RESULT*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(BA_THREAT_RESULT), 'BAnl');
        if (pResult == NULL) {
            DriverDbgPrint("[BA-ETW-SYSCALL] Allocation failed, skipping evaluation\n");
            return;
        }
        RtlZeroMemory(pResult, sizeof(BA_THREAT_RESULT));
        BehaviorEvaluateProcess((INT64)(ULONG_PTR)pEvent->CallerPid, pResult);
        if (pResult->isThreat && pResult->confidence >= 80.0) {
            BehaviorHandleInjectionAlertAsync(
                (INT64)(ULONG_PTR)pEvent->CallerPid, callerName,
                0, "local",
                pResult->threatClass, 0, NULL);
        }
        ExFreePool(pResult);
        pResult = NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (pResult != NULL) {
            ExFreePool(pResult);
            pResult = NULL;
        }
        DriverDbgPrint("[BA-ETW-SYSCALL] Exception caught, dropping event\n");
    }
}

/* ============================================================================
 * BehaviorHandleNtdllReloadEvent - ntdll 重载/Unhook 行为评估
 * 用户态通过 IOCTL_BEHAVIOR_NTDLL_RELOAD_EVENT 下发检测到的事件，
 * 驱动侧将其转换为行为指标并触发实时评估。
 * ========================================================================== */
VOID BehaviorHandleNtdllReloadEvent(PNTDLL_RELOAD_EVENT_DATA pEvent)
{
    BA_INDICATOR indicator = BA_IND_INVALID;
    CHAR evidence[256] = {0};
    CHAR processName[64] = {0};
    int idx;
    BA_THREAT_RESULT* pResult = NULL;   /* 堆分配：BA_MAX_EVIDENCE=64 后约 9.4KB，避免内核栈溢出 */

    if (pEvent == NULL || pEvent->ProcessId == 0) {
        return;
    }

    __try {
        /* 复制进程名 */
        RtlStringCbCopyNA(processName, sizeof(processName),
                          pEvent->ProcessName, sizeof(pEvent->ProcessName) - 1);

        /* 跳过系统关键进程，降低误报 */
        if (processName[0] != '\0') {
            _strlwr(processName);
            if (strstr(processName, "csrss.exe") ||
                strstr(processName, "smss.exe") ||
                strstr(processName, "lsass.exe") ||
                strstr(processName, "wininit.exe") ||
                strstr(processName, "winlogon.exe") ||
                strstr(processName, "services.exe") ||
                strstr(processName, "svchost.exe")) {
                return;
            }
        }

        idx = findOrCreatePidIndex((INT64)(ULONG_PTR)pEvent->ProcessId);
        if (idx < 0) {
            return;
        }

        /* 根据 flags 判定指标类型 */
        if ((pEvent->Flags & NTDLL_RELOAD_FLAG_UNHOOK) && pEvent->IsHooked) {
            indicator = BA_IND_NTDLL_UNHOOK;
            RtlStringCbPrintfA(evidence, sizeof(evidence),
                "NtdllUnhook PID:%lld Base:%p Size:%u Path:%s IsHooked:%u",
                pEvent->ProcessId, (PVOID)(ULONG_PTR)pEvent->ImageBase,
                pEvent->ImageSize, pEvent->FullImagePath, pEvent->IsHooked);
        } else if (pEvent->Flags & NTDLL_RELOAD_FLAG_REMAP) {
            indicator = BA_IND_NTDLL_REMAP;
            RtlStringCbPrintfA(evidence, sizeof(evidence),
                "NtdllRemap PID:%lld Base:%p Size:%u Path:%s",
                pEvent->ProcessId, (PVOID)(ULONG_PTR)pEvent->ImageBase,
                pEvent->ImageSize, pEvent->FullImagePath);
        } else if (pEvent->Flags & NTDLL_RELOAD_FLAG_PATH) {
            indicator = BA_IND_NTDLL_PATH_ANOMALY;
            RtlStringCbPrintfA(evidence, sizeof(evidence),
                "NtdllPathAnomaly PID:%lld Path:%s SystemPath:%u",
                pEvent->ProcessId, pEvent->FullImagePath, pEvent->IsFromSystemPath);
        }

        if (indicator == BA_IND_INVALID) {
            return;
        }

        addIndicator(idx, indicator, evidence);

        DriverDbgPrint("[BA-NTDLL] %s in %s (PID:%lld) Flags:0x%X\n",
            (indicator == BA_IND_NTDLL_UNHOOK) ? "Unhook" :
            (indicator == BA_IND_NTDLL_REMAP) ? "Remap" : "PathAnomaly",
            processName, pEvent->ProcessId, pEvent->Flags);

        /* 触发行为评估，若命中画像则实时告警 */
        pResult = (BA_THREAT_RESULT*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(BA_THREAT_RESULT), 'BAnl');
        if (pResult == NULL) {
            DriverDbgPrint("[BA-NTDLL] Allocation failed, skipping evaluation\n");
            return;
        }
        RtlZeroMemory(pResult, sizeof(BA_THREAT_RESULT));
        BehaviorEvaluateProcess((INT64)(ULONG_PTR)pEvent->ProcessId, pResult);
        if (pResult->isThreat && pResult->confidence >= 80.0) {
            BehaviorHandleInjectionAlertAsync(
                (INT64)(ULONG_PTR)pEvent->ProcessId, processName,
                0, "local",
                pResult->threatClass, 0, NULL);
        }
        ExFreePool(pResult);
        pResult = NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (pResult != NULL) {
            ExFreePool(pResult);
            pResult = NULL;
        }
        DriverDbgPrint("[BA-NTDLL] Exception caught, dropping event\n");
    }
}

/* ============================================================================
 * BehaviorHandleDcomEvent - DCOM 横向移动行为评估
 * 用户态通过 IOCTL 下发检测到的 DCOM 事件，
 * 驱动侧将其转换为行为指标并触发实时评估。
 * ========================================================================== */
VOID BehaviorHandleDcomEvent(PDCOM_EVENT_DATA pEvent)
{
    int idx;
    INT64 pid;
    const CHAR* evidence = NULL;
    BA_INDICATOR ind = BA_IND_DCOM_REMOTE_ACTIVATION;
    BA_THREAT_RESULT* pResult = NULL;   /* 堆分配：BA_MAX_EVIDENCE=64 后约 9.4KB，避免内核栈溢出 */
    CHAR processName[64] = {0};

    if (!pEvent) return;
    if (!g_bDcomDetectionEnabled) return;

    pid = pEvent->CallerPid;
    if (pid == 0) return;

    __try {
        /* 复制进程名 */
        RtlStringCbCopyNA(processName, sizeof(processName),
                          pEvent->CallerProcessName, sizeof(pEvent->CallerProcessName) - 1);

        idx = findOrCreatePidIndex(pid);
        if (idx < 0) {
            return;
        }

        switch (pEvent->EventType) {
        case 1: /* MMC20.Application */
            ind = BA_IND_DCOM_MMC20_SHELLEXEC;
            evidence = "DCOM MMC20.Application ExecuteShellCommand";
            break;
        case 2: /* ShellWindows/ShellBrowserWindow */
            ind = BA_IND_DCOM_SHELLWINDOWS;
            evidence = "DCOM ShellWindows/ShellBrowserWindow ShellExecute";
            break;
        case 3: /* Excel.Application */
            ind = BA_IND_DCOM_EXCEL_DDE;
            evidence = "DCOM Excel.Application remote DDE/macro";
            break;
        case 4: /* Outlook.Application */
            ind = BA_IND_DCOM_OUTLOOK_CREATEOBJECT;
            evidence = "DCOM Outlook.Application CreateObject";
            break;
        case 5: /* WMI remote */
            ind = BA_IND_DCOM_WMI_REMOTE;
            evidence = "DCOM WMI remote execution";
            break;
        default:
            ind = BA_IND_DCOM_REMOTE_ACTIVATION;
            evidence = "DCOM remote activation";
            break;
        }

        addIndicator(idx, ind, evidence);

        /* Also set child process indicator if applicable */
        if (pEvent->TargetPid > 0 && pEvent->EventType >= 1) {
            addIndicator(idx, BA_IND_DCOM_CHILD_PROCESS, "DCOM spawned child process");
        }

        DriverDbgPrint("[BA-DCOM] %s in %s (PID:%lld) EventType:%u\n",
            evidence, processName, pid, pEvent->EventType);

        /* 触发行为评估，若命中画像则实时告警 */
        pResult = (BA_THREAT_RESULT*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(BA_THREAT_RESULT), 'BAnl');
        if (pResult == NULL) {
            DriverDbgPrint("[BA-DCOM] Allocation failed, skipping evaluation\n");
            return;
        }
        RtlZeroMemory(pResult, sizeof(BA_THREAT_RESULT));
        BehaviorEvaluateProcess(pid, pResult);
        if (pResult->isThreat && pResult->confidence >= 80.0) {
            BehaviorHandleInjectionAlertAsync(
                pid, processName,
                pEvent->TargetPid, pEvent->TargetProcessName,
                pResult->threatClass, 0, NULL);
        }
        ExFreePool(pResult);
        pResult = NULL;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        if (pResult != NULL) {
            ExFreePool(pResult);
            pResult = NULL;
        }
        DriverDbgPrint("[BA-DCOM] Exception caught, dropping event\n");
    }
}

VOID BehaviorEvaluateProcess(INT64 pid, BA_THREAT_RESULT* result)
{
    /* 委托给评分引擎模块处理 */
    BehaviorScoreProcess(pid, result);
}

VOID BehaviorEvaluateAll(BA_THREAT_RESULT* results, INT maxResults, INT* outCount)
{
    KIRQL oldIrql = 0;
    KFLOATING_SAVE floatSave;
    NTSTATUS fpStatus;
    int i, j;
    INT64 pid;
    int evaluatedCount = 0;
    int suppressedCount = 0;
    int whitelistedCount = 0;

    if (results == NULL || outCount == NULL) return;

    BOOLEAN floatSaved = FALSE;
    BOOLEAN lockHeld = FALSE;

    *outCount = 0;

    __try {
        /* 保存 FPU 状态，内核模式浮点运算必需 */
        fpStatus = KeSaveFloatingPointState(&floatSave);
        if (!NT_SUCCESS(fpStatus)) return;
        floatSaved = TRUE;

        /* 持锁执行全部评估，避免与回调并发访问共享数据 */
        lockHeld = TRUE;
        KeAcquireSpinLock(&g_baLock, &oldIrql);

        cleanupStalePids();

        for (i = 0; i < g_baIndicatorCount && *outCount < maxResults; i++) {
            pid = g_baIndicatorPids[i];
            if (pid == 0) continue;  /* 跳过 PID 0 */

            /* 已告警过的进程树根进程 → 跳过，避免 ba scan 显示旧威胁
             * 注意：此处直接访问 g_baAlertedPids（锁已持有），避免 IsAlreadyAlerted 双重获取自旋锁 */
            {
                INT64 rootPid = FindRootAncestor(pid);
                int ai, alreadyAlerted = 0;
                for (ai = 0; ai < g_baAlertedCount; ai++) {
                    if (g_baAlertedPids[ai] == rootPid) { alreadyAlerted = 1; break; }
                }
                if (alreadyAlerted) continue;
            }

            /* 白名单检查 */
            {
                int pidx = findProc(pid);
                if (pidx >= 0 && BehaviorIsWhitelisted(g_baProcTree[pidx].imagePath)) {
                    whitelistedCount++;
                    continue;
                }
            }

            {
                /* 堆分配：BA_MAX_EVIDENCE=64 后 BA_THREAT_RESULT 约 9.4KB，避免内核栈溢出；
                 * 持锁在 DISPATCH_LEVEL，必须用 NON_PAGED 池 */
                BA_THREAT_RESULT* pR = (BA_THREAT_RESULT*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(BA_THREAT_RESULT), 'BAnl');
                if (pR == NULL) {
                    DriverDbgPrint("BehaviorEvaluateAll: allocation failed, skipping PID %lld\n", pid);
                    continue;
                }
                RtlZeroMemory(pR, sizeof(BA_THREAT_RESULT));
                BehaviorEvaluateProcess(pid, pR);
                evaluatedCount++;

                if (pR->isThreat && pR->confidence > 0.0) {
                    /* 再次检查白名单（双重验证） */
                    if (BehaviorIsWhitelisted(pR->processPath)) {
                        whitelistedCount++;
                        ExFreePool(pR);
                        continue;
                    }

                    results[*outCount] = *pR;
                    (*outCount)++;
                }
                ExFreePool(pR);
            }
        }

        KeReleaseSpinLock(&g_baLock, oldIrql);
        lockHeld = FALSE;

        /* 按 confidence 降序排序（堆临时变量，避免 9.4KB 结构体上内核栈） */
        {
            BA_THREAT_RESULT* pKey = (BA_THREAT_RESULT*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(BA_THREAT_RESULT), 'BAnl');
            if (pKey != NULL) {
                for (i = 1; i < *outCount; i++) {
                    RtlCopyMemory(pKey, &results[i], sizeof(BA_THREAT_RESULT));
                    j = i - 1;
                    while (j >= 0 && results[j].confidence < pKey->confidence) {
                        results[j + 1] = results[j];
                        j--;
                    }
                    results[j + 1] = *pKey;
                }
                ExFreePool(pKey);
            }
        }

        BehaviorLogInfo("BehaviorEvaluateAll: evaluated=%d, whitelisted=%d, threats=%d, suppressed=%d",
            evaluatedCount, whitelistedCount, *outCount, suppressedCount);
    } __finally {
        if (lockHeld) {
            lockHeld = FALSE;
            KeReleaseSpinLock(&g_baLock, oldIrql);
        }
        if (floatSaved) {
            floatSaved = FALSE;
            KeRestoreFloatingPointState(&floatSave);
        }
    }
}

VOID BehaviorGetStats(BA_STATS* stats)
{
    KIRQL oldIrql = 0;

    if (stats == NULL) return;

    KeAcquireSpinLock(&g_baLock, &oldIrql);
    stats->processCount  = g_baProcCount;
    stats->historyCount  = g_baHistoryCount;
    stats->indicatorCount = g_baIndicatorCount;
    stats->tickCounter   = g_baTickCounter;
    stats->threatCount   = 0; /* 需要 scan 才能获取 */
    KeReleaseSpinLock(&g_baLock, oldIrql);
}

const BA_PROCESS_NODE* BehaviorGetProcessTree(_Out_ INT* count)
{
    if (count != NULL) *count = g_baProcCount;
    return g_baProcTree;
}

const BA_STORED_EVENT* BehaviorGetHistory(_Out_ INT* count)
{
    if (count != NULL) *count = g_baHistoryCount;
    return g_baHistory;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 实时行为检查 — EDR 进程树综合研判 + 告警去重 + 进程挂起
 * ══════════════════════════════════════════════════════════════════════════ */

static VOID MarkAsAlerted(INT64 pid)
{
    KIRQL oldIrql = 0;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    if (g_baAlertedCount < BA_MAX_ALERTED_PIDS) {
        g_baAlertedPids[g_baAlertedCount++] = pid;
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
}

/* ── IsUntrustedProcess: 判断进程是否为不可信的命令进程 ──
 * 命令解释器（cmd/powershell/cscript等）和系统工具（diskpart/reg/bcdedit等）
 * 均可被恶意软件利用，因此在进程树追溯时应被视为"可疑"继续向上追责。 */
static BOOLEAN IsUntrustedProcess(const CHAR* imagePath)
{
    int len = kStrLen(imagePath);
    int i;

    /* 提取文件名（跳过路径） */
    const CHAR* name = imagePath;
    for (i = len - 1; i >= 0; i--) {
        if (imagePath[i] == '\\' || imagePath[i] == '/') {
            name = imagePath + i + 1;
            break;
        }
    }
    int nameLen = kStrLen(name);

    /* 脚本解释器 */
    if (kStrIStrLen(name, nameLen, "cmd.exe", 7))      return TRUE;
    if (kStrIStrLen(name, nameLen, "powershell.exe", 14)) return TRUE;
    if (kStrIStrLen(name, nameLen, "pwsh.exe", 8))     return TRUE;
    if (kStrIStrLen(name, nameLen, "wscript.exe", 11))  return TRUE;
    if (kStrIStrLen(name, nameLen, "cscript.exe", 11))  return TRUE;
    if (kStrIStrLen(name, nameLen, "mshta.exe", 9))    return TRUE;

    /* 系统工具（可被滥用） */
    if (kStrIStrLen(name, nameLen, "diskpart.exe", 12)) return TRUE;
    if (kStrIStrLen(name, nameLen, "reg.exe", 7))      return TRUE;
    if (kStrIStrLen(name, nameLen, "regedit.exe", 11))  return TRUE;
    if (kStrIStrLen(name, nameLen, "bcdedit.exe", 11))  return TRUE;
    if (kStrIStrLen(name, nameLen, "vssadmin.exe", 12)) return TRUE;
    if (kStrIStrLen(name, nameLen, "wmic.exe", 8))     return TRUE;
    if (kStrIStrLen(name, nameLen, "schtasks.exe", 12)) return TRUE;
    if (kStrIStrLen(name, nameLen, "netsh.exe", 9))    return TRUE;
    if (kStrIStrLen(name, nameLen, "sc.exe", 6))       return TRUE;
    if (kStrIStrLen(name, nameLen, "net.exe", 7))      return TRUE;
    if (kStrIStrLen(name, nameLen, "net1.exe", 8))     return TRUE;

    /* DLL 宿主 */
    if (kStrIStrLen(name, nameLen, "rundll32.exe", 12)) return TRUE;
    if (kStrIStrLen(name, nameLen, "regsvr32.exe", 12)) return TRUE;

    /* 下载/传输工具 */
    if (kStrIStrLen(name, nameLen, "certutil.exe", 12)) return TRUE;
    if (kStrIStrLen(name, nameLen, "bitsadmin.exe", 13)) return TRUE;
    if (kStrIStrLen(name, nameLen, "ftp.exe", 7))      return TRUE;

    return FALSE;
}

/* ── FindGhostProcess: 在幽灵进程列表中查找指定PID ── */
static PBA_GHOST_PROCESS FindGhostProcess(INT64 pid)
{
    int i;
    for (i = 0; i < g_baGhostCount; i++) {
        if (g_baGhostProcesses[i].pid == pid) {
            return &g_baGhostProcesses[i];
        }
    }
    return NULL;
}

/* ── IsGhostProcessSuspicious: 检查幽灵进程是否有可疑指标 ── */
static BOOLEAN IsGhostProcessSuspicious(PBA_GHOST_PROCESS ghost)
{
    if (!ghost || !ghost->hasSuspiciousIndicators) return FALSE;

    INT64 elapsed = g_baTickCounter - ghost->exitTick;
    if (elapsed > BA_GHOST_TTL_TICKS) return FALSE;

    INT* indicators = ghost->indicators;
    if (indicators[BA_IND_PROC_FROM_TEMP_DIR] > 0 ||
        indicators[BA_IND_PROC_FROM_DOWNLOADS_DIR] > 0 ||
        indicators[BA_IND_PROC_FROM_APPDATA_DIR] > 0 ||
        indicators[BA_IND_PROC_UNSIGNED] > 0 ||
        indicators[BA_IND_PROC_SCRIPT_INTERPRETER] > 0 ||
        indicators[BA_IND_FILE_SET_SYSTEM_HIDDEN] > 0 ||
        indicators[BA_IND_FILE_PE_IN_IMAGE] > 0 ||
        indicators[BA_IND_REG_ETW_PATCH] > 0 ||
        indicators[BA_IND_REG_INSTRUMENTATION_CALLBACK] > 0 ||
        indicators[BA_IND_REG_DRIVER_SERVICE_CREATE] > 0 ||
        indicators[BA_IND_MEM_ALLOC_EXECUTE_SELF] > 0 ||
        indicators[BA_IND_MEM_ALLOC_EXECUTE] > 0 ||
        indicators[BA_IND_MEM_NONSYSTEM_RWX] > 0 ||
        indicators[BA_IND_MEM_NONSYSTEM_EXEC_READ] > 0 ||
        indicators[BA_IND_MEM_SHELLCODE_DETECTED] > 0) {
        return TRUE;
    }
    return FALSE;
}

/* ── FindRootAncestor: 沿进程树向上追溯，找到进程树的根进程 ──
 * 从当前进程沿父进程链向上查找，遇到不可信进程（命令解释器/系统工具）继续追溯，
 * 遇到正常进程（explorer/system等）则停止。返回追溯到的最后一个不可信进程（或自身）。
 * 追溯条件:
 *   1. 父进程有可疑行为指标（Temp/AppData/Downloads/未签名/脚本解释器）
 *   2. 父进程是不可信命令进程（cmd/powershell/diskpart等）
 *   3. 父进程与当前进程 imagePath 相同（病毒启动自身）
 *   4. 父进程已退出但保留在幽灵追踪中且有可疑指标（银狐行为链回溯） */
static INT64 FindRootAncestor(INT64 pid)
{
    INT64 current = pid;
    INT64 root = pid;
    int iterations = 0;

    while (iterations < 32) {
        int procIdx = findProc(current);

        /* 如果当前进程不在活跃进程树中，尝试在幽灵进程中查找 */
        if (procIdx < 0) {
            PBA_GHOST_PROCESS ghost = FindGhostProcess(current);
            if (!ghost || !IsGhostProcessSuspicious(ghost)) break;

            INT64 parentPid = ghost->parentPid;
            if (parentPid == 0 || parentPid == current) break;

            root = current;
            current = parentPid;
            iterations++;
            continue;
        }

        INT64 parentPid = g_baProcTree[procIdx].parentPid;
        if (parentPid == 0 || parentPid == current) break;

        int parentIsSuspicious = 0;

        /* 条件1: 父进程有可疑行为指标（来自Temp/AppData/Downloads/未签名） */
        int parentIdx = findPidIndex(parentPid);
        if (parentIdx >= 0) {
            if (g_baPidIndicators[parentIdx][BA_IND_PROC_SCRIPT_INTERPRETER] > 0 ||
                g_baPidIndicators[parentIdx][BA_IND_PROC_FROM_TEMP_DIR] > 0 ||
                g_baPidIndicators[parentIdx][BA_IND_PROC_FROM_APPDATA_DIR] > 0 ||
                g_baPidIndicators[parentIdx][BA_IND_PROC_FROM_DOWNLOADS_DIR] > 0 ||
                g_baPidIndicators[parentIdx][BA_IND_PROC_UNSIGNED] > 0) {
                parentIsSuspicious = 1;
            }
        }

        /* 条件2: 父进程是不可信的命令进程（cmd/powershell/diskpart等） */
        if (!parentIsSuspicious) {
            int parentProcIdx = findProc(parentPid);
            if (parentProcIdx >= 0 && IsUntrustedProcess(g_baProcTree[parentProcIdx].imagePath)) {
                parentIsSuspicious = 1;
            }
        }

        /* 条件3: 父进程与当前进程 imagePath 相同（病毒启动自身的情况） */
        if (!parentIsSuspicious) {
            int parentProcIdx = findProc(parentPid);
            if (parentProcIdx >= 0 && procIdx >= 0) {
                if (kStrCmp(g_baProcTree[parentProcIdx].imagePath,
                            g_baProcTree[procIdx].imagePath) == 0) {
                    parentIsSuspicious = 1;
                }
            }
        }

        /* 条件4: 父进程已退出但在幽灵追踪中且有可疑指标 */
        if (!parentIsSuspicious) {
            PBA_GHOST_PROCESS parentGhost = FindGhostProcess(parentPid);
            if (IsGhostProcessSuspicious(parentGhost)) {
                parentIsSuspicious = 1;
            }
        }

        if (parentIsSuspicious) {
            root = parentPid;
            current = parentPid;
            iterations++;
            continue;
        }

        /* 父进程不满足任何可疑条件 → 停止追溯 */
        break;
    }

    return root;
}

/* ── 进程树批量操作：收集/挂起/恢复/终止 ──
 * 注意：treePids 和 treePidCount 由调用者在栈上分配，通过参数传递，
 * 避免多个 BehaviorCheckAndAlert 并发调用时覆盖全局状态。 */

/* CollectTreePids: 枚举进程树中所有 PID（持锁操作）
 * 基于初始化时枚举 + process callback 维护的 g_baProcTree。
 * 修复: 始终先将 rootPid 加入 treePids，即使 rootPid 不在 g_baProcTree 中。 */
static void CollectTreePids(INT64 rootPid, INT64* treePids, int* treePidCount)
{
    int i;
    *treePidCount = 0;

    /* 始终先将根进程加入树（确保主进程一定被挂起/终止） */
    if (*treePidCount < BA_MAX_TREE_PIDS) {
        treePids[(*treePidCount)++] = rootPid;
    }

    /* 遍历 g_baProcTree，收集所有属于该进程树的进程 */
    for (i = 0; i < g_baProcCount && *treePidCount < BA_MAX_TREE_PIDS; i++) {
        INT64 checkPid = g_baProcTree[i].pid;

        /* 跳过根进程本身（已加入） */
        if (checkPid == rootPid) continue;

        /* 沿父进程链追溯，判断是否属于 rootPid 的进程树
         * 支持幽灵感知：父进程不在 g_baProcTree 时，在幽灵进程中查找 */
        {
            INT64 current = checkPid;
            int iterations = 0;
            int isInTree = FALSE;
            while (iterations < 32) {
                int procIdx = findProc(current);
                if (procIdx >= 0) {
                    INT64 parentPid = g_baProcTree[procIdx].parentPid;
                    if (parentPid == rootPid) { isInTree = TRUE; break; }
                    if (parentPid == 0 || parentPid == current) break;
                    current = parentPid;
                } else {
                    /* 父进程不在活跃树中，检查是否为幽灵进程 */
                    PBA_GHOST_PROCESS parentGhost = FindGhostProcess(current);
                    if (parentGhost) {
                        if (parentGhost->parentPid == rootPid) { isInTree = TRUE; break; }
                        if (parentGhost->parentPid == 0 || parentGhost->parentPid == current) break;
                        current = parentGhost->parentPid;
                    } else {
                        break;
                    }
                }
                iterations++;
            }

            if (isInTree) {
                treePids[(*treePidCount)++] = checkPid;
            }
        }
    }
}

/* ── IsCriticalSystemProcess: 检查 PID 是否为系统关键进程 ──
 * 通过 PEPROCESS 获取进程短名，与已知系统进程列表做精确匹配。
 * 用于 SuspendProcessTree/TerminateProcessTree 的最后防线保护，
 * 避免子串匹配把 "mywinlogon.exe" 当成关键进程。
 * 导出给 ProcessCallback.c 用于减少注入检测误报。
 *
 * 注意：PsGetProcessImageFileName 只返回最多15字符的短名，对于
 * SearchIndexer.exe、SearchProtocolHost.exe、ShellExperienceHost.exe
 * 等长名进程会被截断。因此除了完整短名匹配外，还用一组固定的
 * 系统进程名前缀做兜底匹配，避免系统进程间正常操作被误报为注入。 */
BOOLEAN IsCriticalSystemProcess(PEPROCESS process)
{
    UCHAR* procName;
    CHAR nameLower[32] = {0};
    int i;

    if (!process) return FALSE;
    procName = PsGetProcessImageFileName(process);
    if (!procName) return FALSE;

    /* PsGetProcessImageFileName 最多15字符，可能无null终止符 */
    for (i = 0; i < 15 && procName[i]; i++) {
        CHAR c = (CHAR)procName[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        nameLower[i] = c;
    }
    nameLower[i] = '\0';

    /* 先尝试完整短名匹配 */
    if (IsKnownSystemProcessName(nameLower)) return TRUE;

    /* 兜底：长名系统进程被截断后，用前缀匹配。
     * 这里只包含 Windows 自带、路径固定在系统目录的进程名前缀，
     * 且必须与合法短名前缀完全一致，避免 "searchindexer_malware.exe"
     * 等拼写变体绕过。 */
    {
        static const CHAR* prefixes[] = {
            "searchindexer",       /* SearchIndexer.exe */
            "searchprotocol",      /* SearchProtocolHost.exe */
            "searchfilter",        /* SearchFilterHost.exe */
            "backgroundtaskhost",  /* BackgroundTaskHost.exe */
            "shellexperiencehost", /* ShellExperienceHost.exe */
            "startmenuexperience", /* StartMenuExperienceHost.exe */
            "applicationframehost",/* ApplicationFrameHost.exe */
            "microsoftedgeupdate", /* MicrosoftEdgeUpdate.exe */
            "microsoftedge",       /* MicrosoftEdge.exe */
            "securityhealthserv",  /* SecurityHealthService.exe */
            "windowsupdateelevat", /* WindowsUpdateElevatedInstaller.exe */
            NULL
        };
        int pi;
        for (pi = 0; prefixes[pi]; pi++) {
            int plen = 0;
            while (prefixes[pi][plen]) plen++;
            if (kStrNCmp(nameLower, prefixes[pi], plen) == 0) return TRUE;
        }
    }

    return FALSE;
}

/* SuspendProcessTree: 挂起进程树中所有进程 */
static void SuspendProcessTree(INT64* treePids, int treePidCount)
{
    int i;
    DriverDbgPrint("[BA-SUSPEND] Suspending %d processes in tree\n", treePidCount);
    for (i = 0; i < treePidCount; i++) {
        PEPROCESS process = NULL;
        HANDLE hProcess = NULL;
        BOOLEAN suspended = FALSE;

        __try {
            NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)treePids[i], &process);
            if (!NT_SUCCESS(status)) {
                DriverDbgPrint("[BA-SUSPEND] PsLookupProcessByProcessId PID=%lld failed: 0x%X\n",
                    treePids[i], status);
                continue;
            }

            /* 系统关键进程保护：绝不挂起 winlogon/csrss/explorer 等 */
            if (IsCriticalSystemProcess(process)) {
                DriverDbgPrint("[BA-SUSPEND] SKIPPED critical system process PID=%lld\n", treePids[i]);
                continue;
            }

            /* 优先使用 PsSuspendProcess（PEPROCESS 参数，最稳定） */
            if (g_pPsSuspendProcess) {
                NTSTATUS s = g_pPsSuspendProcess(process);
                if (NT_SUCCESS(s)) {
                    DriverDbgPrint("[BA-SUSPEND] Suspended PID=%lld (PsSuspendProcess)\n", treePids[i]);
                    suspended = TRUE;
                } else {
                    DriverDbgPrint("[BA-SUSPEND] PsSuspendProcess PID=%lld failed: 0x%X\n",
                        treePids[i], s);
                }
            }

            /* Fallback: NtSuspendProcess（HANDLE 参数） */
            if (!suspended && g_pNtSuspendProcess) {
                NTSTATUS s = ObOpenObjectByPointer(
                    process, OBJ_KERNEL_HANDLE, NULL,
                    0x0800,  /* PROCESS_SUSPEND_RESUME */
                    *PsProcessType, KernelMode, &hProcess);
                if (NT_SUCCESS(s)) {
                    s = g_pNtSuspendProcess(hProcess);
                    if (NT_SUCCESS(s)) {
                        DriverDbgPrint("[BA-SUSPEND] Suspended PID=%lld (NtSuspendProcess)\n", treePids[i]);
                        suspended = TRUE;
                    } else {
                        DriverDbgPrint("[BA-SUSPEND] NtSuspendProcess PID=%lld failed: 0x%X\n",
                            treePids[i], s);
                    }
                } else {
                    DriverDbgPrint("[BA-SUSPEND] ObOpenObjectByPointer PID=%lld failed: 0x%X\n",
                        treePids[i], s);
                }
            }

            if (!suspended) {
                DriverDbgPrint("[BA-SUSPEND] Failed to suspend PID=%lld (no usable API)\n", treePids[i]);
            }
        } __finally {
            if (hProcess)
                ZwClose(hProcess);
            if (process)
                ObDereferenceObject(process);
        }
    }
}

/* ResumeProcessTree: 恢复进程树中所有进程 */
static void ResumeProcessTree(INT64* treePids, int treePidCount)
{
    int i;
    for (i = 0; i < treePidCount; i++) {
        PEPROCESS process = NULL;
        HANDLE hProcess = NULL;
        BOOLEAN resumed = FALSE;

        __try {
            NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)treePids[i], &process);
            if (!NT_SUCCESS(status)) {
                continue;
            }

            /* 优先使用 PsResumeProcess（PEPROCESS 参数） */
            if (g_pPsResumeProcess) {
                NTSTATUS s = g_pPsResumeProcess(process);
                if (NT_SUCCESS(s)) {
                    DriverDbgPrint("[BA-RESUME] Resumed PID=%lld (PsResumeProcess)\n", treePids[i]);
                    resumed = TRUE;
                } else {
                    DriverDbgPrint("[BA-RESUME] PsResumeProcess PID=%lld failed: 0x%X\n",
                        treePids[i], s);
                }
            }

            /* Fallback: NtResumeProcess（HANDLE 参数） */
            if (!resumed && g_pNtResumeProcess) {
                NTSTATUS s = ObOpenObjectByPointer(
                    process, OBJ_KERNEL_HANDLE, NULL,
                    0x0800,  /* PROCESS_SUSPEND_RESUME */
                    *PsProcessType, KernelMode, &hProcess);
                if (NT_SUCCESS(s)) {
                    s = g_pNtResumeProcess(hProcess);
                    if (NT_SUCCESS(s)) {
                        DriverDbgPrint("[BA-RESUME] Resumed PID=%lld (NtResumeProcess)\n", treePids[i]);
                    } else {
                        DriverDbgPrint("[BA-RESUME] NtResumeProcess PID=%lld failed: 0x%X\n",
                            treePids[i], s);
                    }
                }
            }
        } __finally {
            if (hProcess)
                ZwClose(hProcess);
            if (process)
                ObDereferenceObject(process);
        }
    }
}

/* ── IsProcessMarkedCritical: 查询进程是否被标记为关键进程 ──
 * 通过 ZwQueryInformationProcess(ProcessBreakOnTermination) 查询。
 * 病毒可能调用 RtlSetProcessIsCritical(TRUE) 将自身设为关键进程，
 * 终止此类进程会导致蓝屏（BSOD）。
 * 返回值: *isCritical 输出是否为关键进程 */
static NTSTATUS QueryProcessCritical(HANDLE hProcess, PBOOLEAN isCritical)
{
    ULONG breakOnTermination = 0;
    ULONG returnLength = 0;
    NTSTATUS status;

    if (isCritical) *isCritical = FALSE;

    status = ZwQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0x1D,  /* ProcessBreakOnTermination */
        &breakOnTermination,
        sizeof(breakOnTermination),
        &returnLength);
    if (!NT_SUCCESS(status)) {
        /* 查询失败（可能权限不足），保守起见视为非关键 */
        if (isCritical) *isCritical = FALSE;
        return status;
    }

    if (isCritical) *isCritical = (breakOnTermination != 0) ? TRUE : FALSE;
    return STATUS_SUCCESS;
}

/* ── SetProcessCritical: 设置进程的关键进程标记 ──
 * RtlSetProcessIsCritical 内部调用 NtSetInformationProcess(ProcessBreakOnTermination)。
 * 安全策略：本驱动只允许将进程标记为关键（makeCritical=TRUE），
 * 禁止清除任何进程的关键标记。一旦错误地清除真实关键进程
 * （包括以 LOCAL/NETWORK SERVICE 运行的关键服务）的标记并终止它，
 * 会立即触发 CRITICAL_PROCESS_DIED 蓝屏。病毒若伪装关键进程，
 * 由用户或后续专用清理流程处理，不由驱动直接清除并终止。
 * 注意: 调用此函数需要 SeDebugPrivilege 权限，内核态默认拥有。 */
static NTSTATUS SetProcessCritical(HANDLE hProcess, BOOLEAN makeCritical)
{
    ULONG breakOnTermination = 1;

    if (!makeCritical)
    {
        DriverDbgPrint("[BA-CRITICAL] Refused to clear BreakOnTermination flag to prevent BSOD\n");
        return STATUS_ACCESS_DENIED;
    }

    return ZwSetInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0x1D,  /* ProcessBreakOnTermination */
        &breakOnTermination,
        sizeof(breakOnTermination));
}

/* TerminateProcessTree: 终止进程树中所有进程（从叶到根）
 *
 * 安全策略（避免 CRITICAL_PROCESS_DIED）：
 *   1. 先按进程名/路径判断是否为已知系统进程 → 是则跳过
 *   2. 再查询 ProcessBreakOnTermination 标记 → TRUE 则直接跳过，
 *      不再尝试清除标记。因为一旦误判真实关键进程（包括以 LOCAL/
 *      NETWORK SERVICE 运行的关键服务），清除后终止会立刻蓝屏。
 *   3. 只有既不在系统白名单、又未标记为关键的进程才终止。
 *
 * 恶意软件若伪装关键进程，不会由驱动直接终止，而是持久化挂起并告警，
 * 由用户或后续专用清理流程处理。 */
static void TerminateProcessTree(INT64* treePids, int treePidCount)
{
    int i;
    DriverDbgPrint("[BA-TERM] Terminating %d processes in tree (reverse order: children first)\n",
        treePidCount);
    /* 逆序遍历：先终止子进程，再终止父进程 */
    for (i = treePidCount - 1; i >= 0; i--) {
        PEPROCESS process = NULL;
        HANDLE hProcess = NULL;

        __try {
            NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)treePids[i], &process);
            if (!NT_SUCCESS(status)) {
                DriverDbgPrint("[BA-TERM] PsLookupProcessByProcessId PID=%lld failed: 0x%X\n",
                    treePids[i], status);
                continue;
            }

            /* 系统关键进程保护：绝不终止 winlogon/csrss/explorer/svchost 等
             * 这是最后防线，即使前面的跳过逻辑失效也不会蓝屏 */
            if (IsCriticalSystemProcess(process)) {
                DriverDbgPrint("[BA-TERM] SKIPPED critical system process PID=%lld (last-resort protection)\n",
                    treePids[i]);
                continue;
            }

            /* ZwTerminateProcess 需要 HANDLE，不能直接传 PEPROCESS 指针。
             * PROCESS_QUERY_LIMITED_INFORMATION 用于查询 BreakOnTermination。 */
            NTSTATUS s = ObOpenObjectByPointer(
                process,
                OBJ_KERNEL_HANDLE,
                NULL,
                0x0001 | 0x0400,  /* PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION */
                *PsProcessType,
                KernelMode,
                &hProcess);
            if (!NT_SUCCESS(s)) {
                DriverDbgPrint("[BA-TERM] ObOpenObjectByPointer PID=%lld failed: 0x%X\n",
                    treePids[i], s);
                continue;
            }

            /* 步骤1: 查询进程是否被标记为关键进程 */
            {
                BOOLEAN isCritical = FALSE;
                QueryProcessCritical(hProcess, &isCritical);

                if (isCritical) {
                    /* 关键进程标记为 TRUE → 无论 SID 如何都跳过，
                     * 不再尝试清除标记，彻底杜绝 CRITICAL_PROCESS_DIED。 */
                    DriverDbgPrint("[BA-TERM] SKIPPED BreakOnTermination process PID=%lld to prevent BSOD\n",
                        treePids[i]);
                    continue;
                }
            }

            /* 步骤2: 终止进程 */
            {
                NTSTATUS termStatus = ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
                if (NT_SUCCESS(termStatus)) {
                    DriverDbgPrint("[BA-TERM] Terminated PID=%lld\n", treePids[i]);
                } else {
                    DriverDbgPrint("[BA-TERM] ZwTerminateProcess PID=%lld failed: 0x%X\n",
                        treePids[i], termStatus);
                }
            }
        } __finally {
            if (hProcess)
                ZwClose(hProcess);
            if (process)
                ObDereferenceObject(process);
        }
    }
}

/* ── ClearProcessTreeIndicators: 清除进程树中所有进程的行为指标 ──
 * 在用户决策后调用，避免 ba scan 显示已处理的旧威胁 */
static void ClearProcessTreeIndicators(INT64 rootPid)
{
    int i, j;

    for (i = 0; i < g_baIndicatorCount; i++) {
        INT64 checkPid = g_baIndicatorPids[i];

        /* 判断 checkPid 是否属于 rootPid 的进程树 */
        int isInTree = (checkPid == rootPid);
        if (!isInTree) {
            INT64 current = checkPid;
            int iterations = 0;
            while (iterations < 32) {
                int procIdx = findProc(current);
                if (procIdx < 0) break;
                INT64 parentPid = g_baProcTree[procIdx].parentPid;
                if (parentPid == rootPid) { isInTree = 1; break; }
                if (parentPid == 0 || parentPid == current) break;
                current = parentPid;
                iterations++;
            }
        }

        if (isInTree) {
            for (j = 0; j < BA_MAX_INDICATORS; j++) {
                g_baPidIndicators[i][j] = 0;
            }
            g_baEvidence[i].count = 0;
        }
    }

    /* 压缩数组，移除已清除的条目 */
    cleanupStalePids();
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 文件释放跟踪与威胁清除
 *
 * 设计：
 * 1. FileFilter post-create 回调检测 FILE_CREATED 时调用 BehaviorRecordDroppedFile
 * 2. 用户决策终止后，BehaviorCleanupDroppedFiles 遍历环形缓冲区，
 *    删除属于进程树的新文件（跳过进程本体、系统文件、已存在文件的写入）
 * 3. 清除功能仅在无签名/脚本进程上启用（排除系统文件，含脚本进程）
 * ══════════════════════════════════════════════════════════════════════════ */

/* 检查路径是否为系统目录（跳过跟踪以减少开销）
 * 路径格式为 \Device\HarddiskVolume2\Windows\System32\...，需子串搜索
 * 注意：Program Files 不再视为系统目录，因为 DLL 侧加载/自加载攻击常把
 *       恶意 DLL 投放到 Program Files 下的白程序目录，需要记录以便清理。 */
static BOOLEAN IsSystemDirectoryPath(PUNICODE_STRING path)
{
    static const WCHAR* sysPatterns[] = {
        L"\\Windows\\System32\\",
        L"\\Windows\\SysWOW64\\",
        L"\\Windows\\WinSxS\\",
        L"\\Windows\\assembly\\",
        L"\\Windows\\Installer\\",
        L"\\Windows\\SoftwareDistribution\\",
        L"\\Windows\\servicing\\",
    };
    int i;

    if (!path || !path->Buffer || path->Length < 20)
        return FALSE;

    for (i = 0; i < sizeof(sysPatterns) / sizeof(sysPatterns[0]); i++) {
        const WCHAR* pat = sysPatterns[i];
        ULONG patLen = 0;
        ULONG pathLen = path->Length / sizeof(WCHAR);

        while (pat[patLen]) patLen++;

        /* Substring search: try matching at each position */
        if (pathLen < patLen) continue;
        {
            ULONG start;
            for (start = 0; start + patLen <= pathLen; start++) {
                ULONG j;
                BOOLEAN match = TRUE;
                for (j = 0; j < patLen; j++) {
                    WCHAR pc = path->Buffer[start + j];
                    WCHAR sc = pat[j];
                    if (pc >= L'A' && pc <= L'Z') pc += 32;
                    if (sc >= L'A' && sc <= L'Z') sc += 32;
                    if (pc != sc) { match = FALSE; break; }
                }
                if (match) return TRUE;
            }
        }
    }
    return FALSE;
}

/* BehaviorRecordDroppedFile: 记录进程创建的新文件
 * 由 FileFilter post-create 回调调用，当 IoStatus.Information == FILE_CREATED 时 */
VOID BehaviorRecordDroppedFile(INT64 pid, PUNICODE_STRING filePath)
{
    KIRQL oldIrql = 0;
    LONG idx;
    USHORT copyLen;
    BA_ROLLBACK_LOG_RECORD spillRec = {0};
    BOOLEAN needSpill = FALSE;

    if (!filePath || !filePath->Buffer || filePath->Length == 0)
        return;

    /* Skip system directory files to reduce overhead */
    if (IsSystemDirectoryPath(filePath))
        return;

    /* Skip very long paths */
    if (filePath->Length > (BA_DROPPED_PATH_LEN - 1) * sizeof(WCHAR))
        return;

    KeAcquireSpinLock(&g_baDroppedFileLock, &oldIrql);

    if (g_baDroppedFiles == NULL) {
        KeReleaseSpinLock(&g_baDroppedFileLock, oldIrql);
        return;
    }

    idx = (LONG)((ULONG)InterlockedIncrement(&g_baDroppedFileIdx) % BA_MAX_DROPPED_FILES);

    /* 溢出：覆盖前该槽位仍为有效记录，构造回滚记录上报主程序持久化到磁盘 */
    if (g_baDroppedFiles[idx].valid) {
        spillRec.type = 0;  /* file */
        spillRec.pid = g_baDroppedFiles[idx].pid;
        wpathToAscii(g_baDroppedFiles[idx].path, g_baDroppedFiles[idx].pathLen,
            spillRec.path, BA_RBLOG_PATH_LEN);
        needSpill = TRUE;
    }

    g_baDroppedFiles[idx].pid = pid;
    copyLen = filePath->Length / sizeof(WCHAR);
    RtlCopyMemory(g_baDroppedFiles[idx].path, filePath->Buffer, filePath->Length);
    g_baDroppedFiles[idx].path[copyLen] = L'\0';
    g_baDroppedFiles[idx].pathLen = copyLen;
    g_baDroppedFiles[idx].valid = TRUE;

    KeReleaseSpinLock(&g_baDroppedFileLock, oldIrql);

    /* 在锁外发送，避免持有自旋锁期间进行分配/入队 */
    if (needSpill)
        SendRollbackLogRecord(&spillRec);
}

/* IsScriptProcess: 检查是否为脚本解释器进程（即使签名也启用清除） */
static BOOLEAN IsScriptProcessName(const CHAR* name)
{
    static const char* scripts[] = {
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "conhost.exe", "ftp.exe", "certutil.exe", "bitsadmin.exe",
        "rundll32.exe", "regsvr32.exe", "wmic.exe", "netsh.exe", "schtasks.exe",
        "reg.exe", "regedit.exe", "diskpart.exe", "vssadmin.exe", "msiexec.exe",
        "forfiles.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
    };
    int i;
    if (!name || !name[0]) return FALSE;

    for (i = 0; i < sizeof(scripts) / sizeof(scripts[0]); i++) {
        if (_stricmp(name, scripts[i]) == 0) return TRUE;
    }
    return FALSE;
}

/* IsSystemFilePath: 检查路径是否在系统目录中（排除系统文件） */
static BOOLEAN IsSystemFilePathA(const CHAR* path)
{
    static const char* sysPaths[] = {
        "\\windows\\system32\\",
        "\\windows\\syswow64\\",
        "\\windows\\winsxs\\",
        "\\program files\\",
        "\\program files (x86)\\",
    };
    int i;
    if (!path || !path[0]) return FALSE;

    /* Case-insensitive substring search */
    for (i = 0; i < sizeof(sysPaths) / sizeof(sysPaths[0]); i++) {
        const char* needle = sysPaths[i];
        const char* haystack = path;
        ULONG needleLen = 0;
        while (needle[needleLen]) needleLen++;

        while (*haystack) {
            ULONG j;
            BOOLEAN match = TRUE;
            for (j = 0; j < needleLen; j++) {
                char h = haystack[j];
                char n = needle[j];
                if (h >= 'A' && h <= 'Z') h += 32;
                if (h != n) { match = FALSE; break; }
            }
            if (match) return TRUE;
            haystack++;
        }
    }
    return FALSE;
}

/* ShouldEnableFileCleanup: 判断是否启用文件清除
 * 规则：脚本进程→启用；系统文件路径→禁用；其他→启用（视为无签名） */
static BOOLEAN ShouldEnableFileCleanup(const CHAR* processPath, const CHAR* processName)
{
    /* Script processes: always enable (malware often uses signed scripts) */
    if (IsScriptProcessName(processName))
        return TRUE;

    /* System file path: disable (Microsoft signed system binaries) */
    if (IsSystemFilePathA(processPath))
        return FALSE;

    /* Otherwise: treat as unsigned, enable cleanup */
    return TRUE;
}

/* DeleteKernelFile: 通过 ZwCreateFile + FILE_DELETE_ON_CLOSE 删除文件 */
static NTSTATUS DeleteKernelFile(PCUNICODE_STRING path)
{
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    HANDLE hFile;
    NTSTATUS status;

    InitializeObjectAttributes(&objAttr, (PUNICODE_STRING)path,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hFile, DELETE, &objAttr, &ioStatus,
        NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_DELETE_ON_CLOSE, NULL, 0);

    if (NT_SUCCESS(status)) {
        ZwClose(hFile);
        DriverDbgPrint("[BA-CLEANUP] Deleted: %wZ\n", path);
    } else if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
               status != STATUS_OBJECT_PATH_NOT_FOUND) {
        DriverDbgPrint("[BA-CLEANUP] Delete failed (0x%X): %wZ\n", status, path);
    }

    return status;
}

/* BehaviorCleanupDroppedFiles: 清除进程树释放的新文件
 * 遍历环形缓冲区，删除属于进程树的新文件（跳过进程本体） */
VOID BehaviorCleanupDroppedFiles(INT64* treePids, int treePidCount,
    const CHAR* rootImagePath, const CHAR* rootProcessName)
{
    int i, j;
    int cleanedCount = 0;
    int skippedCount = 0;

    if (g_baDroppedFiles == NULL) return;

    __try {

    /* Check if cleanup should be enabled for this process type */
    if (!ShouldEnableFileCleanup(rootImagePath, rootProcessName)) {
        DriverDbgPrint("[BA-CLEANUP] Skipping file cleanup: process is system file (%s)\n",
            rootProcessName ? rootProcessName : "Unknown");
        return;
    }

    /* 系统进程保护：进程树中包含系统关键进程时，绝不删文件
     * 被注入的系统进程可能"释放"了系统正常文件，删除会导致系统损坏 */
    for (i = 0; i < treePidCount; i++) {
        PEPROCESS process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)treePids[i], &process)) && process) {
            if (IsCriticalSystemProcess(process)) {
                DriverDbgPrint("[BA-CLEANUP] SKIPPED: system process (%lld) in tree, "
                    "file deletion disabled to prevent system damage\n", treePids[i]);
                ObDereferenceObject(process);
                return;
            }
            ObDereferenceObject(process);
        }
    }

    DriverDbgPrint("[BA-CLEANUP] Starting file cleanup for root PID tree, process=%s\n",
        rootProcessName ? rootProcessName : "Unknown");

    /* Convert rootImagePath to wide string for comparison */
    WCHAR rootImageW[BA_MAX_PATH];
    ULONG rootImageWLen = 0;
    if (rootImagePath && rootImagePath[0]) {
        ANSI_STRING ansiStr;
        UNICODE_STRING uniStr = {0};
        RtlInitAnsiString(&ansiStr, rootImagePath);
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniStr, &ansiStr, TRUE))) {
            __try {
                ULONG copyLen = uniStr.Length / sizeof(WCHAR);
                if (copyLen >= BA_MAX_PATH) copyLen = BA_MAX_PATH - 1;
                RtlCopyMemory(rootImageW, uniStr.Buffer, copyLen * sizeof(WCHAR));
                rootImageW[copyLen] = L'\0';
                rootImageWLen = copyLen;
            } __finally {
                RtlFreeUnicodeString(&uniStr);
            }
        }
    }

    /* Iterate the entire ring buffer */
    for (i = 0; i < BA_MAX_DROPPED_FILES; i++) {
        BOOLEAN inTree = FALSE;
        BA_DROPPED_FILE* entry;

        entry = &g_baDroppedFiles[i];
        if (!entry->valid || entry->pathLen == 0)
            continue;

        /* Check if this file's PID is in the process tree */
        for (j = 0; j < treePidCount; j++) {
            if (entry->pid == treePids[j]) {
                inTree = TRUE;
                break;
            }
        }
        if (!inTree)
            continue;

        /* Skip the root process's own image file */
        if (rootImageWLen > 0 && entry->pathLen == rootImageWLen) {
            /* Case-insensitive wide-string comparison (no _wcsnicmp in kernel) */
            ULONG wi;
            BOOLEAN wmatch = TRUE;
            for (wi = 0; wi < rootImageWLen; wi++) {
                WCHAR wc = entry->path[wi];
                WCHAR rc = rootImageW[wi];
                if (wc >= L'A' && wc <= L'Z') wc += 32;
                if (rc >= L'A' && rc <= L'Z') rc += 32;
                if (wc != rc) { wmatch = FALSE; break; }
            }
            if (wmatch) {
                skippedCount++;
                entry->valid = FALSE;
                continue;
            }
        }

        /* Delete the file */
        {
            UNICODE_STRING filePath;
            filePath.Buffer = entry->path;
            filePath.Length = entry->pathLen * sizeof(WCHAR);
            filePath.MaximumLength = filePath.Length;

            NTSTATUS delStatus = DeleteKernelFile(&filePath);
            if (NT_SUCCESS(delStatus)) {
                cleanedCount++;
            }
            entry->valid = FALSE;  /* Mark as processed regardless */
        }
    }

    DriverDbgPrint("[BA-CLEANUP] Done: %d files deleted, %d skipped (root image)\n",
        cleanedCount, skippedCount);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[BA-CLEANUP] Exception caught in BehaviorCleanupDroppedFiles, aborting cleanup\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 威胁回滚机制（参考杀软回滚方法）
 *
 * 当用户对注入 / 行为拦截选择 Block 时，沿祖先链追溯至 explorer（不含 explorer），
 * 对链上每个进程（含根进程及其子孙树）执行的文件释放与注册表修改进行回滚：
 *   - 文件：删除进程释放的新文件（复用 BehaviorCleanupDroppedFiles 逻辑）
 *   - 注册表：SetValue 有原始值→恢复，无原始值→删除；DeleteValue 有备份→恢复
 *
 * 关键约束（用户要求）：
 *   1. 必须只回滚由对应进程执行的操作，不能回滚无关进程 → 按 PID 精确匹配
 *   2. 进程树不可信（中间进程已退出）→ 依据事件记录中保存的 parentPid 重建祖先链
 *   3. 追溯到 explorer 下停止（不回滚 explorer 自身及系统进程的操作）
 * ══════════════════════════════════════════════════════════════════════════ */

/* IsExplorerImagePathA: 判断镜像路径/短名是否为 explorer.exe
 * 兼容完整路径（C:\Windows\explorer.exe）与 15 字符短名（explorer.exe） */
static BOOLEAN IsExplorerImagePathA(const CHAR* imagePath)
{
    CHAR lower[BA_MAX_PATH];
    int len;
    if (imagePath == NULL || imagePath[0] == '\0') return FALSE;
    kStrLowerCopy(lower, BA_MAX_PATH, imagePath);
    len = kStrLen(lower);
    /* 完整路径后缀 \explorer.exe，或短名等于 explorer.exe */
    if (len >= 13 && kStrCmp(lower + len - 13, "explorer.exe") == 0)
        return TRUE;
    if (kStrCmp(lower, "explorer.exe") == 0)
        return TRUE;
    return FALSE;
}

/* BehaviorRecordRegOpWithBackup: 记录注册表操作并备份修改前原始值
 * 在注册表 pre-callback 中调用（PASSIVE_LEVEL），用于后续回滚。
 * 仅备份 SetValue / DeleteValue；DeleteKey 整键恢复代价过高不备份。 */
VOID BehaviorRecordRegOpWithBackup(
    INT64 pid, const CHAR* imageName,
    PUNICODE_STRING keyPath,
    PUNICODE_STRING valueName,
    BA_REG_OP regOp)
{
    UCHAR backupData[BA_REG_BACKUP_DATA_LEN];
    ULONG backupType = 0;
    ULONG backupDataLen = 0;
    BOOLEAN hadExisting = FALSE;
    LONG idx;
    KIRQL oldIrql = 0;
    BA_REG_OP_RECORD* rec;
    BA_ROLLBACK_LOG_RECORD spillRec = {0};
    BOOLEAN needSpill = FALSE;

    if (!g_baInitialized) return;
    if (!g_bBehaviorDetectionEnabled) return;
    if (keyPath == NULL || keyPath->Buffer == NULL || keyPath->Length == 0) return;

    /* 跳过受信任主程序 PID 与白名单（与 BehaviorRecordRegistryEvent 一致） */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pid == g_TrustedMainPid)
        return;
    if (WhitelistCheckByPid(pid) == 1)
        return;

    /* 跳过已知系统进程：svchost/explorer 等频繁写注册表，备份开销大且不会回滚
     * （CollectAncestorChainPids 在系统进程边界停止，回滚不覆盖系统进程）。
     * 病毒冒名但路径/SID 不符的进程不在已知系统进程名精确匹配范围内，仍会备份。 */
    if (imageName && imageName[0]) {
        CHAR nameLower[32] = {0};
        int i;
        for (i = 0; i < 15 && imageName[i]; i++) {
            CHAR c = imageName[i];
            if (c >= 'A' && c <= 'Z') c += 32;
            nameLower[i] = c;
        }
        if (IsKnownSystemProcessName(nameLower))
            return;
    }

    /* 仅备份 SetValue / DeleteValue（常见篡改与持久化向量） */
    if (regOp != BA_ROP_SetValue && regOp != BA_ROP_DeleteValue)
        return;

    /* 路径过长则跳过（截断后无法精确回滚） */
    if (keyPath->Length > (BA_REG_KEY_PATH_LEN - 1) * sizeof(WCHAR))
        return;

    /* 在锁外（PASSIVE_LEVEL）查询原始值：ZwOpenKey/ZwQueryValueKey 不可在自旋锁
     * 持有的 DISPATCH_LEVEL 下调用。重入保护计数器防止回调记录驱动自身查询。 */
    InterlockedIncrement(&g_regDriverAccessDepth);
    __try {
        OBJECT_ATTRIBUTES oa;
        HANDLE hKey = NULL;
        NTSTATUS status;
        ULONG queryBufLen = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + BA_REG_BACKUP_DATA_LEN;
        PKEY_VALUE_PARTIAL_INFORMATION pInfo;

        pInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, queryBufLen, 'BpR');
        if (pInfo == NULL) {
            /* 内存不足：无法备份，仍记录操作（回滚时按"无备份"处理 → 删除值） */
            __leave;
        }

        InitializeObjectAttributes(&oa, keyPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&hKey, KEY_QUERY_VALUE, &oa);
        if (NT_SUCCESS(status) && hKey != NULL) {
            ULONG resultLen = 0;
            UNICODE_STRING localValName;
            PUNICODE_STRING pValName = NULL;

            if (valueName && valueName->Buffer && valueName->Length > 0) {
                localValName = *valueName;
                pValName = &localValName;
            }

            status = ZwQueryValueKey(hKey, pValName,
                KeyValuePartialInformation, pInfo, queryBufLen, &resultLen);

            if (NT_SUCCESS(status)) {
                if (pInfo->DataLength <= BA_REG_BACKUP_DATA_LEN) {
                    hadExisting = TRUE;
                    backupType = pInfo->Type;
                    backupDataLen = pInfo->DataLength;
                    RtlCopyMemory(backupData, pInfo->Data, pInfo->DataLength);
                } else {
                    /* 值存在但数据过大无法备份：标记存在，回滚时删除该值 */
                    hadExisting = TRUE;
                    backupDataLen = 0;
                }
            }
            /* STATUS_OBJECT_NAME_NOT_FOUND → 值不存在，hadExisting 保持 FALSE */
            ZwClose(hKey);
        }
        /* 键不存在（STATUS_OBJECT_NAME_NOT_FOUND）：无法备份，hadExisting=FALSE，
         * SetValue 回滚时删除该值；DeleteValue 无意义但记录无害 */

        ExFreePool(pInfo);
    } __finally {
        InterlockedDecrement(&g_regDriverAccessDepth);
    }

    /* 写入环形缓冲区 */
    KeAcquireSpinLock(&g_baRegOpLock, &oldIrql);

    if (g_baRegOps == NULL) {
        KeReleaseSpinLock(&g_baRegOpLock, oldIrql);
        return;
    }

    idx = (LONG)((ULONG)InterlockedIncrement(&g_baRegOpIdx) % BA_MAX_REG_OPS);
    rec = &g_baRegOps[idx];

    /* 溢出：覆盖前该槽位仍为有效记录，构造自包含回滚记录（含原始值备份）上报主程序持久化 */
    if (rec->valid) {
        spillRec.type = 1;  /* registry */
        spillRec.pid = rec->pid;
        wpathToAscii(rec->keyPath, rec->keyPathLen, spillRec.path, BA_RBLOG_PATH_LEN);
        wpathToAscii(rec->valueName, rec->valueNameLen, spillRec.valueName, BA_RBLOG_VALUE_NAME_LEN);
        spillRec.regOp = rec->regOp;
        spillRec.hadExisting = rec->hadExistingValue;
        spillRec.originalType = rec->originalType;
        spillRec.originalDataLen = (rec->originalDataLen <= BA_RBLOG_BACKUP_LEN)
            ? rec->originalDataLen : BA_RBLOG_BACKUP_LEN;
        if (spillRec.originalDataLen > 0)
            RtlCopyMemory(spillRec.originalData, rec->originalData, spillRec.originalDataLen);
        needSpill = TRUE;
    }

    RtlZeroMemory(rec, sizeof(BA_REG_OP_RECORD));
    rec->pid = pid;
    {
        USHORT copyLen = keyPath->Length / sizeof(WCHAR);
        if (copyLen >= BA_REG_KEY_PATH_LEN) copyLen = BA_REG_KEY_PATH_LEN - 1;
        RtlCopyMemory(rec->keyPath, keyPath->Buffer, copyLen * sizeof(WCHAR));
        rec->keyPath[copyLen] = L'\0';
        rec->keyPathLen = copyLen;
    }
    if (valueName && valueName->Buffer && valueName->Length > 0) {
        USHORT vlen = valueName->Length / sizeof(WCHAR);
        if (vlen >= BA_REG_VALUE_NAME_LEN) vlen = BA_REG_VALUE_NAME_LEN - 1;
        RtlCopyMemory(rec->valueName, valueName->Buffer, vlen * sizeof(WCHAR));
        rec->valueName[vlen] = L'\0';
        rec->valueNameLen = vlen;
    }
    rec->regOp = regOp;
    rec->hadExistingValue = hadExisting;
    rec->originalType = backupType;
    rec->originalDataLen = backupDataLen;
    if (hadExisting && backupDataLen > 0 && backupDataLen <= BA_REG_BACKUP_DATA_LEN) {
        RtlCopyMemory(rec->originalData, backupData, backupDataLen);
    }
    rec->valid = TRUE;
    KeReleaseSpinLock(&g_baRegOpLock, oldIrql);

    /* 在锁外发送，避免持有自旋锁期间进行分配/入队 */
    if (needSpill)
        SendRollbackLogRecord(&spillRec);
}

/* CollectAncestorChainPids: 沿父进程链向上追溯至 explorer（不含），收集祖先 PID
 * 进程树不可信（中间进程已退出）时，回退到事件记录中保存的 parentPid 重建链。
 * 调用时必须持有 g_baLock。 */
static void CollectAncestorChainPids(INT64 rootPid, INT64* outPids, int* outCount)
{
    INT64 current = rootPid;
    int iterations = 0;
    *outCount = 0;

    while (iterations < 32 && *outCount < BA_MAX_TREE_PIDS) {
        INT64 parentPid = 0;
        CHAR parentImage[BA_MAX_PATH] = {0};
        BOOLEAN gotParent = FALSE;
        int i;

        /* 1. 获取 current 的父 PID：优先进程树，回退事件记录 */
        {
            int idx = findProc(current);
            if (idx >= 0) {
                parentPid = g_baProcTree[idx].parentPid;
                gotParent = TRUE;
            }
        }
        if (!gotParent) {
            for (i = 0; i < g_baHistoryCount; i++) {
                int histIdx = (g_baHistoryHead - 1 - i + BA_MAX_HISTORY) % BA_MAX_HISTORY;
                BA_STORED_EVENT* ev = &g_baHistory[histIdx];
                if (ev->pid == current && ev->parentPid != 0) {
                    parentPid = ev->parentPid;
                    gotParent = TRUE;
                    break;
                }
            }
        }
        if (!gotParent || parentPid == 0 || parentPid == current) break;

        /* 2. 获取父进程镜像路径（判断 explorer / 系统进程边界） */
        {
            int pidx = findProc(parentPid);
            if (pidx >= 0) {
                kStrCpy(parentImage, BA_MAX_PATH, g_baProcTree[pidx].imagePath);
            } else {
                for (i = 0; i < g_baHistoryCount; i++) {
                    int histIdx = (g_baHistoryHead - 1 - i + BA_MAX_HISTORY) % BA_MAX_HISTORY;
                    BA_STORED_EVENT* ev = &g_baHistory[histIdx];
                    if (ev->pid == parentPid) {
                        kStrCpy(parentImage, BA_MAX_PATH, ev->imagePath);
                        break;
                    }
                }
            }
        }

        /* 3. 边界判断：父进程为 explorer 或系统进程则停止（不纳入回滚） */
        if (IsExplorerImagePathA(parentImage) || isSystemProcessByPath(parentImage)) {
            break;
        }

        /* 4. 纳入祖先链 */
        outPids[(*outCount)++] = parentPid;
        current = parentPid;
        iterations++;
    }
}

/* RollbackRegistryForPid: 回滚指定 PID 的注册表操作（恢复/删除）
 * 在 PASSIVE_LEVEL 的 work item 中调用，使用重入保护避免回调污染。 */
static VOID RollbackRegistryForPid(INT64 pid)
{
    int i;

    if (g_baRegOps == NULL) return;

    for (i = 0; i < BA_MAX_REG_OPS; i++) {
        BA_REG_OP_RECORD localRec;
        BOOLEAN match = FALSE;
        KIRQL oldIrql = 0;

        /* 持锁快照匹配记录并失效槽位，锁外执行 Zw 恢复操作 */
        KeAcquireSpinLock(&g_baRegOpLock, &oldIrql);
        if (g_baRegOps[i].valid && g_baRegOps[i].pid == pid) {
            RtlCopyMemory(&localRec, &g_baRegOps[i], sizeof(BA_REG_OP_RECORD));
            g_baRegOps[i].valid = FALSE;
            match = TRUE;
        }
        KeReleaseSpinLock(&g_baRegOpLock, oldIrql);

        if (!match) continue;

        InterlockedIncrement(&g_regDriverAccessDepth);
        __try {
            OBJECT_ATTRIBUTES oa;
            HANDLE hKey = NULL;
            UNICODE_STRING keyPathU;
            UNICODE_STRING valNameU;
            NTSTATUS status;

            keyPathU.Buffer = localRec.keyPath;
            keyPathU.Length = localRec.keyPathLen * sizeof(WCHAR);
            keyPathU.MaximumLength = keyPathU.Length;

            InitializeObjectAttributes(&oa, &keyPathU,
                OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwOpenKey(&hKey, KEY_SET_VALUE | DELETE, &oa);
            if (!NT_SUCCESS(status) || hKey == NULL) {
                DriverDbgPrint("[BA-ROLLBACK] ZwOpenKey failed 0x%X for PID=%lld\n",
                    status, pid);
                __leave;
            }

            valNameU.Buffer = localRec.valueName;
            valNameU.Length = localRec.valueNameLen * sizeof(WCHAR);
            valNameU.MaximumLength = valNameU.Length;

            if (localRec.regOp == BA_ROP_SetValue) {
                if (localRec.hadExistingValue && localRec.originalDataLen > 0) {
                    /* 恢复原始值 */
                    status = ZwSetValueKey(hKey, &valNameU, 0,
                        localRec.originalType, localRec.originalData,
                        localRec.originalDataLen);
                    DriverDbgPrint("[BA-ROLLBACK] Restored reg value (PID=%lld): %ws status=0x%X\n",
                        pid, localRec.keyPath, status);
                } else {
                    /* 新增值（无原始值）或值过大无法备份 → 删除 */
                    status = ZwDeleteValueKey(hKey, &valNameU);
                    DriverDbgPrint("[BA-ROLLBACK] Deleted reg value (PID=%lld): %ws status=0x%X\n",
                        pid, localRec.keyPath, status);
                }
            } else if (localRec.regOp == BA_ROP_DeleteValue) {
                if (localRec.hadExistingValue && localRec.originalDataLen > 0) {
                    /* 恢复被删除的值 */
                    status = ZwSetValueKey(hKey, &valNameU, 0,
                        localRec.originalType, localRec.originalData,
                        localRec.originalDataLen);
                    DriverDbgPrint("[BA-ROLLBACK] Restored deleted reg value (PID=%lld): %ws status=0x%X\n",
                        pid, localRec.keyPath, status);
                }
                /* 无原始值的 DeleteValue：无操作（原本就不存在） */
            }

            ZwClose(hKey);
        } __finally {
            InterlockedDecrement(&g_regDriverAccessDepth);
        }
    }
}

/* BehaviorRollbackChain: 威胁回滚主入口
 * 构建回滚 PID 集 = 子孙树 + 根进程 + 祖先链(至 explorer)，删除释放文件 + 回滚注册表。
 * treePids/treePidCount 可为 NULL/0（注入场景仅有源进程）。 */
VOID BehaviorRollbackChain(INT64 rootPid,
    const CHAR* rootImagePath, const CHAR* rootProcessName,
    INT64* treePids, int treePidCount)
{
    INT64 ancestorPids[BA_MAX_TREE_PIDS];
    int ancestorCount = 0;
    INT64 combinedPids[BA_MAX_TREE_PIDS + 32];
    int combinedCount = 0;
    int i, j;
    KIRQL oldIrql = 0;
    WCHAR rootImageW[BA_MAX_PATH];
    ULONG rootImageWLen = 0;

    __try {

    /* 检查是否启用回滚（脚本进程启用；系统文件路径禁用） */
    if (!ShouldEnableFileCleanup(rootImagePath, rootProcessName)) {
        DriverDbgPrint("[BA-ROLLBACK] Skipping: root is system file (%s)\n",
            rootProcessName ? rootProcessName : "Unknown");
        /* 系统文件根进程仍可回滚注册表？为安全起见整体跳过，与文件清理策略一致 */
        return;
    }

    /* 构建祖先链（持 g_baLock） */
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    CollectAncestorChainPids(rootPid, ancestorPids, &ancestorCount);
    KeReleaseSpinLock(&g_baLock, oldIrql);

    DriverDbgPrint("[BA-ROLLBACK] rootPid=%lld ancestorChain=%d treePids=%d\n",
        rootPid, ancestorCount, treePidCount);

    /* 合并 PID 集 = treePids + 根进程 + 祖先链（去重） */
    for (i = 0; i < treePidCount && combinedCount < (int)(sizeof(combinedPids)/sizeof(combinedPids[0])); i++) {
        BOOLEAN dup = FALSE;
        for (j = 0; j < combinedCount; j++) if (combinedPids[j] == treePids[i]) { dup = TRUE; break; }
        if (!dup) combinedPids[combinedCount++] = treePids[i];
    }
    /* 确保根进程在内 */
    {
        BOOLEAN dup = FALSE;
        for (j = 0; j < combinedCount; j++) if (combinedPids[j] == rootPid) { dup = TRUE; break; }
        if (!dup && combinedCount < (int)(sizeof(combinedPids)/sizeof(combinedPids[0])))
            combinedPids[combinedCount++] = rootPid;
    }
    for (i = 0; i < ancestorCount && combinedCount < (int)(sizeof(combinedPids)/sizeof(combinedPids[0])); i++) {
        BOOLEAN dup = FALSE;
        for (j = 0; j < combinedCount; j++) if (combinedPids[j] == ancestorPids[i]) { dup = TRUE; break; }
        if (!dup) combinedPids[combinedCount++] = ancestorPids[i];
    }

    /* 系统进程保护：合并集中含系统关键进程时跳过文件删除（防系统损坏） */
    {
        BOOLEAN hasSysProc = FALSE;
        for (i = 0; i < combinedCount; i++) {
            PEPROCESS process = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)combinedPids[i], &process)) && process) {
                if (IsCriticalSystemProcess(process)) {
                    hasSysProc = TRUE;
                    ObDereferenceObject(process);
                    break;
                }
                ObDereferenceObject(process);
            }
        }
        if (hasSysProc) {
            DriverDbgPrint("[BA-ROLLBACK] SKIPPED file deletion: system process in chain\n");
            /* 仍执行注册表回滚？为安全整体跳过，与 BehaviorCleanupDroppedFiles 一致 */
            return;
        }
    }

    /* 转换 rootImagePath 为宽字符用于跳过进程本体 */
    if (rootImagePath && rootImagePath[0]) {
        ANSI_STRING ansiStr;
        UNICODE_STRING uniStr = {0};
        RtlInitAnsiString(&ansiStr, rootImagePath);
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniStr, &ansiStr, TRUE))) {
            __try {
                ULONG copyLen = uniStr.Length / sizeof(WCHAR);
                if (copyLen >= BA_MAX_PATH) copyLen = BA_MAX_PATH - 1;
                RtlCopyMemory(rootImageW, uniStr.Buffer, copyLen * sizeof(WCHAR));
                rootImageW[copyLen] = L'\0';
                rootImageWLen = copyLen;
            } __finally {
                RtlFreeUnicodeString(&uniStr);
            }
        }
    }

    DriverDbgPrint("[BA-ROLLBACK] Starting: combinedPids=%d process=%s\n",
        combinedCount, rootProcessName ? rootProcessName : "Unknown");

    /* ── 1. 删除释放文件（遍历 g_baDroppedFiles，匹配合并集 PID）── */
    {
        int cleanedCount = 0, skippedCount = 0;
        for (i = 0; i < BA_MAX_DROPPED_FILES; i++) {
            BOOLEAN inSet = FALSE;
            BA_DROPPED_FILE* entry = &g_baDroppedFiles[i];
            if (!entry->valid || entry->pathLen == 0) continue;
            for (j = 0; j < combinedCount; j++) {
                if (entry->pid == combinedPids[j]) { inSet = TRUE; break; }
            }
            if (!inSet) continue;

            /* 跳过根进程本体 */
            if (rootImageWLen > 0 && entry->pathLen == rootImageWLen) {
                ULONG wi;
                BOOLEAN wmatch = TRUE;
                for (wi = 0; wi < rootImageWLen; wi++) {
                    WCHAR wc = entry->path[wi];
                    WCHAR rc = rootImageW[wi];
                    if (wc >= L'A' && wc <= L'Z') wc += 32;
                    if (rc >= L'A' && rc <= L'Z') rc += 32;
                    if (wc != rc) { wmatch = FALSE; break; }
                }
                if (wmatch) {
                    skippedCount++;
                    entry->valid = FALSE;
                    continue;
                }
            }

            {
                UNICODE_STRING filePath;
                filePath.Buffer = entry->path;
                filePath.Length = entry->pathLen * sizeof(WCHAR);
                filePath.MaximumLength = filePath.Length;
                if (NT_SUCCESS(DeleteKernelFile(&filePath))) {
                    cleanedCount++;
                }
                entry->valid = FALSE;
            }
        }
        DriverDbgPrint("[BA-ROLLBACK] Files: %d deleted, %d skipped (root image)\n",
            cleanedCount, skippedCount);
    }

    /* ── 2. 回滚注册表操作（按 PID 精确匹配，仅回滚链上进程）── */
    {
        int regCount = 0;
        for (i = 0; i < combinedCount; i++) {
            RollbackRegistryForPid(combinedPids[i]);
            regCount++;
        }
        DriverDbgPrint("[BA-ROLLBACK] Registry rollback processed for %d PIDs\n", regCount);
    }

    DriverDbgPrint("[BA-ROLLBACK] Done for rootPid=%lld\n", rootPid);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[BA-ROLLBACK] Exception caught, aborting rollback\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 分阶段回滚：收集 → 用户确认 → 执行
 *
 * BehaviorCollectRollbackItems: 收集回滚项到 BA_ROLLBACK_LIST，不执行删除/恢复。
 * BehaviorExecuteRollbackSelected: 根据 selection 执行选中项。
 * ══════════════════════════════════════════════════════════════════════════ */

/* 辅助：WCHAR 路径转 ASCII（截断到 maxChars） */
static void wpathToAscii(const WCHAR* wpath, USHORT wlen, CHAR* out, int maxChars)
{
    int i, copyLen = wlen;
    if (copyLen > maxChars - 1) copyLen = maxChars - 1;
    for (i = 0; i < copyLen; i++) {
        WCHAR wc = wpath[i];
        out[i] = (wc < 128) ? (CHAR)wc : '?';
    }
    out[i] = '\0';
}

VOID BehaviorCollectRollbackItems(INT64 rootPid,
    const CHAR* rootImagePath, const CHAR* rootProcessName,
    const CHAR* threatClass,
    INT64* treePids, int treePidCount,
    PBA_ROLLBACK_LIST outList)
{
    INT64 ancestorPids[BA_MAX_TREE_PIDS];
    int ancestorCount = 0;
    INT64 combinedPids[BA_MAX_TREE_PIDS + 32];
    int combinedCount = 0;
    int i, j;
    KIRQL oldIrql = 0;
    WCHAR rootImageW[BA_MAX_PATH];
    ULONG rootImageWLen = 0;

    if (outList == NULL) return;
    /* 环形缓冲区未分配（分配失败/已清理）时无法收集 */
    if (g_baDroppedFiles == NULL || g_baRegOps == NULL) return;
    RtlZeroMemory(outList, sizeof(BA_ROLLBACK_LIST));
    outList->rootPid = rootPid;
    if (rootProcessName)
        RtlStringCbCopyA(outList->rootProcessName, sizeof(outList->rootProcessName), rootProcessName);
    if (threatClass)
        RtlStringCbCopyA(outList->threatClass, sizeof(outList->threatClass), threatClass);

    __try {

    /* 检查是否启用回滚 */
    if (!ShouldEnableFileCleanup(rootImagePath, rootProcessName)) {
        DriverDbgPrint("[BA-COLLECT] Skipping: root is system file (%s)\n",
            rootProcessName ? rootProcessName : "Unknown");
        return;
    }

    /* 构建祖先链 */
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    CollectAncestorChainPids(rootPid, ancestorPids, &ancestorCount);
    KeReleaseSpinLock(&g_baLock, oldIrql);

    /* 合并 PID 集 = treePids + 根进程 + 祖先链（去重） */
    for (i = 0; i < treePidCount && combinedCount < (int)(sizeof(combinedPids)/sizeof(combinedPids[0])); i++) {
        BOOLEAN dup = FALSE;
        for (j = 0; j < combinedCount; j++) if (combinedPids[j] == treePids[i]) { dup = TRUE; break; }
        if (!dup) combinedPids[combinedCount++] = treePids[i];
    }
    {
        BOOLEAN dup = FALSE;
        for (j = 0; j < combinedCount; j++) if (combinedPids[j] == rootPid) { dup = TRUE; break; }
        if (!dup && combinedCount < (int)(sizeof(combinedPids)/sizeof(combinedPids[0])))
            combinedPids[combinedCount++] = rootPid;
    }
    for (i = 0; i < ancestorCount && combinedCount < (int)(sizeof(combinedPids)/sizeof(combinedPids[0])); i++) {
        BOOLEAN dup = FALSE;
        for (j = 0; j < combinedCount; j++) if (combinedPids[j] == ancestorPids[i]) { dup = TRUE; break; }
        if (!dup) combinedPids[combinedCount++] = ancestorPids[i];
    }

    /* 系统进程保护 */
    for (i = 0; i < combinedCount; i++) {
        PEPROCESS process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)combinedPids[i], &process)) && process) {
            if (IsCriticalSystemProcess(process)) {
                ObDereferenceObject(process);
                DriverDbgPrint("[BA-COLLECT] SKIPPED: system process in chain\n");
                return;
            }
            ObDereferenceObject(process);
        }
    }

    /* 转换 rootImagePath 为宽字符用于跳过进程本体 */
    if (rootImagePath && rootImagePath[0]) {
        ANSI_STRING ansiStr;
        UNICODE_STRING uniStr = {0};
        RtlInitAnsiString(&ansiStr, rootImagePath);
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&uniStr, &ansiStr, TRUE))) {
            __try {
                ULONG copyLen = uniStr.Length / sizeof(WCHAR);
                if (copyLen >= BA_MAX_PATH) copyLen = BA_MAX_PATH - 1;
                RtlCopyMemory(rootImageW, uniStr.Buffer, copyLen * sizeof(WCHAR));
                rootImageW[copyLen] = L'\0';
                rootImageWLen = copyLen;
            } __finally {
                RtlFreeUnicodeString(&uniStr);
            }
        }
    }

    /* ── 1. 收集文件释放项 ── */
    {
        int totalDropped = 0, matchedDropped = 0, skippedSelf = 0;
        for (i = 0; i < BA_MAX_DROPPED_FILES && outList->itemCount < BA_MAX_ROLLBACK_ITEMS; i++) {
            BOOLEAN inSet = FALSE;
            BA_DROPPED_FILE* entry = &g_baDroppedFiles[i];
            if (!entry->valid || entry->pathLen == 0) continue;
            totalDropped++;
            for (j = 0; j < combinedCount; j++) {
                if (entry->pid == combinedPids[j]) { inSet = TRUE; break; }
            }
            if (!inSet) continue;
            matchedDropped++;

            /* 跳过根进程本体 */
            if (rootImageWLen > 0 && entry->pathLen == rootImageWLen) {
                ULONG wi;
                BOOLEAN wmatch = TRUE;
                for (wi = 0; wi < rootImageWLen; wi++) {
                    WCHAR wc = entry->path[wi];
                    WCHAR rc = rootImageW[wi];
                    if (wc >= L'A' && wc <= L'Z') wc += 32;
                    if (rc >= L'A' && rc <= L'Z') rc += 32;
                    if (wc != rc) { wmatch = FALSE; break; }
                }
                if (wmatch) { skippedSelf++; continue; }
            }

            {
                BA_ROLLBACK_ITEM* item = &outList->items[outList->itemCount];
                item->type = 0;  /* file */
                item->pid = entry->pid;
                wpathToAscii(entry->path, entry->pathLen, item->path, 180);
                item->valueName[0] = '\0';
                item->regOp = 0;
                item->hadExisting = 0;
                outList->itemCount++;
            }
        }
        if (totalDropped == 0) {
            DriverDbgPrint("[BA-COLLECT] No dropped files found in g_baDroppedFiles (size=%d)\n", BA_MAX_DROPPED_FILES);
        } else if (matchedDropped == 0) {
            DriverDbgPrint("[BA-COLLECT] %d dropped files found but none matched combinedPids (combinedCount=%d)\n", totalDropped, combinedCount);
        } else if (matchedDropped == skippedSelf) {
            DriverDbgPrint("[BA-COLLECT] All %d matched dropped files skipped (same as root image)\n", skippedSelf);
        }
    }

    /* ── 2. 收集注册表操作项 ── */
    {
        KIRQL regIrql;
        KeAcquireSpinLock(&g_baRegOpLock, &regIrql);
        for (i = 0; i < BA_MAX_REG_OPS && outList->itemCount < BA_MAX_ROLLBACK_ITEMS; i++) {
            BA_REG_OP_RECORD* rec = &g_baRegOps[i];
            BOOLEAN inSet = FALSE;
            if (!rec->valid) continue;
            for (j = 0; j < combinedCount; j++) {
                if (rec->pid == combinedPids[j]) { inSet = TRUE; break; }
            }
            if (!inSet) continue;

            {
                BA_ROLLBACK_ITEM* item = &outList->items[outList->itemCount];
                item->type = 1;  /* registry */
                item->pid = rec->pid;
                wpathToAscii(rec->keyPath, rec->keyPathLen, item->path, 180);
                wpathToAscii(rec->valueName, rec->valueNameLen, item->valueName, 32);
                item->regOp = (UINT8)rec->regOp;
                item->hadExisting = rec->hadExistingValue ? 1 : 0;
                outList->itemCount++;
            }
        }
        KeReleaseSpinLock(&g_baRegOpLock, regIrql);
    }

    DriverDbgPrint("[BA-COLLECT] rootPid=%lld items=%d (files+registry)\n",
        rootPid, outList->itemCount);

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[BA-COLLECT] Exception caught\n");
    }
}

VOID BehaviorExecuteRollbackSelected(
    const BA_ROLLBACK_LIST* rollbackList,
    const BA_ROLLBACK_SELECTION* userSelection)
{
    int i, j;

    if (rollbackList == NULL || userSelection == NULL) return;
    if (userSelection->decision == 0) {
        DriverDbgPrint("[BA-EXEC] User chose IGNORE, no rollback\n");
        return;
    }

    DriverDbgPrint("[BA-EXEC] Executing rollback: %d items, selected=%d\n",
        rollbackList->itemCount, userSelection->itemCount);

    __try {

    for (i = 0; i < rollbackList->itemCount && i < BA_MAX_ROLLBACK_ITEMS; i++) {
        if (userSelection->selected[i] != 1) continue;

        if (rollbackList->items[i].type == 0) {
            /* ── 文件删除 ── */
            CHAR asciiPath[180];
            RtlStringCbCopyA(asciiPath, sizeof(asciiPath), rollbackList->items[i].path);

            /* 在 g_baDroppedFiles 中查找匹配项（PID + 路径） */
            for (j = 0; j < BA_MAX_DROPPED_FILES; j++) {
                CHAR entryAscii[180];
                BA_DROPPED_FILE* entry = &g_baDroppedFiles[j];
                if (!entry->valid || entry->pathLen == 0) continue;
                if (entry->pid != rollbackList->items[i].pid) continue;

                wpathToAscii(entry->path, entry->pathLen, entryAscii, 180);
                if (strcmp(entryAscii, asciiPath) != 0) continue;

                /* 找到匹配项，删除文件 */
                {
                    UNICODE_STRING filePath;
                    filePath.Buffer = entry->path;
                    filePath.Length = entry->pathLen * sizeof(WCHAR);
                    filePath.MaximumLength = filePath.Length;
                    DeleteKernelFile(&filePath);
                    entry->valid = FALSE;
                }
                break;
            }
        } else if (rollbackList->items[i].type == 1) {
            /* ── 注册表回滚 ── */
            CHAR asciiKey[180];
            CHAR asciiVal[32];
            RtlStringCbCopyA(asciiKey, sizeof(asciiKey), rollbackList->items[i].path);
            RtlStringCbCopyA(asciiVal, sizeof(asciiVal), rollbackList->items[i].valueName);

            /* 在 g_baRegOps 中查找匹配项（PID + keyPath + valueName） */
            {
                KIRQL regIrql;
                BA_REG_OP_RECORD localRec;
                BOOLEAN match = FALSE;

                KeAcquireSpinLock(&g_baRegOpLock, &regIrql);
                for (j = 0; j < BA_MAX_REG_OPS; j++) {
                    CHAR entryKey[180];
                    CHAR entryVal[32];
                    BA_REG_OP_RECORD* rec = &g_baRegOps[j];
                    if (!rec->valid) continue;
                    if (rec->pid != rollbackList->items[i].pid) continue;

                    wpathToAscii(rec->keyPath, rec->keyPathLen, entryKey, 180);
                    wpathToAscii(rec->valueName, rec->valueNameLen, entryVal, 32);
                    if (strcmp(entryKey, asciiKey) != 0) continue;
                    if (strcmp(entryVal, asciiVal) != 0) continue;

                    RtlCopyMemory(&localRec, rec, sizeof(BA_REG_OP_RECORD));
                    rec->valid = FALSE;
                    match = TRUE;
                    break;
                }
                KeReleaseSpinLock(&g_baRegOpLock, regIrql);

                if (match) {
                    /* 执行注册表回滚（复用 RollbackRegistryForPid 的逻辑） */
                    InterlockedIncrement(&g_regDriverAccessDepth);
                    __try {
                        OBJECT_ATTRIBUTES oa;
                        HANDLE hKey = NULL;
                        UNICODE_STRING keyPathU;
                        UNICODE_STRING valNameU;
                        NTSTATUS status;

                        keyPathU.Buffer = localRec.keyPath;
                        keyPathU.Length = localRec.keyPathLen * sizeof(WCHAR);
                        keyPathU.MaximumLength = keyPathU.Length;

                        InitializeObjectAttributes(&oa, &keyPathU,
                            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                        status = ZwOpenKey(&hKey, KEY_SET_VALUE | DELETE, &oa);
                        if (NT_SUCCESS(status) && hKey != NULL) {
                            valNameU.Buffer = localRec.valueName;
                            valNameU.Length = localRec.valueNameLen * sizeof(WCHAR);
                            valNameU.MaximumLength = valNameU.Length;

                            if (localRec.regOp == BA_ROP_SetValue) {
                                if (localRec.hadExistingValue && localRec.originalDataLen > 0) {
                                    ZwSetValueKey(hKey, &valNameU, 0,
                                        localRec.originalType, localRec.originalData,
                                        localRec.originalDataLen);
                                } else {
                                    ZwDeleteValueKey(hKey, &valNameU);
                                }
                            } else if (localRec.regOp == BA_ROP_DeleteValue) {
                                if (localRec.hadExistingValue && localRec.originalDataLen > 0) {
                                    ZwSetValueKey(hKey, &valNameU, 0,
                                        localRec.originalType, localRec.originalData,
                                        localRec.originalDataLen);
                                }
                            }
                            ZwClose(hKey);
                        }
                    } __finally {
                        InterlockedDecrement(&g_regDriverAccessDepth);
                    }
                }
            }
        }
    }

    DriverDbgPrint("[BA-EXEC] Rollback execution complete\n");

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[BA-EXEC] Exception caught during rollback\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 周期性清理：移除已退出进程的所有残留数据，防止内存浪费
 *
 * 清理范围：
 *   1. g_baProcTree — 移除已退出但未被 exit callback 捕获的进程条目
 *   2. g_baIndicatorPids/g_baPidIndicators/g_baEvidence — 通过 cleanupStalePids 清理
 *   3. g_baAlertedPids — 移除已退出进程的告警记录（允许 PID 复用时重新检测）
 *   4. g_baHistory — 清零已退出进程的历史事件条目
 *   5. g_baDroppedFiles — 失效已退出进程的文件释放记录
 *
 * 注意：PsLookupProcessByProcessId 需要 PASSIVE_LEVEL，不能在持自旋锁时调用。
 *       采用两阶段：先不持锁收集 PID 并检查存活，再持锁清理残留。
 * ══════════════════════════════════════════════════════════════════════════ */
#define BA_CLEANUP_INTERVAL_TICKS  20  /* 每 20 轮定时器周期（约 10 秒）执行一次清理 */

static VOID BehaviorAnalysisPeriodicCleanup(VOID)
{
    INT64* checkPids = NULL;
    INT64* deadPids = NULL;
    INT checkCount = 0;
    INT deadCount = 0;
    int i, j;
    KIRQL oldIrql = 0;
    PKSPIN_LOCK heldLock = NULL;
    KIRQL droppedIrql = 0;
    PKSPIN_LOCK heldDroppedLock = NULL;
    KIRQL regIrql = 0;
    PKSPIN_LOCK heldRegLock = NULL;

    __try {

    /* Phase 1: 持锁拷贝 ProcTree 中所有 PID */
    checkPids = (INT64*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        BA_MAX_PROCESSES * sizeof(INT64), 'Clba');
    deadPids = (INT64*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        BA_MAX_PROCESSES * sizeof(INT64), 'Dlba');
    if (!checkPids || !deadPids) {
        return;
    }

    heldLock = &g_baLock;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    for (i = 0; i < g_baProcCount && checkCount < BA_MAX_PROCESSES; i++) {
        if (g_baProcTree[i].pid != 0) {
            checkPids[checkCount++] = g_baProcTree[i].pid;
        }
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    heldLock = NULL;

    /* Phase 2: 不持锁检查每个 PID 的存活状态（PASSIVE_LEVEL） */
    for (i = 0; i < checkCount; i++) {
        PEPROCESS process = NULL;
        NTSTATUS status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)checkPids[i], &process);
        if (NT_SUCCESS(status)) {
            ObDereferenceObject(process);
        } else {
            deadPids[deadCount++] = checkPids[i];
        }
    }

    if (deadCount == 0) {
        return;
    }

    DriverDbgPrint("[BA-CLEANUP] Periodic: %d dead processes detected, cleaning up\n",
        deadCount);

    /* Phase 3: 持锁清理死进程在所有数据结构中的残留 */
    heldLock = &g_baLock;
    KeAcquireSpinLock(&g_baLock, &oldIrql);

    /* 3a. 标记死进程条目（pid=0）并从父进程子列表移除 */
        for (j = 0; j < deadCount; j++) {
            INT64 deadPid = deadPids[j];
            int idx = findProc(deadPid);
            if (idx < 0) continue;

            /* 从父进程的子进程列表中移除 */
            {
                INT64 parentPid = g_baProcTree[idx].parentPid;
                if (parentPid != 0) {
                    int pidx = findProc(parentPid);
                    if (pidx >= 0) {
                        int ci;
                        for (ci = 0; ci < g_baProcTree[pidx].childCount; ci++) {
                            if (g_baProcTree[pidx].childPids[ci] == deadPid) {
                                g_baProcTree[pidx].childPids[ci] =
                                    g_baProcTree[pidx].childPids[g_baProcTree[pidx].childCount - 1];
                                g_baProcTree[pidx].childCount--;
                                break;
                            }
                        }
                    }
                }
            }
            /* 标记为死条目 */
            g_baProcTree[idx].pid = 0;
        }

        /* 3b. 紧凑化 ProcTree — 将存活条目前移填充空位 */
        {
            int writeIdx = 0;
            for (i = 0; i < g_baProcCount; i++) {
                if (g_baProcTree[i].pid != 0) {
                    if (writeIdx != i) {
                        RtlCopyMemory(&g_baProcTree[writeIdx], &g_baProcTree[i],
                            sizeof(BA_PROCESS_NODE));
                        RtlZeroMemory(&g_baProcTree[i], sizeof(BA_PROCESS_NODE));
                    }
                    writeIdx++;
                } else {
                    RtlZeroMemory(&g_baProcTree[i], sizeof(BA_PROCESS_NODE));
                }
            }
            if (writeIdx != g_baProcCount) {
                DriverDbgPrint("[BA-CLEANUP] ProcTree: %d -> %d entries\n",
                    g_baProcCount, writeIdx);
            }
            g_baProcCount = writeIdx;
        }

        /* 3c. 清理 indicators/evidence（cleanupStalePids 会移除不在 ProcTree 中的 PID） */
        cleanupStalePids();

        /* 3d. 清理 g_baAlertedPids — 移除死进程的告警记录 */
        {
            int newAlertedCount = 0;
            for (i = 0; i < g_baAlertedCount; i++) {
                INT64 apid = g_baAlertedPids[i];
                BOOLEAN isDead = FALSE;
                for (j = 0; j < deadCount; j++) {
                    if (apid == deadPids[j]) { isDead = TRUE; break; }
                }
                if (!isDead) {
                    g_baAlertedPids[newAlertedCount++] = apid;
                }
            }
            if (newAlertedCount != g_baAlertedCount) {
                DriverDbgPrint("[BA-CLEANUP] AlertedPids: %d -> %d\n",
                    g_baAlertedCount, newAlertedCount);
            }
            g_baAlertedCount = newAlertedCount;
        }

        /* 3e. 清零 g_baHistory 中死进程的事件条目 */
        {
            int cleared = 0;
            for (i = 0; i < BA_MAX_HISTORY; i++) {
                INT64 epid = g_baHistory[i].pid;
                if (epid == 0) continue;
                for (j = 0; j < deadCount; j++) {
                    if (epid == deadPids[j]) {
                        RtlZeroMemory(&g_baHistory[i], sizeof(BA_STORED_EVENT));
                        cleared++;
                        break;
                    }
                }
            }
            if (cleared > 0) {
                DriverDbgPrint("[BA-CLEANUP] History events zeroed: %d\n", cleared);
            }
        }

        /* 3f. 清理过期的幽灵进程条目（TTL 过期）— 必须在持锁状态下执行，
         * 避免与 BehaviorRecordProcessExit 并发修改 g_baGhostProcesses 导致竞争条件。 */
        {
            int newGhostCount = 0;
            INT64 currentTick = g_baTickCounter;
            for (i = 0; i < g_baGhostCount; i++) {
                INT64 elapsed = currentTick - g_baGhostProcesses[i].exitTick;
                if (elapsed <= BA_GHOST_TTL_TICKS) {
                    if (newGhostCount != i) {
                        g_baGhostProcesses[newGhostCount] = g_baGhostProcesses[i];
                    }
                    newGhostCount++;
                } else {
                    DriverDbgPrint("[BA-CLEANUP] Ghost process expired: PID=%lld (age=%lld ticks)\n",
                        g_baGhostProcesses[i].pid, elapsed);
                }
            }
            if (newGhostCount < g_baGhostCount) {
                RtlZeroMemory(&g_baGhostProcesses[newGhostCount],
                    sizeof(BA_GHOST_PROCESS) * (g_baGhostCount - newGhostCount));
                DriverDbgPrint("[BA-CLEANUP] Ghost processes: %d -> %d\n",
                    g_baGhostCount, newGhostCount);
            }
            g_baGhostCount = newGhostCount;
        }

    KeReleaseSpinLock(&g_baLock, oldIrql);
    heldLock = NULL;

    /* Phase 4: 清理 g_baDroppedFiles 中死进程的记录（独立锁）
     * 注意：已告警进程的 dropped files 不立即清除，保留供回滚使用 */
    if (g_baDroppedFiles != NULL)
    {
        int invalidated = 0;
        heldDroppedLock = &g_baDroppedFileLock;
        KeAcquireSpinLock(&g_baDroppedFileLock, &droppedIrql);
        for (i = 0; i < BA_MAX_DROPPED_FILES; i++) {
            if (!g_baDroppedFiles[i].valid) continue;
            /* 跳过已告警进程的 dropped files — 回滚需要这些记录 */
            {
                BOOLEAN isAlerted = FALSE;
                for (int ai = 0; ai < g_baAlertedCount; ai++) {
                    if (g_baAlertedPids[ai] == g_baDroppedFiles[i].pid) {
                        isAlerted = TRUE;
                        break;
                    }
                }
                if (isAlerted) continue;
            }
            for (j = 0; j < deadCount; j++) {
                if (g_baDroppedFiles[i].pid == deadPids[j]) {
                    g_baDroppedFiles[i].valid = FALSE;
                    invalidated++;
                    break;
                }
            }
        }
        KeReleaseSpinLock(&g_baDroppedFileLock, droppedIrql);
        heldDroppedLock = NULL;
        if (invalidated > 0) {
            DriverDbgPrint("[BA-CLEANUP] DroppedFiles invalidated: %d\n", invalidated);
        }
    }

    /* Phase 5: 清理 g_baRegOps 中死进程的注册表回滚记录（独立锁） */
    if (g_baRegOps != NULL)
    {
        int invalidated = 0;
        heldRegLock = &g_baRegOpLock;
        KeAcquireSpinLock(&g_baRegOpLock, &regIrql);
        for (i = 0; i < BA_MAX_REG_OPS; i++) {
            if (!g_baRegOps[i].valid) continue;
            for (j = 0; j < deadCount; j++) {
                if (g_baRegOps[i].pid == deadPids[j]) {
                    g_baRegOps[i].valid = FALSE;
                    invalidated++;
                    break;
                }
            }
        }
        KeReleaseSpinLock(&g_baRegOpLock, regIrql);
        heldRegLock = NULL;
        if (invalidated > 0) {
            DriverDbgPrint("[BA-CLEANUP] RegOps invalidated: %d\n", invalidated);
        }
    }

    } __finally {
        if (heldLock) {
            KeReleaseSpinLock(heldLock, oldIrql);
            heldLock = NULL;
        }
        if (heldDroppedLock) {
            KeReleaseSpinLock(heldDroppedLock, droppedIrql);
            heldDroppedLock = NULL;
        }
        if (heldRegLock) {
            KeReleaseSpinLock(heldRegLock, regIrql);
            heldRegLock = NULL;
        }
        if (checkPids) {
            ExFreePool(checkPids);
            checkPids = NULL;
        }
        if (deadPids) {
            ExFreePool(deadPids);
            deadPids = NULL;
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 异步定时器分析线程（卡巴斯基思路）
 *
 * 回调中仅同步记录事件（BehaviorRecord*），不阻塞 I/O 路径。
 * 本线程每 500ms 轮询所有活跃 PID，异步执行威胁评估和告警。
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── PE 头检测辅助函数 ── */
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE  0x5A4D
#endif

/* 通过文件路径读取前2字节判断是否为 PE 文件（MZ 签名）
 * 仅在用户态上下文（定时器线程）中调用，可做同步 I/O */
static BOOLEAN BaCheckFileIsPe(PWSTR filePath)
{
    if (!filePath || filePath[0] == L'\0') return FALSE;

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    UNICODE_STRING uniPath = { 0 };
    uniPath.Buffer = filePath;
    uniPath.Length = (USHORT)(wcslen(filePath) * sizeof(WCHAR));
    uniPath.MaximumLength = uniPath.Length + sizeof(WCHAR);

    NTSTATUS status = IoCreateFileEx(
        &hFile,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0,
        CreateFileTypeNone, NULL,
        IO_FORCE_ACCESS_CHECK, NULL);

    if (!NT_SUCCESS(status) || !hFile) return FALSE;

    BOOLEAN isPe = FALSE;
    UCHAR magic[2] = { 0 };
    IO_STATUS_BLOCK iosb2 = { 0 };
    NTSTATUS readStatus = ZwReadFile(hFile, NULL, NULL, NULL, &iosb2,
        magic, sizeof(magic), NULL, NULL);
    if (NT_SUCCESS(readStatus) && iosb2.Information >= 2) {
        USHORT magicVal = (USHORT)(magic[0] | (magic[1] << 8));
        isPe = (magicVal == IMAGE_DOS_SIGNATURE);
    }

    ZwClose(hFile);
    return isPe;
}

/* 将 Unicode 路径（含 \Device\ 前缀）转换为内核对象路径并检查 PE 头 */
static BOOLEAN BaCheckPathIsPe(const CHAR* pathA)
{
    if (!pathA || pathA[0] == '\0') return FALSE;

    /* pathA 是内核路径格式（\Device\HarddiskVolume...\...）
     * 直接用其构造 UNICODE_STRING，IoCreateFileEx 可接受 */
    INT len = kStrLen(pathA);
    if (len <= 0 || len > 1020) return FALSE;

    USHORT lenW = (USHORT)(len * 2 + 2);
    PWSTR wPath = (PWSTR)ExAllocatePool2(POOL_FLAG_NON_PAGED, lenW, 'BpCh');
    if (!wPath) return FALSE;

    /* 简单 ANSI→UTF-16：每个 ASCII 字符扩展为 WCHAR */
    for (int j = 0; j < len; j++) {
        wPath[j] = (WCHAR)(ULONG_PTR)pathA[j];
    }
    wPath[len] = L'\0';

    BOOLEAN result = BaCheckFileIsPe(wPath);
    ExFreePoolWithTag(wPath, 'BpCh');
    return result;
}

static VOID BehaviorAnalysisTimerThread(PVOID Context)
{
    int cleanupCounter = 0;

    UNREFERENCED_PARAMETER(Context);

    DriverDbgPrint("BehaviorAnalysis: Timer thread started\n");

    while (g_baTimerRunning) {
        LARGE_INTEGER interval;
        interval.QuadPart = -500 * 10000;  /* 500ms in 100ns units */
        KeDelayExecutionThread(KernelMode, FALSE, &interval);

        if (!g_baTimerRunning) break;

        /* 优化：只复制脏PID列表（有新事件的进程），而非全量扫描所有进程
         * 大幅减少无活动期间的CPU开销 */
        INT64* localPids = (INT64*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            BA_MAX_PROCESSES * sizeof(INT64), 'HbaP');
        if (!localPids) {
            continue;
        }

        {
            KIRQL oldIrql = 0;
            BOOLEAN lockHeld = FALSE;

            __try {
                int localCount = 0;

                lockHeld = TRUE;
                KeAcquireSpinLock(&g_baLock, &oldIrql);

                /* 复制脏PID列表并清空 */
                {
                    int i;
                    for (i = 0; i < g_baDirtyCount && localCount < BA_MAX_PROCESSES; i++) {
                        INT64 pid = g_baDirtyPids[i];
                        if (pid == 0) continue;

                        /* 已告警过的进程树根进程 → 跳过 */
                        {
                            INT64 rootPid = FindRootAncestor(pid);
                            int ai, alreadyAlerted = 0;
                            for (ai = 0; ai < g_baAlertedCount; ai++) {
                                if (g_baAlertedPids[ai] == rootPid) { alreadyAlerted = 1; break; }
                            }
                            if (alreadyAlerted) continue;
                        }

                        localPids[localCount++] = pid;
                    }
                }

                /* 清空脏PID列表 */
                g_baDirtyCount = 0;
                RtlZeroMemory(g_baDirtyPids, sizeof(g_baDirtyPids));

                KeReleaseSpinLock(&g_baLock, oldIrql);
                lockHeld = FALSE;

                /* 对每个脏 PID 执行异步威胁评估（不持锁，可阻塞等待客户端响应） */
                if (localCount > 0) {
                    int i;
                    for (i = 0; i < localCount; i++) {
                        if (!g_baTimerRunning) break;
                        __try {
                            /* 补全 isPeFile：对 isPeFile==FALSE 的 Create 事件检测 PE 头
                             * 注意：不能在持锁状态下做阻塞 I/O，先收集需要检测的路径 */
                            {
                                KIRQL oldIrql2;
                                INT peCheckCount = 0;
                                /* 堆分配替代大栈数组：64KB 栈上分配会导致栈溢出 */
                                CHAR* peCheckPaths = (CHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                    (SIZE_T)64 * BA_MAX_PATH, 'BpCK');
                                if (peCheckPaths) {
                                    KeAcquireSpinLock(&g_baLock, &oldIrql2);
                                    for (int hi = 0; hi < g_baHistoryCount && peCheckCount < 64; hi++) {
                                        int histIdx = (g_baHistoryHead - g_baHistoryCount + hi + BA_MAX_HISTORY) % BA_MAX_HISTORY;
                                        BA_STORED_EVENT* hEv = &g_baHistory[histIdx];
                                        if (hEv->pid != localPids[i]) continue;
                                        if (hEv->category != BA_EC_File || hEv->fileOp != BA_FOP_Create) continue;
                                        if (hEv->isPeFile) continue;
                                        if (hEv->filePath[0] == '\0') continue;
                                        kStrCpy(&peCheckPaths[(SIZE_T)peCheckCount * BA_MAX_PATH], BA_MAX_PATH, hEv->filePath);
                                        peCheckCount++;
                                    }
                                    KeReleaseSpinLock(&g_baLock, oldIrql2);

                                    /* 锁外做 I/O 检测 */
                                    for (int pi = 0; pi < peCheckCount; pi++) {
                                        BOOLEAN isPe = BaCheckPathIsPe(&peCheckPaths[(SIZE_T)pi * BA_MAX_PATH]);
                                        /* 更新历史事件 */
                                        KeAcquireSpinLock(&g_baLock, &oldIrql2);
                                        for (int hi = 0; hi < g_baHistoryCount; hi++) {
                                            int histIdx = (g_baHistoryHead - g_baHistoryCount + hi + BA_MAX_HISTORY) % BA_MAX_HISTORY;
                                            BA_STORED_EVENT* hEv = &g_baHistory[histIdx];
                                            if (hEv->pid != localPids[i]) continue;
                                            if (hEv->category != BA_EC_File || hEv->fileOp != BA_FOP_Create) continue;
                                            if (hEv->isPeFile) continue;
                                            if (kStrCmp(hEv->filePath, &peCheckPaths[(SIZE_T)pi * BA_MAX_PATH]) == 0) {
                                            hEv->isPeFile = isPe;
                                            /* 如果是 PE 文件且之前因 isPeFile==FALSE 跳过了指标，现在重新提取 */
                                            if (isPe) {
                                                extractIndicators(hEv);
                                            }
                                            break;
                                        }
                                        }
                                        KeReleaseSpinLock(&g_baLock, oldIrql2);
                                    }
                                    ExFreePoolWithTag(peCheckPaths, 'BpCK');
                                }
                            }
                            BehaviorCheckAndAlert(localPids[i], "");
                        } __except (EXCEPTION_EXECUTE_HANDLER) {
                            DriverDbgPrint("[BA-TIMER] Exception in BehaviorCheckAndAlert for PID=%lld, continuing\n",
                                localPids[i]);
                        }
                    }
                }

                /* 周期性清理：每 BA_CLEANUP_INTERVAL_TICKS 轮（约 10 秒）执行一次
                 * 移除已退出进程在 ProcTree/Indicators/AlertedPids/History/DroppedFiles 中的残留 */
                cleanupCounter++;
                if (cleanupCounter >= BA_CLEANUP_INTERVAL_TICKS) {
                    cleanupCounter = 0;
                    BehaviorAnalysisPeriodicCleanup();
                }
            } __finally {
                if (lockHeld) {
                    KeReleaseSpinLock(&g_baLock, oldIrql);
                    lockHeld = FALSE;
                }
                ExFreePool(localPids);
            }
        }
    }

    DriverDbgPrint("BehaviorAnalysis: Timer thread exiting\n");
    KeSetEvent(&g_baTimerExitEvent, 0, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/* BehaviorStartTimerThread — 启动异步分析定时器线程 */
VOID BehaviorStartTimerThread(VOID)
{
    NTSTATUS status;
    HANDLE threadHandle;

    if (g_baTimerRunning) return;

    KeInitializeEvent(&g_baTimerExitEvent, NotificationEvent, FALSE);
    g_baTimerRunning = 1;

    /* 枚举已有进程，补充进程树（解决 Unknown 路径问题） */
    EnumerateExistingProcesses();

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        BehaviorAnalysisTimerThread,
        NULL);

    if (NT_SUCCESS(status)) {
        ZwClose(threadHandle);  /* 关闭句柄，线程独立运行 */
        DriverDbgPrint("BehaviorAnalysis: Timer thread created successfully\n");
    } else {
        g_baTimerRunning = 0;
        DriverDbgPrint("BehaviorAnalysis: Failed to create timer thread: 0x%X\n", status);
    }
}

/* BehaviorStopTimerThread — 停止异步分析定时器线程 */
VOID BehaviorStopTimerThread(VOID)
{
    if (!g_baTimerRunning) return;

    DriverDbgPrint("BehaviorAnalysis: Stopping timer thread...\n");
    g_baTimerRunning = 0;

    /* 等待线程退出（最多 10 秒）
     * 线程可能阻塞在用户响应等待中，ResponseSystemCancelAll 会唤醒它，
     * 然后线程需要恢复挂起的进程、清理资源、退出循环 */
    {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000000;  /* 10 seconds in 100ns units */
        KeWaitForSingleObject(
            &g_baTimerExitEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
    }

    DriverDbgPrint("BehaviorAnalysis: Timer thread stopped\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorCheckAndAlert — EDR 进程树综合研判（生产级）
 *
 * 检测到威胁后通过异步 work item 执行：
 *   - 挂起进程树
 *   - 向客户端弹窗等待用户决策（30 秒超时默认 BLOCK）
 *   - BLOCK: 终止进程树并清理释放的新文件
 *   - ALLOW: 恢复进程树
 * 进程树中包含系统关键进程时仅记录日志，不执行拦截，防止系统损坏。
 * 行为检测总开关 g_bBehaviorDetectionEnabled 由用户态控制，默认禁用。
 *
 * 流程：
 *   1. 检查行为检测总开关是否启用
 *   2. 沿进程树向上追溯，找到可疑根进程（脚本解释器/来自Temp/未签名）
 *   3. 聚合根进程及其所有子孙进程的行为指标
 *   4. 综合评分 + 阈值判定
 *   5. 匹配最优威胁画像
 *   6. 收集树内所有证据，打印详细日志
 *   7. 入队异步 work item 执行挂起/弹窗/终止/恢复
 *   8. 标记为已告警并清除指标，避免重复告警
 * ══════════════════════════════════════════════════════════════════════════ */

NTSTATUS BehaviorCheckAndAlert(INT64 pid, const CHAR* imagePath)
{
    KIRQL oldIrql = 0;
    KFLOATING_SAVE floatSave;
    NTSTATUS fpStatus;
    int i;
    DOUBLE combined[BA_MAX_INDICATORS];
    int distinctCnt;
    DOUBLE totalScore;
    BEHAVIOR_DETECTED_RESPONSE alertInfo;
    INT64 rootPid;
    CHAR rootImagePath[BA_MAX_PATH] = {0};

    /* 进程树 PID 列表 — 栈上分配，避免多线程并发覆盖 */
    INT64 treePids[BA_MAX_TREE_PIDS];
    int treePidCount = 0;

    BOOLEAN floatSaved = FALSE;
    BOOLEAN lockHeld = FALSE;

    UNREFERENCED_PARAMETER(imagePath);

    /* 调试/控制：行为检测总开关未启用时直接返回，不评估不记录告警。
     * 这样用户可以在 ProtectionSetting 中完全关闭行为检测。 */
    if (!g_bBehaviorDetectionEnabled)
    {
        return STATUS_SUCCESS;
    }

    /* 行为分析定时器线程中执行，涉及 Zw*、FPU、进程树遍历等复杂操作。
     * 用 SEH 包裹全部逻辑：异常时释放自旋锁和 FPU 状态，避免蓝屏。 */
    __try {

    /* 早期基础过滤：PID/系统进程/白名单 */
    {
        INT64 rootPidToCheck;
        int rootIdx;
        lockHeld = TRUE;
        KeAcquireSpinLock(&g_baLock, &oldIrql);
        rootPidToCheck = FindRootAncestor(pid);
        rootIdx = findProc(rootPidToCheck);
        if (rootIdx >= 0 && g_baProcTree[rootIdx].imagePath[0] != '\0') {
            RtlStringCbCopyA(rootImagePath, BA_MAX_PATH, g_baProcTree[rootIdx].imagePath);
        }
        KeReleaseSpinLock(&g_baLock, oldIrql);
        lockHeld = FALSE;

        if (rootPidToCheck <= 4) return STATUS_SUCCESS;

        if (rootImagePath[0] != '\0' && isGenuineSystemProcess(rootIdx, rootImagePath)) {
            return STATUS_SUCCESS;
        }

        if (rootImagePath[0] != '\0' && BehaviorIsWhitelisted(rootImagePath)) {
            BehaviorLogDebug("Root process %s (PID=%lld) is whitelisted, skipping alert",
                rootImagePath, rootPidToCheck);
            return STATUS_SUCCESS;
        }
    }

    /* ── 步骤1: 沿进程树向上追溯，找到根进程 ── */
    lockHeld = TRUE;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    rootPid = FindRootAncestor(pid);
    KeReleaseSpinLock(&g_baLock, oldIrql);
    lockHeld = FALSE;

    /* 根进程已告警过 → 跳过（避免同一进程树重复告警） */
    if (IsAlreadyAlerted(rootPid)) {
        return STATUS_SUCCESS;
    }

    /* 保存 FPU 状态 — 步骤2在 DISPATCH_LEVEL 下包含浮点运算（DOUBLE 赋值、
     * AggregateTreeIndicators 中的乘法/加法），必须先保存 FPU/XMM 状态，
     * 否则在 x64 内核模式中会导致 PAGE_FAULT_IN_NONPAGED_AREA 蓝屏 */
    fpStatus = KeSaveFloatingPointState(&floatSave);
    if (!NT_SUCCESS(fpStatus)) return STATUS_SUCCESS;
    floatSaved = TRUE;

    /* ── 步骤2: 聚合整个进程树的指标 ── */
    lockHeld = TRUE;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    for (i = 0; i < BA_MAX_INDICATORS; i++) combined[i] = 0.0;
    distinctCnt = 0;
    totalScore = 0.0;
    BehaviorAggregateTreeIndicators(rootPid, combined, &distinctCnt, &totalScore);

    /* ── 聚合幽灵进程（已退出父进程）的指标到 combined[] ──
     * 解决"检测不到"问题：当父进程退出后，BehaviorAggregateTreeIndicators
     * 无法通过 g_baProcTree 遍历到子进程（父链断裂），导致子进程指标丢失。
     * 此处补充：遍历幽灵进程，将与 rootPid 同一进程树的幽灵指标合并。
     * 同时补充：活跃子进程其父链经过幽灵进程的，也合并其指标。 */
    {
        int gi;
        for (gi = 0; gi < g_baGhostCount; gi++) {
            PBA_GHOST_PROCESS ghost = &g_baGhostProcesses[gi];
            if (!ghost->hasSuspiciousIndicators) continue;

            /* 检查幽灵进程是否属于 rootPid 的进程树：
             * 1. 幽灵自身就是 rootPid
             * 2. 幽灵的父进程链中包含 rootPid */
            BOOLEAN inTree = (ghost->pid == rootPid);
            if (!inTree) {
                INT64 current = ghost->parentPid;
                int iter = 0;
                while (iter < 32 && current != 0) {
                    if (current == rootPid) { inTree = TRUE; break; }
                    /* 在活跃进程树中查找父进程 */
                    int pidx = findProc(current);
                    if (pidx >= 0) {
                        current = g_baProcTree[pidx].parentPid;
                    } else {
                        /* 在幽灵进程中查找父进程 */
                        PBA_GHOST_PROCESS parentGhost = FindGhostProcess(current);
                        if (parentGhost) {
                            current = parentGhost->parentPid;
                        } else {
                            break;
                        }
                    }
                    iter++;
                }
            }

            if (!inTree) continue;

            /* 将幽灵进程的指标合并到 combined[] */
            {
                int j;
                for (j = 0; j < BA_MAX_INDICATORS; j++) {
                    if (ghost->indicators[j] > 0 && combined[j] == 0.0) {
                        combined[j] = BehaviorGetIndicatorBaseScore((BA_INDICATOR)j) *
                                      (ghost->indicators[j] > 2 ? 2.0 : (DOUBLE)ghost->indicators[j]);
                        totalScore += combined[j];
                        distinctCnt++;
                    }
                }
            }
        }

        /* 补充：活跃子进程其父链经过幽灵进程的（BehaviorAggregateTreeIndicators 漏掉的）。
         * 遍历所有有指标的活跃进程，检查是否属于 rootPid 的树（通过幽灵感知的父链遍历）。 */
        {
            int pi;
            for (pi = 0; pi < g_baIndicatorCount; pi++) {
                INT64 checkPid = g_baIndicatorPids[pi];
                if (checkPid == 0) continue;
                if (checkPid == rootPid) continue;  /* rootPid 自身已由 BehaviorAggregateTreeIndicators 处理 */

                /* 检查该进程的指标是否已被聚合（如果 combined 中已有该进程的指标则跳过） */
                int pidIdx = findPidIndex(checkPid);
                if (pidIdx < 0) continue;

                /* 检查是否有未被聚合的指标 */
                BOOLEAN hasUnaggregated = FALSE;
                int j;
                for (j = 0; j < BA_MAX_INDICATORS; j++) {
                    if (g_baPidIndicators[pidIdx][j] > 0 && combined[j] == 0.0) {
                        hasUnaggregated = TRUE;
                        break;
                    }
                }
                if (!hasUnaggregated) continue;

                /* 通过幽灵感知的父链遍历检查是否属于 rootPid 的树 */
                BOOLEAN inTree = FALSE;
                INT64 current = checkPid;
                int iter = 0;
                while (iter < 32 && current != 0) {
                    if (current == rootPid) { inTree = TRUE; break; }
                    int pidx = findProc(current);
                    if (pidx >= 0) {
                        INT64 parent = g_baProcTree[pidx].parentPid;
                        if (parent == 0 || parent == current) break;
                        current = parent;
                    } else {
                        PBA_GHOST_PROCESS parentGhost = FindGhostProcess(current);
                        if (parentGhost) {
                            current = parentGhost->parentPid;
                        } else {
                            break;
                        }
                    }
                    iter++;
                }

                if (!inTree) continue;

                /* 合并该活跃进程的指标 */
                for (j = 0; j < BA_MAX_INDICATORS; j++) {
                    int cnt = g_baPidIndicators[pidIdx][j];
                    if (cnt > 0 && combined[j] == 0.0) {
                        combined[j] = BehaviorGetIndicatorBaseScore((BA_INDICATOR)j) *
                                      (cnt > 2 ? 2.0 : (DOUBLE)cnt);
                        totalScore += combined[j];
                        distinctCnt++;
                    }
                }
            }
        }
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    lockHeld = FALSE;

    /* ── 信任链加权：对带可信签名的根进程降低整棵进程树的指标强度，
     * 减少可信软件的误报。msiexec.exe 等被强制不可信的进程（CiIsPidSigned=FALSE）
     * 不享受加成，其恶意 MSI 释放/修改行为保持完整检测权重。
     * 注意：combined[]/totalScore 已聚合完毕，此处做整体衰减。 */
    {
        DOUBLE trustBonus = BehaviorGetTrustBonus(rootPid, rootImagePath);
        if (trustBonus > 0.0) {
            for (i = 0; i < BA_MAX_INDICATORS; i++) {
                if (combined[i] > 0.0) combined[i] *= (1.0 - trustBonus);
            }
            totalScore *= (1.0 - trustBonus);
            DriverDbgPrint("[BA-DETECT] Trust bonus=%.2f applied to root PID=%lld tree, totalScore=%.1f\n",
                trustBonus, rootPid, totalScore);
        }
    }

    /* ── 步骤3: 动态规则匹配（静态 profiles 已移除，全部由 TOML 动态规则管理）──
     * 匹配逻辑：
     *   A) 动态规则匹配成功 → 触发告警
     *   B) 后备：总分 >= 100 且 distinctCnt >= 6 → 触发告警（Generic） */
    RtlZeroMemory(&alertInfo, sizeof(alertInfo));
    {
        DOUBLE bestMatchScore = 0;
        DOUBLE realtimeThreshold = BA_REALTIME_THRESHOLD;
        int requiredDistinct = 8;

        /* 动态规则匹配 */
        {
            DOUBLE dynScore = 0.0;
            ULONG dynRuleId = 0;
            DOUBLE dynConfidence = 0.0;
            NTSTATUS dynStatus = BehaviorMatchDynamicRules(combined, rootImagePath, rootPid,
                &dynScore, &dynRuleId, &dynConfidence);
            if (NT_SUCCESS(dynStatus) && dynScore > bestMatchScore) {
                BA_DYNAMIC_RULE* dynRule = BaFindDynamicRule(dynRuleId);
                if (dynRule != NULL) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass), dynRule->ThreatClass);
                    RtlStringCbCopyA(alertInfo.Description, sizeof(alertInfo.Description), dynRule->Description);
                    alertInfo.Confidence = dynConfidence;
                    if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                    BehaviorUpdateRuleStatsOnMatch(dynRuleId, dynScore, TRUE);
                    bestMatchScore = dynScore;
                    DriverDbgPrint("[BA-DETECT] Dynamic rule %lu matched for PID=%lld, score=%.1f\n",
                        dynRuleId, rootPid, dynScore);
                }
            }
        }

        if (bestMatchScore <= 0) {
            /* 后备：总分 >= realtimeThreshold 且 distinctCnt >= requiredDistinct */
            if (totalScore >= realtimeThreshold && distinctCnt >= requiredDistinct) {
                RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                    "Behavior/SuspiciousBehaviorChain.Generic");
                RtlStringCbCopyA(alertInfo.Description, sizeof(alertInfo.Description),
                    "Suspicious behavior chain detected (multiple behavioral indicators)");
                alertInfo.Confidence = totalScore / 100.0;
                if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                /* 通用阈值通过后，仍检查高危行为链以覆盖家族归类 */
                BOOLEAN chainMatched2 = FALSE;
                BOOLEAN tempOrigin2   = (combined[BA_IND_PROC_FROM_TEMP_DIR] > 0.0 ||
                                         combined[BA_IND_PROC_FROM_DOWNLOADS_DIR] > 0.0 ||
                                         combined[BA_IND_PROC_FROM_APPDATA_DIR] > 0.0);
                BOOLEAN c2Connect2    = (combined[BA_IND_NET_C2_CONNECT] > 0.0 ||
                                         combined[BA_IND_NETWORK_C2_CONNECT] > 0.0 ||
                                         combined[BA_IND_NET_SUSPICIOUS_DNS] > 0.0);
                BOOLEAN hiddenFile2   = (combined[BA_IND_FILE_SET_SYSTEM_HIDDEN] > 0.0);
                BOOLEAN peInImage2    = (combined[BA_IND_FILE_PE_IN_IMAGE] > 0.0);
                BOOLEAN scriptInterp2 = (combined[BA_IND_PROC_SCRIPT_INTERPRETER] > 0.0);
                BOOLEAN selfExec2     = (combined[BA_IND_MEM_ALLOC_EXECUTE_SELF] > 0.0 ||
                                         combined[BA_IND_MEM_SELF_PROTECT_EXECUTABLE] > 0.0 ||
                                         combined[BA_IND_MEM_NONSYSTEM_RWX] > 0.0 ||
                                         combined[BA_IND_MEM_NONSYSTEM_EXEC_READ] > 0.0 ||
                                         combined[BA_IND_MEM_SHELLCODE_DETECTED] > 0.0);
                BOOLEAN allocExec2    = (combined[BA_IND_MEM_ALLOC_EXECUTE] > 0.0);
                BOOLEAN etwPatch2     = (combined[BA_IND_REG_ETW_PATCH] > 0.0);
                BOOLEAN instrCallback2= (combined[BA_IND_REG_INSTRUMENTATION_CALLBACK] > 0.0);
                BOOLEAN driverSvc2    = (combined[BA_IND_REG_DRIVER_SERVICE_CREATE] > 0.0 ||
                                         combined[BA_IND_FILE_BYOVD_DRIVER_LOAD] > 0.0);
                BOOLEAN dllSideLoad2  = (combined[BA_IND_FILE_DLL_SIDE_LOAD] > 0.0 ||
                                         combined[BA_IND_FILE_SELF_LOADING] > 0.0);
                BOOLEAN fileDrop2     = (combined[BA_IND_FILE_DROP_FROM_TEMP] > 0.0 ||
                                         combined[BA_IND_FILE_CREATE_STARTUP_EXE] > 0.0 ||
                                         combined[BA_IND_FILE_TEMP_RANDOM_NAME_EXE] > 0.0);
                BOOLEAN unsignedProc2 = (combined[BA_IND_PROC_UNSIGNED] > 0.0);
                BOOLEAN elevHijack2   = (combined[BA_IND_REG_ELEVATION_SERVICE_HIJACK] > 0.0 ||
                                         combined[BA_IND_FILE_ELEVATION_SERVICE_HIJACK] > 0.0);
                if ((tempOrigin2 && c2Connect2 && (dllSideLoad2 || fileDrop2 || hiddenFile2)) ||
                    (tempOrigin2 && scriptInterp2 && selfExec2) ||
                    (tempOrigin2 && hiddenFile2 && c2Connect2) ||
                    (tempOrigin2 && peInImage2 && hiddenFile2) ||
                    (tempOrigin2 && fileDrop2 && dllSideLoad2) ||
                    (unsignedProc2 && c2Connect2 && (dllSideLoad2 || fileDrop2 || selfExec2))) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.SilverFox/BehaviorChain");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "SilverFox behavior chain: temp=%d c2=%d sideLoad=%d drop=%d hidden=%d selfExec=%d script=%d peImg=%d",
                        tempOrigin2, c2Connect2, dllSideLoad2, fileDrop2, hiddenFile2, selfExec2, scriptInterp2, peInImage2);
                    if (alertInfo.Confidence < 0.85) alertInfo.Confidence = 0.85;
                    chainMatched2 = TRUE;
                    DriverDbgPrint("[BA-DETECT] SilverFox behavior chain (high-threshold): PID=%lld\n", rootPid);
                } else if (etwPatch2 || instrCallback2) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.AVBypass/ETWBypass");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "AV bypass: ETW patch=%d InstrumentationCallback=%d", etwPatch2, instrCallback2);
                    if (alertInfo.Confidence < 0.80) alertInfo.Confidence = 0.80;
                    chainMatched2 = TRUE;
                } else if (driverSvc2) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.Rootkit/DriverLoad");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "Rootkit: driverServiceCreate=%d byovdDriverLoad=%d",
                        (combined[BA_IND_REG_DRIVER_SERVICE_CREATE] > 0.0),
                        (combined[BA_IND_FILE_BYOVD_DRIVER_LOAD] > 0.0));
                    if (alertInfo.Confidence < 0.85) alertInfo.Confidence = 0.85;
                    chainMatched2 = TRUE;
                } else if ((selfExec2 || allocExec2) && (tempOrigin2 || c2Connect2 || unsignedProc2)) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.Exploit/ShellcodeExec");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "Shellcode execution: selfExec=%d temp=%d c2=%d unsigned=%d",
                        selfExec2, tempOrigin2, c2Connect2, unsignedProc2);
                    if (alertInfo.Confidence < 0.80) alertInfo.Confidence = 0.80;
                    chainMatched2 = TRUE;
                } else if (elevHijack2) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.Persistence/ElevationServiceHijack");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "elevation_service persistence hijack detected (T1543.003/T1574.002)");
                    if (alertInfo.Confidence < 0.80) alertInfo.Confidence = 0.80;
                    chainMatched2 = TRUE;
                }
                (void)chainMatched2;
            } else {
                /* ── 独立行为链检测（SilverFox/AVBypass/Rootkit/Exploit）──
                 * 当通用阈值（总分>=100 且 distinctCnt>=6）未通过时，
                 * 检查高危行为链模式。这些模式具有高置信度，即使指标数不足
                 * 也应直接触发告警。解决"检测不到"问题：原逻辑中
                 * BehaviorClassifyMalwareFamily 仅在通用阈值通过后才执行。 */
                BOOLEAN chainMatched = FALSE;
                BOOLEAN tempOrigin    = (combined[BA_IND_PROC_FROM_TEMP_DIR] > 0.0 ||
                                         combined[BA_IND_PROC_FROM_DOWNLOADS_DIR] > 0.0 ||
                                         combined[BA_IND_PROC_FROM_APPDATA_DIR] > 0.0);
                BOOLEAN c2Connect     = (combined[BA_IND_NET_C2_CONNECT] > 0.0 ||
                                         combined[BA_IND_NETWORK_C2_CONNECT] > 0.0 ||
                                         combined[BA_IND_NET_SUSPICIOUS_DNS] > 0.0);
                BOOLEAN hiddenFile    = (combined[BA_IND_FILE_SET_SYSTEM_HIDDEN] > 0.0);
                BOOLEAN peInImage     = (combined[BA_IND_FILE_PE_IN_IMAGE] > 0.0);
                BOOLEAN scriptInterp  = (combined[BA_IND_PROC_SCRIPT_INTERPRETER] > 0.0);
                BOOLEAN selfExec      = (combined[BA_IND_MEM_ALLOC_EXECUTE_SELF] > 0.0 ||
                                        combined[BA_IND_MEM_SELF_PROTECT_EXECUTABLE] > 0.0 ||
                                        combined[BA_IND_MEM_NONSYSTEM_RWX] > 0.0 ||
                                        combined[BA_IND_MEM_NONSYSTEM_EXEC_READ] > 0.0 ||
                                        combined[BA_IND_MEM_SHELLCODE_DETECTED] > 0.0);
                BOOLEAN allocExec     = (combined[BA_IND_MEM_ALLOC_EXECUTE] > 0.0);
                BOOLEAN etwPatch      = (combined[BA_IND_REG_ETW_PATCH] > 0.0);
                BOOLEAN instrCallback = (combined[BA_IND_REG_INSTRUMENTATION_CALLBACK] > 0.0);
                BOOLEAN driverSvc     = (combined[BA_IND_REG_DRIVER_SERVICE_CREATE] > 0.0 ||
                                         combined[BA_IND_FILE_BYOVD_DRIVER_LOAD] > 0.0);
                BOOLEAN dllSideLoad   = (combined[BA_IND_FILE_DLL_SIDE_LOAD] > 0.0 ||
                                         combined[BA_IND_FILE_SELF_LOADING] > 0.0);
                BOOLEAN fileDrop      = (combined[BA_IND_FILE_DROP_FROM_TEMP] > 0.0 ||
                                         combined[BA_IND_FILE_CREATE_STARTUP_EXE] > 0.0 ||
                                         combined[BA_IND_FILE_TEMP_RANDOM_NAME_EXE] > 0.0);
                BOOLEAN unsignedProc  = (combined[BA_IND_PROC_UNSIGNED] > 0.0);
                BOOLEAN elevHijack    = (combined[BA_IND_REG_ELEVATION_SERVICE_HIJACK] > 0.0 ||
                                         combined[BA_IND_FILE_ELEVATION_SERVICE_HIJACK] > 0.0);

                /* Trojan.SilverFox 行为链：
                 * 银狐典型链：Temp/下载起源 + C2通信 + (DLL加载|文件投放|隐藏文件)
                 * 或：Temp起源 + 脚本执行 + 自执行shellcode
                 * 或：Temp起源 + 隐藏文件 + C2通信
                 * 或：Temp起源 + 图像隐写 + 隐藏文件
                 * 或：Temp起源 + 文件投放 + DLL侧加载（投放+加载链）
                 * 或：未签名进程 + C2 + (DLL加载|文件投放|自执行) */
                if ((tempOrigin && c2Connect && (dllSideLoad || fileDrop || hiddenFile)) ||
                    (tempOrigin && scriptInterp && selfExec) ||
                    (tempOrigin && hiddenFile && c2Connect) ||
                    (tempOrigin && peInImage && hiddenFile) ||
                    (tempOrigin && fileDrop && dllSideLoad) ||
                    (unsignedProc && c2Connect && (dllSideLoad || fileDrop || selfExec))) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.SilverFox/BehaviorChain");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "SilverFox behavior chain: temp=%d c2=%d sideLoad=%d drop=%d hidden=%d selfExec=%d script=%d peImg=%d",
                        tempOrigin, c2Connect, dllSideLoad, fileDrop, hiddenFile, selfExec, scriptInterp, peInImage);
                    alertInfo.Confidence = 0.85;
                    if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                    chainMatched = TRUE;
                    DriverDbgPrint("[BA-DETECT] SilverFox behavior chain (independent): PID=%lld temp=%d c2=%d sideLoad=%d drop=%d hidden=%d selfExec=%d\n",
                        rootPid, tempOrigin, c2Connect, dllSideLoad, fileDrop, hiddenFile, selfExec);
                }
                /* Trojan.AVBypass：ETW patch 或 InstrumentationCallback 修改 */
                else if (etwPatch || instrCallback) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.AVBypass/ETWBypass");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "AV bypass: ETW patch=%d InstrumentationCallback=%d",
                        etwPatch, instrCallback);
                    alertInfo.Confidence = 0.80;
                    if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                    chainMatched = TRUE;
                    DriverDbgPrint("[BA-DETECT] AVBypass (independent): PID=%lld etw=%d instr=%d\n",
                        rootPid, etwPatch, instrCallback);
                }
                /* Trojan.Rootkit：高危驱动加载/服务创建 */
                else if (driverSvc) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.Rootkit/DriverLoad");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "Rootkit: driverServiceCreate=%d byovdDriverLoad=%d",
                        (combined[BA_IND_REG_DRIVER_SERVICE_CREATE] > 0.0),
                        (combined[BA_IND_FILE_BYOVD_DRIVER_LOAD] > 0.0));
                    alertInfo.Confidence = 0.85;
                    if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                    chainMatched = TRUE;
                    DriverDbgPrint("[BA-DETECT] Rootkit (independent): PID=%lld\n", rootPid);
                }
                /* Trojan.Exploit：shellcode 执行 + 可疑上下文 */
                else if ((selfExec || allocExec) && (tempOrigin || c2Connect || unsignedProc)) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.Exploit/ShellcodeExec");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "Shellcode execution: selfExec=%d temp=%d c2=%d unsigned=%d",
                        selfExec, tempOrigin, c2Connect, unsignedProc);
                    alertInfo.Confidence = 0.80;
                    if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                    chainMatched = TRUE;
                    DriverDbgPrint("[BA-DETECT] Exploit/ShellcodeExec (independent): PID=%lld\n", rootPid);
                } else if (elevHijack) {
                    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
                        "Trojan.Persistence/ElevationServiceHijack");
                    RtlStringCbPrintfA(alertInfo.Description, sizeof(alertInfo.Description),
                        "elevation_service persistence hijack detected (T1543.003/T1574.002)");
                    alertInfo.Confidence = 0.80;
                    if (alertInfo.Confidence > 0.95) alertInfo.Confidence = 0.95;
                    chainMatched = TRUE;
                    DriverDbgPrint("[BA-DETECT] ElevationServiceHijack (independent): PID=%lld\n", rootPid);
                }

                if (!chainMatched) {
                    floatSaved = FALSE;
                    KeRestoreFloatingPointState(&floatSave);
                    return STATUS_SUCCESS;
                }
            }
        }
    }

    /* 安全网：置信度异常（<=0、NaN、极小值）的告警不应发送到客户端，
     * 避免显示 "0.0%" 误报。 */
    if (alertInfo.Confidence <= 0.0 ||
        alertInfo.Confidence != alertInfo.Confidence || /* NaN */
        alertInfo.Confidence < 0.001)
    {
        /* 内核 RtlStringCbVPrintfA 不支持 %f，用整数（百万分比）显示 */
        LONG confPpm = (LONG)(alertInfo.Confidence * 1000000.0);
        DriverDbgPrint("[BA-DETECT] Suppressed alert with invalid confidence %ld/1000000 for PID=%lld\n",
            confPpm, pid);
        return STATUS_SUCCESS;
    }

    /* ── 步骤5: 收集进程树信息 ──
     * 正式拦截模式：挂起进程树 → 请示用户 → 终止/恢复 + 文件清除
     *
     * 注意：ZwQueryInformationProcess / ZwClose 是系统调用，必须在 PASSIVE_LEVEL 执行。
     * 不能在 KeAcquireSpinLock（DISPATCH_LEVEL）内调用，否则蓝屏 PAGE_FAULT_IN_NONPAGED_AREA。
     * 因此分两步：锁内只读全局数组，锁外在 PASSIVE_LEVEL 做系统调用。 */
    rootImagePath[0] = '\0';  /* 显式初始化，防止 IsBrowserExecutable 读取未初始化数据 */

    /* 步骤5a: 锁内 — 从 g_baProcTree 获取路径、收集树 PID 和证据 */
    lockHeld = TRUE;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    {
        int rootProcIdx = findProc(rootPid);
        if (rootProcIdx >= 0 && g_baProcTree[rootProcIdx].imagePath[0] != '\0') {
            RtlStringCbCopyA(rootImagePath, BA_MAX_PATH, g_baProcTree[rootProcIdx].imagePath);
        }
        CollectTreePids(rootPid, treePids, &treePidCount);
        BehaviorAggregateTreeEvidence(rootPid, &alertInfo);
        alertInfo.Pid = rootPid;
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    lockHeld = FALSE;

    /* ── 步骤5a+: 恶意软件家族归类 ──
     * 在威胁判定通过后、告警发送前，检查进程树中是否出现家族特征指标。
     * 若出现银狐家族特征（伪装目录投放 + 随机文件名），将 threatClass 覆盖为 SilverFox。
     * 此步骤不改变是否告警的判定，仅修改家族分类标签。 */
    if (treePidCount > 0) {
        BehaviorClassifyMalwareFamily(
            treePids, treePidCount,
            alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
            alertInfo.Description, sizeof(alertInfo.Description));
    }

    /* 步骤5b: 锁外（PASSIVE_LEVEL）— 如果路径为空，通过系统调用获取 */
    if (rootImagePath[0] == '\0') {
        PEPROCESS rootProcess = NULL;
        NTSTATUS lookupStatus = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)rootPid, &rootProcess);
        if (NT_SUCCESS(lookupStatus) && rootProcess) {
            HANDLE hRootProc = NULL;
            NTSTATUS obStatus = ObOpenObjectByPointer(
                rootProcess, OBJ_KERNEL_HANDLE, NULL,
                0x0400,  /* PROCESS_QUERY_LIMITED_INFORMATION */
                *PsProcessType, KernelMode, &hRootProc);
            if (NT_SUCCESS(obStatus)) {
                ULONG returnLength = 0;
                PUNICODE_STRING imagePathInfo = NULL;
                NTSTATUS queryStatus = ZwQueryInformationProcess(
                    hRootProc, ProcessImageFileName, NULL, 0, &returnLength);
                if (queryStatus == STATUS_INFO_LENGTH_MISMATCH && returnLength > 0) {
                    imagePathInfo = (PUNICODE_STRING)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, returnLength, 'HtP');
                    if (imagePathInfo) {
                        queryStatus = ZwQueryInformationProcess(
                            hRootProc, ProcessImageFileName,
                            imagePathInfo, returnLength, &returnLength);
                        if (NT_SUCCESS(queryStatus) && imagePathInfo->Buffer) {
                            int wlen = (int)(imagePathInfo->Length / sizeof(WCHAR));
                            if (wlen >= BA_MAX_PATH) wlen = BA_MAX_PATH - 1;
                            int ii;
                            for (ii = 0; ii < wlen; ii++)
                                rootImagePath[ii] = (CHAR)imagePathInfo->Buffer[ii];
                            rootImagePath[wlen] = '\0';
                        }
                        ExFreePool(imagePathInfo);
                    }
                }
                ZwClose(hRootProc);
            }
            ObDereferenceObject(rootProcess);
        }
        /* 最终后备: 使用进程短名 */
        if (rootImagePath[0] == '\0') {
            PEPROCESS proc2 = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)rootPid, &proc2)) && proc2) {
                UCHAR* imgName = PsGetProcessImageFileName(proc2);
                if (imgName) {
                    int ii;
                    for (ii = 0; ii < 15 && imgName[ii]; ii++)
                        rootImagePath[ii] = (CHAR)imgName[ii];
                    rootImagePath[ii] = '\0';
                }
                ObDereferenceObject(proc2);
            }
        }
        if (rootImagePath[0] == '\0') {
            RtlStringCbCopyA(rootImagePath, BA_MAX_PATH, "Unknown");
        }
    }

    /* 填充 alertInfo.ProcessPath（锁外，PASSIVE_LEVEL 安全） */
    RtlStringCbCopyA(alertInfo.ProcessPath, sizeof(alertInfo.ProcessPath), rootImagePath);

    /* 在 Description 中追加进程树行为摘要：展示各子进程及祖先的指标贡献 */
    {
        CHAR treeSummary[512] = {0};
        int summaryLen = 0;
        lockHeld = TRUE;
        KeAcquireSpinLock(&g_baLock, &oldIrql);
        for (int ti = 0; ti < treePidCount && summaryLen < (int)(sizeof(treeSummary) - 64); ti++) {
            INT64 tipid = treePids[ti];
            int tidx = findProc(tipid);
            if (tidx < 0) continue;
            /* 提取短文件名 */
            const CHAR* tp = g_baProcTree[tidx].imagePath;
            const CHAR* tl = NULL;
            while (*tp) { if (*tp == '\\' || *tp == '/') tl = tp; tp++; }
            tp = tl ? tl + 1 : g_baProcTree[tidx].imagePath;
            CHAR shortName[64] = {0};
            int sn = 0;
            while (*tp && sn < 63) { shortName[sn++] = *tp++; }
            shortName[sn] = '\0';
            /* 统计该进程的指标数和总分 */
            int indCnt = 0;
            LONG procScore = 0;
            for (int ii = 0; ii < BA_MAX_INDICATORS; ii++) {
                if (g_baPidIndicators[tidx][ii] > 0) {
                    indCnt++;
                    procScore += (LONG)(g_baIndicatorScores[ii] * (g_baPidIndicators[tidx][ii] > 2 ? 2.0 : (DOUBLE)g_baPidIndicators[tidx][ii]) + 0.5);
                }
            }
            if (indCnt > 0) {
                summaryLen += RtlStringCbPrintfA(treeSummary + summaryLen, sizeof(treeSummary) - summaryLen,
                    " %s(PID:%lld:%d指标%score:%ld)", shortName, tipid, indCnt,
                    (tipid == rootPid) ? "[ROOT]" : "", procScore);
            }
        }
        /* 沿父链向上追溯，补充祖先进程的指标贡献 */
        {
            int pidx = findProc(rootPid);
            if (pidx >= 0) {
                INT64 currentParent = g_baProcTree[pidx].parentPid;
                int parentDepth = 0;
                while (currentParent != 0 && currentParent != rootPid && parentDepth < 8) {
                    int parentIdx = findProc(currentParent);
                    if (parentIdx < 0) break;
                    /* 避免循环 */
                    int isDup = 0;
                    for (int ti = 0; ti < treePidCount; ti++) {
                        if (treePids[ti] == currentParent) { isDup = 1; break; }
                    }
                    if (isDup) break;
                    const CHAR* pp = g_baProcTree[parentIdx].imagePath;
                    const CHAR* pl = NULL;
                    while (*pp) { if (*pp == '\\' || *pp == '/') pl = pp; pp++; }
                    pp = pl ? pl + 1 : g_baProcTree[parentIdx].imagePath;
                    CHAR parentShort[64] = {0};
                    int psn = 0;
                    while (*pp && psn < 63) { parentShort[psn++] = *pp++; }
                    parentShort[psn] = '\0';
                    int indCnt2 = 0;
                    LONG procScore2 = 0;
                    for (int ii = 0; ii < BA_MAX_INDICATORS; ii++) {
                        if (g_baPidIndicators[parentIdx][ii] > 0) {
                            indCnt2++;
                            procScore2 += (LONG)(g_baIndicatorScores[ii] * (g_baPidIndicators[parentIdx][ii] > 2 ? 2.0 : (DOUBLE)g_baPidIndicators[parentIdx][ii]) + 0.5);
                        }
                    }
                    if (indCnt2 > 0 && summaryLen < (int)(sizeof(treeSummary) - 64)) {
                        summaryLen += RtlStringCbPrintfA(treeSummary + summaryLen, sizeof(treeSummary) - summaryLen,
                            " %s(PID:%lld:%d指标score:%ld)[ANC]", parentShort, currentParent, indCnt2, procScore2);
                    }
                    INT64 nextParent = g_baProcTree[parentIdx].parentPid;
                    if (nextParent == 0 || nextParent == currentParent) break;
                    currentParent = nextParent;
                    parentDepth++;
                }
            }
        }
        KeReleaseSpinLock(&g_baLock, oldIrql);
        lockHeld = FALSE;
        if (summaryLen > 0) {
            CHAR fullDesc[512] = {0};
            RtlStringCbPrintfA(fullDesc, sizeof(fullDesc), "%s | Tree:%s",
                alertInfo.Description, treeSummary);
            RtlStringCbCopyA(alertInfo.Description, sizeof(alertInfo.Description), fullDesc);
        }
    }

    DriverDbgPrint("[BA-DETECT] CollectTreePids: rootPid=%lld, treePidCount=%d\n",
        rootPid, treePidCount);

    /* ── 步骤6: 详细日志记录 ── */
    {
        int ii;
        /* 内核 RtlStringCbVPrintfA 不支持 %f，转为整数显示 */
        LONG confPercent = (LONG)(alertInfo.Confidence * 100.0 + 0.5);
        LONG scoreInt = (LONG)(totalScore + 0.5);
        DriverDbgPrint("============================================\n");
        DriverDbgPrint("[BA-DETECT] RootPID=%lld  Path=%s\n", rootPid, rootImagePath);
        DriverDbgPrint("[BA-DETECT] ThreatClass=%s\n", alertInfo.ThreatClass);
        DriverDbgPrint("[BA-DETECT] Description=%s\n", alertInfo.Description);
        DriverDbgPrint("[BA-DETECT] Confidence=%ld%%  TotalScore=%ld  DistinctCnt=%d  TreeProcs=%d\n",
            confPercent, scoreInt, distinctCnt, treePidCount);

        DriverDbgPrint("[BA-DETECT] Indicators: ");
        for (ii = 0; ii < BA_MAX_INDICATORS; ii++) {
            if (combined[ii] > 0.0) {
                LONG indInt = (LONG)(combined[ii] + 0.5);
                DriverDbgPrint("#%d=%ld ", ii, indInt);
            }
        }
        DriverDbgPrint("\n");

        if (alertInfo.EvidenceCount > 0) {
            DriverDbgPrint("[BA-DETECT] Evidence (%d items):\n", alertInfo.EvidenceCount);
            for (ii = 0; ii < alertInfo.EvidenceCount; ii++) {
                DriverDbgPrint("  [%d] %s\n", ii, alertInfo.Evidence[ii]);
            }
        }

        /* 打印进程树所有 PID（验证主进程和子进程都被收集） */
        DriverDbgPrint("[BA-DETECT] Process tree PIDs (%d):\n", treePidCount);
        for (ii = 0; ii < treePidCount; ii++) {
            DriverDbgPrint("  [%d] PID=%lld%s\n", ii, treePids[ii],
                (treePids[ii] == rootPid) ? " (ROOT)" : "");
        }
        DriverDbgPrint("============================================\n");
    }

    /* 所有浮点运算与日志已完成，恢复 FPU 状态 */
    floatSaved = FALSE;
    KeRestoreFloatingPointState(&floatSave);

    /* ── 步骤6.5/7/8: 生产级拦截 — 挂起进程树并弹窗等待用户决策 ── */
    {
        BOOLEAN hasSystemProc = FALSE;
        CHAR sysProcName[64] = {0};

        lockHeld = TRUE;
        KeAcquireSpinLock(&g_baLock, &oldIrql);
        for (i = 0; i < treePidCount; i++) {
            int treeIdx = findProc(treePids[i]);
            if (treeIdx < 0) continue;

            {
                const CHAR* path = g_baProcTree[treeIdx].imagePath;
                const CHAR* lastSlash = NULL;
                const CHAR* p = path;
                CHAR procNameLower[64] = {0};
                int j;

                while (*p) {
                    if (*p == '\\' || *p == '/') lastSlash = p;
                    p++;
                }
                p = lastSlash ? lastSlash + 1 : path;
                for (j = 0; j < 63 && p[j]; j++) {
                    CHAR c = p[j];
                    if (c >= 'A' && c <= 'Z') c += 32;
                    procNameLower[j] = c;
                }
                procNameLower[j] = '\0';

                if (isGenuineSystemProcess(treeIdx, path) ||
                    IsKnownSystemProcessName(procNameLower))
                {
                    hasSystemProc = TRUE;
                    RtlStringCbCopyA(sysProcName, sizeof(sysProcName),
                        procNameLower);
                    break;
                }
            }
        }
        KeReleaseSpinLock(&g_baLock, oldIrql);
        lockHeld = FALSE;

        if (hasSystemProc) {
            DriverDbgPrint("[BA-PROD] System process (%s) in threat tree — "
                "skip suspend/terminate/cleanup to prevent system damage\n", sysProcName);
        } else {
            BEHAVIOR_ALERT_WORKITEM_CTX* ctx = (BEHAVIOR_ALERT_WORKITEM_CTX*)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(BEHAVIOR_ALERT_WORKITEM_CTX), 'AtAB');
            if (ctx != NULL) {
                RtlZeroMemory(ctx, sizeof(BEHAVIOR_ALERT_WORKITEM_CTX));
                ExInitializeWorkItem(&ctx->WorkItem, BehaviorAlertWorkItemRoutine, ctx);
                ctx->rootPid = rootPid;
                ctx->treePidCount = treePidCount;
                ctx->hasSystemProc = hasSystemProc;
                RtlStringCbCopyA(ctx->rootImagePath, sizeof(ctx->rootImagePath),
                    rootImagePath);
                RtlCopyMemory(&ctx->alertInfo, &alertInfo, sizeof(BEHAVIOR_DETECTED_RESPONSE));
                RtlCopyMemory(ctx->treePids, treePids, sizeof(INT64) * treePidCount);
                ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);
                DriverDbgPrint("[BA-PROD] Queued behavior alert work item for PID=%lld treeSize=%d\n",
                    rootPid, treePidCount);
            } else {
                DriverDbgPrint("[BA-PROD] Failed to allocate work item for PID=%lld\n", rootPid);
            }
        }
    }

    /* 标记为已告警并清除指标，避免重复日志 */
    lockHeld = TRUE;
    KeAcquireSpinLock(&g_baLock, &oldIrql);
    {
        if (g_baAlertedCount < BA_MAX_ALERTED_PIDS) {
            g_baAlertedPids[g_baAlertedCount++] = rootPid;
        }
        ClearProcessTreeIndicators(rootPid);
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    lockHeld = FALSE;

    return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* 异常路径：尽最大努力恢复系统状态 */
        if (lockHeld)
        {
            KeReleaseSpinLock(&g_baLock, oldIrql);
        }
        if (floatSaved)
        {
            KeRestoreFloatingPointState(&floatSave);
        }

        DriverDbgPrint("[BA-DETECT] Exception caught in BehaviorCheckAndAlert, skipping\n");
        return STATUS_SUCCESS;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorHandleInjectionAlertAsync — 注入检测Alert（异步work item版本）
 *
 * 匹配条件（主流杀软做法）：
 *   1. 源进程 != 目标进程（跨进程操作）
 *   2. 源进程不是目标进程的父进程（排除正常进程创建）
 *      → 父进程创建子进程时获取 VM_WRITE/VM_OPERATION/CREATE_THREAD 是正常行为
 *      → 只有非父子关系的跨进程操作才是注入
 *
 * 注意：此函数在PreCreateHandle回调中调用，立即返回。
 * 实际的suspend+alert+decision由work item在系统线程中执行，
 * 避免回调线程自挂起导致死锁。
 * ══════════════════════════════════════════════════════════════════════════ */

/* 注入检测work item上下文 */
typedef struct _INJECTION_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    INT64 sourcePid;
    INT64 targetPid;
    INT64 threadId;          /* 远程线程 ID，用于 BLOCK 时终止远程线程 */
    PVOID threadStartAddr;   /* 远程线程起始地址（shellcode 内存证据，可 NULL） */
    CHAR sourceName[64];
    CHAR targetName[64];
    CHAR injectType[128];
} INJECTION_WORKITEM_CTX;

/* 注入检测work item回调（在系统线程中执行） */
static VOID InjectionAlertWorkItemRoutine(PVOID Context)
{
    INJECTION_WORKITEM_CTX* ctx = (INJECTION_WORKITEM_CTX*)Context;
    NTSTATUS status;
    NTSTATUS userResponse;
    PEPROCESS sourceProcess = NULL;
    HANDLE hSourceProcess = NULL;
    BOOLEAN suspended = FALSE;
    BEHAVIOR_DETECTED_RESPONSE alertInfo;
    CHAR alertDesc[512];
    CHAR sourcePath[BA_MAX_PATH] = {0};
    CHAR targetPath[BA_MAX_PATH] = {0};
    KIRQL oldIrql = 0;
    BOOLEAN lockHeld = FALSE;
    KFLOATING_SAVE floatSave;
    NTSTATUS fpStatus;
    BOOLEAN floatSaved = FALSE;

    /* 保存 FPU 状态：本函数涉及浮点格式化（Confidence 等）和系统调用，
     * 必须先保存 FPU/XMM 状态，避免 x64 内核模式蓝屏。 */
    fpStatus = KeSaveFloatingPointState(&floatSave);
    if (!NT_SUCCESS(fpStatus)) {
        ExFreePool(ctx);
        return;
    }
    floatSaved = TRUE;

    /* work item 系统线程中执行，涉及进程挂起/终止、客户端响应等操作。
     * 用 SEH 保护，异常时释放资源和自旋锁，避免蓝屏。 */
    __try {
        __try {

    DriverDbgPrint("[INJECT-ALERT] (async) %s: Source=%s(PID:%lld) -> Target=%s(PID:%lld)\n",
        ctx->injectType, ctx->sourceName, ctx->sourcePid, ctx->targetName, ctx->targetPid);

    /* ── 步骤1: 检查父子关系（放行条件）── */
    {
        BOOLEAN isParentChild = FALSE;
        KeAcquireSpinLock(&g_baLock, &oldIrql);
        lockHeld = TRUE;
        {
            int tgtIdx = findProc(ctx->targetPid);
            if (tgtIdx >= 0 && g_baProcTree[tgtIdx].parentPid == ctx->sourcePid)
            {
                isParentChild = TRUE;
            }
        }
        lockHeld = FALSE;
        KeReleaseSpinLock(&g_baLock, oldIrql);

        /* 进程树可能尚未建立（句柄回调与进程创建回调存在竞态），
         * 直接查询目标 EPROCESS 的 InheritedFromUniqueProcessId 作为后备。 */
        if (!isParentChild)
        {
            PEPROCESS targetProc = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                    (HANDLE)(ULONG_PTR)ctx->targetPid, &targetProc)))
            {
                HANDLE inheritedParent = PsGetProcessInheritedFromUniqueProcessId(targetProc);
                if (inheritedParent != NULL &&
                    (INT64)(ULONG_PTR)inheritedParent == ctx->sourcePid)
                {
                    isParentChild = TRUE;
                }
                ObDereferenceObject(targetProc);
            }
        }

        if (isParentChild)
        {
            /* 如果目标进程已初始化（已收到初始线程通知），
             * 说明这是远程线程注入而非合法初始线程创建，继续告警流程。
             * 与 ThreadCreateNotifyRoutine 中的 g_InitializedPids 逻辑保持一致。 */
            if (!IsProcessInitialized((HANDLE)(ULONG_PTR)ctx->targetPid))
            {
                DriverDbgPrint("[INJECT-ALERT] Source is parent of target (legitimate initial thread creation), allowing\n");
                if (floatSaved) KeRestoreFloatingPointState(&floatSave);
                ExFreePool(ctx);
                return;
            }
            /* 目标进程已初始化 → 这是远程线程注入，不 skip，继续告警 */
            DriverDbgPrint("[INJECT-ALERT] Source is parent of target but target already initialized (remote thread injection), alerting\n");
        }

        /* 受信任的安全软件放行 - 已删除，不再区分受信任进程。 */

        /* 受信任的第三方应用/开发者工具放行 - 已删除，不再区分受信任进程。 */
    }

    /* ── 步骤1.5: shellcode 内存证据检查（对齐 Elastic kernel_shellcode_event）──
     * 线程层回调已获取 StartAddress（ctx->threadStartAddr）：
     *   - 地址落在非镜像可执行内存（unbacked executable）→ 强证据，继续弹窗流程
     *   - 地址在镜像内 → trampoline 跳板 Rip 采样（Elastic 博客公开对抗手段）：
     *     线程上下文 Rip 落入非镜像可执行区 → 跳板注入，仍弹窗
     *   - 均无证据（模块注入/合法工具，如调试器把 StartAddress 指向合法导出）
     *     → 不弹窗不挂起，仅记录日志，由 R3 hook 层与行为评分引擎继续处理，
     *       消除名单机制外的误报
     * 仅对携带 threadStartAddr 的线程注入告警生效（其余告警传 NULL 不受影响）。 */
    if (ctx->threadStartAddr != NULL)
    {
        BOOLEAN unbackedExec = BehaviorCheckStartAddressUnbacked(
            ctx->targetPid, ctx->threadStartAddr, NULL);
        BOOLEAN trampolineHit = FALSE;

        if (!unbackedExec)
        {
            trampolineHit = BehaviorIsThreadRipInUnbackedExecutable(
                ctx->threadId, ctx->targetPid);
        }

        if (!unbackedExec && !trampolineHit)
        {
            CHAR noEvLog[320];
            RtlStringCbPrintfA(noEvLog, sizeof(noEvLog),
                "[注入防护-无内存证据] 远程线程 StartAddress 0x%p 位于已加载镜像且 Rip 未落入非镜像可执行区，跳过弹窗（模块注入/合法工具候选）: Source=%s(PID:%lld) Target=%s(PID:%lld)",
                ctx->threadStartAddr, ctx->sourceName, ctx->sourcePid,
                ctx->targetName, ctx->targetPid);
            SendInjectionLog(noEvLog);
            DriverDbgPrint("%s\n", noEvLog);
            ExFreePool(ctx);
            return;
        }

        DriverDbgPrint("[INJECT-ALERT] Shellcode memory evidence %s (StartAddress=0x%p trampoline=%d)\n",
            unbackedExec ? "UNBACKED-EXEC" : "via-Rip",
            ctx->threadStartAddr, trampolineHit ? 1 : 0);
    }

    /* ── 步骤2: 挂起源进程 ──
     * 仍保留关键系统进程保护，避免蓝屏。 */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ctx->sourcePid, &sourceProcess);
    if (!NT_SUCCESS(status))
    {
        DriverDbgPrint("[INJECT-ALERT] PsLookupProcessByProcessId PID=%lld failed: 0x%X\n",
            ctx->sourcePid, status);
        ExFreePool(ctx);
        return;
    }

    /* 检查源进程是否为系统关键进程（绝不挂起）*/
    if (IsCriticalSystemProcess(sourceProcess))
    {
        DriverDbgPrint("[INJECT-ALERT] Source is critical system process, skipping\n");
        ObDereferenceObject(sourceProcess);
        ExFreePool(ctx);
        return;
    }

    /* 检查目标进程是否为系统关键进程：合法程序（如 cmd.exe）经常需要打开
     * csrss.exe、lsass.exe 等系统进程句柄，此类操作不应被报告为注入。 */
    {
        PEPROCESS targetProcess = NULL;
        __try {
            NTSTATUS tgtStatus = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)ctx->targetPid, &targetProcess);
            if (NT_SUCCESS(tgtStatus))
            {
                if (IsCriticalSystemProcess(targetProcess))
                {
                    DriverDbgPrint("[INJECT-ALERT] Target is critical system process, skipping\n");
                    ObDereferenceObject(targetProcess);
                    targetProcess = NULL;
                    ObDereferenceObject(sourceProcess);
                    ExFreePool(ctx);
                    return;
                }
                ObDereferenceObject(targetProcess);
                targetProcess = NULL;
            }
        } __finally {
            if (targetProcess)
                ObDereferenceObject(targetProcess);
        }
    }

    /* 优先使用 PsSuspendProcess（PEPROCESS 参数） */
    if (g_pPsSuspendProcess)
    {
        NTSTATUS s = g_pPsSuspendProcess(sourceProcess);
        if (NT_SUCCESS(s))
        {
            suspended = TRUE;
            DriverDbgPrint("[INJECT-ALERT] Suspended source PID=%lld (PsSuspendProcess)\n", ctx->sourcePid);
        }
        else
        {
            DriverDbgPrint("[INJECT-ALERT] PsSuspendProcess PID=%lld failed: 0x%X\n",
                ctx->sourcePid, s);
        }
    }

    /* Fallback: NtSuspendProcess（HANDLE 参数） */
    if (!suspended && g_pNtSuspendProcess)
    {
        NTSTATUS s = ObOpenObjectByPointer(
            sourceProcess, OBJ_KERNEL_HANDLE, NULL,
            0x0800,  /* PROCESS_SUSPEND_RESUME */
            *PsProcessType, KernelMode, &hSourceProcess);
        if (NT_SUCCESS(s))
        {
            s = g_pNtSuspendProcess(hSourceProcess);
            if (NT_SUCCESS(s))
            {
                suspended = TRUE;
                DriverDbgPrint("[INJECT-ALERT] Suspended source PID=%lld (NtSuspendProcess)\n", ctx->sourcePid);
            }
            else
            {
                DriverDbgPrint("[INJECT-ALERT] NtSuspendProcess PID=%lld failed: 0x%X\n",
                    ctx->sourcePid, s);
                ZwClose(hSourceProcess);
                hSourceProcess = NULL;
            }
        }
        else
        {
            DriverDbgPrint("[INJECT-ALERT] ObOpenObjectByPointer PID=%lld failed: 0x%X\n",
                ctx->sourcePid, s);
        }
    }

    if (!suspended && !g_pPsSuspendProcess && !g_pNtSuspendProcess)
    {
        DriverDbgPrint("[INJECT-ALERT] No suspend API available, cannot suspend PID=%lld\n",
            ctx->sourcePid);
    }

    /* 用户态可见日志：注入告警已挂起源进程（等待用户决策）。
     * 这是关键的"拦截痕迹"日志，便于用户排查进程启动失败问题。 */
    if (suspended)
    {
        DriverDbgPrint("[INJECT-ALERT] Suspended source PID=%lld -> Target PID=%lld Type=%s\n",
            ctx->sourcePid, ctx->targetPid,
            ctx->injectType ? ctx->injectType : "Unknown");
    }

    /* 无论挂起是否成功，都打开一个 PROCESS_TERMINATE 句柄，
     * 确保用户选择 Block 时能够终止源进程。 */
    if (hSourceProcess == NULL)
    {
        NTSTATUS s = ObOpenObjectByPointer(
            sourceProcess, OBJ_KERNEL_HANDLE, NULL,
            0x0001,  /* PROCESS_TERMINATE */
            *PsProcessType, KernelMode, &hSourceProcess);
        if (!NT_SUCCESS(s))
        {
            DriverDbgPrint("[INJECT-ALERT] Open PROCESS_TERMINATE handle PID=%lld failed: 0x%X\n",
                ctx->sourcePid, s);
            hSourceProcess = NULL;
        }
    }

    ObDereferenceObject(sourceProcess);
    sourceProcess = NULL;  /* 标记已释放，异常处理器不再重复 ObDereferenceObject */

    /* ── 步骤3: 获取源/目标完整镜像路径，避免告警显示被 PsGetProcessImageFileName
     * 截断的短名（如 identity_helper.exe -> identity_helpe）。 */
    {
        INT64 pids[2] = { ctx->sourcePid, ctx->targetPid };
        CHAR* paths[2] = { sourcePath, targetPath };
        int pi;
        for (pi = 0; pi < 2; pi++) {
            PEPROCESS proc = NULL;
            HANDLE hProc = NULL;
            PUNICODE_STRING imagePathInfo = NULL;
            __try {
                if (NT_SUCCESS(PsLookupProcessByProcessId(
                        (HANDLE)(ULONG_PTR)pids[pi], &proc))) {
                    NTSTATUS obStatus = ObOpenObjectByPointer(
                        proc, OBJ_KERNEL_HANDLE, NULL,
                        PROCESS_QUERY_LIMITED_INFORMATION,
                        *PsProcessType, KernelMode, &hProc);
                    ObDereferenceObject(proc);
                    if (NT_SUCCESS(obStatus) && hProc != NULL) {
                        ULONG returnLength = 0;
                        NTSTATUS queryStatus = ZwQueryInformationProcess(
                            hProc, ProcessImageFileName, NULL, 0, &returnLength);
                        if (!NT_SUCCESS(queryStatus) && returnLength > 0) {
                            imagePathInfo = (PUNICODE_STRING)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED, returnLength, 'HtP');
                            if (imagePathInfo) {
                                queryStatus = ZwQueryInformationProcess(
                                    hProc, ProcessImageFileName,
                                    imagePathInfo, returnLength, &returnLength);
                                if (NT_SUCCESS(queryStatus) && imagePathInfo->Buffer) {
                                    int wlen = (int)(imagePathInfo->Length / sizeof(WCHAR));
                                    if (wlen >= BA_MAX_PATH) wlen = BA_MAX_PATH - 1;
                                    int i;
                                    for (i = 0; i < wlen; i++)
                                        paths[pi][i] = (CHAR)imagePathInfo->Buffer[i];
                                    paths[pi][wlen] = '\0';
                                }
                            }
                        }
                    }
                }
            } __finally {
                if (imagePathInfo)
                    ExFreePool(imagePathInfo);
                if (hProc)
                    ZwClose(hProc);
            }
        }
    }

    /* ── 步骤4: 构建alert信息并发送 ──
     * 生产级命名：ThreatClass 直接使用 ctx->injectType 中已映射的
     * DefenseEvasion/Injection:XXX.T1055 格式，不再使用硬编码 "ProcessInjection"，
     * 确保 UI 弹窗、日志、响应缓存中的威胁名称一致且可对应到 MITRE ATT&CK。 */
    RtlZeroMemory(&alertInfo, sizeof(alertInfo));
    alertInfo.Pid = ctx->sourcePid;
    RtlStringCbCopyA(alertInfo.ProcessPath, sizeof(alertInfo.ProcessPath),
        sourcePath[0] ? sourcePath : (ctx->sourceName ? ctx->sourceName : ""));
    RtlStringCbCopyA(alertInfo.ThreatClass, sizeof(alertInfo.ThreatClass),
        ctx->injectType ? ctx->injectType : "DefenseEvasion/Injection:Process.T1055");

    RtlStringCbPrintfA(alertDesc, sizeof(alertDesc),
        "%s\n"
        "Source: %s (PID:%lld)\n"
        "Target: %s (PID:%lld)",
        ctx->injectType,
        sourcePath[0] ? sourcePath : (ctx->sourceName ? ctx->sourceName : "Unknown"),
        ctx->sourcePid,
        targetPath[0] ? targetPath : (ctx->targetName ? ctx->targetName : "Unknown"),
        ctx->targetPid);
    RtlStringCbCopyA(alertInfo.Description, sizeof(alertInfo.Description),
        alertDesc);
    alertInfo.Confidence = 0.85;
    alertInfo.EvidenceCount = 0;

    DriverDbgPrint("[INJECT-ALERT] Built alertInfo for PID=%lld: ThreatClass=%s, Confidence=%ld/10000 (addr=%p)\n",
        ctx->sourcePid, alertInfo.ThreatClass,
        (LONG)(alertInfo.Confidence * 10000.0 + 0.5), &alertInfo.Confidence);

    userResponse = AskClientForBehaviorResponse(
        ctx->sourcePid, ctx->sourceName,
        ctx->injectType ? ctx->injectType : "DefenseEvasion/Injection:Process.T1055",
        alertDesc,
        0.85,
        &alertInfo);

    /* ── 步骤4: 处理用户决策 ── */
    DriverDbgPrint("[INJECT-ALERT] User response received for PID=%lld: 0x%X (%s)\n",
        ctx->sourcePid, userResponse,
        (userResponse == STATUS_ACCESS_DENIED) ? "BLOCK" : "ALLOW");

    if (userResponse == STATUS_ACCESS_DENIED)
    {
        DriverDbgPrint("[INJECT-ALERT] User chose BLOCK. Terminating source PID=%lld\n", ctx->sourcePid);

        /* 用户态可见日志：用户选择阻止，正在终止源进程 */
        {
            CHAR blockLogMsg[400];
            const CHAR* injectTag = ctx->injectType ? ctx->injectType : "Unknown";
            RtlStringCbPrintfA(blockLogMsg, sizeof(blockLogMsg),
                "[%s] 用户选择阻止，正在终止源进程: 源=%s (PID:%lld)",
                injectTag,
                ctx->sourceName ? ctx->sourceName : "Unknown",
                ctx->sourcePid);
            SendInjectionLog(blockLogMsg);
        }

        {
            PEPROCESS srcProc;
            NTSTATUS s2 = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ctx->sourcePid, &srcProc);
            if (NT_SUCCESS(s2))
            {
                /* 终止前重新打开句柄，需要 PROCESS_TERMINATE + PROCESS_QUERY_LIMITED_INFORMATION。
                 * 安全策略：若进程标记为 BreakOnTermination，直接跳过，不再尝试清除标记，
                 * 避免清除真实关键进程后终止导致 CRITICAL_PROCESS_DIED。 */
                HANDLE hTerminate;
                s2 = ObOpenObjectByPointer(
                    srcProc, OBJ_KERNEL_HANDLE, NULL,
                    0x0001 | 0x0400,  /* PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION */
                    *PsProcessType, KernelMode, &hTerminate);
                if (NT_SUCCESS(s2))
                {
                    BOOLEAN isCritical = FALSE;
                    NTSTATUS critStatus = QueryProcessCritical(hTerminate, &isCritical);
                    if (NT_SUCCESS(critStatus) && isCritical)
                    {
                        DriverDbgPrint("[INJECT-ALERT] Source PID=%lld has BreakOnTermination, SKIPPED to prevent BSOD\n",
                            ctx->sourcePid);
                        ZwClose(hTerminate);
                        ObDereferenceObject(srcProc);

                        /* BUGFIX: 进程已在步骤2被挂起（suspended==TRUE），此处因
                         * BreakOnTermination 跳过终止，但必须恢复进程，否则永久挂起
                         * 导致父进程 CreateProcess 卡死（ERROR_GEN_FAILURE）。 */
                        if (suspended)
                        {
                            PEPROCESS critProc;
                            NTSTATUS cs = PsLookupProcessByProcessId(
                                (HANDLE)(ULONG_PTR)ctx->sourcePid, &critProc);
                            if (NT_SUCCESS(cs))
                            {
                                BOOLEAN critResumed = FALSE;
                                if (g_pPsResumeProcess)
                                {
                                    NTSTATUS rs = g_pPsResumeProcess(critProc);
                                    if (NT_SUCCESS(rs)) critResumed = TRUE;
                                }
                                if (!critResumed && g_pNtResumeProcess)
                                {
                                    HANDLE hCritResume;
                                    NTSTATUS os = ObOpenObjectByPointer(
                                        critProc, OBJ_KERNEL_HANDLE, NULL,
                                        0x0800,  /* PROCESS_SUSPEND_RESUME */
                                        *PsProcessType, KernelMode, &hCritResume);
                                    if (NT_SUCCESS(os))
                                    {
                                        g_pNtResumeProcess(hCritResume);
                                        ZwClose(hCritResume);
                                    }
                                }
                                ObDereferenceObject(critProc);
                            }

                            /* 用户态可见日志：关键进程跳过终止并已恢复 */
                            {
                                CHAR critLogMsg[300];
                                RtlStringCbPrintfA(critLogMsg, sizeof(critLogMsg),
                                    "[注入防护-关键进程] 源进程标记为关键(BreakOnTermination)，跳过终止并已恢复: PID=%lld 类型=%s",
                                    ctx->sourcePid,
                                    ctx->injectType ? ctx->injectType : "Unknown");
                                SendInjectionLog(critLogMsg);
                            }
                        }

                        if (hSourceProcess)
                        {
                            ZwClose(hSourceProcess);
                        }
                        ExFreePool(ctx);
                        return;
                    }

                    ZwTerminateProcess(hTerminate, 0);
                    DriverDbgPrint("[INJECT-ALERT] Terminated source PID=%lld\n", ctx->sourcePid);
                    ZwClose(hTerminate);
                }
                else
                {
                    DriverDbgPrint("[INJECT-ALERT] Open terminate handle PID=%lld failed: 0x%X\n",
                        ctx->sourcePid, s2);
                }
                ObDereferenceObject(srcProc);
            }
        }

        if (hSourceProcess)
        {
            ZwClose(hSourceProcess);
        }

        DriverDbgPrint("[INJECT-ALERT] Source PID=%lld terminated\n", ctx->sourcePid);

        /* ═══════════════════════════════════════════════════════════════════
         * 终止远程线程（如果 threadId 有效）。
         * 远程线程在目标进程中运行，仅终止源进程无法清除已注入的远程线程。
         * 必须通过 threadId 单独终止目标进程中的远程线程。
         * ═══════════════════════════════════════════════════════════════════ */
        if (ctx->threadId != 0)
        {
            PETHREAD thread = NULL;
            HANDLE hTermThread = NULL;
            NTSTATUS ts = PsLookupThreadByThreadId(
                (HANDLE)(ULONG_PTR)ctx->threadId, &thread);
            if (NT_SUCCESS(ts))
            {
                ts = ObOpenObjectByPointer(
                    thread, OBJ_KERNEL_HANDLE, NULL,
                    0x0001,  /* THREAD_TERMINATE */
                    *PsThreadType, KernelMode, &hTermThread);
                if (NT_SUCCESS(ts))
                {
                    if (!g_pNtTerminateThread)
                    {
                        UNICODE_STRING name = RTL_CONSTANT_STRING(L"NtTerminateThread");
                        g_pNtTerminateThread = (PFN_NtTerminateThread)MmGetSystemRoutineAddress(&name);
                    }
                    if (g_pNtTerminateThread)
                    {
                        g_pNtTerminateThread(hTermThread, 0);
                        DriverDbgPrint("[INJECT-ALERT] Terminated remote thread TID=%lld in target PID=%lld\n",
                            ctx->threadId, ctx->targetPid);
                    }
                    else
                    {
                        DriverDbgPrint("[INJECT-ALERT] NtTerminateThread not found, cannot terminate TID=%lld\n",
                            ctx->threadId);
                    }
                    ZwClose(hTermThread);
                }
                else
                {
                    DriverDbgPrint("[INJECT-ALERT] Failed to open remote thread TID=%lld for terminate: 0x%X\n",
                        ctx->threadId, ts);
                }
                ObDereferenceObject(thread);
            }
            else
            {
                DriverDbgPrint("[INJECT-ALERT] Failed to lookup remote thread TID=%lld: 0x%X\n",
                    ctx->threadId, ts);
            }
        }

        /* 威胁回滚（分阶段）：注入拦截后，先收集回滚项，
         * 询问用户确认后再执行选中的回滚操作。注入场景无子孙树，
         * 仅回滚源进程及其祖先链执行的操作。 */
        {
            BA_ROLLBACK_LIST rollbackList;
            BA_ROLLBACK_SELECTION sel;
            RtlZeroMemory(&rollbackList, sizeof(rollbackList));
            RtlZeroMemory(&sel, sizeof(sel));
            BehaviorCollectRollbackItems(
                ctx->sourcePid,
                sourcePath[0] ? sourcePath : (ctx->sourceName ? ctx->sourceName : ""),
                ctx->sourceName ? ctx->sourceName : "",
                alertInfo.ThreatClass[0] ? alertInfo.ThreatClass : "DefenseEvasion/Injection",
                NULL, 0, &rollbackList);
            if (rollbackList.itemCount > 0)
            {
                NTSTATUS rbStatus = AskClientForRollbackConfirm(&rollbackList, &sel);
                if (NT_SUCCESS(rbStatus) && sel.decision == 1)
                {
                    BehaviorExecuteRollbackSelected(&rollbackList, &sel);
                    DriverDbgPrint("[INJECT-ALERT] Rollback executed: %d items\n", sel.itemCount);
                }
                else
                {
                    DriverDbgPrint("[INJECT-ALERT] Rollback skipped (user ignore or timeout)\n");
                }
            }
            else
            {
                DriverDbgPrint("[INJECT-ALERT] No rollback items collected\n");
            }
        }
    }
    else
    {
        DriverDbgPrint("[INJECT-ALERT] User chose ALLOW. Resuming source PID=%lld\n", ctx->sourcePid);

        if (suspended)
        {
            /* 重新 lookup source process（suspend 后已 ObDereferenceObject） */
            PEPROCESS srcProc;
            NTSTATUS s2 = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)ctx->sourcePid, &srcProc);
            if (NT_SUCCESS(s2))
            {
                BOOLEAN resumed = FALSE;

                /* 优先 PsResumeProcess（PEPROCESS 参数） */
                if (g_pPsResumeProcess)
                {
                    NTSTATUS s = g_pPsResumeProcess(srcProc);
                    if (NT_SUCCESS(s))
                    {
                        DriverDbgPrint("[INJECT-ALERT] Resumed source PID=%lld (PsResumeProcess)\n",
                            ctx->sourcePid);
                        resumed = TRUE;
                    }
                    else
                    {
                        DriverDbgPrint("[INJECT-ALERT] PsResumeProcess PID=%lld failed: 0x%X\n",
                            ctx->sourcePid, s);
                    }
                }

                /* Fallback: NtResumeProcess（HANDLE 参数） */
                if (!resumed && g_pNtResumeProcess)
                {
                    HANDLE hResume;
                    NTSTATUS s = ObOpenObjectByPointer(
                        srcProc, OBJ_KERNEL_HANDLE, NULL,
                        0x0800,  /* PROCESS_SUSPEND_RESUME */
                        *PsProcessType, KernelMode, &hResume);
                    if (NT_SUCCESS(s))
                    {
                        s = g_pNtResumeProcess(hResume);
                        if (NT_SUCCESS(s))
                        {
                            DriverDbgPrint("[INJECT-ALERT] Resumed source PID=%lld (NtResumeProcess)\n",
                                ctx->sourcePid);
                        }
                        else
                        {
                            DriverDbgPrint("[INJECT-ALERT] NtResumeProcess PID=%lld failed: 0x%X\n",
                                ctx->sourcePid, s);
                        }
                        ZwClose(hResume);
                    }
                }

                ObDereferenceObject(srcProc);
            }
        }

        /* 用户态可见日志：用户选择放行，已恢复源进程 */
        {
            CHAR allowLogMsg[400];
            const CHAR* injectTag = ctx->injectType ? ctx->injectType : "Unknown";
            RtlStringCbPrintfA(allowLogMsg, sizeof(allowLogMsg),
                "[%s] 用户选择放行: 源=%s (PID:%lld)",
                injectTag,
                ctx->sourceName ? ctx->sourceName : "Unknown",
                ctx->sourcePid);
            SendInjectionLog(allowLogMsg);
        }

        if (hSourceProcess)
        {
            ZwClose(hSourceProcess);
        }
    }

    ExFreePool(ctx);
    } __finally {
        if (floatSaved) {
            floatSaved = FALSE;
            KeRestoreFloatingPointState(&floatSave);
        }
    }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        /* 异常路径：尽最大努力恢复系统状态 */
        if (lockHeld)
        {
            KeReleaseSpinLock(&g_baLock, oldIrql);
        }

        /* BUGFIX: 异常发生前若已挂起源进程，必须恢复，否则源进程永久挂起。
         * sourceProcess 在步骤2后已 ObDereferenceObject，此处不能再用，
         * 需重新 PsLookupProcessByProcessId 获取。 */
        if (suspended && ctx != NULL)
        {
            PEPROCESS exceptProc = NULL;
            NTSTATUS ls = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)ctx->sourcePid, &exceptProc);
            if (NT_SUCCESS(ls) && exceptProc)
            {
                BOOLEAN exceptResumed = FALSE;
                if (g_pPsResumeProcess)
                {
                    NTSTATUS rs = g_pPsResumeProcess(exceptProc);
                    if (NT_SUCCESS(rs)) exceptResumed = TRUE;
                }
                if (!exceptResumed && g_pNtResumeProcess)
                {
                    HANDLE hExceptResume;
                    NTSTATUS os = ObOpenObjectByPointer(
                        exceptProc, OBJ_KERNEL_HANDLE, NULL,
                        0x0800,  /* PROCESS_SUSPEND_RESUME */
                        *PsProcessType, KernelMode, &hExceptResume);
                    if (NT_SUCCESS(os))
                    {
                        g_pNtResumeProcess(hExceptResume);
                        ZwClose(hExceptResume);
                    }
                }
                ObDereferenceObject(exceptProc);
            }

            /* 用户态可见日志：异常路径恢复源进程 */
            {
                CHAR excLogMsg[300];
                RtlStringCbPrintfA(excLogMsg, sizeof(excLogMsg),
                    "[注入防护-异常] 注入告警处理异常，已恢复源进程: PID=%lld 类型=%s",
                    ctx->sourcePid,
                    ctx->injectType ? ctx->injectType : "Unknown");
                SendInjectionLog(excLogMsg);
            }
        }

        if (hSourceProcess)
        {
            ZwClose(hSourceProcess);
        }
        /* sourceProcess 在步骤2后已 ObDereferenceObject 并置 NULL，
         * 仅在异常发生在 dereference 之前时才需要释放。 */
        if (sourceProcess)
        {
            ObDereferenceObject(sourceProcess);
        }
        if (ctx)
        {
            ExFreePool(ctx);
        }

        DriverDbgPrint("[INJECT-ALERT] Exception caught in InjectionAlertWorkItemRoutine, cleaning up\n");
    }
}

/* 行为分析告警 work item 回调（在系统线程中执行）
 * 生产级流程：挂起进程树 -> 向客户端弹窗 -> 等待用户决策 ->
 *            BLOCK: 终止进程树并清理释放的文件
 *            ALLOW: 恢复进程树
 * 注意：本函数在 PASSIVE_LEVEL 系统线程中运行，可安全调用 Zw*、
 *       AskClientForBehaviorResponse 等阻塞/系统调用。 */
static VOID BehaviorAlertWorkItemRoutine(PVOID Context)
{
    BEHAVIOR_ALERT_WORKITEM_CTX* ctx = (BEHAVIOR_ALERT_WORKITEM_CTX*)Context;
    NTSTATUS userResponse;
    CHAR rootProcessName[64] = {0};
    KFLOATING_SAVE floatSave;
    NTSTATUS fpStatus;
    BOOLEAN floatSaved = FALSE;

    if (ctx == NULL) return;

    fpStatus = KeSaveFloatingPointState(&floatSave);
    if (!NT_SUCCESS(fpStatus)) {
        ExFreePool(ctx);
        return;
    }
    floatSaved = TRUE;

    __try {
        __try {
        DriverDbgPrint("[BA-PROD] Behavior alert work item started for root PID=%lld treeSize=%d\n",
            ctx->rootPid, ctx->treePidCount);

        /* 系统进程保护：若进程树包含系统进程，仅记录日志，不拦截 */
        if (ctx->hasSystemProc) {
            DriverDbgPrint("[BA-PROD] Skipping production action: system process in tree (PID=%lld)\n",
                ctx->rootPid);
            ctx = NULL;  /* 标记为已释放，防止后续重复释放 */
            return;
        }

        /* 从 rootImagePath 提取进程短名，用于文件清理判断 */
        {
            const CHAR* p = ctx->rootImagePath;
            const CHAR* lastSlash = NULL;
            int j;
            while (*p) {
                if (*p == '\\' || *p == '/') lastSlash = p;
                p++;
            }
            p = lastSlash ? lastSlash + 1 : ctx->rootImagePath;
            for (j = 0; j < 63 && p[j]; j++) {
                rootProcessName[j] = p[j];
            }
            rootProcessName[j] = '\0';
        }

        /* 步骤1: 挂起进程树 */
        SuspendProcessTree(ctx->treePids, ctx->treePidCount);

        /* 用户态可见日志：行为分析已挂起进程树（等待用户决策）
         * 注意：内核 RtlStringCbPrintfA 不支持 %f 浮点格式说明符，
         * 必须将 Confidence 转为整数后用 %ld 显示，否则 %.1f 会输出
         * 字面 "f" 且不消费参数，导致后续 %d 错位读取 Confidence 的
         * 低 4 字节（显示为 0）。 */
        {
            CHAR suspLogMsg[400];
            LONG confPercent = (LONG)(ctx->alertInfo.Confidence * 100.0 + 0.5);
            RtlStringCbPrintfA(suspLogMsg, sizeof(suspLogMsg),
                "[行为分析-挂起] 检测到威胁已挂起进程树: 根PID=%lld 威胁=%s 置信度=%ld%% 进程数=%d",
                ctx->rootPid,
                ctx->alertInfo.ThreatClass ? ctx->alertInfo.ThreatClass : "Unknown",
                confPercent,
                ctx->treePidCount);
            SendInjectionLog(suspLogMsg);
        }

        /* 步骤2: 弹窗等待用户决策 */
        userResponse = AskClientForBehaviorResponse(
            ctx->alertInfo.Pid,
            ctx->rootImagePath,
            ctx->alertInfo.ThreatClass,
            ctx->alertInfo.Description,
            ctx->alertInfo.Confidence,
            &ctx->alertInfo);

        DriverDbgPrint("[BA-PROD] User response for root PID=%lld: 0x%X (%s)\n",
            ctx->rootPid, userResponse,
            (userResponse == STATUS_ACCESS_DENIED) ? "BLOCK" : "ALLOW");

        /* 步骤3: 根据用户决策执行 BLOCK 或 ALLOW */
        if (userResponse == STATUS_ACCESS_DENIED)
        {
            /* 用户态可见日志：用户选择阻止，正在终止进程树 */
            {
                CHAR blockLogMsg[400];
                RtlStringCbPrintfA(blockLogMsg, sizeof(blockLogMsg),
                    "[行为分析-阻止] 用户选择阻止，正在终止进程树: 根PID=%lld 威胁=%s",
                    ctx->rootPid,
                    ctx->alertInfo.ThreatClass ? ctx->alertInfo.ThreatClass : "Unknown");
                SendInjectionLog(blockLogMsg);
            }

            /* BLOCK: 先收集回滚项（必须在终止前快照，避免周期清理线程
             * 在用户决策等待期间清空死进程的 DroppedFiles/RegOps 记录），
             * 再终止进程树，最后弹第二个窗询问用户是否回滚 */
            BA_ROLLBACK_LIST rollbackList;
            BA_ROLLBACK_SELECTION sel;
            RtlZeroMemory(&rollbackList, sizeof(rollbackList));
            RtlZeroMemory(&sel, sizeof(sel));
            BehaviorCollectRollbackItems(
                ctx->rootPid,
                ctx->rootImagePath, rootProcessName,
                ctx->alertInfo.ThreatClass[0] ? ctx->alertInfo.ThreatClass : "Unknown",
                ctx->treePids, ctx->treePidCount, &rollbackList);
            DriverDbgPrint("[BA-PROD] Rollback items collected: %d (pre-terminate snapshot)\n",
                rollbackList.itemCount);

            /* 终止进程树 */
            TerminateProcessTree(ctx->treePids, ctx->treePidCount);

            /* 弹第二个窗：回滚确认（仅当收集到可回滚项） */
            if (rollbackList.itemCount > 0)
            {
                NTSTATUS rbStatus = AskClientForRollbackConfirm(&rollbackList, &sel);
                if (NT_SUCCESS(rbStatus) && sel.decision == 1)
                {
                    BehaviorExecuteRollbackSelected(&rollbackList, &sel);
                    DriverDbgPrint("[BA-PROD] Rollback executed: %d items\n", sel.itemCount);
                }
                else
                {
                    DriverDbgPrint("[BA-PROD] Rollback skipped (user ignore or timeout)\n");
                }
            }
            else
            {
                DriverDbgPrint("[BA-PROD] No rollback items collected\n");
                /* 用户态可见日志：明确告知无项可回滚，避免误以为功能缺失 */
                SendInjectionLog("[行为分析-回滚] 未检测到可回滚的文件/注册表操作，无需回滚确认");
            }
        }
        else
        {
            /* 用户态可见日志：用户选择放行，正在恢复进程树 */
            {
                CHAR allowLogMsg[400];
                RtlStringCbPrintfA(allowLogMsg, sizeof(allowLogMsg),
                    "[行为分析-放行] 用户选择放行，正在恢复进程树: 根PID=%lld 威胁=%s",
                    ctx->rootPid,
                    ctx->alertInfo.ThreatClass ? ctx->alertInfo.ThreatClass : "Unknown");
                SendInjectionLog(allowLogMsg);
            }

            /* ALLOW: 恢复进程树 */
            ResumeProcessTree(ctx->treePids, ctx->treePidCount);
        }

        DriverDbgPrint("[BA-PROD] Behavior alert work item completed for root PID=%lld\n", ctx->rootPid);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[BA-PROD] Exception caught in BehaviorAlertWorkItemRoutine for PID=%lld\n",
            ctx ? ctx->rootPid : 0);

        /* BUGFIX: 异常发生前若已挂起进程树（步骤1已执行），必须恢复，
         * 否则进程树永久挂起导致父进程 CreateProcess 卡死（ERROR_GEN_FAILURE）。
         * 此处无法精确判断异常发生在步骤1之前还是之后，但多恢复一次比永久
         * 挂起更安全——ResumeProcessTree 对未挂起的进程是 no-op。 */
        if (ctx != NULL && ctx->treePidCount > 0)
        {
            ResumeProcessTree(ctx->treePids, ctx->treePidCount);

            /* 用户态可见日志：异常路径恢复进程树 */
            {
                CHAR excLogMsg[300];
                RtlStringCbPrintfA(excLogMsg, sizeof(excLogMsg),
                    "[行为分析-异常] 告警处理异常，已恢复进程树: 根PID=%lld 威胁=%s",
                    ctx->rootPid,
                    ctx->alertInfo.ThreatClass ? ctx->alertInfo.ThreatClass : "Unknown");
                SendInjectionLog(excLogMsg);
            }
        }
    }
    } __finally {
        if (floatSaved) {
            floatSaved = FALSE;
            KeRestoreFloatingPointState(&floatSave);
        }
    }

    if (ctx != NULL)
    {
        ExFreePool(ctx);
    }
}

/* 对外接口：在PreCreateHandle回调中调用，入队work item后立即返回 */
VOID BehaviorHandleInjectionAlertAsync(
    INT64 sourcePid, const CHAR* sourceName,
    INT64 targetPid, const CHAR* targetName,
    const CHAR* injectType,
    INT64 threadId,
    PVOID threadStartAddr)
{
    /* 注入告警（CreateRemoteThread / 句柄剥离 / 线程劫持）始终触发弹窗，
     * 不受 g_bBehaviorDetectionEnabled 开关控制。
     * 行为分析开关仅控制评分引擎/综合威胁画像，不影响直接注入检测的实时告警。 */

    INJECTION_WORKITEM_CTX* ctx = (INJECTION_WORKITEM_CTX*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(INJECTION_WORKITEM_CTX), 'jnIA');
    if (!ctx)
    {
        DriverDbgPrint("[INJECT-ALERT] Failed to allocate work item context\n");
        return;
    }

    RtlZeroMemory(ctx, sizeof(INJECTION_WORKITEM_CTX));
    ctx->sourcePid = sourcePid;
    ctx->targetPid = targetPid;
    ctx->threadId = threadId;
    ctx->threadStartAddr = threadStartAddr;
    RtlStringCbCopyA(ctx->sourceName, sizeof(ctx->sourceName), sourceName ? sourceName : "Unknown");
    RtlStringCbCopyA(ctx->targetName, sizeof(ctx->targetName), targetName ? targetName : "Unknown");
    RtlStringCbCopyA(ctx->injectType, sizeof(ctx->injectType), injectType ? injectType : "Unknown");

    ExInitializeWorkItem(&ctx->WorkItem, InjectionAlertWorkItemRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);

    DriverDbgPrint("[INJECT-ALERT] Queued async work item for PID=%lld, Type=%s\n",
        sourcePid, injectType ? injectType : "Unknown");
}

/* ── BehaviorSuspendThreadById: 通过 TID 挂起指定线程 ──
 * 供 ThreadCreateNotifyRoutine 调用，立即挂起检测到的远程线程 */
NTSTATUS BehaviorSuspendThreadById(HANDLE ThreadId)
{
    NTSTATUS status;
    PETHREAD thread = NULL;
    HANDLE hThread = NULL;

    if (g_pNtSuspendThread == NULL)
        return STATUS_NOT_SUPPORTED;

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status))
        return status;

    status = ObOpenObjectByPointer(
        thread,
        OBJ_KERNEL_HANDLE,
        NULL,
        0x0002, /* THREAD_SUSPEND_RESUME */
        *PsThreadType,
        KernelMode,
        &hThread);
    ObDereferenceObject(thread);
    if (!NT_SUCCESS(status))
        return status;

    status = g_pNtSuspendThread(hThread);
    ZwClose(hThread);
    return status;
}

/* ── BehaviorIsLegitimateProcessCreation: 判断是否为正常进程创建 ──
 * 在 ThreadCreateNotifyRoutine 中使用：如果源进程是目标进程的父进程，
 * 说明这是正常的新进程启动（父进程创建子进程的初始线程），不是远程线程注入。
 * 此时必须跳过挂起，否则会在新进程线程初始化期间挂起它，导致蓝屏。
 * 参考 Elastic Security detection-rules：
 * - 检查进程父子关系
 * - 检查进程创建时间
 * - 检查进程镜像路径 */
BOOLEAN BehaviorIsLegitimateProcessCreation(INT64 childPid, INT64 parentPid)
{
    BOOLEAN result = FALSE;
    KIRQL oldIrql = 0;
    INT64 nowMs;

    if (childPid == 0 || parentPid == 0 || childPid == parentPid)
        return FALSE;

    nowMs = baEtwTickMs();

    KeAcquireSpinLock(&g_baLock, &oldIrql);
    {
        int idx = findProc(childPid);
        if (idx >= 0) {
            /* 检查父子关系：只有实际父子关系才可能为合法进程创建 */
            if (g_baProcTree[idx].parentPid == parentPid) {
                result = TRUE;
            }
            
            /* 检查进程镜像路径是否与父进程相同（支持白加黑等合法场景） */
            int parentIdx = findProc(parentPid);
            if (parentIdx >= 0 &&
                g_baProcTree[idx].imagePath[0] != '\0' &&
                g_baProcTree[parentIdx].imagePath[0] != '\0') {
                if (kStrCmp(g_baProcTree[idx].imagePath, 
                    g_baProcTree[parentIdx].imagePath) == 0) {
                    result = TRUE;
                }
            }
            
            /* 检查进程创建时间：仅在已确认父子关系或同镜像的前提下，
             * 最近创建（5秒内）作为辅助确认，避免独立以时间判断导致误放行。 */
            if (result && g_baProcTree[idx].createTickMs != 0 &&
                (nowMs - g_baProcTree[idx].createTickMs) <= 5000) {
                /* 保持 result = TRUE，时间作为辅助确认 */
            }
        }
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    return result;
}

/* ── BehaviorIsRecentSameFamilyProcess: 判断目标是否为源进程同一家族的最近创建子进程 ──
 * 用于消除 Edge/Chrome 等多进程浏览器中兄弟进程打开 helper 子进程导致的误报。
 * 参考 Elastic Security detection-rules：
 * - 检查进程创建时间
 * - 检查进程镜像路径
 * - 检查进程家族关系
 * - 支持多级家族匹配 */
BOOLEAN BehaviorIsRecentSameFamilyProcess(INT64 sourcePid, INT64 targetPid)
{
    BOOLEAN result = FALSE;
    KIRQL oldIrql = 0;
    INT64 nowMs;

    if (sourcePid == 0 || targetPid == 0 || sourcePid == targetPid)
        return FALSE;

    nowMs = baEtwTickMs();

    KeAcquireSpinLock(&g_baLock, &oldIrql);
    {
        int srcIdx = findProc(sourcePid);
        int tgtIdx = findProc(targetPid);
        if (srcIdx >= 0 && tgtIdx >= 0 &&
            g_baProcTree[tgtIdx].createTickMs != 0 &&
            (nowMs - g_baProcTree[tgtIdx].createTickMs) <= 15000) {

            /* 目标最近创建：检查其进程树中的父进程是否与源进程同镜像 */
            int parentIdx = findProc(g_baProcTree[tgtIdx].parentPid);
            if (parentIdx >= 0 &&
                g_baProcTree[srcIdx].imagePath[0] != '\0' &&
                g_baProcTree[parentIdx].imagePath[0] != '\0') {
                if (kStrCmp(g_baProcTree[srcIdx].imagePath, 
                    g_baProcTree[parentIdx].imagePath) == 0) {
                    result = TRUE;
                }
            }
            
            /* 检查是否为兄弟进程（同一父进程） */
            if (!result && g_baProcTree[srcIdx].parentPid != 0) {
                if (g_baProcTree[tgtIdx].parentPid == g_baProcTree[srcIdx].parentPid) {
                    result = TRUE;
                }
            }

            /* 检查是否为同一镜像路径 */
            if (!result &&
                g_baProcTree[srcIdx].imagePath[0] != '\0' &&
                g_baProcTree[tgtIdx].imagePath[0] != '\0') {
                if (kStrCmp(g_baProcTree[srcIdx].imagePath,
                    g_baProcTree[tgtIdx].imagePath) == 0) {
                    result = TRUE;
                }
            }
        }
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);
    return result;
}

/* ── BehaviorClassifyMalwareFamily: 恶意软件家族归类 ──
 * 当 BehaviorCheckAndAlert 判定为威胁后调用，检查进程树中是否出现家族特征指标。
 * 若出现银狐家族特征指标（BA_IND_FILE_FAKE_DIR_DROP + BA_IND_FILE_TEMP_RANDOM_NAME_EXE），
 * 则将 threatClass 覆盖为 SilverFox 家族。
 *
 * 归类规则：
 *   - 已有 threatClass 明确指向 SilverFox（含 "SilverFox" 子串）→ 不覆盖，保留原值
 *   - threatClass 为通用 "Behavior/SuspiciousBehaviorChain.Generic" → 检查家族指标
 *   - 进程树中同时出现 FAKE_DIR_DROP 和 TEMP_RANDOM_NAME_EXE → 归类为 SilverFox.Generic
 *   - 仅出现 FAKE_DIR_DROP 或仅出现 TEMP_RANDOM_NAME_EXE → 归类为 SilverFox.Suspicious
 *
 * 注意：此函数不改变是否告警的判定，仅在已判定为威胁后修改家族分类标签。
 * 低危指标权重极低（8.0），不会单独触发威胁警报。 */
BOOLEAN BehaviorClassifyMalwareFamily(
    INT64* treePids, int treePidCount,
    CHAR* threatClassBuf, ULONG threatClassBufLen,
    CHAR* descriptionBuf, ULONG descriptionBufLen)
{
    int fakeDirCount = 0;
    int randomNameCount = 0;
    int dllSideLoadCount = 0;
    int appdataDllCount = 0;
    int tempOriginCount = 0;
    int appdataOriginCount = 0;
    int hiddenFileCount = 0;
    int peInImageCount = 0;
    int etwPatchCount = 0;
    int instrCallbackCount = 0;
    int allocExecCount = 0;
    int selfExecCount = 0;
    int c2ConnectCount = 0;
    int scriptInterpreterCount = 0;
    int elevServiceHijackCount = 0;     /* BA_IND_REG_ELEVATION_SERVICE_HIJACK */
    int elevFileHijackCount = 0;        /* BA_IND_FILE_ELEVATION_SERVICE_HIJACK */
    KIRQL oldIrql = 0;
    int i;
    BOOLEAN classified = FALSE;

    if (treePids == NULL || treePidCount <= 0 ||
        threatClassBuf == NULL || threatClassBufLen == 0)
        return FALSE;

    /* 若 threatClass 已明确指向 SilverFox/AVBypass/Rootkit/Exploit/Persistence，无需重复归类 */
    if (kStrIStrLen(threatClassBuf, kStrLen(threatClassBuf), "SilverFox", 9) ||
        kStrIStrLen(threatClassBuf, kStrLen(threatClassBuf), "AVBypass", 8) ||
        kStrIStrLen(threatClassBuf, kStrLen(threatClassBuf), "Rootkit", 7) ||
        kStrIStrLen(threatClassBuf, kStrLen(threatClassBuf), "Exploit", 7) ||
        kStrIStrLen(threatClassBuf, kStrLen(threatClassBuf), "Persistence", 11))
        return FALSE;

    KeAcquireSpinLock(&g_baLock, &oldIrql);
    {
        /* 遍历活跃进程树，统计家族特征指标 */
        for (i = 0; i < treePidCount; i++) {
            int idx = findProc(treePids[i]);
            if (idx < 0 || idx >= BA_MAX_PROCESSES) continue;
            if (g_baPidIndicators[idx][BA_IND_FILE_FAKE_DIR_DROP] > 0)
                fakeDirCount++;
            if (g_baPidIndicators[idx][BA_IND_FILE_TEMP_RANDOM_NAME_EXE] > 0)
                randomNameCount++;
            if (g_baPidIndicators[idx][BA_IND_FILE_DLL_SIDE_LOAD] > 0)
                dllSideLoadCount++;
            if (g_baPidIndicators[idx][BA_IND_FILE_APPDATA_DLL] > 0)
                appdataDllCount++;
            if (g_baPidIndicators[idx][BA_IND_PROC_FROM_TEMP_DIR] > 0)
                tempOriginCount++;
            if (g_baPidIndicators[idx][BA_IND_PROC_FROM_APPDATA_DIR] > 0)
                appdataOriginCount++;
            /* SilverFox 新增指标 */
            if (g_baPidIndicators[idx][BA_IND_FILE_SET_SYSTEM_HIDDEN] > 0)
                hiddenFileCount++;
            if (g_baPidIndicators[idx][BA_IND_FILE_PE_IN_IMAGE] > 0)
                peInImageCount++;
            /* AVBypass 指标 */
            if (g_baPidIndicators[idx][BA_IND_REG_ETW_PATCH] > 0)
                etwPatchCount++;
            if (g_baPidIndicators[idx][BA_IND_REG_INSTRUMENTATION_CALLBACK] > 0)
                instrCallbackCount++;
            /* Exploit 指标 */
            if (g_baPidIndicators[idx][BA_IND_MEM_ALLOC_EXECUTE] > 0)
                allocExecCount++;
            if (g_baPidIndicators[idx][BA_IND_MEM_ALLOC_EXECUTE_SELF] > 0)
                selfExecCount++;
            /* C2/脚本指标 */
            if (g_baPidIndicators[idx][BA_IND_NET_C2_CONNECT] > 0)
                c2ConnectCount++;
            if (g_baPidIndicators[idx][BA_IND_PROC_SCRIPT_INTERPRETER] > 0)
                scriptInterpreterCount++;
        }

        /* 同时检查幽灵进程（已退出的父进程）— 从幽灵进程独立指标副本读取 */
        for (i = 0; i < g_baGhostCount; i++) {
            if (!g_baGhostProcesses[i].hasSuspiciousIndicators) continue;
            INT* gInd = g_baGhostProcesses[i].indicators;
            if (gInd[BA_IND_FILE_SET_SYSTEM_HIDDEN] > 0) hiddenFileCount++;
            if (gInd[BA_IND_FILE_PE_IN_IMAGE] > 0) peInImageCount++;
            if (gInd[BA_IND_REG_ETW_PATCH] > 0) etwPatchCount++;
            if (gInd[BA_IND_REG_INSTRUMENTATION_CALLBACK] > 0) instrCallbackCount++;
            if (gInd[BA_IND_MEM_ALLOC_EXECUTE_SELF] > 0) selfExecCount++;
            if (gInd[BA_IND_MEM_ALLOC_EXECUTE] > 0) allocExecCount++;
            if (gInd[BA_IND_PROC_FROM_TEMP_DIR] > 0) tempOriginCount++;
            if (gInd[BA_IND_PROC_UNSIGNED] > 0) tempOriginCount++;
            if (gInd[BA_IND_NET_C2_CONNECT] > 0) c2ConnectCount++;
            if (gInd[BA_IND_NETWORK_C2_CONNECT] > 0) c2ConnectCount++;
            if (gInd[BA_IND_FILE_DLL_SIDE_LOAD] > 0) dllSideLoadCount++;
            if (gInd[BA_IND_FILE_APPDATA_DLL] > 0) appdataDllCount++;
            if (gInd[BA_IND_FILE_DROP_FROM_TEMP] > 0) fakeDirCount++;
            if (gInd[BA_IND_FILE_TEMP_RANDOM_NAME_EXE] > 0) randomNameCount++;
            if (gInd[BA_IND_FILE_SELF_LOADING] > 0) dllSideLoadCount++;
            if (gInd[BA_IND_MEM_SELF_PROTECT_EXECUTABLE] > 0) selfExecCount++;
            if (gInd[BA_IND_MEM_NONSYSTEM_RWX] > 0) selfExecCount++;
            if (gInd[BA_IND_MEM_NONSYSTEM_EXEC_READ] > 0) selfExecCount++;
            if (gInd[BA_IND_REG_ELEVATION_SERVICE_HIJACK] > 0) elevServiceHijackCount++;
            if (gInd[BA_IND_FILE_ELEVATION_SERVICE_HIJACK] > 0) elevFileHijackCount++;
        }
    }
    KeReleaseSpinLock(&g_baLock, oldIrql);

    /* ── 银狐行为链检测（高置信度，覆盖任意 threatClass）──
     * 典型银狐链：Temp起源 → 脚本/命令行 → PE执行 → 隐藏文件 → C2
     * 或：Temp起源 → 图像隐写 → 隐藏文件 → C2
     * 或：Temp起源 → C2 → DLL侧加载/文件投放/自执行（覆盖银狐投放+加载链）
     * 或：Temp起源 → 文件投放 → DLL侧加载（投放+加载链） */
    if ((tempOriginCount > 0 && hiddenFileCount > 0 && c2ConnectCount > 0) ||
        (tempOriginCount > 0 && peInImageCount > 0 && hiddenFileCount > 0) ||
        (tempOriginCount > 0 && scriptInterpreterCount > 0 && selfExecCount > 0) ||
        (tempOriginCount > 0 && c2ConnectCount > 0 && (dllSideLoadCount > 0 || fakeDirCount > 0 || selfExecCount > 0)) ||
        (tempOriginCount > 0 && fakeDirCount > 0 && dllSideLoadCount > 0)) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Trojan.SilverFox/BehaviorChain");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "SilverFox behavior chain: tempOrigin(%d) hiddenFile(%d) peInImage(%d) c2(%d) script(%d) selfExec(%d) sideLoad(%d) drop(%d)",
                tempOriginCount, hiddenFileCount, peInImageCount, c2ConnectCount,
                scriptInterpreterCount, selfExecCount, dllSideLoadCount, fakeDirCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as Trojan.SilverFox/BehaviorChain: temp=%d hidden=%d peImg=%d c2=%d script=%d selfExec=%d sideLoad=%d drop=%d\n",
            tempOriginCount, hiddenFileCount, peInImageCount, c2ConnectCount,
            scriptInterpreterCount, selfExecCount, dllSideLoadCount, fakeDirCount);
        return classified;
    }

    /* ── elevation_service 持久化检测（T1543.003/T1574.002）──
     * 修改 elevation_service 注册表或替换其 DLL/EXE 是实现提权持久化的常见手段。
     * 即使无其他行为链特征，单一命中也应告警。 */
    if (elevServiceHijackCount > 0 || elevFileHijackCount > 0) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Trojan.Persistence/ElevationServiceHijack");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "elevation_service persistence hijack: regHijack(%d) fileHijack(%d)",
                elevServiceHijackCount, elevFileHijackCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as Trojan.Persistence/ElevationServiceHijack: reg=%d file=%d\n",
            elevServiceHijackCount, elevFileHijackCount);
        return classified;
    }

    /* ── AVBypass 检测 ── */
    if (etwPatchCount > 0 || instrCallbackCount > 0) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Trojan.AVBypass/ETWBypass");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "AV bypass detected: ETW patch(%d) InstrumentationCallback(%d)",
                etwPatchCount, instrCallbackCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as Trojan.AVBypass: etw=%d instr=%d\n",
            etwPatchCount, instrCallbackCount);
        return classified;
    }

    /* ── Exploit 检测（shellcode 执行）── */
    if (selfExecCount > 0 || allocExecCount > 0) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Trojan.Exploit/ShellcodeExec");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "Shellcode execution detected: selfExec(%d) allocExec(%d)",
                selfExecCount, allocExecCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as Trojan.Exploit: selfExec=%d allocExec=%d\n",
            selfExecCount, allocExecCount);
        return classified;
    }

    /* ── 传统银狐家族归类（低置信度）── */
    if (fakeDirCount > 0 && randomNameCount > 0) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Behavior/Trojan:SilverFox.Generic");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "SilverFox trojan classified by family traits: fake dir drop (%d) + random name exe (%d)",
                fakeDirCount, randomNameCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as SilverFox.Generic: fakeDir=%d randomName=%d\n",
            fakeDirCount, randomNameCount);
    } else if (dllSideLoadCount > 0 && appdataDllCount > 0 &&
               (tempOriginCount > 0 || appdataOriginCount > 0)) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Behavior/Trojan:SilverFox.Generic");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "SilverFox trojan classified by behavior chain: dllSideLoad(%d) + appdataDll(%d) + tempOrigin(%d) + appdataOrigin(%d)",
                dllSideLoadCount, appdataDllCount, tempOriginCount, appdataOriginCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as SilverFox.Generic: sideLoad=%d appdataDll=%d temp=%d appdata=%d\n",
            dllSideLoadCount, appdataDllCount, tempOriginCount, appdataOriginCount);
    } else if (fakeDirCount > 0 || randomNameCount > 0 ||
               dllSideLoadCount > 0 || appdataDllCount > 0) {
        RtlStringCbCopyA(threatClassBuf, threatClassBufLen,
            "Behavior/Trojan:SilverFox.Suspicious");
        if (descriptionBuf && descriptionBufLen > 0) {
            RtlStringCbPrintfA(descriptionBuf, descriptionBufLen,
                "Suspicious SilverFox family trait: fakeDir=%d randomName=%d sideLoad=%d appdataDll=%d",
                fakeDirCount, randomNameCount, dllSideLoadCount, appdataDllCount);
        }
        classified = TRUE;
        DriverDbgPrint("[BA-FAMILY] Classified as SilverFox.Suspicious: fakeDir=%d randomName=%d sideLoad=%d appdataDll=%d\n",
            fakeDirCount, randomNameCount, dllSideLoadCount, appdataDllCount);
    }

    return classified;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorIsAddressInLoadedModule — 检查地址是否在目标进程已加载镜像范围内
 *
 * 用于检测线程起始地址是否位于非镜像内存（shellcode 注入）。
 * 原理：通过 ZwQueryVirtualMemory 查询地址的 MemoryBasicInformation，
 * 如果 Type == MEM_IMAGE，则该地址属于某个已加载模块。
 *
 * 参考 Elastic Security shellcode thread 检测策略：
 *   - 远程线程起始地址不在任何已加载 DLL/EXE 范围内 → shellcode 注入
 *   - 此方法比遍历 PEB LDR 更可靠，不受 LDR 隐藏/断链对抗影响
 *
 * 注意：Type == MEM_IMAGE 是可靠的判定依据，因为 Windows 内核保证
 * 所有 MEM_IMAGE 页面都来自文件映射（PE 加载器），shellcode 无法伪造。
 *
 * 返回 TRUE 表示地址在已加载镜像范围内（合法），
 * 返回 FALSE 表示地址在非镜像内存中（shellcode 注入可疑）。
 * ══════════════════════════════════════════════════════════════════════════ */
BOOLEAN BehaviorIsAddressInLoadedModule(
    INT64 targetPid,
    PVOID address)
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    BOOLEAN isImage = FALSE;
    MEMORY_BASIC_INFORMATION mbi;

    if (address == NULL || targetPid <= 0)
        return FALSE;

    /* 通过 PID 查找目标进程 */
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProcess);
    if (!NT_SUCCESS(status) || targetProcess == NULL)
        return FALSE;

    __try
    {
        /* 附加到目标进程地址空间 */
        KeStackAttachProcess(targetProcess, &apcState);
        attached = TRUE;

        /* 查询起始地址的虚拟内存信息 */
        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            ZwCurrentProcess(),
            address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            NULL);

        if (NT_SUCCESS(status))
        {
            /* MEM_IMAGE (0x1000000) 表示该内存区域来自 PE 文件映射 */
            if (mbi.Type == MEM_IMAGE)
            {
                isImage = TRUE;
            }
        }

        /* 还检查地址是否在分配范围内（MEM_PRIVATE 但可能是 shellcode 区域） */
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("[BA-IMG-CHK] ZwQueryVirtualMemory failed for PID=%lld Addr=%p: 0x%X\n",
                targetPid, address, status);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[BA-IMG-CHK] Exception checking address PID=%lld Addr=%p\n",
            targetPid, address);
    }

    if (attached)
    {
        KeUnstackDetachProcess(&apcState);
    }

    if (targetProcess)
    {
        ObDereferenceObject(targetProcess);
    }

    return isImage;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorCheckStartAddressUnbacked — 检查地址是否落在非镜像可执行内存
 *
 * 对齐 Elastic Security shellcode-thread（kernel_shellcode_event）判定：
 *   1. State == MEM_COMMIT
 *   2. Protect 含 PAGE_EXECUTE_*（EXECUTE_READ / EXECUTE_READWRITE 等）
 *   3. Type != MEM_IMAGE（无磁盘 PE 镜像映射，unbacked）
 * 全部命中 = shellcode 注入的强证据。
 *
 * isExecutable 输出该页保护属性是否可执行（供调用方区分
 * "镜像内可执行"（模块注入/trampoline 候选）与"不可执行/未知"）。
 * ═══════════════════════════════════════════════════════════════════════════ */
BOOLEAN BehaviorCheckStartAddressUnbacked(
    INT64 targetPid,
    PVOID address,
    BOOLEAN* isExecutable)
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    KAPC_STATE apcState;
    BOOLEAN attached = FALSE;
    BOOLEAN unbackedExec = FALSE;
    MEMORY_BASIC_INFORMATION mbi;

    if (isExecutable != NULL)
        *isExecutable = FALSE;

    if (address == NULL || targetPid <= 0)
        return FALSE;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &targetProcess);
    if (!NT_SUCCESS(status) || targetProcess == NULL)
        return FALSE;

    __try
    {
        /* 附加到目标进程地址空间 */
        KeStackAttachProcess(targetProcess, &apcState);
        attached = TRUE;

        RtlZeroMemory(&mbi, sizeof(mbi));
        status = ZwQueryVirtualMemory(
            ZwCurrentProcess(),
            address,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            NULL);

        if (NT_SUCCESS(status))
        {
            /* Protect 低字节高四位：0x10/0x20/0x40/0x80 = PAGE_EXECUTE 系列 */
            BOOLEAN executable = (mbi.Protect & 0xF0) != 0;

            if (isExecutable != NULL)
                *isExecutable = executable;

            if (mbi.State == MEM_COMMIT && executable && mbi.Type != MEM_IMAGE)
            {
                unbackedExec = TRUE;
            }
        }
        else
        {
            DriverDbgPrint("[BA-IMG-CHK] ZwQueryVirtualMemory failed for PID=%lld Addr=%p: 0x%X\n",
                targetPid, address, status);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[BA-IMG-CHK] Exception checking address PID=%lld Addr=%p\n",
            targetPid, address);
    }

    if (attached)
    {
        KeUnstackDetachProcess(&apcState);
    }

    if (targetProcess)
    {
        ObDereferenceObject(targetProcess);
    }

    return unbackedExec;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorIsThreadRipInUnbackedExecutable — Trampoline 跳板检测（Rip 采样）
 *
 * Elastic 官方博客公开的对抗手段：恶意软件把线程 StartAddress 指向合法模块
 * 导出（如 ntdll 导出函数），内部 jmp 跳到 shellcode（trampoline 跳板），
 * 此时简单的 unbacked 内存判断失效。对抗方法：线程启动后采样 CPU 上下文
 * Rip 指令指针，若 Rip 实际落入非镜像可执行内存，说明执行已进入 shellcode。
 *
 * 采样失败 / 线程不可访问 / Rip 无效 → 返回 FALSE（无证据，保守放行）。
 * 必须在 PASSIVE_LEVEL 调用（KeGetContextThread 要求）。
 * ═══════════════════════════════════════════════════════════════════════════ */
BOOLEAN BehaviorIsThreadRipInUnbackedExecutable(
    INT64 threadId,
    INT64 targetPid)
{
    NTSTATUS status;
    PETHREAD thread = NULL;
    HANDLE hThread = NULL;
    BOOLEAN unbacked = FALSE;
    CONTEXT ctx;

    if (threadId <= 0 || targetPid <= 0 || g_pNtGetContextThread == NULL)
        return FALSE;

    status = PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)threadId, &thread);
    if (!NT_SUCCESS(status) || thread == NULL)
        return FALSE;

    /* THREAD_GET_CONTEXT = 0x0008 */
    status = ObOpenObjectByPointer(
        thread,
        OBJ_KERNEL_HANDLE,
        NULL,
        0x0008,
        *PsThreadType,
        KernelMode,
        &hThread);
    ObDereferenceObject(thread);
    if (!NT_SUCCESS(status))
        return FALSE;

    RtlZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_CONTROL;
    status = g_pNtGetContextThread(hThread, &ctx);
    ZwClose(hThread);
    if (!NT_SUCCESS(status))
        return FALSE;

    /* Rip 可能为 0（线程尚未被调度）或位于内核地址，直接放行 */
    if (ctx.Rip == 0 || (ULONG_PTR)ctx.Rip > (ULONG_PTR)MmHighestUserAddress)
        return FALSE;

    unbacked = BehaviorCheckStartAddressUnbacked(targetPid, (PVOID)ctx.Rip, NULL);
    return unbacked;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorDetectEdrFreeze — 检测 EDR-Freeze (WerFaultSecure 滥用)
 *
 * 参考 Elastic Security 规则 defense_evasion_edr_freeze_via_werfaultsecure.toml：
 *   WerFaultSecure.exe 是 PPL 版本的 Windows Error Reporting，
 *   正常由 WER 服务 (svchost.exe) 启动。攻击者用它来 dump 安全进程的内存，
 *   然后挂起 WerFaultSecure.exe 本身（保持目标进程挂起状态），
 *   实现 "冻结" EDR/AV 而不触发终止告警。
 *
 * 检测条件：
 *   1. 新进程是 WerFaultSecure.exe
 *   2. 父进程不是 WER 服务 (svchost.exe/wermgr.exe/WerFault.exe)
 *   3. 命令行包含 /pid 和 /encfile（dump 参数）
 *
 * 返回 TRUE 表示检测到 EDR-Freeze 攻击。
 * ══════════════════════════════════════════════════════════════════════════ */
BOOLEAN BehaviorDetectEdrFreeze(
    INT64 newPid,
    const CHAR* newProcName,
    const CHAR* newProcPath,
    const CHAR* cmdLine,
    INT64 parentPid,
    const CHAR* parentProcName,
    const CHAR* parentProcPath)
{
    CHAR procLower[64];
    CHAR parentLower[64];
    CHAR cmdLower[512];

    UNREFERENCED_PARAMETER(parentProcPath);

    /* 参数校验 */
    if (newProcName == NULL || newProcPath == NULL)
        return FALSE;

    /* 仅检测 WerFaultSecure.exe */
    kStrLowerCopy(procLower, 64, newProcName);
    if (kStrStr(procLower, "werfaultsecure.exe") == 0 &&
        kStrStr(procLower, "werfaultsecure") == 0)
        return FALSE;

    /* 检查路径是否在 System32 目录（正常路径），非 System32 路径的 WerFaultSecure 更可疑 */
    {
        CHAR pathLower[BA_MAX_PATH];
        kStrLowerCopy(pathLower, BA_MAX_PATH, newProcPath);
        if (kStrStr(pathLower, "\\system32\\werfaultsecure.exe") == 0 &&
            kStrStr(pathLower, "\\syswow64\\werfaultsecure.exe") == 0)
        {
            /* 路径异常：不在 System32 目录，高度可疑 */
            INT idx = findOrCreatePidIndex(newPid);
            if (idx >= 0)
            {
                addIndicator(idx, BA_IND_PROC_EDR_FREEZE,
                    "EDR-Freeze: WerFaultSecure.exe from non-system directory");
            }
            return TRUE;
        }
    }

    /* 检查父进程是否为正常的 WER 服务 */
    if (parentProcName != NULL)
    {
        kStrLowerCopy(parentLower, 64, parentProcName);
        if (kStrStr(parentLower, "svchost.exe") != 0 ||
            kStrStr(parentLower, "wermgr.exe") != 0 ||
            kStrStr(parentLower, "werfault.exe") != 0 ||
            kStrStr(parentLower, "werfaultsecure.exe") != 0)
        {
            /* 父进程是 WER 组件，正常 */
            DriverDbgPrint("[BA-EDR-FREEZE] Normal WER chain: parent=%s -> %s\n",
                parentProcName, newProcName);
            return FALSE;
        }
    }

    /* 检查命令行是否包含 dump 参数 */
    if (cmdLine != NULL)
    {
        kStrLowerCopy(cmdLower, 512, cmdLine);
        if (kStrStr(cmdLower, "/pid") != 0 && kStrStr(cmdLower, "/encfile") != 0)
        {
            INT idx = findOrCreatePidIndex(newPid);
            if (idx >= 0)
            {
                CHAR evBuf[256];
                RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                    "EDR-Freeze: WerFaultSecure.exe launched by %s (PID:%lld) with /pid /encfile",
                    parentProcName ? parentProcName : "Unknown",
                    parentPid);
                addIndicator(idx, BA_IND_PROC_EDR_FREEZE, evBuf);
            }
            return TRUE;
        }
    }

    /* 如果父进程非 WER 但命令行无 /pid /encfile，也做轻量记录 */
    {
        INT idx = findOrCreatePidIndex(newPid);
        if (idx >= 0)
        {
            CHAR evBuf[256];
            RtlStringCbPrintfA(evBuf, sizeof(evBuf),
                "EDR-Freeze: WerFaultSecure.exe launched by abnormal parent: %s (PID:%lld)",
                parentProcName ? parentProcName : "Unknown",
                parentPid);
            addIndicator(idx, BA_IND_PROC_EDR_FREEZE, evBuf);
        }
        return TRUE;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorRecordPrivilegeEscalationIndicator — 从外部模块记录提权指标并触发告警
 *
 * 供 FileFilter.c / ProcessCallback.c 等模块在检测到提权行为时调用：
 *   - CVE-2021-41379：非签名进程修改 Program Files 目录的 DACL/文件本体
 *   - TrustedInstaller 句柄复制提权
 *
 * 此函数在 PASSIVE_LEVEL 调用，可安全使用 ExAllocatePool2 / ObOpenObjectByPointer。
 * ═══════════════════════════════════════════════════════════════════════════ */
VOID BehaviorRecordPrivilegeEscalationIndicator(
    INT64 pid,
    const CHAR* imageName,
    const CHAR* targetPath,
    BA_INDICATOR indicatorId,
    const CHAR* evidenceText)
{
    UNREFERENCED_PARAMETER(targetPath);
    if (!g_baInitialized || !g_bBehaviorDetectionEnabled)
        return;

    /* 跳过受信任主程序 */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)pid == g_TrustedMainPid)
        return;

    /* 跳过白名单 */
    if (WhitelistCheckByPid(pid) == 1)
        return;

    INT idx = findOrCreatePidIndex(pid);
    if (idx < 0)
        return;

    addIndicator(idx, indicatorId, evidenceText);

    /* 立即触发实时告警（挂起进程 + 用户决策） */
    CHAR nameBuf[64] = {0};
    if (imageName && imageName[0]) {
        int n = 0;
        while (imageName[n] && n < 63) { nameBuf[n] = imageName[n]; n++; }
        nameBuf[n] = '\0';
    } else {
        RtlStringCbPrintfA(nameBuf, sizeof(nameBuf), "PID:%lld", pid);
    }

    /* 根据指标类型选择合适的threatClass前缀，供客户端MapAlertTitle匹配 */
    const CHAR* threatPrefix = NULL;
    if (indicatorId == BA_IND_PROC_DACL_MODIFY)
        threatPrefix = "PrivilegeEscalation/CVE202141379:DACL";
    else if (indicatorId == BA_IND_PROC_TRUSTEDINSTALLER_DUP)
        threatPrefix = "PrivilegeEscalation/TrustedInstaller:DuplicateHandle";
    else
        threatPrefix = "PrivilegeEscalation/Unknown";

    BehaviorHandleInjectionAlertAsync(
        pid, nameBuf,
        pid, nameBuf,
        threatPrefix, 0, NULL);
}

