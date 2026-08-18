#include "../shared/Common.h"
#include "Main.h"
#include "ProcessCallback.h"
#include "BehaviorAnalysis.h"
#include "ResponseSystem.h"
#include "RegistryCallback.h"
#include "Whitelist.h"
#include "ci_verify.h"         /* CiRecordProcessSignature */
#include "DriverDllInject.h"         /* 驱动端 DLL 注入核心库（参考 injdrv） */
#include "VulnerableDriver.h"        /* 漏洞驱动（BYOVD）加载拦截 */
#include <ntimage.h>
#include <ntstrsafe.h>

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* 前置声明：LoadImageNotifyRoutine 中会调用 IsNtdllImage / IsKernel32Image */
static BOOLEAN IsNtdllImage(_In_ PUNICODE_STRING FullImageName);
static BOOLEAN IsKernel32Image(_In_ PUNICODE_STRING FullImageName);

/* ObRegisterCallbacks PreOperation 回调可能在 DISPATCH_LEVEL 执行，必须确保
 * 回调函数本身位于非分页代码段，否则取指令时会触发 IRQL_LESS_OR_EQUAL。 */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(NONPAGED, HandleProcessProtectCallBack)
#pragma alloc_text(NONPAGED, HandleThreadProtectCallBack)
#endif

/* 挂起/恢复进程前向声明 */
static NTSTATUS SuspendProcessByPid(INT64 pid);
static NTSTATUS ResumeProcessByPid(INT64 pid);

/* ── PE 相关常量回退定义（ntimage.h 可能未完全导出）── */
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE  0x5A4D
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE   0x00004550
#endif
#ifndef IMAGE_DIRECTORY_ENTRY_EXPORT
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR64_MAGIC
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#endif
#ifndef IMAGE_NT_OPTIONAL_HDR32_MAGIC
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#endif

/* PsGetProcessInheritedFromUniqueProcessId — 获取进程父进程 PID */
NTKERNELAPI HANDLE PsGetProcessInheritedFromUniqueProcessId(__in PEPROCESS Process);

/* ThreadQuerySetWin32StartAddress — 查询线程实际起始地址的信息类（值 9） */
#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif

/* ZwQueryInformationThread — 内核态 NtQueryInformationThread，用于获取线程起始地址 */
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_opt_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength);

/* ── ROP 检测：栈回溯检查 DLL 加载是否通过 ROP 链发起 ──
 * RtlWalkFrameChain 在 R0 中可用，Flags=1 表示走用户态栈。
 * MEM_IMAGE = 0x1000000（PE 镜像映射内存） */
#ifndef MEM_IMAGE
#define MEM_IMAGE 0x1000000
#endif

/* 检测 DLL 加载是否通过 ROP 链发起。
 * 返回 TRUE 表示检测到 ROP（调用栈含非镜像返回地址）。
 * 检测原理：遍历用户态调用栈前 N 帧，对每个返回地址调用
 * ZwQueryVirtualMemory(MemoryBasicInformation) 检查 Type 是否为 MEM_IMAGE。
 * 若任一返回地址不在镜像内存中，则判定为 ROP。 */
static BOOLEAN DetectDllLoadViaRop(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName);

/* ═══════════════════════════════════════════════════════════════════════════
 * IsKnownSystemProcessNameLocal — 基于进程短名判断是否为已知 Windows 系统组件
 *
 * 在 ObRegisterCallbacks 回调中无法安全打开句柄获取完整路径（会递归触发
 * 对象回调），因此只能使用 PsGetProcessImageFileName 返回的 8.3 短名。
 * 这里将短名转小写后调用 BehaviorAnalysis 导出的 IsKnownSystemProcessName。
 * ══════════════════════════════════════════════════════════════════════════ */
static BOOLEAN IsKnownSystemProcessNameLocal(const CHAR* name)
{
    CHAR lower[32];
    int i;

    if (name == NULL || name[0] == '\0')
        return FALSE;

    for (i = 0; i < 31 && name[i] != '\0'; i++) {
        CHAR c = name[i];
        if (c >= 'A' && c <= 'Z')
            c += 32;
        lower[i] = c;
    }
    lower[i] = '\0';

    return IsKnownSystemProcessName(lower);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IsJITProcessNameLocal — 判断是否为已知的 JIT/脚本引擎进程（误报豁免）
 *
 * .NET CLR、V8、Chakra 等 JIT 引擎会在 MEM_PRIVATE 内存中执行代码，
 * 触发 ROP 检测时会产生误报。此类进程应降低判定严格程度。
 * ══════════════════════════════════════════════════════════════════════════ */
static BOOLEAN IsJITProcessNameLocal(const CHAR* name)
{
    CHAR lower[32];
    int i;

    if (name == NULL || name[0] == '\0')
        return FALSE;

    for (i = 0; i < 31 && name[i] != '\0'; i++) {
        CHAR c = name[i];
        if (c >= 'A' && c <= 'Z')
            c += 32;
        lower[i] = c;
    }
    lower[i] = '\0';

    /* 已知 JIT/脚本引擎进程 */
    return (strcmp(lower, "dotnet.exe") == 0 ||
            strcmp(lower, "dotnet.ex") == 0 ||          /* 8.3 截断 */
            strcmp(lower, "iexplore.exe") == 0 ||       /* IE + Chakra */
            strcmp(lower, "chrome.exe") == 0 ||         /* Chrome + V8 */
            strcmp(lower, "msedge.exe") == 0 ||         /* Edge + V8 */
            strcmp(lower, "powershell.exe") == 0 ||     /* PS + .NET */
            strcmp(lower, "powershell_ise.exe") == 0 ||
            strcmp(lower, "clxsl.exe") == 0);           /* .NET XSLT */
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IsTrustedDeveloperToolLocal — 基于进程短名判断是否为受信任的开发者工具
 *
 * 用于排除 Visual Studio / VS Code / dotnet / MSBuild 等合法 IDE/编译器
 * 创建子进程（如 devenv.exe -> vcpkgsrv.exe、VBCSCompiler.exe）时被误判为
 * ProcessHollowing。仅通过短名白名单识别，避免影响正常防护。
 *
 * 注意：PsGetProcessImageFileName 返回 8.3 短名（如 PERFWAT~1.EXE），
 * 因此这里同时支持完整文件名和 8.3 短名前缀匹配。
 * ══════════════════════════════════════════════════════════════════════════ */

static BOOLEAN IsTrustedDeveloperToolLocal(const CHAR* name)
{
    CHAR lower[64];
    int i, j;
    const CHAR* devNames[] = {
        "devenv.exe", "msbuild.exe", "dotnet.exe", "vbcscompiler.exe",
        "vbc.exe", "csc.exe", "fsc.exe", "servicehub.host.exe",
        "servicehub.host.clr.exe", "vcpkgsrv.exe", "perfwatson2.exe",
        "perfwatson.exe", "vcxprojreader.exe", "cl.exe", "link.exe",
        "ml.exe", "rc.exe", "c1.dll", "c2.dll", "c1xx.dll",
        NULL
    };

    if (name == NULL || name[0] == '\0')
        return FALSE;

    for (i = 0; i < 63 && name[i] != '\0'; i++) {
        CHAR c = name[i];
        if (c >= 'A' && c <= 'Z')
            c += 32;
        lower[i] = c;
    }
    lower[i] = '\0';

    for (i = 0; devNames[i] != NULL; i++) {
        if (kStrCmp(lower, devNames[i]) == 0)
            return TRUE;

        // PsGetProcessImageFileName 最多返回 15 字符，长文件名会被截断。
        // 例如 perfwatson2.exe -> perfwatson2.ex，需按前 15 字符前缀匹配。
        if (kStrLen(lower) == 15 && kStrLen(devNames[i]) > 15 &&
            kStrNCmp(lower, devNames[i], 15) == 0)
            return TRUE;

        for (j = 0; lower[j] != '\0' && lower[j] != '~'; j++);
        if (lower[j] == '~' && j > 0) {
            INT dlen = j;
            if (kStrNCmp(lower, devNames[i], dlen) == 0)
                return TRUE;
        }
    }

    return FALSE;
}

/* ── 判断进程是否为受信任的安全软件 ──
 * 用于排除 360、Windows Defender 等安全产品正常操作被误判为注入。
 * 仅通过短名白名单识别，避免影响正常防护。 */
static BOOLEAN IsTrustedSecurityProductLocal(const CHAR* name)
{
    CHAR lower[64];
    int i, j;
    const CHAR* secNames[] = {
        "360tray.exe", "360rp.exe", "360sd.exe", "360safe.exe",
        "360se.exe", "360chrome.exe", "360hips.exe",
        "msmpeng.exe", "msascui.exe", "mpcmdrun.exe",
        "avp.exe", "avpui.exe", NULL
    };

    if (name == NULL || name[0] == '\0')
        return FALSE;

    for (i = 0; i < 63 && name[i] != '\0'; i++) {
        CHAR c = name[i];
        if (c >= 'A' && c <= 'Z')
            c += 32;
        lower[i] = c;
    }
    lower[i] = '\0';

    for (i = 0; secNames[i] != NULL; i++) {
        if (kStrCmp(lower, secNames[i]) == 0)
            return TRUE;

        // PsGetProcessImageFileName 最多返回 15 字符，长文件名会被截断。
        if (kStrLen(lower) == 15 && kStrLen(secNames[i]) > 15 &&
            kStrNCmp(lower, secNames[i], 15) == 0)
            return TRUE;

        for (j = 0; lower[j] != '\0' && lower[j] != '~'; j++);
        if (lower[j] == '~' && j > 0) {
            INT dlen = j;
            if (kStrNCmp(lower, secNames[i], dlen) == 0)
                return TRUE;
        }
    }

    return FALSE;
}

/* ── 手动声明 WDK 版本可能未导出的 APC 相关类型和函数 ── */

/* KAPC_ENVIRONMENT 枚举 */
#ifndef KAPC_ENVIRONMENT_DEFINED
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;
#define KAPC_ENVIRONMENT_DEFINED
#endif

/* 用户态 APC 回调函数类型 */
#ifndef PKNORMAL_ROUTINE_DEFINED
typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2);
#define PKNORMAL_ROUTINE_DEFINED
#endif

/* Kernel APC 回调函数类型 */
#ifndef PKKERNEL_ROUTINE_DEFINED
typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2);
#define PKKERNEL_ROUTINE_DEFINED
#endif

/* APC Rundown 回调函数类型 */
#ifndef PKRUNDOWN_ROUTINE_DEFINED
typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
    _In_ PKAPC Apc);
#define PKRUNDOWN_ROUTINE_DEFINED
#endif

/* ── 句柄层注入告警 work item 上下文 ──
 * ObRegisterCallbacks PreOperation 回调可能在 DISPATCH_LEVEL 执行，不能调用
 * 复杂/可分页函数。这里只记录原始句柄信息并排队 work item，由系统线程在
 * PASSIVE_LEVEL 完成进程名获取、系统进程/白名单/父子关系检查、行为记录和
 * 用户弹窗。 */
typedef struct _HANDLE_ALERT_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    INT64 sourcePid;
    INT64 targetPid;
    ACCESS_MASK access;
    BOOLEAN isThread;      /* FALSE=process handle, TRUE=thread handle */
    BOOLEAN isDuplicate;   /* TRUE=DuplicateHandle */
} HANDLE_ALERT_WORKITEM_CTX, *PHANDLE_ALERT_WORKITEM_CTX;

/* 前向声明 */
static VOID HandleAlertWorkItemRoutine(PVOID Context);

// 声明未导出的内核 API
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    SIZE_T* RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

// 初始化受保护 PID 列表
NTSTATUS InitializeProtectedPidsList()
{
    KeInitializeSpinLock(&g_ProtectedPids.Lock);
    g_ProtectedPids.Count = 0;
    RtlZeroMemory(g_ProtectedPids.Pids, sizeof(g_ProtectedPids.Pids));
    DriverDbgPrint("Process protection list initialized\n");
    return STATUS_SUCCESS;
}

// 清理受保护 PID 列表
VOID CleanupProtectedPidsList()
{
    // 如果进程回调句柄仍然有效，先注销
    if (g_ProcessRegistrationHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ProcessRegistrationHandle);
        g_ProcessRegistrationHandle = NULL;
        DriverDbgPrint("Process callback unregistered\n");
    }

    g_ProtectedPids.Count = 0;
    RtlZeroMemory(g_ProtectedPids.Pids, sizeof(g_ProtectedPids.Pids));
    DriverDbgPrint("Process protection list cleaned up\n");
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 已初始化进程 PID 跟踪（区分初始线程创建 vs 远程线程注入）
 *
 * 当 ThreadCreateNotifyRoutine 检测到父→子线程创建时，需要区分：
 *   1. 合法初始线程创建：父进程创建子进程时，子进程的第一个线程
 *   2. 恶意远程线程注入：父进程对已运行的子进程调用 CreateRemoteThread
 *
 * 通过 g_InitializedPids 集合跟踪已收到初始线程通知的进程 PID，
 * 首次出现时标记并放行，再次出现时判定为远程线程注入。
 * ══════════════════════════════════════════════════════════════════════════ */
INITIALIZED_PID_LIST g_InitializedPids;

VOID InitializeInitializedPidsList(VOID)
{
    KeInitializeSpinLock(&g_InitializedPids.Lock);
    g_InitializedPids.Count = 0;
    RtlZeroMemory(g_InitializedPids.Pids, sizeof(g_InitializedPids.Pids));
    DriverDbgPrint("Initialized PIDs tracking list initialized (max %d)\n", MAX_INITIALIZED_PIDS);
}

VOID CleanupInitializedPidsList(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_InitializedPids.Lock, &oldIrql);
    g_InitializedPids.Count = 0;
    RtlZeroMemory(g_InitializedPids.Pids, sizeof(g_InitializedPids.Pids));
    KeReleaseSpinLock(&g_InitializedPids.Lock, oldIrql);
    DriverDbgPrint("Initialized PIDs tracking list cleaned up\n");
}

/* 从已初始化 PID 列表中移除指定进程。
 * 进程退出时调用，防止 PID 复用后新进程被误判为已初始化。
 * 若 PID 复用后新进程首次创建线程，IsProcessInitialized 返回 TRUE
 * 会导致新进程的合法初始线程被误判为远程线程注入。 */
VOID RemoveProcessInitialized(HANDLE Pid)
{
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&g_InitializedPids.Lock, &oldIrql);
    for (i = 0; i < g_InitializedPids.Count; i++)
    {
        if (g_InitializedPids.Pids[i] == Pid)
        {
            /* 将最后一个元素移到当前位置，减少数据移动 */
            g_InitializedPids.Pids[i] = g_InitializedPids.Pids[g_InitializedPids.Count - 1];
            g_InitializedPids.Count--;
            break;
        }
    }
    KeReleaseSpinLock(&g_InitializedPids.Lock, oldIrql);
}

BOOLEAN IsProcessInitialized(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_InitializedPids.Lock, &oldIrql);
    for (ULONG i = 0; i < g_InitializedPids.Count; i++)
    {
        if (g_InitializedPids.Pids[i] == Pid)
        {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_InitializedPids.Lock, oldIrql);
    return found;
}

VOID MarkProcessInitialized(HANDLE Pid)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_InitializedPids.Lock, &oldIrql);

    /* 检查是否已存在 */
    for (ULONG i = 0; i < g_InitializedPids.Count; i++)
    {
        if (g_InitializedPids.Pids[i] == Pid)
        {
            KeReleaseSpinLock(&g_InitializedPids.Lock, oldIrql);
            return;
        }
    }

    /* 列表已满时淘汰最旧的条目（简单策略：替换第一个） */
    if (g_InitializedPids.Count >= MAX_INITIALIZED_PIDS)
    {
        for (ULONG i = 0; i < g_InitializedPids.Count - 1; i++)
        {
            g_InitializedPids.Pids[i] = g_InitializedPids.Pids[i + 1];
        }
        g_InitializedPids.Pids[g_InitializedPids.Count - 1] = Pid;
    }
    else
    {
        g_InitializedPids.Pids[g_InitializedPids.Count] = Pid;
        g_InitializedPids.Count++;
    }

    KeReleaseSpinLock(&g_InitializedPids.Lock, oldIrql);
}

// 检查 PID 是否在受保护列表中
BOOLEAN IsPidProtected(HANDLE Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_ProtectedPids.Lock, &oldIrql);

    for (ULONG i = 0; i < g_ProtectedPids.Count; i++)
    {
        if (g_ProtectedPids.Pids[i] == Pid)
        {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_ProtectedPids.Lock, oldIrql);
    return found;
}

// 添加 PID 到受保护列表
NTSTATUS AddPidToProtectedList(HANDLE Pid)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&g_ProtectedPids.Lock, &oldIrql);

    // 检查是否已存在
    for (ULONG i = 0; i < g_ProtectedPids.Count; i++)
    {
        if (g_ProtectedPids.Pids[i] == Pid)
        {
            DriverDbgPrint("PID %d already in protection list, skipping\n", (ULONG)(ULONG_PTR)Pid);
            status = STATUS_ALREADY_REGISTERED;
            goto Exit;
        }
    }

    // 检查列表是否已满
    if (g_ProtectedPids.Count >= MAX_PROTECTED_PIDS)
    {
        DriverDbgPrint("Process protection list full (max %d), cannot add PID %d\n", MAX_PROTECTED_PIDS, (ULONG)(ULONG_PTR)Pid);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    // 添加到列表末尾
    g_ProtectedPids.Pids[g_ProtectedPids.Count] = Pid;
    g_ProtectedPids.Count++;
    DriverDbgPrint("PID %d added to protection list (current %d/%d)\n", (ULONG)(ULONG_PTR)Pid, g_ProtectedPids.Count, MAX_PROTECTED_PIDS);

Exit:
    KeReleaseSpinLock(&g_ProtectedPids.Lock, oldIrql);
    return status;
}

// 从受保护列表中移除 PID
NTSTATUS RemovePidFromProtectedList(HANDLE Pid)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_NOT_FOUND;

    KeAcquireSpinLock(&g_ProtectedPids.Lock, &oldIrql);

    for (ULONG i = 0; i < g_ProtectedPids.Count; i++)
    {
        if (g_ProtectedPids.Pids[i] == Pid)
        {
            // 将后续元素前移
            for (ULONG j = i; j < g_ProtectedPids.Count - 1; j++)
            {
                g_ProtectedPids.Pids[j] = g_ProtectedPids.Pids[j + 1];
            }
            g_ProtectedPids.Pids[g_ProtectedPids.Count - 1] = NULL;
            g_ProtectedPids.Count--;
            status = STATUS_SUCCESS;
            DriverDbgPrint("PID %d removed from protection list (current %d/%d)\n", (ULONG)(ULONG_PTR)Pid, g_ProtectedPids.Count, MAX_PROTECTED_PIDS);
            break;
        }
    }

    if (status == STATUS_NOT_FOUND)
    {
        DriverDbgPrint("PID %d not in protection list, no removal needed\n", (ULONG)(ULONG_PTR)Pid);
    }

    KeReleaseSpinLock(&g_ProtectedPids.Lock, oldIrql);
    return status;
}

/* ── PoolParty Windows Thread Pool injection event recording ──
 * PoolParty uses 8 thread-pool abuse variants. From kernel mode we cannot see
 * the exact TP_* object being manipulated, but the cross-process handle
 * permissions requested by the attacker differ slightly between variants.
 *
 * 重构后设计：
 *   1. 所有可疑权限组合都记录到行为分析引擎（供画像综合评估）。
 *   2. 不再触发单指标实时告警：句柄层只静默剥离权限并记录事件，
 *      实时告警由线程层（PsSetCreateThreadNotifyRoutine）和行为分析画像
 *      负责，避免 OpenProcess 阶段误报。
 * 返回值：保留描述字符串供日志使用，但调用者不再用于弹窗告警。 */
static const CHAR* RecordPoolPartyMemoryEvent(
    INT64 srcPid, const CHAR* srcName,
    const CHAR* tgtName, INT64 tgtPid,
    ACCESS_MASK access,
    BOOLEAN isParentChild)
{
    BOOLEAN hasVMRead     = (access & 0x0010) != 0;  /* PROCESS_VM_READ */
    BOOLEAN hasVMWrite    = (access & 0x0020) != 0;  /* PROCESS_VM_WRITE */
    BOOLEAN hasVMOper     = (access & 0x0008) != 0;  /* PROCESS_VM_OPERATION */
    BOOLEAN hasCreateThrd = (access & 0x0002) != 0;  /* PROCESS_CREATE_THREAD */
    BOOLEAN hasDupHandle  = (access & 0x0040) != 0;  /* PROCESS_DUP_HANDLE */
    BOOLEAN hasQueryInfo  = (access & 0x0400) != 0;  /* PROCESS_QUERY_INFORMATION */
    BOOLEAN hasAllAccess  = (access == 0x1FFFFF) || (access == 0x1F0FFF);

    /* Phase 4: 简化为原子权限组合记录，取消 8 变体分类
     * 原因：内核层无法区分目标进程后续会操作哪种 Thread Pool 对象，
     * 变体分类是用户态语义推断，下沉到用户态 ETW TI 补充。 */

    /* 原子权限组合 1: VM_WRITE + VM_OPERATION (写入+操作权限) */
    if (hasVMWrite && hasVMOper) {
        BehaviorRecordMemoryEvent(srcPid, srcName, tgtName, tgtPid, access, BA_MOP_VMWriteVMOperate, isParentChild, NULL);
        return "VM_WRITE + VM_OPERATION atomic combination";
    }

    /* 原子权限组合 2: VM_OPERATION + CREATE_THREAD (操作+创建线程) */
    if (hasVMOper && hasCreateThrd) {
        BehaviorRecordMemoryEvent(srcPid, srcName, tgtName, tgtPid, access, BA_MOP_VMOperCreateThread, isParentChild, NULL);
        return "VM_OPERATION + CREATE_THREAD atomic combination";
    }

    /* 原子权限组合 3: VM_OPERATION + DUP_HANDLE (操作+复制句柄) */
    if (hasVMOper && hasDupHandle) {
        BehaviorRecordMemoryEvent(srcPid, srcName, tgtName, tgtPid, access, BA_MOP_VMOperDupHandle, isParentChild, NULL);
        return "VM_OPERATION + DUP_HANDLE atomic combination";
    }

    /* PoolParty 精确匹配: 0x0478 (VM_READ|VM_WRITE|VM_OPERATION|DUP_HANDLE|QUERY_INFO) */
    if (!hasAllAccess && hasVMRead && hasVMWrite && hasVMOper && hasDupHandle && hasQueryInfo) {
        BehaviorRecordMemoryEvent(srcPid, srcName, tgtName, tgtPid, access, BA_MOP_PoolParty_HandleRequest, isParentChild, NULL);
        DriverDbgPrint("[POOLPARTY] Matched exact mask 0x0478: %s -> %s\n",
            srcName ? srcName : "Unknown", tgtName ? tgtName : "Unknown");
        return "PoolParty suspicious handle request (0x0478)";
    }

    /* 兜底：全权限访问记录为通用注入指标 */
    if (hasAllAccess) {
        BehaviorRecordMemoryEvent(srcPid, srcName, tgtName, tgtPid, access, BA_MOP_VMWriteVMOperate, isParentChild, NULL);
        return NULL;
    }

    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * HandleAlertWorkItemRoutine — 句柄层注入告警 work item 回调
 *
 * 在 PASSIVE_LEVEL 系统线程中执行，完成 PreOperation 回调不能安全执行的
 * 操作：获取进程名、系统进程/白名单/父子关系检查、行为记录、用户弹窗。
 * ═══════════════════════════════════════════════════════════════════════════ */
static VOID HandleAlertWorkItemRoutine(PVOID Context)
{
    PHANDLE_ALERT_WORKITEM_CTX ctx = (PHANDLE_ALERT_WORKITEM_CTX)Context;
    CHAR srcName[64] = {0};
    CHAR tgtName[64] = {0};
    PEPROCESS srcProc = NULL;
    PEPROCESS tgtProc = NULL;
    BOOLEAN srcIsSystem = FALSE;
    BOOLEAN tgtIsSystem = FALSE;
    BOOLEAN isParentChild = FALSE;

    if (ctx == NULL) return;

    __try {
        /* 获取源进程名称与系统状态 */
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)ctx->sourcePid, &srcProc))) {
            UCHAR* name = PsGetProcessImageFileName(srcProc);
            if (name) {
                int i;
                for (i = 0; i < 15 && name[i]; i++)
                    srcName[i] = (CHAR)name[i];
                srcName[i] = '\0';
            }
            srcIsSystem = IsSystemProcessByEPROCESS(srcProc);
            ObDereferenceObject(srcProc);
            srcProc = NULL;
        }

        /* 获取目标进程名称、系统状态，并直接查询其继承父进程 PID。
         * 使用 PsGetProcessInheritedFromUniqueProcessId 比查询 g_baProcTree
         * 更可靠，避免句柄回调发生在 ProcessCreateNotifyRoutine 建立进程树
         * 之前的竞态，导致正常父子进程创建被误报为远程线程/ProcessHollowing。 */
        HANDLE targetInheritedParent = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)ctx->targetPid, &tgtProc))) {
            UCHAR* name = PsGetProcessImageFileName(tgtProc);
            if (name) {
                int i;
                for (i = 0; i < 15 && name[i]; i++)
                    tgtName[i] = (CHAR)name[i];
                tgtName[i] = '\0';
            }
            tgtIsSystem = IsSystemProcessByEPROCESS(tgtProc);
            targetInheritedParent = PsGetProcessInheritedFromUniqueProcessId(tgtProc);
            ObDereferenceObject(tgtProc);
            tgtProc = NULL;
        }

        /* 系统进程放行 */
        if (srcIsSystem) {
            DriverDbgPrint("[HANDLE-ALERT] Filtered: source is system process %s (PID:%lld)\n",
                srcName, ctx->sourcePid);
            goto Cleanup;
        }

        /* 受信任主程序 PID 放行（避免自身 R3 DLL 注入被误报） */
        if (g_TrustedMainPid != NULL &&
            (HANDLE)(ULONG_PTR)ctx->sourcePid == g_TrustedMainPid) {
            DriverDbgPrint("[HANDLE-ALERT] Filtered: source is trusted main PID:%lld\n",
                ctx->sourcePid);
            goto Cleanup;
        }

        /* 白名单放行 */
        if (WhitelistCheckByPid(ctx->sourcePid) == 1 ||
            WhitelistCheckByName(srcName) == 1) {
            DriverDbgPrint("[HANDLE-ALERT] Filtered: source %s (PID:%lld) is whitelisted\n",
                srcName, ctx->sourcePid);
            goto Cleanup;
        }

        /* 已知 Windows 系统组件放行 */
        if (srcName[0] != '\0' && IsKnownSystemProcessNameLocal(srcName)) {
            DriverDbgPrint("[HANDLE-ALERT] Filtered: source %s (PID:%lld) is known system component\n",
                srcName, ctx->sourcePid);
            goto Cleanup;
        }

        /* ── TrustedInstaller 句柄复制提权检测（T1134.003）──
         * 攻击者通过 DuplicateHandle 从 SYSTEM 进程（如 services.exe）复制句柄，
         * 获得 SYSTEM 权限上下文。典型手法：打开SYSTEM进程→DuplicateHandle→提升token。
         * 仅对非签名进程触发，签名系统工具（如 PsTools）正常放行。 */
        if (!ctx->isThread && ctx->isDuplicate && ctx->access & 0x0040) {  /* PROCESS_DUP_HANDLE */
            BOOLEAN srcSigned = BaIsProcessSigned(ctx->sourcePid);
            if (!srcSigned && tgtIsSystem) {
                CHAR evidence[256];
                RtlStringCbPrintfA(evidence, sizeof(evidence),
                    "TrustedInstaller提权: DuplicateHandle from SYSTEM %s(PID:%lld) by unsigned %s(PID:%lld)",
                    tgtName, ctx->targetPid, srcName, ctx->sourcePid);
                BehaviorRecordPrivilegeEscalationIndicator(
                    ctx->sourcePid, srcName, NULL,
                    BA_IND_PROC_TRUSTEDINSTALLER_DUP, evidence);
                goto Cleanup;
            }
        }

        /* 判断是否为正常父子进程创建；该信息需要记录到行为分析引擎中供
         * ProcessHollowing 指标使用，因此此处仅作标记，不直接过滤掉行为记录。
         * 实时注入告警仍会在下方跳过父子关系场景。
         * 同时使用进程树和 EPROCESS 继承父进程 PID 双重校验，消除竞态漏判。 */
        isParentChild = BehaviorIsLegitimateProcessCreation(ctx->targetPid, ctx->sourcePid);
        if (!isParentChild && targetInheritedParent != NULL &&
            (INT64)(ULONG_PTR)targetInheritedParent == ctx->sourcePid) {
            isParentChild = TRUE;
        }
        if (isParentChild) {
            DriverDbgPrint("[HANDLE-ALERT] Parent-child relation detected: source PID:%lld -> target PID:%lld (recorded for behavior analysis)\n",
                ctx->sourcePid, ctx->targetPid);
        }

        /* 多进程浏览器/应用内部通信：目标虽非源进程直接子进程，但若目标最近创建
         * 且其进程树中的父进程与源进程同镜像（如 msedge.exe 打开由兄弟 msedge.exe
         * 创建的 identity_helper.exe），则视为合法家族进程通信，跳过实时告警。 */
        if (!isParentChild && !tgtIsSystem) {
            if (BehaviorIsRecentSameFamilyProcess(ctx->sourcePid, ctx->targetPid)) {
                isParentChild = TRUE;
                DriverDbgPrint("[HANDLE-ALERT] Same-family process detected: source PID:%lld -> target PID:%lld (recent helper), skipping alert\n",
                    ctx->sourcePid, ctx->targetPid);
            }
        }

        /* 目标为系统关键进程时：仍记录行为分析指标（供 ProcessHollowing 等画像
         * 综合判断），但跳过实时弹窗，避免合法程序访问 csrss/lsass 时轰炸用户。 */
        if (tgtIsSystem) {
            DriverDbgPrint("[HANDLE-ALERT] Target %s (PID:%lld) is system process, recording behavior only\n",
                tgtName, ctx->targetPid);
        }

        if (!ctx->isThread) {
            /* 进程句柄：记录跨进程内存操作指标（含父子关系信息，
             * 供 ProcessHollowing 等画像精确判断） */
            BehaviorRecordMemoryEvent(
                ctx->sourcePid, srcName,
                tgtName, ctx->targetPid,
                (INT64)ctx->access,
                ctx->isDuplicate ? BA_MOP_HandleDuplicate : BA_MOP_HandleCreate,
                isParentChild,
                NULL);

            /* PoolParty 线程池注入指标 */
            RecordPoolPartyMemoryEvent(
                ctx->sourcePid, srcName,
                tgtName, ctx->targetPid,
                ctx->access,
                isParentChild);

            /* 句柄层不再触发实时注入告警！
             *
             * OpenProcess 带有 VM_WRITE/CREATE_THREAD 等权限位不等于实际发生了
             * 注入操作（WriteVirtualMemory/CreateRemoteThread）。仅凭 access mask
             * 触发告警会导致大量误报（如 notepad 经 OLE/DDE 打开带宽权限句柄）。
             *
             * 正确的告警路径：
             *   1. 线程层 PsSetCreateThreadNotifyRoutine：实际 CreateRemoteThread
             *      创建时触发（注入的确凿信号）
             *   2. 行为分析画像：多指标累计达阈值后触发
             *
             * 句柄层只负责记录行为事件（上面的 BehaviorRecordMemoryEvent /
             * RecordPoolPartyMemoryEvent），供画像综合判断。 */
        } else {
            /* 线程句柄：同样不在句柄层触发实时告警。
             * OpenThread 带 THREAD_SET_CONTEXT/THREAD_SUSPEND_RESUME 不等于实际
             * 发生了 SetThreadContext/线程劫持。实际操作由
             * PsSetCreateThreadNotifyRoutine 捕获远程线程创建时触发告警。 */
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[HANDLE-ALERT] Exception caught in HandleAlertWorkItemRoutine\n");
    }

Cleanup:
    if (srcProc) ObDereferenceObject(srcProc);
    if (tgtProc) ObDereferenceObject(tgtProc);
    ExFreePool(ctx);
}

// 进程保护回调（ObRegisterCallbacks PreOperation 回调）
OB_PREOP_CALLBACK_STATUS NTAPI HandleProcessProtectCallBack(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    /* ObRegisterCallbacks 触发频繁且对象状态可能不稳定，用 SEH 保护
     * 防止访问未初始化对象字段导致蓝屏。 */
    __try
    {

    /* 仅处理 PsProcessType 对象 */
    if (OperationInformation->ObjectType != *PsProcessType)
    {
        return OB_PREOP_SUCCESS;
    }

    PEPROCESS targetProcess = (PEPROCESS)OperationInformation->Object;
    HANDLE targetPid = PsGetProcessId(targetProcess);
    HANDLE sourcePid = PsGetCurrentProcessId();

    /* 跳过 System/Kernel (PID 0/4) */
    if ((ULONG)(ULONG_PTR)sourcePid <= 4 || (ULONG)(ULONG_PTR)targetPid <= 4)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 自身操作：记录 BA_IND_MEM_SELF_VM_OPERATION_OPEN 行为事件
     * 进程对自身打开 PROCESS_VM_OPERATION 句柄是 NtProtectVirtualMemory
     * 修改自身内存保护（RW→RX）的前置条件。在 work item 中记录到行为分析。 */
    if (sourcePid == targetPid)
    {
        ACCESS_MASK selfAccess = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
            ? OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
            : OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

        /* 仅当请求包含 PROCESS_VM_OPERATION 时才记录 */
        if ((selfAccess & 0x0008) != 0 && g_bMemoryProtectionEnabled)
        {
            PHANDLE_ALERT_WORKITEM_CTX selfCtx = (PHANDLE_ALERT_WORKITEM_CTX)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(HANDLE_ALERT_WORKITEM_CTX), 'hdAW');
            if (selfCtx != NULL)
            {
                RtlZeroMemory(selfCtx, sizeof(HANDLE_ALERT_WORKITEM_CTX));
                selfCtx->sourcePid = (INT64)(ULONG_PTR)sourcePid;
                selfCtx->targetPid = (INT64)(ULONG_PTR)targetPid;
                selfCtx->access = selfAccess;
                selfCtx->isThread = FALSE;
                selfCtx->isDuplicate = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE);
                ExInitializeWorkItem(&selfCtx->WorkItem, HandleAlertWorkItemRoutine, selfCtx);
                ExQueueWorkItem(&selfCtx->WorkItem, DelayedWorkQueue);
            }
        }
        return OB_PREOP_SUCCESS;
    }

    /* 仅处理句柄创建/复制 */
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInformation->Operation != OB_OPERATION_HANDLE_DUPLICATE)
    {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK originalAccess = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        ? OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
        : OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

    /* 内存防护关闭时：不剥离权限、不排队告警 work item */
    if (!g_bMemoryProtectionEnabled)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 只对有注入相关权限的跨进程句柄排队 work item，减少不必要开销 */
    BOOLEAN hasVMWrite    = (originalAccess & 0x0020) != 0;  /* PROCESS_VM_WRITE */
    BOOLEAN hasVMOper     = (originalAccess & 0x0008) != 0;  /* PROCESS_VM_OPERATION */
    BOOLEAN hasCreateThrd = (originalAccess & 0x0002) != 0;  /* PROCESS_CREATE_THREAD */
    BOOLEAN hasDupHandle  = (originalAccess & 0x0040) != 0;  /* PROCESS_DUP_HANDLE */
    BOOLEAN hasSetInfo    = (originalAccess & 0x0200) != 0;  /* PROCESS_SET_INFORMATION */
    BOOLEAN hasSuspend    = (originalAccess & 0x0800) != 0;  /* PROCESS_SUSPEND_RESUME */
    BOOLEAN hasCreateProc = (originalAccess & 0x0080) != 0;  /* PROCESS_CREATE_PROCESS */
    BOOLEAN hasQueryInfo  = (originalAccess & 0x0400) != 0;  /* PROCESS_QUERY_INFORMATION */

    if (!hasVMWrite && !hasVMOper && !hasCreateThrd && !hasDupHandle &&
        !hasSetInfo && !hasSuspend && !hasCreateProc && !hasQueryInfo)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 在 PreOperation 中只分配 NONPAGED 内存并排队 work item。
     * 所有字符串处理、系统进程/白名单/父子判断、行为记录和用户弹窗
     * 都移到 PASSIVE_LEVEL 的 work item 中执行，避免 DISPATCH_LEVEL
     * 调用可分页代码导致 IRQL_LESS_OR_EQUAL 蓝屏。 */
    PHANDLE_ALERT_WORKITEM_CTX ctx = (PHANDLE_ALERT_WORKITEM_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(HANDLE_ALERT_WORKITEM_CTX), 'hdAW');
    if (ctx == NULL)
    {
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(ctx, sizeof(HANDLE_ALERT_WORKITEM_CTX));
    ctx->sourcePid = (INT64)(ULONG_PTR)sourcePid;
    ctx->targetPid = (INT64)(ULONG_PTR)targetPid;
    ctx->access = originalAccess;
    ctx->isThread = FALSE;
    ctx->isDuplicate = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE);

    ExInitializeWorkItem(&ctx->WorkItem, HandleAlertWorkItemRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);

    /* ═══════════════════════════════════════════════════════════════════
     * 自保护进程检测：当目标进程在 g_ProtectedPids 中（如 injector32、
     * mainUI、servicemain 等），且源进程不是自保护进程也不是系统进程
     * 时，剥离高危权限以阻挡外部进程终止/修改/注入自保护进程。
     *
     * 自保护进程之间可以互相访问（如 mainUI 打开 servicemain），
     * 系统进程（PID <= 4）和受信任主程序（g_TrustedMainPid）也放行。 */
    if (IsPidProtected(targetPid) &&
        !IsPidProtected(sourcePid) &&
        (ULONG)(ULONG_PTR)sourcePid > 4 &&
        (g_TrustedMainPid == NULL || sourcePid != g_TrustedMainPid))
    {
        /* 定义高危权限掩码：终止/读写内存/创建线程/挂起/设置信息/复制句柄/创建进程 */
        ACCESS_MASK dangerousMask =
            0x0001  |  /* PROCESS_TERMINATE */
            0x0002  |  /* PROCESS_CREATE_THREAD */
            0x0008  |  /* PROCESS_VM_OPERATION */
            0x0010  |  /* PROCESS_VM_READ */
            0x0020  |  /* PROCESS_VM_WRITE */
            0x0040  |  /* PROCESS_DUP_HANDLE */
            0x0080  |  /* PROCESS_CREATE_PROCESS */
            0x0200  |  /* PROCESS_SET_INFORMATION */
            0x0800;    /* PROCESS_SUSPEND_RESUME */

        ACCESS_MASK newAccess = originalAccess & ~dangerousMask;

        if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        {
            OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = newAccess;
        }
        else
        {
            OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = newAccess;
        }

        DriverDbgPrint("[OB-PROTECT] Stripped permissions for PID %lu -> %lu (protected): 0x%X -> 0x%X\n",
            (ULONG)(ULONG_PTR)sourcePid, (ULONG)(ULONG_PTR)targetPid,
            originalAccess, newAccess);
    }

    /* ═══════════════════════════════════════════════════════════════════
     * 句柄层不剥离注入相关权限。
     *
     * 原因：请求 PROCESS_CREATE_THREAD 权限 ≠ 实际注入行为。大量合法程序
     * （调试器、csrss、任务管理器、系统服务等）都会请求此权限，无条件剥离
     * 会导致严重误报和系统功能异常（如"连接到系统上的设备没有发挥作用"错误）。
     *
     * 注入检测应交给行为分析层：
     *   - 句柄层：仅排队 work item 记录事件（上方已完成）
     *   - 线程层：PsSetCreateThreadNotifyRoutine 检测真实远程线程创建
     *   - 行为层：BehaviorAnalysis 定时器动态分析注入链
     *
     * 参见项目约束：
     *   - PoolParty injection detection must use pure dynamic behavior analysis
     *   - Process object callbacks must not strip injection-related permissions
     * ═══════════════════════════════════════════════════════════════════ */

    return OB_PREOP_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[OB-PROCESS] Exception caught in HandleProcessProtectCallBack, allowing\n");
        return OB_PREOP_SUCCESS;
    }
}

// ============================================================================
// HandleThreadProtectCallBack — 线程对象保护回调
//
// 拦截跨进程线程操作，防止线程劫持注入：
//   THREAD_SET_CONTEXT  (0x0010) — SetThreadContext (T1055.003/012)
//   THREAD_SUSPEND_RESUME (0x0002) — SuspendThread/ResumeThread (T1055.003/012)
//   THREAD_SET_INFORMATION (0x0020) — SetThreadInformation
//   THREAD_DIRECT_IMPERSONATION (0x0100) — 模拟令牌窃取
//
// 重构后：不再在回调中同步剥离权限，而是把可疑句柄信息排队到 work item，
// 在 PASSIVE_LEVEL 系统线程中完成过滤与弹窗，避免 DISPATCH_LEVEL 蓝屏。
// ============================================================================
OB_PREOP_CALLBACK_STATUS NTAPI HandleThreadProtectCallBack(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    /* 线程对象回调可能访问未完全初始化的线程/进程对象，用 SEH 保护。 */
    __try
    {

    UNREFERENCED_PARAMETER(RegistrationContext);

    /* 仅处理 PsThreadType 对象 */
    if (OperationInformation->ObjectType != *PsThreadType)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 获取线程所属进程 */
    PEPROCESS targetProcess = IoThreadToProcess(OperationInformation->Object);
    HANDLE targetPid = PsGetProcessId(targetProcess);
    HANDLE sourcePid = PsGetCurrentProcessId();

    /* 自身线程操作不拦截（进程操作自己的线程是正常行为） */
    if (sourcePid == targetPid)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 跳过 PID 0/4 (System/Kernel) */
    if ((ULONG)(ULONG_PTR)sourcePid <= 4 || (ULONG)(ULONG_PTR)targetPid <= 4)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 仅处理句柄创建/复制 */
    if (OperationInformation->Operation != OB_OPERATION_HANDLE_CREATE &&
        OperationInformation->Operation != OB_OPERATION_HANDLE_DUPLICATE)
    {
        return OB_PREOP_SUCCESS;
    }

    ACCESS_MASK originalAccess = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
        ? OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess
        : OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

    /* 内存防护关闭时：不排队告警 work item */
    if (!g_bMemoryProtectionEnabled)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 线程注入相关权限标志：
     *   THREAD_SET_CONTEXT     (0x0010)
     *   THREAD_SUSPEND_RESUME  (0x0002)
     *   THREAD_SET_INFORMATION (0x0020)
     *   THREAD_DIRECT_IMPERSONATION (0x0100) */
    BOOLEAN hasSetContext  = (originalAccess & 0x0010) != 0;
    BOOLEAN hasSuspend     = (originalAccess & 0x0002) != 0;
    BOOLEAN hasSetInfo     = (originalAccess & 0x0020) != 0;
    BOOLEAN hasImpersonate = (originalAccess & 0x0100) != 0;

    if (!hasSetContext && !hasSuspend && !hasSetInfo && !hasImpersonate)
    {
        return OB_PREOP_SUCCESS;
    }

    /* 排队到 PASSIVE_LEVEL work item 做进一步判断与弹窗 */
    PHANDLE_ALERT_WORKITEM_CTX ctx = (PHANDLE_ALERT_WORKITEM_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(HANDLE_ALERT_WORKITEM_CTX), 'hdAW');
    if (ctx == NULL)
    {
        return OB_PREOP_SUCCESS;
    }

    RtlZeroMemory(ctx, sizeof(HANDLE_ALERT_WORKITEM_CTX));
    ctx->sourcePid = (INT64)(ULONG_PTR)sourcePid;
    ctx->targetPid = (INT64)(ULONG_PTR)targetPid;
    ctx->access = originalAccess;
    ctx->isThread = TRUE;
    ctx->isDuplicate = (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE);

    ExInitializeWorkItem(&ctx->WorkItem, HandleAlertWorkItemRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);

    return OB_PREOP_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[OB-THREAD] Exception caught in HandleThreadProtectCallBack, allowing\n");
        return OB_PREOP_SUCCESS;
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ThreadCreateNotifyRoutine — 线程创建通知回调（重构后：主要实时告警源）
 *
 * 检测远程线程创建（CreateRemoteThread / NtCreateThreadEx 跨进程注入）
 *
 * 原理：当线程创建回调被调用时，它在创建线程的进程上下文中执行。
 * 通过 PsGetCurrentProcessId() 获取发起创建的进程 PID，
 * 与目标进程 PID（ProcessId参数）对比：
 *   - 相同 → 正常线程创建（进程内）
 *   - 不同 → 远程线程创建，是注入的实际证据
 *
 * 生产级 EDR 策略（重构后）：
 *   1) 源==目标：正常，放行。
 *   2) 源是目标父进程：新进程初始线程创建，放行（避免蓝屏/误报）。
 *   3) 系统进程 -> 任意进程：Windows 正常机制，放行。
 *   4) 受信任主程序 PID -> 任意进程：自身 R3 DLL 注入，放行。
 *   5) 白名单/已知系统组件：放行。
 *   6) 其他非系统进程 -> 任意进程：触发实时告警并挂起源进程。
 *
 * 与 ObRegisterCallbacks 形成分层：
 *   - ObRegisterCallbacks：句柄层仅记录可疑句柄事件并触发异步告警，不再静默
 *     剥离权限；避免 DISPATCH_LEVEL 下执行复杂过滤/弹窗导致 IRQL 蓝屏。
 *   - ThreadCreateNotify：线程层捕获实际远程线程创建，作为弹窗证据
 * ══════════════════════════════════════════════════════════════════════════ */
VOID NTAPI ThreadCreateNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create)
{
    /* 仅处理线程创建事件 */
    if (!Create)
        return;

    /* 内存防护关闭时：不检测远程线程注入 */
    if (!g_bMemoryProtectionEnabled)
        return;

    /* 线程创建回调触发时线程对象可能尚未完全初始化，用 SEH 保护，
     * 避免访问未初始化字段导致 PAGE_FAULT_IN_NONPAGED_AREA。 */
    __try {

    /* 获取当前进程（创建线程的进程） */
    HANDLE currentProcessId = PsGetCurrentProcessId();

    DriverDbgPrint("[THREAD-NOTIFY] Thread create event: SourcePID=%d TargetPID=%d\n",
        (ULONG)(ULONG_PTR)currentProcessId,
        (ULONG)(ULONG_PTR)ProcessId);

    /* 排除系统进程（PID 0/4） */
    if ((ULONG)(ULONG_PTR)currentProcessId <= 4 ||
        (ULONG)(ULONG_PTR)ProcessId <= 4)
    {
        DriverDbgPrint("[THREAD-NOTIFY] Skipped: system process involved (PID<=4)\n");
        return;
    }

    /* 同一进程内创建线程 → 正常操作，跳过 */
    if (currentProcessId == ProcessId)
    {
        DriverDbgPrint("[THREAD-NOTIFY] Skipped: same process\n");
        return;
    }

    /* 排除正常进程创建的初始线程通知：父进程创建子进程时，
     * PsSetCreateThreadNotifyRoutine 会先触发子进程初始线程创建
     * （currentProcessId==父进程，ProcessId==子进程）。此时子线程尚未初始化
     * 完成，直接挂起会导致 PAGE_FAULT_IN_NONPAGED_AREA。
     *
     * 通过 g_InitializedPids 集合区分：
     *   - 首次出现：合法初始线程创建 → 标记并放行
     *   - 再次出现：远程线程注入（CreateRemoteThread）→ 继续告警流程 */
    {
        PEPROCESS targetProc = NULL;
        BOOLEAN isParentChild = FALSE;

        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &targetProc)) && targetProc)
        {
            HANDLE parentPid = PsGetProcessInheritedFromUniqueProcessId(targetProc);
            ObDereferenceObject(targetProc);

            if (parentPid == currentProcessId)
            {
                isParentChild = TRUE;
            }
        }

        if (!isParentChild)
        {
            isParentChild = BehaviorIsLegitimateProcessCreation(
                (INT64)(ULONG_PTR)ProcessId,
                (INT64)(ULONG_PTR)currentProcessId);
        }

        if (isParentChild)
        {
            /* 父→子线程创建：检查子进程是否已初始化 */
            if (!IsProcessInitialized(ProcessId))
            {
                /* 首次：合法初始线程创建，标记并放行 */
                MarkProcessInitialized(ProcessId);
                DriverDbgPrint("[THREAD-NOTIFY] Initial thread for PID=%d (parent PID=%d), marked as initialized\n",
                    (ULONG)(ULONG_PTR)ProcessId, (ULONG)(ULONG_PTR)currentProcessId);
                return;
            }
            /* 子进程已初始化，父进程再次创建线程 = 远程线程注入，
             * 不 return，继续走下方告警流程 */
            DriverDbgPrint("[THREAD-NOTIFY] Remote thread injection: parent PID=%d -> child PID=%d (already initialized)\n",
                (ULONG)(ULONG_PTR)currentProcessId, (ULONG)(ULONG_PTR)ProcessId);
        }
    }

    /* 获取源进程和目标进程名称及源进程系统状态 */
    CHAR sourceName[16] = "Unknown";
    CHAR targetName[16] = "Unknown";
    BOOLEAN srcIsSystem = FALSE;
    {
        PEPROCESS srcProc = NULL, tgtProc = NULL;
        NTSTATUS s;

        s = PsLookupProcessByProcessId(currentProcessId, &srcProc);
        if (NT_SUCCESS(s))
        {
            UCHAR* name = PsGetProcessImageFileName(srcProc);
            if (name)
            {
                int i;
                for (i = 0; i < 15 && name[i]; i++)
                    sourceName[i] = (CHAR)name[i];
                sourceName[i] = '\0';
            }
            srcIsSystem = IsSystemProcessByEPROCESS(srcProc);
        }

        s = PsLookupProcessByProcessId(ProcessId, &tgtProc);
        if (NT_SUCCESS(s))
        {
            UCHAR* name = PsGetProcessImageFileName(tgtProc);
            if (name)
            {
                int i;
                for (i = 0; i < 15 && name[i]; i++)
                    targetName[i] = (CHAR)name[i];
                targetName[i] = '\0';
            }
        }

        if (srcProc) ObDereferenceObject(srcProc);
        if (tgtProc) ObDereferenceObject(tgtProc);
    }

    /* 远程线程创建源进程策略（重构后：线程层是主要实时告警源）
     *   系统进程 -> 任意进程   : 放行（Windows 正常机制）
     *   非系统进程 -> 任意进程 : 实时告警（实际发生跨进程线程创建，是注入的直接证据）
     * 使用 SID 判定系统进程，比短名匹配更可靠。
     *
     * 句柄层只静默剥离权限并记录事件，不弹窗；线程层在实际
     * CreateRemoteThread / NtCreateThreadEx 发生时触发告警，误报率最低。 */
    if (srcIsSystem)
    {
        DriverDbgPrint("[THREAD-CREATE] Source is system process, allowed: %s -> %s\n",
            sourceName, targetName);
        return;
    }

    /* 受信任主程序自身的 CreateRemoteThread（R3 DLL 注入）放行 */
    if (g_TrustedMainPid != NULL &&
        (HANDLE)(ULONG_PTR)currentProcessId == g_TrustedMainPid)
    {
        DriverDbgPrint("[THREAD-CREATE] Source is trusted main process, allowed: %s -> %s\n",
            sourceName, targetName);
        return;
    }

    /* 白名单放行 */
    if (WhitelistCheckByPid((INT64)(ULONG_PTR)currentProcessId) == 1 ||
        WhitelistCheckByName(sourceName) == 1)
    {
        DriverDbgPrint("[THREAD-CREATE] Source is whitelisted, allowed: %s -> %s\n",
            sourceName, targetName);
        return;
    }

    /* 放行 Windows 系统组件发起的远程线程创建（如系统服务辅助线程、
     * 任务调度等），减少误报。 */
    if (sourceName[0] != '\0' && IsKnownSystemProcessNameLocal(sourceName))
    {
        DriverDbgPrint("[THREAD-CREATE] Source is known Windows component, allowed: %s -> %s\n",
            sourceName, targetName);
        return;
    }

    /* 受信任的开发者工具/安全软件放行，避免 Visual Studio、360 等合法工具
     * 的正常线程操作被误判为注入。 */
    if (IsTrustedDeveloperToolLocal(sourceName) || IsTrustedSecurityProductLocal(sourceName))
    {
        DriverDbgPrint("[THREAD-CREATE] Source is trusted developer tool/security product, allowed: %s -> %s\n",
            sourceName, targetName);
        return;
    }

    DriverDbgPrint("[THREAD-INJECT] Remote thread detected!\n"
        "  Source: %s (PID:%d) -> Target: %s (PID:%d)\n",
        sourceName, (ULONG)(ULONG_PTR)currentProcessId,
        targetName, (ULONG)(ULONG_PTR)ProcessId);

    /* 不在回调中直接挂起目标线程：PsSetCreateThreadNotifyRoutine 触发时线程
     * 尚未完成初始化，此时 ZwSuspendThread 极易访问未初始化的 KTHREAD/ETHREAD
     * 字段，导致 PAGE_FAULT_IN_NONPAGED_AREA。这里仅记录并交由异步 work item
     * 挂起源进程、等待用户决策。 */
    /* CreateRemoteThread / NtCreateThreadEx 始终通过注入告警流程触发弹窗，
     * 不受行为分析开关控制。 */

    /* ── 获取线程起始地址（shellcode 注入检测）──
     * 参考 Elastic Security shellcode thread 检测策略：
     * 远程线程起始地址不在任何已加载 DLL/EXE 范围内 = shellcode 注入。
     * 通过 PsGetThreadStartAddress 获取起始地址，
     * 记录到行为事件供 BehaviorExtractMemoryIndicators 分析。 */
    {
        PETHREAD remoteThread = NULL;
        PVOID threadStartAddr = NULL;

        NTSTATUS lookupStatus = PsLookupThreadByThreadId(ThreadId, &remoteThread);
        if (NT_SUCCESS(lookupStatus) && remoteThread != NULL)
        {
            /* 【核心改动】：摒弃 ObOpenObjectByPointer，直接利用 PETHREAD 结构体指针查询 */
            /* 参数 2: 传入 NULL 表示使用当前进程的句柄表（内核模式会直接处理），无需打开句柄 */
            NTSTATUS qsStatus = ZwQueryInformationThread(
                remoteThread,                       // 直接传入 PETHREAD 指针
                (THREADINFOCLASS)ThreadQuerySetWin32StartAddress,
                &threadStartAddr,
                sizeof(PVOID),
                NULL
            );

            if (NT_SUCCESS(qsStatus) && threadStartAddr != NULL)
            {
                DriverDbgPrint("[THREAD-INJECT] Remote thread start address: 0x%p\n",
                    threadStartAddr);
            }

            /* 注意：要释放通过 PsLookupThreadByThreadId 获取的引用 */
            ObDereferenceObject(remoteThread);
        }

        /* 记录远程线程创建事件（含起始地址），供行为分析引擎综合研判 */
        BehaviorRecordMemoryEvent(
            (INT64)(ULONG_PTR)currentProcessId, sourceName,
            targetName, (INT64)(ULONG_PTR)ProcessId, 0,
            BA_MOP_RemoteThreadUnbacked,
            FALSE,               /* isParentChild — 非父子关系，已在上层排除 */
            threadStartAddr);    /* 线程起始地址 */
    }

    BehaviorHandleInjectionAlertAsync(
        (INT64)(ULONG_PTR)currentProcessId, sourceName,
        (INT64)(ULONG_PTR)ProcessId, targetName,
        "DefenseEvasion/Injection:CreateRemoteThread.T1055.002",
        (INT64)(ULONG_PTR)ThreadId,
        threadStartAddr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[THREAD-CREATE] Exception caught in ThreadCreateNotifyRoutine, skipping\n");
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * FindExportByName — 在 PE 镜像中按名称查找导出函数
 *
 * 通用 PE 导出表解析，用于在 ntdll.dll 加载时获取 LdrLoadDll 地址。
 * 同一系统 DLL 在同一引导会话中所有进程通常加载到相同基址，
 * 因此从通知回调中获取的地址在目标进程中同样有效。
 * ══════════════════════════════════════════════════════════════════════════ */
PVOID FindExportByName(PVOID ImageBase, PCSTR FunctionName)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    IMAGE_DATA_DIRECTORY exportDir;
    PIMAGE_EXPORT_DIRECTORY exports;
    PULONG nameTable;
    PUSHORT ordinalTable;
    PULONG funcTable;
    ULONG i;

    if (!ImageBase || !FunctionName)
        return NULL;

    /* PE 解析可能访问无效内存（镜像部分映射、损坏的 PE 头等），
     * 使用 __try/__except 防止蓝屏 */
    __try {
        dosHeader = (PIMAGE_DOS_HEADER)ImageBase;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return NULL;

        /* e_lfanew 可能指向越界地址，需验证 */
        ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)ImageBase + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            return NULL;

        exportDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exportDir.VirtualAddress == 0 || exportDir.Size == 0)
            return NULL;

        exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ImageBase + exportDir.VirtualAddress);
        nameTable = (PULONG)((PUCHAR)ImageBase + exports->AddressOfNames);
        ordinalTable = (PUSHORT)((PUCHAR)ImageBase + exports->AddressOfNameOrdinals);
        funcTable = (PULONG)((PUCHAR)ImageBase + exports->AddressOfFunctions);

        for (i = 0; i < exports->NumberOfNames; i++)
        {
            PCSTR name = (PCSTR)((PUCHAR)ImageBase + nameTable[i]);
            if (_stricmp(name, FunctionName) == 0)
            {
                return (PVOID)((PUCHAR)ImageBase + funcTable[ordinalTable[i]]);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return NULL;
    }

    return NULL;
}
/*═══════════════════════════════════════════════════════════════════════════
 *  DetectDllLoadViaRop - 检测 ROP 加载 DLL (改进版，降低误报)
 *═══════════════════════════════════════════════════════════════════════════*/
static BOOLEAN DetectDllLoadViaRop(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING FullImageName)
{
    NTSTATUS status;
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    PEPROCESS currentProcess = PsGetCurrentProcess();
    PVOID callers[32] = { 0 };
    ULONG frames = 0;
    ULONG i;
    CHAR procNameA[16] = { 0 };
    ANSI_STRING dllPathA = { 0 };
    BOOLEAN bRopDetected = FALSE;
    ULONG validFrames = 0;          // 新增：有效查询帧计数
    ULONG imageFrameCount = 0;      // MEM_IMAGE 帧计数
    ULONG privateExecCount = 0;     // RWX 私有内存帧计数

    // 跳过系统进程
    if (pid <= 4)
        return FALSE;

    // 获取进程名
    UCHAR* shortName = PsGetProcessImageFileName(currentProcess);
    if (shortName)
        RtlStringCbCopyA(procNameA, sizeof(procNameA), (PCHAR)shortName);

    // 转换 DLL 路径（用于日志）
    if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
        status = RtlUnicodeStringToAnsiString(&dllPathA, FullImageName, TRUE);
        if (!NT_SUCCESS(status))
            RtlInitAnsiString(&dllPathA, "");
    }
    else {
        RtlInitAnsiString(&dllPathA, "");
    }

    // ---- 白名单：系统 DLL 路径 ----
    if (FullImageName && FullImageName->Buffer) {
        // 原有系统路径
        if (wcsstr(FullImageName->Buffer, L"\\Windows\\System32\\") ||
            wcsstr(FullImageName->Buffer, L"\\Windows\\SysWOW64\\") ||
            // 新增：WinSxS 和 .NET 框架路径
            wcsstr(FullImageName->Buffer, L"\\Windows\\WinSxS\\") ||
            wcsstr(FullImageName->Buffer, L"\\Windows\\Microsoft.NET\\Framework\\") ||
            wcsstr(FullImageName->Buffer, L"\\Windows\\Microsoft.NET\\Framework64\\")) {
            goto Cleanup;
        }

        // 新增：核心系统 DLL 直接放行（如 ntdll、kernel32 等）
        if (wcsstr(FullImageName->Buffer, L"\\ntdll.dll") ||
            wcsstr(FullImageName->Buffer, L"\\kernel32.dll") ||
            wcsstr(FullImageName->Buffer, L"\\kernelbase.dll") ||
            wcsstr(FullImageName->Buffer, L"\\user32.dll") ||
            wcsstr(FullImageName->Buffer, L"\\gdi32.dll")) {
            goto Cleanup;
        }
    }

    // ---- 获取用户态调用栈 ----
    __try {
        frames = RtlWalkFrameChain(callers, RTL_NUMBER_OF(callers), 1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        frames = 0;
    }

    if (frames == 0)
        goto Cleanup;   // 无栈帧，放行（无法判定）

    // ---- 遍历栈帧，寻找 MEM_IMAGE 并统计有效帧 ----
    for (i = 0; i < frames; i++) {
        PVOID retAddr = callers[i];
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        SIZE_T retLen = 0;
        NTSTATUS qs;

        if (!retAddr)
            continue;

        // 只处理用户态地址
        if ((ULONG_PTR)retAddr > (ULONG_PTR)MmHighestUserAddress)
            continue;

        // 查询内存类型
        __try {
            qs = ZwQueryVirtualMemory(
                ZwCurrentProcess(),
                retAddr,
                MemoryBasicInformation,
                &mbi,
                sizeof(mbi),
                &retLen);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            qs = STATUS_UNSUCCESSFUL;
        }

        if (!NT_SUCCESS(qs))
            continue;

        validFrames++;   // 成功查询到 MBI 的帧计数

        // Phase 4: 统计 MEM_IMAGE 帧和 RWX 帧
        if (mbi.Type == MEM_IMAGE) {
            imageFrameCount++;
            goto Cleanup;  // 找到合法镜像帧 → 正常调用，放行
        }
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
            // RWX 内存（非 MEM_IMAGE）— ROP 的典型特征
            privateExecCount++;
        }
        // 否则继续检查下一个帧
    }

    // ---- 新增容错：有效帧数量不足或比例过低，认为回溯不可靠，放行 ----
    if (validFrames < 3) {
        // 有效帧少于3个，可能回溯不全，放行
        goto Cleanup;
    }
    if ((validFrames * 100 / frames) < 50) {
        // 有效帧比例低于50%，同样放行
        goto Cleanup;
    }

    // ---- 执行至此，说明栈中没有任何 MEM_IMAGE 返回地址，判定为 ROP ----
    bRopDetected = TRUE;

    // 触发行为告警
    if (g_bBehaviorDetectionEnabled) {
        BehaviorRecordMemoryEvent(
            (INT64)pid,
            procNameA,
            dllPathA.Buffer ? dllPathA.Buffer : "",
            (INT64)pid,
            0,
            BA_MOP_DllLoadViaRop,
            FALSE,
            NULL);
    }

    if (g_bMemoryProtectionEnabled) {
        BehaviorHandleInjectionAlertAsync(
            (INT64)pid,
            procNameA,
            (INT64)pid,
            procNameA,
            "DLL Load via ROP (no valid return address)",
            0,
            NULL);
    }

Cleanup:
    if (dllPathA.Buffer)
        RtlFreeAnsiString(&dllPathA);
    return bRopDetected;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * LoadImageNotifyRoutine — 镜像加载通知回调
 *
 * 在进程首次加载 kernel32.dll 时（最早的用户态就绪时机），
 * 通过挂起-注入-恢复方案注入 R3 防御 DLL。
 *
 * 原理：
 *   PsSetLoadImageNotifyRoutine 回调在加载镜像的线程上下文中
 *   以 PASSIVE_LEVEL 执行。当 kernel32.dll 被加载时：
 *   1. 在更早的 ntdll.dll 加载通知中缓存 ntdll!LdrLoadDll 地址
 *   2. 排队一个内核 APC 后立刻返回（避免在 NtMapViewOfSection 调用栈中
 *      分配内存导致 AddressCreationLock 死锁）
 *   3. 内核 APC 在离开 NtMapViewOfSection 后交付，将实际注入排队到
 *      PASSIVE_LEVEL work item
 *   4. work item 分配远程可执行内存，写入调用 ntdll!LdrLoadDll 的 shellcode
 *      与参数块，并插入用户态 APC（NormalRoutine = shellcode）
 *   5. ntdll!LdrpInitialize 完成后线程进入 alertable 状态，APC 自然交付，
 *      此时 ntdll 已就绪，shellcode 调用 LdrLoadDll 加载 R3 防御 DLL
 *
 * 优点：
 *   - 不依赖 kernel32!LoadLibraryW/A，规避部分映射导致导出不可用的 bug
 *   - 无固定 1 秒延迟，注入窗口极小
 *   - 注入时机仍在 main/WinMain 之前，早于所有 R3 hook
 *   - 无需 R3 递归注入，消除 explorer.exe 依赖
 *   - 与 ObRegisterCallbacks 注入防护不冲突
 * ══════════════════════════════════════════════════════════════════════════ */
VOID NTAPI LoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{

    /* ── Ntdll 处理 ──
     * 无论 R3 防护是否启用，都检测 ntdll.dll 加载：
     *   1. 若启用重载检测，记录加载事件以发现 ntdll 重载/卸载绕过行为。 */
    if (FullImageName && FullImageName->Buffer &&
        ProcessId > (HANDLE)4 &&
        IsNtdllImage(FullImageName))
    {
        if (g_bNtdllReloadDetectionEnabled)
        {
            NtdllTrackUpdate(
                ProcessId,
                (ULONG_PTR)ImageInfo->ImageBase,
                (ULONG)ImageInfo->ImageSize,
                FullImageName->Buffer,
                NULL);
        }
    }

    /* ── 漏洞驱动（BYOVD）加载拦截 ──
     * 识别 .sys 驱动镜像，排队 work item 在 PASSIVE_LEVEL 计算 SHA256 并
     * 与黑名单比对，命中则终止发起加载的进程。独立于 R3 防护开关运行。 */
    if (FullImageName && FullImageName->Buffer &&
        VdIsDriverImagePath(FullImageName))
    {
        VdQueueCheck(FullImageName, ProcessId);
    }

    /* R3 DLL 防护未启用时禁止注入：用户态必须显式开启 R3 防护后，
     * 驱动才允许向新进程注入 DLL。 */
    if (!g_bR3ProtectionEnabled)
    {
        return;
    }

    /* 检查 DLL 路径是否已设置 */
    if (!g_bDllInjectPathSet)
    {
        return;
    }

    /* 跳过系统进程（PID 0/4） */
    if ((ULONG)(ULONG_PTR)ProcessId <= 4)
        return;

    /* ── ROP 检测：DLL 加载是否通过 ROP 链发起 ──
     * 在 LoadImage notify 中（发起线程上下文）获取用户态调用栈，
     * 检查返回地址是否在非镜像内存（堆/栈/JIT/shellcode）。
     * 仅对 .dll 文件检测，避免对 .exe 主程序加载误报。
     * 跳过系统 DLL（ntdll/kernel32/kernelbase）以减少误报。 */
    if (g_bMemoryProtectionEnabled && FullImageName && FullImageName->Buffer)
    {
        UNICODE_STRING dllExt;
        RtlInitUnicodeString(&dllExt, L".dll");
        if (FullImageName->Length >= dllExt.Length)
        {
            UNICODE_STRING tail;
            tail.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer +
                FullImageName->Length - dllExt.Length);
            tail.Length = dllExt.Length;
            tail.MaximumLength = dllExt.Length;
            if (RtlEqualUnicodeString(&tail, &dllExt, TRUE))
            {
                /* 仅对非系统 DLL 检测 ROP */
                if (!IsNtdllImage(FullImageName) &&
                    !IsKernel32Image(FullImageName))
                {
                    DetectDllLoadViaRop(ProcessId, FullImageName);
                }
            }
        }
    }

    /* 跳过空镜像名 */
    if (FullImageName == NULL || FullImageName->Buffer == NULL)
        return;

    /* ── 签名程序加载未签名 DLL 检查 ── */
    if (g_bUnsignedDllScanEnabled)
    {
        UNICODE_STRING dllExt;
        UNICODE_STRING tail;
        USHORT dllLen;
        WCHAR procShortName[16] = { 0 };
        UCHAR* pShortName = NULL;

        /* 仅检查 .dll 文件，跳过主程序（.exe）和 kernel32.dll（后面单独处理注入） */
        RtlInitUnicodeString(&dllExt, L".dll");
        dllLen = dllExt.Length;
        if (FullImageName->Length >= dllLen)
        {
            tail.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer + FullImageName->Length - dllLen);
            tail.Length = dllLen;
            tail.MaximumLength = dllLen;
            if (RtlEqualUnicodeString(&tail, &dllExt, TRUE))
            {
                /* 跳过 ntdll.dll 和 kernel32.dll：系统 DLL 始终有微软签名，
                 * 且 kernel32.dll 加载是后续 DLL 注入的触发时机，不可被扫描阻塞。 */
                if (IsNtdllImage(FullImageName) || IsKernel32Image(FullImageName))
                {
                    goto skip_dll_scan;
                }

                /* 跳过自身注入的防护 DLL，避免自扫描 */
                if (g_bDllInjectPathSet && g_DllInjectPath[0] != L'\0')
                {
                    UNICODE_STRING injectPath;
                    RtlInitUnicodeString(&injectPath, g_DllInjectPath);
                    USHORT injectLen = injectPath.Length;
                    if (FullImageName->Length >= injectLen)
                    {
                        UNICODE_STRING prefix;
                        prefix.Buffer = FullImageName->Buffer;
                        prefix.Length = injectLen;
                        prefix.MaximumLength = injectLen;
                        if (RtlEqualUnicodeString(&prefix, &injectPath, TRUE))
                        {
                            return;
                        }
                    }
                }

                /* 获取进程短名（最多 15 字符），用于判断是否为主程序自身加载 */
                pShortName = PsGetProcessImageFileName(PsGetCurrentProcess());
                if (pShortName)
                {
                    int i;
                    for (i = 0; i < 15 && pShortName[i]; i++)
                    {
                        procShortName[i] = (WCHAR)pShortName[i];
                    }
                    procShortName[i] = L'\0';
                }

                /* 如果加载的 DLL 名与进程名前缀匹配，可能是主程序自身加载自身（如自解压），跳过 */
                if (procShortName[0] != L'\0' &&
                    FullImageName->Length >= (USHORT)(wcslen(procShortName) * sizeof(WCHAR)))
                {
                    UNICODE_STRING procName;
                    UNICODE_STRING imgPrefix;
                    RtlInitUnicodeString(&procName, procShortName);
                    imgPrefix.Buffer = FullImageName->Buffer;
                    imgPrefix.Length = (USHORT)(wcslen(procShortName) * sizeof(WCHAR));
                    imgPrefix.MaximumLength = imgPrefix.Length;
                    if (RtlEqualUnicodeString(&procName, &imgPrefix, TRUE))
                    {
                        return;
                    }
                }

                /* 获取加载进程的完整路径（在 APC 例程中查询，避免 LoadImageNotifyRoutine 中重操作） */
                {
                    CHAR processPath[512] = { 0 };
                    PEPROCESS proc = NULL;
                    HANDLE hProc = NULL;
                    NTSTATUS qs = STATUS_UNSUCCESSFUL;
                    ULONG retLen = 0;

                    if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &proc)))
                    {
                        qs = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                            PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProc);
                        ObDereferenceObject(proc);
                    }

                    if (NT_SUCCESS(qs) && hProc)
                    {
                        qs = ZwQueryInformationProcess(hProc, ProcessImageFileName, NULL, 0, &retLen);
                        if (NT_SUCCESS(qs) && retLen > 0)
                        {
                            PUNICODE_STRING pImgPath = (PUNICODE_STRING)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED, retLen, 'DlSP');
                            if (pImgPath)
                            {
                                qs = ZwQueryInformationProcess(hProc, ProcessImageFileName,
                                    pImgPath, retLen, &retLen);
                                if (NT_SUCCESS(qs) && pImgPath->Buffer)
                                {
                                    int wlen = (int)(pImgPath->Length / sizeof(WCHAR));
                                    if (wlen >= 512) wlen = 511;
                                    for (int i = 0; i < wlen; i++)
                                    {
                                        processPath[i] = (CHAR)pImgPath->Buffer[i];
                                    }
                                    processPath[wlen] = '\0';
                                }
                                ExFreePool(pImgPath);
                            }
                        }
                        ZwClose(hProc);
                    }

                    /* 回退：使用短名 */
                    if (processPath[0] == '\0' && pShortName)
                    {
                        int i;
                        for (i = 0; i < 15 && pShortName[i]; i++)
                        {
                            processPath[i] = (CHAR)pShortName[i];
                        }
                        processPath[i] = '\0';
                    }

                    /* 仅当进程路径已知时才继续检查 */
                    if (processPath[0] != '\0')
                    {
                        /* 转换 DLL 路径为 ANSI */
                        CHAR dllPathA[520] = { 0 };
                        int wlen = (int)(FullImageName->Length / sizeof(WCHAR));
                        if (wlen >= 520) wlen = 519;
                        for (int i = 0; i < wlen; i++)
                        {
                            dllPathA[i] = (CHAR)FullImageName->Buffer[i];
                        }
                        dllPathA[wlen] = '\0';

                        /* ── 同目录未签名 DLL 检测（Side-Load 降级）──
                         * 提取进程 EXE 所在目录，与 DLL 路径比较。
                         * 若 DLL 与 EXE 同目录且 DLL 未签名，则标记该进程为不可信。 */
                        BOOLEAN sameDirUnsignedDll = FALSE;
                        {
                            /* 找进程路径最后反斜杠位置（EXE 文件名之前） */
                            INT lastSlash = -1;
                            for (int si = 0; processPath[si] != '\0'; si++)
                            {
                                if (processPath[si] == '\\' || processPath[si] == '/')
                                    lastSlash = si;
                            }
                            if (lastSlash >= 0)
                            {
                                /* 提取 EXE 目录路径 */
                                CHAR exeDir[512] = { 0 };
                                INT dirLen = lastSlash;
                                if (dirLen >= (INT)sizeof(exeDir)) dirLen = (INT)sizeof(exeDir) - 1;
                                RtlCopyMemory(exeDir, processPath, (UINT32)dirLen);
                                exeDir[dirLen] = '\0';

                                /* 检查 DLL 是否在同目录：取 DLL 路径最后一个反斜杠后的部分作为文件名 */
                                INT dllLastSlash = -1;
                                for (int di = 0; dllPathA[di] != '\0'; di++)
                                {
                                    if (dllPathA[di] == '\\' || dllPathA[di] == '/')
                                        dllLastSlash = di;
                                }
                                if (dllLastSlash >= 0)
                                {
                                    /* DLL 路径的前缀（目录部分）应与 exeDir 相同 */
                                    INT dllDirLen = dllLastSlash;
                                    if (dllDirLen == dirLen &&
                                        RtlEqualMemory(exeDir, dllPathA, (SIZE_T)dirLen))
                                    {
                                        /* 同目录！检查 DLL 是否未签名 */
                                        BOOLEAN dllSigned = CiIsImageSignedAndTrusted(ImageInfo);
                                        if (!dllSigned)
                                        {
                                            sameDirUnsignedDll = TRUE;
                                            DriverDbgPrint("[SIDE-LOAD] Same-dir unsigned DLL detected: PID=%d DLL=%s EXE_DIR=%s\n",
                                                (INT)(ULONG_PTR)ProcessId, dllPathA, exeDir);
                                        }
                                    }
                                }
                            }

                            /* 标记签名降级：无论是否阻塞扫描，都先降级签名状态 */
                            if (sameDirUnsignedDll)
                            {
                                BaMarkPidUnsignedDueToSideLoad((INT64)(ULONG_PTR)ProcessId, dllPathA);
                            }
                        }

                        /* 签名进程加载未签名 DLL、或任意进程加载同目录未签名 DLL（侧载）时进行 DLL 扫描告警 */
                        {
                            BOOLEAN processSigned = CiIsPidSigned((INT64)(ULONG_PTR)ProcessId);
                            if (processSigned || sameDirUnsignedDll)
                            {
                                if (sameDirUnsignedDll)
                                {
                                    BehaviorRecordDllSideLoad((INT64)(ULONG_PTR)ProcessId, dllPathA, processSigned);
                                }
                        DriverDbgPrint("[DLL-SCAN] Checking DLL signature: PID=%d DLL=%s Process=%s\n",
                            (INT)(ULONG_PTR)ProcessId, dllPathA, processPath);

                        if (g_bDllBlockingScanEnabled)
                        {
                            NTSTATUS suspendStatus = SuspendProcessByPid((INT64)(ULONG_PTR)ProcessId);
                            if (NT_SUCCESS(suspendStatus))
                            {
                                DriverDbgPrint("[DLL-SCAN] Suspended PID=%d for blocking scan\n",
                                    (INT)(ULONG_PTR)ProcessId);

                                /* 用户态可见日志：DLL 阻塞扫描挂起进程 */
                                {
                                    CHAR dllLogMsg[400];
                                    RtlStringCbPrintfA(dllLogMsg, sizeof(dllLogMsg),
                                        "[DLL扫描-阻塞] 已挂起进程等待签名验证: PID=%d DLL=%s 进程=%s",
                                        (INT)(ULONG_PTR)ProcessId, dllPathA, processPath);
                                    SendInjectionLog(dllLogMsg);
                                }
                            }
                            else
                            {
                                DriverDbgPrint("[DLL-SCAN] Failed to suspend PID=%d, skip blocking\n",
                                    (INT)(ULONG_PTR)ProcessId);

                                /* 用户态可见日志：挂起失败 */
                                {
                                    CHAR dllLogMsg[300];
                                    RtlStringCbPrintfA(dllLogMsg, sizeof(dllLogMsg),
                                        "[DLL扫描-阻塞] 挂起失败(放行): PID=%d DLL=%s",
                                        (INT)(ULONG_PTR)ProcessId, dllPathA);
                                    SendInjectionLog(dllLogMsg);
                                }
                            }
                        }

                        QueueDllScanWorkItem(
                            (INT64)(ULONG_PTR)ProcessId,
                            FullImageName->Buffer,
                            processPath,
                            g_bDllBlockingScanEnabled,
                            sameDirUnsignedDll ? TRUE : FALSE);

                        if (g_bDllBlockingScanEnabled)
                        {
                            return;
                        }
                            }
                        }
                    }
                }
            }
        }
    }




skip_dll_scan:

    /* ── 记录进程主 EXE 的签名状态到缓存 ──
     * 进程主镜像（.exe）加载时，通过 ImageInfo->ImageSignatureLevel
     * 判断是否带有有效签名（AUTHENTICODE 及以上）。签名状态写入缓存后，
     * 后续的 BaMarkPidUnsignedDueToSideLoad、CiIsPidSigned 等检查才能正确工作。 */
    if (FullImageName && FullImageName->Buffer && ProcessId > (HANDLE)4)
    {
        UNICODE_STRING exeExt;
        RtlInitUnicodeString(&exeExt, L".exe");
        if (FullImageName->Length >= exeExt.Length)
        {
            UNICODE_STRING tailExe;
            tailExe.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer +
                FullImageName->Length - exeExt.Length);
            tailExe.Length = exeExt.Length;
            tailExe.MaximumLength = exeExt.Length;
            if (RtlEqualUnicodeString(&tailExe, &exeExt, TRUE))
            {
                /* 跳过系统镜像（ntdll/kernel32 等本身不是主 EXE 加载） */
                if (!IsNtdllImage(FullImageName) && !IsKernel32Image(FullImageName))
                {
                    BOOLEAN isSigned = CiIsImageSignedAndTrusted(ImageInfo);
                    CiRecordProcessSignature((INT64)(ULONG_PTR)ProcessId, isSigned);
                    DriverDbgPrint("[SIG-RECORD] PID=%lld EXE signed=%d\n",
                        (INT64)(ULONG_PTR)ProcessId, isSigned);
                }
            }
        }
    }


    /* ── DLL 注入：调用 DriverDllInject（参考 injdrv: https://github.com/wbenny/injdrv）──
     * 使用 kernel APC + thunk/thunkless 方案，
     * 在 ntdll.dll 加载后触发，避免 LoaderLock 竞争和死锁。 */
    DriverDllInjectLoadImageNotifyRoutine(FullImageName, ProcessId, ImageInfo);
}

/* ============================================================================
 * R0 独立进程创建检查支持（R3 未启用时）
 * 在 ProcessCreateNotifyRoutine 中挂起新进程，通过用户态 Client 转发到
 * main.cpp 执行命令行风险检测和静态扫描，根据用户决策恢复或终止。
 * 注意：以下代码从 Main_disk.c 迁移到 ProcessCallback.c，确保参与构建。
 * ========================================================================== */

/* 进程操作 API 指针（动态解析，避免链接问题） */
static NTSTATUS (*g_pfnPsSuspendProcess)(PEPROCESS) = NULL;
static NTSTATUS (*g_pfnPsResumeProcess)(PEPROCESS) = NULL;
static NTSTATUS (*g_pfnNtSuspendProcess)(HANDLE) = NULL;
static NTSTATUS (*g_pfnNtResumeProcess)(HANDLE) = NULL;
static NTSTATUS (*g_pfnNtTerminateProcess)(HANDLE, NTSTATUS) = NULL;

VOID ResolveProcessManipulationApis(VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsSuspendProcess");
    g_pfnPsSuspendProcess = (NTSTATUS(*)(PEPROCESS))MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"PsResumeProcess");
    g_pfnPsResumeProcess = (NTSTATUS(*)(PEPROCESS))MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"NtSuspendProcess");
    g_pfnNtSuspendProcess = (NTSTATUS(*)(HANDLE))MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"NtResumeProcess");
    g_pfnNtResumeProcess = (NTSTATUS(*)(HANDLE))MmGetSystemRoutineAddress(&name);
    RtlInitUnicodeString(&name, L"NtTerminateProcess");
    g_pfnNtTerminateProcess = (NTSTATUS(*)(HANDLE, NTSTATUS))MmGetSystemRoutineAddress(&name);
}


static BOOLEAN QueryProcessCritical(HANDLE hProcess)
{
    ULONG breakOnTermination = 0;
    ULONG returnLength = 0;
    NTSTATUS status;

    status = ZwQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)0x1D,  /* ProcessBreakOnTermination */
        &breakOnTermination,
        sizeof(breakOnTermination),
        &returnLength);
    if (!NT_SUCCESS(status)) return FALSE;
    return (breakOnTermination != 0) ? TRUE : FALSE;
}

/* 挂起进程 */
static NTSTATUS SuspendProcessByPid(INT64 pid)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    BOOLEAN suspended = FALSE;
    if (!NT_SUCCESS(status)) return status;

    /* 关键系统进程保护：挂起系统关键进程（如 csrss/winlogon/services）
     * 会导致系统卡死或触发 watchdog 蓝屏。先按进程名过滤，再查询
     * BreakOnTermination 标记，任一命中都直接放行。 */
    if (IsCriticalSystemProcess(process)) {
        DriverDbgPrint("[PROCESS-CHECK] Suspend SKIPPED critical system process PID=%lld (name filter)\n", pid);
        ObDereferenceObject(process);
        return STATUS_ACCESS_DENIED;
    }
    {
        HANDLE hQuery = NULL;
        NTSTATUS qs = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
            0x0400, /* PROCESS_QUERY_LIMITED_INFORMATION */
            *PsProcessType, KernelMode, &hQuery);
        if (NT_SUCCESS(qs) && hQuery) {
            if (QueryProcessCritical(hQuery)) {
                DriverDbgPrint("[PROCESS-CHECK] Suspend SKIPPED BreakOnTermination PID=%lld\n", pid);
                ZwClose(hQuery);
                ObDereferenceObject(process);
                return STATUS_ACCESS_DENIED;
            }
            ZwClose(hQuery);
        }
    }

    if (g_pfnPsSuspendProcess) {
        status = g_pfnPsSuspendProcess(process);
        if (NT_SUCCESS(status)) suspended = TRUE;
    }

    if (!suspended && g_pfnNtSuspendProcess) {
        HANDLE hProcess = NULL;
        status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
            0x0800, /* PROCESS_SUSPEND_RESUME */
            *PsProcessType, KernelMode, &hProcess);
        if (NT_SUCCESS(status) && hProcess) {
            status = g_pfnNtSuspendProcess(hProcess);
            if (NT_SUCCESS(status)) suspended = TRUE;
            ZwClose(hProcess);
        }
    }

    ObDereferenceObject(process);
    return suspended ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* 恢复进程 */
static NTSTATUS ResumeProcessByPid(INT64 pid)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    BOOLEAN resumed = FALSE;
    if (!NT_SUCCESS(status)) return status;

    if (g_pfnPsResumeProcess) {
        status = g_pfnPsResumeProcess(process);
        if (NT_SUCCESS(status)) resumed = TRUE;
    }

    if (!resumed && g_pfnNtResumeProcess) {
        HANDLE hProcess = NULL;
        status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
            0x0800, /* PROCESS_SUSPEND_RESUME */
            *PsProcessType, KernelMode, &hProcess);
        if (NT_SUCCESS(status) && hProcess) {
            status = g_pfnNtResumeProcess(hProcess);
            if (NT_SUCCESS(status)) resumed = TRUE;
            ZwClose(hProcess);
        }
    }

    ObDereferenceObject(process);
    return resumed ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* 终止进程 */
static NTSTATUS TerminateProcessByPid(INT64 pid)
{
    PEPROCESS process;
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status)) return status;

    /* 关键系统进程保护：绝不终止已知关键进程（winlogon/csrss/services 等）。
     * 这是 BreakOnTermination 之前的额外防线，防止某些系统进程在启动早期
     * 尚未被标记为 critical 时被误杀。 */
    if (IsCriticalSystemProcess(process)) {
        DriverDbgPrint("[PROCESS-CHECK] Terminate SKIPPED critical system process PID=%lld (name filter)\n", pid);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }

    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
        0x0001 | 0x0400, /* PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION */
        *PsProcessType, KernelMode, &hProcess);
    if (NT_SUCCESS(status) && hProcess) {
        /* 安全策略：任何标记为 BreakOnTermination 的进程都禁止终止，
         * 避免触发 CRITICAL_PROCESS_DIED。 */
        if (QueryProcessCritical(hProcess)) {
            DriverDbgPrint("[PROCESS-CHECK] PID=%lld has BreakOnTermination, skip termination to prevent BSOD\n", pid);
        } else if (g_pfnNtTerminateProcess) {
            g_pfnNtTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
        }
        ZwClose(hProcess);
    }
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/* 进程创建检查 work item 上下文 */
typedef struct _PROCESS_CHECK_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    INT64 pid;
    INT64 parentPid;
    CHAR processPath[512];
    CHAR processName[64];
    CHAR parentName[64];
} PROCESS_CHECK_WORKITEM_CTX, *PPROCESS_CHECK_WORKITEM_CTX;

/* 进程创建检查 work item 回调 */
static VOID ProcessCheckWorkItemRoutine(PVOID Context)
{
    PROCESS_CHECK_WORKITEM_CTX* ctx = (PROCESS_CHECK_WORKITEM_CTX*)Context;
    PRESPONSE_REQUEST request = NULL;
    KLOCK_QUEUE_HANDLE lockHandle;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    NTSTATUS result = STATUS_ACCESS_DENIED; /* 默认阻止 */
    BOOLEAN queued = FALSE;
    BOOLEAN lockHeld = FALSE;

    __try {
        request = (PRESPONSE_REQUEST)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'RESP');
        if (!request) {
            DriverDbgPrint("[PROCESS-CHECK] Failed to allocate request, resume PID=%lld\n", ctx->pid);
            ResumeProcessByPid(ctx->pid);
            ExFreePool(ctx);
            return;
        }

        RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));
        KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
        request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
        request->RuleType = RULE_TYPE_PROCESS_CHECK;
        request->ProcessPid = (int)(ULONG_PTR)ctx->pid;
        request->ParentPid = (int)(ULONG_PTR)ctx->parentPid;
        request->FullPath = NULL;
        request->ValueName = NULL;
        request->NewValueData = NULL;
        RtlStringCbCopyA(request->ProcessName, sizeof(request->ProcessName),
            ctx->processName ? ctx->processName : "Unknown");
        RtlStringCbCopyA(request->ParentName, sizeof(request->ParentName),
            ctx->parentName ? ctx->parentName : "Unknown");
        RtlStringCbCopyA(request->ProcessPath, sizeof(request->ProcessPath),
            ctx->processPath ? ctx->processPath : "");
        RtlStringCbCopyA(request->RuleDesc, sizeof(request->RuleDesc),
            "ProcessStartCheck");

        KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
        lockHeld = TRUE;
        /* queued 必须在 EnqueueRequest 之前（持锁期间）设置：
         * 若在锁外设置，EnqueueRequest 与 queued=TRUE 之间存在异常窗口，
         * 异常处理器的 if(queued && request) 为 FALSE，导致 ExFreePool
         * 释放仍在队列中的 request → use-after-free → 池破坏蓝屏。 */
        queued = TRUE;
        if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
        {
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            lockHeld = FALSE;
            DriverDbgPrint("[PROCESS-CHECK] Queue full, resume PID=%lld\n", ctx->pid);
            ResumeProcessByPid(ctx->pid);
            ExFreePool(request);
            ExFreePool(ctx);
            return;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        lockHeld = FALSE;

        DriverDbgPrint("[PROCESS-CHECK] Queued check request PID=%lld Path=%s\n",
            ctx->pid, ctx->processPath);

        timeout.QuadPart = -35LL * 1000 * 1000 * 10;
        waitStatus = KeWaitForSingleObject(
            &request->CompletionEvent, Executive, KernelMode, FALSE, &timeout);

        if (waitStatus != STATUS_SUCCESS) {
            DriverDbgPrint("[PROCESS-CHECK] Wait timeout PID=%lld\n", ctx->pid);
            KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
            lockHeld = TRUE;
            /* 检查请求是否仍在队列中：HandleUserResponse 可能已移除并设置了结果 */
            if (request->ListEntry.Flink != &request->ListEntry)
            {
                RemoveEntryList(&request->ListEntry);
                InitializeListHead(&request->ListEntry);
                InterlockedDecrement(&g_RequestQueueCount);
                result = STATUS_ACCESS_DENIED;
            }
            else
            {
                /* 已被 HandleUserResponse 移除，使用其设置的结果 */
                result = request->ResultStatus;
            }
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            lockHeld = FALSE;
        } else {
            result = request->ResultStatus;
        }

        if (result == STATUS_SUCCESS) {
            DriverDbgPrint("[PROCESS-CHECK] Allow PID=%lld, resuming\n", ctx->pid);
            ResumeProcessByPid(ctx->pid);
        } else {
            DriverDbgPrint("[PROCESS-CHECK] Block PID=%lld, terminating\n", ctx->pid);
            TerminateProcessByPid(ctx->pid);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[PROCESS-CHECK] Exception in work item PID=%lld\n", ctx ? ctx->pid : 0);
        if (lockHeld) {
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            lockHeld = FALSE;
        }
        if (queued && request) {
            KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
            /* 检查请求是否仍在队列中：HandleUserResponse 可能已移除并
             * 调用了 InitializeListHead，此时 Flink==&self，RemoveEntryList
             * 虽是 no-op 但仍需检查避免对已释放内存操作。 */
            if (request->ListEntry.Flink != &request->ListEntry)
            {
                RemoveEntryList(&request->ListEntry);
                InitializeListHead(&request->ListEntry);
                InterlockedDecrement(&g_RequestQueueCount);
            }
            KeReleaseInStackQueuedSpinLock(&lockHandle);
        }
        if (ctx) {
            ResumeProcessByPid(ctx->pid);
        }
    }

    if (request) {
        ExFreePool(request);
    }
    if (ctx) {
        ExFreePool(ctx);
    }
}

/* 排队进程创建检查 work item */
static VOID QueueProcessCheckWorkItem(
    INT64 pid, INT64 parentPid,
    const CHAR* processPath, const CHAR* processName, const CHAR* parentName)
{
    PROCESS_CHECK_WORKITEM_CTX* ctx = (PROCESS_CHECK_WORKITEM_CTX*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(PROCESS_CHECK_WORKITEM_CTX), 'PcWk');
    if (!ctx) {
        DriverDbgPrint("[PROCESS-CHECK] Failed to allocate work item context PID=%lld\n", pid);
        ResumeProcessByPid(pid);
        return;
    }

    RtlZeroMemory(ctx, sizeof(PROCESS_CHECK_WORKITEM_CTX));
    ctx->pid = pid;
    ctx->parentPid = parentPid;
    if (processPath) RtlStringCbCopyA(ctx->processPath, sizeof(ctx->processPath), processPath);
    if (processName) RtlStringCbCopyA(ctx->processName, sizeof(ctx->processName), processName);
    if (parentName) RtlStringCbCopyA(ctx->parentName, sizeof(ctx->parentName), parentName);

    ExInitializeWorkItem(&ctx->WorkItem, ProcessCheckWorkItemRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);
}

/* 进程启动检查主函数 */
VOID ProcessStartCheck(INT64 pid, INT64 parentPid, const CHAR* processPath, const CHAR* imageName)
{
    /* 系统进程也要 check，不再按进程名整体跳过。
     * 真正的关键系统进程（BreakOnTermination 或名字匹配）由 SuspendProcessByPid
     * 内部保护：无法挂起的进程直接放行，避免误杀导致 CRITICAL_PROCESS_DIED。
     * 普通系统进程（如 backgroundTaskHost.exe、SearchProtocolHost.exe）仍可正常
     * 挂起并走扫描流程。
     *
     * R0+R3 同时启用时也走此路径：R3 的 NtCreateUserProcess 路径在 R0 启用时
     * 直接放行（不扫描），由 R0 负责挂起新进程并发送 PROCESS_CHECK 给 main.cpp。
     * 不能用 !g_bR3ProtectionEnabled 排除 R3 启用的场景，否则 R0/R3 一起开时
     * vbs/js 等脚本宿主（系统白名单文件）不会被扫描，恶意脚本被放行。 */
    if (g_bProcessProtectionEnabled &&
        pid > 4 &&
        imageName != NULL &&
        imageName[0] != '\0')
    {
        /* 受信任主程序及其直接子进程放行，避免主程序自身组件被挂起扫描 */
        if (g_TrustedMainPid != NULL &&
            ((HANDLE)(ULONG_PTR)pid == g_TrustedMainPid ||
             (HANDLE)(ULONG_PTR)parentPid == g_TrustedMainPid))
        {
            DriverDbgPrint("[PROCESS-CHECK] Trusted main PID=%lld or its child, skip check\n", pid);
            return;
        }

        /* 白名单放行：用户已标记为 AutoAllow 的进程不进入进程启动检查 */
        if (WhitelistCheckByPid(pid) == 1 ||
            WhitelistCheckByName(imageName) == 1)
        {
            DriverDbgPrint("[PROCESS-CHECK] Whitelisted PID=%lld Name=%s, skip check\n",
                pid, imageName);
            return;
        }

        CHAR parentName[64] = {0};

        if (parentPid > 0) {
            PEPROCESS parentProc = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)parentPid, &parentProc))) {
                UCHAR* pName = PsGetProcessImageFileName(parentProc);
                if (pName) {
                    int i;
                    for (i = 0; i < 15 && pName[i]; i++) {
                        parentName[i] = (CHAR)pName[i];
                    }
                    parentName[i] = '\0';
                }
                ObDereferenceObject(parentProc);
            }
        }

        NTSTATUS suspendStatus = SuspendProcessByPid(pid);
        if (NT_SUCCESS(suspendStatus)) {
            DriverDbgPrint("[PROCESS-CHECK] Suspended new process PID=%lld Name=%s\n",
                pid, imageName);

            QueueProcessCheckWorkItem(
                pid, parentPid,
                processPath ? processPath : "",
                imageName,
                parentName);
        } else {
            DriverDbgPrint("[PROCESS-CHECK] Failed to suspend PID=%lld, skip check\n", pid);
        }
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DLL 未签名扫描 work item 上下文
 * ═══════════════════════════════════════════════════════════════════════════ */
typedef struct _DLL_SCAN_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    INT64 pid;
    WCHAR dllPath[520];
    CHAR processPath[512];
    BOOLEAN blocking;
    BOOLEAN isSideLoad;
} DLL_SCAN_WORKITEM_CTX, *PDLL_SCAN_WORKITEM_CTX;

/* ═══════════════════════════════════════════════════════════════════════════
 * DllScanWorkItemRoutine — 签名程序加载未签名 DLL 检查 work item 回调
 *
 * 在 PASSIVE_LEVEL 系统线程中执行，负责：
 * 1. 若为阻塞模式，已由 LoadImageNotifyRoutine 挂起目标进程
 * 2. 向用户态发送扫描请求并等待响应（阻塞模式）
 * 3. 异步模式仅发通知，不等待
 * 4. 根据响应恢复或终止目标进程
 * ═══════════════════════════════════════════════════════════════════════════ */
static VOID DllScanWorkItemRoutine(PVOID Context)
{
    PDLL_SCAN_WORKITEM_CTX ctx = (PDLL_SCAN_WORKITEM_CTX)Context;
    PRESPONSE_REQUEST request = NULL;
    KLOCK_QUEUE_HANDLE lockHandle;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    NTSTATUS result = STATUS_ACCESS_DENIED;
    BOOLEAN queued = FALSE;
    BOOLEAN lockHeld = FALSE;

    __try {
        /* 转换 DLL 路径为 ANSI */
        CHAR dllPathA[520] = { 0 };
        int i;
        for (i = 0; i < 519 && ctx->dllPath[i]; i++)
        {
            dllPathA[i] = (CHAR)ctx->dllPath[i];
        }
        dllPathA[i] = '\0';

        if (!ctx->blocking)
        {
            /* ── 异步扫描：仅通知用户态，立即放行 ── */
            DriverDbgPrint("[DLL-SCAN] Async notify PID=%lld DLL=%S\n",
                ctx->pid, ctx->dllPath);

            request = (PRESPONSE_REQUEST)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'DlSc');
            if (request)
            {
                RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));
                KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
                request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
                request->RuleType = RULE_TYPE_DLL_SCAN;
                request->ProcessPid = (int)(ULONG_PTR)ctx->pid;
                request->ParentPid = 0;
                RtlStringCbCopyA(request->ProcessName, sizeof(request->ProcessName), "Unknown");
                RtlStringCbCopyA(request->ParentName, sizeof(request->ParentName), "");
                RtlStringCbCopyA(request->ProcessPath, sizeof(request->ProcessPath),
                    ctx->processPath ? ctx->processPath : "");
                RtlStringCbCopyA(request->DllPath, sizeof(request->DllPath), dllPathA);
                RtlStringCbCopyA(request->RuleDesc, sizeof(request->RuleDesc),
                    "UnsignedDllScan-Async");
                request->IsSideLoad = ctx->isSideLoad ? 1 : 0;

                KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
                lockHeld = TRUE;
                /* FireAndForget 必须在持锁期间设置：HandleUserResponse 移除请求后
                 * 会读取此标志决定是否释放内存，锁外设置存在竞态窗口 */
                request->FireAndForget = TRUE;
                /* queued 必须在 EnqueueRequest 之前（持锁期间）设置，
                 * 避免异常窗口内 ExFreePool 释放队列中的 request。 */
                queued = TRUE;
                if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
                {
                    /* 入队失败（队列满且全是同步请求），释放 request */
                    KeReleaseInStackQueuedSpinLock(&lockHandle);
                    lockHeld = FALSE;
                    ExFreePool(request);
                    request = NULL;
                }
                else
                {
                    KeReleaseInStackQueuedSpinLock(&lockHandle);
                    lockHeld = FALSE;
                    /* 异步模式不等待响应，由 HandleUserResponse 释放请求 */
                    request = NULL;
                    DriverDbgPrint("[DLL-SCAN] Async request queued PID=%lld\n", ctx->pid);
                }
            }
            result = STATUS_SUCCESS;
        }
        else
        {
            /* ── 阻塞扫描：通过 CI.DLL 直接验证签名 ── */
            BOOLEAN dllSigned = FALSE;
            NTSTATUS verifyStatus = STATUS_ACCESS_DENIED;
            HANDLE fileHandle = NULL;
            PFILE_OBJECT fileObject = NULL;
            IO_STATUS_BLOCK ioStatus;
            OBJECT_ATTRIBUTES objAttr;
            UNICODE_STRING dllPathW;
            NTSTATUS openStatus;

            RtlInitUnicodeString(&dllPathW, ctx->dllPath);
            InitializeObjectAttributes(&objAttr, &dllPathW,
                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

            openStatus = IoCreateFileEx(
                &fileHandle,
                FILE_READ_DATA | SYNCHRONIZE,
                &objAttr,
                &ioStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                NULL,
                0,
                CreateFileTypeNone,
                NULL,
                IO_FORCE_ACCESS_CHECK,
                NULL);

            if (NT_SUCCESS(openStatus) && fileHandle)
            {
                verifyStatus = ObReferenceObjectByHandle(
                    fileHandle,
                    FILE_READ_DATA,
                    *IoFileObjectType,
                    KernelMode,
                    (PVOID*)&fileObject,
                    NULL);

                if (NT_SUCCESS(verifyStatus) && fileObject)
                {
                    verifyStatus = CiVerifyFileObject(fileObject, &dllSigned);
                    ObDereferenceObject(fileObject);
                }

                ZwClose(fileHandle);
            }
            else
            {
                verifyStatus = openStatus;
            }

            if (NT_SUCCESS(verifyStatus) && dllSigned)
            {
                DriverDbgPrint("[DLL-SCAN] Signed DLL allowed PID=%lld DLL=%s\n",
                    ctx->pid, dllPathA);
                result = STATUS_SUCCESS;
            }
            else
            {
                /* 签名验证失败或未实现，回退到用户态决策队列 */
                request = (PRESPONSE_REQUEST)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'DlSc');
                if (!request)
                {
                    DriverDbgPrint("[DLL-SCAN] Failed to allocate request, resume PID=%lld\n", ctx->pid);
                    ResumeProcessByPid(ctx->pid);
                    ExFreePool(ctx);
                    return;
                }

                RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));
                KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
                request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
                request->RuleType = RULE_TYPE_DLL_SCAN;
                request->ProcessPid = (int)(ULONG_PTR)ctx->pid;
                request->ParentPid = 0;
                RtlStringCbCopyA(request->ProcessName, sizeof(request->ProcessName), "Unknown");
                RtlStringCbCopyA(request->ParentName, sizeof(request->ParentName), "");
                RtlStringCbCopyA(request->ProcessPath, sizeof(request->ProcessPath),
                    ctx->processPath ? ctx->processPath : "");
                RtlStringCbCopyA(request->DllPath, sizeof(request->DllPath), dllPathA);
                RtlStringCbCopyA(request->RuleDesc, sizeof(request->RuleDesc), "UnsignedDllScan-Blocking");
                request->IsSideLoad = ctx->isSideLoad ? 1 : 0;

                KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
                lockHeld = TRUE;
                /* queued 必须在 EnqueueRequest 之前（持锁期间）设置，
                 * 避免异常窗口内 ExFreePool 释放队列中的 request。 */
                queued = TRUE;
                if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
                {
                    KeReleaseInStackQueuedSpinLock(&lockHandle);
                    lockHeld = FALSE;
                    DriverDbgPrint("[DLL-SCAN] Queue full, resume PID=%lld\n", ctx->pid);
                    ResumeProcessByPid(ctx->pid);
                    ExFreePool(request);
                    ExFreePool(ctx);
                    return;
                }
                KeReleaseInStackQueuedSpinLock(&lockHandle);
                lockHeld = FALSE;

                DriverDbgPrint("[DLL-SCAN] Queued blocking check request PID=%lld DLL=%S\n",
                    ctx->pid, ctx->dllPath);

                timeout.QuadPart = -35LL * 1000 * 1000 * 10;
                waitStatus = KeWaitForSingleObject(
                    &request->CompletionEvent, Executive, KernelMode, FALSE, &timeout);

                if (waitStatus != STATUS_SUCCESS)
                {
                    DriverDbgPrint("[DLL-SCAN] Wait timeout PID=%lld\n", ctx->pid);
                    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
                    lockHeld = TRUE;
                    /* 检查请求是否仍在队列中，避免对已移除的链表节点调用 RemoveEntryList */
                    if (request->ListEntry.Flink != &request->ListEntry)
                    {
                        RemoveEntryList(&request->ListEntry);
                        InitializeListHead(&request->ListEntry);
                        InterlockedDecrement(&g_RequestQueueCount);
                        result = STATUS_ACCESS_DENIED;
                    }
                    else
                    {
                        result = request->ResultStatus;
                    }
                    KeReleaseInStackQueuedSpinLock(&lockHandle);
                    lockHeld = FALSE;
                }
                else
                {
                    result = request->ResultStatus;
                }
            }
        }

        if (result == STATUS_SUCCESS)
        {
            DriverDbgPrint("[DLL-SCAN] Allow PID=%lld, %s\n",
                ctx->pid, ctx->blocking ? "resuming" : "already running");
            if (ctx->blocking)
            {
                ResumeProcessByPid(ctx->pid);
            }
        }
        else
        {
            DriverDbgPrint("[DLL-SCAN] Block PID=%lld, terminating\n", ctx->pid);
            TerminateProcessByPid(ctx->pid);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[DLL-SCAN] Exception in work item PID=%lld\n", ctx ? ctx->pid : 0);
        if (lockHeld)
        {
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            lockHeld = FALSE;
        }
        if (queued && request)
        {
            KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
            /* 检查请求是否仍在队列中，避免对已移除节点调用 RemoveEntryList */
            if (request->ListEntry.Flink != &request->ListEntry)
            {
                RemoveEntryList(&request->ListEntry);
                InitializeListHead(&request->ListEntry);
                InterlockedDecrement(&g_RequestQueueCount);
            }
            KeReleaseInStackQueuedSpinLock(&lockHandle);
        }
        if (ctx)
        {
            ResumeProcessByPid(ctx->pid);
        }
    }

    if (request)
    {
        ExFreePool(request);
    }
    if (ctx)
    {
        ExFreePool(ctx);
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * QueueDllScanWorkItem — 排队 DLL 未签名扫描 work item
 *
 * 在 LoadImageNotifyRoutine 中调用，将检查推迟到 PASSIVE_LEVEL 执行，
 * 避免在 NtMapViewOfSection 调用栈中分配内存导致死锁。
 * ═══════════════════════════════════════════════════════════════════════════ */
VOID QueueDllScanWorkItem(
    INT64 pid,
    const WCHAR* dllPath,
    const CHAR* processPath,
    BOOLEAN blocking,
    BOOLEAN isSideLoad)
{
    PDLL_SCAN_WORKITEM_CTX ctx = (PDLL_SCAN_WORKITEM_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DLL_SCAN_WORKITEM_CTX), 'DlSW');
    if (!ctx)
    {
        DriverDbgPrint("[DLL-SCAN] Failed to allocate work item context PID=%lld\n", pid);
        if (blocking)
        {
            ResumeProcessByPid(pid);
        }
        return;
    }

    RtlZeroMemory(ctx, sizeof(DLL_SCAN_WORKITEM_CTX));
    ctx->pid = pid;
    ctx->blocking = blocking ? TRUE : FALSE;
    ctx->isSideLoad = isSideLoad ? TRUE : FALSE;
    if (dllPath)
    {
        int i;
        for (i = 0; i < 519 && dllPath[i]; i++)
        {
            ctx->dllPath[i] = dllPath[i];
        }
        ctx->dllPath[i] = L'\0';
    }
    if (processPath)
    {
        RtlStringCbCopyA(ctx->processPath, sizeof(ctx->processPath), processPath);
    }

    ExInitializeWorkItem(&ctx->WorkItem, DllScanWorkItemRoutine, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Ntdll 重载/Unhook 检测
 *
 * 通过 PsSetLoadImageNotifyRoutine 监控 ntdll.dll 的加载事件，追踪每个进程
 * 中 ntdll.dll 的基地址、大小和加载路径。当检测到以下情况时判定为重载/Unhook：
 *   1. 基地址发生变化（在同一进程中多次加载 ntdll.dll）
 *   2. 加载路径不在系统目录（非标准路径加载）
 *   3. 映像大小异常（与系统 ntdll.dll 不匹配）
 * ═══════════════════════════════════════════════════════════════════════════ */

/* 初始化 ntdll 追踪上下文 */
VOID NtdllTrackInitialize(VOID)
{
    KeInitializeSpinLock(&g_NtdllTrackContext.Lock);
    RtlZeroMemory(g_NtdllTrackContext.Entries, sizeof(g_NtdllTrackContext.Entries));
    g_NtdllTrackContext.Count = 0;
    g_bNtdllReloadDetectionEnabled = TRUE;
    g_NtdllReloadEventSequence = 0;
    DriverDbgPrint("[NTDLL-TRACK] Ntdll tracking initialized (max %d entries)\n",
        NTDLL_MAX_TRACKED_PROCESSES);
}

/* 清理 ntdll 追踪上下文 */
VOID NtdllTrackCleanup(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_NtdllTrackContext.Lock, &oldIrql);
    RtlZeroMemory(g_NtdllTrackContext.Entries, sizeof(g_NtdllTrackContext.Entries));
    g_NtdllTrackContext.Count = 0;
    KeReleaseSpinLock(&g_NtdllTrackContext.Lock, oldIrql);
    g_bNtdllReloadDetectionEnabled = FALSE;
    DriverDbgPrint("[NTDLL-TRACK] Ntdll tracking cleaned up\n");
}

/* 进程退出时清理其 ntdll 追踪条目。
 * 必须在进程退出回调中调用，否则 PID 复用会导致新进程的首次
 * ntdll 加载被误判为"重载"（因 ASLR 导致基地址不同）。
 *
 * 使用 hash-based 查找：从 hash 位置开始线性探测，只扫描必要的条目。
 * WOW64 进程可能有 System32 + SysWOW64 两条记录，需要扫描到第一个
 * 空槽位为止（相同 PID 的记录在 hash 链上相邻）。 */

static ULONG NtdllTrackHash(HANDLE ProcessId);

VOID NtdllTrackCleanupProcess(HANDLE ProcessId)
{
    KIRQL oldIrql;
    ULONG hash;
    ULONG probe;
    ULONG targetPid = (ULONG)(ULONG_PTR)ProcessId;
    BOOLEAN cleaned = FALSE;

    if (!g_bNtdllReloadDetectionEnabled)
        return;

    hash = NtdllTrackHash(ProcessId);

    KeAcquireSpinLock(&g_NtdllTrackContext.Lock, &oldIrql);

    /* 从 hash 位置开始线性探测，清除该 PID 的所有条目。
     * 遇到空槽位（ImageBase == 0）时停止：相同 PID 的条目在 hash 链上
     * 相邻，空槽位之后不可能再有该 PID 的条目。 */
    for (probe = 0; probe < NTDLL_MAX_TRACKED_PROCESSES; probe++)
    {
        ULONG idx = (hash + probe) % NTDLL_MAX_TRACKED_PROCESSES;

        if (g_NtdllTrackContext.Entries[idx].ImageBase == 0)
        {
            /* 空槽位：该 PID 的条目已全部清除 */
            break;
        }

        if (g_NtdllTrackContext.Entries[idx].ProcessId == targetPid)
        {
            RtlZeroMemory(&g_NtdllTrackContext.Entries[idx],
                          sizeof(g_NtdllTrackContext.Entries[idx]));
            if (g_NtdllTrackContext.Count > 0)
                g_NtdllTrackContext.Count--;
            cleaned = TRUE;
        }
    }

    KeReleaseSpinLock(&g_NtdllTrackContext.Lock, oldIrql);

    if (cleaned)
    {
        DriverDbgPrint("[NTDLL-TRACK] Cleaned entries for exited PID=%lu\n", targetPid);
    }
}

/* 计算哈希值用于快速查找 */
static ULONG NtdllTrackHash(HANDLE ProcessId)
{
    return (ULONG)((ULONG_PTR)ProcessId % NTDLL_MAX_TRACKED_PROCESSES);
}

/* 检查路径是否为系统目录中的 ntdll.dll */
static BOOLEAN NtdllTrackIsSystemPath(PCWSTR path)
{
    UNICODE_STRING sysDir;
    UNICODE_STRING sys32Dir;
    UNICODE_STRING sysWOW64Dir;
    UNICODE_STRING usPath;

    if (!path || path[0] == L'\0')
        return FALSE;

    RtlInitUnicodeString(&sysDir, L"\\SystemRoot\\System32\\ntdll.dll");
    RtlInitUnicodeString(&sys32Dir, L"\\System32\\ntdll.dll");
    RtlInitUnicodeString(&sysWOW64Dir, L"\\SysWOW64\\ntdll.dll");
    RtlInitUnicodeString(&usPath, path);

    if (RtlEqualUnicodeString(&sysDir, &usPath, TRUE) ||
        RtlEqualUnicodeString(&sys32Dir, &usPath, TRUE) ||
        RtlEqualUnicodeString(&sysWOW64Dir, &usPath, TRUE))
    {
        return TRUE;
    }

    /* 检查路径是否包含 System32 或 SysWOW64 */
    if (wcsstr(path, L"System32") || wcsstr(path, L"SysWOW64"))
    {
        /* 进一步检查是否以 ntdll.dll 结尾 */
        size_t len = wcslen(path);
        if (len >= 10 && _wcsicmp(path + len - 10, L"ntdll.dll") == 0)
        {
            return TRUE;
        }
    }

    return FALSE;
}

/* 发送 ntdll 重载事件到用户态（Fire-and-Forget） */
static VOID NtdllTrackSendEvent(
    HANDLE ProcessId,
    ULONG_PTR ImageBase,
    ULONG ImageSize,
    ULONG LoadSequence,
    ULONG Flags,
    PCWSTR FullPath,
    PNTDLL_TRACK_ENTRY pPrevEntry)
{
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;
    NTDLL_RELOAD_EVENT_DATA* pEventData = NULL;

    if (!g_pDriverDeviceObject)
        return;

    request = (PRESPONSE_REQUEST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'NtDl');
    if (request == NULL)
    {
        DriverDbgPrint("[NTDLL-TRACK] Failed to allocate request\n");
        return;
    }

    RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));
    KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
    request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
    request->RuleType = RULE_TYPE_NTDLL_RELOAD;
    request->ProcessPid = (INT)(ULONG_PTR)ProcessId;
    request->FireAndForget = TRUE;
    request->FullPath = NULL;
    request->ValueName = NULL;
    request->NewValueData = NULL;

    pEventData = (PNTDLL_RELOAD_EVENT_DATA)&request->BehaviorAlert;
    RtlZeroMemory(pEventData, sizeof(NTDLL_RELOAD_EVENT_DATA));

    pEventData->ProcessId = (INT64)(ULONG_PTR)ProcessId;
    pEventData->ImageBase = ImageBase;
    pEventData->ImageSize = ImageSize;
    pEventData->LoadSequence = LoadSequence;
    pEventData->Flags = Flags;
    pEventData->IsHooked = (Flags & NTDLL_RELOAD_FLAG_UNHOOK) ? 1 : 0;
    pEventData->ReloadCount = (pPrevEntry) ? pPrevEntry->LoadSequence : 0;
    pEventData->EventSequence = (INT64)InterlockedIncrement((volatile LONG *)&g_NtdllReloadEventSequence);

    /* 转换路径为 ANSI（使用 RtlUnicodeStringToAnsiString 正确转换，避免 WCHAR->CHAR 截断丢高位） */
    if (FullPath && FullPath[0] != L'\0')
    {
        UNICODE_STRING usPath;
        RtlInitUnicodeString(&usPath, FullPath);
        ANSI_STRING asPath;
        RtlZeroMemory(&asPath, sizeof(asPath));
        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&asPath, &usPath, TRUE)))
        {
            if (asPath.Length > 0 && asPath.Buffer)
            {
                int copyLen = asPath.Length;
                if (copyLen >= MAX_PATH) copyLen = MAX_PATH - 1;
                RtlCopyMemory(pEventData->FullImagePath, asPath.Buffer, copyLen);
                pEventData->FullImagePath[copyLen] = '\0';
            }
            RtlFreeAnsiString(&asPath);
        }
        pEventData->IsFromSystemPath = NtdllTrackIsSystemPath(FullPath) ? 1 : 0;
    }

    /* 获取进程名和完整路径 */
    {
        PEPROCESS proc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &proc)))
        {
            /* 先用 PsGetProcessImageFileName 作为兜底（返回 8.3 短名，OEM 编码，最长 15 字节）。
             * 对于含中文等非 ASCII 字符的进程名，短名会被截断/乱码，后续若成功获取完整路径则覆盖。 */
            UCHAR* pName = PsGetProcessImageFileName(proc);
            if (pName)
            {
                int i;
                for (i = 0; i < 15 && pName[i]; i++)
                {
                    pEventData->ProcessName[i] = (CHAR)pName[i];
                }
                pEventData->ProcessName[i] = '\0';
            }

            /* 获取进程完整路径 */
            HANDLE hProc = NULL;
            NTSTATUS qs = ObOpenObjectByPointer(proc, OBJ_KERNEL_HANDLE, NULL,
                PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProc);
            ObDereferenceObject(proc);

            if (NT_SUCCESS(qs) && hProc)
            {
                ULONG retLen = 0;
                ZwQueryInformationProcess(hProc, ProcessImageFileName, NULL, 0, &retLen);
                if (retLen > 0)
                {
                    PUNICODE_STRING pImgPath = (PUNICODE_STRING)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED, retLen, 'NtDp');
                    if (pImgPath)
                    {
                        qs = ZwQueryInformationProcess(hProc, ProcessImageFileName,
                            pImgPath, retLen, &retLen);
                        if (NT_SUCCESS(qs) && pImgPath->Buffer)
                        {
                            /* 使用 RtlUnicodeStringToAnsiString 正确转换，避免 WCHAR->CHAR 截断丢高位 */
                            ANSI_STRING asImgPath;
                            RtlZeroMemory(&asImgPath, sizeof(asImgPath));
                            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&asImgPath, pImgPath, TRUE)))
                            {
                                if (asImgPath.Length > 0 && asImgPath.Buffer)
                                {
                                    int copyLen = asImgPath.Length;
                                    if (copyLen >= MAX_PATH) copyLen = MAX_PATH - 1;
                                    RtlCopyMemory(pEventData->ProcessImagePath, asImgPath.Buffer, copyLen);
                                    pEventData->ProcessImagePath[copyLen] = '\0';

                                    /* 从完整路径中提取文件名（最后一个 '\' 或 '/' 之后的部分），
                                     * 覆盖 PsGetProcessImageFileName 返回的 8.3 短名，确保中文进程名正确。 */
                                    {
                                        CHAR* pBase = pEventData->ProcessImagePath;
                                        CHAR* pLast = pBase;
                                        for (int j = 0; j < copyLen && pBase[j]; j++)
                                        {
                                            if (pBase[j] == '\\' || pBase[j] == '/')
                                                pLast = &pBase[j + 1];
                                        }
                                        ULONG nameLen = (ULONG)(pBase + copyLen - pLast);
                                        if (nameLen >= sizeof(pEventData->ProcessName))
                                            nameLen = sizeof(pEventData->ProcessName) - 1;
                                        RtlCopyMemory(pEventData->ProcessName, pLast, nameLen);
                                        pEventData->ProcessName[nameLen] = '\0';
                                    }
                                }
                                RtlFreeAnsiString(&asImgPath);
                            }
                        }
                        ExFreePool(pImgPath);
                    }
                }
                ZwClose(hProc);
            }
        }
    }

    /* 获取父进程 PID */
    {
        PEPROCESS proc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &proc)))
        {
            pEventData->ParentProcessId = (INT64)(ULONG_PTR)
                PsGetProcessInheritedFromUniqueProcessId(proc);
            ObDereferenceObject(proc);
        }
    }

    /* 插入队列，不等待 */
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
    if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
    {
        /* 入队失败（队列满且全是同步请求），释放本请求 */
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        ExFreePool(request);
        return;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DriverDbgPrint("[NTDLL-TRACK] Event queued PID=%llu Base=%p Size=%u Flags=0x%X\n",
        (ULONGLONG)(ULONG_PTR)ProcessId, (PVOID)ImageBase, ImageSize, Flags);
}

/* 更新 ntdll 追踪记录并检测重载/Unhook
 *
 * 使用 hash-based 查找（从 hash 位置开始线性探测），避免 O(N) 全表扫描
 * 在 LoadImageNotifyRoutine 中持有自旋锁时造成性能问题。
 * 之前虽然计算了 hash 值，但搜索始终从索引 0 开始，等于退化成了全表扫描。
 * 现在改为从 hash 位置开始，平均查找时间从 O(N) 降到 O(1)。 */
BOOLEAN NtdllTrackUpdate(
    HANDLE ProcessId,
    ULONG_PTR ImageBase,
    ULONG ImageSize,
    PCWSTR FullPath,
    PNTDLL_TRACK_ENTRY pPrevEntry)
{
    UNREFERENCED_PARAMETER(pPrevEntry);
    KIRQL oldIrql;
    ULONG hash;
    ULONG slotIdx = 0;
    ULONG probe;
    BOOLEAN found = FALSE;
    BOOLEAN isNew = FALSE;
    ULONG flags = 0;
    ULONG emptySlot = (ULONG)-1;

    if (!g_bNtdllReloadDetectionEnabled)
        return FALSE;

    hash = NtdllTrackHash(ProcessId);

    KeAcquireSpinLock(&g_NtdllTrackContext.Lock, &oldIrql);

    /* 单次遍历：从 hash 位置开始线性探测，同时查找匹配条目和空槽位。
     * WOW64 进程会同时加载 64 位 (System32) 和 32 位 (SysWOW64) ntdll，
     * 路径不同属于正常行为，必须分别跟踪，否则第二次加载会被误判为重载。 */
    for (probe = 0; probe < NTDLL_MAX_TRACKED_PROCESSES; probe++)
    {
        ULONG idx = (hash + probe) % NTDLL_MAX_TRACKED_PROCESSES;

        if (g_NtdllTrackContext.Entries[idx].ImageBase == 0)
        {
            /* 记录第一个空槽位，继续搜索是否有匹配的 PID */
            if (emptySlot == (ULONG)-1)
                emptySlot = idx;
            continue;
        }

        if (g_NtdllTrackContext.Entries[idx].ProcessId == (ULONG)(ULONG_PTR)ProcessId)
        {
            /* 进程匹配后再校验路径：仅相同路径才视为同一 ntdll 实例的重载 */
            if (FullPath && FullPath[0] != L'\0' &&
                g_NtdllTrackContext.Entries[idx].FullPath[0] != L'\0')
            {
                UNICODE_STRING usExisting, usNew;
                RtlInitUnicodeString(&usExisting, g_NtdllTrackContext.Entries[idx].FullPath);
                RtlInitUnicodeString(&usNew, FullPath);
                if (RtlEqualUnicodeString(&usExisting, &usNew, TRUE))
                {
                    found = TRUE;
                    slotIdx = idx;
                    break;
                }
                /* 路径不同（如 System32 vs SysWOW64），继续查找下一条目 */
            }
            else
            {
                /* 无路径信息时回退到仅按 PID 匹配（向后兼容） */
                found = TRUE;
                slotIdx = idx;
                break;
            }
        }
    }

    if (!found)
    {
        if (emptySlot != (ULONG)-1)
        {
            /* 使用探测到的空槽位 */
            slotIdx = emptySlot;
            isNew = TRUE;
            found = TRUE;
        }
        else
        {
            /* 表已满：替换 hash 位置的条目，但视为新条目处理，
             * 避免将不相关进程的旧记录误判为当前进程的"重载"。 */
            slotIdx = hash;
            isNew = TRUE;
        }
    }

    /* 检查是否为重载：仅当条目已记录过至少一次加载（LoadSequence > 0）
     * 且属于同一进程实例时，才进行重载判定。首次加载不报重载。 */
    if (!isNew && g_NtdllTrackContext.Entries[slotIdx].ImageBase != 0 &&
        g_NtdllTrackContext.Entries[slotIdx].LoadSequence > 0)
    {
        PNTDLL_TRACK_ENTRY pEntry = &g_NtdllTrackContext.Entries[slotIdx];

        /* 基地址变化：同一进程中 ntdll 被重新加载 */
        if (pEntry->ImageBase != ImageBase)
        {
            flags |= NTDLL_RELOAD_FLAG_REMAP;
        }

        /* 大小变化 */
        if (pEntry->ImageSize != 0 && pEntry->ImageSize != ImageSize)
        {
            flags |= NTDLL_RELOAD_FLAG_REMAP;
        }

        /* 路径变化 */
        if (pEntry->FullPath[0] != L'\0' && FullPath && FullPath[0] != L'\0')
        {
            UNICODE_STRING usEntryPath;
            UNICODE_STRING usFullPath;
            RtlInitUnicodeString(&usEntryPath, pEntry->FullPath);
            RtlInitUnicodeString(&usFullPath, FullPath);
            if (!RtlEqualUnicodeString(&usEntryPath, &usFullPath, TRUE))
            {
                flags |= NTDLL_RELOAD_FLAG_PATH;
            }
        }

        /* 非系统路径加载 */
        if (FullPath && FullPath[0] != L'\0')
        {
            if (!NtdllTrackIsSystemPath(FullPath))
            {
                flags |= NTDLL_RELOAD_FLAG_PATH;
            }
        }

        /* 启发式判断是否被 hook：路径异常 + 大小异常 */
        if ((flags & (NTDLL_RELOAD_FLAG_REMAP | NTDLL_RELOAD_FLAG_PATH)) != 0)
        {
            flags |= NTDLL_RELOAD_FLAG_UNHOOK;
        }
    }

    /* 在更新前捕获前一个条目的状态快照，用于 NtdllTrackSendEvent
     * 正确填充 ReloadCount（重载前的加载序列号）。
     * 调用者 LoadImageNotifyRoutine 传入的 pPrevEntry 始终为 NULL，
     * 因此必须在此处内部捕获。 */
    NTDLL_TRACK_ENTRY prevEntryState = { 0 };
    if (!isNew && g_NtdllTrackContext.Entries[slotIdx].ImageBase != 0)
    {
        RtlCopyMemory(&prevEntryState, &g_NtdllTrackContext.Entries[slotIdx],
                      sizeof(NTDLL_TRACK_ENTRY));
    }

    /* 更新记录 */
    if (isNew)
    {
        g_NtdllTrackContext.Count++;
        /* 新条目：重置加载序列，从 1 开始（首次加载） */
        g_NtdllTrackContext.Entries[slotIdx].LoadSequence = 0;
        g_NtdllTrackContext.Entries[slotIdx].FullPath[0] = L'\0';
    }

    g_NtdllTrackContext.Entries[slotIdx].ProcessId = (ULONG)(ULONG_PTR)ProcessId;
    g_NtdllTrackContext.Entries[slotIdx].ImageBase = ImageBase;
    g_NtdllTrackContext.Entries[slotIdx].ImageSize = ImageSize;
    g_NtdllTrackContext.Entries[slotIdx].LoadSequence++;
    g_NtdllTrackContext.Entries[slotIdx].Flags = flags;

    if (FullPath && FullPath[0] != L'\0')
    {
        RtlStringCbCopyW(g_NtdllTrackContext.Entries[slotIdx].FullPath,
            sizeof(g_NtdllTrackContext.Entries[slotIdx].FullPath), FullPath);
    }

    KeReleaseSpinLock(&g_NtdllTrackContext.Lock, oldIrql);

    /* 如果检测到重载标志，发送事件。
     * 传入 prevEntryState 快照，使 NtdllTrackSendEvent 能正确填充
     * ReloadCount（重载前的加载序列号），而非始终为 0。 */
    if (flags != 0)
    {
        NtdllTrackSendEvent(ProcessId, ImageBase, ImageSize,
            g_NtdllTrackContext.Entries[slotIdx].LoadSequence, flags, FullPath,
            (prevEntryState.ImageBase != 0) ? &prevEntryState : NULL);
    }

    return (flags != 0);
}

/* 判断是否为 ntdll.dll */
static BOOLEAN IsNtdllImage(_In_ PUNICODE_STRING FullImageName)
{
    UNICODE_STRING ntdllName;
    USHORT ntdllLen;
    PWCHAR tail;
    UNICODE_STRING tailStr;

    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0)
        return FALSE;

    RtlInitUnicodeString(&ntdllName, L"ntdll.dll");
    ntdllLen = ntdllName.Length;

    if (FullImageName->Length < ntdllLen)
        return FALSE;

    tail = (PWCHAR)((PUCHAR)FullImageName->Buffer + FullImageName->Length - ntdllLen);
    tailStr.Buffer = tail;
    tailStr.Length = ntdllLen;
    tailStr.MaximumLength = ntdllLen;

    return RtlEqualUnicodeString(&ntdllName, &tailStr, TRUE);
}

/* 判断是否为 kernel32.dll */
static BOOLEAN IsKernel32Image(_In_ PUNICODE_STRING FullImageName)
{
    UNICODE_STRING ksName;
    USHORT ksLen;
    PWCHAR tail;
    UNICODE_STRING tailStr;

    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length == 0)
        return FALSE;

    RtlInitUnicodeString(&ksName, L"kernel32.dll");
    ksLen = ksName.Length;

    if (FullImageName->Length < ksLen)
        return FALSE;

    tail = (PWCHAR)((PUCHAR)FullImageName->Buffer + FullImageName->Length - ksLen);
    tailStr.Buffer = tail;
    tailStr.Length = ksLen;
    tailStr.MaximumLength = ksLen;

    return RtlEqualUnicodeString(&ksName, &tailStr, TRUE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * VdTerminateProcessByPid — 漏洞驱动拦截专用进程终止入口
 *
 * 复用 TerminateProcessByPid 的内核句柄 + BreakOnTermination 保护逻辑。
 * 供 VulnerableDriver.c 在检测到漏洞驱动加载时终止发起加载的进程。
 * 仅在 PASSIVE_LEVEL 调用。
 * ═══════════════════════════════════════════════════════════════════════════ */
NTSTATUS VdTerminateProcessByPid(INT64 pid)
{
    PEPROCESS process;
    NTSTATUS status;

    if (pid <= 4)
        return STATUS_SUCCESS;

    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
    if (!NT_SUCCESS(status))
        return status;

    /* 关键系统进程保护：绝不终止已知关键进程 */
    if (IsCriticalSystemProcess(process)) {
        DriverDbgPrint("[VULN-DRIVER] Terminate SKIPPED critical process PID=%lld\n", pid);
        ObDereferenceObject(process);
        return STATUS_SUCCESS;
    }

    HANDLE hProcess = NULL;
    status = ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, NULL,
        0x0001 | 0x0400, /* PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION */
        *PsProcessType, KernelMode, &hProcess);
    if (NT_SUCCESS(status) && hProcess) {
        if (QueryProcessCritical(hProcess)) {
            DriverDbgPrint("[VULN-DRIVER] PID=%lld has BreakOnTermination, skip termination\n", pid);
        } else if (g_pfnNtTerminateProcess) {
            g_pfnNtTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
        }
        ZwClose(hProcess);
    }
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}