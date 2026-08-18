#pragma once
#include "../shared/Common.h"

// 受保护PID列表结构
typedef struct _PROTECTED_PID_LIST {
    HANDLE Pids[MAX_PROTECTED_PIDS];
    ULONG Count;
    KSPIN_LOCK Lock;
} PROTECTED_PID_LIST, *PPROTECTED_PID_LIST;

NTSTATUS InitializeProtectedPidsList();
VOID CleanupProtectedPidsList();
BOOLEAN IsPidProtected(HANDLE Pid);
NTSTATUS AddPidToProtectedList(HANDLE Pid);
NTSTATUS RemovePidFromProtectedList(HANDLE Pid);
OB_PREOP_CALLBACK_STATUS NTAPI HandleProcessProtectCallBack(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation);

// 线程保护回调 — 拦截跨进程线程操作（SetThreadContext/SuspendThread/QueueUserAPC）
OB_PREOP_CALLBACK_STATUS NTAPI HandleThreadProtectCallBack(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION OperationInformation);

// ── 线程创建通知回调（PsSetCreateThreadNotifyRoutine）──
// 检测远程线程创建：当创建线程的进程 != 目标进程时，判定为注入行为
// 这是检测 CreateRemoteThread / NtCreateThreadEx 跨进程注入最直接的手段
VOID NTAPI ThreadCreateNotifyRoutine(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create);

// 镜像加载通知回调（PsSetLoadImageNotifyRoutine）——
// 在 kernel32.dll 加载时通过 kernel APC + user-mode APC 注入 R3 DLL，
// 无固定延迟；注入时机仍在 main/WinMain 之前，早于任何 R3 hook
VOID NTAPI LoadImageNotifyRoutine(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);

// ── R0 独立进程创建检查（R3 未启用时）──
// 解析进程挂起/恢复/终止 API
VOID ResolveProcessManipulationApis(VOID);

// 进程启动检查：挂起新进程并排队 work item 等待用户态决策
VOID ProcessStartCheck(
    INT64 pid,
    INT64 parentPid,
    const CHAR* processPath,
    const CHAR* imageName);

// 签名程序加载未签名 DLL 检查：排队 work item 等待用户态决策
VOID QueueDllScanWorkItem(
    INT64 pid,
    const WCHAR* dllPath,
    const CHAR* processPath,
    BOOLEAN blocking,
    BOOLEAN isSideLoad);

// ── 已初始化进程 PID 跟踪（区分初始线程创建 vs 远程线程注入）──
// 当 ThreadCreateNotifyRoutine 检测到父→子线程创建时，通过此集合判断
// 是合法初始线程（首次）还是远程线程注入（已初始化后再次创建线程）。
#define MAX_INITIALIZED_PIDS    256

typedef struct _INITIALIZED_PID_LIST {
    HANDLE Pids[MAX_INITIALIZED_PIDS];
    ULONG Count;
    KSPIN_LOCK Lock;
} INITIALIZED_PID_LIST, *PINITIALIZED_PID_LIST;

VOID InitializeInitializedPidsList(VOID);
VOID CleanupInitializedPidsList(VOID);
BOOLEAN IsProcessInitialized(HANDLE Pid);
VOID MarkProcessInitialized(HANDLE Pid);
VOID RemoveProcessInitialized(HANDLE Pid);

// ── Ntdll 重载/Unhook 检测 ──
#define NTDLL_MAX_TRACKED_PROCESSES  1024
#define NTDLL_RELOAD_FLAG_UNHOOK     0x00000001
#define NTDLL_RELOAD_FLAG_REMAP      0x00000002
#define NTDLL_RELOAD_FLAG_PATH       0x00000004

typedef struct _NTDLL_TRACK_ENTRY {
    ULONG_PTR    ImageBase;
    ULONG        ImageSize;
    ULONG        LoadSequence;
    ULONG        Flags;
    ULONG        ProcessId;           // Owner PID for lookup
    WCHAR        FullPath[MAX_PATH];
} NTDLL_TRACK_ENTRY, *PNTDLL_TRACK_ENTRY;

typedef struct _NTDLL_TRACK_CONTEXT {
    NTDLL_TRACK_ENTRY Entries[NTDLL_MAX_TRACKED_PROCESSES];
    ULONG             Count;
    KSPIN_LOCK        Lock;
} NTDLL_TRACK_CONTEXT, *PNTDLL_TRACK_CONTEXT;

VOID NtdllTrackInitialize(VOID);
VOID NtdllTrackCleanup(VOID);
// 进程退出时清理 ntdll 追踪条目，避免 PID 复用导致误报重载
VOID NtdllTrackCleanupProcess(HANDLE ProcessId);
BOOLEAN NtdllTrackUpdate(
    HANDLE ProcessId,
    ULONG_PTR ImageBase,
    ULONG ImageSize,
    PCWSTR FullPath,
    PNTDLL_TRACK_ENTRY pPrevEntry);