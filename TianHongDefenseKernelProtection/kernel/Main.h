#pragma once
#include "../shared/Common.h"
#include "ProcessCallback.h"  // 需要 PROTECTED_PID_LIST 类型

// 全局变量声明
extern PROTECTED_PID_LIST g_ProtectedPids;
extern PVOID g_ProcessRegistrationHandle;
extern PVOID g_ProcessCreateNotifyHandle;
extern PVOID g_ThreadCreateNotifyHandle;  /* PsSetCreateThreadNotifyRoutine 注册句柄 */
extern PVOID g_LoadImageNotifyHandle;      /* PsSetLoadImageNotifyRoutine 注册句柄 */
extern WCHAR g_DllInjectPath[260];         /* 待注入的 DLL 路径 */
extern BOOLEAN g_bDllInjectPathSet;         /* DLL 路径是否已设置 */
extern BOOLEAN g_bR3ProtectionEnabled;      /* R3 DLL 防护是否启用（TRUE 时才允许 DLL 注入） */
extern BOOLEAN g_bProcessProtectionEnabled; /* R0 独立进程创建检查是否启用（R3 未启用时生效） */
extern BOOLEAN g_bSilentModeEnabled;        /* 静默模式是否启用（TRUE 时行为分析直接阻止，不弹窗） */
extern BOOLEAN g_bUnsignedDllScanEnabled;   /* 签名程序加载未签名 DLL 扫描是否启用 */
extern BOOLEAN g_bDllBlockingScanEnabled;   /* 签名程序加载未签名 DLL 扫描是否阻塞（TRUE=阻塞等待扫描结果） */
extern BOOLEAN g_bMemoryProtectionEnabled;  /* 内存防护（句柄剥离/注入拦截）是否启用 */
extern BOOLEAN g_bDcomDetectionEnabled;    /* DCOM 横向移动检测是否启用 */
extern BOOLEAN g_bSilverFoxEnabled;        /* SilverFox 检测（文件隐藏+图片PE）是否启用 */
extern BOOLEAN g_bAVBypassEnabled;         /* AVBypass 检测（ETW/InstrumentationCallback 绕过）是否启用 */
extern HANDLE g_TrustedMainPid;              /* 受信任主程序 PID（用于注入检测白名单，防止自误报） */
extern LARGE_INTEGER g_RegCookie;
extern KSPIN_LOCK g_RegCallbackLock;          /* 保护 CmRegisterCallback 竞态条件 */
extern KSPIN_LOCK g_RequestQueueLock;
extern LIST_ENTRY g_RequestQueueHead;
extern KEVENT g_RequestAvailableEvent;
extern volatile LONG g_RequestQueueCount;       /* 请求队列计数器（追踪当前队列中的请求数量） */
extern RULE_DATA g_Rules[MAX_RULES];
extern ULONG g_RuleCount;
extern KSPIN_LOCK g_RulesLock;
extern RULE_FILE_DATA g_FileRules[MAX_FILE_RULES];
extern ULONG g_FileRuleCount;
extern ULONG g_TotalBlockedOperations;
extern ULONG g_TotalAllowedOperations;
extern PDEVICE_OBJECT g_pDriverDeviceObject; /* 驱动设备对象，用于内核态 IOCTL */

// ── 已初始化进程 PID 跟踪（区分初始线程创建 vs 远程线程注入）──
extern INITIALIZED_PID_LIST g_InitializedPids;

// ── Ntdll 重载/Unhook 检测全局变量 ──
extern NTDLL_TRACK_CONTEXT g_NtdllTrackContext;
extern BOOLEAN g_bNtdllReloadDetectionEnabled;  /* Ntdll 重载检测是否启用 */
extern ULONG g_NtdllReloadEventSequence;          /* 事件序列号 */

// 函数声明
VOID DriverDbgPrint(__in PCSTR Format, ...);
NTSTATUS StringToULong(PCHAR str, PULONG result);
NTSTATUS StringToUlong64(PCHAR str, PULONG64 result);
NTSTATUS CreateDriverObject(IN PDRIVER_OBJECT pDriver);
VOID DriverUnload(PDRIVER_OBJECT pDriver);
VOID NTAPI ProcessCreateNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create);