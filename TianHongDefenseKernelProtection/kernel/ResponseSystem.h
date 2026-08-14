#pragma once
#include "../shared/Common.h"

// 响应缓存条目：按 (ProcessPid, RuleId) 缓存上次响应
typedef struct _RESPONSE_CACHE_ENTRY {
    HANDLE ProcessPid;
    int RuleId;
    NTSTATUS LastResponse;  // STATUS_SUCCESS = 允许, STATUS_ACCESS_DENIED = 阻止
    BOOLEAN Valid;
} RESPONSE_CACHE_ENTRY;

#define MAX_RESPONSE_CACHE 64

/* 请求队列最大长度：超过此限制时，丢弃最旧的 FireAndForget 请求，
 * 防止队列无限制增长导致池内存耗尽和 IOCTL 响应超时。
 * 同步等待请求（非 FireAndForget）入队时若队列已满，返回错误。 */
#define MAX_REQUEST_QUEUE_SIZE 256

NTSTATUS InitializeResponseSystem();
VOID CleanupResponseSystem();
NTSTATUS HandleUserResponse(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
NTSTATUS GetPendingRequest(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack);
NTSTATUS AskClientForResponse(
    _In_ int RuleId,
    _In_ int RuleType,
    _In_ int ProcessPid,
    _In_ PUNICODE_STRING FullPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID NewValueData,
    _In_ ULONG NewValueSize,
    _In_ ULONG ValueType);

// 行为分析实时告警
NTSTATUS AskClientForBehaviorResponse(
    _In_ INT64 Pid,
    _In_ const CHAR* ProcessPath,
    _In_ const CHAR* ThreatClass,
    _In_ const CHAR* Description,
    _In_ DOUBLE Confidence,
    _In_ const BEHAVIOR_DETECTED_RESPONSE* AlertInfo);

// 威胁回滚确认（收集→询问用户→执行）
// 调用者提供已收集的 rollbackList，函数将列表发送到用户态等待用户选择，
// 用户决策通过 outSelection 返回（0=忽略, 1=回滚 + 选中项）。
// 返回 STATUS_SUCCESS=用户已响应, 其他=超时/失败（outSelection.decision=0 忽略）
NTSTATUS AskClientForRollbackConfirm(
    _In_ const BA_ROLLBACK_LIST* rollbackList,
    _Out_ BA_ROLLBACK_SELECTION* outSelection);

// 用户态文件签名验证（已迁移到内核态 CI.DLL 直接调用）
NTSTATUS CiVerifyFileObject(_In_ struct _FILE_OBJECT* FileObject, _Out_ PBOOLEAN IsSigned);

// 签名缓存控制
VOID SignatureCacheSetEnabled(BOOLEAN enabled);
BOOLEAN SignatureCacheIsEnabled();
VOID SignatureCacheClear();
VOID SignatureCacheRemoveFile(_In_ const CHAR* FilePath);
BOOLEAN SignatureCacheLookup(
    _In_ const CHAR* FilePath,
    _In_ ULONGLONG FileSize,
    _In_ ULONGLONG LastWriteTime,
    _Out_opt_ PBOOLEAN IsSigned,
    _Out_opt_ PNTSTATUS VerifyStatus);
VOID SignatureCacheAdd(
    _In_ const CHAR* FilePath,
    _In_ ULONGLONG FileSize,
    _In_ ULONGLONG LastWriteTime,
    _In_ BOOLEAN IsSigned,
    _In_ NTSTATUS VerifyStatus);

// Kernel EA 读写
NTSTATUS SignatureEaRead(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_opt_ PBOOLEAN IsSigned,
    _Out_opt_ PNTSTATUS VerifyStatus,
    _Out_opt_ PBOOLEAN EaHit);
NTSTATUS SignatureEaWrite(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ BOOLEAN IsSigned,
    _In_ NTSTATUS VerifyStatus);

// CI.DLL 接口
NTSTATUS CiInitialize(VOID);
VOID CiCleanup(VOID);

// 行为分析日志发送（Fire-and-Forget，不等待响应，仅记录到客户端）
VOID SendBehaviorLog(
    _In_ INT64 Pid,
    _In_ const CHAR* ProcessPath,
    _In_ const CHAR* ThreatClass,
    _In_ const CHAR* Description,
    _In_ DOUBLE Confidence,
    _In_ const BEHAVIOR_DETECTED_RESPONSE* AlertInfo);

// 驱动注入日志发送（Fire-and-Forget，不等待响应，转发到main.cpp日志显示）
VOID SendInjectionLog(
    _In_ const CHAR* Message);

// 响应缓存控制
VOID ResponseCacheSetEnabled(BOOLEAN enabled);
BOOLEAN ResponseCacheIsEnabled();
VOID ResponseCacheClear();
// 进程退出时移除其缓存条目，防止PID复用导致决策被错误继承
VOID ResponseCacheRemovePid(HANDLE procId);

// 取消所有待处理请求（驱动卸载时调用，唤醒所有等待线程）
VOID ResponseSystemCancelAll(VOID);

// 带队列大小限制的请求入队（由 ProcessCallback.c 等调用方使用）
NTSTATUS EnqueueRequest(
    _In_ PRESPONSE_REQUEST request,
    _In_ KLOCK_QUEUE_HANDLE* lockHandle);
