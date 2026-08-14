/*++
Copyright (c) 2024  TianHong Security Defense

Module Name:
    FileFilter.c

Abstract:
    File system minifilter driver for file operation interception.
    Uses Filter Manager to attach to volumes, intercepts IRP_MJ_CREATE,
    IRP_MJ_WRITE, etc., and enforces security rules.

Environment:
    Kernel mode
--*/

#include "../shared/Common.h"
#include "Main.h"
#include "FileFilter.h"
#include "KernelRuleEngine.h"
#include "ResponseSystem.h"
#include "BehaviorAnalysis.h"
#include "ProcessCallback.h"
#include "RegistryCallback.h"

// 未导出内核 API 声明
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

/* ── PE 相关常量回退定义（ntimage.h 可能未完全导出）── */
#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE  0x5A4D
#endif

/* ── File信息类常量回退（新SDK才导出，旧SDK编译时需手动指定）── */
#ifndef FileSecurityInformation
#define FileSecurityInformation  ((ULONG)17)
#endif
#ifndef FileSecurityInformationEx
#define FileSecurityInformationEx  ((ULONG)258)
#endif
#ifndef WRITE_DAC
#define WRITE_DAC  0x00040000L
#endif
#ifndef WRITE_OWNER
#define WRITE_OWNER  0x00080000L
#endif

// 外部全局变量
extern RULE_FILE_DATA g_FileRules[MAX_FILE_RULES];
extern ULONG g_FileRuleCount;
extern ULONG g_TotalBlockedOperations;
extern ULONG g_TotalAllowedOperations;

// --------------------------------------------------------------------------
// 全局数据
// --------------------------------------------------------------------------
PFLT_FILTER g_FilterHandle = NULL;

// 同步对象（规则与缓存）
static KSPIN_LOCK g_RuleLock;
static KSPIN_LOCK g_CacheLock;

// LRU 命中缓存
#define CACHE_SIZE 8
typedef struct _MATCH_CACHE_ENTRY {
    UNICODE_STRING Path;
    FILE_OPERATION Operation;
    int            MatchedRuleId;
    BOOLEAN        Valid;
    LARGE_INTEGER  LastAccess;
} MATCH_CACHE_ENTRY;
static MATCH_CACHE_ENTRY g_MatchCache[CACHE_SIZE] = { 0 };

// --------------------------------------------------------------------------
// 函数原型
// --------------------------------------------------------------------------

// 路径解析（在文件末尾定义，此处为前向声明）
static NTSTATUS DiskFilterGetPathComponents(
    _In_ PUNICODE_STRING FullPath,
    _Out_opt_ PUNICODE_STRING* Directory,
    _Out_opt_ PUNICODE_STRING* FileName,
    _Out_opt_ PUNICODE_STRING* Extension);

// 规则匹配
static BOOLEAN FileFilterMatchRules(
    _In_ PUNICODE_STRING FilePath,
    _In_ FILE_OPERATION Operation,
    _Out_ int* pMatchedRuleId);

// 签名验证（内存缓存 -> Kernel EA -> 用户态）
static NTSTATUS VerifyFileSignatureWithCache(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PVOID FltObjectsContext,
    _Out_ PBOOLEAN IsSigned);

// Instance 回调
static NTSTATUS FileFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

static VOID FileFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

static VOID FileFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

static NTSTATUS FileFilterQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

// 预操作回调
static FLT_PREOP_CALLBACK_STATUS FileFilterPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS FileFilterPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

static FLT_PREOP_CALLBACK_STATUS FileFilterPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext);

static FLT_PREOP_CALLBACK_STATUS FileFilterPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext);

static FLT_POSTOP_CALLBACK_STATUS FileFilterPostDirControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

// 操作处理
static NTSTATUS FileFilterHandleCreate(_In_ PFLT_INSTANCE Instance, _Inout_ PFLT_CALLBACK_DATA Data);
static NTSTATUS FileFilterHandleOperation(_In_ PFLT_INSTANCE Instance, _Inout_ PFLT_CALLBACK_DATA Data, _In_ FILE_OPERATION Operation);

// 安全判断当前进程是否为系统进程（minifilter 回调可能在 APC_LEVEL，不能调用 Zw*）
static BOOLEAN IsCurrentProcessSystemSafe(VOID)
{
    HANDLE currentPid = PsGetCurrentProcessId();
    /* PID 4 = System, PID 0 = Idle。minifilter 回调中调用 ZwOpenProcessTokenEx 可能因 IRQL 导致 bug check，
     * 因此使用 PID 快速判断。 */
    return (currentPid == (HANDLE)4 || currentPid == (HANDLE)0);
}

/* 判断是否为网络文件系统（MUP/UNC）。对网络卷做 FltGetFileNameInformation 等操作
 * 容易引发递归、死锁或 MUP_FILE_SYSTEM 蓝屏，因此直接跳过。
 * 注意：_FLT_RELATED_OBJECTS 没有 FileSystem 成员，通过 FileObject 的设备对象判断。 */
static BOOLEAN FileFilterIsNetworkVolume(_In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    if (FltObjects == NULL)
        return FALSE;

    if (FltObjects->FileObject != NULL && FltObjects->FileObject->DeviceObject != NULL)
        return (FltObjects->FileObject->DeviceObject->DeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM);

    return FALSE;
}

/* 检查 RuleId 对应的规则是否为勒索诱捕规则（通过 Description 字段判断）。
 * 用于 Paging IO 时区分勒索诱捕文件和普通文件规则。 */
static BOOLEAN IsRansomHoneypotRule(int ruleId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN result = FALSE;
    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &lockHandle);
    for (ULONG i = 0; i < g_FileRuleCount; i++) {
        if (g_FileRules[i].RuleId == (ULONG)ruleId) {
            result = (strstr(g_FileRules[i].Description, "RansomHoneypot") != NULL);
            break;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return result;
}

// --------------------------------------------------------------------------
// 回调结构表
// --------------------------------------------------------------------------
const FLT_OPERATION_REGISTRATION g_OperationCallbacks[] = {
    { IRP_MJ_CREATE, 0, FileFilterPreCreate, FileFilterPostCreate },
    { IRP_MJ_WRITE,  0, FileFilterPreWrite, 0 },
    { IRP_MJ_SET_INFORMATION, 0, FileFilterPreSetInformation, 0 },
    { IRP_MJ_DIRECTORY_CONTROL, 0, 0, FileFilterPostDirControl },
    { IRP_MJ_OPERATION_END }
};

// ============================================================================
// FileFilterInitialize - Minifilter 初始化
// ============================================================================
NTSTATUS FileFilterInitialize(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    FLT_REGISTRATION fltReg = { 0 };

    fltReg.Size = sizeof(FLT_REGISTRATION);
    fltReg.Version = FLT_REGISTRATION_VERSION;
    fltReg.Flags = 0;
    fltReg.OperationRegistration = (PFLT_OPERATION_REGISTRATION)g_OperationCallbacks;
    fltReg.InstanceSetupCallback = (PFLT_INSTANCE_SETUP_CALLBACK)FileFilterInstanceSetup;
    fltReg.InstanceQueryTeardownCallback = (PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK)FileFilterQueryTeardown;
    fltReg.InstanceTeardownStartCallback = (PFLT_INSTANCE_TEARDOWN_CALLBACK)FileFilterInstanceTeardownStart;
    fltReg.InstanceTeardownCompleteCallback = (PFLT_INSTANCE_TEARDOWN_CALLBACK)FileFilterInstanceTeardownComplete;

    // 初始化自旋锁
    KeInitializeSpinLock(&g_RuleLock);
    KeInitializeSpinLock(&g_CacheLock);
    RtlZeroMemory(g_MatchCache, sizeof(g_MatchCache));

    // 向 Filter Manager 注册 minifilter
    status = FltRegisterFilter(DriverObject, &fltReg, &g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        DriverDbgPrint("FltRegisterFilter failed: 0x%X\n", status);
        return status;
    }

    // 开始过滤
    status = FltStartFiltering(g_FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        DriverDbgPrint("FltStartFiltering failed: 0x%X\n", status);
        return status;
    }

    DriverDbgPrint("FileFilter (minifilter) initialized successfully\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// VerifyFileSignatureWithCache - 签名验证（内存缓存 -> Kernel EA -> CI.DLL）
// ============================================================================
static NTSTATUS VerifyFileSignatureWithCache(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ PVOID FltObjectsContext,
    _Out_ PBOOLEAN IsSigned)
{
    NTSTATUS status;
    BOOLEAN eaHit = FALSE;
    CHAR pathA[MAX_PATH_LEN] = { 0 };
    ULONGLONG fileSize = 0;
    ULONGLONG lastWriteTime = 0;
    PFLT_CALLBACK_DATA data = (PFLT_CALLBACK_DATA)FltObjectsContext;

    if (IsSigned == NULL || NameInfo == NULL || Instance == NULL || data == NULL)
        return STATUS_INVALID_PARAMETER;

    *IsSigned = FALSE;

    if (NameInfo->Name.Length == 0 || NameInfo->Name.Buffer == NULL)
        return STATUS_NOT_SUPPORTED;

    {
        int len = (int)(NameInfo->Name.Length / sizeof(WCHAR));
        if (len >= MAX_PATH_LEN) len = MAX_PATH_LEN - 1;
        for (int i = 0; i < len; i++)
            pathA[i] = (CHAR)(NameInfo->Name.Buffer[i]);
        pathA[len] = '\0';
    }

    if (pathA[0] == '\0')
        return STATUS_NOT_SUPPORTED;

    if (data->Iopb && data->Iopb->TargetFileObject)
    {
        FILE_STANDARD_INFORMATION stdInfo = { 0 };
        if (FltQueryInformationFile(
                Instance,
                data->Iopb->TargetFileObject,
                &stdInfo,
                sizeof(stdInfo),
                FileStandardInformation,
                NULL) == STATUS_SUCCESS)
        {
            fileSize = (ULONGLONG)stdInfo.EndOfFile.QuadPart;
        }

        {
            FILE_BASIC_INFORMATION basicInfo = { 0 };
            if (FltQueryInformationFile(
                    Instance,
                    data->Iopb->TargetFileObject,
                    &basicInfo,
                    sizeof(basicInfo),
                    FileBasicInformation,
                    NULL) == STATUS_SUCCESS)
            {
                lastWriteTime = basicInfo.LastWriteTime.QuadPart;
            }
        }
    }

    if (SignatureCacheLookup(pathA, fileSize, lastWriteTime, IsSigned, &status))
    {
        DriverDbgPrint("VerifyFileSignatureWithCache: Cache HIT for %s, Signed=%d\n",
            pathA, *IsSigned);
        return STATUS_SUCCESS;
    }

    {
        BOOLEAN eaSigned = FALSE;
        NTSTATUS eaStatus = STATUS_NOT_FOUND;
        status = SignatureEaRead(Instance, NameInfo, &eaSigned, &eaStatus, &eaHit);
        if (NT_SUCCESS(status) && eaHit)
        {
            *IsSigned = eaSigned;
            SignatureCacheAdd(pathA, fileSize, lastWriteTime, eaSigned, eaStatus);
            DriverDbgPrint("VerifyFileSignatureWithCache: EA HIT for %s, Signed=%d\n",
                pathA, *IsSigned);
            return STATUS_SUCCESS;
        }
    }

    if (data->Iopb && data->Iopb->TargetFileObject)
    {
        status = CiVerifyFileObject(data->Iopb->TargetFileObject, IsSigned);
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("VerifyFileSignatureWithCache: CI verify failed for %s, status=0x%X\n",
                pathA, status);
            *IsSigned = FALSE;
            return status;
        }

        if (SignatureCacheIsEnabled())
        {
            SignatureCacheAdd(pathA, fileSize, lastWriteTime, *IsSigned, STATUS_SUCCESS);
        }

        {
            NTSTATUS writeStatus = SignatureEaWrite(Instance, NameInfo, *IsSigned, STATUS_SUCCESS);
            if (!NT_SUCCESS(writeStatus))
            {
                DriverDbgPrint("VerifyFileSignatureWithCache: EA write failed for %s, status=0x%X\n",
                    pathA, writeStatus);
            }
        }

        DriverDbgPrint("VerifyFileSignatureWithCache: CI verified %s, Signed=%d\n",
            pathA, *IsSigned);

        return STATUS_SUCCESS;
    }

    return STATUS_NOT_SUPPORTED;
}

// ============================================================================
// FileFilterUnloadWrapper - 卸载 minifilter
// ============================================================================
VOID FileFilterUnloadWrapper()
{
    if (g_FilterHandle != NULL) {
        KLOCK_QUEUE_HANDLE lockHandle;
        // 释放缓存内存
        KeAcquireInStackQueuedSpinLock(&g_CacheLock, &lockHandle);
        for (int i = 0; i < CACHE_SIZE; i++) {
            if (g_MatchCache[i].Valid && g_MatchCache[i].Path.Buffer) {
                ExFreePool(g_MatchCache[i].Path.Buffer);
            }
        }
        RtlZeroMemory(g_MatchCache, sizeof(g_MatchCache));
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        FltUnregisterFilter(g_FilterHandle);
        g_FilterHandle = NULL;
        DriverDbgPrint("FileFilter (minifilter) unloaded\n");
    }
}

// ============================================================================
// InstanceSetup
// ============================================================================
static NTSTATUS FileFilterInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    /* 不附加到网络文件系统（MUP/UNC），避免 MUP_FILE_SYSTEM 蓝屏。
     * 同时预操作回调也会再次过滤，做双重保险。 */
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
    {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// InstanceTeardownStart
// ============================================================================
static VOID FileFilterInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// ============================================================================
// InstanceTeardownComplete
// ============================================================================
static VOID FileFilterInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
}

// ============================================================================
// QueryTeardown
// ============================================================================
static NTSTATUS FileFilterQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

// ============================================================================
// FileFilterPreCreate - IRP_MJ_CREATE 预操作回调
// ============================================================================
static FLT_PREOP_CALLBACK_STATUS FileFilterPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext)
{
    __try {
        if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        *CompletionContext = NULL;

        if (Data->Iopb->IrpFlags & IRP_PAGING_IO) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (FileFilterIsNetworkVolume(FltObjects)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* 受信任主程序自身操作（如重建/清理勒索诱捕文件）放行，避免自误报 */
        if (g_TrustedMainPid != NULL &&
            (HANDLE)(ULONG_PTR)PsGetCurrentProcessId() == g_TrustedMainPid) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        NTSTATUS handleStatus = FileFilterHandleCreate(FltObjects->Instance, Data);

        if (handleStatus == STATUS_ACCESS_DENIED) {
            /* Rule hit: block the operation */
            return FLT_PREOP_COMPLETE;
        }

        /* Check if this create has file-creation disposition.
         * If so, request post-operation callback to track FILE_CREATED events. */
        {
            ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
            if (createDisposition == FILE_CREATE ||
                createDisposition == FILE_OVERWRITE_IF ||
                createDisposition == FILE_SUPERSEDE)
            {
                return FLT_PREOP_SUCCESS_WITH_CALLBACK;
            }
        }

        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[FILEFILTER] Exception in FileFilterPreCreate, allowing\n");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

// ============================================================================
// FileFilterPostCreate - IRP_MJ_CREATE 后操作回调
// Tracks FILE_CREATED events for threat cleanup (new files dropped by processes)
// ============================================================================
static FLT_POSTOP_CALLBACK_STATUS FileFilterPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    __try {
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        NTSTATUS status;

        if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        UNREFERENCED_PARAMETER(FltObjects);
        UNREFERENCED_PARAMETER(CompletionContext);

        if (Flags & FLTFL_POST_OPERATION_DRAINING) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* Only track if the create actually created a new file */
        if (!NT_SUCCESS(Data->IoStatus.Status) ||
            Data->IoStatus.Information != FILE_CREATED)
        {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        status = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP,
            &nameInfo);
        if (!NT_SUCCESS(status) || !nameInfo) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* Record the dropped file for threat cleanup */
        {
            INT64 pid = (INT64)(ULONG_PTR)PsGetCurrentProcessId();
            BehaviorRecordDroppedFile(pid, &nameInfo->Name);
        }

        FltReleaseFileNameInformation(nameInfo);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[FILEFILTER] Exception in FileFilterPostCreate, finishing\n");
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
}

// ============================================================================
// FileFilterPreWrite - IRP_MJ_WRITE 预操作回调
// ============================================================================
static FLT_PREOP_CALLBACK_STATUS FileFilterPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext)
{
    __try {
        if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        UNREFERENCED_PARAMETER(CompletionContext);

        if (Data->Iopb->IrpFlags & IRP_PAGING_IO) {
            /* Paging IO（内存映射写回 / Cache Manager 延迟写入）：
             * 不能阻塞等待用户响应，但需阻止对勒索诱捕文件的写入。
             * 检查目标文件是否匹配 RansomHoneypot 规则，若匹配则直接阻止 +
             * 通过 FireAndForget 发送告警，由用户态终止进程。
             * 跳过系统进程（PID 4 = System, PID 0 = Idle），避免误拦 Cache Manager 写回。 */
            if (IsCurrentProcessSystemSafe()) {
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            PFLT_FILE_NAME_INFORMATION pagingNameInfo = NULL;
            NTSTATUS pagingStatus = FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &pagingNameInfo);
            if (NT_SUCCESS(pagingStatus) && pagingNameInfo) {
                int pagingRuleId = 0;
                if (FileFilterMatchRules(&pagingNameInfo->Name, FILE_OPERATION_WRITE, &pagingRuleId) &&
                    IsRansomHoneypotRule(pagingRuleId)) {
                    INT64 pagingPid = (INT64)(ULONG_PTR)PsGetCurrentProcessId();
                    CHAR alertMsg[256];
                    RtlStringCbPrintfA(alertMsg, sizeof(alertMsg),
                        "[勒索防护-PAGING] PID=%lld", pagingPid);
                    SendInjectionLog(alertMsg);
                    FltReleaseFileNameInformation(pagingNameInfo);
                    InterlockedIncrement((LONG volatile*)&g_TotalBlockedOperations);
                    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
                    Data->IoStatus.Information = 0;
                    return FLT_PREOP_COMPLETE;
                }
                FltReleaseFileNameInformation(pagingNameInfo);
            }
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (FileFilterIsNetworkVolume(FltObjects)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* 受信任主程序自身操作（如重建/清理勒索诱捕文件）放行，避免自误报 */
        if (g_TrustedMainPid != NULL &&
            (HANDLE)(ULONG_PTR)PsGetCurrentProcessId() == g_TrustedMainPid) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        NTSTATUS handleStatus = FileFilterHandleOperation(FltObjects->Instance, Data, FILE_OPERATION_WRITE);
        return (handleStatus == STATUS_ACCESS_DENIED)
            ? FLT_PREOP_COMPLETE : FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[FILEFILTER] Exception in FileFilterPreWrite, allowing\n");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

// ============================================================================
// FileFilterPreSetInformation - IRP_MJ_SET_INFORMATION 预操作回调
// ============================================================================
static FLT_PREOP_CALLBACK_STATUS FileFilterPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Out_ PVOID *CompletionContext)
{
    __try {
        if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        UNREFERENCED_PARAMETER(CompletionContext);

        if (Data->Iopb->IrpFlags & IRP_PAGING_IO) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        if (FileFilterIsNetworkVolume(FltObjects)) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* 受信任主程序自身操作（如重建/清理勒索诱捕文件）放行，避免自误报 */
        if (g_TrustedMainPid != NULL &&
            (HANDLE)(ULONG_PTR)PsGetCurrentProcessId() == g_TrustedMainPid) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        FILE_OPERATION op;
        ULONG infoBufferLength = Data->Iopb->Parameters.SetFileInformation.Length;
        PVOID infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
        ULONG infoClass = (ULONG)Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

        /* CVE-2021-41379：FileSecurityInformation(17)/FileSecurityInformationEx(258) 修改DACL */
        if (infoClass == 17 || infoClass == 258)
        {
            PFLT_FILE_NAME_INFORMATION secNameInfo = NULL;
            PUNICODE_STRING secDir = NULL, secFileName = NULL;
            NTSTATUS secStatus = FltGetFileNameInformation(Data,
                FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &secNameInfo);
            if (NT_SUCCESS(secStatus) && secNameInfo)
            {
                PUNICODE_STRING secFullPath = &secNameInfo->Name;
                DiskFilterGetPathComponents(secFullPath, &secDir, &secFileName, NULL);

                INT64 curPid = (INT64)(ULONG_PTR)PsGetCurrentProcessId();
                UCHAR* curProcName = PsGetProcessImageFileName(PsGetCurrentProcess());
                CHAR curName[16] = {0};
                if (curProcName) {
                    int ni = 0;
                    while (curProcName[ni] && ni < 15) { curName[ni++] = (CHAR)curProcName[ni]; }
                    curName[ni] = '\0';
                }
                CHAR dirBuf[BA_MAX_PATH] = {0};
                if (secDir) {
                    int dlen = (int)(secDir->Length / sizeof(WCHAR));
                    if (dlen >= BA_MAX_PATH) dlen = BA_MAX_PATH - 1;
                    for (int di = 0; di < dlen; di++) dirBuf[di] = (CHAR)secDir->Buffer[di];
                    dirBuf[dlen] = '\0';
                }
                CHAR pathBuf[BA_MAX_PATH] = {0};
                if (secFullPath) {
                    int plen = (int)(secFullPath->Length / sizeof(WCHAR));
                    if (plen >= BA_MAX_PATH) plen = BA_MAX_PATH - 1;
                    for (int pi = 0; pi < plen; pi++) pathBuf[pi] = (CHAR)secFullPath->Buffer[pi];
                    pathBuf[plen] = '\0';
                }

                if (dirBuf[0] && (kStrStrLen(dirBuf, (int)kStrLen(dirBuf), "program files", 13) ||
                                  kStrStrLen(dirBuf, (int)kStrLen(dirBuf), "\\windows\\", 9)))
                {
                    BOOLEAN procSigned = BaIsProcessSigned(curPid);
                    if (!procSigned) {
                        CHAR evidence[256];
                        RtlStringCbPrintfA(evidence, sizeof(evidence),
                            "CVE-2021-41379: Unsigned process %s(PID:%lld) modifying DACL on %s",
                            curName, curPid, pathBuf);
                        BehaviorRecordPrivilegeEscalationIndicator(
                            curPid, curName, pathBuf,
                            BA_IND_PROC_DACL_MODIFY, evidence);
                    }
                }
            }
            if (secNameInfo) FltReleaseFileNameInformation(secNameInfo);
            if (secDir) ExFreePool(secDir);
            if (secFileName) ExFreePool(secFileName);
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        /* Minifilter 中 SET_INFORMATION 参数在 SetFileInformation 联合体中 */
        switch (infoClass) {
        case FileDispositionInformation:
            if (infoBuffer == NULL || infoBufferLength < sizeof(FILE_DISPOSITION_INFORMATION))
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            if (((PFILE_DISPOSITION_INFORMATION)infoBuffer)->DeleteFile)
                op = FILE_OPERATION_DELETE;
            else
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            break;
        case FileDispositionInformationEx:
            if (infoBuffer == NULL || infoBufferLength < sizeof(FILE_DISPOSITION_INFORMATION_EX))
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            if (((PFILE_DISPOSITION_INFORMATION_EX)infoBuffer)->Flags & FILE_DISPOSITION_DELETE)
                op = FILE_OPERATION_DELETE;
            else
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            break;
        case FileRenameInformation:
        case FileRenameInformationEx:
            op = FILE_OPERATION_RENAME;
            break;
        /* FileEndOfFileInformation / FileAllocationInformation 可截断文件为 0 字节，
         * 勒索软件常用于在写入加密内容前清空原文件。映射到 WRITE 操作触发规则匹配。 */
        case FileEndOfFileInformation:
        case FileAllocationInformation:
            op = FILE_OPERATION_WRITE;
            break;
        default:
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        NTSTATUS handleStatus = FileFilterHandleOperation(FltObjects->Instance, Data, op);
        return (handleStatus == STATUS_ACCESS_DENIED)
            ? FLT_PREOP_COMPLETE : FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[FILEFILTER] Exception in FileFilterPreSetInformation, allowing\n");
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
}

// ============================================================================
// FileFilterPostDirControl - IRP_MJ_DIRECTORY_CONTROL 后操作回调
// 当 explorer.exe 枚举目录时，从结果中过滤掉勒索诱捕文件，使其不可见。
// 仅过滤 Description="RansomHoneypot"（非 Dir）且 FileName 为具体文件名的规则。
// ============================================================================
static FLT_POSTOP_CALLBACK_STATUS FileFilterPostDirControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    __try {
        if (Data == NULL || Data->Iopb == NULL || FltObjects == NULL) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        UNREFERENCED_PARAMETER(CompletionContext);

        if (Flags & FLTFL_POST_OPERATION_DRAINING) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 仅处理 IRP_MN_QUERY_DIRECTORY（目录枚举查询） */
        if (Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 仅处理成功完成的请求 */
        if (!NT_SUCCESS(Data->IoStatus.Status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 受信任主程序自身操作放行（如重建/清理诱捕文件） */
        if (g_TrustedMainPid != NULL &&
            (HANDLE)(ULONG_PTR)PsGetCurrentProcessId() == g_TrustedMainPid) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 仅对 explorer.exe 过滤诱捕文件。
         * PsGetProcessImageFileName 返回 8.3 短名，explorer.exe 不含中文，短名与长名一致。 */
        {
            PEPROCESS currentProc = PsGetCurrentProcess();
            if (currentProc == NULL) {
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
            UCHAR* procName = PsGetProcessImageFileName(currentProc);
            if (procName == NULL) {
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
            if (_stricmp((const char*)procName, "explorer.exe") != 0) {
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
        }

        /* 获取被枚举的目录路径 */
        PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
        NTSTATUS nameStatus = FltGetFileNameInformation(Data,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
        if (!NT_SUCCESS(nameStatus) || nameInfo == NULL) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 收集需要隐藏的文件名（来自 RansomHoneypot 规则，非 Dir 类型，且 FileName 非 "*"）。
         * 最多收集 64 个文件名，足够覆盖典型诱捕场景。 */
        #define MAX_HIDE_NAMES 64
        ANSI_STRING hideNames[MAX_HIDE_NAMES];
        int hideCount = 0;
        CHAR dirPathBuf[520] = {0};

        /* 将目录路径转为 ANSI 便于比较 */
        {
            ANSI_STRING dirAnsi;
            RtlZeroMemory(&dirAnsi, sizeof(dirAnsi));
            if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&dirAnsi, &nameInfo->Name, TRUE))) {
                if (dirAnsi.Length > 0 && dirAnsi.Buffer) {
                    int copyLen = dirAnsi.Length;
                    if (copyLen >= (int)sizeof(dirPathBuf) - 1) copyLen = sizeof(dirPathBuf) - 1;
                    RtlCopyMemory(dirPathBuf, dirAnsi.Buffer, copyLen);
                    dirPathBuf[copyLen] = '\0';
                }
                RtlFreeAnsiString(&dirAnsi);
            }
        }

        FltReleaseFileNameInformation(nameInfo);

        if (dirPathBuf[0] == '\0') {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 遍历规则，收集与当前目录匹配的诱捕文件名。
         * 注意：rule->FullPath 来自用户态（如 "C:\Users\..."），
         * dirPathBuf 来自 FltGetFileNameInformation 内核格式
         * （如 "\Device\HarddiskVolume3\Users\..."），需归一化后比较。 */
        {
            KLOCK_QUEUE_HANDLE lockHandle;
            KeAcquireInStackQueuedSpinLock(&g_RuleLock, &lockHandle);
            for (ULONG i = 0; i < g_FileRuleCount && hideCount < MAX_HIDE_NAMES; i++) {
                RULE_FILE_DATA* rule = &g_FileRules[i];
                /* 仅匹配 RansomHoneypot（非 RansomHoneypotDir）规则 */
                if (strstr(rule->Description, "RansomHoneypot") == NULL ||
                    strstr(rule->Description, "Dir") != NULL)
                    continue;
                /* FileName 为 "*" 表示目录级规则，不隐藏整个目录内容 */
                if (rule->FileName[0] == '\0' || strcmp(rule->FileName, "*") == 0)
                    continue;

                /* 归一化规则路径：跳过驱动器号前缀 "C:" 等 */
                const CHAR* ruleTail = rule->FullPath;
                if (ruleTail[0] && ruleTail[1] == ':' && ruleTail[2] == '\\')
                    ruleTail += 2;  /* 保留反斜杠，如 "\Users\..." */

                /* 归一化目录路径：跳过 "\Device\HarddiskVolumeX" 内核卷前缀 */
                const CHAR* dirTail = dirPathBuf;
                if (_strnicmp(dirTail, "\\Device\\HarddiskVolume", 22) == 0) {
                    dirTail += 22;
                    while (*dirTail >= '0' && *dirTail <= '9') dirTail++;
                }

                /* 比较归一化后的路径（不区分大小写） */
                if (_stricmp(ruleTail, dirTail) == 0) {
                    /* 初始化 ANSI_STRING 指向规则中的 FileName */
                    RtlInitAnsiString(&hideNames[hideCount], rule->FileName);
                    hideCount++;
                }
            }
            KeReleaseInStackQueuedSpinLock(&lockHandle);
        }

        if (hideCount == 0) {
            return FLT_POSTOP_FINISHED_PROCESSING;
        }

        /* 遍历目录信息缓冲区，隐藏匹配的文件名。
         * 支持常见的目录信息类型，通过 NextEntryOffset 链表遍历。 */
        {
            FILE_INFORMATION_CLASS infoClass =
                Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
            PVOID buffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
            ULONG bufferLen = (ULONG)Data->IoStatus.Information;

            if (buffer == NULL || bufferLen == 0) {
                return FLT_POSTOP_FINISHED_PROCESSING;
            }

            /* 根据信息类确定 FileName 字段偏移和 NextEntryOffset 偏移 */
            ULONG nextEntryOffset = 0;
            ULONG fileNameOffset = 0;

            switch (infoClass) {
                case FileDirectoryInformation:
                    nextEntryOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, NextEntryOffset);
                    fileNameOffset = FIELD_OFFSET(FILE_DIRECTORY_INFORMATION, FileName);
                    break;
                case FileFullDirectoryInformation:
                    nextEntryOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, NextEntryOffset);
                    fileNameOffset = FIELD_OFFSET(FILE_FULL_DIR_INFORMATION, FileName);
                    break;
                case FileBothDirectoryInformation:
                    nextEntryOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, NextEntryOffset);
                    fileNameOffset = FIELD_OFFSET(FILE_BOTH_DIR_INFORMATION, FileName);
                    break;
                case FileIdBothDirectoryInformation:
                    nextEntryOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, NextEntryOffset);
                    fileNameOffset = FIELD_OFFSET(FILE_ID_BOTH_DIR_INFORMATION, FileName);
                    break;
                case FileIdFullDirectoryInformation:
                    nextEntryOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, NextEntryOffset);
                    fileNameOffset = FIELD_OFFSET(FILE_ID_FULL_DIR_INFORMATION, FileName);
                    break;
                case FileNamesInformation:
                    nextEntryOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, NextEntryOffset);
                    fileNameOffset = FIELD_OFFSET(FILE_NAMES_INFORMATION, FileName);
                    break;
                default:
                    /* 不支持的信息类，不过滤 */
                    return FLT_POSTOP_FINISHED_PROCESSING;
            }

            /* 遍历链表，通过将前一个条目的 NextEntryOffset 指向后一个条目来"删除"当前条目 */
            PVOID prevEntry = NULL;
            ULONG offset = 0;

            while (offset < bufferLen) {
                PVOID currentEntry = (PUCHAR)buffer + offset;
                ULONG nextOffset = *(PULONG)((PUCHAR)currentEntry + nextEntryOffset);

                /* 获取当前条目的文件名并转为 ANSI 进行比较 */
                BOOLEAN shouldHide = FALSE;
                {
                    UNICODE_STRING entryFileName;
                    entryFileName.Buffer = (PWCH)((PUCHAR)currentEntry + fileNameOffset);
                    /* 文件名长度字段在 fileNameOffset - sizeof(USHORT) 处 */
                    USHORT nameLen = *(PUSHORT)((PUCHAR)currentEntry + fileNameOffset - sizeof(USHORT));
                    entryFileName.Length = nameLen;
                    entryFileName.MaximumLength = nameLen;

                    ANSI_STRING entryAnsi;
                    RtlZeroMemory(&entryAnsi, sizeof(entryAnsi));
                    if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&entryAnsi, &entryFileName, TRUE))) {
                        for (int h = 0; h < hideCount; h++) {
                            if (RtlEqualString(&entryAnsi, &hideNames[h], TRUE)) {
                                shouldHide = TRUE;
                                break;
                            }
                        }
                        RtlFreeAnsiString(&entryAnsi);
                    }
                }

                if (shouldHide) {
                    /* 隐藏当前条目：将前一个条目的 NextEntryOffset 跳过当前条目 */
                    if (prevEntry != NULL) {
                        if (nextOffset == 0) {
                            /* 当前是最后一个条目，前一个成为最后 */
                            *(PULONG)((PUCHAR)prevEntry + nextEntryOffset) = 0;
                        } else {
                            *(PULONG)((PUCHAR)prevEntry + nextEntryOffset) =
                                (ULONG)((PUCHAR)currentEntry - (PUCHAR)prevEntry) + nextOffset;
                        }
                    } else {
                        /* 当前是第一个条目 */
                        if (nextOffset == 0) {
                            /* 唯一条目，返回空结果 */
                            Data->IoStatus.Status = STATUS_NO_SUCH_FILE;
                            Data->IoStatus.Information = 0;
                            return FLT_POSTOP_FINISHED_PROCESSING;
                        } else {
                            /* 将缓冲区内容前移，跳过第一个条目 */
                            ULONG remaining = bufferLen - offset - nextOffset;
                            if (remaining > 0) {
                                RtlMoveMemory(buffer,
                                    (PUCHAR)buffer + offset + nextOffset,
                                    remaining);
                            }
                            bufferLen -= (offset + nextOffset);
                            Data->IoStatus.Information = bufferLen;
                            /* 重新从开头遍历，因为缓冲区已前移 */
                            offset = 0;
                            prevEntry = NULL;
                            continue;
                        }
                    }
                    DriverDbgPrint("[FILEFILTER] Hidden honeypot file from explorer directory enumeration\n");
                } else {
                    prevEntry = currentEntry;
                }

                if (nextOffset == 0) break;
                offset += nextOffset;
            }
        }

        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[FILEFILTER] Exception in FileFilterPostDirControl, allowing\n");
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
}

// ============================================================================
// FileFilterHandleCreate - 创建文件处理
// ============================================================================
static NTSTATUS FileFilterHandleCreate(_In_ PFLT_INSTANCE Instance, _Inout_ PFLT_CALLBACK_DATA Data)
{
    PFILE_OBJECT fileObject;
    NTSTATUS status;
    int matchedRuleId = 0;
    int processId;

    if (Data == NULL || Data->Iopb == NULL)
        return STATUS_INVALID_PARAMETER;

    fileObject = Data->Iopb->TargetFileObject;
    if (!fileObject)
        return STATUS_NOT_SUPPORTED;

    /* FltGetFileNameInformation 返回 PFLT_FILE_NAME_INFORMATION，
     * 路径在 ->Name 字段中（UNICODE_STRING）。
     * PostCreate 使用 QUERY_DEFAULT：此时文件已打开，可安全查询文件系统，
     * 并由 Filter Manager 缓存文件名，供后续 PreWrite 用 ALWAYS_ALLOW_CACHE_LOOKUP 获取。 */
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo)
        return STATUS_NOT_SUPPORTED;

    PUNICODE_STRING fullPath = &nameInfo->Name;
    PUNICODE_STRING directory = NULL, fileName = NULL, extension = NULL;

    DiskFilterGetPathComponents(fullPath, &directory, &fileName, &extension);

    // 行为分析
    {
        INT64 pid = (INT64)(ULONG_PTR)PsGetCurrentProcessId();
        UCHAR* procName = PsGetProcessImageFileName(PsGetCurrentProcess());
        CHAR imageName[64] = { 0 }, pathA[BA_MAX_PATH] = { 0 }, dirA[BA_MAX_PATH] = { 0 };
        CHAR nameA[BA_MAX_NAME] = { 0 }, extA[16] = { 0 };

        if (procName) {
            int i;
            for (i = 0; i < 15 && procName[i]; i++) imageName[i] = (CHAR)procName[i];
            imageName[i] = '\0';
        }
        if (fullPath) {
            int len = (int)(fullPath->Length / sizeof(WCHAR));
            if (len >= BA_MAX_PATH) len = BA_MAX_PATH - 1;
            for (int i = 0; i < len; i++) pathA[i] = (CHAR)(fullPath->Buffer[i]);
            pathA[len] = '\0';
        }
        if (directory) {
            int len = (int)(directory->Length / sizeof(WCHAR));
            if (len >= BA_MAX_PATH) len = BA_MAX_PATH - 1;
            for (int i = 0; i < len; i++) dirA[i] = (CHAR)(directory->Buffer[i]);
            dirA[len] = '\0';
        }
        if (fileName) {
            int len = (int)(fileName->Length / sizeof(WCHAR));
            if (len >= BA_MAX_NAME) len = BA_MAX_NAME - 1;
            for (int i = 0; i < len; i++) nameA[i] = (CHAR)(fileName->Buffer[i]);
            nameA[len] = '\0';
        }
        if (extension) {
            int len = (int)(extension->Length / sizeof(WCHAR));
            if (len >= 16) len = 15;
            for (int i = 0; i < len; i++) extA[i] = (CHAR)(extension->Buffer[i]);
            extA[len] = '\0';
        }

        /* 验证文件签名（内存缓存 -> Kernel EA -> 用户态） */
        BOOLEAN isSigned = FALSE;
        if (pathA[0] && fullPath && Instance)
        {
            NTSTATUS verifyStatus = VerifyFileSignatureWithCache(
                Instance, nameInfo, Data, &isSigned);
            if (!NT_SUCCESS(verifyStatus))
            {
                isSigned = FALSE;
            }
        }

        /* 获取文件属性（隐藏/系统/只读等） */
        UCHAR fileAttrs = 0;
        if (pathA[0] && Data->Iopb && Data->Iopb->TargetFileObject)
        {
            FILE_BASIC_INFORMATION basicInfo = { 0 };
            if (FltQueryInformationFile(
                    Instance,
                    Data->Iopb->TargetFileObject,
                    &basicInfo,
                    sizeof(basicInfo),
                    FileBasicInformation,
                    NULL) == STATUS_SUCCESS)
            {
                fileAttrs = (UCHAR)basicInfo.FileAttributes;
            }
        }

        /* 读取文件头前2字节判断是否为 PE 可执行文件 */
        BOOLEAN isPeFile = FALSE;
        /* 注意：不在 minifilter 回调中做同步 I/O（IoCreateFileEx/ZwReadFile），
         * 避免 IRP 重入导致的双重异常（Double Fault 0x7f）。
         * isPeFile 默认 FALSE，由行为分析异步线程通过路径检查补全。 */

        /* ── CVE-2021-41379 检测：非签名进程以 WRITE_DAC/WRITE_OWNER 访问 Program Files 文件 ──
         * 攻击者通过 msiexec.exe 或其他进程修改系统目录中二进制文件的 DACL，
         * 然后将恶意代码注入到服务二进制文件中实现提权。 */
        if (pathA[0] && !isSigned) {
            BOOLEAN isInSystemDir = kStrStrLen(dirA, (int)kStrLen(dirA), "program files", 13) ||
                                    kStrStrLen(dirA, (int)kStrLen(dirA), "\\windows\\", 9);
            if (isInSystemDir) {
                CHAR cveEvidence[256];
                RtlStringCbPrintfA(cveEvidence, sizeof(cveEvidence),
                    "CVE-2021-41379: Unsigned %s(PID:%lld) file access in system dir %s",
                    imageName, pid, pathA);
                BehaviorRecordPrivilegeEscalationIndicator(
                    pid, imageName, pathA,
                    BA_IND_PROC_DACL_MODIFY, cveEvidence);
            }
        }

        BehaviorRecordFileEvent(pid, imageName, pathA, dirA, nameA, extA, BA_FOP_Create, isSigned, fileAttrs, isPeFile);
    }

    // Determine create intent from disposition and desired access
    // BUGFIX: was checking WRITE/DELETE/RENAME rules on every IRP_MJ_CREATE,
    // causing false positives (e.g. launching cmd.exe from System32 triggered
    // "System32 exe drop" WRITE rule). Now only check rules matching actual intent.
    {
        PIO_SECURITY_CONTEXT secCtx = Data->Iopb->Parameters.Create.SecurityContext;
        ACCESS_MASK desiredAccess = secCtx ? secCtx->DesiredAccess : 0;
        ULONG createDisposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
        ULONG createOptions = Data->Iopb->Parameters.Create.Options & 0x00FFFFFF;

        /* Write intent: creating/superseding/overwriting, or opening with write access */
        BOOLEAN hasWriteIntent = (createDisposition == FILE_SUPERSEDE) ||
                                 (createDisposition == FILE_CREATE) ||
                                 (createDisposition == FILE_OVERWRITE) ||
                                 (createDisposition == FILE_OVERWRITE_IF) ||
                                 (desiredAccess & (FILE_WRITE_DATA | FILE_APPEND_DATA |
                                                   WRITE_DAC | WRITE_OWNER |
                                                   FILE_WRITE_ATTRIBUTES));
        /* Delete intent: opening with DELETE access or FILE_DELETE_ON_CLOSE */
        BOOLEAN hasDeleteIntent = (desiredAccess & DELETE) ||
                                 (createOptions & FILE_DELETE_ON_CLOSE);
        /* RENAME is handled in FileFilterPreSetInformation, not on CREATE */

        BOOLEAN ruleMatched = FALSE;
        if (hasWriteIntent && FileFilterMatchRules(fullPath, FILE_OPERATION_WRITE, &matchedRuleId))
            ruleMatched = TRUE;
        else if (hasDeleteIntent && FileFilterMatchRules(fullPath, FILE_OPERATION_DELETE, &matchedRuleId))
            ruleMatched = TRUE;

        if (!ruleMatched) {
            FltReleaseFileNameInformation(nameInfo);
            if (directory) ExFreePool(directory);
            if (fileName) ExFreePool(fileName);
            if (extension) ExFreePool(extension);
            return STATUS_NOT_SUPPORTED;
        }
    }

    {
        processId = (int)(ULONG_PTR)PsGetCurrentProcessId();
        DriverDbgPrint("FileFilter(CREATE): Rule hit RuleId=%d, Path=%wZ, Pid=%d\n",
            matchedRuleId, fullPath, processId);

        /* Check SEcurity Flag: skip system processes for SEF_NOT_SYSTEM_BLOCKED */
        {
            SECURITY_FLAG sef = SEF_ALL_BLOCKED;
            KLOCK_QUEUE_HANDLE ruleLockHandle;
            KeAcquireInStackQueuedSpinLock(&g_RuleLock, &ruleLockHandle);
            for (ULONG i = 0; i < g_FileRuleCount; i++) {
                if (g_FileRules[i].RuleId == (ULONG)matchedRuleId) {
                    sef = g_FileRules[i].sef;
                    break;
                }
            }
            KeReleaseInStackQueuedSpinLock(&ruleLockHandle);
            if (sef != SEF_ALL_BLOCKED && IsCurrentProcessSystemSafe()) {
                DriverDbgPrint("FileFilter(CREATE): System process, skipped (sef=%d)\n", sef);
                FltReleaseFileNameInformation(nameInfo);
                if (directory) ExFreePool(directory);
                if (fileName) ExFreePool(fileName);
                if (extension) ExFreePool(extension);
                return STATUS_NOT_SUPPORTED;
            }
        }

        status = AskClientForResponse(
            matchedRuleId, RULE_TYPE_FILE, processId,
            fullPath, NULL, NULL, 0, 0);
        if (!NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
            InterlockedIncrement((LONG volatile*)&g_TotalBlockedOperations);
            FltReleaseFileNameInformation(nameInfo);
            if (directory) ExFreePool(directory);
            if (fileName) ExFreePool(fileName);
            if (extension) ExFreePool(extension);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return STATUS_ACCESS_DENIED;
        }
        else {
            InterlockedIncrement((LONG volatile*)&g_TotalAllowedOperations);
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    if (directory) ExFreePool(directory);
    if (fileName) ExFreePool(fileName);
    if (extension) ExFreePool(extension);
    return STATUS_NOT_SUPPORTED;
}

// ============================================================================
// FileFilterHandleOperation - 通用操作拦截
// ============================================================================
static NTSTATUS FileFilterHandleOperation(_In_ PFLT_INSTANCE Instance, _Inout_ PFLT_CALLBACK_DATA Data, _In_ FILE_OPERATION Operation)
{
    PFILE_OBJECT fileObject;
    NTSTATUS status;
    int matchedRuleId = 0;
    int processId;

    if (Data == NULL || Data->Iopb == NULL)
        return STATUS_INVALID_PARAMETER;

    fileObject = Data->Iopb->TargetFileObject;
    if (!fileObject)
        return STATUS_NOT_SUPPORTED;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo)
        return STATUS_NOT_SUPPORTED;

    PUNICODE_STRING fullPath = &nameInfo->Name;
    PUNICODE_STRING directory = NULL, fileName = NULL, extension = NULL;

    DiskFilterGetPathComponents(fullPath, &directory, &fileName, &extension);

    // 行为分析
    {
        INT64 pid = (INT64)(ULONG_PTR)PsGetCurrentProcessId();
        UCHAR* procName = PsGetProcessImageFileName(PsGetCurrentProcess());
        CHAR imageName[64] = { 0 }, pathA[BA_MAX_PATH] = { 0 }, dirA[BA_MAX_PATH] = { 0 };
        CHAR nameA[BA_MAX_NAME] = { 0 }, extA[16] = { 0 };

        if (procName) {
            int i;
            for (i = 0; i < 15 && procName[i]; i++) imageName[i] = (CHAR)procName[i];
            imageName[i] = '\0';
        }
        if (fullPath) {
            int len = (int)(fullPath->Length / sizeof(WCHAR));
            if (len >= BA_MAX_PATH) len = BA_MAX_PATH - 1;
            for (int i = 0; i < len; i++) pathA[i] = (CHAR)(fullPath->Buffer[i]);
            pathA[len] = '\0';
        }
        if (directory) {
            int len = (int)(directory->Length / sizeof(WCHAR));
            if (len >= BA_MAX_PATH) len = BA_MAX_PATH - 1;
            for (int i = 0; i < len; i++) dirA[i] = (CHAR)(directory->Buffer[i]);
            dirA[len] = '\0';
        }
        if (fileName) {
            int len = (int)(fileName->Length / sizeof(WCHAR));
            if (len >= BA_MAX_NAME) len = BA_MAX_NAME - 1;
            for (int i = 0; i < len; i++) nameA[i] = (CHAR)(fileName->Buffer[i]);
            nameA[len] = '\0';
        }
        if (extension) {
            int len = (int)(extension->Length / sizeof(WCHAR));
            if (len >= 16) len = 15;
            for (int i = 0; i < len; i++) extA[i] = (CHAR)(extension->Buffer[i]);
            extA[len] = '\0';
        }

        BA_FILE_OP baOp;
        switch (Operation) {
        case FILE_OPERATION_WRITE:  baOp = BA_FOP_Write; break;
        case FILE_OPERATION_DELETE: baOp = BA_FOP_Delete; break;
        case FILE_OPERATION_RENAME: baOp = BA_FOP_Modify; break;
        case FILE_OPERATION_READ:   baOp = BA_FOP_Read; break;
        default:                    baOp = BA_FOP_Create; break;
        }

        /* 验证文件签名（内存缓存 -> Kernel EA -> 用户态） */
        BOOLEAN isSigned = FALSE;
        if (pathA[0] && fullPath && Instance)
        {
            NTSTATUS verifyStatus = VerifyFileSignatureWithCache(
                Instance, nameInfo, Data, &isSigned);
            if (!NT_SUCCESS(verifyStatus))
            {
                isSigned = FALSE;
            }
        }

        BehaviorRecordFileEvent(pid, imageName, pathA, dirA, nameA, extA, baOp, isSigned, 0, FALSE);
    }

    if (FileFilterMatchRules(fullPath, Operation, &matchedRuleId)) {
        processId = (int)(ULONG_PTR)PsGetCurrentProcessId();
        DriverDbgPrint("FileFilter: Rule hit RuleId=%d, Op=%d, Path=%wZ, Pid=%d\n",
            matchedRuleId, Operation, fullPath, processId);

        /* Check SEcurity Flag: skip system processes for SEF_NOT_SYSTEM_BLOCKED */
        {
            SECURITY_FLAG sef = SEF_ALL_BLOCKED;
            KLOCK_QUEUE_HANDLE ruleLockHandle;
            KeAcquireInStackQueuedSpinLock(&g_RuleLock, &ruleLockHandle);
            for (ULONG i = 0; i < g_FileRuleCount; i++) {
                if (g_FileRules[i].RuleId == (ULONG)matchedRuleId) {
                    sef = g_FileRules[i].sef;
                    break;
                }
            }
            KeReleaseInStackQueuedSpinLock(&ruleLockHandle);
            if (sef != SEF_ALL_BLOCKED && IsCurrentProcessSystemSafe()) {
                DriverDbgPrint("FileFilter: System process, skipped (sef=%d)\n", sef);
                FltReleaseFileNameInformation(nameInfo);
                if (directory) ExFreePool(directory);
                if (fileName) ExFreePool(fileName);
                if (extension) ExFreePool(extension);
                return STATUS_NOT_SUPPORTED;
            }
        }

        status = AskClientForResponse(
            matchedRuleId, RULE_TYPE_FILE, processId,
            fullPath, NULL, NULL, 0, 0);
        if (!NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED) {
            InterlockedIncrement((LONG volatile*)&g_TotalBlockedOperations);
            FltReleaseFileNameInformation(nameInfo);
            if (directory) ExFreePool(directory);
            if (fileName) ExFreePool(fileName);
            if (extension) ExFreePool(extension);
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            return STATUS_ACCESS_DENIED;
        }
        else {
            InterlockedIncrement((LONG volatile*)&g_TotalAllowedOperations);
        }
    }

    FltReleaseFileNameInformation(nameInfo);
    if (directory) ExFreePool(directory);
    if (fileName) ExFreePool(fileName);
    if (extension) ExFreePool(extension);
    return STATUS_NOT_SUPPORTED;
}

// ============================================================================
// DiskFilterGetPathComponents - 解析目录、文件名、扩展名
// ============================================================================
static NTSTATUS DiskFilterGetPathComponents(
    _In_ PUNICODE_STRING FullPath,
    _Out_opt_ PUNICODE_STRING* Directory,
    _Out_opt_ PUNICODE_STRING* FileName,
    _Out_opt_ PUNICODE_STRING* Extension)
{
    if (!FullPath || FullPath->Buffer == NULL || FullPath->Length == 0 || (FullPath->Length % sizeof(WCHAR)) != 0)
        return STATUS_INVALID_PARAMETER;

    PWCHAR buffer = FullPath->Buffer;
    LONG len = FullPath->Length / sizeof(WCHAR);
    LONG slashPos = -1, dotPos = -1;

    for (LONG i = len - 1; i >= 0; i--) {
        if (buffer[i] == L'\\' || buffer[i] == L'/') {
            slashPos = i;
            break;
        }
    }

    if (Directory) {
        *Directory = NULL;
        if (slashPos >= 0) {
            USHORT dirLen = (USHORT)((slashPos + 1) * sizeof(WCHAR));
            PUNICODE_STRING dir = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'HtP');
            if (dir) {
                PWCHAR dirBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, dirLen + sizeof(WCHAR), 'HtP');
                if (dirBuf) {
                    RtlCopyMemory(dirBuf, buffer, dirLen);
                    dirBuf[dirLen / sizeof(WCHAR)] = L'\0';
                    dir->Buffer = dirBuf;
                    dir->Length = dirLen;
                    dir->MaximumLength = dirLen + sizeof(WCHAR);
                    *Directory = dir;
                }
                else {
                    ExFreePool(dir);
                }
            }
        }
    }

    if (FileName) {
        *FileName = NULL;
        PWCHAR nameStart = (slashPos >= 0) ? buffer + slashPos + 1 : buffer;
        LONG nameLen = (slashPos >= 0) ? (len - slashPos - 1) : len;
        if (nameLen > 0) {
            USHORT fnameLen = (USHORT)(nameLen * sizeof(WCHAR));
            PUNICODE_STRING fname = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'HtP');
            if (fname) {
                PWCHAR fnameBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, fnameLen + sizeof(WCHAR), 'HtP');
                if (fnameBuf) {
                    RtlCopyMemory(fnameBuf, nameStart, fnameLen);
                    fnameBuf[fnameLen / sizeof(WCHAR)] = L'\0';
                    fname->Buffer = fnameBuf;
                    fname->Length = fnameLen;
                    fname->MaximumLength = fnameLen + sizeof(WCHAR);
                    *FileName = fname;
                }
                else {
                    ExFreePool(fname);
                }
            }
        }
    }

    if (Extension) {
        *Extension = NULL;
        PWCHAR nameStart = (slashPos >= 0) ? buffer + slashPos + 1 : buffer;
        LONG nameLen = (slashPos >= 0) ? (len - slashPos - 1) : len;
        for (LONG i = nameLen - 1; i >= 0; i--) {
            if (nameStart[i] == L'.') {
                dotPos = i;
                break;
            }
        }
        if (dotPos >= 0) {
            USHORT extLen = (USHORT)((nameLen - dotPos) * sizeof(WCHAR));
            PUNICODE_STRING ext = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING), 'HtP');
            if (ext) {
                PWCHAR extBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, extLen + sizeof(WCHAR), 'HtP');
                if (extBuf) {
                    RtlCopyMemory(extBuf, nameStart + dotPos, extLen);
                    extBuf[extLen / sizeof(WCHAR)] = L'\0';
                    ext->Buffer = extBuf;
                    ext->Length = extLen;
                    ext->MaximumLength = extLen + sizeof(WCHAR);
                    *Extension = ext;
                }
                else {
                    ExFreePool(ext);
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// FileFilterMatchRules - 带缓存的规则匹配
// ============================================================================
static BOOLEAN FileFilterMatchRules(
    _In_ PUNICODE_STRING FilePath,
    _In_ FILE_OPERATION Operation,
    _Out_ int* pMatchedRuleId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    BOOLEAN found = FALSE;

    *pMatchedRuleId = 0;

    // 查缓存
    KeAcquireInStackQueuedSpinLock(&g_CacheLock, &lockHandle);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (g_MatchCache[i].Valid &&
            g_MatchCache[i].Operation == Operation &&
            RtlEqualUnicodeString(&g_MatchCache[i].Path, FilePath, TRUE))
        {
            *pMatchedRuleId = g_MatchCache[i].MatchedRuleId;
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            return TRUE;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // 遍历规则
    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &lockHandle);
    for (ULONG i = 0; i < g_FileRuleCount; i++) {
        RULE_FILE_DATA* rule = &g_FileRules[i];
        if (rule->Operation != Operation)
            continue;

        WCHAR pattern[2048];
        ULONG patLen = 1;
        pattern[0] = L'*';
        const CHAR* ansiStr = rule->FullPath;
        if (ansiStr[0] && ansiStr[1] == ':' && ansiStr[2] == '\\')
            ansiStr += 2;
        for (ULONG j = 0; ansiStr[j] && patLen < 2040; j++)
            pattern[patLen++] = (WCHAR)(UCHAR)ansiStr[j];
        if (patLen > 1 && pattern[patLen - 1] != L'\\')
            pattern[patLen++] = L'\\';
        if (rule->FileName[0] && strcmp(rule->FileName, "*") != 0) {
            const CHAR* fn = rule->FileName;
            for (ULONG j = 0; fn[j] && patLen < 2040; j++)
                pattern[patLen++] = (WCHAR)(UCHAR)fn[j];
        }
        else {
            pattern[patLen++] = L'*';
        }
        pattern[patLen++] = L'*';
        pattern[patLen] = L'\0';

        if (WildcardMatch(pattern, FilePath->Buffer)) {
            /* Check file extension if rule specifies one (BUGFIX: was never checked) */
            if (rule->FileExt[0] != '\0' && strcmp(rule->FileExt, "*") != 0) {
                BOOLEAN extMatch = FALSE;
                LONG pathLen2 = FilePath->Length / sizeof(WCHAR);
                LONG dotPos2 = -1;
                for (LONG k = pathLen2 - 1; k >= 0; k--) {
                    if (FilePath->Buffer[k] == L'.') { dotPos2 = k; break; }
                    if (FilePath->Buffer[k] == L'\\' || FilePath->Buffer[k] == L'/') break;
                }
                if (dotPos2 >= 0) {
                    const CHAR* ruleExt = rule->FileExt;
                    int ri = 0;
                    LONG fi = dotPos2 + 1;
                    extMatch = TRUE;
                    while (ruleExt[ri] && fi < pathLen2) {
                        WCHAR fc = FilePath->Buffer[fi];
                        CHAR rc = ruleExt[ri];
                        if (fc >= L'a' && fc <= L'z') fc -= 32;
                        if (rc >= 'a' && rc <= 'z') rc -= 32;
                        if (fc != (WCHAR)(UCHAR)rc) { extMatch = FALSE; break; }
                        ri++; fi++;
                    }
                    if (ruleExt[ri] || fi < pathLen2) extMatch = FALSE;
                }
                if (!extMatch) continue;  /* Extension mismatch, try next rule */
            }

            found = TRUE;
            *pMatchedRuleId = (int)rule->RuleId;
            break;
        }
    }

    /* RENAME 操作额外检查：操作路径是否是勒索诱捕规则路径的父目录。
     * 即勒索软件重命名诱捕文件所在目录时，也触发拦截。
     * 检查方式：规则路径以 操作路径 + '\' 开头。 */
    if (!found && Operation == FILE_OPERATION_RENAME) {
        for (ULONG i = 0; i < g_FileRuleCount; i++) {
            RULE_FILE_DATA* rule = &g_FileRules[i];
            if (rule->Operation != FILE_OPERATION_RENAME) continue;
            /* 只对 RansomHoneypot 规则检查父目录重命名 */
            if (strstr(rule->Description, "RansomHoneypot") == NULL) continue;

            /* 将规则路径转换为 UNICODE 进行前缀比较 */
            WCHAR rulePathW[MAX_PATH_LEN];
            ULONG ruleLen = 0;
            const CHAR* ansiStr = rule->FullPath;
            for (; ansiStr[ruleLen] && ruleLen < MAX_PATH_LEN - 1; ruleLen++)
                rulePathW[ruleLen] = (WCHAR)(UCHAR)ansiStr[ruleLen];
            rulePathW[ruleLen] = L'\0';

            ULONG pathLen = FilePath->Length / sizeof(WCHAR);
            if (pathLen < ruleLen) {
                /* 操作路径比规则路径短：检查是否为前缀 */
                BOOLEAN isPrefix = TRUE;
                for (ULONG j = 0; j < pathLen; j++) {
                    WCHAR fc = FilePath->Buffer[j];
                    WCHAR rc = rulePathW[j];
                    if (fc >= L'a' && fc <= L'z') fc -= 32;
                    if (rc >= L'a' && rc <= L'z') rc -= 32;
                    if (fc != rc) { isPrefix = FALSE; break; }
                }
                /* 规则路径中操作路径之后的位置必须是 '\'，确认是父目录 */
                if (isPrefix && rulePathW[pathLen] == L'\\') {
                    found = TRUE;
                    *pMatchedRuleId = (int)rule->RuleId;
                    break;
                }
            }
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // 更新缓存
    if (found) {
        KeAcquireInStackQueuedSpinLock(&g_CacheLock, &lockHandle);
        int replaceIdx = -1;
        LARGE_INTEGER oldestTime;
        oldestTime.QuadPart = MAXLONGLONG;
        for (int i = 0; i < CACHE_SIZE; i++) {
            if (!g_MatchCache[i].Valid) {
                replaceIdx = i;
                break;
            }
            if (g_MatchCache[i].LastAccess.QuadPart < oldestTime.QuadPart) {
                oldestTime = g_MatchCache[i].LastAccess;
                replaceIdx = i;
            }
        }
        if (replaceIdx >= 0) {
            if (g_MatchCache[replaceIdx].Path.Buffer)
                ExFreePool(g_MatchCache[replaceIdx].Path.Buffer);
            RtlZeroMemory(&g_MatchCache[replaceIdx], sizeof(g_MatchCache[replaceIdx]));
            g_MatchCache[replaceIdx].Path.Buffer = (PWCHAR)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, FilePath->Length + sizeof(WCHAR), 'HcP');
            if (g_MatchCache[replaceIdx].Path.Buffer) {
                RtlCopyMemory(g_MatchCache[replaceIdx].Path.Buffer, FilePath->Buffer, FilePath->Length);
                g_MatchCache[replaceIdx].Path.Buffer[FilePath->Length / sizeof(WCHAR)] = L'\0';
                g_MatchCache[replaceIdx].Path.Length = FilePath->Length;
                g_MatchCache[replaceIdx].Path.MaximumLength = FilePath->Length + sizeof(WCHAR);
                g_MatchCache[replaceIdx].Operation = Operation;
                g_MatchCache[replaceIdx].MatchedRuleId = *pMatchedRuleId;
                g_MatchCache[replaceIdx].Valid = TRUE;
                KeQuerySystemTime(&g_MatchCache[replaceIdx].LastAccess);
            }
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
    }

    return found;
}

// ============================================================================
// 规则管理函数（保持对外接口不变）
// ============================================================================
NTSTATUS FileFilterAddRule(RULE_FILE_DATA* rule)
{
    if (!rule) return STATUS_INVALID_PARAMETER;

    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &lockHandle);
    if (g_FileRuleCount >= MAX_FILE_RULES) {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(&g_FileRules[g_FileRuleCount], rule, sizeof(RULE_FILE_DATA));
    g_FileRules[g_FileRuleCount].FullPath[MAX_PATH_LEN - 1] = '\0';
    g_FileRules[g_FileRuleCount].FileName[MAX_VALUE_NAME_LEN - 1] = '\0';
    g_FileRules[g_FileRuleCount].FileExt[31] = '\0';
    g_FileRules[g_FileRuleCount].Description[127] = '\0';
    g_FileRuleCount++;
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return STATUS_SUCCESS;
}

NTSTATUS FileFilterRemoveRule(ULONG ruleId)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &lockHandle);
    for (ULONG i = 0; i < g_FileRuleCount; i++) {
        if (g_FileRules[i].RuleId == ruleId) {
            if (i < g_FileRuleCount - 1)
                RtlMoveMemory(&g_FileRules[i], &g_FileRules[i + 1], (g_FileRuleCount - i - 1) * sizeof(RULE_FILE_DATA));
            RtlZeroMemory(&g_FileRules[g_FileRuleCount - 1], sizeof(RULE_FILE_DATA));
            g_FileRuleCount--;
            KeReleaseInStackQueuedSpinLock(&lockHandle);

            KeAcquireInStackQueuedSpinLock(&g_CacheLock, &lockHandle);
            for (int c = 0; c < CACHE_SIZE; c++) {
                if (g_MatchCache[c].Valid && g_MatchCache[c].MatchedRuleId == (int)ruleId) {
                    ExFreePool(g_MatchCache[c].Path.Buffer);
                    g_MatchCache[c].Path.Buffer = NULL;
                    g_MatchCache[c].Valid = FALSE;
                }
            }
            KeReleaseInStackQueuedSpinLock(&lockHandle);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return STATUS_NOT_FOUND;
}

NTSTATUS FileFilterClearRules()
{
    KLOCK_QUEUE_HANDLE lockHandle;
    KeAcquireInStackQueuedSpinLock(&g_RuleLock, &lockHandle);
    RtlZeroMemory(g_FileRules, sizeof(g_FileRules));
    g_FileRuleCount = 0;
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    KeAcquireInStackQueuedSpinLock(&g_CacheLock, &lockHandle);
    for (int i = 0; i < CACHE_SIZE; i++) {
        if (g_MatchCache[i].Path.Buffer) {
            ExFreePool(g_MatchCache[i].Path.Buffer);
            g_MatchCache[i].Path.Buffer = NULL;
        }
        g_MatchCache[i].Valid = FALSE;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
    return STATUS_SUCCESS;
}

NTSTATUS FileFilterGetStats(FILE_RULE_STATS* stats)
{
    if (!stats) return STATUS_INVALID_PARAMETER;
    stats->TotalRules = MAX_FILE_RULES;
    stats->ActiveRules = g_FileRuleCount;
    stats->BlockedOperations = g_TotalBlockedOperations;
    stats->AllowedOperations = g_TotalAllowedOperations;
    return STATUS_SUCCESS;
}

VOID FileFilterSetControlDevice(PDEVICE_OBJECT DeviceObject)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return;
}