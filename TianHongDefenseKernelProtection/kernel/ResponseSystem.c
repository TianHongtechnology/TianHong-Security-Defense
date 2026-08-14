#include "../shared/Common.h"
#include "../shared/Ioctl.h"
#include "Main.h"
#include "ResponseSystem.h"
#include "FileFilter.h"  /* g_FilterHandle，用于 FltCreateFileEx2 避免 minifilter 重入 */

/* SendInjectionLog 可能被内核 APC 例程（APC_LEVEL）调用，必须位于非分页
 * 代码段，否则取指令时会触发 IRQL_LESS_OR_EQUAL 蓝屏。 */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(NONPAGED, SendInjectionLog)
#endif

/* Undocumented kernel API declarations for process info gathering */
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
NTKERNELAPI NTSTATUS ZwQueryInformationProcess(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
);

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* ============================================================================
 * ResponseSystem.c - 请求-响应系统，内核-用户态同步通信
 * 使用 LIST_ENTRY + KEVENT 模型
 * 包含响应缓存：按 (ProcessPid, RuleId) 缓存上次决策
 * ========================================================================== */

// 响应缓存
static RESPONSE_CACHE_ENTRY g_ResponseCache[MAX_RESPONSE_CACHE];
static BOOLEAN g_ResponseCacheEnabled = FALSE;
static KSPIN_LOCK g_ResponseCacheLock;

// 签名验证缓存
static SIGNATURE_CACHE_ENTRY g_SignatureCache[MAX_SIGNATURE_CACHE_ENTRIES];
static BOOLEAN g_SignatureCacheEnabled = TRUE;
static KSPIN_LOCK g_SignatureCacheLock;

// CI.DLL 接口
CI_VALIDATE_FILE_OBJECT g_CiValidateFileObject = NULL;
CI_FREE_POLICY_INFO g_CiFreePolicyInfo = NULL;

// 全局取消标志（驱动卸载时设为 TRUE，新请求直接失败）
static volatile LONG g_ResponseSystemCancelled = 0;

// 请求队列计数器（追踪当前队列中的请求数量）
volatile LONG g_RequestQueueCount = 0;

// 静默模式标志（由用户态通过 IOCTL_SET_SILENT_MODE 控制）
BOOLEAN g_bSilentModeEnabled = FALSE;
BOOLEAN g_bSilverFoxEnabled = TRUE;       /* SilverFox 检测默认启用 */
BOOLEAN g_bAVBypassEnabled = TRUE;        /* AVBypass 检测默认启用 */

// 前向声明
VOID SendInjectionLog(_In_ const CHAR* Message);

// ----------------------------------------------------------------------------
// EnqueueRequest - 带队列大小限制的请求入队
//
// 当队列超过 MAX_REQUEST_QUEUE_SIZE 时：
//   - FireAndForget 请求：遍历队列，丢弃最旧的 FireAndForget 请求腾出空间
//   - 同步等待请求：返回 STATUS_INSUFFICIENT_RESOURCES，调用者负责释放 request
// 调用者必须持有 g_RequestQueueLock。
// ----------------------------------------------------------------------------
NTSTATUS EnqueueRequest(
    _In_ PRESPONSE_REQUEST request,
    _In_ KLOCK_QUEUE_HANDLE* lockHandle)
{
    UNREFERENCED_PARAMETER(lockHandle);

    LONG currentCount = InterlockedIncrement(&g_RequestQueueCount);

    if (currentCount > MAX_REQUEST_QUEUE_SIZE)
    {
        if (request->FireAndForget)
        {
            /* 队列已满且新请求为 FireAndForget：遍历队列，丢弃最旧的
             * FireAndForget 请求腾出空间。同步等待请求不丢弃，因为
             * 有线程正在等待它们的完成事件。 */
            PLIST_ENTRY entry = g_RequestQueueHead.Flink;
            BOOLEAN dropped = FALSE;
            while (entry != &g_RequestQueueHead)
            {
                PRESPONSE_REQUEST oldReq = CONTAINING_RECORD(entry, RESPONSE_REQUEST, ListEntry);
                PLIST_ENTRY nextEntry = entry->Flink;
                if (oldReq->FireAndForget)
                {
                    RemoveEntryList(entry);
                    InitializeListHead(entry);
                    /* 释放 FireAndForget 请求的内存 */
                    if (oldReq->FullPath != NULL) ExFreePool(oldReq->FullPath);
                    if (oldReq->ValueName != NULL) ExFreePool(oldReq->ValueName);
                    if (oldReq->NewValueData != NULL) ExFreePool(oldReq->NewValueData);
                    ExFreePool(oldReq);
                    InterlockedDecrement(&g_RequestQueueCount);
                    dropped = TRUE;
                    DriverDbgPrint("EnqueueRequest: Dropped oldest FireAndForget, queue was full (%d)\n",
                        MAX_REQUEST_QUEUE_SIZE);
                    break;
                }
                entry = nextEntry;
            }
            if (!dropped)
            {
                /* 队列中全是同步等待请求，无法丢弃。拒绝新请求。 */
                InterlockedDecrement(&g_RequestQueueCount);
                DriverDbgPrint("EnqueueRequest: Queue full (%d) with sync requests only, rejecting FireAndForget\n",
                    MAX_REQUEST_QUEUE_SIZE);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        else
        {
            /* 同步等待请求在队列满时拒绝 */
            InterlockedDecrement(&g_RequestQueueCount);
            DriverDbgPrint("EnqueueRequest: Queue full (%d), rejecting sync request\n",
                MAX_REQUEST_QUEUE_SIZE);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    InsertTailList(&g_RequestQueueHead, &request->ListEntry);
    KeSetEvent(&g_RequestAvailableEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// InitializeResponseSystem - 初始化响应系统全局队列
// ----------------------------------------------------------------------------
NTSTATUS InitializeResponseSystem()
{
    KeInitializeSpinLock(&g_RequestQueueLock);
    InitializeListHead(&g_RequestQueueHead);
    KeInitializeEvent(&g_RequestAvailableEvent, NotificationEvent, FALSE);

    // 初始化响应缓存
    KeInitializeSpinLock(&g_ResponseCacheLock);
    RtlZeroMemory(g_ResponseCache, sizeof(g_ResponseCache));
    g_ResponseCacheEnabled = FALSE;

    // 初始化签名验证缓存
    KeInitializeSpinLock(&g_SignatureCacheLock);
    RtlZeroMemory(g_SignatureCache, sizeof(g_SignatureCache));
    g_SignatureCacheEnabled = TRUE;

    // 初始化 CI.DLL 接口
    CiInitialize();

    DriverDbgPrint("Response system initialized\n");

    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// CleanupResponseSystem - 清理响应系统资源
// ----------------------------------------------------------------------------
VOID CleanupResponseSystem()
{
    // 清理 CI.DLL 接口
    CiCleanup();

    DriverDbgPrint("Response system cleaned up\n");
}

// ----------------------------------------------------------------------------
// HandleUserResponse - 处理来自用户态的响应结果
// FireAndForget 请求：不由发送方等待，由本函数负责释放内存
// ----------------------------------------------------------------------------
NTSTATUS HandleUserResponse(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    UNREFERENCED_PARAMETER(Stack);

    PCOMM_RESPONSE_PACKET responsePacket;
    PCOMM_RESPONSE_RESULT responseResult;
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN fireAndForget = FALSE;
    int ruleId = 0;

    // 检查输入缓冲区大小
    if (Irp->AssociatedIrp.SystemBuffer == NULL ||
        Stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(COMM_RESPONSE_PACKET))
    {
        DriverDbgPrint("HandleUserResponse: Buffer too small\n");
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    responsePacket = (PCOMM_RESPONSE_PACKET)Irp->AssociatedIrp.SystemBuffer;

    // 检查数据包类型
    if (responsePacket->Type != RESPONSE_RESULT)
    {
        DriverDbgPrint("HandleUserResponse: Wrong packet type %d\n", responsePacket->Type);
        Irp->IoStatus.Information = 0;
        return STATUS_INVALID_PARAMETER;
    }

    responseResult = (PCOMM_RESPONSE_RESULT)&responsePacket->Data;

    // 加锁并访问队列
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);

    if (IsListEmpty(&g_RequestQueueHead))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        DriverDbgPrint("HandleUserResponse: Queue empty, no pending requests\n");
        Irp->IoStatus.Information = 0;
        return STATUS_NO_MORE_ENTRIES;
    }

    // 从队列头部移除第一个等待请求
    PLIST_ENTRY entry = RemoveHeadList(&g_RequestQueueHead);
    request = CONTAINING_RECORD(entry, RESPONSE_REQUEST, ListEntry);
    InitializeListHead(&request->ListEntry);
    InterlockedDecrement(&g_RequestQueueCount);

    // 在释放锁之前捕获字段、设置结果并触发完成事件
    fireAndForget = request->FireAndForget;
    ruleId = request->RuleId;
    request->ResultStatus = responseResult->nts;

    /* 回滚确认请求：从用户态响应中提取 BA_ROLLBACK_SELECTION */
    if (request->RuleType == RULE_TYPE_ROLLBACK_CONFIRM)
    {
        PBA_ROLLBACK_SELECTION pSel = (PBA_ROLLBACK_SELECTION)&responseResult->Data;
        RtlCopyMemory(&request->RollbackSelection, pSel, sizeof(BA_ROLLBACK_SELECTION));
        DriverDbgPrint("HandleUserResponse: Rollback selection decision=%d items=%d\n",
            pSel->decision, pSel->itemCount);
    }

    KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DriverDbgPrint("User-mode response processed: RuleId=%d, Result=0x%X, FireAndForget=%d\n",
                   ruleId, request->ResultStatus, fireAndForget);

    /* FireAndForget 请求：发送方不等待，由本函数负责释放内存 */
    if (fireAndForget) {
        if (request->FullPath != NULL) ExFreePool(request->FullPath);
        if (request->ValueName != NULL) ExFreePool(request->ValueName);
        if (request->NewValueData != NULL) ExFreePool(request->NewValueData);
        if (request->RollbackList != NULL) ExFreePool(request->RollbackList);
        ExFreePool(request);
    }

    Irp->IoStatus.Information = 0;
    return status;
}

// ----------------------------------------------------------------------------
// GetPendingRequest - 用户态轮询获取待处理的检测请求
// ----------------------------------------------------------------------------
NTSTATUS GetPendingRequest(_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
    PCOMM_RESPONSE_PACKET packet;
    PCOMM_RULE_DETECTED detected;
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;
    ULONG outputLength;
    int ruleId = 0;
    int ruleType = 0;
    int processPid = 0;
    int parentPid = 0;
    CHAR processName[64] = {0};
    CHAR parentName[64] = {0};
    CHAR processPath[512] = {0};
    CHAR dllPath[512] = {0};
    CHAR ruleDesc[128] = {0};
    WCHAR fullPathBuffer[MAX_PATH_LEN] = {0};
    USHORT fullPathLength = 0;
    WCHAR valueNameBuffer[MAX_VALUE_NAME_LEN] = {0};
    USHORT valueNameLength = 0;
    BEHAVIOR_DETECTED_RESPONSE behaviorAlert = {0};
    INJECTION_LOG_DATA injectionLog = {0};
    BA_ROLLBACK_LIST rollbackList = {0};

    outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (Irp->AssociatedIrp.SystemBuffer == NULL ||
        outputLength < sizeof(COMM_RESPONSE_PACKET))
    {
        DriverDbgPrint("GetPendingRequest: Output buffer too small\n");
        Irp->IoStatus.Information = 0;
        return STATUS_BUFFER_TOO_SMALL;
    }

    packet = (PCOMM_RESPONSE_PACKET)Irp->AssociatedIrp.SystemBuffer;
    RtlZeroMemory(packet, sizeof(COMM_RESPONSE_PACKET));

    // 加锁并检查队列
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);

    if (IsListEmpty(&g_RequestQueueHead))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        Irp->IoStatus.Information = 0;
        return STATUS_NO_MORE_ENTRIES;
    }

    // 获取队列中第一个请求（不移除），并在持有锁期间复制字段和字符串内容
    PLIST_ENTRY entry = g_RequestQueueHead.Flink;
    request = CONTAINING_RECORD(entry, RESPONSE_REQUEST, ListEntry);

    ruleId = request->RuleId;
    ruleType = request->RuleType;
    processPid = request->ProcessPid;
    parentPid = request->ParentPid;
    RtlCopyMemory(processName, request->ProcessName, sizeof(processName));
    RtlCopyMemory(parentName, request->ParentName, sizeof(parentName));
    RtlCopyMemory(processPath, request->ProcessPath, sizeof(processPath));
    RtlCopyMemory(dllPath, request->DllPath, sizeof(dllPath));
    RtlCopyMemory(ruleDesc, request->RuleDesc, sizeof(ruleDesc));

    if (ruleType == RULE_TYPE_BEHAVIOR || ruleType == RULE_TYPE_NTDLL_RELOAD)
    {
        RtlCopyMemory(&behaviorAlert, &request->BehaviorAlert, sizeof(behaviorAlert));
    }
    else if (ruleType == RULE_TYPE_INJECTION_LOG)
    {
        RtlCopyMemory(&injectionLog, &request->InjectionLog, sizeof(injectionLog));
    }
    else if (ruleType == RULE_TYPE_ROLLBACK_CONFIRM)
    {
        if (request->RollbackList != NULL)
            RtlCopyMemory(&rollbackList, request->RollbackList, sizeof(rollbackList));
    }
    else
    {
        if (request->FullPath != NULL && request->FullPath->Buffer != NULL)
        {
            USHORT copyLen = request->FullPath->Length;
            if (copyLen > sizeof(fullPathBuffer)) copyLen = (USHORT)sizeof(fullPathBuffer);
            RtlCopyMemory(fullPathBuffer, request->FullPath->Buffer, copyLen);
            fullPathLength = copyLen;
        }
        if (request->ValueName != NULL && request->ValueName->Buffer != NULL)
        {
            USHORT copyLen = request->ValueName->Length;
            if (copyLen > sizeof(valueNameBuffer)) copyLen = (USHORT)sizeof(valueNameBuffer);
            RtlCopyMemory(valueNameBuffer, request->ValueName->Buffer, copyLen);
            valueNameLength = copyLen;
        }
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    // 填充响应包
    packet->Type = RESPONSE_RULE_DETECTED;
    detected = (PCOMM_RULE_DETECTED)&packet->Data;
    detected->RuleId = ruleId;
    detected->ProcessPid = processPid;
    detected->RuleType = ruleType;
    RtlCopyMemory(detected->ProcessName, processName, sizeof(detected->ProcessName));
    detected->ParentPid = parentPid;
    RtlCopyMemory(detected->ParentName, parentName, sizeof(detected->ParentName));
    RtlCopyMemory(detected->ProcessPath, processPath, sizeof(detected->ProcessPath));
    RtlCopyMemory(detected->DllPath, dllPath, sizeof(detected->DllPath));
    RtlCopyMemory(detected->RuleDesc, ruleDesc, sizeof(detected->RuleDesc));

    if (ruleType == RULE_TYPE_BEHAVIOR)
    {
        // 行为分析：直接复制 BehaviorAlert 到 Data
        PBEHAVIOR_DETECTED_RESPONSE behResponse = (PBEHAVIOR_DETECTED_RESPONSE)&detected->Data;
        RtlCopyMemory(behResponse, &behaviorAlert, sizeof(BEHAVIOR_DETECTED_RESPONSE));
        DriverDbgPrint("GetPendingRequest: Sending behavior alert PID=%lld, Class=%s, Confidence=%ld/10000\n",
            behResponse->Pid, behResponse->ThreatClass,
            (LONG)(behResponse->Confidence * 10000.0 + 0.5));
    }
    else if (ruleType == RULE_TYPE_NTDLL_RELOAD)
    {
        // ntdll 重载/Unhook 检测：将事件数据复制到 Data
        PNTDLL_RELOAD_EVENT_DATA pNtdllEvent = (PNTDLL_RELOAD_EVENT_DATA)&detected->Data;
        RtlCopyMemory(pNtdllEvent, &behaviorAlert, sizeof(NTDLL_RELOAD_EVENT_DATA));
        DriverDbgPrint("GetPendingRequest: Sending ntdll reload event PID=%lld Base=%p Flags=0x%X\n",
            pNtdllEvent->ProcessId, (PVOID)pNtdllEvent->ImageBase, pNtdllEvent->Flags);
    }
    else if (ruleType == RULE_TYPE_INJECTION_LOG)
    {
        // 注入日志：复制 InjectionLog 到 Data
        PINJECTION_LOG_DATA logData = (PINJECTION_LOG_DATA)&detected->Data;
        RtlCopyMemory(logData, &injectionLog, sizeof(INJECTION_LOG_DATA));
    }
    else if (ruleType == RULE_TYPE_ROLLBACK_CONFIRM)
    {
        // 回滚确认：复制 BA_ROLLBACK_LIST 到 Data
        PBA_ROLLBACK_LIST pList = (PBA_ROLLBACK_LIST)&detected->Data;
        RtlCopyMemory(pList, &rollbackList, sizeof(BA_ROLLBACK_LIST));
        DriverDbgPrint("GetPendingRequest: Sending rollback list rootPid=%lld items=%d class=%s\n",
            rollbackList.rootPid, rollbackList.itemCount, rollbackList.threatClass);
    }
    // 将 Unicode FullPath 转换为 ANSI，根据规则类型填充响应
    else if (fullPathLength > 0)
    {
        UNICODE_STRING unicodeFullPath;
        ANSI_STRING ansiFullPath;
        NTSTATUS convStatus;

        unicodeFullPath.Buffer = fullPathBuffer;
        unicodeFullPath.Length = fullPathLength;
        unicodeFullPath.MaximumLength = (USHORT)sizeof(fullPathBuffer);

        convStatus = RtlUnicodeStringToAnsiString(&ansiFullPath, &unicodeFullPath, TRUE);
        if (!NT_SUCCESS(convStatus))
        {
            Irp->IoStatus.Information = 0;
            return convStatus;
        }

        if (ruleType == RULE_TYPE_FILE)
        {
            // 文件规则：填充 RULE_FILE_DETECTED_RESPONSE
            PRULE_FILE_DETECTED_RESPONSE fileResponse = (PRULE_FILE_DETECTED_RESPONSE)&detected->Data;
            RtlZeroMemory(fileResponse, sizeof(RULE_FILE_DETECTED_RESPONSE));
            RtlStringCbCopyNA(fileResponse->FullPath, MAX_PATH_LEN, ansiFullPath.Buffer, ansiFullPath.Length);

            // 从完整路径中提取文件名
            LONG i;
            for (i = (LONG)(ansiFullPath.Length - 1); i >= 0; i--)
            {
                if (ansiFullPath.Buffer[i] == '\\')
                {
                    LONG nameLen = (LONG)ansiFullPath.Length - i - 1;
                    if (nameLen > 0 && nameLen < MAX_VALUE_NAME_LEN)
                    {
                        RtlStringCbCopyNA(fileResponse->FileName, MAX_VALUE_NAME_LEN,
                            &ansiFullPath.Buffer[i + 1], nameLen);
                    }
                    break;
                }
            }
        }
        else
        {
            // 注册表规则：填充 RULE_REG_DETECTED_RESPONSE
            PRULE_REG_DETECTED_RESPONSE regResponse = (PRULE_REG_DETECTED_RESPONSE)&detected->Data;
            RtlZeroMemory(regResponse, sizeof(RULE_REG_DETECTED_RESPONSE));
            RtlStringCbCopyNA(regResponse->FullPath, MAX_PATH_LEN, ansiFullPath.Buffer, ansiFullPath.Length);

            // 如果有值名称，也复制它
            if (valueNameLength > 0)
            {
                UNICODE_STRING unicodeValueName;
                ANSI_STRING ansiValueName;

                unicodeValueName.Buffer = valueNameBuffer;
                unicodeValueName.Length = valueNameLength;
                unicodeValueName.MaximumLength = (USHORT)sizeof(valueNameBuffer);

                convStatus = RtlUnicodeStringToAnsiString(&ansiValueName, &unicodeValueName, TRUE);
                if (!NT_SUCCESS(convStatus))
                {
                    RtlFreeAnsiString(&ansiFullPath);
                    Irp->IoStatus.Information = 0;
                    return convStatus;
                }

                RtlStringCbCopyNA(regResponse->ChangeName, sizeof(regResponse->ChangeName),
                    ansiValueName.Buffer, ansiValueName.Length);
                regResponse->IsChangeNameEnabled = TRUE;
                RtlFreeAnsiString(&ansiValueName);
            }
        }

        RtlFreeAnsiString(&ansiFullPath);
    }

    DriverDbgPrint("User-mode fetched pending request: RuleId=%d, Pid=%d\n",
                   detected->RuleId, detected->ProcessPid);

    Irp->IoStatus.Information = sizeof(COMM_RESPONSE_PACKET);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// AskClientForResponse - 查询用户态并同步等待（30s 超时）
// ----------------------------------------------------------------------------
NTSTATUS AskClientForResponse(
    _In_ int RuleId,
    _In_ int RuleType,
    _In_ int ProcessPid,
    _In_ PUNICODE_STRING FullPath,
    _In_opt_ PUNICODE_STRING ValueName,
    _In_opt_ PVOID NewValueData,
    _In_ ULONG NewValueSize,
    _In_ ULONG ValueType)
{
    PRESPONSE_REQUEST request;
    PUNICODE_STRING copiedFullPath = NULL;
    PUNICODE_STRING copiedValueName = NULL;
    PVOID copiedNewValueData = NULL;
    KLOCK_QUEUE_HANDLE lockHandle;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    NTSTATUS result;
    KIRQL oldIrql;
    HANDLE procId = (HANDLE)(ULONG_PTR)ProcessPid;

    // 检查响应缓存（如果启用）
    if (g_ResponseCacheEnabled)
    {
        KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
        for (int i = 0; i < MAX_RESPONSE_CACHE; i++)
        {
            if (g_ResponseCache[i].Valid &&
                g_ResponseCache[i].ProcessPid == procId &&
                g_ResponseCache[i].RuleId == RuleId)
            {
                result = g_ResponseCache[i].LastResponse;
                KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
                DriverDbgPrint("Response cache hit: RuleId=%d, Pid=%d, CachedResult=0x%X\n",
                    RuleId, ProcessPid, result);
                return result;
            }
        }
        KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    }

    /* 检查全局取消标志：驱动正在卸载时直接拒绝 */
    if (g_ResponseSystemCancelled)
    {
        DriverDbgPrint("AskClientForResponse: System cancelled, denying by default\n");
        return STATUS_ACCESS_DENIED;
    }

    // 分配请求结构体
    request = (PRESPONSE_REQUEST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(RESPONSE_REQUEST),
        'RESP'
    );

    if (request == NULL)
    {
        DriverDbgPrint("AskClientForResponse: Failed to allocate request structure\n");
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));

    // 初始化完成事件
    KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);

    // 复制基本信息
    request->RuleId = RuleId;
    request->RuleType = RuleType;
    request->ProcessPid = ProcessPid;
    request->ValueType = ValueType;
    request->NewValueSize = NewValueSize;

    // Gather process context info (runs in triggering process's context)
    {
        PEPROCESS currentProc = PsGetCurrentProcess();

        /* Process name */
        UCHAR* procName = PsGetProcessImageFileName(currentProc);
        if (procName) {
            ULONG i;
            /* PsGetProcessImageFileName 最多15字符，可能无null终止符 */
            for (i = 0; i < 15 && procName[i]; i++)
                request->ProcessName[i] = (CHAR)procName[i];
            request->ProcessName[i] = '\0';
        }

        /* Parent process PID and name */
        {
            HANDLE parentPid = NULL;
            HANDLE hProcess = NULL;
            NTSTATUS status = ObOpenObjectByPointer(
                currentProc,
                OBJ_KERNEL_HANDLE,
                NULL,
                0,
                *PsProcessType,
                KernelMode,
                &hProcess
            );

            if (NT_SUCCESS(status)) {
                PROCESS_BASIC_INFORMATION pbi = { 0 };
                ULONG returnLength = 0;

                status = ZwQueryInformationProcess(
                    hProcess,
                    ProcessBasicInformation,
                    &pbi,
                    sizeof(pbi),
                    &returnLength
                );

                if (NT_SUCCESS(status)) {
                    parentPid = (HANDLE)pbi.InheritedFromUniqueProcessId;
                }

                ZwClose(hProcess);
            }

            request->ParentPid = (int)(ULONG_PTR)(parentPid ? parentPid : 0);

            // 获取父进程名称
            if (parentPid) {
                PEPROCESS parentProc = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId(parentPid, &parentProc))) {
                    UCHAR* parentName = PsGetProcessImageFileName(parentProc);
                    if (parentName) {
                        ULONG i;
                        /* PsGetProcessImageFileName 最多15字符，可能无null终止符 */
                        for (i = 0; i < 15 && parentName[i]; i++)
                            request->ParentName[i] = (CHAR)parentName[i];
                        request->ParentName[i] = '\0';
                    }
                    ObDereferenceObject(parentProc);
                }
            }
            else {
                // 没有父进程（System Idle 或 System 进程）
                request->ParentName[0] = '\0';
            }
        }

        /* Process image path via ZwQueryInformationProcess */
        {
            ULONG neededSize = 0;
            ZwQueryInformationProcess(NtCurrentProcess(), ProcessImageFileName,
                                      NULL, 0, &neededSize);
            if (neededSize > 0 && neededSize < 0x10000) {
                PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, neededSize, 'PthP');
                if (buf) {
                    if (NT_SUCCESS(ZwQueryInformationProcess(NtCurrentProcess(),
                                     ProcessImageFileName, buf, neededSize,
                                     &neededSize))) {
                        PUNICODE_STRING imgName = (PUNICODE_STRING)buf;
                        ANSI_STRING ansi;
                        if (NT_SUCCESS(RtlUnicodeStringToAnsiString(&ansi,
                                         imgName, TRUE))) {
                            ULONG copyLen = ansi.Length;
                            if (copyLen >= sizeof(request->ProcessPath))
                                copyLen = sizeof(request->ProcessPath) - 1;
                            RtlCopyMemory(request->ProcessPath, ansi.Buffer, copyLen);
                            request->ProcessPath[copyLen] = '\0';
                            RtlFreeAnsiString(&ansi);
                        }
                    }
                    ExFreePool(buf);
                }
            }
        }

        /* Rule description lookup */
        if (RuleType == RULE_TYPE_FILE) {
            for (ULONG i = 0; i < g_FileRuleCount; i++) {
                if (g_FileRules[i].RuleId == (ULONG)RuleId) {
                    RtlStringCbCopyA(request->RuleDesc, sizeof(request->RuleDesc),
                                     g_FileRules[i].Description);
                    break;
                }
            }
        } else if (RuleType == RULE_TYPE_REG) {
            for (ULONG i = 0; i < g_RuleCount; i++) {
                if (g_Rules[i].rt == RULE_TYPE_REG &&
                    g_Rules[i].RuleId == (ULONG)RuleId) {
                    PRULE_REG_DATA regData = (PRULE_REG_DATA)&g_Rules[i].Data;
                    RtlStringCbCopyA(request->RuleDesc, sizeof(request->RuleDesc),
                                     regData->Description);
                    break;
                }
            }
        }
    }

    // 复制 FullPath
    if (FullPath != NULL && FullPath->Length > 0)
    {
        copiedFullPath = (PUNICODE_STRING)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(UNICODE_STRING) + FullPath->Length,
            'RESP'
        );

        if (copiedFullPath != NULL)
        {
            copiedFullPath->Length = FullPath->Length;
            copiedFullPath->MaximumLength = FullPath->Length;
            copiedFullPath->Buffer = (PWSTR)((PUCHAR)copiedFullPath + sizeof(UNICODE_STRING));
            RtlCopyMemory(copiedFullPath->Buffer, FullPath->Buffer, FullPath->Length);
            request->FullPath = copiedFullPath;
        }
    }
    else
    {
        request->FullPath = NULL;
    }

    // 复制 ValueName
    if (ValueName != NULL && ValueName->Length > 0)
    {
        copiedValueName = (PUNICODE_STRING)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            sizeof(UNICODE_STRING) + ValueName->Length,
            'RESP'
        );

        if (copiedValueName != NULL)
        {
            copiedValueName->Length = ValueName->Length;
            copiedValueName->MaximumLength = ValueName->Length;
            copiedValueName->Buffer = (PWSTR)((PUCHAR)copiedValueName + sizeof(UNICODE_STRING));
            RtlCopyMemory(copiedValueName->Buffer, ValueName->Buffer, ValueName->Length);
            request->ValueName = copiedValueName;
        }
    }
    else
    {
        request->ValueName = NULL;
    }

    // 复制 NewValueData
    if (NewValueData != NULL && NewValueSize > 0)
    {
        copiedNewValueData = ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            NewValueSize,
            'RESP'
        );

        if (copiedNewValueData != NULL)
        {
            RtlCopyMemory(copiedNewValueData, NewValueData, NewValueSize);
            request->NewValueData = copiedNewValueData;
        }
    }
    else
    {
        request->NewValueData = NULL;
    }

    // 插入到队列尾部
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
    if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        DriverDbgPrint("AskClientForResponse: Queue full, denying by default\n");
        result = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DriverDbgPrint("Request sent to user-mode: RuleId=%d, Pid=%d, waiting for response...\n",
                   RuleId, ProcessPid);

    // 等待响应，35 秒超时（给 mainUI alert 对话框留出足够时间）
    timeout.QuadPart = -35LL * 1000 * 1000 * 10; // 35 秒，相对时间（100ns 单位）
    waitStatus = KeWaitForSingleObject(
        &request->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    if (waitStatus != STATUS_SUCCESS)
    {
        // 超时或等待失败，从队列中移除并清理
        DriverDbgPrint("AskClientForResponse: Wait timeout or failure (0x%X), RuleId=%d\n",
                       waitStatus, RuleId);

        KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
        if (request->ListEntry.Flink != &request->ListEntry)
        {
            RemoveEntryList(&request->ListEntry);
            InitializeListHead(&request->ListEntry);
            InterlockedDecrement(&g_RequestQueueCount);
            result = STATUS_ACCESS_DENIED;
        }
        else
        {
            // 已被 HandleUserResponse 移除并设置了结果
            result = request->ResultStatus;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);

        goto Cleanup;
    }

    // 获取结果
    result = request->ResultStatus;

    DriverDbgPrint("User-mode response returned: RuleId=%d, Result=0x%X\n", RuleId, result);

    // 存入响应缓存（如果启用）
    if (g_ResponseCacheEnabled)
    {
        KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
        // 查找是否已有同 (Pid, RuleId) 的条目
        int slot = -1;
        int emptySlot = -1;
        for (int i = 0; i < MAX_RESPONSE_CACHE; i++)
        {
            if (!g_ResponseCache[i].Valid)
            {
                if (emptySlot == -1) emptySlot = i;
            }
            else if (g_ResponseCache[i].ProcessPid == procId &&
                     g_ResponseCache[i].RuleId == RuleId)
            {
                slot = i;
                break;
            }
        }
        if (slot == -1) slot = emptySlot;
        if (slot != -1)
        {
            g_ResponseCache[slot].ProcessPid = procId;
            g_ResponseCache[slot].RuleId = RuleId;
            g_ResponseCache[slot].LastResponse = result;
            g_ResponseCache[slot].Valid = TRUE;
            DriverDbgPrint("Response cache stored: RuleId=%d, Pid=%d, slot=%d, Result=0x%X\n",
                RuleId, ProcessPid, slot, result);
        }
        KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    }

Cleanup:
    // 释放分配的内存
    if (copiedFullPath != NULL)
    {
        ExFreePool(copiedFullPath);
    }
    if (copiedValueName != NULL)
    {
        ExFreePool(copiedValueName);
    }
    if (copiedNewValueData != NULL)
    {
        ExFreePool(copiedNewValueData);
    }
    if (request != NULL)
    {
        ExFreePool(request);
    }

    return result;
}

// ----------------------------------------------------------------------------
// AskClientForBehaviorResponse - 行为分析实时告警，查询用户态并等待
// 返回: STATUS_SUCCESS = 允许, STATUS_ACCESS_DENIED = 阻止
// ----------------------------------------------------------------------------
NTSTATUS AskClientForBehaviorResponse(
    _In_ INT64 Pid,
    _In_ const CHAR* ProcessPath,
    _In_ const CHAR* ThreatClass,
    _In_ const CHAR* Description,
    _In_ DOUBLE Confidence,
    _In_ const BEHAVIOR_DETECTED_RESPONSE* AlertInfo)
{
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    NTSTATUS result;
    KIRQL oldIrql;
    HANDLE procId = (HANDLE)(ULONG_PTR)Pid;

    /* 检查响应缓存 */
    if (g_ResponseCacheEnabled)
    {
        KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
        for (int i = 0; i < MAX_RESPONSE_CACHE; i++)
        {
            if (g_ResponseCache[i].Valid &&
                g_ResponseCache[i].ProcessPid == procId &&
                g_ResponseCache[i].RuleId == RULE_ID_BEHAVIOR_ANALYSIS)
            {
                result = g_ResponseCache[i].LastResponse;
                KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
                DriverDbgPrint("Behavior response cache hit: Pid=%lld, Result=0x%X\n", Pid, result);
                return result;
            }
        }
        KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    }

    /* 检查全局取消标志：驱动正在卸载时直接拒绝 */
    if (g_ResponseSystemCancelled)
    {
        DriverDbgPrint("AskClientForBehaviorResponse: System cancelled, denying by default\n");
        return STATUS_ACCESS_DENIED;
    }

    /* 静默模式：通知用户态并直接阻止，不弹窗询问用户 */
    if (g_bSilentModeEnabled)
    {
        DriverDbgPrint("AskClientForBehaviorResponse: Silent mode enabled, blocking PID=%lld\n", Pid);

        /* 构造告警数据并发送日志到用户态，由用户态负责弹窗通知和日志记录 */
        if (AlertInfo != NULL)
        {
            BEHAVIOR_DETECTED_RESPONSE silentAlert = {0};
            RtlCopyMemory(&silentAlert, AlertInfo, sizeof(BEHAVIOR_DETECTED_RESPONSE));
            silentAlert.SilentMode = TRUE;
            SendBehaviorLog(Pid, silentAlert.ProcessPath, silentAlert.ThreatClass,
                            silentAlert.Description, silentAlert.Confidence, &silentAlert);
        }
        else if (ProcessPath != NULL || ThreatClass != NULL)
        {
            BEHAVIOR_DETECTED_RESPONSE silentAlert = {0};
            silentAlert.Pid = Pid;
            RtlStringCbCopyA(silentAlert.ProcessPath, sizeof(silentAlert.ProcessPath),
                ProcessPath ? ProcessPath : "");
            RtlStringCbCopyA(silentAlert.ThreatClass, sizeof(silentAlert.ThreatClass),
                ThreatClass ? ThreatClass : "");
            RtlStringCbCopyA(silentAlert.Description, sizeof(silentAlert.Description),
                Description ? Description : "");
            silentAlert.Confidence = Confidence;
            silentAlert.SilentMode = TRUE;
            SendBehaviorLog(Pid, silentAlert.ProcessPath, silentAlert.ThreatClass,
                            silentAlert.Description, silentAlert.Confidence, &silentAlert);
        }

        return STATUS_ACCESS_DENIED;
    }

    /* 分配请求 */
    request = (PRESPONSE_REQUEST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'RESP');
    if (request == NULL)
    {
        DriverDbgPrint("AskClientForBehaviorResponse: Failed to allocate request\n");
        return STATUS_ACCESS_DENIED;
    }

    RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));

    /* 初始化 */
    KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
    request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
    request->RuleType = RULE_TYPE_BEHAVIOR;
    request->ProcessPid = (int)(ULONG_PTR)procId;
    request->FullPath = NULL;
    request->ValueName = NULL;
    request->NewValueData = NULL;

    /* 查找源进程的父进程 PID 和名称。
     * AskClientForBehaviorResponse 在 work item 系统线程中执行，
     * PsGetCurrentProcess() 返回 System 进程而非触发进程，
     * 因此必须通过 procId 查找 EPROCESS 获取父进程信息。 */
    {
        PEPROCESS srcProc = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)procId, &srcProc)))
        {
            HANDLE hProc = NULL;
            NTSTATUS obStatus = ObOpenObjectByPointer(
                srcProc, OBJ_KERNEL_HANDLE, NULL,
                PROCESS_QUERY_LIMITED_INFORMATION,
                *PsProcessType, KernelMode, &hProc);
            if (NT_SUCCESS(obStatus) && hProc != NULL)
            {
                PROCESS_BASIC_INFORMATION pbi = { 0 };
                ULONG retLen = 0;
                NTSTATUS qStatus = ZwQueryInformationProcess(
                    hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
                if (NT_SUCCESS(qStatus) && pbi.InheritedFromUniqueProcessId != 0)
                {
                    HANDLE parentPidHandle = (HANDLE)pbi.InheritedFromUniqueProcessId;
                    request->ParentPid = (int)(ULONG_PTR)parentPidHandle;

                    /* 查找父进程名 */
                    PEPROCESS parentProc = NULL;
                    if (NT_SUCCESS(PsLookupProcessByProcessId(
                            parentPidHandle, &parentProc)))
                    {
                        UCHAR* pName = PsGetProcessImageFileName(parentProc);
                        if (pName)
                        {
                            ULONG i;
                            for (i = 0; i < 15 && pName[i]; i++)
                                request->ParentName[i] = (CHAR)pName[i];
                            request->ParentName[i] = '\0';
                        }
                        ObDereferenceObject(parentProc);
                    }
                }
                ZwClose(hProc);
            }
            ObDereferenceObject(srcProc);
        }
    }

    /* 填充行为分析告警数据 */
    if (AlertInfo != NULL)
    {
        RtlCopyMemory(&request->BehaviorAlert, AlertInfo, sizeof(BEHAVIOR_DETECTED_RESPONSE));

        DriverDbgPrint("AskClientForBehaviorResponse: Copied AlertInfo confidence %ld/10000 for PID=%lld (sizeof=%lu)\n",
            (LONG)(request->BehaviorAlert.Confidence * 10000.0 + 0.5), Pid,
            (ULONG)sizeof(BEHAVIOR_DETECTED_RESPONSE));

        /* 安全网：如果 AlertInfo 中的置信度异常（0/NaN/极小），
         * 使用显式传入的 Confidence 参数，避免客户端显示 0.0%。 */
        if (request->BehaviorAlert.Confidence <= 0.0)
        {
            DriverDbgPrint("AskClientForBehaviorResponse: Invalid AlertInfo confidence %ld/10000, overriding to %ld/10000\n",
                (LONG)(request->BehaviorAlert.Confidence * 10000.0 + 0.5),
                (LONG)(Confidence * 10000.0 + 0.5));
            request->BehaviorAlert.Confidence = Confidence;
        }

        /* 注入类实时告警（句柄层/线程层检测）强制使用传入的 Confidence 参数。
         * 当前只有注入告警会调用此函数，因此可直接覆盖，避免任何数据传递
         * 异常导致客户端显示 0.0%。 */
        if (request->BehaviorAlert.ThreatClass[0] != '\0' &&
            RtlCompareMemory(request->BehaviorAlert.ThreatClass, "DefenseEvasion/Injection", 24) == 24)
        {
            if (request->BehaviorAlert.Confidence != Confidence)
            {
                DriverDbgPrint("AskClientForBehaviorResponse: Forcing injection alert confidence to %ld/10000 (was %ld/10000)\n",
                    (LONG)(Confidence * 10000.0 + 0.5),
                    (LONG)(request->BehaviorAlert.Confidence * 10000.0 + 0.5));
                request->BehaviorAlert.Confidence = Confidence;
            }
        }
    }
    else
    {
        request->BehaviorAlert.Pid = Pid;
        RtlStringCbCopyA(request->BehaviorAlert.ProcessPath, sizeof(request->BehaviorAlert.ProcessPath),
            ProcessPath ? ProcessPath : "");
        RtlStringCbCopyA(request->BehaviorAlert.ThreatClass, sizeof(request->BehaviorAlert.ThreatClass),
            ThreatClass ? ThreatClass : "");
        RtlStringCbCopyA(request->BehaviorAlert.Description, sizeof(request->BehaviorAlert.Description),
            Description ? Description : "");
        request->BehaviorAlert.Confidence = Confidence;
        request->BehaviorAlert.EvidenceCount = 0;
    }

    /* 插入队列 */
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
    if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        DriverDbgPrint("AskClientForBehaviorResponse: Queue full, denying by default\n");
        result = STATUS_ACCESS_DENIED;
        goto Cleanup;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DriverDbgPrint("Behavior alert sent to user-mode: Pid=%lld, Class=%s, Confidence=%ld%%\n",
        Pid, request->BehaviorAlert.ThreatClass,
        (LONG)(request->BehaviorAlert.Confidence * 100.0 + 0.5));

    /* 等待用户响应，35 秒超时 */
    timeout.QuadPart = -35 * 1000 * 1000 * 10;
    waitStatus = KeWaitForSingleObject(
        &request->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (waitStatus != STATUS_SUCCESS)
    {
        DriverDbgPrint("AskClientForBehaviorResponse: Timeout, Pid=%lld\n", Pid);
        KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
        if (request->ListEntry.Flink != &request->ListEntry)
        {
            RemoveEntryList(&request->ListEntry);
            InitializeListHead(&request->ListEntry);
            InterlockedDecrement(&g_RequestQueueCount);
            result = STATUS_ACCESS_DENIED;
        }
        else
        {
            // 已被 HandleUserResponse 移除并设置了结果
            result = request->ResultStatus;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        goto Cleanup;
    }

    result = request->ResultStatus;

    DriverDbgPrint("Behavior response returned: Pid=%lld, Result=0x%X\n", Pid, result);

    /* 存入缓存 */
    if (g_ResponseCacheEnabled)
    {
        KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
        int slot = -1;
        int emptySlot = -1;
        for (int i = 0; i < MAX_RESPONSE_CACHE; i++)
        {
            if (!g_ResponseCache[i].Valid)
            {
                if (emptySlot == -1) emptySlot = i;
            }
            else if (g_ResponseCache[i].ProcessPid == procId &&
                     g_ResponseCache[i].RuleId == RULE_ID_BEHAVIOR_ANALYSIS)
            {
                slot = i;
                break;
            }
        }
        if (slot == -1) slot = emptySlot;
        if (slot != -1)
        {
            g_ResponseCache[slot].ProcessPid = procId;
            g_ResponseCache[slot].RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
            g_ResponseCache[slot].LastResponse = result;
            g_ResponseCache[slot].Valid = TRUE;
        }
        KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    }

Cleanup:
    if (request != NULL)
    {
        ExFreePool(request);
    }
    return result;
}

// ----------------------------------------------------------------------------
// AskClientForRollbackConfirm - 威胁回滚确认请求，查询用户态并等待
// 发送 BA_ROLLBACK_LIST 到用户态，等待用户选择回滚/忽略及选中项
// 返回: STATUS_SUCCESS = 用户已响应, STATUS_TIMEOUT = 超时（默认忽略）
// ----------------------------------------------------------------------------
NTSTATUS AskClientForRollbackConfirm(
    _In_ const BA_ROLLBACK_LIST* rollbackList,
    _Out_ BA_ROLLBACK_SELECTION* outSelection)
{
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;
    LARGE_INTEGER timeout;
    NTSTATUS waitStatus;
    NTSTATUS result;

    if (rollbackList == NULL || outSelection == NULL)
        return STATUS_INVALID_PARAMETER;

    /* 默认返回忽略 */
    RtlZeroMemory(outSelection, sizeof(BA_ROLLBACK_SELECTION));

    /* 检查全局取消标志 */
    if (g_ResponseSystemCancelled)
    {
        DriverDbgPrint("AskClientForRollbackConfirm: System cancelled, default ignore\n");
        return STATUS_CANCELLED;
    }

    /* 无回滚项时直接返回忽略 */
    if (rollbackList->itemCount <= 0)
    {
        DriverDbgPrint("AskClientForRollbackConfirm: No items to rollback\n");
        return STATUS_SUCCESS;
    }

    /* 分配请求 */
    request = (PRESPONSE_REQUEST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'RESP');
    if (request == NULL)
    {
        DriverDbgPrint("AskClientForRollbackConfirm: Failed to allocate request\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));

    /* 初始化 */
    KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
    request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;  /* 复用行为分析 RuleId */
    request->RuleType = RULE_TYPE_ROLLBACK_CONFIRM;
    request->ProcessPid = (int)rollbackList->rootPid;
    request->FullPath = NULL;
    request->ValueName = NULL;
    request->NewValueData = NULL;

    /* 分配并拷贝回滚列表（用户态通过 GetPendingRequest 读取） */
    request->RollbackList = (PBA_ROLLBACK_LIST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(BA_ROLLBACK_LIST), 'RBLK');
    if (request->RollbackList == NULL)
    {
        DriverDbgPrint("AskClientForRollbackConfirm: Failed to allocate rollback list\n");
        ExFreePool(request);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlCopyMemory(request->RollbackList, rollbackList, sizeof(BA_ROLLBACK_LIST));

    DriverDbgPrint("[BA-ROLLBACK-CONFIRM] Sending rollback list: rootPid=%lld items=%d class=%s\n",
        rollbackList->rootPid, rollbackList->itemCount, rollbackList->threatClass);

    /* 插入队列 */
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
    if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        DriverDbgPrint("AskClientForRollbackConfirm: Queue full, default ignore\n");
        ExFreePool(request->RollbackList);
        ExFreePool(request);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    /* 等待用户响应，60 秒超时（回滚决策需要更多时间审视列表） */
    timeout.QuadPart = -60 * 1000 * 1000 * 10;
    waitStatus = KeWaitForSingleObject(
        &request->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout);

    if (waitStatus != STATUS_SUCCESS)
    {
        DriverDbgPrint("[BA-ROLLBACK-CONFIRM] Timeout, rootPid=%lld\n", rollbackList->rootPid);
        KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
        if (request->ListEntry.Flink != &request->ListEntry)
        {
            RemoveEntryList(&request->ListEntry);
            InitializeListHead(&request->ListEntry);
            InterlockedDecrement(&g_RequestQueueCount);
            result = STATUS_TIMEOUT;
        }
        else
        {
            /* 已被 HandleUserResponse 移除并设置了结果 */
            result = request->ResultStatus;
        }
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        goto Cleanup;
    }

    result = request->ResultStatus;
    RtlCopyMemory(outSelection, &request->RollbackSelection, sizeof(BA_ROLLBACK_SELECTION));

    DriverDbgPrint("[BA-ROLLBACK-CONFIRM] Response: decision=%d items=%d\n",
        outSelection->decision, outSelection->itemCount);

Cleanup:
    if (request != NULL)
    {
        if (request->RollbackList != NULL)
            ExFreePool(request->RollbackList);
        ExFreePool(request);
    }
    return result;
}

// ----------------------------------------------------------------------------
// SendBehaviorLog - 发送行为分析日志到用户态（Fire-and-Forget，不等待响应）
// 用于日志记录模式：驱动将检测结果发送到客户端展示，不阻塞定时器线程
// ----------------------------------------------------------------------------
VOID SendBehaviorLog(
    _In_ INT64 Pid,
    _In_ const CHAR* ProcessPath,
    _In_ const CHAR* ThreatClass,
    _In_ const CHAR* Description,
    _In_ DOUBLE Confidence,
    _In_ const BEHAVIOR_DETECTED_RESPONSE* AlertInfo)
{
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;

    request = (PRESPONSE_REQUEST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'RESP');
    if (request == NULL) {
        DriverDbgPrint("SendBehaviorLog: Failed to allocate request\n");
        return;
    }

    RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));

    /* 初始化事件（HandleUserResponse 需要设置此事件，即使没人等待） */
    KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
    request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;
    request->RuleType = RULE_TYPE_BEHAVIOR;
    request->ProcessPid = (int)(ULONG_PTR)Pid;
    request->FireAndForget = TRUE;  /* 发送后不等待，由 HandleUserResponse 释放 */
    request->FullPath = NULL;
    request->ValueName = NULL;
    request->NewValueData = NULL;

    /* 填充行为分析数据 */
    if (AlertInfo != NULL) {
        RtlCopyMemory(&request->BehaviorAlert, AlertInfo, sizeof(BEHAVIOR_DETECTED_RESPONSE));
    } else {
        request->BehaviorAlert.Pid = Pid;
        RtlStringCbCopyA(request->BehaviorAlert.ProcessPath, sizeof(request->BehaviorAlert.ProcessPath),
            ProcessPath ? ProcessPath : "");
        RtlStringCbCopyA(request->BehaviorAlert.ThreatClass, sizeof(request->BehaviorAlert.ThreatClass),
            ThreatClass ? ThreatClass : "");
        RtlStringCbCopyA(request->BehaviorAlert.Description, sizeof(request->BehaviorAlert.Description),
            Description ? Description : "");
        request->BehaviorAlert.Confidence = Confidence;
        request->BehaviorAlert.EvidenceCount = 0;
    }

    /* 插入队列，不等待 */
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
    if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        ExFreePool(request);
        return;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DriverDbgPrint("Behavior log sent to user-mode: Pid=%lld, Class=%s, Confidence=%ld%%\n",
        Pid, request->BehaviorAlert.ThreatClass,
        (LONG)(Confidence * 100.0 + 0.5));
}

// ----------------------------------------------------------------------------
// SendInjectionLog - 发送驱动注入日志到用户态（Fire-and-Forget，不等待响应）
// 用于驱动注入流程的日志记录，转发到 main.cpp 日志显示
// ----------------------------------------------------------------------------
VOID SendInjectionLog(
    _In_ const CHAR* Message)
{
    PRESPONSE_REQUEST request;
    KLOCK_QUEUE_HANDLE lockHandle;

    request = (PRESPONSE_REQUEST)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(RESPONSE_REQUEST), 'RESP');
    if (request == NULL) {
        return;
    }

    RtlZeroMemory(request, sizeof(RESPONSE_REQUEST));

    /* 初始化事件（HandleUserResponse 需要设置此事件，即使没人等待） */
    KeInitializeEvent(&request->CompletionEvent, SynchronizationEvent, FALSE);
    request->RuleId = RULE_ID_BEHAVIOR_ANALYSIS;  /* 复用 RuleId */
    request->RuleType = RULE_TYPE_INJECTION_LOG;
    request->FireAndForget = TRUE;  /* 发送后不等待，由 HandleUserResponse 释放 */
    request->FullPath = NULL;
    request->ValueName = NULL;
    request->NewValueData = NULL;

    /* 填充日志消息 */
    RtlStringCbCopyA(request->InjectionLog.Message, sizeof(request->InjectionLog.Message),
        Message ? Message : "");

    /* 插入队列，不等待 */
    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);
    if (!NT_SUCCESS(EnqueueRequest(request, &lockHandle)))
    {
        KeReleaseInStackQueuedSpinLock(&lockHandle);
        ExFreePool(request);
        return;
    }
    KeReleaseInStackQueuedSpinLock(&lockHandle);
}

// ============================================================================
// 响应缓存控制函数
// ============================================================================

VOID ResponseCacheSetEnabled(BOOLEAN enabled)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
    g_ResponseCacheEnabled = enabled;
    if (!enabled)
    {
        RtlZeroMemory(g_ResponseCache, sizeof(g_ResponseCache));
    }
    KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    DriverDbgPrint("Response cache: %s\n", enabled ? "ENABLED" : "DISABLED");
}

BOOLEAN ResponseCacheIsEnabled()
{
    return g_ResponseCacheEnabled;
}

VOID ResponseCacheClear()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
    RtlZeroMemory(g_ResponseCache, sizeof(g_ResponseCache));
    KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    DriverDbgPrint("Response cache: cleared\n");
}

VOID ResponseCacheRemovePid(HANDLE procId)
{
    KIRQL oldIrql;
    int removed = 0;
    int i;
    KeAcquireSpinLock(&g_ResponseCacheLock, &oldIrql);
    for (i = 0; i < MAX_RESPONSE_CACHE; i++) {
        if (g_ResponseCache[i].Valid && g_ResponseCache[i].ProcessPid == procId) {
            RtlZeroMemory(&g_ResponseCache[i], sizeof(RESPONSE_CACHE_ENTRY));
            removed++;
        }
    }
    KeReleaseSpinLock(&g_ResponseCacheLock, oldIrql);
    if (removed > 0) {
        DriverDbgPrint("Response cache: removed %d entries for PID %d\n",
            removed, (ULONG)(ULONG_PTR)procId);
    }
}

// ============================================================================
// 签名验证缓存：内存缓存，使用文件路径+大小+修改时间作为 key
// ============================================================================

VOID SignatureCacheSetEnabled(BOOLEAN enabled)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SignatureCacheLock, &oldIrql);
    g_SignatureCacheEnabled = enabled;
    if (!enabled)
    {
        RtlZeroMemory(g_SignatureCache, sizeof(g_SignatureCache));
    }
    KeReleaseSpinLock(&g_SignatureCacheLock, oldIrql);
    DriverDbgPrint("Signature cache: %s\n", enabled ? "ENABLED" : "DISABLED");
}

BOOLEAN SignatureCacheIsEnabled()
{
    return g_SignatureCacheEnabled;
}

VOID SignatureCacheClear()
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SignatureCacheLock, &oldIrql);
    RtlZeroMemory(g_SignatureCache, sizeof(g_SignatureCache));
    KeReleaseSpinLock(&g_SignatureCacheLock, oldIrql);
    DriverDbgPrint("Signature cache: cleared\n");
}

VOID SignatureCacheRemoveFile(_In_ const CHAR* FilePath)
{
    KIRQL oldIrql;
    int removed = 0;
    int i;
    KeAcquireSpinLock(&g_SignatureCacheLock, &oldIrql);
    for (i = 0; i < MAX_SIGNATURE_CACHE_ENTRIES; i++) {
        if (g_SignatureCache[i].Valid &&
            strcmp(g_SignatureCache[i].FilePath, FilePath) == 0) {
            RtlZeroMemory(&g_SignatureCache[i], sizeof(SIGNATURE_CACHE_ENTRY));
            removed++;
        }
    }
    KeReleaseSpinLock(&g_SignatureCacheLock, oldIrql);
    if (removed > 0) {
        DriverDbgPrint("Signature cache: removed %d entries for %s\n",
            removed, FilePath);
    }
}

BOOLEAN SignatureCacheLookup(
    _In_ const CHAR* FilePath,
    _In_ ULONGLONG FileSize,
    _In_ ULONGLONG LastWriteTime,
    _Out_opt_ PBOOLEAN IsSigned,
    _Out_opt_ PNTSTATUS VerifyStatus)
{
    KIRQL oldIrql;
    int i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_SignatureCacheLock, &oldIrql);
    for (i = 0; i < MAX_SIGNATURE_CACHE_ENTRIES; i++) {
        if (g_SignatureCache[i].Valid &&
            strcmp(g_SignatureCache[i].FilePath, FilePath) == 0 &&
            g_SignatureCache[i].FileSize == FileSize &&
            g_SignatureCache[i].LastWriteTime == LastWriteTime)
        {
            // Check TTL
            ULONGLONG now = KeQueryInterruptTime();
            if ((now - g_SignatureCache[i].Timestamp) <
                (ULONGLONG)SIGNATURE_CACHE_TTL_SECONDS * 10000000ULL)
            {
                if (IsSigned) *IsSigned = g_SignatureCache[i].IsSigned;
                if (VerifyStatus) *VerifyStatus = g_SignatureCache[i].VerifyStatus;
                found = TRUE;
            }
            else
            {
                // Expired
                RtlZeroMemory(&g_SignatureCache[i], sizeof(SIGNATURE_CACHE_ENTRY));
            }
            break;
        }
    }
    KeReleaseSpinLock(&g_SignatureCacheLock, oldIrql);
    return found;
}

VOID SignatureCacheAdd(
    _In_ const CHAR* FilePath,
    _In_ ULONGLONG FileSize,
    _In_ ULONGLONG LastWriteTime,
    _In_ BOOLEAN IsSigned,
    _In_ NTSTATUS VerifyStatus)
{
    KIRQL oldIrql;
    int i;
    int oldestIdx = 0;
    ULONGLONG oldestTime = MAXULONG64;
    ULONGLONG now = KeQueryInterruptTime();

    KeAcquireSpinLock(&g_SignatureCacheLock, &oldIrql);
    for (i = 0; i < MAX_SIGNATURE_CACHE_ENTRIES; i++) {
        if (!g_SignatureCache[i].Valid) {
            // Empty slot found
            RtlZeroMemory(&g_SignatureCache[i], sizeof(SIGNATURE_CACHE_ENTRY));
            strncpy(g_SignatureCache[i].FilePath, FilePath, MAX_PATH_LEN - 1);
            g_SignatureCache[i].FilePath[MAX_PATH_LEN - 1] = '\0';
            g_SignatureCache[i].FileSize = FileSize;
            g_SignatureCache[i].LastWriteTime = LastWriteTime;
            g_SignatureCache[i].IsSigned = IsSigned;
            g_SignatureCache[i].VerifyStatus = VerifyStatus;
            g_SignatureCache[i].Timestamp = now;
            g_SignatureCache[i].Valid = TRUE;
            KeReleaseSpinLock(&g_SignatureCacheLock, oldIrql);
            return;
        }
        if (g_SignatureCache[i].Timestamp < oldestTime) {
            oldestTime = g_SignatureCache[i].Timestamp;
            oldestIdx = i;
        }
    }
    // Cache full, evict oldest
    RtlZeroMemory(&g_SignatureCache[oldestIdx], sizeof(SIGNATURE_CACHE_ENTRY));
    strncpy(g_SignatureCache[oldestIdx].FilePath, FilePath, MAX_PATH_LEN - 1);
    g_SignatureCache[oldestIdx].FilePath[MAX_PATH_LEN - 1] = '\0';
    g_SignatureCache[oldestIdx].FileSize = FileSize;
    g_SignatureCache[oldestIdx].LastWriteTime = LastWriteTime;
    g_SignatureCache[oldestIdx].IsSigned = IsSigned;
    g_SignatureCache[oldestIdx].VerifyStatus = VerifyStatus;
    g_SignatureCache[oldestIdx].Timestamp = now;
    g_SignatureCache[oldestIdx].Valid = TRUE;
    KeReleaseSpinLock(&g_SignatureCacheLock, oldIrql);
}

// ============================================================================
// 响应缓存控制函数
// ============================================================================

// ============================================================================
// ResponseSystemCancelAll - 取消所有待处理请求
// 驱动卸载时调用，唤醒所有等待用户响应的线程
// ============================================================================
VOID ResponseSystemCancelAll(VOID)
{
    KLOCK_QUEUE_HANDLE lockHandle;
    PLIST_ENTRY entry;
    PLIST_ENTRY nextEntry;
    PRESPONSE_REQUEST request;

    DriverDbgPrint("ResponseSystem: Cancelling all pending requests...\n");

    /* 设置全局取消标志，防止新请求入队 */
    InterlockedExchange(&g_ResponseSystemCancelled, 1);

    KeAcquireInStackQueuedSpinLock(&g_RequestQueueLock, &lockHandle);

    /* 遍历所有待处理请求 */
    entry = g_RequestQueueHead.Flink;
    while (entry != &g_RequestQueueHead)
    {
        nextEntry = entry->Flink;
        request = CONTAINING_RECORD(entry, RESPONSE_REQUEST, ListEntry);

        /* 从队列中移除 */
        RemoveEntryList(entry);
        InitializeListHead(entry);
        InterlockedDecrement(&g_RequestQueueCount);

        if (request->FireAndForget)
        {
            /* Fire-and-Forget 请求：直接释放内存 */
            if (request->FullPath != NULL) ExFreePool(request->FullPath);
            if (request->ValueName != NULL) ExFreePool(request->ValueName);
            if (request->NewValueData != NULL) ExFreePool(request->NewValueData);
            if (request->RollbackList != NULL) ExFreePool(request->RollbackList);
            ExFreePool(request);
        }
        else
        {
            /* 同步等待请求：设置取消状态并唤醒等待线程
             * 线程被唤醒后会自行释放内存 */
            request->ResultStatus = STATUS_CANCELLED;
            KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);
        }

        entry = nextEntry;
    }

    KeReleaseInStackQueuedSpinLock(&lockHandle);

    DriverDbgPrint("ResponseSystem: All pending requests cancelled\n");
}

#ifdef _KERNEL_MODE
// ----------------------------------------------------------------------------
// SignatureEaRead - 读取文件签名验证 Kernel EA
// ----------------------------------------------------------------------------
NTSTATUS SignatureEaRead(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _Out_opt_ PBOOLEAN IsSigned,
    _Out_opt_ PNTSTATUS VerifyStatus,
    _Out_opt_ PBOOLEAN EaHit)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING fileName;
    PFILE_FULL_EA_INFORMATION eaBuffer = NULL;
    ULONG eaLength;
    ULONG offset;
    BOOLEAN found = FALSE;

    if (EaHit) *EaHit = FALSE;
    if (IsSigned) *IsSigned = FALSE;
    if (VerifyStatus) *VerifyStatus = STATUS_NOT_FOUND;

    if (Instance == NULL || NameInfo == NULL ||
        NameInfo->Name.Length == 0 || NameInfo->Name.Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    eaLength = sizeof(FILE_FULL_EA_INFORMATION) + SIG_VERIFY_EA_NAME_LENGTH + 1 + SIG_VERIFY_EA_VALUE_LENGTH;
    eaBuffer = (PFILE_FULL_EA_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, eaLength, 'EAi1');
    if (eaBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(eaBuffer, eaLength);

    fileName = NameInfo->Name;
    InitializeObjectAttributes(&objAttr, &fileName, OBJ_KERNEL_HANDLE, NULL, NULL);

    /* 使用 FltCreateFileEx2 替代 IoCreateFileEx：
     * 1. 传入 Instance 让 Filter Manager 跳过当前 minifilter 的 Pre/Post 回调，
     *    避免 IRP_MJ_CREATE 递归触发 VerifyFileSignatureWithCache 导致栈溢出/池破坏。
     * 2. DriverContext 传 NULL（不需要 ECP），修复原来将 PFLT_INSTANCE 强转为
     *    PIO_DRIVER_CREATE_CONTEXT 的类型混淆蓝屏。 */
    status = FltCreateFileEx2(
        g_FilterHandle,
        Instance,
        &fileHandle,
        NULL,                       /* 不需要 FileObject */
        FILE_READ_EA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,                       /* AllocationSize */
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,                       /* EaBuffer */
        0,                          /* EaLength */
        IO_FORCE_ACCESS_CHECK | IO_IGNORE_SHARE_ACCESS_CHECK,
        NULL);                      /* DriverContext - 不需要 ECP */
    if (!NT_SUCCESS(status))
    {
        ExFreePool(eaBuffer);
        return status;
    }

    status = ZwQueryEaFile(
        fileHandle,
        &ioStatus,
        eaBuffer,
        eaLength,
        FALSE,
        NULL,
        0,
        NULL,
        TRUE);
    if (!NT_SUCCESS(status))
    {
        if (fileHandle) ZwClose(fileHandle);
        ExFreePool(eaBuffer);
        return status;
    }

    offset = 0;
    while (offset < ioStatus.Information)
    {
        PFILE_FULL_EA_INFORMATION eaEntry = (PFILE_FULL_EA_INFORMATION)((PUCHAR)eaBuffer + offset);
        if (eaEntry->EaNameLength == SIG_VERIFY_EA_NAME_LENGTH &&
            RtlCompareMemory(eaEntry->EaName, SIG_VERIFY_EA_NAME, SIG_VERIFY_EA_NAME_LENGTH) == SIG_VERIFY_EA_NAME_LENGTH)
        {
            if (eaEntry->EaValueLength >= SIG_VERIFY_EA_VALUE_LENGTH)
            {
                PSIGNATURE_EA_VALUE eaValue = (PSIGNATURE_EA_VALUE)((PUCHAR)eaEntry +
                    FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + eaEntry->EaNameLength);
                if (IsSigned) *IsSigned = eaValue->IsSigned;
                if (VerifyStatus) *VerifyStatus = eaValue->VerifyStatus;
                if (EaHit) *EaHit = TRUE;
                found = TRUE;
            }
            break;
        }
        if (eaEntry->NextEntryOffset == 0) break;
        offset += eaEntry->NextEntryOffset;
    }

    if (fileHandle) ZwClose(fileHandle);
    ExFreePool(eaBuffer);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

// ----------------------------------------------------------------------------
// SignatureEaWrite - 写入/更新文件签名验证 Kernel EA
// ----------------------------------------------------------------------------
NTSTATUS SignatureEaWrite(
    _In_ PFLT_INSTANCE Instance,
    _In_ PFLT_FILE_NAME_INFORMATION NameInfo,
    _In_ BOOLEAN IsSigned,
    _In_ NTSTATUS VerifyStatus)
{
    NTSTATUS status;
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus;
    OBJECT_ATTRIBUTES objAttr;
    PFILE_FULL_EA_INFORMATION eaBuffer = NULL;
    ULONG eaLength;
    PSIGNATURE_EA_VALUE eaValue;

    if (Instance == NULL || NameInfo == NULL ||
        NameInfo->Name.Length == 0 || NameInfo->Name.Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    eaLength = sizeof(FILE_FULL_EA_INFORMATION) + SIG_VERIFY_EA_NAME_LENGTH + 1 + SIG_VERIFY_EA_VALUE_LENGTH;
    eaBuffer = (PFILE_FULL_EA_INFORMATION)ExAllocatePool2(POOL_FLAG_NON_PAGED, eaLength, 'EAw1');
    if (eaBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(eaBuffer, eaLength);
    eaBuffer->NextEntryOffset = 0;
    eaBuffer->Flags = 0;
    eaBuffer->EaNameLength = (UCHAR)SIG_VERIFY_EA_NAME_LENGTH;
    eaBuffer->EaValueLength = (USHORT)SIG_VERIFY_EA_VALUE_LENGTH;
    RtlCopyMemory(eaBuffer->EaName, SIG_VERIFY_EA_NAME, SIG_VERIFY_EA_NAME_LENGTH);
    eaBuffer->EaName[SIG_VERIFY_EA_NAME_LENGTH] = '\0';

    eaValue = (PSIGNATURE_EA_VALUE)((PUCHAR)eaBuffer +
        FIELD_OFFSET(FILE_FULL_EA_INFORMATION, EaName) + eaBuffer->EaNameLength);
    eaValue->FileSize = 0;
    eaValue->LastWriteTime = 0;
    eaValue->IsSigned = IsSigned;
    eaValue->VerifyStatus = VerifyStatus;
    eaValue->Timestamp = KeQueryInterruptTime();
    eaValue->Flags = 0;

    InitializeObjectAttributes(&objAttr, &NameInfo->Name, OBJ_KERNEL_HANDLE, NULL, NULL);

    /* FltCreateFileEx2 传入 Instance 避免 minifilter 回调重入，DriverContext=NULL
     * 修复 IoCreateFileEx 类型混淆蓝屏。 */
    status = FltCreateFileEx2(
        g_FilterHandle,
        Instance,
        &fileHandle,
        NULL,
        FILE_WRITE_EA | SYNCHRONIZE,
        &objAttr,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0,
        IO_FORCE_ACCESS_CHECK | IO_IGNORE_SHARE_ACCESS_CHECK,
        NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(eaBuffer);
        return status;
    }

    status = ZwSetEaFile(
        fileHandle,
        &ioStatus,
        eaBuffer,
        eaLength);
    if (!NT_SUCCESS(status))
    {
        DriverDbgPrint("SignatureEaWrite: ZwSetEaFile failed for %wZ, status=0x%X\n",
            NameInfo->Name, status);
    }

    if (fileHandle) ZwClose(fileHandle);
    ExFreePool(eaBuffer);

    return status;
}

// ----------------------------------------------------------------------------
// CiInitialize - 直接解析 ci.dll 导出函数
// ----------------------------------------------------------------------------
NTSTATUS CiInitialize(VOID)
{
    NTSTATUS status = STATUS_SUCCESS;
    UNICODE_STRING ciFuncName;

    if (g_CiValidateFileObject != NULL && g_CiFreePolicyInfo != NULL)
        return STATUS_SUCCESS;

    RtlInitUnicodeString(&ciFuncName, L"CiValidateFileObject");
    g_CiValidateFileObject = (CI_VALIDATE_FILE_OBJECT)MmGetSystemRoutineAddress(&ciFuncName);
    if (g_CiValidateFileObject == NULL)
    {
        DriverDbgPrint("CiInitialize: CiValidateFileObject not found\n");
        status = STATUS_ENTRYPOINT_NOT_FOUND;
        return status;
    }

    RtlInitUnicodeString(&ciFuncName, L"CiFreePolicyInfo");
    g_CiFreePolicyInfo = (CI_FREE_POLICY_INFO)MmGetSystemRoutineAddress(&ciFuncName);
    if (g_CiFreePolicyInfo == NULL)
    {
        DriverDbgPrint("CiInitialize: CiFreePolicyInfo not found\n");
        g_CiValidateFileObject = NULL;
        status = STATUS_ENTRYPOINT_NOT_FOUND;
        return status;
    }

    DriverDbgPrint("CiInitialize: CI functions resolved\n");
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// CiCleanup - 释放 CI 函数指针
// ----------------------------------------------------------------------------
VOID CiCleanup(VOID)
{
    g_CiValidateFileObject = NULL;
    g_CiFreePolicyInfo = NULL;
    DriverDbgPrint("CiCleanup: CI functions released\n");
}

// ----------------------------------------------------------------------------
// CiVerifyFileObject - 使用 CiValidateFileObject 验证文件签名
// ----------------------------------------------------------------------------
NTSTATUS CiVerifyFileObject(_In_ struct _FILE_OBJECT* FileObject, _Out_ PBOOLEAN IsSigned)
{
    NTSTATUS status;
    CI_POLICY_INFO signerPolicy = { 0 };
    CI_POLICY_INFO timestampPolicy = { 0 };
    LARGE_INTEGER signingTime = { 0 };
    UCHAR digestBuffer[64];
    ULONG digestSize = sizeof(digestBuffer);
    ULONG digestId = 0;

    if (IsSigned == NULL || FileObject == NULL)
        return STATUS_INVALID_PARAMETER;

    if (g_CiValidateFileObject == NULL)
    {
        DriverDbgPrint("CiVerifyFileObject: CiValidateFileObject not loaded\n");
        return STATUS_NOT_IMPLEMENTED;
    }

    *IsSigned = FALSE;

    signerPolicy.StructSize = sizeof(signerPolicy);
    timestampPolicy.StructSize = sizeof(timestampPolicy);

    status = g_CiValidateFileObject(
        FileObject,
        0,
        0,
        &signerPolicy,
        &timestampPolicy,
        &signingTime,
        digestBuffer,
        &digestSize,
        &digestId
    );

    if (NT_SUCCESS(status) && NT_SUCCESS(signerPolicy.VerificationStatus))
    {
        *IsSigned = TRUE;
    }

    if (signerPolicy.CertChainInfo && g_CiFreePolicyInfo)
    {
        g_CiFreePolicyInfo(&signerPolicy);
    }
    if (timestampPolicy.CertChainInfo && g_CiFreePolicyInfo)
    {
        g_CiFreePolicyInfo(&timestampPolicy);
    }

    return status;
}
#endif