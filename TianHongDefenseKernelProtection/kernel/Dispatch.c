#include "../shared/Common.h"
#include "../shared/Ioctl.h"
#include "Main.h"
#include "Dispatch.h"
#include "ProcessCallback.h"
#include "RegistryCallback.h"
#include "FileFilter.h"
#include "ResponseSystem.h"
#include "BehaviorAnalysis.h"
#include "BehaviorDynamicRules.h"
#include "BehaviorAnalysisScoring.h"
#include "Whitelist.h"

/* PsGetProcessProtection — 读取 EPROCESS->Protection。
 * Windows 8.1+ 通常已导出，若未导出则 fallback 到直接读内存。
 * 注意：该 API 签名为 PS_PROTECTION PsGetProcessProtection(PEPROCESS Process)，
 * 返回值即为 Protection 字节（UCHAR），不通过输出参数返回，也不是 NTSTATUS。 */
typedef UCHAR (*PFN_PS_GET_PROCESS_PROTECTION)(PEPROCESS Process);
static PFN_PS_GET_PROCESS_PROTECTION g_pfnPsGetProcessProtection = NULL;

/* 尝试解析 PsGetProcessProtection；仅在第一次设置 PPL 时调用 */
static VOID DispatchResolvePsProtectionApi(VOID)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsGetProcessProtection");
    g_pfnPsGetProcessProtection = (PFN_PS_GET_PROCESS_PROTECTION)MmGetSystemRoutineAddress(&name);
}

/* 读取指定进程的 PS_PROTECTION 值 */
static NTSTATUS DispatchReadProcessProtection(HANDLE Pid, PUCHAR pProtection)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &process);
    if (!NT_SUCCESS(status) || process == NULL)
        return status;

    if (g_pfnPsGetProcessProtection != NULL) {
        *pProtection = g_pfnPsGetProcessProtection(process);
        status = STATUS_SUCCESS;
    } else {
        /* 未导出 PsGetProcessProtection 时拒绝读取，避免使用硬编码偏移损坏 EPROCESS。 */
        status = STATUS_NOT_SUPPORTED;
    }

    ObDereferenceObject(process);
    return status;
}

/* 缓存的 EPROCESS->Protection 偏移，首次设置时动态探测 */
static ULONG g_EprocessProtectionOffset = 0;

/* 保护 CmRegisterCallback 注册/注销的竞态条件 */
KSPIN_LOCK g_RegCallbackLock;

/* 根据 OS 版本返回已知的 EPROCESS->Protection（PS_PROTECTION，1 字节）偏移。
 * 未知版本返回 0，由调用方决定是否走动态扫描。
 *
 * 参考：
 *   Win10 22H2 (19045) EPROCESS->Protection = 0x87A
 *   Win10 2004~21H2 (19041~19044) 亦保持 0x87A
 *   Win11 21H2/22H2/23H2 (22000~22631) 目前实测/广泛引用为 0x87A
 *   更旧版本（1607~1909）偏移较小，随 build 递增。
 */
static ULONG DispatchGetKnownProtectionOffset(VOID)
{
    RTL_OSVERSIONINFOW osvi = { sizeof(RTL_OSVERSIONINFOW) };
    if (!NT_SUCCESS(RtlGetVersion(&osvi)))
        return 0;

    /* Windows 10 / 11 均为 Major=10 Minor=0 */
    if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0)
    {
        if (osvi.dwBuildNumber >= 22000)
        {
            /* Windows 11 21H2/22H2/23H2 */
            if (osvi.dwBuildNumber <= 22631)
                return 0x87A;
            /* Windows 11 24H2+ 偏移未统一确认，不硬编码 */
        }
        else
        {
            /* Windows 10 */
            if (osvi.dwBuildNumber >= 19041 && osvi.dwBuildNumber <= 19045)
                return 0x87A; /* 2004 / 20H2 / 21H1 / 21H2 / 22H2 */
            if (osvi.dwBuildNumber >= 18362 && osvi.dwBuildNumber <= 18363)
                return 0x6FA; /* 1903 / 1909 */
            if (osvi.dwBuildNumber == 17763)
                return 0x6D2; /* 1809 */
            if (osvi.dwBuildNumber == 17134)
                return 0x6CA; /* 1803 */
            if (osvi.dwBuildNumber >= 15063 && osvi.dwBuildNumber <= 16299)
                return 0x6CA; /* 1703 / 1709 */
            if (osvi.dwBuildNumber == 14393)
                return 0x6C2; /* 1607 */
        }
    }
    return 0;
}

/* 验证 offset 是否为目标进程 EPROCESS->Protection 字段：
 * 写入期望值后，通过 PsGetProcessProtection 读回确认。
 * 成功时若 pOriginalProtection 非空，返回写入前的原始值。 */
static NTSTATUS DispatchVerifyProtectionOffset(
    PEPROCESS targetProcess,
    ULONG offset,
    UCHAR desiredProtection,
    PUCHAR pOriginalProtection)
{
    PUCHAR base = (PUCHAR)targetProcess;
    UCHAR saved = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    if (pOriginalProtection != NULL)
        *pOriginalProtection = 0;

    __try
    {
        saved = base[offset];
        base[offset] = desiredProtection;

        UCHAR readBack = g_pfnPsGetProcessProtection(targetProcess);

        if (readBack == desiredProtection)
        {
            if (pOriginalProtection != NULL)
                *pOriginalProtection = saved;
            return STATUS_SUCCESS;
        }

        /* 不是正确偏移：恢复原始值 */
        base[offset] = saved;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_UNSUCCESSFUL;
        __try
        {
            base[offset] = saved;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            (void)0;
        }
    }

    return STATUS_NOT_FOUND;
}

/* 动态定位 EPROCESS->Protection 偏移。
 * 策略（按优先级）：
 * 1) 先用 OS 版本对应的已知偏移验证，避免对错误偏移做大量写入；
 * 2) 失败则在目标进程上扫描当前保护值并验证；
 * 3) 仍失败则从 PsGetProcessProtection 第一条机器指令解析偏移。
 *    PsGetProcessProtection 第一条指令为「MOV AL, byte ptr [RCX + offset]」
 *    （8A 81 XX XX XX XX），偏移量在指令字节 2~5 处，直接读取即可。
 *
 * 注意：该操作仍属于未文档化行为，如果微软改变 EPROCESS 布局或 PsGetProcessProtection
 * 实现，可能导致误判/蓝屏。仅作为兼容当前 Windows 版本的折中方案。 */
static NTSTATUS DispatchFindProtectionOffset(PEPROCESS targetProcess, UCHAR desiredProtection)
{
    NTSTATUS status;
    UCHAR originalProtection = 0;
    RTL_OSVERSIONINFOW osvi = { sizeof(RTL_OSVERSIONINFOW) };

    if (g_pfnPsGetProcessProtection == NULL)
        return STATUS_NOT_SUPPORTED;

    originalProtection = g_pfnPsGetProcessProtection(targetProcess);

    RtlGetVersion(&osvi); /* 失败仅影响日志，不影响功能 */

    /* 1) 优先使用 OS 版本对应的已知偏移并验证 */
    ULONG knownOffset = DispatchGetKnownProtectionOffset();
    if (knownOffset != 0)
    {
        status = DispatchVerifyProtectionOffset(targetProcess, knownOffset, desiredProtection, &originalProtection);
        if (NT_SUCCESS(status))
        {
            g_EprocessProtectionOffset = knownOffset;
            DriverDbgPrint("[PPL] Use known Protection offset 0x%X (build %u)\n",
                           knownOffset, osvi.dwBuildNumber);
            return STATUS_SUCCESS;
        }
        DriverDbgPrint("[PPL] Known offset 0x%X verification failed (0x%X), fallback to scan\n",
                       knownOffset, status);
    }

    /* 2) 动态扫描：在目标进程 EPROCESS 中搜索当前保护值，验证后缓存。
     * 扫描目标而非 System，避免 System 进程保护值特殊或 PsInitialSystemProcess
     * 类型差异导致误判；同时扩大扫描范围以覆盖未来可能的布局变化。 */
    PUCHAR targetBase = (PUCHAR)targetProcess;

    for (ULONG offset = 0x500; offset < 0xA00; offset++)
    {
        if (targetBase[offset] != originalProtection)
            continue;

        status = DispatchVerifyProtectionOffset(targetProcess, offset, desiredProtection, NULL);
        if (NT_SUCCESS(status))
        {
            g_EprocessProtectionOffset = offset;
            DriverDbgPrint("[PPL] Dynamic scan found Protection offset 0x%X (build %u)\n",
                           offset, osvi.dwBuildNumber);
            return STATUS_SUCCESS;
        }
    }

    /* 3) 从 PsGetProcessProtection 机器码解析偏移。
     * PsGetProcessProtection 第一条指令为「MOV AL, [RCX + imm32]」
     * 编码为 8A 81 XX XX XX XX（6 字节），偏移量在 +2 处（小端序 DWORD）。 */
    {
        PUCHAR funcBase = (PUCHAR)g_pfnPsGetProcessProtection;
        if (funcBase && funcBase[0] == 0x8A && funcBase[1] == 0x81)
        {
            ULONG codeOffset = *(DWORD*)(funcBase + 2);
            if (codeOffset != 0)
            {
                DriverDbgPrint("[PPL] Parsed Protection offset 0x%X from PsGetProcessProtection code\n",
                               codeOffset);
                status = DispatchVerifyProtectionOffset(targetProcess, codeOffset, desiredProtection, &originalProtection);
                if (NT_SUCCESS(status))
                {
                    g_EprocessProtectionOffset = codeOffset;
                    DriverDbgPrint("[PPL] Code-parse offset 0x%X verified (build %u)\n",
                                   codeOffset, osvi.dwBuildNumber);
                    return STATUS_SUCCESS;
                }
                DriverDbgPrint("[PPL] Code-parse offset 0x%X verification failed (0x%X)\n",
                               codeOffset, status);
            }
        }
    }

    DriverDbgPrint("[PPL] Failed to find Protection offset (build %u)\n", osvi.dwBuildNumber);
    return STATUS_NOT_FOUND;
}

/* 写指定进程 EPROCESS->Protection（内部实现，调用方已持有 EPROCESS 引用） */
static NTSTATUS DispatchWriteProcessProtectionEx(PEPROCESS process, UCHAR protection)
{
    if (process == NULL)
        return STATUS_INVALID_PARAMETER;

    if (g_pfnPsGetProcessProtection == NULL)
        DispatchResolvePsProtectionApi();

    if (g_pfnPsGetProcessProtection == NULL)
        return STATUS_NOT_SUPPORTED;

    /* 使用 InterlockedCompareExchange 保护偏移探测，确保只有一个线程进行扫描。
     * 先尝试原子地将 0 替换为 0xFFFFFFFF（占位符），成功者负责探测。 */
    if (InterlockedCompareExchange((LONG*)&g_EprocessProtectionOffset, 0xFFFFFFFF, 0) == 0)
    {
        NTSTATUS status = DispatchFindProtectionOffset(process, protection);
        if (!NT_SUCCESS(status))
        {
            /* 探测失败，重置为 0，允许后续调用重试 */
            InterlockedExchange((LONG*)&g_EprocessProtectionOffset, 0);
            return status;
        }
        /* 探测成功，g_EprocessProtectionOffset 已被 DispatchFindProtectionOffset 设置 */
    }
    else
    {
        /* 其他线程正在探测，自旋等待直到探测完成 */
        ULONG spinCount = 0;
        while (g_EprocessProtectionOffset == 0xFFFFFFFF && spinCount < 10000)
        {
            KeStallExecutionProcessor(10);
            spinCount++;
        }
        if (g_EprocessProtectionOffset == 0xFFFFFFFF || g_EprocessProtectionOffset == 0)
        {
            /* 探测超时或失败，回退到直接尝试 */
            DriverDbgPrint("[PPL] Offset discovery timeout, falling back\n");
            return STATUS_NOT_FOUND;
        }
    }

    PUCHAR base = (PUCHAR)process;
    __try
    {
        base[g_EprocessProtectionOffset] = protection;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/* 根据 OS 版本返回已知的 EPROCESS->SignatureLevel 偏移；未知返回 0。
 * SignatureLevel / SectionSignatureLevel 无导出 API 可验证，写错偏移会破坏 EPROCESS，
 * 因此仅对经过确认的 Windows 10 22H2（19045）返回；其它版本只设置 Protection。 */
static ULONG DispatchGetKnownSignatureLevelOffset(VOID)
{
    RTL_OSVERSIONINFOW osvi = { sizeof(RTL_OSVERSIONINFOW) };
    if (!NT_SUCCESS(RtlGetVersion(&osvi)))
        return 0;

    if (osvi.dwMajorVersion == 10 && osvi.dwMinorVersion == 0)
    {
        if (osvi.dwBuildNumber < 22000)
        {
            /* Windows 10：2004~22H2 共享 0x2E8 */
            if (osvi.dwBuildNumber >= 19041 && osvi.dwBuildNumber <= 19045)
                return 0x2E8;
        }
        /* Windows 11 各版本 SignatureLevel 偏移未充分确认，不硬编码，避免蓝屏。 */
    }
    return 0;
}

/* 设置指定进程的 SignatureLevel、SectionSignatureLevel 和 Protection。
 * SignerType / SignatureSigner 与 PS_PROTECTION 位域一致。
 * SignatureLevel = SectionSignatureLevel = (SignerType << 4) | SignatureSigner。
 * Protection = SignerType | (SignatureSigner << 4)。 */
static NTSTATUS DispatchSetProcessSignature(
    HANDLE Pid,
    UCHAR signerType,
    UCHAR signatureSigner)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &process);
    if (!NT_SUCCESS(status) || process == NULL)
        return status;

    UCHAR signatureLevel = (signerType << 4) | signatureSigner;
    UCHAR protection = signerType | (signatureSigner << 4);

    /* 1) 设置 SignatureLevel / SectionSignatureLevel（仅对已知版本） */
    ULONG sigOffset = DispatchGetKnownSignatureLevelOffset();
    if (sigOffset != 0)
    {
        PUCHAR base = (PUCHAR)process;
        __try
        {
            base[sigOffset] = signatureLevel;
            base[sigOffset + 1] = signatureLevel; /* SectionSignatureLevel */
            DriverDbgPrint("[PPL] Set SignatureLevel=0x%02X at offset 0x%X for PID %lu\n",
                           signatureLevel, sigOffset, (ULONG)(ULONG_PTR)Pid);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ObDereferenceObject(process);
            return STATUS_UNSUCCESSFUL;
        }
    }
    else
    {
        DriverDbgPrint("[PPL] SignatureLevel offset unknown for this OS, skipping\n");
    }

    /* 2) 设置 Protection（带动态偏移探测） */
    status = DispatchWriteProcessProtectionEx(process, protection);
    if (!NT_SUCCESS(status) && sigOffset != 0)
    {
        /* Protection 设置失败时，最佳努力恢复 SignatureLevel */
        PUCHAR base = (PUCHAR)process;
        __try
        {
            base[sigOffset] = 0;
            base[sigOffset + 1] = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            (void)0;
        }
    }

    ObDereferenceObject(process);
    return status;
}

/* 写指定进程的 PS_PROTECTION 值（兼容旧接口） */
static NTSTATUS DispatchWriteProcessProtection(HANDLE Pid, UCHAR protection)
{
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(Pid, &process);
    if (!NT_SUCCESS(status) || process == NULL)
        return status;

    status = DispatchWriteProcessProtectionEx(process, protection);
    ObDereferenceObject(process);
    return status;
}

/* ============================================================================
 * Dispatch.c - IRP 分发处理函数
 * 处理用户态 IOCTL 请求，分发给各子系统
 * 通信模型：LIST_ENTRY + KEVENT 同步请求-响应
 * ========================================================================== */

// ----------------------------------------------------------------------------
// DispatchCreate - 处理 IRP_MJ_CREATE（打开设备）
// ----------------------------------------------------------------------------
NTSTATUS DispatchCreate(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDevObj);

    DriverDbgPrint("Device opened\n");

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// DispatchClose - 处理 IRP_MJ_CLOSE（关闭设备）
// ----------------------------------------------------------------------------
NTSTATUS DispatchClose(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDevObj);

    DriverDbgPrint("Device closed\n");

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// DispatchIoctl - 处理 IRP_MJ_DEVICE_CONTROL（IOCTL 分发）
// ----------------------------------------------------------------------------
NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDevObj);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG ioctlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    // 默认输出信息
    pIrp->IoStatus.Information = 0;

    switch (ioctlCode)
    {
    // ── 进程保护 ──
    case IOCTL_PROTECT_PROCESS:
    {
        PCOMM_CONTROL_PACKET packet;
        PCHAR pidStr;
        ULONG pid;
        ULONG inputLen;

        inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        // 检查输入缓冲区
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_PROTECT_PROCESS: Buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        pidStr = packet->Data;

        DriverDbgPrint("Process protection request received, PID string: %s\n", pidStr);

        // 解析 PID 字符串
        status = StringToULong(pidStr, &pid);
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("Failed to parse PID: %s\n", pidStr);
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // 添加 PID 到保护列表
        status = AddPidToProtectedList((HANDLE)(ULONG_PTR)pid);
        if (!NT_SUCCESS(status) && status != STATUS_ALREADY_REGISTERED)
        {
            DriverDbgPrint("Failed to add PID to protected list: 0x%X\n", status);
            break;
        }

        /* ObRegisterCallbacks 已在 DriverEntry 中注册，无需在此重复注册 */

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 添加规则（注册表） ──
    case IOCTL_ADD_RULE:
    {
        PCOMM_CONTROL_PACKET packet;
        PRULE_DATA ruleData;
        ULONG inputLen;
        KIRQL oldIrql;

        inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        // 检查输入缓冲区
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_ADD_RULE: Buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;

        // 验证 Data 字段能容纳 RULE_DATA 结构体，防止越界读取
        if (inputLen < FIELD_OFFSET(COMM_CONTROL_PACKET, Data) + sizeof(RULE_DATA))
        {
            DriverDbgPrint("IOCTL_ADD_RULE: Data field too small for RULE_DATA\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ruleData = (PRULE_DATA)&packet->Data;

        KeAcquireSpinLock(&g_RulesLock, &oldIrql);

        // 检查规则列表是否已满
        if (g_RuleCount >= MAX_RULES)
        {
            KeReleaseSpinLock(&g_RulesLock, oldIrql);
            DriverDbgPrint("Rule list full (max %d), cannot add new rule\n", MAX_RULES);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        // 存储规则数据
        RtlCopyMemory(&g_Rules[g_RuleCount], ruleData, sizeof(RULE_DATA));
        g_RuleCount++;

        DriverDbgPrint("Rule added: RuleId=%d, Type=%d, current count=%d\n",
            ruleData->RuleId, ruleData->rt, g_RuleCount);

        KeReleaseSpinLock(&g_RulesLock, oldIrql);

        // 如果是注册表规则且尚未注册 CmRegisterCallback，则注册
        // 使用专用锁保护检查-注册序列，防止多线程竞态导致 cookie 泄漏
        if (ruleData->rt == RULE_TYPE_REG)
        {
            KIRQL cbIrql;
            KeAcquireSpinLock(&g_RegCallbackLock, &cbIrql);
            if (g_RegCookie.QuadPart == 0)
            {
                UNICODE_STRING altitude;

                RtlInitUnicodeString(&altitude, L"320100");
                status = CmRegisterCallback(
                    RegistryProtectCallback,
                    NULL,
                    &g_RegCookie);

                if (!NT_SUCCESS(status))
                {
                    DriverDbgPrint("CmRegisterCallback registration failed: 0x%X\n", status);
                    g_RegCookie.QuadPart = 0;
                }
                else
                {
                    DriverDbgPrint("CmRegisterCallback registered successfully\n");
                }
            }
            KeReleaseSpinLock(&g_RegCallbackLock, cbIrql);
        }

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 添加文件规则 ──
    case IOCTL_ADD_FILE_RULE:
    {
        PCOMM_CONTROL_PACKET packet;
        PRULE_FILE_DATA fileRule;
        ULONG inputLen;

        inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        // 检查输入缓冲区
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_ADD_FILE_RULE: Buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        fileRule = (PRULE_FILE_DATA)&packet->Data;

        DriverDbgPrint("Add file rule request received: RuleId=%d, Path=%s\n",
            fileRule->RuleId, fileRule->FullPath);

        // 调用文件过滤模块添加规则
        status = FileFilterAddRule(fileRule);
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("Failed to add file rule: 0x%X\n", status);
        }
        else
        {
            DriverDbgPrint("File rule added successfully: RuleId=%d\n", fileRule->RuleId);
        }

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 删除文件规则 ──
    case IOCTL_REMOVE_FILE_RULE:
    {
        PCOMM_CONTROL_PACKET packet;
        PULONG ruleId;
        ULONG inputLen;

        inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        // 检查输入缓冲区
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_REMOVE_FILE_RULE: Buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        ruleId = (PULONG)&packet->Data;

        DriverDbgPrint("Remove file rule request received: RuleId=%d\n", *ruleId);

        // 调用文件过滤模块删除规则
        status = FileFilterRemoveRule(*ruleId);
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("Failed to remove file rule: RuleId=%d, Status=0x%X\n", *ruleId, status);
        }
        else
        {
            DriverDbgPrint("File rule removed successfully: RuleId=%d\n", *ruleId);
        }

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 获取文件规则统计 ──
    case IOCTL_GET_FILE_RULE_STATS:
    {
        FILE_RULE_STATS stats;
        PCOMM_CONTROL_PACKET packet;
        ULONG outputLen;

        outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        // 检查输出缓冲区
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            outputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_GET_FILE_RULE_STATS: Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // 调用文件过滤模块获取统计信息
        RtlZeroMemory(&stats, sizeof(FILE_RULE_STATS));
        status = FileFilterGetStats(&stats);
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("Failed to get file rule stats: 0x%X\n", status);
            break;
        }

        // 写入统计信息到输出缓冲区
        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        RtlCopyMemory(&packet->Data, &stats, sizeof(FILE_RULE_STATS));
        pIrp->IoStatus.Information = sizeof(COMM_CONTROL_PACKET);

        DriverDbgPrint("File rule stats: Total=%d, Active=%d, Blocked=%d, Allowed=%d\n",
            stats.TotalRules, stats.ActiveRules, stats.BlockedOperations, stats.AllowedOperations);

        break;
    }

    // ── 清除所有文件规则 ──
    case IOCTL_CLEAR_FILE_RULES:
    {
        DriverDbgPrint("Clear all file rules request received\n");

        // 调用文件过滤模块清除所有规则
        status = FileFilterClearRules();
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("Failed to clear file rules: 0x%X\n", status);
        }
        else
        {
            DriverDbgPrint("All file rules cleared\n");
        }

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 删除注册表规则 ──
    case IOCTL_REMOVE_RULE:
    {
        PCOMM_CONTROL_PACKET packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        if (packet == NULL || stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(COMM_CONTROL_PACKET))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // 验证 Data 字段至少包含一个 ULONG（RuleId）
        if (stack->Parameters.DeviceIoControl.InputBufferLength <
            FIELD_OFFSET(COMM_CONTROL_PACKET, Data) + sizeof(ULONG))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG ruleId = *(PULONG)packet->Data;
        DriverDbgPrint("Remove registry rule request received: RuleId=%lu\n", ruleId);

        KIRQL oldIrql;
        BOOLEAN found = FALSE;

        KeAcquireSpinLock(&g_RulesLock, &oldIrql);

        for (ULONG i = 0; i < g_RuleCount; i++)
        {
            if (g_Rules[i].RuleId == ruleId && g_Rules[i].rt == RULE_TYPE_REG)
            {
                // 将后续元素前移
                for (ULONG j = i; j < g_RuleCount - 1; j++)
                {
                    g_Rules[j] = g_Rules[j + 1];
                }
                RtlZeroMemory(&g_Rules[g_RuleCount - 1], sizeof(RULE_DATA));
                g_RuleCount--;
                found = TRUE;
                DriverDbgPrint("Registry rule removed: RuleId=%lu, remaining count=%lu\n", ruleId, g_RuleCount);
                break;
            }
        }

        KeReleaseSpinLock(&g_RulesLock, oldIrql);

        if (!found)
        {
            DriverDbgPrint("Registry rule not found: RuleId=%lu\n", ruleId);
            status = STATUS_NOT_FOUND;
        }
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 清除所有注册表规则 ──
    case IOCTL_CLEAR_RULES:
    {
        KIRQL oldIrql;

        DriverDbgPrint("Clear all registry rules request received\n");

        KeAcquireSpinLock(&g_RulesLock, &oldIrql);
        RtlZeroMemory(g_Rules, sizeof(g_Rules));
        g_RuleCount = 0;
        KeReleaseSpinLock(&g_RulesLock, oldIrql);

        DriverDbgPrint("All registry rules cleared\n");
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 获取待处理的检测请求（异步查询） ──
    case IOCTL_RULE_DETECTED_REQUEST:
    {
        // 委托给响应系统处理
        status = GetPendingRequest(pIrp, stack);
        break;
    }

    // ── 发送用户响应 ──
    case IOCTL_RULE_DETECTED_SEND_USER_RESPONSE:
    {
        DriverDbgPrint("User response received\n");

        // 委托给响应系统处理用户响应
        status = HandleUserResponse(pIrp, stack);
        break;
    }

    // ── 设置响应缓存 ──
    case IOCTL_SET_RESPONSE_CACHE:
    {
        PCOMM_CONTROL_PACKET packet;
        ULONG inputLen;

        inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_SET_RESPONSE_CACHE: Buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;

        // 验证 Data 字段至少包含一个 ULONG
        if (inputLen < FIELD_OFFSET(COMM_CONTROL_PACKET, Data) + sizeof(ULONG))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG cacheCmd = *(PULONG)packet->Data; // 0=disable, 1=enable, 2=clear

        switch (cacheCmd)
        {
        case 0:
            ResponseCacheSetEnabled(FALSE);
            DriverDbgPrint("Response cache: disabled by user-mode\n");
            break;
        case 1:
            ResponseCacheSetEnabled(TRUE);
            DriverDbgPrint("Response cache: enabled by user-mode\n");
            break;
        case 2:
            ResponseCacheClear();
            DriverDbgPrint("Response cache: cleared by user-mode\n");
            break;
        default:
            DriverDbgPrint("IOCTL_SET_RESPONSE_CACHE: Unknown command %d\n", cacheCmd);
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 清除所有受保护 PID ──
    case IOCTL_CLEAR_PROTECTED_PIDS:
    {
        DriverDbgPrint("Clear all protected PIDs request received\n");

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_ProtectedPids.Lock, &oldIrql);
        g_ProtectedPids.Count = 0;
        RtlZeroMemory(g_ProtectedPids.Pids, sizeof(g_ProtectedPids.Pids));
        KeReleaseSpinLock(&g_ProtectedPids.Lock, oldIrql);

        DriverDbgPrint("All protected PIDs cleared\n");
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── 动态行为分析：评估所有进程 ──
    case IOCTL_BEHAVIOR_ANALYSIS_EVALUATE:
    {
        PCOMM_CONTROL_PACKET packet;
        ULONG outputLen;
        /* 堆分配，避免栈溢出（每个 BA_THREAT_RESULT ~5.5KB，64个 ~352KB） */
        BA_THREAT_RESULT* results;
        INT resultCount = 0;
        INT i;

        outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            outputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_BEHAVIOR_ANALYSIS_EVALUATE: Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        results = (BA_THREAT_RESULT*)ExAllocatePool2(
            POOL_FLAG_PAGED, sizeof(BA_THREAT_RESULT) * BA_MAX_RESULTS, 'BAnl');
        if (results == NULL)
        {
            DriverDbgPrint("IOCTL_BEHAVIOR_ANALYSIS_EVALUATE: Memory allocation failed\n");
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        BehaviorEvaluateAll(results, BA_MAX_RESULTS, &resultCount);

        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(packet, sizeof(COMM_CONTROL_PACKET));

        /* 将结果序列化到 Data 字段 */
        /* 格式: 前4字节=结果数量, 后面跟多个 BA_THREAT_RESULT */
        CHAR* dest = packet->Data;
        dest += sizeof(INT);  /* 预留 count 字段，稍后回填实际复制数量 */

        INT actualCopied = 0;
        for (i = 0; i < resultCount && i < BA_MAX_RESULTS; i++) {
            INT copySize = sizeof(BA_THREAT_RESULT);
            INT remaining = sizeof(packet->Data) - (INT)(dest - packet->Data);
            if (remaining < copySize) break;
            RtlCopyMemory(dest, &results[i], copySize);
            dest += copySize;
            actualCopied++;
        }

        /* 回填实际复制的数量（可能小于 resultCount，因为 Data 缓冲区大小有限） */
        *(INT*)packet->Data = actualCopied;

        ExFreePool(results);

        pIrp->IoStatus.Information = sizeof(COMM_CONTROL_PACKET);

        DriverDbgPrint("Behavior analysis: Evaluated %d processes, found %d threats, copied %d to client\n",
            resultCount >= 0 ? resultCount : 0, resultCount, actualCopied);
        break;
    }

    // ── 动态行为分析：获取统计 ──
    case IOCTL_BEHAVIOR_ANALYSIS_GET_STATS:
    {
        PCOMM_CONTROL_PACKET packet;
        ULONG outputLen;
        BA_STATS stats;

        outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            outputLen < sizeof(COMM_CONTROL_PACKET))
        {
            DriverDbgPrint("IOCTL_BEHAVIOR_ANALYSIS_GET_STATS: Output buffer too small\n");
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        BehaviorGetStats(&stats);
        packet = (PCOMM_CONTROL_PACKET)pIrp->AssociatedIrp.SystemBuffer;
        RtlCopyMemory(packet->Data, &stats, sizeof(BA_STATS));
        pIrp->IoStatus.Information = sizeof(COMM_CONTROL_PACKET);

        DriverDbgPrint("Behavior analysis stats: Processes=%d, History=%d, Indicators=%d\n",
            stats.processCount, stats.historyCount, stats.indicatorCount);
        break;
    }

    // ── 动态行为分析：清除数据 ──
    case IOCTL_BEHAVIOR_ANALYSIS_CLEAR:
    {
        DriverDbgPrint("Behavior analysis: Clear all data request received\n");

        BehaviorAnalysisCleanup();
        BehaviorAnalysisInit();

        DriverDbgPrint("Behavior analysis: All data cleared\n");
        pIrp->IoStatus.Information = 0;
        break;
    }

    case IOCTL_PREPARE_UNLOAD:
    {
        DriverDbgPrint("Prepare unload: cancelling pending requests first\n");

        /* 步骤1: 取消所有待处理的用户响应请求，唤醒所有等待线程
         * 这确保行为分析定时器线程不会阻塞在用户响应等待上 */
        ResponseSystemCancelAll();

        /* 步骤2: 停止行为分析定时器线程
         * 等待更长时间（10秒）确保线程完全退出
         * 注意：线程被取消后会从用户响应等待中返回，恢复挂起的进程，然后退出 */
        DriverDbgPrint("Prepare unload: stopping behavior analysis timer thread\n");
        BehaviorStopTimerThread();

        /* 步骤3: 卸载 Minifilter（FltUnregisterFilter 必须在 DriverUnload 之前调用） */
        DriverDbgPrint("Prepare unload: unregistering minifilter\n");
        FileFilterUnloadWrapper();

        /* 步骤4: 注销所有回调，确保驱动可以被安全卸载 */
        DriverDbgPrint("Prepare unload: unregistering all callbacks\n");

        if (g_ProcessRegistrationHandle != NULL)
        {
            ObUnRegisterCallbacks(g_ProcessRegistrationHandle);
            g_ProcessRegistrationHandle = NULL;
            DriverDbgPrint("Prepare unload: process/thread callbacks unregistered\n");
        }

        if (g_ProcessCreateNotifyHandle != NULL)
        {
            PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, TRUE);
            g_ProcessCreateNotifyHandle = NULL;
            DriverDbgPrint("Prepare unload: process create notify unregistered\n");
        }

        if (g_ThreadCreateNotifyHandle != NULL)
        {
            PsRemoveCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);
            g_ThreadCreateNotifyHandle = NULL;
            DriverDbgPrint("Prepare unload: thread create notify unregistered\n");
        }

        if (g_LoadImageNotifyHandle != NULL)
        {
            PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
            g_LoadImageNotifyHandle = NULL;
            DriverDbgPrint("Prepare unload: load image notify unregistered\n");
        }

        if (g_RegCookie.QuadPart != 0)
        {
            CmUnRegisterCallback(g_RegCookie);
            g_RegCookie.QuadPart = 0;
            DriverDbgPrint("Prepare unload: registry callback unregistered\n");
        }

        DriverDbgPrint("Prepare unload: complete, driver ready to be unloaded\n");
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_DLL_INJECT_PATH：设置待注入的 DLL 路径 ──
    case IOCTL_SET_DLL_INJECT_PATH:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: WCHAR 路径字符串（以 null 终止）
         * 路径长度不能超过 259 个 WCHAR */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(WCHAR) ||
            inputLen > sizeof(g_DllInjectPath))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        /* 复制 DLL 路径到全局变量 */
        SIZE_T copyLen = inputLen;
        if (copyLen >= sizeof(g_DllInjectPath))
            copyLen = sizeof(g_DllInjectPath) - sizeof(WCHAR);

        RtlZeroMemory(g_DllInjectPath, sizeof(g_DllInjectPath));
        RtlCopyMemory(g_DllInjectPath, pIrp->AssociatedIrp.SystemBuffer, copyLen);
        g_DllInjectPath[copyLen / sizeof(WCHAR)] = L'\0';  /* 确保 null 终止 */

        g_bDllInjectPathSet = TRUE;
        DriverDbgPrint("DLL inject path set: %ws\n", g_DllInjectPath);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_R3_PROTECTION_ENABLED：启用/禁用 R3 DLL 防护注入 ──
    case IOCTL_SET_R3_PROTECTION_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 BOOLEAN（1 字节），TRUE 表示启用 R3 DLL 注入，FALSE 表示禁用 */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(BOOLEAN))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = *(BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer;
        g_bR3ProtectionEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("R3 DLL protection %s\n",
            g_bR3ProtectionEnabled ? "enabled" : "disabled");
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_BEHAVIOR_DETECTION_ENABLED：启用/禁用行为检测 ──
    case IOCTL_SET_BEHAVIOR_DETECTION_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 BOOLEAN（1 字节），TRUE 启用行为检测，FALSE 禁用 */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(BOOLEAN))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = *(BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer;
        BehaviorSetDetectionEnabled(bEnable);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_PROCESS_PROTECTION_ENABLED：启用/禁用 R0 独立进程创建检查 ──
    case IOCTL_SET_PROCESS_PROTECTION_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 BOOLEAN（1 字节），TRUE 启用，FALSE 禁用 */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(BOOLEAN))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = *(BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer;
        g_bProcessProtectionEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("[PROCESS-CHECK] Process protection %s via IOCTL\n",
            g_bProcessProtectionEnabled ? "ENABLED" : "DISABLED");
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_UNSIGNED_DLL_SCAN：启用/禁用签名程序加载未签名 DLL 扫描 ──
    case IOCTL_SET_UNSIGNED_DLL_SCAN:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 两个 BOOLEAN（2 字节）
         *   Byte 0: TRUE=启用未签名 DLL 扫描, FALSE=禁用
         *   Byte 1: TRUE=阻塞扫描（等待 main.cpp 结果）, FALSE=异步扫描（仅告警） */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < 2)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = ((BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer)[0];
        BOOLEAN bBlocking = ((BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer)[1];
        g_bUnsignedDllScanEnabled = bEnable ? TRUE : FALSE;
        g_bDllBlockingScanEnabled = bBlocking ? TRUE : FALSE;
        DriverDbgPrint("[DLL-SCAN] Unsigned DLL scan %s, blocking=%s via IOCTL\n",
            g_bUnsignedDllScanEnabled ? "ENABLED" : "DISABLED",
            g_bDllBlockingScanEnabled ? "YES" : "NO");
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_SILENT_MODE：启用/禁用静默模式 ──
    case IOCTL_SET_SILENT_MODE:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 BOOLEAN（1 字节），TRUE 启用静默模式，FALSE 禁用 */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(BOOLEAN))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = *(BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer;
        g_bSilentModeEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("[SILENT-MODE] Silent mode %s via IOCTL\n",
            g_bSilentModeEnabled ? "ENABLED" : "DISABLED");
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_MEMORY_PROTECTION_ENABLED：启用/禁用内存防护（句柄剥离/注入拦截） ──
    case IOCTL_SET_MEMORY_PROTECTION_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 BOOLEAN（1 字节），TRUE 启用内存防护，FALSE 禁用 */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(BOOLEAN))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = *(BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer;
        g_bMemoryProtectionEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("[MEM-PROTECT] Memory protection %s via IOCTL\n",
            g_bMemoryProtectionEnabled ? "ENABLED" : "DISABLED");
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_TRUSTED_PID：设置受信任主程序 PID（注入检测白名单） ──
    case IOCTL_SET_TRUSTED_PID:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 ULONG（4 字节）PID */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(ULONG))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONG trustedPid = *(PULONG)pIrp->AssociatedIrp.SystemBuffer;
        g_TrustedMainPid = (HANDLE)(ULONG_PTR)trustedPid;
        DriverDbgPrint("[TRUSTED-PID] Trusted main PID set to %lu via IOCTL\n", trustedPid);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_PROCESS_PPL：将用户态进程提升为指定 PPL，并设置 SignatureLevel ──
    case IOCTL_SET_PROCESS_PPL:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        if (pIrp->AssociatedIrp.SystemBuffer == NULL)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (g_pfnPsGetProcessProtection == NULL)
            DispatchResolvePsProtectionApi();

        ULONG targetPid = 0;
        UCHAR signerType = 1;        /* 默认 ProtectedLight */
        UCHAR signatureSigner = 3;   /* 默认 Antimalware */

        /* 兼容旧格式：输入为 ULONG PID；新格式：PROCESS_SIGNATURE */
        if (inputLen == sizeof(ULONG))
        {
            targetPid = *(PULONG)pIrp->AssociatedIrp.SystemBuffer;
        }
        else if (inputLen >= sizeof(PROCESS_SIGNATURE))
        {
            PPROCESS_SIGNATURE sig = (PPROCESS_SIGNATURE)pIrp->AssociatedIrp.SystemBuffer;
            targetPid = sig->Pid;
            signerType = sig->SignerType;
            signatureSigner = sig->SignatureSigner;
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (targetPid == 0)
            targetPid = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();

        status = DispatchSetProcessSignature(
            (HANDLE)(ULONG_PTR)targetPid, signerType, signatureSigner);
        if (NT_SUCCESS(status)) {
            DriverDbgPrint("[PPL] PID %lu set PPL (type=%u signer=%u)\n",
                           targetPid, signerType, signatureSigner);
        } else {
            DriverDbgPrint("[PPL] Failed to set PPL for PID %lu: 0x%X\n", targetPid, status);
        }

        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SYNC_WHITELIST_TO_DRIVER：同步用户态 AutoAllow/AutoPrevent 列表到驱动 ──
    case IOCTL_SYNC_WHITELIST_TO_DRIVER:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PWHITELIST_SYNC_DATA syncData =
            (PWHITELIST_SYNC_DATA)pIrp->AssociatedIrp.SystemBuffer;

        /* 输入: WHITELIST_SYNC_DATA，Type + Count + Entries[] */
        if (syncData == NULL ||
            inputLen < (ULONG)FIELD_OFFSET(WHITELIST_SYNC_DATA, Entries))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = WhitelistSync(syncData->Type, syncData, inputLen);
        if (NT_SUCCESS(status))
        {
            DriverDbgPrint("[WHITELIST] Sync type=%lu count=%lu succeeded\n",
                syncData->Type, syncData->Count);
        }
        else
        {
            DriverDbgPrint("[WHITELIST] Sync type=%lu failed: 0x%X\n",
                syncData->Type, status);
        }
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BEHAVIOR_ETW_MEMORY_EVENT：处理用户态 ETW Threat-Intelligence 内存事件 ──
    case IOCTL_BEHAVIOR_ETW_MEMORY_EVENT:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PETW_MEMORY_EVENT_DATA pEvent =
            (PETW_MEMORY_EVENT_DATA)pIrp->AssociatedIrp.SystemBuffer;

        if (pEvent == NULL || inputLen < sizeof(ETW_MEMORY_EVENT_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        BehaviorHandleEtwMemoryEvent(pEvent);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BEHAVIOR_ETW_NETWORK_EVENT：处理用户态 ETW Network 网络事件用于 C2 检测 ──
    case IOCTL_BEHAVIOR_ETW_NETWORK_EVENT:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PETW_NETWORK_EVENT_DATA pEvent =
            (PETW_NETWORK_EVENT_DATA)pIrp->AssociatedIrp.SystemBuffer;

        if (pEvent == NULL || inputLen < sizeof(ETW_NETWORK_EVENT_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        BehaviorHandleEtwNetworkEvent(pEvent);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BEHAVIOR_ETW_SYSCALL_EVENT：处理用户态 ETW syscall 事件，检测 direct/indirect syscall ──
    case IOCTL_BEHAVIOR_ETW_SYSCALL_EVENT:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PETW_SYSCALL_EVENT_DATA pEvent =
            (PETW_SYSCALL_EVENT_DATA)pIrp->AssociatedIrp.SystemBuffer;

        if (pEvent == NULL || inputLen < sizeof(ETW_SYSCALL_EVENT_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        BehaviorHandleEtwSyscallEvent(pEvent);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BEHAVIOR_NTDLL_RELOAD_EVENT：处理用户态 ntdll 重载/Unhook 检测事件 ──
    case IOCTL_BEHAVIOR_NTDLL_RELOAD_EVENT:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PNTDLL_RELOAD_EVENT_DATA pEvent =
            (PNTDLL_RELOAD_EVENT_DATA)pIrp->AssociatedIrp.SystemBuffer;

        if (pEvent == NULL || inputLen < sizeof(NTDLL_RELOAD_EVENT_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        BehaviorHandleNtdllReloadEvent(pEvent);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_DCOM_PROTECTION_ENABLED：启用/禁用 DCOM 横向移动检测 ──
    case IOCTL_SET_DCOM_PROTECTION_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;

        /* 输入: 一个 BOOLEAN（1 字节），TRUE 启用，FALSE 禁用 */
        if (pIrp->AssociatedIrp.SystemBuffer == NULL ||
            inputLen < sizeof(BOOLEAN))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        BOOLEAN bEnable = *(BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer;
        g_bDcomDetectionEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("[DCOM] DCOM lateral movement detection %s via IOCTL\n",
            g_bDcomDetectionEnabled ? "ENABLED" : "DISABLED");
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BEHAVIOR_DCOM_EVENT：处理用户态 DCOM 横向移动检测事件 ──
    case IOCTL_BEHAVIOR_DCOM_EVENT:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PDCOM_EVENT_DATA pEvent =
            (PDCOM_EVENT_DATA)pIrp->AssociatedIrp.SystemBuffer;

        if (pEvent == NULL || inputLen < sizeof(DCOM_EVENT_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        BehaviorHandleDcomEvent(pEvent);
        status = STATUS_SUCCESS;
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BA_LOAD_DYNAMIC_RULE：加载动态行为规则 ──
    case IOCTL_BA_LOAD_DYNAMIC_RULE:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PBA_DYNAMIC_RULE_LOAD_REQ pReq =
            (PBA_DYNAMIC_RULE_LOAD_REQ)pIrp->AssociatedIrp.SystemBuffer;

        if (pReq == NULL || inputLen < sizeof(BA_DYNAMIC_RULE_LOAD_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // 验证规则 ID 合法性
        if (pReq->Rule.RuleId == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = BaLoadDynamicRule(&pReq->Rule);
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BA_REMOVE_DYNAMIC_RULE：移除动态行为规则 ──
    case IOCTL_BA_REMOVE_DYNAMIC_RULE:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PBA_DYNAMIC_RULE_REMOVE_REQ pReq =
            (PBA_DYNAMIC_RULE_REMOVE_REQ)pIrp->AssociatedIrp.SystemBuffer;

        if (pReq == NULL || inputLen < sizeof(BA_DYNAMIC_RULE_REMOVE_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = BaRemoveDynamicRule(pReq->RuleId);
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BA_CLEAR_DYNAMIC_RULES：清除全部动态规则 ──
    case IOCTL_BA_CLEAR_DYNAMIC_RULES:
    {
        status = BaClearDynamicRules();
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BA_SET_DYNAMIC_RULE_STATE：设置规则状态 ──
    case IOCTL_BA_SET_DYNAMIC_RULE_STATE:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        PBA_DYNAMIC_RULE_STATE_REQ pReq =
            (PBA_DYNAMIC_RULE_STATE_REQ)pIrp->AssociatedIrp.SystemBuffer;

        if (pReq == NULL || inputLen < sizeof(BA_DYNAMIC_RULE_STATE_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = BaSetDynamicRuleContext(pReq->RuleId, pReq->State);
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_BA_GET_DYNAMIC_RULE_STATS：查询规则统计 ──
    case IOCTL_BA_GET_DYNAMIC_RULE_STATS:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PBA_DYNAMIC_RULE_STATS_REQ pReq =
            (PBA_DYNAMIC_RULE_STATS_REQ)pIrp->AssociatedIrp.SystemBuffer;
        PBA_RULE_STATS pStats = (PBA_RULE_STATS)pIrp->AssociatedIrp.SystemBuffer;

        if (pReq == NULL || inputLen < sizeof(BA_DYNAMIC_RULE_STATS_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // 输出缓冲区足够大以容纳单个或全部规则统计
        ULONG maxStats = outputLen / sizeof(BA_RULE_STATS);
        if (maxStats == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = BaGetDynamicRuleStats(pReq->RuleId, pStats);
        if (NT_SUCCESS(status)) {
            ULONG statsCount = (pReq->RuleId == 0) ? g_baDynamicRulePool.Count : 1;
            pIrp->IoStatus.Information = min(statsCount, maxStats) * sizeof(BA_RULE_STATS);
        }
        break;
    }

    // ── IOCTL_BA_GET_DYNAMIC_RULE_LIST：查询规则列表（分页）──
    case IOCTL_BA_GET_DYNAMIC_RULE_LIST:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;
        PBA_DYNAMIC_RULE_LIST_REQ pReq =
            (PBA_DYNAMIC_RULE_LIST_REQ)pIrp->AssociatedIrp.SystemBuffer;
        PBA_DYNAMIC_RULE pOutRules = (PBA_DYNAMIC_RULE)pIrp->AssociatedIrp.SystemBuffer;

        if (pReq == NULL || inputLen < sizeof(BA_DYNAMIC_RULE_LIST_REQ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // 计算输出缓冲区可容纳的规则数
        ULONG maxRules = outputLen / sizeof(BA_DYNAMIC_RULE);
        if (maxRules == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        ULONG actualCount = 0;
        status = BaGetDynamicRuleList(pReq->Offset, pReq->Count, pOutRules, &actualCount);
        if (NT_SUCCESS(status)) {
            pIrp->IoStatus.Information = actualCount * sizeof(BA_DYNAMIC_RULE);
        }
        break;
    }

    // ── IOCTL_BA_GET_DYNAMIC_RULE_VERSION：查询规则集版本 ──
    case IOCTL_BA_GET_DYNAMIC_RULE_VERSION:
    {
        ULONG* pVersion = (ULONG*)pIrp->AssociatedIrp.SystemBuffer;

        if (pVersion == NULL) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        *pVersion = BaGetDynamicRuleVersion();
        pIrp->IoStatus.Information = sizeof(ULONG);
        status = STATUS_SUCCESS;
        break;
    }

    // ── IOCTL_BA_REPORT_FEEDBACK：用户反馈（误报/确认恶意）──
    case IOCTL_BA_REPORT_FEEDBACK:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        typedef struct _BA_FEEDBACK_ENTRY {
            ULONG  RuleId;
            INT64  Pid;
            CHAR   ImagePath[BA_MAX_PATH];
            ULONG  Action;      // 1=允许(确认误报) 2=阻止(确认恶意)
            INT64  TimestampMs;
        } BA_FEEDBACK_ENTRY, *PBA_FEEDBACK_ENTRY;

        PBA_FEEDBACK_ENTRY pFeedback =
            (PBA_FEEDBACK_ENTRY)pIrp->AssociatedIrp.SystemBuffer;

        if (pFeedback == NULL || inputLen < sizeof(ULONG) + sizeof(INT64) + BA_MAX_PATH) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        // 确保 ImagePath 以 NULL 结尾
        pFeedback->ImagePath[BA_MAX_PATH - 1] = '\0';

        status = BehaviorReportFeedback(
            pFeedback->RuleId,
            pFeedback->Pid,
            pFeedback->ImagePath,
            pFeedback->Action,
            pFeedback->TimestampMs
        );
        pIrp->IoStatus.Information = 0;
        break;
    }

    // ── IOCTL_SET_SILVERFOX_ENABLED：启用/禁用 SilverFox 检测 ──
    case IOCTL_SET_SILVERFOX_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (inputLen < sizeof(BOOLEAN)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        BOOLEAN bEnable = *((BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer);
        g_bSilverFoxEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("[IOCTL] SilverFox detection %s\n",
            g_bSilverFoxEnabled ? "ENABLED" : "DISABLED");
        pIrp->IoStatus.Information = 0;
        status = STATUS_SUCCESS;
        break;
    }

    // ── IOCTL_SET_AVBYPASS_ENABLED：启用/禁用 AVBypass 检测 ──
    case IOCTL_SET_AVBYPASS_ENABLED:
    {
        ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
        if (inputLen < sizeof(BOOLEAN)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        BOOLEAN bEnable = *((BOOLEAN*)pIrp->AssociatedIrp.SystemBuffer);
        g_bAVBypassEnabled = bEnable ? TRUE : FALSE;
        DriverDbgPrint("[IOCTL] AVBypass detection %s\n",
            g_bAVBypassEnabled ? "ENABLED" : "DISABLED");
        pIrp->IoStatus.Information = 0;
        status = STATUS_SUCCESS;
        break;
    }

    // ── 未知 IOCTL 代码 ──
    default:
    {
        DriverDbgPrint("Unknown IOCTL code: 0x%X\n", ioctlCode);
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    }

    // 完成 IRP 请求
    pIrp->IoStatus.Status = status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);
    return status;
}