#include "../shared/Common.h"
#include "../shared/Event.h"
#include "../shared/Ioctl.h"
#include "Main.h"
#include "Dispatch.h"
#include "ResponseSystem.h"
#include "ProcessCallback.h"
#include "RegistryCallback.h"
#include "FileFilter.h"
#include "KernelRuleEngine.h"
#include "BehaviorAnalysis.h"
#include "BehaviorDynamicRules.h"
#include "BehaviorIndicatorDefs.h"
#include "Whitelist.h"
#include "DriverDllInject.h"        /* 驱动端 DLL 注入（参考 injdrv: https://github.com/wbenny/injdrv） */

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

/* 外部声明 */
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

/* ZwQueryInformationProcess — 获取进程完整镜像路径 */
NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_to_opt_(ProcessInformationLength, *ReturnLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

// 全局变量
PROTECTED_PID_LIST g_ProtectedPids = { 0 };
PVOID g_ProcessRegistrationHandle = NULL;
LARGE_INTEGER g_RegCookie = { 0 };
PVOID g_ProcessCreateNotifyHandle = NULL;  /* PsSetCreateProcessNotifyRoutineEx 注册句柄 */
PVOID g_ThreadCreateNotifyHandle = NULL;   /* PsSetCreateThreadNotifyRoutine 注册句柄 */
PVOID g_LoadImageNotifyHandle = NULL;       /* PsSetLoadImageNotifyRoutine 注册句柄 */
WCHAR g_DllInjectPath[260] = { 0 };         /* 待注入的 DLL 路径 */
BOOLEAN g_bDllInjectPathSet = FALSE;         /* DLL 路径是否已设置 */
BOOLEAN g_bR3ProtectionEnabled = FALSE;      /* R3 DLL 防护是否启用：默认禁用，需用户态显式开启才注入 DLL */
BOOLEAN g_bProcessProtectionEnabled = FALSE; /* R0 独立进程创建检查：默认禁用，由用户态通过 IOCTL 控制 */
BOOLEAN g_bUnsignedDllScanEnabled = FALSE;   /* 签名程序加载未签名 DLL 扫描：默认禁用 */
BOOLEAN g_bDllBlockingScanEnabled = FALSE;   /* 签名程序加载未签名 DLL 扫描是否阻塞：默认非阻塞 */
BOOLEAN g_bMemoryProtectionEnabled = FALSE;  /* 内存防护（句柄剥离/注入拦截）：默认禁用，由用户态通过 IOCTL 控制 */
BOOLEAN g_bDcomDetectionEnabled = FALSE;    /* DCOM 横向移动检测：默认禁用，由用户态通过 IOCTL 控制 */
HANDLE g_TrustedMainPid = NULL;              /* 受信任主程序 PID：由用户态通过 IOCTL 设置 */

// 全局队列锁（请求响应系统）
KSPIN_LOCK g_RequestQueueLock;
LIST_ENTRY g_RequestQueueHead;
KEVENT g_RequestAvailableEvent;

// 规则存储
RULE_DATA g_Rules[MAX_RULES];
ULONG g_RuleCount = 0;
KSPIN_LOCK g_RulesLock;

// 文件规则存储
RULE_FILE_DATA g_FileRules[MAX_FILE_RULES];
ULONG g_FileRuleCount = 0;
ULONG g_TotalBlockedOperations = 0;
ULONG g_TotalAllowedOperations = 0;
PDEVICE_OBJECT g_pDriverDeviceObject = NULL; /* 驱动设备对象，用于内核态 IOCTL */

// ── Ntdll 重载/Unhook 检测全局变量 ──
NTDLL_TRACK_CONTEXT g_NtdllTrackContext = { 0 };
BOOLEAN g_bNtdllReloadDetectionEnabled = FALSE;  /* Ntdll 重载检测是否启用 */
ULONG g_NtdllReloadEventSequence = 0;             /* 事件序列号 */

// 自定义dbgprint
/* DriverDbgPrint 可能在 DISPATCH_LEVEL/APC_LEVEL 的回调中被调用，必须位于
 * 非分页代码段，否则取指令时会触发 IRQL_LESS_OR_EQUAL 蓝屏。 */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(NONPAGED, DriverDbgPrint)
#endif
__drv_maxIRQL(APC_LEVEL) VOID DriverDbgPrint(
    __in PCSTR Format,
    ...
)
{
#if TH_RELEASE_BUILD
    UNREFERENCED_PARAMETER(Format);
    return;
#else
    va_list args;
    CHAR buffer[512];
    NTSTATUS status;

    va_start(args, Format);

    // 格式化输出
    status = RtlStringCbVPrintfA(buffer, sizeof(buffer), Format, args);
    if (NT_SUCCESS(status))
    {
        // 添加驱动前缀，输出
        DbgPrint("%s%s", DRIVER_PREFIX, buffer);
    }

    va_end(args);
#endif
}

// 字符串转ULONG
NTSTATUS StringToULong(PCHAR str, PULONG result)
{
    ULONG value = 0;
    ULONG i = 0;

    if (str == NULL || result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 跳过开头空格
    while (str[i] == ' ' || str[i] == '\t') {
        i++;
    }

    // 检查是否为空字符串
    if (str[i] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    // 转换数字
    while (str[i] != '\0') {
        if (str[i] >= '0' && str[i] <= '9') {
            // 检查乘法溢出：value * 10 不能超过 MAXULONG
            if (value > MAXULONG / 10) {
                return STATUS_INTEGER_OVERFLOW;
            }
            value = value * 10 + (str[i] - '0');
            // 检查加法溢出：加上 digit 后不能超过 MAXULONG
            if (value > MAXULONG) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        else {
            // 遇到非数字字符，停止转换
            break;
        }
        i++;
    }

    *result = value;
    return STATUS_SUCCESS;
}

// 字符串转ULONG64
NTSTATUS StringToUlong64(PCHAR str, PULONG64 result)
{
    ULONG64 value = 0;
    ULONG i = 0;

    if (str == NULL || result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    // 跳过开头空格
    while (str[i] == ' ' || str[i] == '\t') {
        i++;
    }

    // 检查是否为空字符串
    if (str[i] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    // 转换数字
    while (str[i] != '\0') {
        if (str[i] >= '0' && str[i] <= '9') {
            // 检查乘法溢出：value * 10 不能超过 MAXULONG64
            if (value > MAXULONG64 / 10) {
                return STATUS_INTEGER_OVERFLOW;
            }
            value = value * 10 + (str[i] - '0');
            // 检查加法溢出：加上 digit 后不能超过 MAXULONG64
            if (value > MAXULONG64) {
                return STATUS_INTEGER_OVERFLOW;
            }
        }
        else {
            break;
        }
        i++;
    }

    *result = value;
    return STATUS_SUCCESS;
}

// 创建驱动对象和符号链接
NTSTATUS CreateDriverObject(IN PDRIVER_OBJECT pDriver)
{
    NTSTATUS Status;
    PDEVICE_OBJECT pDevObj;
    UNICODE_STRING DriverName;
    UNICODE_STRING SymLinkName;

    RtlInitUnicodeString(&DriverName, DEVICE_NAME);
    Status = IoCreateDevice(pDriver, 0, &DriverName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDevObj);

    if (!NT_SUCCESS(Status) || !pDevObj)
    {
        DriverDbgPrint("IoCreateDevice failed: %d\n", Status);
        return Status;
    }

    // DO_BUFFERED_IO 这种读写方式 Flags参数默认值不对，应写为DO_BUFFERED_IO或DO_DIRECT_IO，0
    pDevObj->Flags |= DO_BUFFERED_IO;
    RtlInitUnicodeString(&SymLinkName, SYMLINK_NAME);
    Status = IoCreateSymbolicLink(&SymLinkName, &DriverName);

    if (!NT_SUCCESS(Status))
    {
        DriverDbgPrint("IoCreateSymbolicLink failed: %d\n", Status);
        IoDeleteDevice(pDevObj);
        return Status;
    }

    return STATUS_SUCCESS;
}

/* ── 帮助函数：从 PEPROCESS 查询进程完整镜像路径 ──
 * 内部打开内核句柄 → ZwQueryInformationProcess → 关闭句柄
 * 返回 STATUS_SUCCESS 表示成功，PathBuf 被填充；否则 PathBuf 不变。 */
static NTSTATUS GetProcessImagePathFromProcess(
    PEPROCESS Process,
    CHAR* PathBuf,
    SIZE_T BufSize)
{
    HANDLE hProc = NULL;
    NTSTATUS status;

    status = ObOpenObjectByPointer(
        Process, OBJ_KERNEL_HANDLE, NULL,
        PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProc);
    if (!NT_SUCCESS(status))
        return status;

    ULONG retLen = 0;
    status = ZwQueryInformationProcess(
        hProc, ProcessImageFileName, NULL, 0, &retLen);
    if (NT_SUCCESS(status) || retLen == 0)
    {
        ZwClose(hProc);
        return STATUS_UNSUCCESSFUL;
    }

    PUNICODE_STRING pi = (PUNICODE_STRING)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, retLen, 'HtP');
    if (!pi)
    {
        ZwClose(hProc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQueryInformationProcess(
        hProc, ProcessImageFileName, pi, retLen, &retLen);
    if (NT_SUCCESS(status) && pi->Buffer)
    {
        int wlen = (int)(pi->Length / sizeof(WCHAR));
        int i;
        if (wlen >= (int)BufSize) wlen = (int)BufSize - 1;
        for (i = 0; i < wlen; i++)
            PathBuf[i] = (CHAR)pi->Buffer[i];
        PathBuf[wlen] = '\0';
    }
    ExFreePool(pi);
    ZwClose(hProc);
    return STATUS_SUCCESS;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 进程创建回调 — 构建进程树，使子进程指标可被父进程继承
 * ══════════════════════════════════════════════════════════════════════════ */

VOID NTAPI ProcessCreateNotifyRoutine(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create)
{
    if (Create) {
        /* 声明移到 __try 之外，使 __except 能访问 processRefd/process 做清理 */
        INT64 pid = (INT64)(ULONG_PTR)ProcessId;
        INT64 parentPid = (INT64)(ULONG_PTR)ParentId;
        PEPROCESS process = NULL;
        BOOLEAN processRefd = FALSE;
        BOOLEAN processFound = FALSE;
        HANDLE hProcess = NULL;
        CHAR fullPath[BA_MAX_PATH] = {0};
        CHAR cmdLineBuf[BA_MAX_CMDLINE] = {0};
        CHAR imageNameBuf[BA_MAX_PATH] = {0};

        /* 进程创建回调处于内核敏感路径，新进程对象/PEB 可能未完全初始化。
         * 用 SEH 包裹进程对象操作部分：一旦访问违规，直接返回，避免蓝屏。
         * 后续 BehaviorRecordProcessCreate / ProcessStartCheck 等纯逻辑调用
         * 不在 SEH 内，使这些区域的 bug 能通过蓝屏被及时发现。 */
        __try {
        NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
        if (NT_SUCCESS(status)) {
            int i;
            processRefd = TRUE;
            processFound = TRUE;

            /* 一次打开句柄，依次查询 imagePath 和 cmdLine，避免重复 ObOpenObjectByPointer */
            {
                NTSTATUS obStatus = ObOpenObjectByPointer(
                    process, OBJ_KERNEL_HANDLE, NULL,
                    PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProcess);
                if (NT_SUCCESS(obStatus)) {
                    ULONG returnLength;
                    PUNICODE_STRING imagePathInfo = NULL;
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
                                /* 直接截取低字节，不用 & 0x7F（会丢失非ASCII字符高位导致乱码） */
                                for (i = 0; i < wlen; i++)
                                    fullPath[i] = (CHAR)imagePathInfo->Buffer[i];
                                fullPath[wlen] = '\0';
                            }
                            ExFreePool(imagePathInfo);
                        }
                    }

                    /* 查询进程命令行（ProcessCommandLineInformation = 60，Win8.1+）。
                     * 复用同一内核句柄，避免重复 ObOpenObjectByPointer 调用。 */
                    {
                        ULONG cmdReturnLength = 0;
                        NTSTATUS cmdQueryStatus = ZwQueryInformationProcess(
                            hProcess, (PROCESSINFOCLASS)60, NULL, 0, &cmdReturnLength);
                        if (!NT_SUCCESS(cmdQueryStatus) && cmdReturnLength > 0) {
                            PUNICODE_STRING cmdLineInfo = (PUNICODE_STRING)ExAllocatePool2(
                                POOL_FLAG_NON_PAGED, cmdReturnLength, 'CtP');
                            if (cmdLineInfo) {
                                cmdQueryStatus = ZwQueryInformationProcess(
                                    hProcess, (PROCESSINFOCLASS)60,
                                    cmdLineInfo, cmdReturnLength, &cmdReturnLength);
                                if (NT_SUCCESS(cmdQueryStatus) && cmdLineInfo->Buffer) {
                                    int cwlen = (int)(cmdLineInfo->Length / sizeof(WCHAR));
                                    if (cwlen >= BA_MAX_CMDLINE) cwlen = BA_MAX_CMDLINE - 1;
                                    int ci;
                                    for (ci = 0; ci < cwlen; ci++)
                                        cmdLineBuf[ci] = (CHAR)cmdLineInfo->Buffer[ci];
                                    cmdLineBuf[cwlen] = '\0';
                                }
                                ExFreePool(cmdLineInfo);
                            }
                        }
                    }
                    ZwClose(hProcess);
                    hProcess = NULL;
                }
            }

            /* 从完整路径提取文件名作为进程名 */
            {
                const CHAR* p = fullPath;
                const CHAR* lastSlash = NULL;
                while (*p) {
                    if (*p == '\\' || *p == '/') lastSlash = p;
                    p++;
                }
                p = lastSlash ? lastSlash + 1 : fullPath;
                RtlStringCbCopyA(imageNameBuf, sizeof(imageNameBuf), p);
            }

            /* 后备：ZwQueryInformationProcess 失败时使用短名 */
            if (fullPath[0] == '\0' && imageNameBuf[0] != '\0') {
                RtlStringCbCopyA(fullPath, sizeof(fullPath), imageNameBuf);
            }

            ObDereferenceObject(process);
            processRefd = FALSE;
        }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            /* 确保异常时释放 PEPROCESS 引用，防止资源泄漏 */
            if (processRefd && process != NULL) {
                ObDereferenceObject(process);
            }
            DriverDbgPrint("[PROCESS-CREATE] Exception caught in ProcessCreateNotifyRoutine, skipping\n");
        }

        /* ── 以下为纯逻辑调用，不涉及未初始化进程对象，不在 SEH 内 ──
         * 这样如果 BehaviorRecordProcessCreate 等函数本身有 bug，
         * 会直接蓝屏，便于开发阶段发现和修复。 */
        if (!processFound)
            return;

        /* 即使拿不到完整路径，也要把进程加入行为分析进程树。
         * 否则 ThreadCreateNotifyRoutine 的父子判断失效，
         * 会把正常的新进程初始线程误判为远程线程注入。 */
        BehaviorRecordProcessCreate(pid, parentPid,
            fullPath[0] != '\0' ? fullPath : "Unknown",
            cmdLineBuf[0] != '\0' ? cmdLineBuf : NULL);

        /* ── 注册新进程用于驱动 APC 注入 ──
         * R0+R3 启用时，驱动通过 LoadImageNotifyRoutine 监听系统 DLL 加载，
         * 待 ntdll/kernel32 就绪后以 kernel APC + user APC 注入防御 DLL。
         * 必须在进程创建时加入 g_DriverDllInjectInfoListHead，否则
         * DriverDllInjectLoadImageNotifyRoutine 中 FindInjectionInfo 返回 NULL，
         * 注入永远不会触发。具体注入条件（R3 开关、DLL 路径、受保护进程）由
         * LoadImageNotifyRoutine 内部自行过滤。 */
        if (g_bR3ProtectionEnabled && g_bDllInjectPathSet)
        {
            NTSTATUS injStatus = DriverDllInjectCreateInjectionInfo(NULL, (HANDLE)(ULONG_PTR)pid);
            DriverDbgPrint("[DLL-INJECT] ProcessCreate: PID=%lld status=0x%X enabled=%d pathSet=%d\n",
                (INT64)(ULONG_PTR)pid, injStatus, g_bR3ProtectionEnabled, g_bDllInjectPathSet);
        }

        /* 无签名脚本宿主独立检测通道 */
        BehaviorCheckUnsignedScriptHost(pid, parentPid,
            fullPath[0] != '\0' ? fullPath : "Unknown");

        /* EDR-Freeze 检测：WerFaultSecure.exe 被非 WER 服务启动 */
        {
            CHAR parentNameBuf[16] = {0};
            CHAR parentPathBuf[BA_MAX_PATH] = {0};
            PEPROCESS parentProc = NULL;
            NTSTATUS ps = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)parentPid, &parentProc);
            if (NT_SUCCESS(ps) && parentProc)
            {
                int i;
                UCHAR* pName = PsGetProcessImageFileName(parentProc);
                if (pName)
                {
                    for (i = 0; i < 15 && pName[i]; i++)
                        parentNameBuf[i] = (CHAR)pName[i];
                    parentNameBuf[i] = '\0';
                }
                /* 使用帮助函数获取父进程完整路径（复用内部句柄操作） */
                GetProcessImagePathFromProcess(parentProc, parentPathBuf, sizeof(parentPathBuf));
                ObDereferenceObject(parentProc);
            }
            BehaviorDetectEdrFreeze(
                pid, imageNameBuf, fullPath, cmdLineBuf,
                parentPid, parentNameBuf, parentPathBuf);
        }

        /* R3 未启用时，R0 独立执行进程启动检查：
         * 挂起新进程 -> 通过 Client 转发 main.cpp -> 根据决策恢复/终止 */
        ProcessStartCheck(pid, parentPid, fullPath, imageNameBuf);
    } else {
        /* 进程退出：从进程树中移除，清理关联指标 */
        /* 用 SEH 包裹：BehaviorRecordProcessExit 可能因幽灵进程追踪等异常而崩溃，
         * 必须捕获异常防止升级为 IRQL_LESS_OR_EQUAL 蓝屏。 */
        __try {
            INT64 pid = (INT64)(ULONG_PTR)ProcessId;
            BehaviorRecordProcessExit(pid);
            /* 清理该进程的 ntdll 追踪条目，避免 PID 复用导致误报重载 */
            NtdllTrackCleanupProcess(ProcessId);
            /* 清理已初始化 PID 列表，避免 PID 复用后新进程合法初始线程
             * 被误判为远程线程注入（CreateRemoteThread） */
            RemoveProcessInitialized(ProcessId);
            /* 清理注入去重表，避免 PID 复用后新进程被误判为已注入而跳过注入 */
            DriverDllInjectRemoveInjectionInfoByProcessId(ProcessId, TRUE);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DriverDbgPrint("[PROCESS-CREATE] Exception caught in process exit handling, skipping\n");
        }
    }
}

// BypassCheckSign: 绕过驱动签名检查（测试用）
BOOLEAN BypassCheckSign(PDRIVER_OBJECT pDriverObject) {
#ifdef _WIN64
    typedef struct _KLDR_DATA_TABLE_ENTRY {
        LIST_ENTRY listEntry;
        ULONG64 __Undefined1;
        ULONG64 __Undefined2;
        ULONG64 __Undefined3;
        ULONG64 NonPagedDebugInfo;
        ULONG64 DllBase;
        ULONG64 EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG Flags;
        USHORT LoadCount;
        USHORT __Undefined5;
        ULONG64 __Undefined6;
        ULONG CheckSum;
        ULONG __padding1;
        ULONG TimeDateStamp;
        ULONG __padding2;
    }    KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#else
    typedef struct _KLDR_DATA_TABLE_ENTRY {
        LIST_ENTRY listEntry;
        ULONG unknown1;
        ULONG unknown2;
        ULONG unknown3;
        ULONG unknown4;
        ULONG unknown5;
        ULONG unknown6;
        ULONG unknown7;
        UNICODE_STRING path;
        UNICODE_STRING name;
        ULONG Flags;
    }    KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;
#endif
    PKLDR_DATA_TABLE_ENTRY pLdrData = (PKLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
    pLdrData->Flags = pLdrData->Flags | 0x20;
    return (TRUE);
}

// 驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS loadStatus;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverDbgPrint("TianHongHips driver loading started\n");

    loadStatus = CreateDriverObject(DriverObject);
    if (!NT_SUCCESS(loadStatus))
    {
        DriverDbgPrint("CreateDriverObject failed: 0x%X, driver load aborted\n", loadStatus);
        return loadStatus;
    }

    InitializeProtectedPidsList();
    InitializeInitializedPidsList();

    KeInitializeSpinLock(&g_RulesLock);
    KeInitializeSpinLock(&g_RegCallbackLock);

    InitializeResponseSystem(); // 初始化响应系统

    InitSystemProcessCheck(); // 初始化系统进程SID检测

    // 初始化规则引擎
    KernelRuleEngineInitialize();

    // 初始化动态行为分析引擎
    BehaviorAnalysisInit();

    // 初始化 R0 白名单（AutoAllowList / AutoPreventList 同步）
    WhitelistInitialize();

    // 解析进程操作 API（R0 独立进程创建检查使用）
    ResolveProcessManipulationApis();

    // 初始化 ntdll 追踪上下文
    NtdllTrackInitialize();

    // 初始化 DLL 注入模块（参考 injdrv）
    {
        DRIVER_DLL_INJECT_SETTINGS injectSettings = { 0 };
#if defined(_M_AMD64)
        injectSettings.Method = DriverDllInjectMethodThunkless;
#else
        injectSettings.Method = DriverDllInjectMethodThunk;
#endif
        NTSTATUS injectStatus = DriverDllInjectInitialize(DriverObject, RegistryPath, &injectSettings);
        if (!NT_SUCCESS(injectStatus))
        {
            DriverDbgPrint("[DLL-INJECT] DriverDllInjectInitialize failed: 0x%X\n", injectStatus);
        }
    }

    // 启动异步行为分析定时器线程（卡巴斯基思路：回调同步记录，定时器异步分析）
    BehaviorStartTimerThread();

    // 注册进程创建回调（构建进程树，用于父子进程指标继承）
    {
        NTSTATUS status = PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, FALSE);
        if (NT_SUCCESS(status)) {
            g_ProcessCreateNotifyHandle = (PVOID)1;  /* 标记已注册 */
            DriverDbgPrint("Process create notify routine registered\n");
        } else {
            DriverDbgPrint("PsSetCreateProcessNotifyRoutine failed: 0x%X\n", status);
        }
    }

    // 绕过签名/完整性检查限制，必须在 ObRegisterCallbacks 之前调用
    BypassCheckSign(DriverObject);

    // ── 注册 ObRegisterCallbacks（全局注入防护）──
    // 在驱动启动时注册，确保注入检测始终激活，不依赖保护列表
    {
        OB_OPERATION_REGISTRATION opReg[2] = { 0 };
        OB_CALLBACK_REGISTRATION cbReg = { 0 };
        UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"100000");

        opReg[0].ObjectType = PsProcessType;
        opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg[0].PreOperation = HandleProcessProtectCallBack;
        opReg[0].PostOperation = NULL;

        opReg[1].ObjectType = PsThreadType;
        opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
        opReg[1].PreOperation = HandleThreadProtectCallBack;
        opReg[1].PostOperation = NULL;

        cbReg.Version = OB_FLT_REGISTRATION_VERSION;
        cbReg.OperationRegistrationCount = 2;
        cbReg.RegistrationContext = NULL;
        cbReg.Altitude = altitude;
        cbReg.OperationRegistration = opReg;

        NTSTATUS status = ObRegisterCallbacks(&cbReg, &g_ProcessRegistrationHandle);
        if (NT_SUCCESS(status))
        {
            DriverDbgPrint("ObRegisterCallbacks registered (Process+Thread, global injection protection)\n");
            /* 成功注册无需额外日志，仅在失败时记录 */
        }
        else
        {
            CHAR errBuf[128];
            DriverDbgPrint("ObRegisterCallbacks registration failed: 0x%X\n", status);
            RtlStringCbPrintfA(errBuf, sizeof(errBuf),
                "[OB-CALLBACKS] ObRegisterCallbacks registration FAILED: 0x%X", status);
            SendInjectionLog(errBuf);
            g_ProcessRegistrationHandle = NULL;
        }
    }

    // ── 注册 PsSetCreateThreadNotifyRoutine（远程线程注入检测）──
    // 这是检测 CreateRemoteThread / NtCreateThreadEx 跨进程注入最核心的手段
    {
        NTSTATUS status = PsSetCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);
        if (NT_SUCCESS(status))
        {
            g_ThreadCreateNotifyHandle = (PVOID)1;
            DriverDbgPrint("Thread create notify routine registered (remote thread injection detection)\n");
            /* 成功注册无需额外日志，仅在失败时记录 */
        }
        else
        {
            CHAR errBuf[128];
            DriverDbgPrint("PsSetCreateThreadNotifyRoutine failed: 0x%X\n", status);
            RtlStringCbPrintfA(errBuf, sizeof(errBuf),
                "[THREAD-CALLBACK] PsSetCreateThreadNotifyRoutine FAILED: 0x%X", status);
            SendInjectionLog(errBuf);
        }
    }

    // ── 注册 PsSetLoadImageNotifyRoutine（DLL注入：kernel32.dll 加载时 kernel APC 注入）──
    // 当 R0+R3 同时启用时，不再依赖 R3 递归注入，
    // 而是由驱动在进程首次加载 kernel32.dll 时通过 kernel APC 注入 R3 防御 DLL
    {
        NTSTATUS imgStatus = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        if (NT_SUCCESS(imgStatus))
        {
            g_LoadImageNotifyHandle = (PVOID)1;
        }
        else
        {
            DriverDbgPrint("[DLL-INJECT] PsSetLoadImageNotifyRoutine FAILED: 0x%X\n", imgStatus);
        }
    }

    // 初始化 ntdll 重载检测
    NtdllTrackInitialize();

    // 设置分发函数
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    // 驱动卸载回调
    DriverObject->DriverUnload = DriverUnload;

    // 保存驱动设备对象引用，供内核态 IOCTL 使用
    g_pDriverDeviceObject = DriverObject->DeviceObject;

    // 初始化文件过滤（Minifilter）
    FileFilterSetControlDevice(DriverObject->DeviceObject);
    {
        NTSTATUS status = FileFilterInitialize(DriverObject);
        if (!NT_SUCCESS(status)) {
            DriverDbgPrint("FileFilterInitialize failed: 0x%X\n", status);
        }
        else {
            DriverDbgPrint("File filter initialized successfully\n");
        }
    }

    DriverDbgPrint("TianHongHips driver loading completed\n");
    return STATUS_SUCCESS;
}

// 驱动卸载
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    DriverDbgPrint("Starting driver unload...\n");

    /* 先取消所有待处理请求，唤醒等待线程 */
    ResponseSystemCancelAll();

    /* 清理 DLL 注入模块，防止访问已释放的驱动代码导致蓝屏 */
    DriverDllInjectDestroy();

    DriverDbgPrint("Unregistering callbacks...\n");

    // 注销进程回调
    if (g_ProcessRegistrationHandle != NULL)
    {
        ObUnRegisterCallbacks(g_ProcessRegistrationHandle);
        g_ProcessRegistrationHandle = NULL;
        DriverDbgPrint("Process callback unregistered\n");
    }

    // 注销进程创建回调
    if (g_ProcessCreateNotifyHandle != NULL)
    {
        PsSetCreateProcessNotifyRoutine(ProcessCreateNotifyRoutine, TRUE);
        g_ProcessCreateNotifyHandle = NULL;
        DriverDbgPrint("Process create notify routine unregistered\n");
    }

    // 注销线程创建回调（远程线程注入检测）
    if (g_ThreadCreateNotifyHandle != NULL)
    {
        PsRemoveCreateThreadNotifyRoutine(ThreadCreateNotifyRoutine);
        g_ThreadCreateNotifyHandle = NULL;
        DriverDbgPrint("Thread create notify routine unregistered\n");
    }

    // 注销镜像加载回调（kernel APC DLL 注入）
    if (g_LoadImageNotifyHandle != NULL)
    {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        g_LoadImageNotifyHandle = NULL;
        DriverDbgPrint("Load image notify routine unregistered\n");
    }

    // 清理 ntdll 重载检测
    NtdllTrackCleanup();

    // 注销注册表回调
    if (g_RegCookie.QuadPart != 0)
    {
        CmUnRegisterCallback(g_RegCookie);
        g_RegCookie.QuadPart = 0;
        DriverDbgPrint("Registry callback unregistered\n");
    }

    // 清理动态行为分析引擎（必须在 FileFilter 卸载前停止定时器线程，
    // 否则定时器线程可能在 minifilter 已卸载后访问其资源，导致 BSOD）
    BehaviorStopTimerThread();
    BehaviorAnalysisCleanup();

    // 清理动态规则池和指标定义池
    BaDynamicRulesCleanup();
    BaIndicatorDefsCleanup();

    // 清理文件过滤（Minifilter）
    FileFilterUnloadWrapper();
    DriverDbgPrint("File filter cleaned up\n");

    CleanupProtectedPidsList();
    CleanupInitializedPidsList();

    // 清理 R0 白名单
    WhitelistCleanup();

    // 清理响应系统（卸载 CI.DLL）
    CleanupResponseSystem();

    PDEVICE_OBJECT pDev;
    UNICODE_STRING SymLinkName;

    pDev = DriverObject->DeviceObject;

    /* 必须先删除符号链接，再删除设备对象。符号链接持有对设备对象的引用，
     * 若先 IoDeleteDevice，引用计数无法降到 0，会导致驱动对象无法被释放，
     * 最终服务状态停留在 RUNNING。 */
    RtlInitUnicodeString(&SymLinkName, SYMLINK_NAME);
    IoDeleteSymbolicLink(&SymLinkName);

    if (pDev != NULL)
    {
        IoDeleteDevice(pDev);
    }

    g_pDriverDeviceObject = NULL;

    DriverDbgPrint("Device object and symbolic link deleted successfully\n");

    DriverDbgPrint("Driver unload completed\n");
}
