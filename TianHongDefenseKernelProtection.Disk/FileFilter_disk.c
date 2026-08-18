/*++
Copyright (c) 2024  TianHong Security Defense

Module Name:
    FileFilter_disk.c

Abstract:
    Standalone WDM disk filter driver — attaches to physical disk devices
    (\Device\HarddiskX\DRX) to intercept writes to the boot region
    (sectors 0-62, covering MBR + gap before first partition).

    When a write to the boot region is detected:
    1. The write IRP is blocked (STATUS_ACCESS_DENIED)
    2. An alert is queued for the client to poll via IOCTL_DISK_FILTER_POLL_ALERT
    3. The client forwards the alert to the GUI for user decision

    All other disk I/O passes through to the lower device unmodified.

Environment:
    Kernel mode
--*/

#include "../shared/Common.h"
#include "Main_disk.h"
#include "FileFilter_disk.h"

/* 内核函数声明（ntddk.h 不导出这些符号，需手动声明） */
#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationProcess(
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount_opt(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
);

// --------------------------------------------------------------------------
// 过滤设备扩展
// --------------------------------------------------------------------------
typedef struct _FILTER_DEVICE_EXTENSION {
    PDEVICE_OBJECT  LowerDevice;     /* IoAttachDeviceToDeviceStack 返回值 */
    PDEVICE_OBJECT  FilterDevice;
    LIST_ENTRY      ListEntry;
    BOOLEAN         IsFilterDevice;
    BOOLEAN         IsDiskDevice;    /* TRUE=物理磁盘设备(拦截MBR写), FALSE=卷设备(纯透传) */
    ULONG           DiskNumber;      /* 物理磁盘编号（用于告警） */
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;

// --------------------------------------------------------------------------
// 告警队列
// --------------------------------------------------------------------------
typedef struct _DISK_ALERT_ENTRY {
    LIST_ENTRY      ListEntry;
    DISK_FILTER_ALERT Alert;
} DISK_ALERT_ENTRY, *PDISK_ALERT_ENTRY;

// --------------------------------------------------------------------------
// 全局数据
// --------------------------------------------------------------------------
static LIST_ENTRY g_FilterDeviceListHead;
static KSPIN_LOCK g_FilterListLock;
static KSPIN_LOCK g_RuleLock;

static LIST_ENTRY g_AlertListHead;       /* 告警队列 */
static KSPIN_LOCK g_AlertListLock;
static KEVENT     g_AlertAvailableEvent; /* 有新告警时触发 */

static PDEVICE_OBJECT g_ControlDevice = NULL;
static PDRIVER_OBJECT g_DriverObject = NULL;
static volatile BOOLEAN g_bProtectionEnabled = FALSE; /* MBR保护开关，默认禁用 */

/* attach / 拦截统计（供 IOCTL_DISK_FILTER_GET_STATUS 返回） */
static volatile LONG g_lAttachedDiskCount = 0;     /* 已 attach 的物理磁盘设备数 */
static volatile LONG g_lAttachedVolumeCount = 0;   /* 已 attach 的卷设备数 */
static volatile LONG g_lTotalBlockedWrites = 0;    /* 累计拦截的引导区写入次数 */

// --------------------------------------------------------------------------
// 函数原型
// --------------------------------------------------------------------------
NTSTATUS DiskFilterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);
VOID DiskFilterUnload(PDRIVER_OBJECT DriverObject);
VOID DiskFilterReinit(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count);
static BOOLEAN DiskFilterAttachToDevice(PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING deviceName, BOOLEAN isDiskDevice, ULONG diskNumber);
static VOID DiskFilterAttachVolumes(PDRIVER_OBJECT DriverObject);

// --------------------------------------------------------------------------
// 自定义 dbgprint — 同时输出到 DbgPrint 和日志队列（供 main UI 显示）
// --------------------------------------------------------------------------
/* 日志队列：与告警队列并行，存放普通日志文本供客户端轮询转发到 main UI */
typedef struct _DISK_LOG_ENTRY {
    LIST_ENTRY      ListEntry;
    DISK_FILTER_LOG Log;
} DISK_LOG_ENTRY, *PDISK_LOG_ENTRY;

static LIST_ENTRY   g_LogListHead;
static KSPIN_LOCK   g_LogListLock;
static volatile LONG g_lLogCount = 0;     /* 当前队列日志数（限制上限，防止刷屏） */
#define DISK_LOG_QUEUE_MAX  256           /* 日志队列上限：超出丢弃最旧条目 */

/* DiskDbgPrintV — 内部实现：格式化 -> DbgPrint + 入队
 * 注意：内核 RtlStringCbVPrintfA 不支持 %f 浮点格式，调用方需用整数显示。
 * 本函数可在任意 IRQL 调用（用 NonPaged pool + SpinLock）。 */
static VOID DiskDbgPrintV(PCSTR fmt, va_list args)
{
    CHAR buffer[DISK_FILTER_LOG_MSG_MAX];
    NTSTATUS status;

    /* 格式化日志文本（含 [TianHongHips.Disk] 前缀） */
    status = RtlStringCbVPrintfA(buffer, sizeof(buffer), fmt, args);
    if (!NT_SUCCESS(status)) {
        return;
    }

#if !defined(TH_RELEASE_BUILD)
    /* Debug 构建：同时输出到内核调试器（DbgView/WinDbg 可见） */
    DbgPrint("%s%s", DISK_DRIVER_PREFIX, buffer);
#endif

    /* 入队日志，供客户端 IOCTL_DISK_FILTER_POLL_LOG 轮询转发到 main UI */
    {
        PDISK_LOG_ENTRY entry;
        KIRQL oldIrql;
        BOOLEAN dropped = FALSE;

        entry = (PDISK_LOG_ENTRY)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(DISK_LOG_ENTRY), 'DLTH');
        if (entry == NULL) {
            return;   /* 内存不足，丢弃日志 */
        }

        RtlZeroMemory(&entry->Log, sizeof(DISK_FILTER_LOG));
        entry->Log.timestampMs = (INT64)KeQueryInterruptTime() / 10000;
        /* 前缀 + 正文，确保 UI 显示时能区分来源 */
        RtlStringCbPrintfA(entry->Log.Message, sizeof(entry->Log.Message),
            "%s%s", DISK_DRIVER_PREFIX, buffer);

        KeAcquireSpinLock(&g_LogListLock, &oldIrql);
        /* 队列满时丢弃最旧条目，腾出空间给新日志 */
        if (g_lLogCount >= DISK_LOG_QUEUE_MAX) {
            PLIST_ENTRY oldest = RemoveHeadList(&g_LogListHead);
            PDISK_LOG_ENTRY oldEntry = CONTAINING_RECORD(oldest, DISK_LOG_ENTRY, ListEntry);
            ExFreePool(oldEntry);
            g_lLogCount--;
            dropped = TRUE;
        }
        InsertTailList(&g_LogListHead, &entry->ListEntry);
        g_lLogCount++;
        KeReleaseSpinLock(&g_LogListLock, oldIrql);
    }
}

/* DiskDbgPrint — 对外接口（可变参数），所有原宏调用点无需修改。
 * 非 static：供 Main_disk.c 中的 DriverEntry 等调用，使日志统一入队转发到 UI。 */
VOID DiskDbgPrint(PCSTR fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    DiskDbgPrintV(fmt, args);
    va_end(args);
}

// ============================================================================
// DiskFilterLogInit — 初始化日志队列（供 DriverEntry 早期调用）
// ============================================================================
VOID DiskFilterLogInit(VOID)
{
    InitializeListHead(&g_LogListHead);
    KeInitializeSpinLock(&g_LogListLock);
    g_lLogCount = 0;
}

// ============================================================================
// FileFilterSetControlDevice
// ============================================================================
VOID FileFilterSetControlDevice(PDEVICE_OBJECT DeviceObject)
{
    g_ControlDevice = DeviceObject;
}

// ============================================================================
// FileFilterIsEnabled — 获取 MBR 保护启用状态
// ============================================================================
BOOLEAN DiskFilterIsEnabled(VOID)
{
    return g_bProtectionEnabled;
}

// ============================================================================
// DiskFilterQueueAlert — 将 MBR 写入告警加入队列
// ============================================================================
static VOID DiskFilterQueueAlert(
    INT64 pid,
    PCSTR processName,
    PCSTR processPath,
    ULONG diskNumber,
    LARGE_INTEGER byteOffset,
    ULONG writeLength,
    PCSTR deviceName)
{
    PDISK_ALERT_ENTRY entry;
    KIRQL oldIrql;

    entry = (PDISK_ALERT_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(DISK_ALERT_ENTRY), 'DATH');
    if (entry == NULL) {
        DiskDbgPrint("Failed to allocate alert entry\n");
        return;
    }

    RtlZeroMemory(&entry->Alert, sizeof(DISK_FILTER_ALERT));
    entry->Alert.timestampMs = (INT64)KeQueryInterruptTime() / 10000;
    entry->Alert.pid = pid;
    entry->Alert.diskNumber = diskNumber;
    entry->Alert.byteOffset = byteOffset;
    entry->Alert.writeLength = writeLength;

    if (processName) {
        RtlStringCbCopyA(entry->Alert.processName, sizeof(entry->Alert.processName), processName);
    }
    if (processPath) {
        RtlStringCbCopyA(entry->Alert.processPath, sizeof(entry->Alert.processPath), processPath);
    }
    if (deviceName) {
        RtlStringCbCopyA(entry->Alert.deviceName, sizeof(entry->Alert.deviceName), deviceName);
    }

    KeAcquireSpinLock(&g_AlertListLock, &oldIrql);
    InsertTailList(&g_AlertListHead, &entry->ListEntry);
    KeReleaseSpinLock(&g_AlertListLock, oldIrql);

    KeSetEvent(&g_AlertAvailableEvent, IO_NO_INCREMENT, FALSE);

    DiskDbgPrint("MBR write alert queued: PID=%lld Disk=%lu Offset=%lld Len=%lu\n",
        pid, diskNumber, byteOffset.QuadPart, writeLength);
}

// ============================================================================
// DiskFilterDequeueAlert — 从队列取出一条告警（供 IOCTL_POLL_ALERT 使用）
// ============================================================================
static BOOLEAN DiskFilterDequeueAlert(PDISK_FILTER_ALERT pAlert)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_AlertListLock, &oldIrql);
    if (!IsListEmpty(&g_AlertListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_AlertListHead);
        PDISK_ALERT_ENTRY alertEntry = CONTAINING_RECORD(entry, DISK_ALERT_ENTRY, ListEntry);
        RtlCopyMemory(pAlert, &alertEntry->Alert, sizeof(DISK_FILTER_ALERT));
        ExFreePool(alertEntry);
        found = TRUE;
    }
    KeReleaseSpinLock(&g_AlertListLock, oldIrql);

    return found;
}

// ============================================================================
// DiskFilterClearAlerts — 清空告警队列（unload 时调用）
// ============================================================================
static VOID DiskFilterClearAlerts(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_AlertListLock, &oldIrql);
    while (!IsListEmpty(&g_AlertListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_AlertListHead);
        PDISK_ALERT_ENTRY alertEntry = CONTAINING_RECORD(entry, DISK_ALERT_ENTRY, ListEntry);
        ExFreePool(alertEntry);
    }
    KeReleaseSpinLock(&g_AlertListLock, oldIrql);
}

// ============================================================================
// DiskFilterDequeueLog — 从日志队列取出一条日志（供 IOCTL_POLL_LOG 使用）
// ============================================================================
static BOOLEAN DiskFilterDequeueLog(PDISK_FILTER_LOG pLog)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_LogListLock, &oldIrql);
    if (!IsListEmpty(&g_LogListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_LogListHead);
        PDISK_LOG_ENTRY logEntry = CONTAINING_RECORD(entry, DISK_LOG_ENTRY, ListEntry);
        RtlCopyMemory(pLog, &logEntry->Log, sizeof(DISK_FILTER_LOG));
        ExFreePool(logEntry);
        g_lLogCount--;
        found = TRUE;
    }
    KeReleaseSpinLock(&g_LogListLock, oldIrql);

    return found;
}

// ============================================================================
// DiskFilterClearLogs — 清空日志队列（unload 时调用）
// ============================================================================
static VOID DiskFilterClearLogs(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_LogListLock, &oldIrql);
    while (!IsListEmpty(&g_LogListHead)) {
        PLIST_ENTRY entry = RemoveHeadList(&g_LogListHead);
        PDISK_LOG_ENTRY logEntry = CONTAINING_RECORD(entry, DISK_LOG_ENTRY, ListEntry);
        ExFreePool(logEntry);
    }
    g_lLogCount = 0;
    KeReleaseSpinLock(&g_LogListLock, oldIrql);
}

// ============================================================================
// DiskFilterGetProcessInfo — 获取发起写操作的进程信息
// ============================================================================
static VOID DiskFilterGetProcessInfo(
    INT64* pPid,
    CHAR* processName,
    ULONG nameLen,
    CHAR* processPath,
    ULONG pathLen)
{
    PEPROCESS process = NULL;
    HANDLE pidHandle = PsGetCurrentProcessId();

    *pPid = (INT64)(ULONG_PTR)pidHandle;

    if (NT_SUCCESS(PsLookupProcessByProcessId(pidHandle, &process)) && process) {
        PUCHAR imageName = PsGetProcessImageFileName(process);
        if (imageName && processName && nameLen > 0) {
            ULONG i;
            for (i = 0; i < 15 && imageName[i]; i++) {
                processName[i] = (CHAR)imageName[i];
            }
            processName[i] = '\0';
        }

        /* 获取进程路径：通过 ZwQueryInformationProcess */
        if (processPath && pathLen > 0) {
            HANDLE hProcess = NULL;
            NTSTATUS status = ObOpenObjectByPointer(
                process, OBJ_KERNEL_HANDLE, NULL,
                PROCESS_QUERY_LIMITED_INFORMATION, *PsProcessType, KernelMode, &hProcess);
            if (NT_SUCCESS(status) && hProcess) {
                ULONG returnLength = 0;
                ZwQueryInformationProcess(hProcess, ProcessImageFileName,
                    NULL, 0, &returnLength);
                if (returnLength > 0) {
                    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLength, 'PIPD');
                    if (buffer) {
                        status = ZwQueryInformationProcess(hProcess, ProcessImageFileName,
                            buffer, returnLength, &returnLength);
                        if (NT_SUCCESS(status)) {
                            PUNICODE_STRING uniName = (PUNICODE_STRING)buffer;
                            if (uniName->Buffer) {
                                int cwlen = (int)(uniName->Length / sizeof(WCHAR));
                                if (cwlen >= (int)pathLen) cwlen = pathLen - 1;
                                /* 截取低字节（与其他代码一致） */
                                int ci;
                                for (ci = 0; ci < cwlen; ci++) {
                                    processPath[ci] = (CHAR)uniName->Buffer[ci];
                                }
                                processPath[cwlen] = '\0';
                            }
                        }
                        ExFreePool(buffer);
                    }
                }
                ZwClose(hProcess);
            }
        }
        ObDereferenceObject(process);
    } else {
        if (processName && nameLen > 0) processName[0] = '\0';
        if (processPath && pathLen > 0) processPath[0] = '\0';
    }
}

// ============================================================================
// DiskFilterIsWriteToBootRegion — 检查写入是否落在引导区（扇区 0-62）
// ============================================================================
static BOOLEAN DiskFilterIsWriteToBootRegion(PIRP Irp)
{
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    LARGE_INTEGER byteOffset = irpStack->Parameters.Write.ByteOffset;
    LONGLONG bootEnd = (LONGLONG)MBR_PROTECTION_SECTOR_COUNT * 512;

    /* 引导区保护范围：[0, bootEnd)（扇区 0-62，约 31KB）
     * 覆盖 MBR（扇区0）+ 扇区1-62 的间隙区域
     * （第一分区通常从扇区 63 或 2048 开始）
     *
     * 写入与引导区有交集 ⟺ offset < bootEnd（offset 恒 >= 0）
     * 原先的第二个条件 offset < bootEnd + length 会误拦扇区 63 之后的写入，已移除 */
    if (byteOffset.QuadPart < bootEnd) {
        return TRUE;
    }

    return FALSE;
}

// ============================================================================
// DiskFilterDispatch — 主分发函数
// ============================================================================
NTSTATUS DiskFilterDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PFILTER_DEVICE_EXTENSION extension;
    PIO_STACK_LOCATION irpStack;
    ULONG majorFunction;

    /* 控制设备：转发给 IOCTL 处理 */
    if (DeviceObject == g_ControlDevice) {
        irpStack = IoGetCurrentIrpStackLocation(Irp);
        majorFunction = irpStack->MajorFunction;

        if (majorFunction == IRP_MJ_DEVICE_CONTROL) {
            return DiskFilterDispatchIoctl(DeviceObject, Irp);
        }

        /* 其他 IRP 直接完成（控制设备不处理普通 I/O） */
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    extension = (PFILTER_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    if (extension == NULL || !extension->IsFilterDevice) {
        /* 不是过滤设备，直接完成 */
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    irpStack = IoGetCurrentIrpStackLocation(Irp);
    majorFunction = irpStack->MajorFunction;

    /* ── 物理磁盘设备：拦截引导区写入 ── */
    if (extension->IsDiskDevice && majorFunction == IRP_MJ_WRITE) {
        if (g_bProtectionEnabled && DiskFilterIsWriteToBootRegion(Irp)) {
            /* 获取进程信息 */
            INT64 pid = 0;
            CHAR processName[64] = {0};
            CHAR processPath[512] = {0};
            CHAR deviceNameBuf[128] = {0};
            LARGE_INTEGER byteOffset = irpStack->Parameters.Write.ByteOffset;
            ULONG writeLength = irpStack->Parameters.Write.Length;

            DiskFilterGetProcessInfo(&pid, processName, sizeof(processName),
                processPath, sizeof(processPath));

            /* 构建设备名 */
            RtlStringCbPrintfA(deviceNameBuf, sizeof(deviceNameBuf),
                "\\Device\\Harddisk%lu\\DR%lu", extension->DiskNumber, extension->DiskNumber);

            /* 排队告警 */
            DiskFilterQueueAlert(pid, processName, processPath,
                extension->DiskNumber, byteOffset, writeLength, deviceNameBuf);

            DiskDbgPrint("BLOCKED boot region write: PID=%lld Disk=%lu Offset=%lld Len=%lu\n",
                pid, extension->DiskNumber, byteOffset.QuadPart, writeLength);

            /* 累计拦截计数（供 IOCTL_DISK_FILTER_GET_STATUS 查询） */
            InterlockedIncrement(&g_lTotalBlockedWrites);

            /* 阻止写入 */
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_ACCESS_DENIED;
        }
    }

    /* 所有其他 IRP：转发给下层设备 */
    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(extension->LowerDevice, Irp);
}

// ============================================================================
// DiskFilterAttachToDevice — 附加过滤设备到指定目标设备栈
// ============================================================================
static BOOLEAN DiskFilterAttachToDevice(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING deviceName,
    BOOLEAN isDiskDevice,
    ULONG diskNumber)
{
    PFILE_OBJECT fileObject = NULL;
    PDEVICE_OBJECT targetDevice = NULL;
    PDEVICE_OBJECT filterDevice = NULL;
    PDEVICE_OBJECT lowerDevice = NULL;
    PFILTER_DEVICE_EXTENSION extension;
    NTSTATUS status;

    status = IoGetDeviceObjectPointer(
        deviceName, FILE_READ_ATTRIBUTES, &fileObject, &targetDevice);
    if (!NT_SUCCESS(status)) {
        /* 设备不存在（NAME_NOT_FOUND / PATH_NOT_FOUND）属于正常枚举扫描，
         * 系统并非每个 HarddiskX / HarddiskVolumeX 都存在，静默跳过即可。 */
        if (status != STATUS_OBJECT_NAME_NOT_FOUND &&
            status != STATUS_OBJECT_PATH_NOT_FOUND) {
            /* 非预期失败：仅保留 DbgPrint 调试日志，不发送到用户态 */
        }
        return FALSE;
    }

    /* 过滤设备类型：只附加磁盘类设备 */
    if (targetDevice->DeviceType != FILE_DEVICE_DISK &&
        targetDevice->DeviceType != FILE_DEVICE_DISK_FILE_SYSTEM &&
        targetDevice->DeviceType != FILE_DEVICE_VIRTUAL_DISK) {
        ObDereferenceObject(fileObject);
        return FALSE;
    }

    status = IoCreateDevice(
        DriverObject,
        sizeof(FILTER_DEVICE_EXTENSION),
        NULL,
        targetDevice->DeviceType,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &filterDevice);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(fileObject);
        return FALSE;
    }

    lowerDevice = IoAttachDeviceToDeviceStack(filterDevice, targetDevice);
    if (lowerDevice == NULL) {
        IoDeleteDevice(filterDevice);
        ObDereferenceObject(fileObject);
        return FALSE;
    }

    extension = (PFILTER_DEVICE_EXTENSION)filterDevice->DeviceExtension;
    RtlZeroMemory(extension, sizeof(FILTER_DEVICE_EXTENSION));
    extension->LowerDevice = lowerDevice;
    extension->FilterDevice = filterDevice;
    extension->IsFilterDevice = TRUE;
    extension->IsDiskDevice = isDiskDevice;
    extension->DiskNumber = diskNumber;

    /* 继承下层设备的标志 */
    filterDevice->Flags |= lowerDevice->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE);

    /* 加入设备列表 */
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_FilterListLock, &oldIrql);
        InsertTailList(&g_FilterDeviceListHead, &extension->ListEntry);
        KeReleaseSpinLock(&g_FilterListLock, oldIrql);
    }

    ObDereferenceObject(fileObject);

    /* 累加 attach 计数（供 IOCTL_DISK_FILTER_GET_STATUS 验证防护是否生效） */
    if (isDiskDevice) {
        InterlockedIncrement(&g_lAttachedDiskCount);
    } else {
        InterlockedIncrement(&g_lAttachedVolumeCount);
    }

    return TRUE;
}

// ============================================================================
// DiskFilterAttachVolumes — 附加到所有磁盘/卷设备
// ============================================================================
static VOID DiskFilterAttachVolumes(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING deviceName;
    WCHAR nameBuf[64];
    ULONG i;

    /* 附加到物理磁盘设备: \Device\HarddiskX\DRX */
    for (i = 0; i < 16; i++) {
        RtlStringCbPrintfW(nameBuf, sizeof(nameBuf), L"\\Device\\Harddisk%lu\\DR%lu", i, i);
        RtlInitUnicodeString(&deviceName, nameBuf);
        DiskFilterAttachToDevice(DriverObject, &deviceName, TRUE, i);
    }

    /* 附加到卷设备: \Device\HarddiskVolumeX (纯透传，不拦截) */
    for (i = 1; i <= 32; i++) {
        RtlStringCbPrintfW(nameBuf, sizeof(nameBuf), L"\\Device\\HarddiskVolume%lu", i);
        RtlInitUnicodeString(&deviceName, nameBuf);
        DiskFilterAttachToDevice(DriverObject, &deviceName, FALSE, 0);
    }
}

// ============================================================================
// DiskFilterReinit — 延迟初始化（DriverEntry 返回后附加设备）
// ============================================================================
VOID DiskFilterReinit(PDRIVER_OBJECT DriverObject, PVOID Context, ULONG Count)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(Count);

    DiskFilterAttachVolumes(DriverObject);
}

// ============================================================================
// FileFilterInitialize — 初始化磁盘过滤
// ============================================================================
NTSTATUS FileFilterInitialize(PDRIVER_OBJECT DriverObject)
{
    g_DriverObject = DriverObject;

    InitializeListHead(&g_FilterDeviceListHead);
    KeInitializeSpinLock(&g_FilterListLock);
    KeInitializeSpinLock(&g_RuleLock);

    InitializeListHead(&g_AlertListHead);
    KeInitializeSpinLock(&g_AlertListLock);
    KeInitializeEvent(&g_AlertAvailableEvent, NotificationEvent, FALSE);

    /* 日志队列已在 DriverEntry 中通过 DiskFilterLogInit() 初始化 */

    /* 设置分发函数 */
    {
        ULONG i;
        for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
            DriverObject->MajorFunction[i] = DiskFilterDispatch;
        }
        DriverObject->DriverUnload = DiskFilterUnload;
    }

    /* 注册延迟初始化：在 DriverEntry 返回后附加设备栈
     * 避免在 DriverEntry 中附加设备导致的死锁 */
    IoRegisterDriverReinitialization(DriverObject, DiskFilterReinit, NULL);

    return STATUS_SUCCESS;
}

// ============================================================================
// FileFilterUnloadWrapper — 卸载磁盘过滤
// ============================================================================
VOID FileFilterUnloadWrapper(VOID)
{
    KIRQL oldIrql;
    PLIST_ENTRY entry;

    /* 从所有设备栈分离并删除过滤设备 */
    KeAcquireSpinLock(&g_FilterListLock, &oldIrql);
    while (!IsListEmpty(&g_FilterDeviceListHead)) {
        entry = RemoveHeadList(&g_FilterDeviceListHead);
        PFILTER_DEVICE_EXTENSION ext = CONTAINING_RECORD(entry, FILTER_DEVICE_EXTENSION, ListEntry);
        if (ext->LowerDevice) {
            IoDetachDevice(ext->LowerDevice);
        }
        if (ext->FilterDevice) {
            IoDeleteDevice(ext->FilterDevice);
        }
    }
    KeReleaseSpinLock(&g_FilterListLock, oldIrql);

    /* 清空告警队列 */
    DiskFilterClearAlerts();

    /* 清空日志队列 */
    DiskFilterClearLogs();

    DiskDbgPrint("Disk filter unloaded\n");
}

// ============================================================================
// DiskFilterUnload — 驱动卸载
// ============================================================================
VOID DiskFilterUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    /* 先分离所有过滤设备并清空队列 */
    FileFilterUnloadWrapper();

    /* 删除控制设备与符号链接。若漏删，\Device\TianHongDiskFilter 与
     * \??\TianHongDiskFilter 会残留，导致驱动卸载后无法再次加载：
     * IoCreateDevice / IoCreateSymbolicLink 返回 STATUS_OBJECT_NAME_COLLISION，
     * 服务启动失败（StartService 返回 ERROR_DRIVER_BLOCKED 0x1B1）。 */
    {
        UNICODE_STRING symLink;
        RtlInitUnicodeString(&symLink, DISK_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symLink);

        if (g_DiskFilterDeviceObject != NULL) {
            IoDeleteDevice(g_DiskFilterDeviceObject);
            g_DiskFilterDeviceObject = NULL;
        }
    }
}

// ============================================================================
// DiskFilterDispatchIoctl — IOCTL 处理
// ============================================================================
NTSTATUS DiskFilterDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG outputLen = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG inputLen = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID inBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_DISK_FILTER_SET_ENABLED:
    {
        /* 启用/禁用 MBR 保护 */
        if (inputLen < sizeof(BOOLEAN)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        g_bProtectionEnabled = *(BOOLEAN*)inBuffer;
        bytesReturned = 0;
        DiskDbgPrint("MBR protection %s\n", g_bProtectionEnabled ? "ENABLED" : "DISABLED");
        break;
    }

    case IOCTL_DISK_FILTER_POLL_ALERT:
    {
        /* 轮询告警：返回 DISK_FILTER_ALERT 或空（无告警） */
        if (outputLen < sizeof(DISK_FILTER_ALERT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (DiskFilterDequeueAlert((PDISK_FILTER_ALERT)outBuffer)) {
            bytesReturned = sizeof(DISK_FILTER_ALERT);
        } else {
            bytesReturned = 0;
        }
        break;
    }

    case IOCTL_DISK_FILTER_SEND_RESPONSE:
    {
        /* 用户决策（目前为静默处理，因为写入已被阻止）
         * 未来可扩展为：先挂起写入IRP等待用户决策 */
        if (inputLen < sizeof(DISK_FILTER_RESPONSE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PDISK_FILTER_RESPONSE pResp = (PDISK_FILTER_RESPONSE)inBuffer;
        DiskDbgPrint("User response: PID=%lld Decision=%d\n",
            pResp->pid, pResp->decision);
        bytesReturned = 0;
        break;
    }

    case IOCTL_DISK_FILTER_GET_STATUS:
    {
        /* 查询防护状态：供客户端验证 attach 是否成功、防护是否生效 */
        if (outputLen < sizeof(DISK_FILTER_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PDISK_FILTER_STATUS pStatus = (PDISK_FILTER_STATUS)outBuffer;
        RtlZeroMemory(pStatus, sizeof(DISK_FILTER_STATUS));
        pStatus->protectionEnabled = g_bProtectionEnabled;
        pStatus->attachedDiskCount = (ULONG)g_lAttachedDiskCount;
        pStatus->attachedVolumeCount = (ULONG)g_lAttachedVolumeCount;
        pStatus->totalBlockedWrites = (ULONG)g_lTotalBlockedWrites;

        /* 统计待处理告警数（持锁遍历队列） */
        {
            KIRQL oldIrql;
            ULONG cnt = 0;
            PLIST_ENTRY e;
            KeAcquireSpinLock(&g_AlertListLock, &oldIrql);
            for (e = g_AlertListHead.Flink; e != &g_AlertListHead; e = e->Flink) {
                cnt++;
            }
            KeReleaseSpinLock(&g_AlertListLock, oldIrql);
            pStatus->pendingAlerts = cnt;
        }
        bytesReturned = sizeof(DISK_FILTER_STATUS);
        break;
    }

    case IOCTL_DISK_FILTER_POLL_LOG:
    {
        /* 轮询日志：返回一条 DISK_FILTER_LOG 或空（无日志）
         * 客户端 HandleDiskAlerts 线程每次轮询告警时顺便拉取所有待处理日志，
         * 通过 CLIENT_MSG_LOG 转发到 main UI 显示 */
        if (outputLen < sizeof(DISK_FILTER_LOG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        if (DiskFilterDequeueLog((PDISK_FILTER_LOG)outBuffer)) {
            bytesReturned = sizeof(DISK_FILTER_LOG);
        } else {
            bytesReturned = 0;
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
