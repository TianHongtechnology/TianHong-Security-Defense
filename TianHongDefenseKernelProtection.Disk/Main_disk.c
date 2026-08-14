/*++
Copyright (c) 2024  TianHong Security Defense

Module Name:
    Main_disk.c

Abstract:
    Standalone WDM disk filter driver entry point for TianHongHips.Disk service.

    Creates control device (\Device\TianHongDiskFilter) and symbolic link
    (\??\TianHongDiskFilter) for user-mode communication via IOCTLs.
    Initializes FileFilter_disk.c to attach to physical disk devices and
    intercept writes to the boot region (sectors 0-62) for MBR protection.

Environment:
    Kernel mode
--*/

#include "../shared/Common.h"
#include "Main_disk.h"
#include "FileFilter_disk.h"

// --------------------------------------------------------------------------
// 全局变量
// --------------------------------------------------------------------------
PDEVICE_OBJECT g_DiskFilterDeviceObject = NULL;

// --------------------------------------------------------------------------
// 前向声明
// --------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
static NTSTATUS DiskFilterCreateDevice(PDRIVER_OBJECT DriverObject);
static NTSTATUS DiskFilterDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS DiskFilterDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// ============================================================================
// DriverEntry — 驱动入口
// ============================================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UNREFERENCED_PARAMETER(RegistryPath);

    /* 优先初始化日志队列，使 DiskDbgPrint 可用（日志会入队转发到 main UI） */
    DiskFilterLogInit();

    /* 创建控制设备和符号链接 */
    status = DiskFilterCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DiskDbgPrint("Failed to create control device: 0x%X\n", status);
        return status;
    }

    /* 设置 CREATE/CLOSE 分发函数 */
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DiskFilterDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DiskFilterDispatchClose;
    /* DEVICE_CONTROL 和其他 IRP 由 FileFilterInitialize 中设置的 DiskFilterDispatch 处理 */

    /* 初始化磁盘过滤（附加到物理磁盘设备栈） */
    status = FileFilterInitialize(DriverObject);
    if (!NT_SUCCESS(status)) {
        DiskDbgPrint("Failed to initialize disk filter: 0x%X\n", status);
        /* 清理已创建的控制设备 */
        UNICODE_STRING symLink;
        RtlInitUnicodeString(&symLink, DISK_SYMLINK_NAME);
        IoDeleteSymbolicLink(&symLink);
        if (g_DiskFilterDeviceObject) {
            IoDeleteDevice(g_DiskFilterDeviceObject);
        }
        return status;
    }

    /* 设置控制设备指针（供 dispatch 区分控制设备和过滤设备） */
    FileFilterSetControlDevice(g_DiskFilterDeviceObject);

    return STATUS_SUCCESS;
}

// ============================================================================
// DiskFilterCreateDevice — 创建控制设备和符号链接
// ============================================================================
static NTSTATUS DiskFilterCreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLinkName;

    RtlInitUnicodeString(&deviceName, DISK_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DiskFilterDeviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    g_DiskFilterDeviceObject->Flags |= DO_BUFFERED_IO;
    g_DiskFilterDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&symLinkName, DISK_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DiskFilterDeviceObject);
        g_DiskFilterDeviceObject = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

// ============================================================================
// DiskFilterDispatchCreate — IRP_MJ_CREATE 处理
// ============================================================================
static NTSTATUS DiskFilterDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ============================================================================
// DiskFilterDispatchClose — IRP_MJ_CLOSE 处理
// ============================================================================
static NTSTATUS DiskFilterDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
