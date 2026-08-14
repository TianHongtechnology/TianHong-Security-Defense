/*++
Copyright (c) 2024  TianHong Security Defense

Module Name:
    Main_network.c

Abstract:
    WDM network filter driver entry point for TianHongHips.Network service.
    Uses WFP (Windows Filtering Platform) to monitor outbound TCP/UDP
    connections for DoH/C2/exfiltration detection.

Environment:
    Kernel mode
--*/

/* 网络驱动是纯 WDM，不包含 Common.h（含 fltKernel.h，会与 NDIS 类型冲突）。
 * 所需类型定义在 WfpCallout.h 中自包含。 */
#include <ntddk.h>
#include "WfpCallout.h"

// --------------------------------------------------------------------------
// 全局变量
// --------------------------------------------------------------------------
PDEVICE_OBJECT g_NetworkDeviceObject = NULL;

// --------------------------------------------------------------------------
// 前向声明
// --------------------------------------------------------------------------
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
static NTSTATUS NetworkFilterCreateDevice(PDRIVER_OBJECT DriverObject);
static NTSTATUS NetworkFilterDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS NetworkFilterDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS NetworkFilterDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static VOID NetworkFilterUnload(PDRIVER_OBJECT DriverObject);

// ============================================================================
// DriverEntry — 驱动入口
// ============================================================================
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    UINT32 i;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[TianHongHips.Network] DriverEntry\n");

    /* 创建控制设备 */
    status = NetworkFilterCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] CreateDevice failed: 0x%X\n", status);
        return status;
    }

    /* 设置分发函数 */
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = NetworkFilterDispatchCreate;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = NetworkFilterDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = NetworkFilterDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = NetworkFilterDispatchIoctl;
    DriverObject->DriverUnload = NetworkFilterUnload;

    /* 注册 WFP callout */
    status = WfpRegisterCallouts(DriverObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] WfpRegisterCallouts failed: 0x%X\n", status);
        /* 即使 WFP 注册失败也继续，设备仍可用于 IOCTL */
    }

    DbgPrint("[TianHongHips.Network] DriverEntry completed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// NetworkFilterCreateDevice — 创建控制设备
// ============================================================================
static NTSTATUS NetworkFilterCreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;

    RtlInitUnicodeString(&deviceName, NETWORK_DEVICE_NAME);
    RtlInitUnicodeString(&symlinkName, NETWORK_SYMLINK_NAME);

    status = IoCreateDevice(DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_NetworkDeviceObject);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] IoCreateDevice failed: 0x%X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] IoCreateSymbolicLink failed: 0x%X\n", status);
        IoDeleteDevice(g_NetworkDeviceObject);
        g_NetworkDeviceObject = NULL;
        return status;
    }

    g_NetworkDeviceObject->Flags |= DO_BUFFERED_IO;
    g_NetworkDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

// ============================================================================
// DispatchCreate/Close
// ============================================================================
static NTSTATUS NetworkFilterDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS NetworkFilterDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// ============================================================================
// NetworkFilterDispatchIoctl — IOCTL 处理
// ============================================================================
static NTSTATUS NetworkFilterDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID inBuf = Irp->AssociatedIrp.SystemBuffer;
    PVOID outBuf = Irp->AssociatedIrp.SystemBuffer;
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    __try {
        switch (ioControlCode) {
            case IOCTL_NETWORK_SET_ENABLED:
            {
                if (inputLen >= sizeof(ULONG)) {
                    ULONG* enabled = (ULONG*)inBuf;
                    g_bNetworkProtectionEnabled = (*enabled) ? TRUE : FALSE;
                    DbgPrint("[TianHongHips.Network] Protection %s\n",
                        g_bNetworkProtectionEnabled ? "enabled" : "disabled");
                }
                break;
            }

            case IOCTL_NETWORK_POLL_EVENT:
            {
                if (outputLen >= sizeof(NETWORK_EVENT_DATA)) {
                    if (WfpPollEvent((PNETWORK_EVENT_DATA)outBuf)) {
                        bytesReturned = sizeof(NETWORK_EVENT_DATA);
                    } else {
                        status = STATUS_NO_MORE_ENTRIES;
                    }
                } else {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                break;
            }

            case IOCTL_NETWORK_GET_STATUS:
            {
                if (outputLen >= sizeof(ULONG)) {
                    ULONG* state = (ULONG*)outBuf;
                    *state = g_bNetworkProtectionEnabled ? 1 : 0;
                    bytesReturned = sizeof(ULONG);
                }
                break;
            }

            case IOCTL_NETWORK_ADD_DOH_SERVER:
            {
                if (inputLen >= sizeof(DOH_SERVER_ENTRY)) {
                    status = WfpAddDohServer((PDOH_SERVER_ENTRY)inBuf);
                } else {
                    status = STATUS_BUFFER_TOO_SMALL;
                }
                break;
            }

            case IOCTL_NETWORK_CLEAR_DOH_SERVERS:
            {
                WfpClearDohServers();
                break;
            }

            default:
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ============================================================================
// NetworkFilterUnload — 驱动卸载
// ============================================================================
static VOID NetworkFilterUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;
    UNREFERENCED_PARAMETER(DriverObject);

    DbgPrint("[TianHongHips.Network] Unloading\n");

    /* 注销 WFP callout */
    WfpUnregisterCallouts();

    /* 删除符号链接和设备 */
    RtlInitUnicodeString(&symlinkName, NETWORK_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (g_NetworkDeviceObject) {
        IoDeleteDevice(g_NetworkDeviceObject);
        g_NetworkDeviceObject = NULL;
    }

    DbgPrint("[TianHongHips.Network] Unload completed\n");
}
