#pragma once

/* ============================================================================
 * FileFilter_disk.h - Disk filter driver header (MBR protection)
 *
 * Standalone WDM disk filter driver for TianHongHips.Disk service.
 * Attaches to physical disk devices and intercepts writes to boot region
 * (sectors 0-62) to protect MBR.
 * ========================================================================== */

#include "../shared/Common.h"

/* 初始化磁盘过滤设备，附加到所有物理磁盘设备栈 */
NTSTATUS FileFilterInitialize(PDRIVER_OBJECT DriverObject);

/* 卸载磁盘过滤设备，从所有设备栈分离 */
VOID FileFilterUnloadWrapper(VOID);

/* 设置控制设备指针（供 dispatch 区分控制设备和过滤设备） */
VOID FileFilterSetControlDevice(PDEVICE_OBJECT DeviceObject);

/* IOCTL 处理函数 */
NTSTATUS DiskFilterDispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/* 获取当前 MBR 保护启用状态 */
BOOLEAN DiskFilterIsEnabled(VOID);

/* 初始化日志队列（供 DriverEntry 早期调用，使 DiskDbgPrint 可用） */
VOID DiskFilterLogInit(VOID);

/* 日志输出：DbgPrint + 入队（供客户端轮询转发到 main UI）。
 * 可变参数，用法同 printf。注意内核不支持 %f 浮点格式。 */
VOID DiskDbgPrint(PCSTR fmt, ...);
