#pragma once
/* ============================================================================
 * Ioctl.h — IOCTL 接口定义（驱动与用户态共享）
 * ========================================================================== */

#include "Common.h"

// ── IOCTL 代码已在 Common.h 中定义 ──
// 本文件保留用于未来扩展

// ── NTSTATUS 常量（用户态定义） ──
#ifndef _KERNEL_MODE
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#define STATUS_TIMEOUT                   ((NTSTATUS)0x00000102L)
#define STATUS_TOO_MANY_COMMANDS         ((NTSTATUS)0xC00000CEL)
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#define STATUS_OBJECT_NAME_EXISTS        ((NTSTATUS)0x40000000L)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#define STATUS_INVALID_DEVICE_REQUEST    ((NTSTATUS)0xC0000010L)
#define STATUS_INTEGER_OVERFLOW          ((NTSTATUS)0xC0000095L)
#endif