#pragma once
/* ============================================================================
 * Ioctl.h — IOCTL 接口定义（驱动与用户态共享）
 * ========================================================================== */

#include "Common.h"

// ── IOCTL 代码已在 Common.h 中定义 ──
// 本文件保留用于未来扩展

// ── NTSTATUS 常量（用户态定义，仅在 winnt.h 未定义时补充） ──
#ifndef _KERNEL_MODE
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED             ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER         ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#endif
#ifndef STATUS_TIMEOUT
#define STATUS_TIMEOUT                   ((NTSTATUS)0x00000102L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND                 ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#endif
#ifndef STATUS_INTEGER_OVERFLOW
#define STATUS_INTEGER_OVERFLOW          ((NTSTATUS)0xC0000095L)
#endif
#endif