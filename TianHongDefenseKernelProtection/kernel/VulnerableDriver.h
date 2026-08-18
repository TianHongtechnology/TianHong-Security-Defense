#pragma once
#include "../shared/Common.h"

/* ============================================================================
 * VulnerableDriver.h — 漏洞驱动（BYOVD）加载拦截
 *
 * 原理：维护已知漏洞驱动（BYOVD, Bring Your Own Vulnerable Driver）的
 * SHA256 哈希黑名单。驱动镜像加载时（PsSetLoadImageNotifyRoutine 回调，
 * .sys 文件），在 PASSIVE_LEVEL work item 中读取驱动文件并计算 SHA256，
 * 与黑名单比对，命中则阻止加载（终止发起加载的进程）。
 *
 * 哈希来源：LOLDrivers (https://www.loldrivers.io) 已验证样本 + 公开情报。
 * ========================================================================== */

#define VD_SHA256_SIZE 32

/* 已知漏洞驱动条目（Name 仅用于日志展示，Sha256Hex 为 64 位小写十六进制） */
typedef struct _VD_DRIVER_ENTRY {
    char Name[48];
    char Sha256Hex[65];   /* 64 hex 字符 + 结尾 '\0' */
} VD_DRIVER_ENTRY;

/* 漏洞驱动黑名单（在 VulnerableDriver.c 中定义） */
extern const VD_DRIVER_ENTRY g_VulnDrivers[];
extern const ULONG g_VulnDriverCount;

/* 判断镜像路径是否为 .sys 驱动文件（用于筛选加载回调中的驱动） */
BOOLEAN VdIsDriverImagePath(_In_ PUNICODE_STRING FullImageName);

/* 计算文件 SHA256 哈希。
 * 必须在 PASSIVE_LEVEL 调用（内部做同步文件 I/O，通常在 work item 中）。
 * 成功返回 STATUS_SUCCESS，hash 填充 32 字节。 */
NTSTATUS VdComputeFileSha256(_In_ PUNICODE_STRING FilePath,
                             _Out_ UCHAR hash[VD_SHA256_SIZE]);

/* 判断哈希是否命中漏洞驱动黑名单 */
BOOLEAN VdIsBlockedHash(_In_ const UCHAR hash[VD_SHA256_SIZE]);

/* 返回命中条目的驱动名（用于日志），未命中返回 NULL */
const char* VdGetMatchedDriverName(_In_ const UCHAR hash[VD_SHA256_SIZE]);

/* 综合检查：计算哈希、比对黑名单，命中则通知用户态并（LogOnly=FALSE 时）
 * 终止发起加载的进程。返回 TRUE 表示命中并已拦截。必须在 PASSIVE_LEVEL 调用。 */
BOOLEAN VdCheckAndBlock(
    _In_ PUNICODE_STRING DriverPath,
    _In_ HANDLE LoaderPid,
    _In_ BOOLEAN LogOnly);

/* 排队漏洞驱动检查 work item（在 LoadImageNotifyRoutine 中调用，
 * 内部异步在 PASSIVE_LEVEL 执行哈希检查与拦截）。 */
VOID VdQueueCheck(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE LoaderPid);