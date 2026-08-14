#pragma once
/* ============================================================================
 * Whitelist.h - R0 白名单模块
 *
 * 用户态 AutoAllowList / AutoPreventList 通过 IOCTL_SYNC_WHITELIST_TO_DRIVER
 * 同步到驱动，供进程检查、注入检测、行为记录等路径快速跳过受信任或已标记
 * 阻止的进程。
 * ========================================================================== */

#include "../shared/Common.h"

#ifdef _KERNEL_MODE

NTSTATUS WhitelistInitialize(VOID);
VOID WhitelistCleanup(VOID);

/* 同步用户态白名单到驱动，Type=WHITELIST_TYPE_ALLOW/PREVENT */
NTSTATUS WhitelistSync(ULONG type, PWHITELIST_SYNC_DATA data, ULONG inputLength);

/* 按 PID 或进程短名/路径查询白名单。
 * 返回值：1=允许(Allow), -1=阻止(Prevent), 0=未命中 */
INT WhitelistCheckByPid(INT64 pid);
INT WhitelistCheckByName(const CHAR* name);

#endif /* _KERNEL_MODE */
