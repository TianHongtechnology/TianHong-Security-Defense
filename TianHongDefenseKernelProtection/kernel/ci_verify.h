#pragma once
/* ============================================================================
 * ci_verify.h — 进程/镜像可信度验证（基于签名等级）
 *
 * 签名等级定义（Windows 8.1+）：
 *   SE_SIGNING_LEVEL_UNCHECKED       0x00  — 未检查
 *   SE_SIGNING_LEVEL_UNSIGNED        0x01  — 未签名
 *   SE_SIGNING_LEVEL_FILE_HASH       0x02  — 文件哈希（不可信）
 *   SE_SIGNING_LEVEL_AUTHENTICODE    0x03  — 有效内嵌签名或 .cat 目录签名（可信）
 *   SE_SIGNING_LEVEL_ANTIMALWARE     0x05  — AMSI/杀软签名
 *   SE_SIGNING_LEVEL_MICROSOFT       0x06  — 微软官方签名
 *   SE_SIGNING_LEVEL_WINDOWS         0x07  — Windows 核心组件签名
 *
 * 可信阈值：>= SE_SIGNING_LEVEL_AUTHENTICODE (0x03)
 *
 * 设计：
 *   - CiIsImageSignedAndTrusted  : 从 PIMAGE_INFO 直接读取 ImageSignatureLevel（静态内联）
 *   - CiIsPidSigned              : 查 g_baSigCache 表（由 LoadImageNotifyRoutine 维护）
 *   - CiRecordProcessSignature   : 由 LoadImageNotifyRoutine 调用，写入缓存
 *
 * 注意：CiIsProcessSignedAndTrusted 已移除。
 *   PsGetProcessSignatureLevel 未导出，EPROCESS 偏移读取不稳定。
 *   改为在 LoadImageNotifyRoutine 中记录 ImageSignatureLevel 到缓存表。
 * ============================================================================ */

#ifndef SE_SIGNING_LEVEL_UNCHECKED
#define SE_SIGNING_LEVEL_UNCHECKED       0x00
#define SE_SIGNING_LEVEL_UNSIGNED        0x01
#define SE_SIGNING_LEVEL_FILE_HASH       0x02
#define SE_SIGNING_LEVEL_AUTHENTICODE    0x03
#define SE_SIGNING_LEVEL_ANTIMALWARE     0x05
#define SE_SIGNING_LEVEL_MICROSOFT       0x06
#define SE_SIGNING_LEVEL_WINDOWS         0x07
#endif

/* 可信阈值：AUTHENTICODE 及以上视为可信 */
#define CI_TRUSTED_SIGNING_LEVEL_MIN  SE_SIGNING_LEVEL_AUTHENTICODE

/* ============================================================================
 * CiIsImageSignedAndTrusted — 判断当前加载的模块/DLL/EXE 是否可信
 *
 * 兼容内嵌签名 + .cat 目录签名。
 * ImageSignatureLevel 是 Win8.1+ 内核在映射镜像时自动填充的字段。
 *
 * 参数：
 *   ImageInfo — PIMAGE_INFO，由 PsSetLoadImageNotifyRoutine 回调提供
 *
 * 返回：
 *   TRUE  — 可信（带有合法签名：微软/第三方 CA/.cat 目录）
 *   FALSE — 未签名或签名已被篡改
 * ============================================================================ */
static BOOLEAN CiIsImageSignedAndTrusted(PIMAGE_INFO ImageInfo)
{
    if (!ImageInfo)
        return FALSE;

    /* ImageSignatureLevel 是 Win8.1+ 内核在映射镜像时自动填充的字段 */
    UCHAR sigLevel = (UCHAR)ImageInfo->ImageSignatureLevel;

    if (sigLevel >= CI_TRUSTED_SIGNING_LEVEL_MIN)
        return TRUE;  /* 可信：带有合法签名（微软/第三方 CA/.cat 目录） */

    return FALSE;  /* 未签名或签名已被篡改 */
}

/* ============================================================================
 * CiRecordProcessSignature — 记录进程主镜像的签名状态到缓存表
 *
 * 由 LoadImageNotifyRoutine 在进程主 EXE 加载时调用。
 * 后续 CiIsPidSigned 通过查表判断进程是否可信。
 *
 * 参数：
 *   pid       — 进程 ID
 *   isSigned  — 主镜像是否带有 AUTHENTICODE 及以上签名
 * ============================================================================ */
VOID CiRecordProcessSignature(INT64 pid, BOOLEAN isSigned);

/* ============================================================================
 * CiIsPidSigned — 通过缓存表检查进程是否可信
 *
 * 返回缓存中记录的签名状态。若缓存未命中，返回 FALSE（保守：未缓存视为不可信）。
 *
 * 参数：
 *   pid — 进程 ID
 *
 * 返回：
 *   TRUE  — 可信（缓存命中且 isSigned=TRUE）
 *   FALSE — 不可信或未缓存
 * ============================================================================ */
BOOLEAN CiIsPidSigned(INT64 pid);
