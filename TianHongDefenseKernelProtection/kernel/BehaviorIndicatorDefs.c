#include "../shared/Common.h"
#include "BehaviorIndicatorDefs.h"
#include "BehaviorAnalysis.h"
#include <ntddk.h>

#ifndef STATUS_OBJECT_NOT_FOUND
#define STATUS_OBJECT_NOT_FOUND ((NTSTATUS)0xC000022DL)
#endif

/* ============================================================================
 * BehaviorIndicatorDefs.c — 动态指标定义池实现
 *
 * 支持声明式指标定义，通过 IOCTL 热加载，无需重新编译驱动。
 * ========================================================================== */

// ── 全局指标定义池 ──
BA_INDICATOR_DEFINITION_POOL g_baIndicatorDefPool = {0};
BOOLEAN g_baIndicatorDefsEnabled = FALSE;

/* --------------------------------------------------------------------------
 * 初始化/清理
 * -------------------------------------------------------------------------- */
NTSTATUS BaIndicatorDefsInit(VOID)
{
    KeInitializeSpinLock(&g_baIndicatorDefPool.Lock);
    g_baIndicatorDefPool.Count = 0;
    g_baIndicatorDefPool.Version = 0;
    RtlZeroMemory(g_baIndicatorDefPool.Definitions, sizeof(g_baIndicatorDefPool.Definitions));
    KdPrint((" [TianHong] Indicator definition pool initialized (max=%d)\n", BA_IND_DEF_MAX));
    return STATUS_SUCCESS;
}

VOID BaIndicatorDefsCleanup(VOID)
{
    g_baIndicatorDefsEnabled = FALSE;
    RtlZeroMemory(g_baIndicatorDefPool.Definitions, sizeof(g_baIndicatorDefPool.Definitions));
    g_baIndicatorDefPool.Count = 0;
    g_baIndicatorDefPool.Version = 0;
    KdPrint((" [TianHong] Indicator definition pool cleaned up\n"));
}

/* --------------------------------------------------------------------------
 * 加载指标定义
 * -------------------------------------------------------------------------- */
NTSTATUS BaLoadIndicatorDefinition(const BA_INDICATOR_DEFINITION* def)
{
    if (def == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);

    // 检查是否已存在同 IndicatorId
    for (ULONG i = 0; i < g_baIndicatorDefPool.Count; i++) {
        if (g_baIndicatorDefPool.Definitions[i].IndicatorId == def->IndicatorId) {
            // 更新已有定义
            RtlCopyMemory(&g_baIndicatorDefPool.Definitions[i], def, sizeof(BA_INDICATOR_DEFINITION));
            g_baIndicatorDefPool.Version++;
            KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
            KdPrint((" [TianHong] Indicator def updated: id=%lu\n", def->IndicatorId));
            return STATUS_SUCCESS;
        }
    }

    // 检查池是否已满
    if (g_baIndicatorDefPool.Count >= BA_IND_DEF_MAX) {
        KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
        KdPrint((" [TianHong] Indicator def pool full\n"));
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    // 添加新定义
    ULONG idx = g_baIndicatorDefPool.Count;
    RtlCopyMemory(&g_baIndicatorDefPool.Definitions[idx], def, sizeof(BA_INDICATOR_DEFINITION));
    g_baIndicatorDefPool.Count++;
    g_baIndicatorDefPool.Version++;

    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);

    KdPrint((" [TianHong] Indicator def loaded: id=%lu name=%s\n",
             def->IndicatorId, def->Name));
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * 移除指标定义
 * -------------------------------------------------------------------------- */
NTSTATUS BaRemoveIndicatorDefinition(ULONG indicatorId)
{
    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);

    for (ULONG i = 0; i < g_baIndicatorDefPool.Count; i++) {
        if (g_baIndicatorDefPool.Definitions[i].IndicatorId == indicatorId) {
            // 用最后一条定义覆盖被删除的定义
            if (i < g_baIndicatorDefPool.Count - 1) {
                RtlCopyMemory(&g_baIndicatorDefPool.Definitions[i],
                              &g_baIndicatorDefPool.Definitions[g_baIndicatorDefPool.Count - 1],
                              sizeof(BA_INDICATOR_DEFINITION));
            }
            RtlZeroMemory(&g_baIndicatorDefPool.Definitions[g_baIndicatorDefPool.Count - 1],
                          sizeof(BA_INDICATOR_DEFINITION));
            g_baIndicatorDefPool.Count--;
            g_baIndicatorDefPool.Version++;
            KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
            KdPrint((" [TianHong] Indicator def removed: id=%lu\n", indicatorId));
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
    KdPrint((" [TianHong] Indicator def not found: id=%lu\n", indicatorId));
    return STATUS_OBJECT_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * 清除全部指标定义
 * -------------------------------------------------------------------------- */
NTSTATUS BaClearIndicatorDefinitions(VOID)
{
    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);
    RtlZeroMemory(g_baIndicatorDefPool.Definitions, sizeof(g_baIndicatorDefPool.Definitions));
    g_baIndicatorDefPool.Count = 0;
    g_baIndicatorDefPool.Version++;
    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
    KdPrint((" [TianHong] All indicator definitions cleared\n"));
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * 查询指标定义版本
 * -------------------------------------------------------------------------- */
ULONG BaGetIndicatorDefinitionVersion(VOID)
{
    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);
    ULONG ver = g_baIndicatorDefPool.Version;
    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
    return ver;
}

/* --------------------------------------------------------------------------
 * 检查指标是否已定义
 * -------------------------------------------------------------------------- */
BOOLEAN BaIsIndicatorDefined(ULONG indicatorId)
{
    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);

    BOOLEAN found = FALSE;
    for (ULONG i = 0; i < g_baIndicatorDefPool.Count; i++) {
        if (g_baIndicatorDefPool.Definitions[i].IndicatorId == indicatorId) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
    return found;
}

/* --------------------------------------------------------------------------
 * 获取指标定义
 * -------------------------------------------------------------------------- */
BA_INDICATOR_DEFINITION* BaGetIndicatorDefinition(ULONG indicatorId)
{
    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);

    BA_INDICATOR_DEFINITION* result = NULL;
    for (ULONG i = 0; i < g_baIndicatorDefPool.Count; i++) {
        if (g_baIndicatorDefPool.Definitions[i].IndicatorId == indicatorId) {
            result = &g_baIndicatorDefPool.Definitions[i];
            break;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);
    return result;
}

/* --------------------------------------------------------------------------
 * 快照读取（指标提取时使用）
 * -------------------------------------------------------------------------- */
NTSTATUS BaSnapshotIndicatorDefs(BA_INDICATOR_DEFINITION** outSnapshot, PULONG outCount)
{
    if (outSnapshot == NULL || outCount == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);
    ULONG count = g_baIndicatorDefPool.Count;
    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);

    if (count == 0) {
        *outSnapshot = NULL;
        *outCount = 0;
        return STATUS_SUCCESS;
    }

    SIZE_T size = count * sizeof(BA_INDICATOR_DEFINITION);
    BA_INDICATOR_DEFINITION* snapshot = (BA_INDICATOR_DEFINITION*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, size, 'dInB');
    if (snapshot == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    KeAcquireSpinLockAtDpcLevel(&g_baIndicatorDefPool.Lock);
    RtlCopyMemory(snapshot, g_baIndicatorDefPool.Definitions, size);
    KeReleaseSpinLockFromDpcLevel(&g_baIndicatorDefPool.Lock);

    *outSnapshot = snapshot;
    *outCount = count;
    return STATUS_SUCCESS;
}

VOID BaReleaseIndicatorDefSnapshot(BA_INDICATOR_DEFINITION* snapshot)
{
    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, 'dInB');
    }
}
