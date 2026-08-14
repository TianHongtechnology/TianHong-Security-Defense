#include "../shared/Common.h"
#include "BehaviorDynamicRules.h"
#include "BehaviorAnalysis.h"
#include <ntddk.h>

#ifndef STATUS_OBJECT_NOT_FOUND
#define STATUS_OBJECT_NOT_FOUND ((NTSTATUS)0xC000022DL)
#endif

/* ============================================================================
 * BehaviorDynamicRules.c — 动态规则池实现
 *
 * 支持最多 512 条可热加载规则，KSPIN_LOCK 保护并发访问。
 * ========================================================================== */

// ── 全局规则池 ──
BA_DYNAMIC_RULE_POOL g_baDynamicRulePool = {0};
BOOLEAN g_baDynamicRulesEnabled = FALSE;

/* --------------------------------------------------------------------------
 * 初始化/清理
 * -------------------------------------------------------------------------- */
NTSTATUS BaDynamicRulesInit(VOID)
{
    KeInitializeSpinLock(&g_baDynamicRulePool.Lock);
    g_baDynamicRulePool.Count = 0;
    g_baDynamicRulePool.Version = 0;
    RtlZeroMemory(g_baDynamicRulePool.Rules, sizeof(g_baDynamicRulePool.Rules));
    KdPrint((" [TianHong] Dynamic rule pool initialized (max=%d)\n", BA_DYN_MAX_RULES));
    return STATUS_SUCCESS;
}

VOID BaDynamicRulesCleanup(VOID)
{
    g_baDynamicRulesEnabled = FALSE;
    RtlZeroMemory(g_baDynamicRulePool.Rules, sizeof(g_baDynamicRulePool.Rules));
    g_baDynamicRulePool.Count = 0;
    g_baDynamicRulePool.Version = 0;
    KdPrint((" [TianHong] Dynamic rule pool cleaned up\n"));
}

/* --------------------------------------------------------------------------
 * 规则加载
 * -------------------------------------------------------------------------- */
NTSTATUS BaLoadDynamicRule(const BA_DYNAMIC_RULE* rule)
{
    if (rule == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);

    // 检查是否已存在同 RuleId
    for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
        if (g_baDynamicRulePool.Rules[i].RuleId == rule->RuleId) {
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            KdPrint((" [TianHong] Rule %lu already exists\n", rule->RuleId));
            return STATUS_OBJECT_NAME_EXISTS;
        }
    }

    // 检查池是否已满
    if (g_baDynamicRulePool.Count >= BA_DYN_MAX_RULES) {
        KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
        KdPrint((" [TianHong] Rule pool full\n"));
        return STATUS_MEMORY_NOT_ALLOCATED;
    }

    // 复制规则
    ULONG idx = g_baDynamicRulePool.Count;
    RtlCopyMemory(&g_baDynamicRulePool.Rules[idx], rule, sizeof(BA_DYNAMIC_RULE));
    g_baDynamicRulePool.Rules[idx].State = BA_RS_ENABLED;
    g_baDynamicRulePool.Rules[idx].LastLoadedTickMs = baEtwTickMs();
    g_baDynamicRulePool.Count++;
    g_baDynamicRulePool.Version++;

    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);

    KdPrint((" [TianHong] Rule loaded: id=%lu name=%s version=%lu\n",
             rule->RuleId, rule->Name, g_baDynamicRulePool.Version));
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * 规则移除
 * -------------------------------------------------------------------------- */
NTSTATUS BaRemoveDynamicRule(ULONG ruleId)
{
    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);

    for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
        if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
            // 用最后一条规则覆盖被删除的规则
            if (i < g_baDynamicRulePool.Count - 1) {
                RtlCopyMemory(&g_baDynamicRulePool.Rules[i],
                              &g_baDynamicRulePool.Rules[g_baDynamicRulePool.Count - 1],
                              sizeof(BA_DYNAMIC_RULE));
            }
            RtlZeroMemory(&g_baDynamicRulePool.Rules[g_baDynamicRulePool.Count - 1],
                          sizeof(BA_DYNAMIC_RULE));
            g_baDynamicRulePool.Count--;
            g_baDynamicRulePool.Version++;
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            KdPrint((" [TianHong] Rule removed: id=%lu\n", ruleId));
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    KdPrint((" [TianHong] Rule not found: id=%lu\n", ruleId));
    return STATUS_OBJECT_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * 清除全部规则
 * -------------------------------------------------------------------------- */
NTSTATUS BaClearDynamicRules(VOID)
{
    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    RtlZeroMemory(g_baDynamicRulePool.Rules, sizeof(g_baDynamicRulePool.Rules));
    g_baDynamicRulePool.Count = 0;
    g_baDynamicRulePool.Version++;
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    KdPrint((" [TianHong] All dynamic rules cleared\n"));
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * 设置规则状态
 * -------------------------------------------------------------------------- */
NTSTATUS BaSetDynamicRuleContext(ULONG ruleId, BA_RULE_STATE state)
{
    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);

    for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
        if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
            g_baDynamicRulePool.Rules[i].State = state;
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            KdPrint((" [TianHong] Rule state set: id=%lu state=%d\n", ruleId, state));
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    return STATUS_OBJECT_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * 查询规则统计
 * -------------------------------------------------------------------------- */
NTSTATUS BaGetDynamicRuleStats(ULONG ruleId, BA_RULE_STATS* stats)
{
    if (stats == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);

    if (ruleId == 0) {
        // 查询全部规则统计
        for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
            BA_DYNAMIC_RULE* r = &g_baDynamicRulePool.Rules[i];
            stats[i].RuleId = r->RuleId;
            stats[i].TriggerCount = r->Stats.TriggerCount;
            stats[i].TruePositiveCount = r->Stats.TruePositiveCount;
            stats[i].FalsePositiveCount = r->Stats.FalsePositiveCount;
            stats[i].AvgScore = r->Stats.AvgScore;
            stats[i].LastTriggered = r->Stats.LastTriggered;
        }
    } else {
        // 查询单条规则
        BOOLEAN found = FALSE;
        for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
            if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
                RtlCopyMemory(stats, &g_baDynamicRulePool.Rules[i].Stats, sizeof(BA_RULE_STATS));
                found = TRUE;
                break;
            }
        }
        if (!found) {
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            return STATUS_OBJECT_NOT_FOUND;
        }
    }

    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * 重置规则统计
 * -------------------------------------------------------------------------- */
NTSTATUS BaResetDynamicRuleStats(ULONG ruleId)
{
    if (ruleId == 0)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
        if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
            RtlZeroMemory(&g_baDynamicRulePool.Rules[i].Stats, sizeof(BA_RULE_STATS));
            g_baDynamicRulePool.Rules[i].Stats.RuleId = ruleId;
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    return STATUS_OBJECT_NOT_FOUND;
}

/* --------------------------------------------------------------------------
 * 查询规则列表
 * -------------------------------------------------------------------------- */
NTSTATUS BaGetDynamicRuleList(ULONG offset, ULONG count, BA_DYNAMIC_RULE* outRules, PULONG outCount)
{
    if (outRules == NULL || outCount == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);

    ULONG total = g_baDynamicRulePool.Count;
    ULONG start = (offset < total) ? offset : total;
    ULONG toCopy = (count < (total - start)) ? count : (total - start);

    for (ULONG i = 0; i < toCopy; i++) {
        RtlCopyMemory(&outRules[i], &g_baDynamicRulePool.Rules[start + i], sizeof(BA_DYNAMIC_RULE));
    }

    *outCount = toCopy;
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------------------------
 * 查询规则集版本
 * -------------------------------------------------------------------------- */
ULONG BaGetDynamicRuleVersion(VOID)
{
    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    ULONG ver = g_baDynamicRulePool.Version;
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    return ver;
}

/* --------------------------------------------------------------------------
 * 递增版本（热更新时用）
 * -------------------------------------------------------------------------- */
VOID BaIncrementRuleRevision(VOID)
{
    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    g_baDynamicRulePool.Version++;
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
}

/* --------------------------------------------------------------------------
 * 快照读取（评分时使用，避免长时间持锁）
 * -------------------------------------------------------------------------- */
NTSTATUS BaSnapshotDynamicRules(BA_DYNAMIC_RULE** outSnapshot, PULONG outCount)
{
    if (outSnapshot == NULL || outCount == NULL)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    ULONG count = g_baDynamicRulePool.Count;
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);

    if (count == 0) {
        *outSnapshot = NULL;
        *outCount = 0;
        return STATUS_SUCCESS;
    }

    // 分配快照内存（在 NonPagedPool 中）
    SIZE_T size = count * sizeof(BA_DYNAMIC_RULE);
    BA_DYNAMIC_RULE* snapshot = (BA_DYNAMIC_RULE*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, size, 'lRyB');
    if (snapshot == NULL)
        return STATUS_MEMORY_NOT_ALLOCATED;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    RtlCopyMemory(snapshot, g_baDynamicRulePool.Rules, size);
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);

    *outSnapshot = snapshot;
    *outCount = count;
    return STATUS_SUCCESS;
}

VOID BaReleaseDynamicRuleSnapshot(BA_DYNAMIC_RULE* snapshot)
{
    if (snapshot != NULL) {
        ExFreePoolWithTag(snapshot, 'lRyB');
    }
}

/* --------------------------------------------------------------------------
 * 根据 RuleId 查找动态规则
 * -------------------------------------------------------------------------- */
BA_DYNAMIC_RULE* BaFindDynamicRule(ULONG ruleId)
{
    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
        if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            return &g_baDynamicRulePool.Rules[i];
        }
    }
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    return NULL;
}
