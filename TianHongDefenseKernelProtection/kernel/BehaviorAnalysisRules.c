#include "../shared/Common.h"
#include "Main.h"
#include "BehaviorAnalysis.h"
#include "BehaviorAnalysisRules.h"
#include "BehaviorDynamicRules.h"

/* 外部全局变量声明 */
extern BA_RULE_STATS g_baRuleStats[];
extern KSPIN_LOCK g_baRuleStatsLock;

/* ── 规则版本与状态管理 ── */
static ULONG  g_baRuleVersion = 1;
static ULONG  g_baRuleRevision = 0;
static BA_RULE_STATE g_baGlobalRuleState = BA_RS_ENABLED;

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorAnalysisRules.c — 规则管理模块
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── BehaviorGetRule: 根据规则 ID 获取动态规则 ── */
BA_RULE* BehaviorGetRule(ULONG ruleId)
{
    BA_DYNAMIC_RULE* dynRule = BaFindDynamicRule(ruleId);
    if (dynRule != NULL)
        return (BA_RULE*)dynRule;
    return NULL;
}

/* ── BehaviorGetRuleCount: 获取动态规则总数 ── */
ULONG BehaviorGetRuleCount(VOID)
{
    return g_baDynamicRulePool.Count;
}

/* ── BehaviorSetRuleState: 设置规则状态 ── */
NTSTATUS BehaviorSetRuleState(ULONG ruleId, BA_RULE_STATE state)
{
    BA_RULE* rule = BehaviorGetRule(ruleId);
    if (rule == NULL)
        return STATUS_INVALID_PARAMETER;

    if (state > BA_RS_DEPRECATED)
        return STATUS_INVALID_PARAMETER;

    rule->State = state;
    BehaviorLogInfo("Rule %lu (%s) state changed to %d", ruleId, rule->Name, state);
    return STATUS_SUCCESS;
}

/* ── BehaviorGetRuleState: 获取规则状态 ── */
BA_RULE_STATE BehaviorGetRuleState(ULONG ruleId)
{
    BA_RULE* rule = BehaviorGetRule(ruleId);
    if (rule == NULL)
        return BA_RS_DISABLED;

    return rule->State;
}

/* ── BehaviorGetRuleStats: 获取规则性能统计 ── */
VOID BehaviorGetRuleStats(ULONG ruleId, BA_RULE_STATS* stats)
{
    if (stats == NULL)
        return;

    RtlZeroMemory(stats, sizeof(BA_RULE_STATS));
    if (ruleId == 0)
        return;

    /* 优先从动态规则池获取统计 */
    BaGetDynamicRuleStats(ruleId, stats);
}

/* ── BehaviorResetRuleStats: 重置规则性能统计 ── */
VOID BehaviorResetRuleStats(ULONG ruleId)
{
    if (ruleId == 0)
        return;

    BaResetDynamicRuleStats(ruleId);
    BehaviorLogInfo("Rule %lu stats reset", ruleId);
}

/* ── BehaviorUpdateRuleStats: 更新动态规则性能统计 ── */
VOID BehaviorUpdateRuleStats(ULONG ruleId, DOUBLE score, BOOLEAN isTruePositive)
{
    if (ruleId == 0)
        return;

    KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
    for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
        if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
            BA_RULE_STATS* stats = &g_baDynamicRulePool.Rules[i].Stats;
            stats->TriggerCount++;
            stats->LastTriggered = baEtwTickMs();
            if (isTruePositive)
                stats->TruePositiveCount++;
            else
                stats->FalsePositiveCount++;
            if (stats->TriggerCount == 1)
                stats->AvgScore = score;
            else
                stats->AvgScore = stats->AvgScore * 0.9 + score * 0.1;
            KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
            return;
        }
    }
    KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
}

/* ── BehaviorGetRuleVersion: 获取当前规则版本 ── */
ULONG BehaviorGetRuleVersion(VOID)
{
    return g_baRuleVersion;
}

/* ── BehaviorSetRuleVersion: 设置规则版本 ── */
NTSTATUS BehaviorSetRuleVersion(ULONG version)
{
    if (version == 0 || version > 65535)
        return STATUS_INVALID_PARAMETER;

    g_baRuleVersion = version;
    BehaviorLogInfo("Rule version set to %lu", version);
    return STATUS_SUCCESS;
}

/* ── BehaviorGetRuleRevision: 获取当前规则修订号 ── */
ULONG BehaviorGetRuleRevision(VOID)
{
    return g_baRuleRevision;
}

/* ── BehaviorIncrementRuleRevision: 递增规则修订号 ── */
NTSTATUS BehaviorIncrementRuleRevision(VOID)
{
    if (g_baRuleRevision < 65535)
        g_baRuleRevision++;
    else
        g_baRuleRevision = 1;

    BehaviorLogInfo("Rule revision incremented to %lu", g_baRuleRevision);
    return STATUS_SUCCESS;
}