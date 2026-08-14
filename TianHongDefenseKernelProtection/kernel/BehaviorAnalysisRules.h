#pragma once
#include "../shared/Common.h"
#include "BehaviorAnalysis.h"

#ifdef __cplusplus
extern "C" {
#endif

// ── 规则管理 API ──
BA_RULE* BehaviorGetRule(ULONG ruleId);
ULONG BehaviorGetRuleCount(VOID);
NTSTATUS BehaviorSetRuleState(ULONG ruleId, BA_RULE_STATE state);
BA_RULE_STATE BehaviorGetRuleState(ULONG ruleId);
VOID BehaviorGetRuleStats(ULONG ruleId, BA_RULE_STATS* stats);
VOID BehaviorResetRuleStats(ULONG ruleId);

// ── 规则性能统计更新 ──
VOID BehaviorUpdateRuleStats(ULONG ruleId, DOUBLE score, BOOLEAN isTruePositive);

// ── 规则版本管理 ──
ULONG BehaviorGetRuleVersion(VOID);
NTSTATUS BehaviorSetRuleVersion(ULONG version);
ULONG BehaviorGetRuleRevision(VOID);
NTSTATUS BehaviorIncrementRuleRevision(VOID);

#ifdef __cplusplus
}
#endif