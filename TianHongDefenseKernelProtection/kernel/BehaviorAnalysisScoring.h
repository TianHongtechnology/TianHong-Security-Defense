#pragma once
#include "../shared/Common.h"
#include "BehaviorAnalysis.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── 评分引擎 API ── */

/* 获取指标基础分 */
DOUBLE BehaviorGetIndicatorBaseScore(BA_INDICATOR id);

/* 匹配最优威胁画像 */
NTSTATUS BehaviorMatchBestProfile(
    DOUBLE* combined,
    int* outBestProfile,
    DOUBLE* outBestScore,
    DOUBLE* outConfidence
);

/* 计算综合行为评分 */
VOID BehaviorCalculateTotalScore(
    DOUBLE* combined,
    int distinctCnt,
    DOUBLE* outTotalScore,
    DOUBLE* outConfidence
);

/* 评估单个进程的威胁等级 */
VOID BehaviorScoreProcess(
    INT64 pid,
    BA_THREAT_RESULT* result
);

/* 聚合进程树指标 */
VOID BehaviorAggregateTreeIndicators(
    INT64 rootPid,
    DOUBLE* combined,
    int* pDistinctCnt,
    DOUBLE* pTotalScore
);

/* 聚合进程树证据 */
VOID BehaviorAggregateTreeEvidence(
    INT64 rootPid,
    BEHAVIOR_DETECTED_RESPONSE* alertInfo
);

/* 更新规则性能统计 */
VOID BehaviorUpdateRuleStatsOnMatch(ULONG ruleId, DOUBLE score, BOOLEAN isTruePositive);

/* 处理用户反馈（误报/确认恶意）*/
NTSTATUS BehaviorReportFeedback(
    ULONG ruleId,
    INT64 pid,
    const CHAR* imagePath,
    ULONG action,
    INT64 timestampMs
);

/* 匹配最优动态规则 */
NTSTATUS BehaviorMatchDynamicRules(
    DOUBLE* combined,
    const CHAR* imagePath,
    INT64 pid,
    DOUBLE* outScore,
    ULONG* outRuleId,
    DOUBLE* outConfidence
);

#ifdef __cplusplus
}
#endif
