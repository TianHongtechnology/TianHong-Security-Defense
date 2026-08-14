#include "../shared/Common.h"
#include "Main.h"
#include "BehaviorAnalysis.h"
#include "BehaviorAnalysisScoring.h"
#include "BehaviorAnalysisRules.h"
#include "BehaviorDynamicRules.h"
#include "BehaviorIndicatorDefs.h"

/* 外部全局变量声明 */
extern BA_RULE_STATS g_baRuleStats[];
extern KSPIN_LOCK g_baRuleStatsLock;
extern KSPIN_LOCK g_baLock;

/* 外部 API 声明 */
extern VOID markDirty(INT64 pid);
extern VOID BehaviorLogDebug(const CHAR* format, ...);
extern VOID BehaviorLogInfo(const CHAR* format, ...);
extern VOID BehaviorLogWarning(const CHAR* format, ...);
extern VOID BehaviorLogError(const CHAR* format, ...);

/* 误报缓解 API 声明 */
extern BOOLEAN BehaviorIsWhitelisted(const CHAR* imagePath);
extern BOOLEAN BehaviorCheckException(ULONG ruleId, const CHAR* imagePath);
extern BOOLEAN BehaviorIsRuleSuppressed(ULONG ruleId, INT64 pid);
extern VOID BehaviorUpdateRuleStatsOnMatch(ULONG ruleId, DOUBLE score, BOOLEAN isTruePositive);
extern BOOLEAN BehaviorIsLegitimateProcessCreation(INT64 childPid, INT64 parentPid);
extern BOOLEAN BehaviorIsRecentSameFamilyProcess(INT64 sourcePid, INT64 targetPid);
extern BOOLEAN IsKnownSystemProcessName(const CHAR* nameLower);
extern BOOLEAN IsCriticalSystemProcess(PEPROCESS process);


/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorAnalysisScoring.c — 评分引擎模块
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── BehaviorGetIndicatorBaseScore: 获取指标基础分 ── */
DOUBLE BehaviorGetIndicatorBaseScore(BA_INDICATOR id)
{
    if (id >= BA_MAX_INDICATORS)
        return 0.0;
    return g_baIndicatorScores[id];
}

/* ── BehaviorMatchBestProfile: 匹配最优威胁画像（已迁移至动态规则）──
 * 静态 profiles 已移除，此函数改为调用动态规则匹配 */
NTSTATUS BehaviorMatchBestProfile(
    DOUBLE* combined,
    int* outBestProfile,
    DOUBLE* outBestScore,
    DOUBLE* outConfidence
)
{
    if (combined == NULL || outBestProfile == NULL || outBestScore == NULL || outConfidence == NULL)
        return STATUS_INVALID_PARAMETER;

    *outBestProfile = -1;
    *outBestScore = 0.0;
    *outConfidence = 0.0;

    /* 调用动态规则匹配 */
    ULONG dynRuleId = 0;
    DOUBLE dynScore = 0.0;
    DOUBLE dynConfidence = 0.0;
    NTSTATUS status = BehaviorMatchDynamicRules(combined, NULL, 0, &dynScore, &dynRuleId, &dynConfidence);

    if (NT_SUCCESS(status) && dynScore > 0) {
        *outBestProfile = -(int)dynRuleId;  /* 负数表示动态规则 */
        *outBestScore = dynScore;
        *outConfidence = dynConfidence;
        if (*outConfidence > 0.95) *outConfidence = 0.95;
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

/* ── BehaviorCalculateTotalScore: 计算综合行为评分 ── */
VOID BehaviorCalculateTotalScore(
    DOUBLE* combined,
    int distinctCnt,
    DOUBLE* outTotalScore,
    DOUBLE* outConfidence
)
{
    int i;
    DOUBLE totalScore = 0.0;

    if (combined == NULL || outTotalScore == NULL || outConfidence == NULL)
        return;

    *outTotalScore = 0.0;
    *outConfidence = 0.0;

    if (distinctCnt == 0)
        return;

    for (i = 0; i < BA_MAX_INDICATORS; i++)
        totalScore += combined[i];

    *outTotalScore = totalScore;

    if (totalScore >= 60.0) {
        *outConfidence = totalScore / 100.0;
        if (*outConfidence > 0.70) *outConfidence = 0.70;
    }
}

/* ── BehaviorScoreProcess: 评估单个进程的威胁等级 ──
 * 采用简洁的 Elastic detection-rules 风格：
 * - 白名单优先放行
 * - 规则例外/抑制检查
 * - 画像匹配 + 置信度计算
 * - 必要的系统进程兜底跳过
 */
VOID BehaviorScoreProcess(INT64 pid, BA_THREAT_RESULT* result)
{
    int pidx, idx, i;
    DOUBLE combined[BA_MAX_INDICATORS];
    int distinctCnt = 0;
    DOUBLE bestScore = 0.0;
    DOUBLE totalScore = 0.0;
    DOUBLE confidence = 0.0;
    BOOLEAN isWhitelisted = FALSE;
    BOOLEAN isSystemProc = FALSE;

    if (result == NULL) return;

    RtlZeroMemory(result, sizeof(BA_THREAT_RESULT));
    result->pid = pid;

    if (pid == 0) return;

    pidx = -1;
    idx = -1;

    for (i = 0; i < g_baProcCount; i++) {
        if (g_baProcTree[i].pid == pid) {
            pidx = i;
            break;
        }
    }

    for (i = 0; i < g_baIndicatorCount; i++) {
        if (g_baIndicatorPids[i] == pid) {
            idx = i;
            break;
        }
    }

    if (idx < 0) {
        if (pidx >= 0) {
            RtlStringCbCopyA(result->processPath, BA_MAX_PATH, g_baProcTree[pidx].imagePath);
        }
        return;
    }

    if (pidx >= 0) {
        RtlStringCbCopyA(result->processPath, BA_MAX_PATH, g_baProcTree[pidx].imagePath);
    }

    if (result->processPath[0] == '\0') {
        RtlStringCbCopyA(result->processPath, BA_MAX_PATH, "unknown");
    }

    /* 1. 白名单检查 */
    isWhitelisted = BehaviorIsWhitelisted(result->processPath);
    if (isWhitelisted) {
        BehaviorLogDebug("Process %s (PID=%lld) is whitelisted, skipping evaluation",
            result->processPath, pid);
        return;
    }

    /* 2. 系统关键进程兜底跳过（需 SYSTEM SID 验证，防冒名病毒绕过） */
    isSystemProc = isGenuineSystemProcess(pidx, result->processPath);
    if (isSystemProc) {
        int sysProcIndicators = 0;
        for (i = 0; i < BA_MAX_INDICATORS; i++) {
            if (g_baPidIndicators[idx][i] > 0) sysProcIndicators++;
        }
        if (sysProcIndicators <= 2) {
            BehaviorLogDebug("System process %s (PID=%lld) with %d indicators, skipping",
                result->processPath, pid, sysProcIndicators);
            return;
        }
    }

    /* 3. 合并自身指标 */
    for (i = 0; i < BA_MAX_INDICATORS; i++) combined[i] = 0.0;

    for (i = 0; i < BA_MAX_INDICATORS; i++) {
        int cnt = g_baPidIndicators[idx][i];
        if (cnt > 0) {
            DOUBLE baseScore = BehaviorGetIndicatorBaseScore((BA_INDICATOR)i);
            combined[i] = baseScore * (cnt > 2 ? 2.0 : (DOUBLE)cnt);
            distinctCnt++;
        }
    }

    /* 4. 动态规则匹配（静态 profiles 已移除） */
    {
        DOUBLE dynScore = 0.0;
        ULONG dynRuleId = 0;
        DOUBLE dynConfidence = 0.0;
        NTSTATUS dynStatus = BehaviorMatchDynamicRules(combined, result->processPath, pid,
            &dynScore, &dynRuleId, &dynConfidence);
        if (NT_SUCCESS(dynStatus) && dynScore > 0) {
            BA_DYNAMIC_RULE* dynRule = BaFindDynamicRule(dynRuleId);
            if (dynRule != NULL) {
                result->isThreat = 1;
                RtlStringCbCopyA(result->threatClass, sizeof(result->threatClass), dynRule->ThreatClass);
                RtlStringCbCopyA(result->description, sizeof(result->description), dynRule->Description);
                result->confidence = dynConfidence;
                if (result->confidence > 0.95) result->confidence = 0.95;
                BehaviorUpdateRuleStatsOnMatch(dynRuleId, dynScore, TRUE);
                bestScore = dynScore;
                BehaviorLogInfo("Dynamic rule %lu matched for %s (PID=%lld), score=%.1f",
                    dynRuleId, result->processPath, pid, dynScore);
            }
        }

        /* 后备：总分 >= 100 且 distinctCnt >= 6 */
        if (!result->isThreat) {
            BehaviorCalculateTotalScore(combined, distinctCnt, &totalScore, &confidence);
            if (totalScore >= 100.0 && distinctCnt >= 6) {
                result->isThreat = 1;
                RtlStringCbCopyA(result->threatClass, sizeof(result->threatClass),
                    "Behavior/SuspiciousBehaviorChain.Generic");
                RtlStringCbCopyA(result->description, sizeof(result->description),
                    "Suspicious behavior chain detected (multiple behavioral indicators)");
                result->confidence = totalScore / 100.0;
                if (result->confidence > 0.70) result->confidence = 0.70;
            }
        }
    }

    result->evidenceCount = 0;
    if (idx >= 0 && g_baEvidence[idx].count > 0) {
        for (i = 0; i < g_baEvidence[idx].count && result->evidenceCount < BA_MAX_EVIDENCE; i++) {
            RtlStringCbCopyA(result->evidence[result->evidenceCount], 128, g_baEvidence[idx].items[i]);
            result->evidenceCount++;
        }
    }

    if (result->isThreat) {
        BehaviorLogInfo("Process %s (PID=%lld) evaluated as THREAT, confidence=%ld/10000, rule=DynamicRule",
            result->processPath, pid,
            (LONG)(result->confidence * 10000.0 + 0.5));
    } else if (idx >= 0) {
        BehaviorLogDebug("Process %s (PID=%lld) evaluated as CLEAN", result->processPath, pid);
    }
}

/* ── collectTreeIndicatorsRecursive: 递归收集进程树中所有子孙进程的指标 ──
 * 从指定 pid 出发，沿 childPids 向下遍历整棵树，将每个进程的指标累加到 combined[]。
 * 与旧的向上追溯方式不同：向下遍历保证 rootPid 自身的指标也参与聚合，
 * 且多个子进程对同一指标的贡献可以累加（而非首次命中即止）。 */
static VOID collectTreeIndicatorsRecursive(
    INT64 pid,
    DOUBLE* combined,
    int* pDistinctCnt,
    DOUBLE* pTotalScore,
    INT64* visited,
    int* visitedCnt)
{
    int pidx, vi;
    INT64 childPid;
    int childIdx, i, cnt;

    pidx = findProc(pid);
    if (pidx < 0) return;

    /* 去重：防止循环引用或重复访问 */
    for (vi = 0; vi < *visitedCnt; vi++) {
        if (visited[vi] == pidx) return;
    }
    if (*visitedCnt < BA_MAX_PROCESSES) visited[(*visitedCnt)++] = pidx;

    /* 收集当前进程的指标 */
    childIdx = pidx;
    for (i = 0; i < BA_MAX_INDICATORS; i++) {
        cnt = g_baPidIndicators[childIdx][i];
        if (cnt > 0) {
            DOUBLE score = BehaviorGetIndicatorBaseScore((BA_INDICATOR)i) * (cnt > 2 ? 2.0 : (DOUBLE)cnt);
            if (combined[i] == 0.0) {
                /* 首次发现该指标：记录分数并计数 */
                combined[i] = score;
                (*pDistinctCnt)++;
                (*pTotalScore) += score;
            } else {
                /* 已有值：累加（来自多个子进程） */
                combined[i] += score;
                (*pTotalScore) += score;
            }
        }
    }

    /* 递归处理所有子进程 */
    for (vi = 0; vi < g_baProcTree[pidx].childCount; vi++) {
        childPid = g_baProcTree[pidx].childPids[vi];
        collectTreeIndicatorsRecursive(childPid, combined, pDistinctCnt, pTotalScore, visited, visitedCnt);
    }
}

/* ── BehaviorAggregateTreeIndicators: 聚合进程树指标 ──
 * 从 rootPid 出发向下遍历整棵进程树，收集所有子孙进程（含 rootPid 自身）的指标。
 * 多个子进程对同一指标的贡献会累加，而不是首次命中即止。 */
VOID BehaviorAggregateTreeIndicators(
    INT64 rootPid,
    DOUBLE* combined,
    int* pDistinctCnt,
    DOUBLE* pTotalScore
){
    INT64 visited[BA_MAX_PROCESSES];
    int visitedCnt = 0;

    if (combined == NULL || pDistinctCnt == NULL || pTotalScore == NULL)
        return;

    RtlZeroMemory(visited, sizeof(visited));
    collectTreeIndicatorsRecursive(rootPid, combined, pDistinctCnt, pTotalScore, visited, &visitedCnt);
}

/* ── collectTreeEvidenceRecursive: 递归收集进程树中所有子孙进程及祖先的证据 ──
 * 不仅收集 rootPid 的子孙进程证据，还沿父链向上追溯，收集祖先进程的证据。
 * 这是因为告警触发点可能是子进程，但其可疑行为可能由父进程产生。 */
static VOID collectTreeEvidenceRecursive(
    INT64 pid,
    BEHAVIOR_DETECTED_RESPONSE* alertInfo,
    CHAR(*seenEvidence)[128],
    int* seenCount,
    INT64* visited,
    int* visitedCnt)
{
    int pidx, vi, j;
    INT64 childPid;

    pidx = findProc(pid);
    if (pidx < 0) return;

    /* 去重 */
    for (vi = 0; vi < *visitedCnt; vi++) {
        if (visited[vi] == pidx) return;
    }
    if (*visitedCnt < BA_MAX_PROCESSES) visited[(*visitedCnt)++] = pidx;

    /* 收集当前进程的证据 */
    for (j = 0; j < g_baEvidence[pidx].count && alertInfo->EvidenceCount < BA_ALERT_EVIDENCE_MAX; j++) {
        CHAR* evText = g_baEvidence[pidx].items[j];
        /* 全局去重 */
        int dup = 0;
        for (int s = 0; s < *seenCount; s++) {
            if (strcmp(seenEvidence[s], evText) == 0) { dup = 1; break; }
        }
        if (dup) continue;
        if (*seenCount < (int)(128 * BA_MAX_EVIDENCE)) {
            RtlStringCbCopyA(seenEvidence[(*seenCount)++], 128, evText);
        }
        RtlStringCbCopyA(alertInfo->Evidence[alertInfo->EvidenceCount++], 128, evText);
    }

    /* 递归处理所有子进程 */
    for (vi = 0; vi < g_baProcTree[pidx].childCount; vi++) {
        childPid = g_baProcTree[pidx].childPids[vi];
        collectTreeEvidenceRecursive(childPid, alertInfo, seenEvidence, seenCount, visited, visitedCnt);
    }

    /* 沿父链向上追溯，收集祖先进程的证据 */
    {
        INT64 currentParent = g_baProcTree[pidx].parentPid;
        int parentDepth = 0;
        while (currentParent != 0 && currentParent != pid && parentDepth < 16) {
            int parentIdx = findProc(currentParent);
            if (parentIdx < 0) break;
            /* 避免循环引用 */
            int isDup = 0;
            for (vi = 0; vi < *visitedCnt; vi++) {
                if (visited[vi] == parentIdx) { isDup = 1; break; }
            }
            if (isDup) break;
            if (*visitedCnt < BA_MAX_PROCESSES) visited[(*visitedCnt)++] = parentIdx;

            /* 收集祖先进程的证据 */
            for (j = 0; j < g_baEvidence[parentIdx].count && alertInfo->EvidenceCount < BA_ALERT_EVIDENCE_MAX; j++) {
                CHAR* evText = g_baEvidence[parentIdx].items[j];
                int dup = 0;
                for (int s = 0; s < *seenCount; s++) {
                    if (strcmp(seenEvidence[s], evText) == 0) { dup = 1; break; }
                }
                if (dup) continue;
                if (*seenCount < (int)(128 * BA_MAX_EVIDENCE)) {
                    RtlStringCbCopyA(seenEvidence[(*seenCount)++], 128, evText);
                }
                RtlStringCbCopyA(alertInfo->Evidence[alertInfo->EvidenceCount++], 128, evText);
            }

            INT64 nextParent = g_baProcTree[parentIdx].parentPid;
            if (nextParent == 0 || nextParent == currentParent) break;
            currentParent = nextParent;
            parentDepth++;
        }
    }
}

/* ── BehaviorAggregateTreeEvidence: 聚合进程树证据（带全局去重）
 *
 * 注意：去重数组 seenEvidence 使用堆分配而非栈上分配。
 * 原版本 CHAR seenEvidence[128*BA_MAX_EVIDENCE][128] = 512KB 栈上分配，
 * 远超系统线程栈限制（〜12KB），导致 _chkstk IRQL_NOT_LESS_OR_EQUAL 蓝屏。
── */
VOID BehaviorAggregateTreeEvidence(INT64 rootPid, BEHAVIOR_DETECTED_RESPONSE* alertInfo)
{
    INT64 visited[BA_MAX_PROCESSES];
    int visitedCnt = 0;
    int seenCount = 0;
    CHAR(*seenEvidence)[128] = NULL;

    if (alertInfo == NULL)
        return;

    /* 堆分配去重数组（512KB 栈上分配→堆分配，避免系统线程栈溢出） */
    seenEvidence = (CHAR(*)[128])ExAllocatePool2(
        POOL_FLAG_NON_PAGED, 128 * BA_MAX_EVIDENCE * 128, 'EvSe');
    if (!seenEvidence)
        return;

    __try {
    alertInfo->EvidenceCount = 0;
    RtlZeroMemory(visited, sizeof(visited));
    collectTreeEvidenceRecursive(rootPid, alertInfo, seenEvidence, &seenCount, visited, &visitedCnt);
    } __finally {
        ExFreePool(seenEvidence);
    }
}

/* ── BehaviorUpdateRuleStatsOnMatch: 更新动态规则性能统计 ── */
VOID BehaviorUpdateRuleStatsOnMatch(ULONG ruleId, DOUBLE score, BOOLEAN isTruePositive)
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

/* ═══════════════════════════════════════════════════════════════════════════
 * Phase 2: 动态规则匹配 + 信誉加权 + 信任链加权
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── BehaviorMatchDynamicRule: 匹配单条动态规则 ── */
static DOUBLE BehaviorMatchDynamicRule(
    DOUBLE* combined,
    BA_DYNAMIC_RULE* rule,
    const CHAR* imagePath,
    INT64 pid
)
{
    UNREFERENCED_PARAMETER(pid);

    if (rule == NULL || combined == NULL || imagePath == NULL)
        return 0.0;

    // 1. 检查规则状态
    if (rule->State != BA_RS_ENABLED)
        return 0.0;

    // 2. 检查规则级例外
    for (INT i = 0; i < rule->ExceptionCount; i++) {
        if (rule->Exceptions[i].Enabled &&
            strstr(imagePath, rule->Exceptions[i].ImagePath) != NULL) {
            rule->Stats.FalsePositiveCount++;
            return 0.0;
        }
    }

    // 3. 检查规则级抑制
    LARGE_INTEGER systemTime;
    KeQuerySystemTime(&systemTime);
    INT64 nowMs = systemTime.QuadPart / 10000;
    for (INT i = 0; i < rule->SuppressionCount; i++) {
        if (rule->Suppressions[i].DurationMs == 0 ||
            nowMs < rule->Suppressions[i].StartTickMs + rule->Suppressions[i].DurationMs) {
            if (strstr(imagePath, rule->Suppressions[i].ImagePath) != NULL) {
                return 0.0;
            }
        }
    }

    // 4. 计算指标得分
    DOUBLE score = 0.0;
    INT matchCount = 0;
    BOOLEAN allRequiredMet = TRUE;

    for (INT i = 0; i < rule->IndicatorCount; i++) {
        if (rule->Indicators[i].IndicatorId >= BA_MAX_INDICATORS)
            continue;

        DOUBLE indicatorValue = combined[rule->Indicators[i].IndicatorId];
        if (indicatorValue > 0) {
            matchCount++;
            score += indicatorValue * rule->Indicators[i].Weight / 30.0;
        } else if (rule->Indicators[i].Required) {
            allRequiredMet = FALSE;
        }
    }

    // 5. 验证匹配条件
    if (!allRequiredMet)
        return 0.0;
    if (matchCount < rule->MinMatchCount)
        return 0.0;
    if (score < rule->Threshold)
        return 0.0;

    // 6. 证据质量过滤
    if (rule->EvidenceQuality.MinQualityScore > 0) {
        // 简化：假设证据质量已满足
        // 实际实现需要查询 g_baEvidenceQuality[]
    }

    return score;
}

/* ── BehaviorApplyReputationWeighting: 信誉加权 ── */
static VOID BehaviorApplyReputationWeighting(
    BA_THREAT_RESULT* result,
    DOUBLE* scoreMultiplier
)
{
    if (result == NULL || scoreMultiplier == NULL)
        return;

    DOUBLE reputation = 0.5; // 默认中性
    BOOLEAN found = FALSE;

    // 查找进程信誉
    for (ULONG i = 0; i < BA_MAX_PROCESSES; i++) {
        if (g_baReputations[i].Pid == result->pid) {
            reputation = g_baReputations[i].ReputationScore;
            found = TRUE;
            break;
        }
    }

    if (!found)
        return;

    // 已知良好进程：降低置信度
    if (reputation > 0.5) {
        *scoreMultiplier *= (1.0 - reputation * 0.5);
        BehaviorLogDebug("Process %s (PID=%lld) has good reputation=%.2f, reducing score",
            result->processPath, result->pid, reputation);
    }

    // 已知恶意进程：提升置信度
    if (reputation < 0.2) {
        *scoreMultiplier = min(*scoreMultiplier * 1.3, 0.95);
        BehaviorLogDebug("Process %s (PID=%lld) has bad reputation=%.2f, increasing score",
            result->processPath, result->pid, reputation);
    }
}

/* ── BehaviorGetTrustBonus: 信任链加权 ── */
static DOUBLE BehaviorGetTrustBonus(const CHAR* imagePath)
{
    if (imagePath == NULL)
        return 0.0;

    // 1. 查可信发布者表
    for (ULONG i = 0; i < BA_MAX_TRUSTED_PRODUCTORS; i++) {
        // 简化：使用简单字符串匹配
        if (strstr(imagePath, "Microsoft") != NULL ||
            strstr(imagePath, "Windows") != NULL) {
            return 0.3; // 知名厂商加分
        }
    }

    // 2. 查签名发布者跟踪表（历史统计）
    for (ULONG i = 0; i < BA_MAX_SIGNED_PRODUCTORS; i++) {
        if (g_baSignedProducers[i].SeenCount > 10) {
            if (strstr(imagePath, g_baSignedProducers[i].Publisher) != NULL) {
                return 0.15; // 历史可信发布者加分
            }
        }
    }

    return 0.0;
}

/* ── BehaviorMatchDynamicRules: 匹配所有动态规则 ── */
NTSTATUS BehaviorMatchDynamicRules(
    DOUBLE* combined,
    const CHAR* imagePath,
    INT64 pid,
    DOUBLE* outScore,
    ULONG* outRuleId,
    DOUBLE* outConfidence
)
{
    if (combined == NULL || imagePath == NULL || outScore == NULL || outRuleId == NULL)
        return STATUS_INVALID_PARAMETER;

    *outScore = 0.0;
    *outRuleId = 0;
    *outConfidence = 0.0;

    // 获取动态规则快照
    BA_DYNAMIC_RULE* snapshot = NULL;
    ULONG count = 0;
    NTSTATUS status = BaSnapshotDynamicRules(&snapshot, &count);
    if (!NT_SUCCESS(status) || snapshot == NULL)
        return status;

    DOUBLE bestScore = 0.0;
    ULONG bestRuleId = 0;

    for (ULONG i = 0; i < count; i++) {
        DOUBLE score = BehaviorMatchDynamicRule(combined, &snapshot[i], imagePath, pid);
        if (score > bestScore) {
            bestScore = score;
            bestRuleId = snapshot[i].RuleId;
        }
    }

    BaReleaseDynamicRuleSnapshot(snapshot);

    if (bestScore > 0) {
        *outScore = bestScore;
        *outRuleId = bestRuleId;
        *outConfidence = min(bestScore / 100.0, 0.95);
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Phase 2: 用户反馈闭环
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── BehaviorReportFeedback: 处理用户反馈（误报/确认恶意） ── */
NTSTATUS BehaviorReportFeedback(
    ULONG ruleId,
    INT64 pid,
    const CHAR* imagePath,
    ULONG action,  // 1=允许(确认误报) 2=阻止(确认恶意)
    INT64 timestampMs
)
{
    if (ruleId == 0 || imagePath == NULL)
        return STATUS_INVALID_PARAMETER;

    BOOLEAN isFalsePositive = (action == 1);

    // 更新动态规则统计
    if (g_baDynamicRulesEnabled) {
        KeAcquireSpinLockAtDpcLevel(&g_baDynamicRulePool.Lock);
        for (ULONG i = 0; i < g_baDynamicRulePool.Count; i++) {
            if (g_baDynamicRulePool.Rules[i].RuleId == ruleId) {
                BA_RULE_STATS* stats = &g_baDynamicRulePool.Rules[i].Stats;
                stats->TriggerCount++;
                stats->LastTriggered = timestampMs;
                if (isFalsePositive) {
                    stats->FalsePositiveCount++;
                    // 自动降低信誉：增加阈值
                    if (stats->FalsePositiveCount > stats->TruePositiveCount * 2) {
                        g_baDynamicRulePool.Rules[i].Threshold *= 1.2;
                        KdPrint((" [TianHong] Rule %lu threshold increased to %.1f due to false positives\n",
                                 ruleId, g_baDynamicRulePool.Rules[i].Threshold));
                    }
                } else {
                    stats->TruePositiveCount++;
                }
                break;
            }
        }
        KeReleaseSpinLockFromDpcLevel(&g_baDynamicRulePool.Lock);
    }

    // 更新进程信誉
    if (pid != 0) {
        DOUBLE reputationDelta = isFalsePositive ? 0.1 : -0.2;
        BOOLEAN found = FALSE;
        for (ULONG i = 0; i < BA_MAX_PROCESSES; i++) {
            if (g_baReputations[i].Pid == pid) {
                g_baReputations[i].ReputationScore =
                    max(0.0, min(1.0, g_baReputations[i].ReputationScore + reputationDelta));
                g_baReputations[i].LastUpdatedTickMs = timestampMs;
                found = TRUE;
                break;
            }
        }
        if (!found) {
            for (ULONG i = 0; i < BA_MAX_PROCESSES; i++) {
                if (g_baReputations[i].Pid == 0) {
                    g_baReputations[i].Pid = pid;
                    RtlStringCbCopyA(g_baReputations[i].ImagePath, BA_MAX_PATH, imagePath);
                    g_baReputations[i].ReputationScore = max(0.0, min(1.0, 0.5 + reputationDelta));
                    g_baReputations[i].FirstSeenTickMs = timestampMs;
                    g_baReputations[i].LastUpdatedTickMs = timestampMs;
                    break;
                }
            }
        }
    }

    KdPrint((" [TianHong] Feedback reported: rule=%lu pid=%lld action=%s imagePath=%s\n",
             ruleId, pid, isFalsePositive ? "FALSE_POSITIVE" : "TRUE_POSITIVE", imagePath));
    return STATUS_SUCCESS;
}
