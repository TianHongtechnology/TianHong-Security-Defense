#include "../shared/Common.h"
#include "Main.h"
#include "BehaviorAnalysis.h"
#include "BehaviorAnalysisBaseline.h"

/* 外部全局变量声明 */
extern BA_BASELINE g_baBaselines[];
extern INT g_baBaselineCount;
extern KSPIN_LOCK g_baBaselineLock;

/* ═══════════════════════════════════════════════════════════════════════════
 * BehaviorAnalysisBaseline.c — 异常检测基线模块
 * ══════════════════════════════════════════════════════════════════════════ */

/* ── BehaviorUpdateBaseline: 更新异常检测基线 ── */
NTSTATUS BehaviorUpdateBaseline(INT64 pid, BA_INDICATOR indicator, DOUBLE value)
{
    KIRQL oldIrql;
    int i;
    INT64 nowMs = baEtwTickMs();
    DOUBLE alpha = 0.1;

    if (pid == 0 || indicator >= BA_MAX_INDICATORS)
        return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_baBaselineLock, &oldIrql);

    for (i = 0; i < g_baBaselineCount; i++) {
        if (g_baBaselines[i].Pid == pid && g_baBaselines[i].Indicator == indicator) {
            if (g_baBaselines[i].SampleCount > 0) {
                g_baBaselines[i].Mean = alpha * value + (1.0 - alpha) * g_baBaselines[i].Mean;
                DOUBLE diff = value - g_baBaselines[i].Mean;
                g_baBaselines[i].StdDev = alpha * diff * diff + (1.0 - alpha) * g_baBaselines[i].StdDev;
            } else {
                g_baBaselines[i].Mean = value;
                g_baBaselines[i].StdDev = 0.0;
            }
            g_baBaselines[i].SampleCount++;
            g_baBaselines[i].LastUpdateTick = nowMs;
            KeReleaseSpinLock(&g_baBaselineLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    if (g_baBaselineCount >= BA_MAX_BASELINES) {
        int oldestIdx = 0;
        INT64 oldestTick = g_baBaselines[0].LastUpdateTick;
        for (i = 1; i < g_baBaselineCount; i++) {
            if (g_baBaselines[i].LastUpdateTick < oldestTick) {
                oldestTick = g_baBaselines[i].LastUpdateTick;
                oldestIdx = i;
            }
        }
        RtlZeroMemory(&g_baBaselines[oldestIdx], sizeof(BA_BASELINE));
        g_baBaselines[oldestIdx].Pid = pid;
        g_baBaselines[oldestIdx].Indicator = indicator;
        g_baBaselines[oldestIdx].Mean = value;
        g_baBaselines[oldestIdx].StdDev = 0.0;
        g_baBaselines[oldestIdx].SampleCount = 1;
        g_baBaselines[oldestIdx].LastUpdateTick = nowMs;
    } else {
        g_baBaselines[g_baBaselineCount].Pid = pid;
        g_baBaselines[g_baBaselineCount].Indicator = indicator;
        g_baBaselines[g_baBaselineCount].Mean = value;
        g_baBaselines[g_baBaselineCount].StdDev = 0.0;
        g_baBaselines[g_baBaselineCount].SampleCount = 1;
        g_baBaselines[g_baBaselineCount].LastUpdateTick = nowMs;
        g_baBaselineCount++;
    }

    KeReleaseSpinLock(&g_baBaselineLock, oldIrql);
    return STATUS_SUCCESS;
}

/* ── BehaviorDetectAnomaly: 检测异常行为 ── */
BOOLEAN BehaviorDetectAnomaly(INT64 pid, BA_INDICATOR indicator, DOUBLE value, DOUBLE* zScore)
{
    KIRQL oldIrql;
    int i;
    BOOLEAN found = FALSE;
    DOUBLE z = 0.0;

    if (zScore != NULL)
        *zScore = 0.0;

    if (pid == 0 || indicator >= BA_MAX_INDICATORS)
        return FALSE;

    KeAcquireSpinLock(&g_baBaselineLock, &oldIrql);

    for (i = 0; i < g_baBaselineCount; i++) {
        if (g_baBaselines[i].Pid == pid && g_baBaselines[i].Indicator == indicator) {
            found = TRUE;
            if (g_baBaselines[i].StdDev > 0.0001) {
                z = (value - g_baBaselines[i].Mean) / g_baBaselines[i].StdDev;
            } else if (g_baBaselines[i].Mean > 0.0001) {
                z = (value - g_baBaselines[i].Mean) / g_baBaselines[i].Mean;
            }
            break;
        }
    }

    KeReleaseSpinLock(&g_baBaselineLock, oldIrql);

    if (found && zScore != NULL)
        *zScore = z;

    return (found && fabs(z) > 3.0);
}

/* ── BehaviorCleanupBaseline: 清理进程的异常检测基线 ── */
VOID BehaviorCleanupBaseline(INT64 pid)
{
    KIRQL oldIrql;
    int i;

    if (pid == 0)
        return;

    KeAcquireSpinLock(&g_baBaselineLock, &oldIrql);

    for (i = 0; i < g_baBaselineCount; i++) {
        if (g_baBaselines[i].Pid == pid) {
            if (i != g_baBaselineCount - 1) {
                RtlCopyMemory(&g_baBaselines[i], &g_baBaselines[g_baBaselineCount - 1],
                    sizeof(BA_BASELINE));
            }
            RtlZeroMemory(&g_baBaselines[g_baBaselineCount - 1], sizeof(BA_BASELINE));
            g_baBaselineCount--;
            i--;
        }
    }

    KeReleaseSpinLock(&g_baBaselineLock, oldIrql);
}

/* ── BehaviorGetBaseline: 获取基线信息 ── */
NTSTATUS BehaviorGetBaseline(INT64 pid, BA_INDICATOR indicator, BA_BASELINE* baseline)
{
    KIRQL oldIrql;
    int i;

    if (baseline == NULL || pid == 0 || indicator >= BA_MAX_INDICATORS)
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(baseline, sizeof(BA_BASELINE));

    KeAcquireSpinLock(&g_baBaselineLock, &oldIrql);

    for (i = 0; i < g_baBaselineCount; i++) {
        if (g_baBaselines[i].Pid == pid && g_baBaselines[i].Indicator == indicator) {
            RtlCopyMemory(baseline, &g_baBaselines[i], sizeof(BA_BASELINE));
            KeReleaseSpinLock(&g_baBaselineLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }

    KeReleaseSpinLock(&g_baBaselineLock, oldIrql);
    return STATUS_NOT_FOUND;
}

/* ── BehaviorCleanupAllBaselines: 清理所有基线数据 ── */
VOID BehaviorCleanupAllBaselines(VOID)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_baBaselineLock, &oldIrql);
    RtlZeroMemory(g_baBaselines, sizeof(g_baBaselines[0]) * BA_MAX_BASELINES);
    g_baBaselineCount = 0;
    KeReleaseSpinLock(&g_baBaselineLock, oldIrql);

    BehaviorLogInfo("All baselines cleaned up");
}