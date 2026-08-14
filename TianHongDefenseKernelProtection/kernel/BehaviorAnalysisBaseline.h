#pragma once
#include "../shared/Common.h"
#include "BehaviorAnalysis.h"

#ifdef __cplusplus
extern "C" {
#endif

// ── 异常检测基线 API ──
NTSTATUS BehaviorUpdateBaseline(INT64 pid, BA_INDICATOR indicator, DOUBLE value);
BOOLEAN BehaviorDetectAnomaly(INT64 pid, BA_INDICATOR indicator, DOUBLE value, DOUBLE* zScore);
VOID BehaviorCleanupBaseline(INT64 pid);

// ── 基线查询 API ──
NTSTATUS BehaviorGetBaseline(INT64 pid, BA_INDICATOR indicator, BA_BASELINE* baseline);
VOID BehaviorCleanupAllBaselines(VOID);

#ifdef __cplusplus
}
#endif