#pragma once
#include "../shared/Common.h"
#include "BehaviorAnalysis.h"

/* ============================================================================
 * BehaviorDynamicRules.h — 动态规则池（内核态）
 *
 * 支持运行时热加载（IOCTL），最多 512 条规则，KSPIN_LOCK 保护并发访问。
 * ========================================================================== */

// ── 动态规则限制 ──
#define BA_DYN_MAX_RULES              512
#define BA_DYN_MAX_INDICATORS         32
#define BA_DYN_MAX_EXCEPTIONS         16
#define BA_DYN_MAX_SUPPRESSIONS       8
#define BA_DYN_RULE_FIELD_LEN         256
#define BA_DYN_RULE_DESC_LEN          512
#define BA_DYN_RULE_PATH_LEN          260
#define BA_DYN_RULE_REASON_LEN        128
#define BA_DYN_RULE_NAME_LEN          128
#define BA_DYN_RULE_CLASS_LEN         128
#define BA_DYN_VERSION_MAX            256

// ── 动态规则指标引用 ──
typedef struct _BA_DYN_INDICATOR_REF {
    ULONG  IndicatorId;
    DOUBLE Weight;
    BOOLEAN Required;
} BA_DYN_INDICATOR_REF;

// ── 动态规则例外 ──
typedef struct _BA_DYN_EXCEPTION {
    CHAR   ImagePath[BA_DYN_RULE_PATH_LEN];
    CHAR   Reason[BA_DYN_RULE_REASON_LEN];
    BOOLEAN Enabled;
} BA_DYN_EXCEPTION;

// ── 动态规则抑制 ──
typedef struct _BA_DYN_SUPPRESSION {
    CHAR   ImagePath[BA_DYN_RULE_PATH_LEN];
    INT64  DurationMs;
    CHAR   Reason[BA_DYN_RULE_REASON_LEN];
    INT64  StartTickMs;
} BA_DYN_SUPPRESSION;

// ── 动态规则上下文过滤 ──
typedef struct _BA_DYN_CONTEXT_FILTER {
    CHAR   ParentName[BA_DYN_RULE_NAME_LEN];
    CHAR   ParentPathPattern[BA_DYN_RULE_PATH_LEN];
    BOOLEAN ExcludeSignedParent;
    BOOLEAN RequireUnsignedSelf;
} BA_DYN_CONTEXT_FILTER;

// ── 动态规则证据质量要求 ──
typedef struct _BA_DYN_EVIDENCE_QUALITY_REQ {
    DOUBLE MinQualityScore;
    BOOLEAN RequireConfirmation;
} BA_DYN_EVIDENCE_QUALITY_REQ;

// ── 动态规则条目 ──
typedef struct _BA_DYNAMIC_RULE {
    // 元数据
    ULONG   RuleId;
    ULONG   Version;
    CHAR    Name[BA_DYN_RULE_NAME_LEN];
    CHAR    ThreatClass[BA_DYN_RULE_CLASS_LEN];
    CHAR    Description[BA_DYN_RULE_DESC_LEN];
    ULONG   Severity;
    ULONG   RiskScore;
    ULONG   MitreTactic;
    CHAR    MitreTechnique[32];

    // 检测逻辑
    DOUBLE  Threshold;
    INT     MinMatchCount;
    BOOLEAN DirectMalicious;
    INT     IndicatorCount;
    BA_DYN_INDICATOR_REF Indicators[BA_DYN_MAX_INDICATORS];

    // 上下文过滤
    BA_DYN_CONTEXT_FILTER Context;

    // 误报缓解
    INT     ExceptionCount;
    BA_DYN_EXCEPTION Exceptions[BA_DYN_MAX_EXCEPTIONS];
    INT     SuppressionCount;
    BA_DYN_SUPPRESSION Suppressions[BA_DYN_MAX_SUPPRESSIONS];

    // 证据质量
    BA_DYN_EVIDENCE_QUALITY_REQ EvidenceQuality;

    // 运行时状态
    BA_RULE_STATE State;
    BA_RULE_STATS Stats;
    INT64   LastLoadedTickMs;
} BA_DYNAMIC_RULE, *PBA_DYNAMIC_RULE;

// ── 动态规则池 ──
typedef struct _BA_DYNAMIC_RULE_POOL {
    BA_DYNAMIC_RULE Rules[BA_DYN_MAX_RULES];
    ULONG Count;
    ULONG Version;
    KSPIN_LOCK Lock;
} BA_DYNAMIC_RULE_POOL, *PBA_DYNAMIC_RULE_POOL;

// ── 用户态下发的规则加载请求 ──
typedef struct _BA_DYNAMIC_RULE_LOAD_REQ {
    BA_DYNAMIC_RULE Rule;
} BA_DYNAMIC_RULE_LOAD_REQ, *PBA_DYNAMIC_RULE_LOAD_REQ;

// ── 用户态下发的规则移除请求 ──
typedef struct _BA_DYNAMIC_RULE_REMOVE_REQ {
    ULONG RuleId;
} BA_DYNAMIC_RULE_REMOVE_REQ, *PBA_DYNAMIC_RULE_REMOVE_REQ;

// ── 用户态下发的规则状态设置请求 ──
typedef struct _BA_DYNAMIC_RULE_STATE_REQ {
    ULONG RuleId;
    BA_RULE_STATE State;
} BA_DYNAMIC_RULE_STATE_REQ, *PBA_DYNAMIC_RULE_STATE_REQ;

// ── 用户态查询规则统计请求 ──
typedef struct _BA_DYNAMIC_RULE_STATS_REQ {
    ULONG RuleId;  // 0 = 查询全部
} BA_DYNAMIC_RULE_STATS_REQ, *PBA_DYNAMIC_RULE_STATS_REQ;

// ── 用户态查询规则列表请求 ──
typedef struct _BA_DYNAMIC_RULE_LIST_REQ {
    ULONG Offset;
    ULONG Count;
} BA_DYNAMIC_RULE_LIST_REQ, *PBA_DYNAMIC_RULE_LIST_REQ;

// ── 规则池全局变量 ──
extern BA_DYNAMIC_RULE_POOL g_baDynamicRulePool;
extern BOOLEAN g_baDynamicRulesEnabled;

// ── 公开 API ──
NTSTATUS BaDynamicRulesInit(VOID);
VOID BaDynamicRulesCleanup(VOID);
NTSTATUS BaLoadDynamicRule(const BA_DYNAMIC_RULE* rule);
NTSTATUS BaRemoveDynamicRule(ULONG ruleId);
NTSTATUS BaClearDynamicRules(VOID);
NTSTATUS BaSetDynamicRuleContext(ULONG ruleId, BA_RULE_STATE state);
NTSTATUS BaGetDynamicRuleStats(ULONG ruleId, BA_RULE_STATS* stats);
NTSTATUS BaResetDynamicRuleStats(ULONG ruleId);
NTSTATUS BaGetDynamicRuleList(ULONG offset, ULONG count, BA_DYNAMIC_RULE* outRules, PULONG outCount);
ULONG BaGetDynamicRuleVersion(VOID);
VOID BaIncrementRuleRevision(VOID);

// ── 快照读取（评分时使用）──
NTSTATUS BaSnapshotDynamicRules(BA_DYNAMIC_RULE** outSnapshot, PULONG outCount);
VOID BaReleaseDynamicRuleSnapshot(BA_DYNAMIC_RULE* snapshot);

// ── 根据 RuleId 查找规则 ──
BA_DYNAMIC_RULE* BaFindDynamicRule(ULONG ruleId);
