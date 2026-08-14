#pragma once
#include "../shared/Common.h"
#include "BehaviorAnalysis.h"
#include "BehaviorDynamicRules.h"

/* ============================================================================
 * BehaviorIndicatorDefs.h — 动态指标定义池（内核态）
 *
 * 支持声明式指标定义，通过 IOCTL 热加载，无需重新编译驱动。
 * ========================================================================== */

// ── 指标定义限制 ──
#define BA_IND_DEF_MAX              256
#define BA_IND_MAX_SUB_CONDITIONS   8
#define BA_IND_MAX_EXCLUDE_PATTERNS 8
#define BA_IND_MAX_STRING_LIST      64
#define BA_IND_DEF_NAME_LEN         128
#define BA_IND_DEF_DESC_LEN         256
#define BA_IND_DEF_FIELD_LEN        128

// ── 指标条件类型 ──
typedef enum _BA_INDICATOR_CONDITION_TYPE {
    BA_COND_ALWAYS_TRUE = 0,
    BA_COND_PATH_CONTAINS,
    BA_COND_PATH_NOT_CONTAINS,
    BA_COND_PATH_MATCHES,
    BA_COND_FILE_OP_EQ,
    BA_COND_REG_OP_EQ,
    BA_COND_MEM_OP_EQ,
    BA_COND_DESIRED_ACCESS_HAS_FLAG,
    BA_COND_IS_SIGNED_EQ,
    BA_COND_FILE_EXT_IN_LIST,
    BA_COND_FILE_EXT_EQ,
    BA_COND_PARENT_NAME_IN_LIST,
    BA_COND_ALL_OF,
    BA_COND_ANY_OF,
    BA_COND_BULK_OPERATION,
    BA_COND_TIME_WINDOW_COUNT,
    BA_COND_PARENT_CHILD_MATCH
} BA_INDICATOR_CONDITION_TYPE;

// ── 指标条件字段 ──
typedef enum _BA_INDICATOR_CONDITION_FIELD {
    BA_FIELD_IMAGE_PATH = 0,
    BA_FIELD_FILE_PATH,
    BA_FIELD_FILE_DIR,
    BA_FIELD_FILE_NAME,
    BA_FIELD_FILE_EXT,
    BA_FIELD_REG_PATH,
    BA_FIELD_REG_VALUE,
    BA_FIELD_DESIRED_ACCESS,
    BA_FIELD_MEM_OP,
    BA_FIELD_FILE_OP,
    BA_FIELD_REG_OP,
    BA_FIELD_IS_SIGNED,
    BA_FIELD_TARGET_PROCESS,
    BA_FIELD_TARGET_PID,
    BA_FIELD_PARENT_NAME,
    BA_FIELD_PARENT_PATH,
    BA_FIELD_CATEGORY
} BA_INDICATOR_CONDITION_FIELD;

// ── 指标条件操作符 ──
typedef enum _BA_INDICATOR_CONDITION_OP {
    BA_OP_EQ = 0,
    BA_OP_NEQ,
    BA_OP_CONTAINS,
    BA_OP_NOT_CONTAINS,
    BA_OP_MATCHES,
    BA_OP_IN_LIST,
    BA_OP_HAS_FLAG
} BA_INDICATOR_CONDITION_OP;

// ── 子条件 ──
typedef struct _BA_INDICATOR_SUB_COND {
    BA_INDICATOR_CONDITION_FIELD Field;
    BA_INDICATOR_CONDITION_OP Op;
    CHAR StringValue[BA_IND_DEF_FIELD_LEN];
    ULONG UlongValue;
    BOOLEAN Negate;
} BA_INDICATOR_SUB_COND;

// ── 指标定义 ──
typedef struct _BA_INDICATOR_DEFINITION {
    ULONG   IndicatorId;
    CHAR    Name[BA_IND_DEF_NAME_LEN];
    CHAR    Description[BA_IND_DEF_DESC_LEN];
    BA_EVENT_CATEGORY Category;
    DOUBLE  BaseScore;
    BOOLEAN IsDynamic;

    BA_INDICATOR_CONDITION_TYPE ConditionType;
    BA_INDICATOR_SUB_COND SubConditions[BA_IND_MAX_SUB_CONDITIONS];
    INT     SubConditionCount;

    BA_INDICATOR_SUB_COND ExcludeConditions[BA_IND_MAX_EXCLUDE_PATTERNS];
    INT     ExcludeConditionCount;

    CHAR    StringList[BA_IND_MAX_STRING_LIST][32];
    INT     StringListCount;

    struct {
        INT LookbackCount;
        INT Threshold;
        INT64 TimeWindowMs;
    } BulkParams;

    BA_DYN_CONTEXT_FILTER RequiredContext;
} BA_INDICATOR_DEFINITION;

// ── 指标定义池 ──
typedef struct _BA_INDICATOR_DEFINITION_POOL {
    BA_INDICATOR_DEFINITION Definitions[BA_IND_DEF_MAX];
    ULONG Count;
    ULONG Version;
    KSPIN_LOCK Lock;
} BA_INDICATOR_DEFINITION_POOL;

// ── 用户态下发的指标定义加载请求 ──
typedef struct _BA_INDICATOR_DEF_LOAD_REQ {
    BA_INDICATOR_DEFINITION Def;
} BA_INDICATOR_DEF_LOAD_REQ;

// ── 全局变量 ──
extern BA_INDICATOR_DEFINITION_POOL g_baIndicatorDefPool;
extern BOOLEAN g_baIndicatorDefsEnabled;

// ── 公开 API ──
NTSTATUS BaIndicatorDefsInit(VOID);
VOID BaIndicatorDefsCleanup(VOID);
NTSTATUS BaLoadIndicatorDefinition(const BA_INDICATOR_DEFINITION* def);
NTSTATUS BaRemoveIndicatorDefinition(ULONG indicatorId);
NTSTATUS BaClearIndicatorDefinitions(VOID);
ULONG BaGetIndicatorDefinitionVersion(VOID);
BOOLEAN BaIsIndicatorDefined(ULONG indicatorId);
BA_INDICATOR_DEFINITION* BaGetIndicatorDefinition(ULONG indicatorId);

// ── 快照读取 ──
NTSTATUS BaSnapshotIndicatorDefs(BA_INDICATOR_DEFINITION** outSnapshot, PULONG outCount);
VOID BaReleaseIndicatorDefSnapshot(BA_INDICATOR_DEFINITION* snapshot);
