/* ============================================================================
 * Whitelist.c - R0 白名单存储与查询
 * ========================================================================== */

/* Whitelist.c 是内核模式源文件；若项目未自动传入 _KERNEL_MODE，
 * 在此处强制进入内核路径，确保 KSPIN_LOCK、ExAllocatePool2 等可用。 */
#ifndef _KERNEL_MODE
#define _KERNEL_MODE
#endif

#include "Whitelist.h"
#include "Main.h"

/* 白名单表项：同时保存 PID 与名称（短名/路径片段），任一命中即生效 */
typedef struct _WHITELIST_TABLE {
    KSPIN_LOCK Lock;
    INT64      Pids[WHITELIST_MAX_ENTRIES];
    CHAR       Names[WHITELIST_MAX_ENTRIES][WHITELIST_NAME_LEN];
    ULONG      Count;
    BOOLEAN    Initialized;
} WHITELIST_TABLE, *PWHITELIST_TABLE;

static WHITELIST_TABLE g_AllowList = { 0 };
static WHITELIST_TABLE g_PreventList = { 0 };

static VOID WhitelistLockTable(PWHITELIST_TABLE table, PKIRQL oldIrql)
{
    KeAcquireSpinLock(&table->Lock, oldIrql);
}

static VOID WhitelistUnlockTable(PWHITELIST_TABLE table, KIRQL oldIrql)
{
    KeReleaseSpinLock(&table->Lock, oldIrql);
}

static NTSTATUS WhitelistReplaceTable(
    PWHITELIST_TABLE table,
    PWHITELIST_ENTRY entries,
    ULONG count)
{
    KIRQL oldIrql;
    ULONG i;

    if (count > WHITELIST_MAX_ENTRIES)
        count = WHITELIST_MAX_ENTRIES;

    WhitelistLockTable(table, &oldIrql);

    RtlZeroMemory(table->Pids, sizeof(table->Pids));
    RtlZeroMemory(table->Names, sizeof(table->Names));
    table->Count = count;

    for (i = 0; i < count; i++) {
        table->Pids[i] = entries[i].Pid;
        RtlStringCbCopyA(table->Names[i], sizeof(table->Names[i]), entries[i].Name);
    }

    WhitelistUnlockTable(table, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS WhitelistInitialize(VOID)
{
    RtlZeroMemory(&g_AllowList, sizeof(g_AllowList));
    RtlZeroMemory(&g_PreventList, sizeof(g_PreventList));
    KeInitializeSpinLock(&g_AllowList.Lock);
    KeInitializeSpinLock(&g_PreventList.Lock);
    g_AllowList.Initialized = TRUE;
    g_PreventList.Initialized = TRUE;
    DriverDbgPrint("[WHITELIST] Initialized\n");
    return STATUS_SUCCESS;
}

VOID WhitelistCleanup(VOID)
{
    KIRQL oldIrql;

    if (g_AllowList.Initialized) {
        WhitelistLockTable(&g_AllowList, &oldIrql);
        RtlZeroMemory(&g_AllowList.Pids, sizeof(g_AllowList.Pids));
        RtlZeroMemory(&g_AllowList.Names, sizeof(g_AllowList.Names));
        g_AllowList.Count = 0;
        WhitelistUnlockTable(&g_AllowList, oldIrql);
    }

    if (g_PreventList.Initialized) {
        WhitelistLockTable(&g_PreventList, &oldIrql);
        RtlZeroMemory(&g_PreventList.Pids, sizeof(g_PreventList.Pids));
        RtlZeroMemory(&g_PreventList.Names, sizeof(g_PreventList.Names));
        g_PreventList.Count = 0;
        WhitelistUnlockTable(&g_PreventList, oldIrql);
    }
}

NTSTATUS WhitelistSync(
    ULONG type,
    PWHITELIST_SYNC_DATA data,
    ULONG inputLength)
{
    PWHITELIST_TABLE table;

    if (!data || inputLength < sizeof(ULONG) * 2)
        return STATUS_INVALID_PARAMETER;

    if (type == WHITELIST_TYPE_ALLOW) {
        table = &g_AllowList;
    } else if (type == WHITELIST_TYPE_PREVENT) {
        table = &g_PreventList;
    } else {
        return STATUS_INVALID_PARAMETER;
    }

    /* 校验 Count 不超过数组上限，防止越界拷贝 */
    if (data->Count > WHITELIST_MAX_ENTRIES)
        return STATUS_INVALID_PARAMETER;

    /* 校验输入长度至少能容纳声明的条目数 */
    if (inputLength < FIELD_OFFSET(WHITELIST_SYNC_DATA, Entries) +
                      data->Count * sizeof(WHITELIST_ENTRY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    return WhitelistReplaceTable(table, data->Entries, data->Count);
}

INT WhitelistCheckByPid(INT64 pid)
{
    KIRQL oldIrql;
    ULONG i;
    INT result = 0;

    if (pid <= 0)
        return 0;

    /* 先查阻止列表 */
    WhitelistLockTable(&g_PreventList, &oldIrql);
    for (i = 0; i < g_PreventList.Count; i++) {
        if (g_PreventList.Pids[i] == pid) {
            result = -1;
            break;
        }
    }
    WhitelistUnlockTable(&g_PreventList, oldIrql);
    if (result != 0)
        return result;

    /* 再查允许列表 */
    WhitelistLockTable(&g_AllowList, &oldIrql);
    for (i = 0; i < g_AllowList.Count; i++) {
        if (g_AllowList.Pids[i] == pid) {
            result = 1;
            break;
        }
    }
    WhitelistUnlockTable(&g_AllowList, oldIrql);

    return result;
}

INT WhitelistCheckByName(const CHAR* name)
{
    KIRQL oldIrql;
    ULONG i;
    INT result = 0;
    CHAR lowerName[WHITELIST_NAME_LEN] = { 0 };
    const CHAR* p;
    int j;

    if (!name || name[0] == '\0')
        return 0;

    /* 提取名称中的最后一段（文件名），并转小写以进行不区分大小写比较 */
    p = name;
    while (*p) p++;
    while (p > name && *(p - 1) != '\\' && *(p - 1) != '/')
        p--;

    for (j = 0; j < WHITELIST_NAME_LEN - 1 && p[j]; j++) {
        CHAR c = p[j];
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        lowerName[j] = c;
    }

    /* 先查阻止列表 */
    WhitelistLockTable(&g_PreventList, &oldIrql);
    for (i = 0; i < g_PreventList.Count; i++) {
        CHAR entryLower[WHITELIST_NAME_LEN] = { 0 };
        int k;
        for (k = 0; k < WHITELIST_NAME_LEN - 1 && g_PreventList.Names[i][k]; k++) {
            CHAR c = g_PreventList.Names[i][k];
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            entryLower[k] = c;
        }
        if (strstr(entryLower, lowerName) != NULL || strstr(lowerName, entryLower) != NULL) {
            result = -1;
            break;
        }
    }
    WhitelistUnlockTable(&g_PreventList, oldIrql);
    if (result != 0)
        return result;

    /* 再查允许列表 */
    WhitelistLockTable(&g_AllowList, &oldIrql);
    for (i = 0; i < g_AllowList.Count; i++) {
        CHAR entryLower[WHITELIST_NAME_LEN] = { 0 };
        int k;
        for (k = 0; k < WHITELIST_NAME_LEN - 1 && g_AllowList.Names[i][k]; k++) {
            CHAR c = g_AllowList.Names[i][k];
            if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
            entryLower[k] = c;
        }
        if (strstr(entryLower, lowerName) != NULL || strstr(lowerName, entryLower) != NULL) {
            result = 1;
            break;
        }
    }
    WhitelistUnlockTable(&g_AllowList, oldIrql);

    return result;
}
