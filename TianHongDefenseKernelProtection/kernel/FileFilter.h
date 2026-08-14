#pragma once
#include "../shared/Common.h"

NTSTATUS FileFilterInitialize(PDRIVER_OBJECT DriverObject);
VOID FileFilterUnloadWrapper();
NTSTATUS FileFilterAddRule(RULE_FILE_DATA* rule);
NTSTATUS FileFilterRemoveRule(ULONG ruleId);
NTSTATUS FileFilterClearRules();
NTSTATUS FileFilterGetStats(FILE_RULE_STATS* stats);
VOID FileFilterSetControlDevice(PDEVICE_OBJECT DeviceObject);

/* 全局 minifilter 句柄。ResponseSystem.c 中 SignatureEaRead/Write 需要用
 * FltCreateFileEx2 打开文件，传入此句柄 + Instance 可避免 minifilter 回调重入。 */
extern PFLT_FILTER g_FilterHandle;