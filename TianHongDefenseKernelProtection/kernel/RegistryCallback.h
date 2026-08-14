#pragma once
#include "../shared/Common.h"

NTSTATUS RegistryProtectCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2);

REG_OPERATION GetOperationFromNotifyClass(REG_NOTIFY_CLASS NotifyClass);
NTSTATUS GetRegistryKeyPath(_In_ PVOID KeyObject, _Out_ PUNICODE_STRING* KeyPath);
VOID FreeRegistryKeyPath(_In_ PUNICODE_STRING KeyPath);
NTSTATUS CombineKeyPathAndValueName(
    _In_ PUNICODE_STRING FullKeyPath,
    _In_ PUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING OutPutPath);

// 注册表合并防护
BOOLEAN IsRegistryMergeAttack(
    _In_ PVOID KeyObject,
    _In_ PUNICODE_STRING NewName,
    _Out_opt_ PUNICODE_STRING* pFullKeyPath);

// 初始化/清理系统进程检测
VOID InitSystemProcessCheck();
BOOLEAN IsSystemProcess();
BOOLEAN IsSystemProcessByEPROCESS(PEPROCESS process);