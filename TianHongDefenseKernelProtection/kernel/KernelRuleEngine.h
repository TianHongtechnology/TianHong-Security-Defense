#pragma once
#include "../shared/Common.h"

VOID KernelRuleEngineInitialize();
BOOLEAN WildcardMatch(const WCHAR* pattern, const WCHAR* string);
BOOLEAN DetectRegPath(
    _In_ PVOID Argument2,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _In_ PUNICODE_STRING RegPath,
    _In_ PUNICODE_STRING ValueName,
    _In_ REG_OPERATION RegOp,
    _Out_ int* RuleIdDetected);
BOOLEAN DetectRegValue(
    _In_ PVOID Argument2,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _In_ CHAR* DetectValuePattern);
BOOLEAN DetectStringValue(
    _In_ WCHAR* ValueData,
    _In_ ULONG DataSize,
    _In_ ULONG ValueType,
    _In_ const CHAR* DetectPattern);
BOOLEAN DetectDwordValue(_In_ ULONG Value, _In_ CHAR* DetectPattern);
BOOLEAN DetectQwordValue(_In_ ULONG64 Value, _In_ CHAR* DetectPattern);