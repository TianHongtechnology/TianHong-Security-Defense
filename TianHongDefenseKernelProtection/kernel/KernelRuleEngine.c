#include "../shared/Common.h"
#include "Main.h"
#include "KernelRuleEngine.h"
#include <ntstrsafe.h>

/* ============================================================================
 * KernelRuleEngine.c - 规则引擎实现
 * 处理注册表规则匹配、通配符匹配和值检测
 * ========================================================================== */

// 通配符匹配短缓冲区（临时截断字符串存储）
#define MAX_DETECT_BUFFER 512


// ----------------------------------------------------------------------------
// KernelRuleEngineInitialize - 初始化规则引擎
// 规则通过 IOCTL 动态添加，此处无需额外初始化
// ----------------------------------------------------------------------------
VOID KernelRuleEngineInitialize()
{
    // 规则通过 IOCTL 动态添加，无需额外初始化
    DriverDbgPrint("Rule engine initialized\n");
}

// ----------------------------------------------------------------------------
// WildcardMatch - 通配符匹配
// 支持 *（匹配任意字符序列）和 ?（匹配单个字符）
// 使用 RtlUpcaseUnicodeChar 进行大小写不敏感比较
// 支持回溯（当 * 匹配失败时重试）
// ----------------------------------------------------------------------------
BOOLEAN WildcardMatch(const WCHAR* pattern, const WCHAR* string)
{
    const WCHAR* starPos = NULL;
    const WCHAR* stringBackup = NULL;
    const WCHAR* p = pattern;
    const WCHAR* s = string;

    if (pattern == NULL || string == NULL)
    {
        return FALSE;
    }

    while (*s != L'\0')
    {
        if (*p == L'?')
        {
            // ? 匹配任意单个字符
            p++;
            s++;
        }
        else if (*p == L'*')
        {
            // * 匹配任意字符序列，记录位置以便回溯
            starPos = p;
            p++;
            if (*p == L'\0')
            {
                // * 在末尾，匹配所有剩余字符
                return TRUE;
            }
            stringBackup = s;
        }
        else
        {
            // 普通字符，大小写不敏感比较
            if (RtlUpcaseUnicodeChar(*p) == RtlUpcaseUnicodeChar(*s))
            {
                p++;
                s++;
            }
            else
            {
                // 不匹配，回溯到最后一个 * 位置
                if (starPos != NULL && stringBackup != NULL)
                {
                    p = starPos + 1;
                    stringBackup++;
                    s = stringBackup;
                }
                else
                {
                    return FALSE;
                }
            }
        }
    }

    // 字符串完全匹配，跳过模式中所有尾部 *
    while (*p == L'*')
    {
        p++;
    }

    return (*p == L'\0');
}

// ----------------------------------------------------------------------------
// AnsiToUnicode - 将 ANSI 字符串转换为 Unicode（栈缓冲区）
// 返回转换后的 WCHAR 缓冲区指针（调用者必须释放），失败返回 NULL
// ----------------------------------------------------------------------------
static PWCHAR AnsiToUnicode(_In_ const CHAR* ansiStr)
{
    size_t ansiLen;
    PWCHAR unicodeBuf;
    size_t i;

    if (ansiStr == NULL)
    {
        return NULL;
    }

    if (!NT_SUCCESS(RtlStringCbLengthA(ansiStr, MAXUSHORT, &ansiLen)) || ansiLen == 0)
    {
        return NULL;
    }

    unicodeBuf = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        (ansiLen + 1) * sizeof(WCHAR), 'KREM');
    if (unicodeBuf == NULL)
    {
        return NULL;
    }

    for (i = 0; i < ansiLen; i++)
    {
        unicodeBuf[i] = (WCHAR)(UCHAR)ansiStr[i];
    }
    unicodeBuf[ansiLen] = L'\0';

    return unicodeBuf;
}

// ----------------------------------------------------------------------------
// DetectStringValue - 检测字符串值
// 将 ANSI DetectPattern 转换为 Unicode，将 ValueData 复制到临时缓冲区（null 结尾）
// MULTI_SZ 仅取第一个字符串，使用 WildcardMatch 进行匹配
// ----------------------------------------------------------------------------
BOOLEAN DetectStringValue(
    _In_ WCHAR* ValueData,
    _In_ ULONG DataSize,
    _In_ ULONG ValueType,
    _In_ const CHAR* DetectPattern)
{
    PWCHAR detectPatternW = NULL;
    PWCHAR tempBuffer = NULL;
    ULONG copySize;
    ULONG i;
    BOOLEAN result = FALSE;

    if (ValueData == NULL || DataSize == 0 || DetectPattern == NULL)
    {
        return FALSE;
    }

    // 将 ANSI 检测模式转换为 Unicode
    detectPatternW = AnsiToUnicode(DetectPattern);
    if (detectPatternW == NULL)
    {
        return FALSE;
    }

    // 分配临时缓冲区（确保 null 结尾）
    tempBuffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        DataSize + sizeof(WCHAR), 'KREB');
    if (tempBuffer == NULL)
    {
        ExFreePool(detectPatternW);
        return FALSE;
    }

    RtlZeroMemory(tempBuffer, DataSize + sizeof(WCHAR));

    // 将 ValueData 复制到临时缓冲区
    copySize = DataSize;
    if (copySize > DataSize)
    {
        copySize = DataSize;
    }
    RtlCopyMemory(tempBuffer, ValueData, copySize);

    // 如果是 MULTI_SZ，仅取第一个字符串（在第一个 \0\0 处截断）
    if (ValueType == REG_MULTI_SZ)
    {
        for (i = 0; i < (copySize / sizeof(WCHAR)) - 1; i++)
        {
            if (tempBuffer[i] == L'\0' && tempBuffer[i + 1] == L'\0')
            {
                // 找到多字符串分隔符，在第一个 \0 处截断
                tempBuffer[i] = L'\0';
                break;
            }
        }
    }

    // 使用通配符匹配
    result = WildcardMatch(detectPatternW, tempBuffer);

    ExFreePool(tempBuffer);
    ExFreePool(detectPatternW);

    return result;
}

// ----------------------------------------------------------------------------
// DetectDwordValue - 检测 DWORD 值
// 支持的格式：
//   [DWORD]!123        - 不等于
//   [DWORD]0<<132      - 范围（>= 0 且 <= 132）
//   [DWORD]>123        - 大于
//   [DWORD]<123        - 小于
//   [DWORD]=123        - 等于
//   [DWORD]123         - 等于
//   *                  - 匹配任意值
// ----------------------------------------------------------------------------
BOOLEAN DetectDwordValue(_In_ ULONG Value, _In_ CHAR* DetectPattern)
{
    CHAR* ptr;
    ULONG cmpValue;
    NTSTATUS status;
    CHAR op;

    if (DetectPattern == NULL)
    {
        return FALSE;
    }

    // * 匹配任意值
    if (DetectPattern[0] == '*' && DetectPattern[1] == '\0')
    {
        return TRUE;
    }

    // 跳过 [DWORD] 前缀
    ptr = DetectPattern;
    if (ptr[0] == '[' && ptr[1] == 'D' && ptr[2] == 'W' &&
        ptr[3] == 'O' && ptr[4] == 'R' && ptr[5] == 'D' && ptr[6] == ']')
    {
        ptr += 7;
    }

    // 检查运算符
    op = 0;
    if (*ptr == '!' || *ptr == '>' || *ptr == '<' || *ptr == '=')
    {
        op = *ptr;
        ptr++;
    }

    // 检查范围格式：0<<132
    if (op == '<' && *ptr == '<')
    {
        // 范围格式：数字<<数字
        ptr = DetectPattern;
        if (ptr[0] == '[' && ptr[1] == 'D' && ptr[2] == 'W' &&
            ptr[3] == 'O' && ptr[4] == 'R' && ptr[5] == 'D' && ptr[6] == ']')
        {
            ptr += 7;
        }

        // 解析范围格式：<小值><<大值>
        // 查找 << 分隔符
        {
            CHAR* sep = strstr(ptr, "<<");
            if (sep != NULL)
            {
                ULONG lowValue, highValue;
                CHAR saveLow = *sep;
                *sep = '\0';
                status = StringToULong(ptr, &lowValue);
                *sep = saveLow;

                if (!NT_SUCCESS(status))
                {
                    return FALSE;
                }

                status = StringToULong(sep + 2, &highValue);
                if (!NT_SUCCESS(status))
                {
                    return FALSE;
                }

                return (Value >= lowValue && Value <= highValue);
            }
        }
        return FALSE;
    }

    // 解析比较值
    status = StringToULong(ptr, &cmpValue);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    // 根据运算符进行比较
    switch (op)
    {
        case '!':
            return (Value != cmpValue);
        case '>':
            return (Value > cmpValue);
        case '<':
            return (Value < cmpValue);
        case '=':
            return (Value == cmpValue);
        default:
            // 无运算符，默认等于
            return (Value == cmpValue);
    }
}

// ----------------------------------------------------------------------------
// DetectQwordValue - 检测 QWORD 值（64 位）
// 格式与 DetectDwordValue 相同，使用 [QWORD] 前缀
// 使用 StringToUlong64 进行转换
// ----------------------------------------------------------------------------
BOOLEAN DetectQwordValue(_In_ ULONG64 Value, _In_ CHAR* DetectPattern)
{
    CHAR* ptr;
    ULONG64 cmpValue;
    NTSTATUS status;
    CHAR op;

    if (DetectPattern == NULL)
    {
        return FALSE;
    }

    // * 匹配任意值
    if (DetectPattern[0] == '*' && DetectPattern[1] == '\0')
    {
        return TRUE;
    }

    // 跳过 [QWORD] 前缀
    ptr = DetectPattern;
    if (ptr[0] == '[' && ptr[1] == 'Q' && ptr[2] == 'W' &&
        ptr[3] == 'O' && ptr[4] == 'R' && ptr[5] == 'D' && ptr[6] == ']')
    {
        ptr += 7;
    }

    // 检查运算符
    op = 0;
    if (*ptr == '!' || *ptr == '>' || *ptr == '<' || *ptr == '=')
    {
        op = *ptr;
        ptr++;
    }

    // 检查范围格式：0<<132
    if (op == '<' && *ptr == '<')
    {
        // 重新解析范围格式
        ptr = DetectPattern;
        if (ptr[0] == '[' && ptr[1] == 'Q' && ptr[2] == 'W' &&
            ptr[3] == 'O' && ptr[4] == 'R' && ptr[5] == 'D' && ptr[6] == ']')
        {
            ptr += 7;
        }

        {
            CHAR* sep = strstr(ptr, "<<");
            if (sep != NULL)
            {
                ULONG64 lowValue, highValue;
                CHAR saveLow = *sep;
                *sep = '\0';
                status = StringToUlong64(ptr, &lowValue);
                *sep = saveLow;

                if (!NT_SUCCESS(status))
                {
                    return FALSE;
                }

                status = StringToUlong64(sep + 2, &highValue);
                if (!NT_SUCCESS(status))
                {
                    return FALSE;
                }

                return (Value >= lowValue && Value <= highValue);
            }
        }
        return FALSE;
    }

    // 解析比较值
    status = StringToUlong64(ptr, &cmpValue);
    if (!NT_SUCCESS(status))
    {
        return FALSE;
    }

    // 根据运算符进行比较
    switch (op)
    {
        case '!':
            return (Value != cmpValue);
        case '>':
            return (Value > cmpValue);
        case '<':
            return (Value < cmpValue);
        case '=':
            return (Value == cmpValue);
        default:
            // 无运算符，默认等于
            return (Value == cmpValue);
    }
}

// ----------------------------------------------------------------------------
// DetectRegValue - 检测注册表值内容
// 根据 NotifyClass 和 DetectValuePattern 进行值内容匹配
//   RegNtSetValueKey: 根据 Type 调用不同的检测函数
//     REG_SZ/REG_EXPAND_SZ/REG_MULTI_SZ -> DetectStringValue
//     REG_DWORD -> DetectDwordValue
//     REG_QWORD -> DetectQwordValue
//     REG_BINARY(4 字节) -> DetectDwordValue
//   RegNtRenameKey: 使用 DetectStringValue 检测新名称
//   DetectValuePattern 为空或 NULL 返回 TRUE
// ----------------------------------------------------------------------------
BOOLEAN DetectRegValue(
    _In_ PVOID Argument2,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _In_ CHAR* DetectValuePattern)
{
    // 如果检测模式为空或 NULL，直接返回 TRUE
    if (DetectValuePattern == NULL || DetectValuePattern[0] == '\0')
    {
        return TRUE;
    }

    switch (NotifyClass)
    {
        case RegNtSetValueKey:
        {
            REG_SET_VALUE_KEY_INFORMATION* setInfo;

            if (Argument2 == NULL)
            {
                return FALSE;
            }

            setInfo = (REG_SET_VALUE_KEY_INFORMATION*)Argument2;

            switch (setInfo->Type)
            {
                case REG_SZ:
                case REG_EXPAND_SZ:
                case REG_MULTI_SZ:
                {
                    return DetectStringValue(
                        (WCHAR*)setInfo->Data,
                        setInfo->DataSize,
                        setInfo->Type,
                        DetectValuePattern);
                }

                case REG_DWORD:
                {
                    if (setInfo->Data == NULL || setInfo->DataSize < sizeof(ULONG))
                    {
                        return FALSE;
                    }
                    return DetectDwordValue(
                        *(PULONG)setInfo->Data,
                        DetectValuePattern);
                }

                case REG_QWORD:
                {
                    if (setInfo->Data == NULL || setInfo->DataSize < sizeof(ULONG64))
                    {
                        return FALSE;
                    }
                    return DetectQwordValue(
                        *(PULONG64)setInfo->Data,
                        DetectValuePattern);
                }

                case REG_BINARY:
                {
                    // REG_BINARY 4 字节视为 DWORD
                    if (setInfo->Data != NULL && setInfo->DataSize == sizeof(ULONG))
                    {
                        return DetectDwordValue(
                            *(PULONG)setInfo->Data,
                            DetectValuePattern);
                    }
                    return FALSE;
                }

                default:
                    return FALSE;
            }
            break;
        }

        case RegNtRenameKey:
        {
            REG_RENAME_KEY_INFORMATION* renameInfo;

            if (Argument2 == NULL)
            {
                return FALSE;
            }

            renameInfo = (REG_RENAME_KEY_INFORMATION*)Argument2;

            // 使用 DetectStringValue 检测新名称
            // NewName 是 PUNICODE_STRING（指针），使用 -> 访问成员
            if (renameInfo->NewName != NULL && renameInfo->NewName->Length > 0)
            {
                return DetectStringValue(
                    renameInfo->NewName->Buffer,
                    renameInfo->NewName->Length,
                    REG_SZ,
                    DetectValuePattern);
            }
            return FALSE;
        }

        default:
            return FALSE;
    }
}

// ----------------------------------------------------------------------------
// DetectRegPath - 检测注册表路径匹配（核心函数）
// 遍历 g_Rules 数组，仅处理 RULE_TYPE_REG 类型
//   1. 检查 Operation 匹配
//   2. 将规则的 FullPathWithOutValueName 转换为 Unicode，使用 WildcardMatch
//   3. 如果 pathMatch 且 IsNeedValueName 为 TRUE，检查 ValueName 匹配
//   4. 如果 pathMatch 且 valueNameMatch 且 DetectValue 非空，调用 DetectRegValue
//   5. 全部匹配，设置 *RuleIdDetected 并返回 TRUE
// ----------------------------------------------------------------------------
BOOLEAN DetectRegPath(
    _In_ PVOID Argument2,
    _In_ REG_NOTIFY_CLASS NotifyClass,
    _In_ PUNICODE_STRING RegPath,
    _In_ PUNICODE_STRING ValueName,
    _In_ REG_OPERATION RegOp,
    _Out_ int* RuleIdDetected)
{
    ULONG i;
    PRULE_REG_DATA ruleRegData;
    PWCHAR rulePathW = NULL;
    PWCHAR ruleValueNameW = NULL;
    BOOLEAN pathMatch;
    BOOLEAN valueNameMatch;
    BOOLEAN valueMatch;

    if (RegPath == NULL || RuleIdDetected == NULL)
    {
        return FALSE;
    }

    *RuleIdDetected = 0;

    for (i = 0; i < g_RuleCount; i++)
    {
        // 仅处理注册表规则类型
        if (g_Rules[i].rt != RULE_TYPE_REG)
        {
            continue;
        }

        ruleRegData = (PRULE_REG_DATA)&g_Rules[i].Data;

        // 检查操作类型匹配
        if (ruleRegData->Operation != RegOp)
        {
            continue;
        }

        pathMatch = FALSE;
        valueNameMatch = FALSE;
        valueMatch = FALSE;

        // 将规则的 FullPathWithOutValueName 从 ANSI 转换为 Unicode
        rulePathW = AnsiToUnicode(ruleRegData->FullPathWithOutValueName);
        if (rulePathW == NULL)
        {
            continue;
        }

        // 使用通配符匹配路径
        pathMatch = WildcardMatch(rulePathW, RegPath->Buffer);
        ExFreePool(rulePathW);
        rulePathW = NULL;

        if (!pathMatch)
        {
            continue;
        }

        // 路径匹配，检查是否需要值名称匹配
        if (ruleRegData->IsNeedValueName)
        {
            if (ValueName != NULL &&
                ruleRegData->ValueName[0] != '\0')
            {
                ruleValueNameW = AnsiToUnicode(ruleRegData->ValueName);
                if (ruleValueNameW != NULL)
                {
                    // 空值名称（默认值）可能 Buffer 为 NULL，用空字符串替代
                    const WCHAR* actualValueName = (ValueName->Buffer != NULL)
                        ? ValueName->Buffer : L"";
                    valueNameMatch = WildcardMatch(ruleValueNameW, actualValueName);
                    ExFreePool(ruleValueNameW);
                    ruleValueNameW = NULL;
                }
            }
            else
            {
                // 规则值名称模式为空，要求实际值名称也为空才匹配
                valueNameMatch = (ValueName == NULL || ValueName->Length == 0);
            }
        }
        else
        {
            // 不需要值名称检查，默认匹配
            valueNameMatch = TRUE;
        }

        if (!valueNameMatch)
        {
            continue;
        }

        // 路径和值名称都匹配，检查是否需要值内容检测
        if (ruleRegData->DetectValue[0] != '\0')
        {
            valueMatch = DetectRegValue(Argument2, NotifyClass, ruleRegData->DetectValue);
        }
        else
        {
            // 没有检测值要求，默认匹配
            valueMatch = TRUE;
        }

        if (!valueMatch)
        {
            continue;
        }

        // 全部匹配
        *RuleIdDetected = (int)ruleRegData->RuleId;
        DriverDbgPrint("Rule engine: Rule matched RuleId=%d, Operation=%d\n",
            ruleRegData->RuleId, RegOp);
        return TRUE;
    }

    return FALSE;
}