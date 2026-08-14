#include "../shared/Common.h"
#include "Main.h"
#include "RegistryCallback.h"
#include "KernelRuleEngine.h"
#include "ResponseSystem.h"
#include "BehaviorAnalysis.h"

// 声明未导出的内核 API
NTKERNELAPI UCHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
NTKERNELAPI PACCESS_TOKEN PsReferencePrimaryToken(_In_ PEPROCESS Process);
NTSYSAPI VOID PsDereferencePrimaryToken(_In_ PACCESS_TOKEN PrimaryToken);


/* ═══════════════════════════════════════════════════════════════════════════
 * 注册表合并防护 (Registry Merge Protection)
 *
 * 原理：监控 RegNtRenameKey 操作，当有程序试图将一个注册表键重命名为
 * 关键键的名称（在同一父键下），即构成"合并攻击"——攻击者先创建恶意键，
 * 再通过重命名替换/合并到关键注册表位置，绕过常规的创建/写入监控。
 *
 * 覆盖范围（内核路径格式 \REGISTRY\MACHINE\... 和 \REGISTRY\USER\...）：
 *   - Image File Execution Options (IFEO Debugger 劫持)
 *   - Run / RunOnce / RunOnceEx (自启动)
 *   - Winlogon / AppInit_DLLs (登录劫持)
 *   - LSA / Security Packages (认证劫持)
 *   - Services (服务劫持，含通配符)
 *   - Shell Extensions / BHO (Shell 劫持)
 *   - Print Monitors (打印驱动劫持)
 *   - Session Manager (会话劫持)
 *   - Active Setup (活动安装劫持)
 *   - Svchost / Drivers32 (服务宿主/驱动劫持)
 *   - Accessibility (辅助功能劫持)
 *   - 以及其他常见持久化/劫持路径
 * ══════════════════════════════════════════════════════════════════════════ */

/* 关键注册表键路径列表（内核格式 \REGISTRY\MACHINE = HKLM, \REGISTRY\USER = HKCU）
 * 覆盖常见的持久化、劫持路径，用于检测注册表合并攻击。
 * 注意：使用静态编译期常量字符串数组，避免运行时函数（wcslen/wcsrchr）
 * 在静态初始化器中被调用导致 C2099 错误。 */
static const PCWSTR g_RegMergeProtectedPaths[] = {
    /* ── HKLM 持久化路径 ── */
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Active Setup\\Installed Components",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths",

    /* ── Winlogon / 登录劫持 ── */
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Taskman",

    /* ── LSA / 认证劫持 ── */
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders",

    /* ── 服务 / 驱动劫持 ── */
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32",

    /* ── Shell 劫持 ── */
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions\\Approved",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Extensions",

    /* ── 会话管理器 / 打印驱动 ── */
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors",

    /* ── 辅助功能劫持 ── */
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Configuration",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\ATs",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Accessibility\\Utility Manager",

    /* ── 系统策略 ── */
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\System",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy",

    /* ── 网络 / 协议劫持 ── */
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order",
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures",

    /* ── WMI 持久化 ── */
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Wbem\\Scripting",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Wbem\\CIMOM",

    /* ── 时间提供者 / DLL 劫持 ── */
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones",

    /* ── 凭据 / 认证 ── */
    L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Provider Filters",
    L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\PLAP Providers",

    /* ── HKCU 持久化路径 ── */
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winlogon\\Shell",

    /* ── HKCU Windows NT 持久化路径（对应 HKLM 同名路径）── */
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify",
    L"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
};

static const ULONG g_RegMergeProtectedCount = ARRAYSIZE(g_RegMergeProtectedPaths);

/* ── IsRegistryMergeAttack: 检测注册表合并攻击 ──
 *
 * 在 RegNtRenameKey 操作中，检查正在被重命名的键的新名称是否与
 * 预定义的关键注册表键名相同且在同一父键下，若是则判定为合并攻击。
 *
 * 两阶段匹配：
 *   1. 快速键名比较：NewName 与每个关键条目的 KeyName 比较（O(1) per entry）
 *   2. 完整路径验证：仅键名匹配时，获取当前键的父路径，构造新完整路径
 *      （父路径 + "\\" + NewName），与关键条目的 FullPath 做通配符匹配。
 *      通配符 * 用于 HKCU 路径中的用户 SID 占位。
 *
 * 参数：
 *   KeyObject    - 正在被重命名的键对象
 *   NewName      - 新的键名（UNICODE_STRING）
 *   pFullKeyPath - (可选输出) 合并攻击目标路径，调用者需 FreeRegistryKeyPath 释放
 *
 * 返回：TRUE = 检测到合并攻击，FALSE = 安全 */
BOOLEAN IsRegistryMergeAttack(
    _In_ PVOID KeyObject,
    _In_ PUNICODE_STRING NewName,
    _Out_opt_ PUNICODE_STRING* pFullKeyPath)
{
    ULONG i;
    PUNICODE_STRING keyPath = NULL;
    NTSTATUS status;

    if (KeyObject == NULL || NewName == NULL || NewName->Buffer == NULL || NewName->Length == 0)
        return FALSE;

    if (pFullKeyPath)
        *pFullKeyPath = NULL;

    /* 阶段1：快速键名匹配（仅比较 NewName 和关键键名，无需分配/查询路径） */
    for (i = 0; i < g_RegMergeProtectedCount; i++)
    {
        PCWSTR fullPath = g_RegMergeProtectedPaths[i];
        PCWSTR keyName;
        USHORT keyNameBytes;

        /* 从完整路径中提取键名（最后一个 '\\' 之后的部分） */
        {
            PCWSTR lastSlash = wcsrchr(fullPath, L'\\');
            if (lastSlash == NULL)
                continue;
            keyName = lastSlash + 1;
            keyNameBytes = (USHORT)(wcslen(keyName) * sizeof(WCHAR));
        }

        /* 比较键名长度：长度不同直接跳过 */
        if (NewName->Length != keyNameBytes)
            continue;

        /* 大小写不敏感比较键名 */
        {
            UNICODE_STRING usNewName;
            UNICODE_STRING usEntryName;
            usNewName.Buffer = NewName->Buffer;
            usNewName.Length = NewName->Length;
            usNewName.MaximumLength = NewName->MaximumLength;
            RtlInitUnicodeString(&usEntryName, keyName);
            if (!RtlEqualUnicodeString(&usNewName, &usEntryName, TRUE))
                continue;
        }

        /* 阶段2：键名匹配 → 获取父路径，构造新完整路径，与关键条目做通配符匹配 */
        if (keyPath == NULL)
        {
            status = GetRegistryKeyPath(KeyObject, &keyPath);
            if (!NT_SUCCESS(status) || keyPath == NULL)
                return FALSE;
        }

        /* 从当前键路径中提取父路径：去掉最后一个 '\\' 及之后的键名 */
        {
            PWCHAR lastSlash = NULL;
            USHORT parentLen;
            USHORT newPathLen;
            PWCHAR newPathBuf = NULL;
            BOOLEAN isMatch = FALSE;

            /* 反向查找最后一个 '\\' */
            {
                LONG idx = (LONG)(keyPath->Length / sizeof(WCHAR)) - 1;
                while (idx >= 0)
                {
                    if (keyPath->Buffer[idx] == L'\\')
                    {
                        lastSlash = &keyPath->Buffer[idx];
                        break;
                    }
                    idx--;
                }
            }

            if (lastSlash == NULL)
                continue;

            parentLen = (USHORT)((PUCHAR)lastSlash - (PUCHAR)keyPath->Buffer);

            /* 构造新完整路径：父路径 + "\\" + NewName */
            newPathLen = parentLen + sizeof(WCHAR) + NewName->Length;
            newPathBuf = (PWCHAR)ExAllocatePool2(
                POOL_FLAG_NON_PAGED,
                newPathLen + sizeof(WCHAR), /* +null terminator */
                'RegM');

            if (newPathBuf == NULL)
                continue;

            RtlCopyMemory(newPathBuf, keyPath->Buffer, parentLen);
            newPathBuf[parentLen / sizeof(WCHAR)] = L'\\';
            RtlCopyMemory(
                &newPathBuf[parentLen / sizeof(WCHAR) + 1],
                NewName->Buffer,
                NewName->Length);
            newPathBuf[newPathLen / sizeof(WCHAR)] = L'\0';

            /* 通配符匹配：HKLM 路径精确匹配，HKCU 路径含 * 通配用户 SID */
            isMatch = WildcardMatch(fullPath, newPathBuf);

            if (isMatch)
            {
                /* 合并攻击！构造输出路径 */
                if (pFullKeyPath)
                {
                    PUNICODE_STRING outPath = (PUNICODE_STRING)ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(UNICODE_STRING) + newPathLen + sizeof(WCHAR),
                        'RegM');
                    if (outPath)
                    {
                        RtlZeroMemory(outPath, sizeof(UNICODE_STRING) + newPathLen + sizeof(WCHAR));
                        outPath->Buffer = (PWSTR)((PUCHAR)outPath + sizeof(UNICODE_STRING));
                        outPath->Length = newPathLen;
                        outPath->MaximumLength = newPathLen + sizeof(WCHAR);
                        RtlCopyMemory(outPath->Buffer, newPathBuf, newPathLen);
                        *pFullKeyPath = outPath;
                    }
                }

                ExFreePool(newPathBuf);
                FreeRegistryKeyPath(keyPath);
                return TRUE;
            }

            ExFreePool(newPathBuf);
        }
    }

    if (keyPath)
        FreeRegistryKeyPath(keyPath);

    return FALSE;
}

// ----------------------------------------------------------------------------
// SYSTEM SID cache for IsSystemProcess check
// ----------------------------------------------------------------------------
static UCHAR g_SystemSidBuffer[sizeof(SID) + sizeof(ULONG)];
static PSID g_SystemSid = NULL;

VOID InitSystemProcessCheck()
{
    SID* sid = (SID*)g_SystemSidBuffer;
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 1;
    sid->IdentifierAuthority.Value[0] = 0;
    sid->IdentifierAuthority.Value[1] = 0;
    sid->IdentifierAuthority.Value[2] = 0;
    sid->IdentifierAuthority.Value[3] = 0;
    sid->IdentifierAuthority.Value[4] = 0;
    sid->IdentifierAuthority.Value[5] = 5;
    sid->SubAuthority[0] = SECURITY_LOCAL_SYSTEM_RID;
    g_SystemSid = (PSID)sid;
}

BOOLEAN IsSystemProcess()
{
    NTSTATUS status;
    HANDLE hToken = NULL;
    BOOLEAN isSystem = FALSE;
    PTOKEN_USER tokenUser = NULL;
    ULONG returnLength;

    if (g_SystemSid == NULL) return FALSE;

    status = ZwOpenProcessTokenEx(
        NtCurrentProcess(),
        TOKEN_QUERY,
        OBJ_KERNEL_HANDLE,
        &hToken);
    if (!NT_SUCCESS(status)) return FALSE;

    __try {
        status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &returnLength);
        if (status != STATUS_BUFFER_TOO_SMALL) {
            __leave;
        }

        tokenUser = (PTOKEN_USER)ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLength, 'HtT');
        if (!tokenUser) {
            __leave;
        }

        status = ZwQueryInformationToken(hToken, TokenUser, tokenUser, returnLength, &returnLength);
        if (NT_SUCCESS(status)) {
            isSystem = RtlEqualSid(tokenUser->User.Sid, g_SystemSid);
        }
    }
    __finally {
        if (tokenUser != NULL) {
            ExFreePool(tokenUser);
        }
        ZwClose(hToken);
    }

    return isSystem;
}

// IsSystemProcessByEPROCESS - check if the given process runs under SYSTEM SID
// Used to distinguish genuine system processes from malware impersonating
// critical process names (e.g. virus naming itself "csrss.exe").
//
// 注意：本函数可能在 ObRegisterCallbacks 的 PreOperation 回调中被调用。
// 在该上下文中绝不能调用 ObOpenObjectByPointer/ZwOpenProcessTokenEx 等会
// 创建新句柄的 API，否则创建句柄会再次触发 ObRegisterCallbacks，导致
// 无限递归、栈溢出，最终引发 UNEXPECTED_KERNEL_MODE_TRAP (0x7F)。
// 这里改用 PsReferencePrimaryToken + SeQueryInformationToken，只引用已有
// Token 对象而不创建新句柄。
BOOLEAN IsSystemProcessByEPROCESS(PEPROCESS process)
{
    PACCESS_TOKEN token;
    PTOKEN_USER tokenUser = NULL;
    BOOLEAN isSystem = FALSE;
    NTSTATUS status;

    if (g_SystemSid == NULL || process == NULL) return FALSE;

    /* 引用进程主 Token（不创建句柄，避免递归） */
    token = PsReferencePrimaryToken(process);
    if (token == NULL) return FALSE;

    __try {
        /* SeQueryInformationToken 返回由它内部分配的 TokenInformation 指针，
         * 调用者负责用 ExFreePool 释放。 */
        status = SeQueryInformationToken(token, TokenUser, (PVOID*)&tokenUser);
        if (NT_SUCCESS(status) && tokenUser != NULL) {
            isSystem = RtlEqualSid(tokenUser->User.Sid, g_SystemSid);
        }
    }
    __finally {
        if (tokenUser != NULL) {
            ExFreePool(tokenUser);
        }
        PsDereferencePrimaryToken(token);
    }

    return isSystem;
}

// ----------------------------------------------------------------------------
// GetOperationFromNotifyClass - 将 REG_NOTIFY_CLASS 转换为 REG_OPERATION 枚举
// ----------------------------------------------------------------------------
REG_OPERATION GetOperationFromNotifyClass(REG_NOTIFY_CLASS NotifyClass)
{
    switch (NotifyClass)
    {
        case RegNtSetValueKey:
            return REG_OPERATION_SET;

        case RegNtDeleteValueKey:
        case RegNtDeleteKey:
            return REG_OPERATION_DELETE;

        case RegNtRenameKey:
            return REG_OPERATION_RENAME;

        case RegNtQueryValueKey:
            return REG_OPERATION_READ;

        default:
            return (REG_OPERATION)-1;
    }
}

// ----------------------------------------------------------------------------
// GetRegistryKeyPath - 使用 CmCallbackGetKeyObjectIDEx 获取完整键路径
// 返回调用者拥有的 UNICODE_STRING（通过 FreeRegistryKeyPath 释放）
// ----------------------------------------------------------------------------
NTSTATUS GetRegistryKeyPath(_In_ PVOID KeyObject, _Out_ PUNICODE_STRING* KeyPath)
{
    NTSTATUS status;
    PCUNICODE_STRING sourceName = NULL;
    PUNICODE_STRING keyPathBuf;
    USHORT allocSize;

    if (KeyObject == NULL || KeyPath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    *KeyPath = NULL;

    // 获取系统管理的键路径名
    status = CmCallbackGetKeyObjectIDEx(&g_RegCookie, KeyObject, NULL, &sourceName, 0);
    if (!NT_SUCCESS(status))
    {
        DriverDbgPrint("CmCallbackGetKeyObjectIDEx failed: 0x%X\n", status);
        return status;
    }

    if (sourceName == NULL || sourceName->Buffer == NULL)
    {
        if (sourceName != NULL)
        {
            CmCallbackReleaseKeyObjectIDEx(sourceName);
        }
        return STATUS_UNSUCCESSFUL;
    }

    // USHORT 溢出检查：Length + sizeof(WCHAR) 必须能放入 UNICODE_STRING 的 MaximumLength
    if (sourceName->Length > ((USHORT)(-1) - sizeof(WCHAR)))
    {
        CmCallbackReleaseKeyObjectIDEx(sourceName);
        return STATUS_NAME_TOO_LONG;
    }
    allocSize = sourceName->Length + (USHORT)sizeof(WCHAR);

    // 分配 UNICODE_STRING + 字符串缓冲区（连续内存）
    keyPathBuf = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED,
        sizeof(UNICODE_STRING) + allocSize, 'REGK');
    if (keyPathBuf == NULL)
    {
        CmCallbackReleaseKeyObjectIDEx(sourceName);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(keyPathBuf, sizeof(UNICODE_STRING) + allocSize);
    keyPathBuf->Buffer = (PWSTR)((PUCHAR)keyPathBuf + sizeof(UNICODE_STRING));
    keyPathBuf->MaximumLength = allocSize;

    RtlCopyMemory(keyPathBuf->Buffer, sourceName->Buffer, sourceName->Length);
    keyPathBuf->Length = sourceName->Length;

    // 释放系统管理的名称
    CmCallbackReleaseKeyObjectIDEx(sourceName);

    *KeyPath = keyPathBuf;
    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// FreeRegistryKeyPath - 释放由 GetRegistryKeyPath 分配的内存
// ----------------------------------------------------------------------------
VOID FreeRegistryKeyPath(_In_ PUNICODE_STRING KeyPath)
{
    if (KeyPath != NULL)
    {
        ExFreePool(KeyPath);
    }
}

// ----------------------------------------------------------------------------
// CombineKeyPathAndValueName - 拼接键路径和值名称
// 示例: \Registry\Machine\SOFTWARE\Microsoft + TestValue -> ...\TestValue
// ----------------------------------------------------------------------------
NTSTATUS CombineKeyPathAndValueName(
    _In_ PUNICODE_STRING FullKeyPath,
    _In_ PUNICODE_STRING ValueName,
    _Out_ PUNICODE_STRING OutPutPath)
{
    USHORT totalLength;
    PWCHAR buffer;
    USHORT keyPathChars;
    USHORT valueNameLength = 0;

    if (FullKeyPath == NULL || OutPutPath == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 初始化输出，使 SEH 清理路径可以安全地检查并释放 Buffer
    OutPutPath->Buffer = NULL;
    OutPutPath->Length = 0;
    OutPutPath->MaximumLength = 0;

    if (FullKeyPath->Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (ValueName != NULL && ValueName->Length > 0 && ValueName->Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    // 计算总长度：键路径 + 反斜杠 + 值名称（使用 USHORT 并检查溢出）
    totalLength = FullKeyPath->Length;
    if (ValueName != NULL && ValueName->Length > 0)
    {
        if (totalLength > ((USHORT)(-1) - sizeof(WCHAR)))
        {
            return STATUS_NAME_TOO_LONG;
        }
        totalLength += sizeof(WCHAR); // 反斜杠

        if (totalLength > ((USHORT)(-1) - ValueName->Length))
        {
            return STATUS_NAME_TOO_LONG;
        }
        totalLength += ValueName->Length;
        valueNameLength = ValueName->Length;
    }

    // 还要为尾部 null 预留空间
    if (totalLength > ((USHORT)(-1) - sizeof(WCHAR)))
    {
        return STATUS_NAME_TOO_LONG;
    }

    // 分配缓冲区（带尾部 null）
    buffer = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, totalLength + sizeof(WCHAR), 'REGC');
    if (buffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // 分配后立即赋值，使调用者的 SEH 清理能够释放该缓冲区
    OutPutPath->Buffer = buffer;
    OutPutPath->Length = totalLength;
    OutPutPath->MaximumLength = totalLength + sizeof(WCHAR);

    RtlZeroMemory(buffer, totalLength + sizeof(WCHAR));

    // 手动复制键路径
    keyPathChars = FullKeyPath->Length / sizeof(WCHAR);
    RtlCopyMemory(buffer, FullKeyPath->Buffer, FullKeyPath->Length);

    // 添加反斜杠和值名称
    if (valueNameLength > 0)
    {
        buffer[keyPathChars] = L'\\';
        RtlCopyMemory(&buffer[keyPathChars + 1], ValueName->Buffer, valueNameLength);
    }

    return STATUS_SUCCESS;
}

// ----------------------------------------------------------------------------
// RegistryProtectCallback - 主注册表回调处理函数
// ----------------------------------------------------------------------------
NTSTATUS RegistryProtectCallback(
    _In_ PVOID CallbackContext,
    _In_ PVOID Argument1,
    _In_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    REG_NOTIFY_CLASS notifyClass;
    REG_OPERATION operation;
    PVOID keyObject = NULL;
    PUNICODE_STRING valueName = NULL;
    PVOID newValueData = NULL;
    ULONG newValueSize = 0;
    ULONG valueType = 0;
    PUNICODE_STRING fullKeyPath = NULL;
    UNICODE_STRING fullPathWithValue = { 0 };
    BOOLEAN detected = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN shouldBlock = FALSE;
    int ruleId = 0;
    HANDLE processId;

    /* 注册表回调在关键路径执行，参数对象可能未完全初始化。
     * 用 SEH 包裹全部处理逻辑：一旦发生访问违规等异常，
     * 释放已分配资源并放行，避免升级为 PAGE_FAULT_IN_NONPAGED_AREA。 */
    __try {

    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    /* 重入保护：驱动自身发起的注册表访问（备份查询 / 回滚恢复）会触发回调重入，
     * 此时跳过所有记录与检测，避免污染事件日志与误报。 */
    if (g_regDriverAccessDepth > 0)
    {
        return STATUS_SUCCESS;
    }

    // 获取操作类型
    operation = GetOperationFromNotifyClass(notifyClass);
    if ((INT)operation == -1)
    {
        return STATUS_SUCCESS;
    }

    // 根据通知类型提取参数
    switch (notifyClass)
    {
        case RegNtSetValueKey:
        {
            REG_SET_VALUE_KEY_INFORMATION* setInfo = (REG_SET_VALUE_KEY_INFORMATION*)Argument2;
            keyObject = setInfo->Object;
            valueName = setInfo->ValueName;
            newValueData = setInfo->Data;
            newValueSize = setInfo->DataSize;
            valueType = setInfo->Type;
            break;
        }

        case RegNtDeleteValueKey:
        {
            REG_DELETE_VALUE_KEY_INFORMATION* delInfo = (REG_DELETE_VALUE_KEY_INFORMATION*)Argument2;
            keyObject = delInfo->Object;
            valueName = delInfo->ValueName;
            break;
        }

        case RegNtDeleteKey:
        {
            REG_DELETE_KEY_INFORMATION* delKeyInfo = (REG_DELETE_KEY_INFORMATION*)Argument2;
            keyObject = delKeyInfo->Object;
            valueName = NULL;
            break;
        }

        case RegNtRenameKey:
        {
            REG_RENAME_KEY_INFORMATION* renameInfo = (REG_RENAME_KEY_INFORMATION*)Argument2;
            keyObject = renameInfo->Object;
            valueName = renameInfo->NewName;

            /* 注册表合并防护：检测是否有程序试图将其他键重命名为关键键名。
             * 攻击者先创建恶意键，再通过 RegRenameKey 将其重命名为关键键名，
             * 从而绕过常规的创建/写入监控。在父键下检测 rename 目标是否为受保护键名。 */
            {
                PUNICODE_STRING mergeTargetPath = NULL;
                if (IsRegistryMergeAttack(keyObject, valueName, &mergeTargetPath))
                {
                    HANDLE pid = PsGetCurrentProcessId();
                    CHAR procNameStr[16] = { 0 };
                    UCHAR* rawProcName = PsGetProcessImageFileName(PsGetCurrentProcess());
                    if (rawProcName) {
                        ULONG i;
                        for (i = 0; i < 15 && rawProcName[i]; i++)
                            procNameStr[i] = (CHAR)rawProcName[i];
                        procNameStr[i] = '\0';
                    }

                    DriverDbgPrint("[REG-MERGE] Registry merge attack detected! PID=%lu, Process=%s, Target=%wZ\n",
                        (ULONG)(ULONG_PTR)pid,
                        procNameStr[0] ? procNameStr : "Unknown",
                        mergeTargetPath);

                    if (mergeTargetPath)
                        FreeRegistryKeyPath(mergeTargetPath);

                    return STATUS_ACCESS_DENIED;
                }
            }
            break;
        }

        case RegNtQueryValueKey:
        {
            REG_QUERY_VALUE_KEY_INFORMATION* queryInfo = (REG_QUERY_VALUE_KEY_INFORMATION*)Argument2;
            keyObject = queryInfo->Object;
            valueName = queryInfo->ValueName;
            break;
        }

        default:
            return STATUS_SUCCESS;
    }

    if (keyObject == NULL)
    {
        return STATUS_SUCCESS;
    }

    // 获取完整键路径
    status = GetRegistryKeyPath(keyObject, &fullKeyPath);
    if (!NT_SUCCESS(status) || fullKeyPath == NULL)
    {
        DriverDbgPrint("GetRegistryKeyPath failed: 0x%X\n", status);
        return STATUS_SUCCESS;
    }

    // 拼接完整路径（含值名称）
    if (valueName != NULL && valueName->Length > 0)
    {
        status = CombineKeyPathAndValueName(fullKeyPath, valueName, &fullPathWithValue);
        if (!NT_SUCCESS(status))
        {
            DriverDbgPrint("CombineKeyPathAndValueName failed: 0x%X\n", status);
            FreeRegistryKeyPath(fullKeyPath);
            return STATUS_SUCCESS;
        }
    }
    else
    {
        // 没有值名称，直接使用键路径
        fullPathWithValue = *fullKeyPath;
    }

    // 规则检测
    detected = DetectRegPath(Argument2, notifyClass, fullKeyPath, valueName, operation, &ruleId);
    shouldBlock = detected;  // 规则匹配意味着应该阻止

    // ── 动态行为分析：记录注册表事件 ──
    {
        INT64 pid;
        CHAR imageName[64];
        CHAR regPathAnsi[BA_MAX_PATH];
        CHAR regValueAnsi[BA_MAX_NAME];
        UCHAR* procName;
        int i;

        pid = (INT64)(ULONG_PTR)PsGetCurrentProcessId();
        procName = PsGetProcessImageFileName(PsGetCurrentProcess());
        if (procName) {
            for (i = 0; i < 15 && procName[i]; i++) imageName[i] = (CHAR)procName[i];
            imageName[i] = '\0';
        } else {
            imageName[0] = '\0';
        }

        /* 将注册表路径转为 ANSI */
        {
            int wlen = (int)(fullPathWithValue.Length / sizeof(WCHAR));
            if (wlen >= BA_MAX_PATH) wlen = BA_MAX_PATH - 1;
            for (i = 0; i < wlen; i++) {
                regPathAnsi[i] = (CHAR)(fullPathWithValue.Buffer[i]);
            }
            regPathAnsi[wlen] = '\0';
        }

        /* 将值名称转为 ANSI */
        if (valueName != NULL && valueName->Buffer != NULL && valueName->Length > 0) {
            int wlen = (int)(valueName->Length / sizeof(WCHAR));
            if (wlen >= BA_MAX_NAME) wlen = BA_MAX_NAME - 1;
            for (i = 0; i < wlen; i++) {
                regValueAnsi[i] = (CHAR)(valueName->Buffer[i]);
            }
            regValueAnsi[wlen] = '\0';
        } else {
            regValueAnsi[0] = '\0';
        }

        /* 映射操作类型 */
        BA_REG_OP baOp;
        switch (operation) {
            case REG_OPERATION_SET:    baOp = BA_ROP_SetValue; break;
            case REG_OPERATION_DELETE: baOp = BA_ROP_DeleteValue; break;
            case REG_OPERATION_RENAME: baOp = BA_ROP_SetValue; break;
            case REG_OPERATION_READ:   baOp = BA_ROP_QueryValue; break;  /* VM/RDP 探测检测 */
            default:                   baOp = BA_ROP_SetValue; break;
        }

        BehaviorRecordRegistryEvent(pid, imageName, regPathAnsi, regValueAnsi, baOp);

        /* 注册表操作回滚备份：在 pre-callback 中备份 SetValue/DeleteValue 修改前的原始值，
         * 供用户选择 Block 时 BehaviorRollbackChain 恢复/删除。DeleteKey/Rename/Query 不备份。
         * 注意：根据 notifyClass 精确区分 DeleteValue 与 DeleteKey（GetOperationFromNotifyClass
         * 将二者合并为 REG_OPERATION_DELETE，无法区分）。 */
        {
            BA_REG_OP backupOp = BA_ROP_SetValue;
            BOOLEAN doBackup = FALSE;
            switch (notifyClass) {
                case RegNtSetValueKey:     backupOp = BA_ROP_SetValue;    doBackup = TRUE; break;
                case RegNtDeleteValueKey:  backupOp = BA_ROP_DeleteValue; doBackup = TRUE; break;
                default: break;  /* RegNtDeleteKey / RegNtRenameKey / RegNtQueryValueKey 不备份 */
            }
            if (doBackup && fullKeyPath != NULL) {
                BehaviorRecordRegOpWithBackup(pid, imageName,
                    fullKeyPath, valueName, backupOp);
            }
        }
    }

    if (!detected)
    {
        // 没有匹配规则，释放资源，放行
        if (fullPathWithValue.Buffer != NULL && fullPathWithValue.Buffer != fullKeyPath->Buffer)
        {
            ExFreePool(fullPathWithValue.Buffer);
        }
        FreeRegistryKeyPath(fullKeyPath);
        return STATUS_SUCCESS;
    }

    // 规则匹配
    processId = PsGetCurrentProcessId();

    DriverDbgPrint("Registry protection: Rule matched RuleId=%d, Operation=%d, Path=%wZ\n",
        ruleId, operation, &fullPathWithValue);

    /* Check SEcurity Flag: skip system processes for SEF_NOT_SYSTEM_BLOCKED */
    {
        SECURITY_FLAG sef = SEF_ALL_BLOCKED;
        for (ULONG i = 0; i < g_RuleCount; i++) {
            if (g_Rules[i].rt == RULE_TYPE_REG && g_Rules[i].RuleId == (ULONG)ruleId) {
                sef = g_Rules[i].sef;
                break;
            }
        }

        if (sef != SEF_ALL_BLOCKED && IsSystemProcess()) {
            DriverDbgPrint("Registry protection: System process, skipped (sef=%d)\n", sef);
            if (fullPathWithValue.Buffer != NULL && fullPathWithValue.Buffer != fullKeyPath->Buffer)
                ExFreePool(fullPathWithValue.Buffer);
            FreeRegistryKeyPath(fullKeyPath);
            return STATUS_SUCCESS;
        }
    }

    // 对于 SET 和 RENAME 操作，查询用户态
    if (operation == REG_OPERATION_SET || operation == REG_OPERATION_RENAME)
    {
        status = AskClientForResponse(
            ruleId,
            RULE_TYPE_REG,
            (int)(ULONG_PTR)processId,
            &fullPathWithValue,
            valueName,
            newValueData,
            newValueSize,
            valueType);

        // 如果用户态返回拒绝，则阻止
        if (!NT_SUCCESS(status) || status == STATUS_ACCESS_DENIED)
        {
            shouldBlock = TRUE;
        }
        else
        {
            shouldBlock = FALSE;
        }
    }
    else
    {
        // 其他操作：直接阻止
        DriverDbgPrint("Registry protection: Directly blocking operation Path=%wZ\n", &fullPathWithValue);
        shouldBlock = TRUE;
    }

    // 释放资源
    if (fullPathWithValue.Buffer != NULL && fullPathWithValue.Buffer != fullKeyPath->Buffer)
    {
        ExFreePool(fullPathWithValue.Buffer);
    }
    FreeRegistryKeyPath(fullKeyPath);

    if (shouldBlock)
    {
        DriverDbgPrint("Registry protection: Operation blocked, returning STATUS_ACCESS_DENIED\n");
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DriverDbgPrint("[REGISTRY] Exception caught in RegistryProtectCallback, allowing\n");

        /* 尽最大努力释放已分配资源，避免异常路径内存泄漏 */
        if (fullKeyPath != NULL)
        {
            if (fullPathWithValue.Buffer != NULL && fullPathWithValue.Buffer != fullKeyPath->Buffer)
            {
                ExFreePool(fullPathWithValue.Buffer);
            }
            FreeRegistryKeyPath(fullKeyPath);
        }
        else if (fullPathWithValue.Buffer != NULL)
        {
            ExFreePool(fullPathWithValue.Buffer);
        }

        return STATUS_SUCCESS;
    }
}