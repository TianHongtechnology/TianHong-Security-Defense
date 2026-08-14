#include "Comm.h"
#include "ConsoleOutput.h"
#include <cstdio>
#include <cstring>

HANDLE CommOpenDevice()
{
    HANDLE hDevice = CreateFileW(
        L"\\\\.\\TianHongHips",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        PrintFailure("[-] CommOpenDevice: 无法打开设备 \\\\.\\TianHongHips (错误码: %lu)", GetLastError());
        return NULL;
    }

    PrintSuccess("[+] CommOpenDevice: 成功打开设备 \\\\.\\TianHongHips");
    return hDevice;
}

VOID CommCloseDevice(HANDLE hDevice)
{
    if (hDevice == NULL || hDevice == INVALID_HANDLE_VALUE)
    {
        PrintFailure("[-] CommCloseDevice: 无效的设备句柄");
        return;
    }

    if (CloseHandle(hDevice))
    {
        PrintSuccess("[+] CommCloseDevice: 设备已关闭");
    }
    else
    {
        PrintFailure("[-] CommCloseDevice: 关闭设备失败 (错误码: %lu)", GetLastError());
    }
}

BOOL CommSendIoctl(HANDLE hDevice, DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned)
{
    if (hDevice == NULL || hDevice == INVALID_HANDLE_VALUE)
    {
        PrintFailure("[-] CommSendIoctl: 无效的设备句柄 (IOCTL: 0x%08X)", ioctlCode);
        return FALSE;
    }

    DWORD dwBytesReturned = 0;
    BOOL result = DeviceIoControl(
        hDevice,
        ioctlCode,
        inBuffer,
        inSize,
        outBuffer,
        outSize,
        &dwBytesReturned,
        NULL
    );

    if (bytesReturned != NULL)
    {
        *bytesReturned = dwBytesReturned;
    }

    if (!result)
    {
        PrintFailure("[-] CommSendIoctl: DeviceIoControl 失败 (IOCTL: 0x%08X, 错误码: %lu)", ioctlCode, GetLastError());
    }
    else
    {
        PrintSuccess("[+] CommSendIoctl: DeviceIoControl 成功 (IOCTL: 0x%08X, 返回字节: %lu)", ioctlCode, dwBytesReturned);
    }

    return result;
}

BOOL CommSendRule(HANDLE hDevice, RULE_DATA* rule)
{
    if (rule == NULL)
    {
        PrintFailure("[-] CommSendRule: rule 参数为空");
        return FALSE;
    }

    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_ADD_RULE;
    memcpy(packet.Data, rule, sizeof(RULE_DATA));

    PrintInfo("[*] CommSendRule: 发送规则 RuleId=%lu", rule->RuleId);

    return CommSendIoctl(hDevice, IOCTL_ADD_RULE, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommProtectProcess(HANDLE hDevice, ULONG pid)
{
    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_PROTECT_PROCESS;
    memcpy(packet.Data, &pid, sizeof(ULONG));

    PrintInfo("[*] CommProtectProcess: 保护进程 PID=%lu", pid);

    return CommSendIoctl(hDevice, IOCTL_PROTECT_PROCESS, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommAddFileRule(HANDLE hDevice, RULE_FILE_DATA* rule)
{
    if (rule == NULL)
    {
        PrintFailure("[-] CommAddFileRule: rule 参数为空");
        return FALSE;
    }

    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_ADD_FILE_RULE;
    memcpy(packet.Data, rule, sizeof(RULE_FILE_DATA));

    PrintInfo("[*] CommAddFileRule: 添加文件规则 RuleId=%lu, Path=%s", rule->RuleId, rule->FullPath);

    return CommSendIoctl(hDevice, IOCTL_ADD_FILE_RULE, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommRemoveFileRule(HANDLE hDevice, ULONG ruleId)
{
    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_REMOVE_FILE_RULE;
    memcpy(packet.Data, &ruleId, sizeof(ULONG));

    PrintInfo("[*] CommRemoveFileRule: 移除文件规则 RuleId=%lu", ruleId);

    return CommSendIoctl(hDevice, IOCTL_REMOVE_FILE_RULE, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommClearFileRules(HANDLE hDevice)
{
    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_CLEAR_FILE_RULES;

    PrintInfo("[*] CommClearFileRules: 清除所有文件规则");

    return CommSendIoctl(hDevice, IOCTL_CLEAR_FILE_RULES, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommRemoveRule(HANDLE hDevice, ULONG ruleId)
{
    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_REMOVE_RULE;
    memcpy(packet.Data, &ruleId, sizeof(ULONG));

    PrintInfo("[*] CommRemoveRule: 移除注册表规则 RuleId=%lu", ruleId);

    return CommSendIoctl(hDevice, IOCTL_REMOVE_RULE, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommClearRules(HANDLE hDevice)
{
    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_CLEAR_RULES;

    PrintInfo("[*] CommClearRules: 清除所有注册表规则");

    return CommSendIoctl(hDevice, IOCTL_CLEAR_RULES, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommGetFileRuleStats(HANDLE hDevice, FILE_RULE_STATS* stats)
{
    if (stats == NULL)
    {
        PrintFailure("[-] CommGetFileRuleStats: stats 参数为空");
        return FALSE;
    }

    ZeroMemory(stats, sizeof(FILE_RULE_STATS));
    DWORD bytesReturned = 0;

    PrintInfo("[*] CommGetFileRuleStats: 获取文件规则统计");

    BOOL result = CommSendIoctl(hDevice, IOCTL_GET_FILE_RULE_STATS, NULL, 0, stats, sizeof(FILE_RULE_STATS), &bytesReturned);

    if (result)
    {
        PrintSuccess("[+] CommGetFileRuleStats: 总数=%lu, 活跃=%lu, 已阻止=%lu, 已允许=%lu",
            stats->TotalRules, stats->ActiveRules, stats->BlockedOperations, stats->AllowedOperations);
    }

    return result;
}

BOOL CommPollDetectedEvent(HANDLE hDevice, COMM_RESPONSE_PACKET* response)
{
    if (response == NULL)
    {
        PrintFailure("[-] CommPollDetectedEvent: response 参数为空");
        return FALSE;
    }

    ZeroMemory(response, sizeof(COMM_RESPONSE_PACKET));
    DWORD bytesReturned = 0;

    BOOL result = CommSendIoctl(hDevice, IOCTL_RULE_DETECTED_REQUEST, NULL, 0, response, sizeof(COMM_RESPONSE_PACKET), &bytesReturned);

    if (result)
    {
        PrintSuccess("[+] CommPollDetectedEvent: 检测到事件, Type=%d", response->Type);
    }
    else
    {
        PrintFailure("[-] CommPollDetectedEvent: 未检测到事件或轮询失败");
    }

    return result;
}

BOOL CommSendUserResponse(HANDLE hDevice, NTSTATUS result, const char* message)
{
    COMM_RESPONSE_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = RESPONSE_RESULT;

    COMM_RESPONSE_RESULT* pResult = (COMM_RESPONSE_RESULT*)packet.Data;
    pResult->nts = result;
    if (message != NULL)
    {
        strncpy_s(pResult->Data, sizeof(pResult->Data), message, _TRUNCATE);
    }

    PrintInfo("[*] CommSendUserResponse: 发送用户响应, NTSTATUS=0x%08X, 消息=%s",
        result, (message != NULL) ? message : "(null)");

    return CommSendIoctl(hDevice, IOCTL_RULE_DETECTED_SEND_USER_RESPONSE, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommSetResponseCache(HANDLE hDevice, ULONG cmd)
{
    COMM_CONTROL_PACKET packet;
    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_PROTECT_PROCESS;  // Type field unused for this IOCTL
    *(PULONG)packet.Data = cmd;

    const char* cmdStr = (cmd == 0) ? "disable" : (cmd == 1) ? "enable" : "clear";
    PrintInfo("[*] CommSetResponseCache: 设置响应缓存 %s", cmdStr);

    return CommSendIoctl(hDevice, IOCTL_SET_RESPONSE_CACHE, &packet, sizeof(packet), NULL, 0, NULL);
}

BOOL CommSetFullScanMode(HANDLE hDevice, BOOL enable)
{
    PrintInfo("[*] CommSetFullScanMode: 完整扫描模式 %s", enable ? "启用" : "禁用");

    return CommSendIoctl(hDevice, IOCTL_SET_UNSIGNED_DLL_SCAN, (LPVOID)&enable, sizeof(BOOL), NULL, 0, NULL);
}

BOOL CommSetUnsignedDllScan(HANDLE hDevice, BOOL enable, BOOL blocking)
{
    PrintInfo("[*] CommSetUnsignedDllScan: 未签名DLL扫描 %s, 阻塞模式=%s",
        enable ? "启用" : "禁用", blocking ? "是" : "否");

    BOOLEAN settings[2] = { (BOOLEAN)enable, (BOOLEAN)blocking };
    return CommSendIoctl(hDevice, IOCTL_SET_UNSIGNED_DLL_SCAN, settings, sizeof(settings), NULL, 0, NULL);
}

BOOL CommSetBehaviorDetection(HANDLE hDevice, BOOL enable)
{
    PrintInfo("[*] CommSetBehaviorDetection: 行为检测 %s", enable ? "启用" : "禁用");

    BOOLEAN bEnable = (BOOLEAN)enable;
    return CommSendIoctl(hDevice, IOCTL_SET_BEHAVIOR_DETECTION_ENABLED, &bEnable, sizeof(BOOLEAN), NULL, 0, NULL);
}

BOOL CommSetR3Protection(HANDLE hDevice, BOOL enable)
{
    PrintInfo("[*] CommSetR3Protection: R3 DLL防护注入 %s", enable ? "启用" : "禁用");

    BOOLEAN bEnable = (BOOLEAN)enable;
    return CommSendIoctl(hDevice, IOCTL_SET_R3_PROTECTION_ENABLED, &bEnable, sizeof(BOOLEAN), NULL, 0, NULL);
}

BOOL CommSetDcomProtection(HANDLE hDevice, BOOL bEnable)
{
    return CommSendIoctl(hDevice, IOCTL_SET_DCOM_PROTECTION_ENABLED, &bEnable, sizeof(BOOLEAN), NULL, 0, NULL);
}

BOOL CommSetProcessProtection(HANDLE hDevice, BOOL enable)
{
    PrintInfo("[*] CommSetProcessProtection: 进程保护 %s", enable ? "启用" : "禁用");

    BOOLEAN bEnable = (BOOLEAN)enable;
    return CommSendIoctl(hDevice, IOCTL_SET_PROCESS_PROTECTION_ENABLED, &bEnable, sizeof(BOOLEAN), NULL, 0, NULL);
}

BOOL CommClearProtectedPids(HANDLE hDevice)
{
    PrintInfo("[*] CommClearProtectedPids: 清除所有受保护 PID");

    return CommSendIoctl(hDevice, IOCTL_CLEAR_PROTECTED_PIDS, NULL, 0, NULL, 0, NULL);
}

BOOL CommBehaviorEvaluate(HANDLE hDevice, BA_THREAT_RESULT* results, INT maxResults, INT* outCount)
{
    COMM_CONTROL_PACKET packet;
    COMM_CONTROL_PACKET outPacket;
    DWORD bytesReturned = 0;
    INT i;
    CHAR* src;

    if (results == NULL || outCount == NULL)
    {
        PrintFailure("[-] CommBehaviorEvaluate: 参数为空");
        return FALSE;
    }

    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_GENERIC;

    ZeroMemory(&outPacket, sizeof(outPacket));

    BOOL result = CommSendIoctl(hDevice, IOCTL_BEHAVIOR_ANALYSIS_EVALUATE,
        &packet, sizeof(packet), &outPacket, sizeof(outPacket), &bytesReturned);

    if (!result)
    {
        PrintFailure("[-] CommBehaviorEvaluate: IOCTL 失败");
        return FALSE;
    }

    /* 解析返回数据: 前4字节=结果数量，后面跟多个 BA_THREAT_RESULT */
    src = outPacket.Data;
    *outCount = *(PINT)src;
    src += sizeof(INT);

    /* 安全限制: 不超过调用方缓冲区、不超过内核实际写入的数量 */
    if (*outCount > maxResults) *outCount = maxResults;

    for (i = 0; i < *outCount; i++) {
        /* 边界检查: 确保 src 不超过 outPacket.Data 边界 */
        INT consumed = (INT)(src - outPacket.Data) + (INT)sizeof(BA_THREAT_RESULT);
        if (consumed > (INT)sizeof(outPacket.Data)) {
            *outCount = i;
            break;
        }
        RtlCopyMemory(&results[i], src, sizeof(BA_THREAT_RESULT));
        src += sizeof(BA_THREAT_RESULT);
    }

    PrintSuccess("[+] CommBehaviorEvaluate: 扫描完成，发现 %d 个威胁", *outCount);

    return TRUE;
}

BOOL CommBehaviorGetStats(HANDLE hDevice, BA_STATS* stats)
{
    COMM_CONTROL_PACKET packet;
    COMM_CONTROL_PACKET outPacket;
    DWORD bytesReturned = 0;

    if (stats == NULL)
    {
        PrintFailure("[-] CommBehaviorGetStats: 参数为空");
        return FALSE;
    }

    ZeroMemory(&packet, sizeof(packet));
    packet.Type = PACKET_TYPE_GENERIC;

    ZeroMemory(&outPacket, sizeof(outPacket));

    BOOL result = CommSendIoctl(hDevice, IOCTL_BEHAVIOR_ANALYSIS_GET_STATS,
        &packet, sizeof(packet), &outPacket, sizeof(outPacket), &bytesReturned);

    if (!result)
    {
        PrintFailure("[-] CommBehaviorGetStats: IOCTL 失败");
        return FALSE;
    }

    RtlCopyMemory(stats, outPacket.Data, sizeof(BA_STATS));

    PrintSuccess("[+] CommBehaviorGetStats: 进程=%d, 历史事件=%d, 指标=%d, 时间戳=%lld",
        stats->processCount, stats->historyCount, stats->indicatorCount, stats->tickCounter);

    return TRUE;
}

BOOL CommBehaviorClear(HANDLE hDevice)
{
    PrintInfo("[*] CommBehaviorClear: 清除所有行为分析数据");

    return CommSendIoctl(hDevice, IOCTL_BEHAVIOR_ANALYSIS_CLEAR,
        NULL, 0, NULL, 0, NULL);
}

// ── 动态规则相关函数 ──
BOOL CommLoadDynamicRule(HANDLE hDevice, BA_DYNAMIC_RULE_LOAD_REQ* req)
{
    PrintInfo("[*] CommLoadDynamicRule: 加载动态规则 RuleId=%lu", req->Rule.RuleId);

    DWORD bytesReturned = 0;
    return CommSendIoctl(hDevice, IOCTL_BA_LOAD_DYNAMIC_RULE,
        req, sizeof(BA_DYNAMIC_RULE_LOAD_REQ), NULL, 0, &bytesReturned);
}

BOOL CommRemoveDynamicRule(HANDLE hDevice, ULONG ruleId)
{
    BA_DYNAMIC_RULE_REMOVE_REQ req = { ruleId };
    PrintInfo("[*] CommRemoveDynamicRule: 移除动态规则 RuleId=%lu", ruleId);

    DWORD bytesReturned = 0;
    return CommSendIoctl(hDevice, IOCTL_BA_REMOVE_DYNAMIC_RULE,
        &req, sizeof(BA_DYNAMIC_RULE_REMOVE_REQ), NULL, 0, &bytesReturned);
}

BOOL CommClearDynamicRules(HANDLE hDevice)
{
    PrintInfo("[*] CommClearDynamicRules: 清除所有动态规则");

    DWORD bytesReturned = 0;
    return CommSendIoctl(hDevice, IOCTL_BA_CLEAR_DYNAMIC_RULES,
        NULL, 0, NULL, 0, &bytesReturned);
}

BOOL CommGetDynamicRuleVersion(HANDLE hDevice, ULONG* pVersion)
{
    PrintInfo("[*] CommGetDynamicRuleVersion: 查询规则版本");

    DWORD bytesReturned = 0;
    return CommSendIoctl(hDevice, IOCTL_BA_GET_DYNAMIC_RULE_VERSION,
        NULL, 0, pVersion, sizeof(ULONG), &bytesReturned);
}

BOOL CommGetDynamicRuleStats(HANDLE hDevice, std::vector<BA_RULE_STATS>& outStats)
{
    PrintInfo("[*] CommGetDynamicRuleStats: 查询规则统计");

    // 一次性获取最多 512 条规则统计
    BYTE buffer[512 * sizeof(BA_RULE_STATS) + sizeof(BA_DYNAMIC_RULE_STATS_REQ)] = {0};
    BA_DYNAMIC_RULE_STATS_REQ* pReq = (BA_DYNAMIC_RULE_STATS_REQ*)buffer;
    pReq->RuleId = 0;  // 0 = 查询全部
    BA_RULE_STATS* pStats = (BA_RULE_STATS*)(buffer + sizeof(BA_DYNAMIC_RULE_STATS_REQ));

    DWORD bytesReturned = 0;
    BOOL result = CommSendIoctl(hDevice, IOCTL_BA_GET_DYNAMIC_RULE_STATS,
        pReq, sizeof(BA_DYNAMIC_RULE_STATS_REQ), pStats, sizeof(buffer) - sizeof(BA_DYNAMIC_RULE_STATS_REQ), &bytesReturned);

    if (result && bytesReturned > 0) {
        outStats.clear();
        ULONG count = bytesReturned / sizeof(BA_RULE_STATS);
        for (ULONG i = 0; i < count && i < 512; i++) {
            outStats.push_back(pStats[i]);
        }
    }

    return result;
}

BOOL CommGetDynamicRuleList(HANDLE hDevice, std::vector<BA_DYNAMIC_RULE>& outRules)
{
    PrintInfo("[*] CommGetDynamicRuleList: 查询规则列表");

    // 一次性获取最多 512 条规则
    BYTE buffer[512 * sizeof(BA_DYNAMIC_RULE) + sizeof(BA_DYNAMIC_RULE_LIST_REQ)] = {0};
    BA_DYNAMIC_RULE_LIST_REQ* pReq = (BA_DYNAMIC_RULE_LIST_REQ*)buffer;
    pReq->Offset = 0;
    pReq->Count = 512;
    BA_DYNAMIC_RULE* pRules = (BA_DYNAMIC_RULE*)(buffer + sizeof(BA_DYNAMIC_RULE_LIST_REQ));

    DWORD bytesReturned = 0;
    BOOL result = CommSendIoctl(hDevice, IOCTL_BA_GET_DYNAMIC_RULE_LIST,
        pReq, sizeof(BA_DYNAMIC_RULE_LIST_REQ), pRules, sizeof(buffer) - sizeof(BA_DYNAMIC_RULE_LIST_REQ), &bytesReturned);

    if (result && bytesReturned > 0) {
        outRules.clear();
        ULONG count = bytesReturned / sizeof(BA_DYNAMIC_RULE);
        for (ULONG i = 0; i < count && i < 512; i++) {
            outRules.push_back(pRules[i]);
        }
    }

    return result;
}

BOOL CommReportFeedback(HANDLE hDevice, ULONG ruleId, INT64 pid, const char* imagePath, ULONG action, INT64 timestampMs)
{
    typedef struct _BA_FEEDBACK_ENTRY {
        ULONG  RuleId;
        INT64  Pid;
        CHAR   ImagePath[BA_MAX_PATH];
        ULONG  Action;
        INT64  TimestampMs;
    } BA_FEEDBACK_ENTRY;

    BA_FEEDBACK_ENTRY feedback = {0};
    feedback.RuleId = ruleId;
    feedback.Pid = pid;
    strncpy_s(feedback.ImagePath, BA_MAX_PATH, imagePath ? imagePath : "", _TRUNCATE);
    feedback.Action = action;
    feedback.TimestampMs = timestampMs;

    PrintInfo("[*] CommReportFeedback: rule=%lu pid=%lld action=%s",
             ruleId, pid, action == 1 ? "FALSE_POSITIVE" : "TRUE_POSITIVE");

    DWORD bytesReturned = 0;
    return CommSendIoctl(hDevice, IOCTL_BA_REPORT_FEEDBACK,
        &feedback, sizeof(BA_FEEDBACK_ENTRY), NULL, 0, &bytesReturned);
}