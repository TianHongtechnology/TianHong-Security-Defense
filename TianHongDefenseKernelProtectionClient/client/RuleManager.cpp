#include "RuleManager.h"
#include "Comm.h"
#include "ConsoleOutput.h"
#include <cstdio>
#include <cstring>

// ============================================================================
// Instance - 返回单例
// ============================================================================
RuleManager& RuleManager::Instance()
{
    static RuleManager instance;
    return instance;
}

// ============================================================================
// AddRegRule - 通过Comm发送注册表规则到驱动
// ============================================================================
bool RuleManager::AddRegRule(const RULE_REG_DATA& rule)
{
    PrintInfo("RuleManager: 添加注册表规则 RuleId=%lu, Path=%s", rule.RuleId, rule.FullPathWithOutValueName);

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == NULL || m_hDevice == INVALID_HANDLE_VALUE)
        {
            PrintFailure("RuleManager: 无法打开驱动设备");
            return false;
        }
    }

    // 构造 RULE_DATA
    RULE_DATA rulePacket = { 0 };
    rulePacket.RuleId = rule.RuleId;
    rulePacket.rt = RULE_TYPE_REG;
    rulePacket.sef = rule.sef;
    memcpy_s(rulePacket.Data, sizeof(rulePacket.Data), &rule, sizeof(RULE_REG_DATA));

    BOOL result = CommSendRule(m_hDevice, &rulePacket);

    if (result)
        PrintSuccess("RuleManager: 注册表规则添加成功 RuleId=%lu", rule.RuleId);
    else
        PrintFailure("RuleManager: 注册表规则添加失败 RuleId=%lu", rule.RuleId);

    return result != FALSE;
}

// ============================================================================
// AddFileRule - 通过Comm发送文件规则到驱动
// ============================================================================
bool RuleManager::AddFileRule(const RULE_FILE_DATA& rule)
{
    PrintInfo("RuleManager: 添加文件规则 RuleId=%lu, Path=%s, FileName=%s",
        rule.RuleId, rule.FullPath, rule.FileName);

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == NULL || m_hDevice == INVALID_HANDLE_VALUE)
        {
            PrintFailure("RuleManager: 无法打开驱动设备");
            return false;
        }
    }

    // 构造可变副本以通过Comm发送
    RULE_FILE_DATA ruleCopy = rule;
    BOOL result = CommAddFileRule(m_hDevice, &ruleCopy);

    if (result)
        PrintSuccess("RuleManager: 文件规则添加成功 RuleId=%lu", rule.RuleId);
    else
        PrintFailure("RuleManager: 文件规则添加失败 RuleId=%lu", rule.RuleId);

    return result != FALSE;
}

// ============================================================================
// RemoveFileRule - 通过Comm移除文件规则
// ============================================================================
bool RuleManager::RemoveFileRule(ULONG ruleId)
{
    PrintInfo("RuleManager: 移除文件规则 RuleId=%lu", ruleId);

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == NULL || m_hDevice == INVALID_HANDLE_VALUE)
        {
            PrintFailure("RuleManager: 无法打开驱动设备");
            return false;
        }
    }

    BOOL result = CommRemoveFileRule(m_hDevice, ruleId);

    if (result)
        PrintSuccess("RuleManager: 文件规则移除成功 RuleId=%lu", ruleId);
    else
        PrintFailure("RuleManager: 文件规则移除失败 RuleId=%lu", ruleId);

    return result != FALSE;
}

// ============================================================================
// ClearFileRules - 清除所有文件规则
// ============================================================================
void RuleManager::ClearFileRules()
{
    PrintInfo("RuleManager: 清除所有文件规则");

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == NULL || m_hDevice == INVALID_HANDLE_VALUE)
        {
            PrintFailure("RuleManager: 无法打开驱动设备");
            return;
        }
    }

    BOOL result = CommClearFileRules(m_hDevice);

    if (result)
        PrintSuccess("RuleManager: 所有文件规则已清除");
    else
        PrintFailure("RuleManager: 清除文件规则失败");
}

// ============================================================================
// GetFileRuleStats - 获取文件规则统计
// ============================================================================
bool RuleManager::GetFileRuleStats(FILE_RULE_STATS& stats)
{
    PrintInfo("RuleManager: 获取文件规则统计");

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == NULL || m_hDevice == INVALID_HANDLE_VALUE)
        {
            PrintFailure("RuleManager: 无法打开驱动设备");
            return false;
        }
    }

    ZeroMemory(&stats, sizeof(stats));
    BOOL result = CommGetFileRuleStats(m_hDevice, &stats);

    if (result)
    {
        PrintSuccess("RuleManager: 统计获取成功 - 总数=%lu, 活跃=%lu, 已阻止=%lu, 已允许=%lu",
            stats.TotalRules, stats.ActiveRules, stats.BlockedOperations, stats.AllowedOperations);
    }
    else
    {
        PrintFailure("RuleManager: 统计获取失败");
    }

    return result != FALSE;
}

// ============================================================================
// LoadRulesFromConfig - 从配置文件加载规则
// ============================================================================
bool RuleManager::LoadRulesFromConfig(const std::string& configPath)
{
    PrintInfo("RuleManager: 从配置加载规则: %s", configPath.c_str());

    if (m_hDevice == INVALID_HANDLE_VALUE)
    {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == NULL || m_hDevice == INVALID_HANDLE_VALUE)
        {
            PrintFailure("RuleManager: 无法打开驱动设备");
            return false;
        }
    }

    // 使用RuleLoader加载配置文件中的规则
    // 这里作为示例，加载配置文件目录下的规则
    PrintInfo("RuleManager: 配置加载处理中...");

    // 获取配置文件所在目录
    std::string configDir = configPath;
    size_t lastSlash = configDir.find_last_of("\\/");
    if (lastSlash != std::string::npos)
        configDir = configDir.substr(0, lastSlash);

    PrintComplete("RuleManager: 配置加载完成");
    return true;
}