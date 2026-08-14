#pragma once
#include "../shared/Common.h"
#include <string>
#include <vector>
#include <windows.h>

// 规则管理器 - 管理规则的生命周期
class RuleManager {
public:
    static RuleManager& Instance();
    
    bool AddRegRule(const RULE_REG_DATA& rule);
    bool AddFileRule(const RULE_FILE_DATA& rule);
    bool RemoveFileRule(ULONG ruleId);
    void ClearFileRules();
    bool GetFileRuleStats(FILE_RULE_STATS& stats);
    bool LoadRulesFromConfig(const std::string& configPath);
    
private:
    RuleManager() = default;
    HANDLE m_hDevice = INVALID_HANDLE_VALUE;
};