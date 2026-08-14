#pragma once
#include "../shared/Common.h"
#include <string>
#include <vector>

// ── 动态规则加载器 ──
class DynamicRuleLoader {
public:
    DynamicRuleLoader() = default;
    ~DynamicRuleLoader() = default;

    // 解析单个 TOML 文件，返回 BA_DYNAMIC_RULE 列表
    bool ParseRuleFile(const std::string& filePath, std::vector<BA_DYNAMIC_RULE>& outRules);

    // 解析目录下的所有 TOML 文件
    bool ParseAllRuleFiles(const std::string& directory, std::vector<BA_DYNAMIC_RULE>& outRules);

    // 解析指标定义文件
    bool ParseIndicatorDefFile(const std::string& filePath, std::vector<BA_INDICATOR_DEFINITION>& outDefs);

private:
    // 简单的 TOML 解析辅助函数
    bool TrimString(const std::string& str, std::string& out);
    bool LowerCase(const std::string& str, std::string& out);
    bool ReadFileToString(const std::string& filePath, std::string& outContent);
};

// ── 规则管理器（扩展）──
class DynamicRuleManager {
public:
    static DynamicRuleManager& Instance();

    // 初始化：加载所有规则文件
    bool Init(HANDLE hDevice, const std::string& rulesDir);

    // 启动文件监控（热更新）
    bool StartWatching();

    // 停止监控
    void StopWatching();

    // 卸载所有规则
    void UnloadAll();

    // 获取规则统计
    bool GetRuleStats(std::vector<BA_RULE_STATS>& outStats);

    // 获取规则列表
    bool GetRuleList(std::vector<BA_DYNAMIC_RULE>& outRules);

    // 获取规则版本
    ULONG GetRuleVersion();

private:
    DynamicRuleManager() = default;
    HANDLE m_hDevice = INVALID_HANDLE_VALUE;
    std::string m_rulesDir;
    ULONG m_lastVersion;
    BOOL m_watching = FALSE;
};
