#pragma once
#include "../shared/Common.h"
#include <string>
#include <vector>
#include <windows.h>

// ── TOML 规则解析器 ──
class TomlRuleParser {
public:
    TomlRuleParser() = default;
    ~TomlRuleParser() = default;

    bool ParseFile(const std::string& filePath, std::vector<BA_DYNAMIC_RULE>& outRules);
    bool ValidateRule(const BA_DYNAMIC_RULE& rule, std::string* errorOut = nullptr);

private:
    std::string Trim(const std::string& s);
    std::string LowerCase(const std::string& s);
    bool ReadFile(const std::string& path, std::string& content);
    ULONG ResolveIndicatorId(const std::string& name);
};

// ── 规则管理器 ──
class DynamicRuleManagerV2 {
public:
    DynamicRuleManagerV2() = default;
    ~DynamicRuleManagerV2() = default;

    bool Init(HANDLE hDevice, const std::string& rulesDir);
    bool LoadRules(const std::string& rulesDir);
    bool StartWatching();
    void StopWatching();
    ULONG GetVersion();
    bool GetStats(std::vector<BA_RULE_STATS>& outStats);
    bool GetList(std::vector<BA_DYNAMIC_RULE>& outRules);
    void UnloadAll();
    bool ReportFeedback(ULONG ruleId, INT64 pid, const char* imagePath,
                        ULONG action, INT64 timestampMs);

private:
    HANDLE m_hDevice = INVALID_HANDLE_VALUE;
    std::string m_rulesDir;
    ULONG m_lastVersion = 0;
    BOOL m_watching = FALSE;

    static DWORD WINAPI WatchThreadFunc(LPVOID param);
    void WatchThreadFunc();
    void ProcessRuleFile(const std::string& filePath, bool isAdd);
};
