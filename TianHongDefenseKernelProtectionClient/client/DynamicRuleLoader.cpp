#include "DynamicRuleLoader.h"
#include "Comm.h"
#include "ConsoleOutput.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

// ============================================================================
// DynamicRuleLoader 实现
// ============================================================================

bool DynamicRuleLoader::TrimString(const std::string& str, std::string& out) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        out = "";
        return true;
    }
    size_t end = str.find_last_not_of(" \t\r\n");
    out = str.substr(start, end - start + 1);
    return true;
}

bool DynamicRuleLoader::LowerCase(const std::string& str, std::string& out) {
    out = str;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return true;
}

bool DynamicRuleLoader::ReadFileToString(const std::string& filePath, std::string& outContent) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    outContent = buffer.str();
    file.close();
    return true;
}

bool DynamicRuleLoader::ParseRuleFile(const std::string& filePath, std::vector<BA_DYNAMIC_RULE>& outRules) {
    std::string content;
    if (!ReadFileToString(filePath, content)) {
        return false;
    }

    // 简单的 TOML 解析（实际项目应使用完整 TOML 库）
    // 这里实现基本解析逻辑
    std::istringstream stream(content);
    std::string line;
    BA_DYNAMIC_RULE currentRule = {0};
    bool inDetection = false;
    bool inIndicators = false;
    bool inThreat = false;

    while (std::getline(stream, line)) {
        TrimString(line, line);

        // 跳过注释和空行
        if (line.empty() || line[0] == '#') continue;

        // 解析 section
        if (line == "[rule]") {
            inDetection = false;
            inIndicators = false;
            continue;
        }
        if (line == "[rule.detection]") {
            inDetection = true;
            inIndicators = false;
            continue;
        }
        if (line == "[[rule.detection.indicators]]") {
            inIndicators = true;
            inDetection = false;
            // 添加新指标条目
            if (currentRule.IndicatorCount < BA_DYN_MAX_INDICATORS) {
                currentRule.Indicators[currentRule.IndicatorCount].IndicatorId = 0;
                currentRule.Indicators[currentRule.IndicatorCount].Weight = 0.0;
                currentRule.Indicators[currentRule.IndicatorCount].Required = FALSE;
            }
            continue;
        }
        if (line == "[[rule.threat]]") {
            inThreat = true;
            continue;
        }

        // 解析 key = value
        size_t eqPos = line.find('=');
        if (eqPos == std::string::npos) continue;

        std::string key = line.substr(0, eqPos);
        std::string value = line.substr(eqPos + 1);
        TrimString(key, key);
        TrimString(value, value);

        // 移除引号
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
            value = value.substr(1, value.size() - 2);
        }

        if (inDetection) {
            if (key == "threshold") {
                currentRule.Threshold = std::stod(value);
            } else if (key == "min_match_count") {
                currentRule.MinMatchCount = std::stoi(value);
            } else if (key == "direct_malicious") {
                currentRule.DirectMalicious = (value == "true" || value == "1");
            } else if (inIndicators && key == "id") {
                // 解析指标 ID（如 "BA_IND_PROC_FROM_TEMP_DIR"）
                // 实际实现需要映射指标名到 ID 值
                currentRule.Indicators[currentRule.IndicatorCount].IndicatorId = 0;
            } else if (inIndicators && key == "weight") {
                currentRule.Indicators[currentRule.IndicatorCount].Weight = std::stod(value);
            } else if (inIndicators && key == "required") {
                currentRule.Indicators[currentRule.IndicatorCount].Required = (value == "true" || value == "1");
            }
        } else if (key == "name") {
            strncpy_s(currentRule.Name, value.c_str(), _TRUNCATE);
        } else if (key == "description") {
            strncpy_s(currentRule.Description, value.c_str(), _TRUNCATE);
        } else if (key == "severity") {
            if (value == "critical") currentRule.Severity = 5;
            else if (value == "high") currentRule.Severity = 4;
            else if (value == "medium") currentRule.Severity = 3;
            else if (value == "low") currentRule.Severity = 2;
            else currentRule.Severity = 1;
        } else if (key == "risk_score") {
            currentRule.RiskScore = std::stoi(value);
        } else if (key == "threat_class") {
            strncpy_s(currentRule.ThreatClass, value.c_str(), _TRUNCATE);
        } else if (key == "rule_id") {
            currentRule.RuleId = std::stoul(value);
        } else if (key == "version") {
            currentRule.Version = std::stoul(value);
        }
    }

    // 添加规则到列表
    if (currentRule.RuleId != 0) {
        currentRule.IndicatorCount = 0; // 简化：实际应计数
        outRules.push_back(currentRule);
    }

    return true;
}

bool DynamicRuleLoader::ParseAllRuleFiles(const std::string& directory, std::vector<BA_DYNAMIC_RULE>& outRules) {
    if (!fs::exists(directory)) {
        std::cerr << "Directory does not exist: " << directory << std::endl;
        return false;
    }

    for (const auto& entry : fs::directory_iterator(directory)) {
        if (entry.is_regular_file() && entry.path().extension() == ".toml") {
            std::vector<BA_DYNAMIC_RULE> rules;
            if (ParseRuleFile(entry.path().string(), rules)) {
                outRules.insert(outRules.end(), rules.begin(), rules.end());
            }
        }
    }

    return true;
}

bool DynamicRuleLoader::ParseIndicatorDefFile(const std::string& filePath, std::vector<BA_INDICATOR_DEFINITION>& outDefs) {
    // 类似 ParseRuleFile 的实现
    return false;
}

// ============================================================================
// DynamicRuleManager 实现
// ============================================================================

DynamicRuleManager& DynamicRuleManager::Instance() {
    static DynamicRuleManager instance;
    return instance;
}

bool DynamicRuleManager::Init(HANDLE hDevice, const std::string& rulesDir) {
    m_rulesDir = rulesDir;
    m_hDevice = hDevice;
    m_lastVersion = 0;

    // 加载所有规则文件
    std::vector<BA_DYNAMIC_RULE> rules;
    DynamicRuleLoader loader;
    if (!loader.ParseAllRuleFiles(rulesDir, rules)) {
        std::cerr << "Failed to parse rule files from: " << rulesDir << std::endl;
        return false;
    }

    // 批量加载规则
    for (const auto& rule : rules) {
        BA_DYNAMIC_RULE_LOAD_REQ req = { rule };
        if (!CommLoadDynamicRule(m_hDevice, &req)) {
            std::cerr << "Failed to load rule: " << rule.Name << std::endl;
        }
    }

    // 获取当前版本
    ULONG ver = 0;
    CommGetDynamicRuleVersion(m_hDevice, &ver);
    m_lastVersion = ver;

    std::cout << "DynamicRuleManager: Loaded " << rules.size() << " rules, version=" << m_lastVersion << std::endl;
    return true;
}

bool DynamicRuleManager::StartWatching() {
    if (m_watching) return true;

    // 启动文件监控线程
    m_watching = TRUE;
    // 实际实现应启动监控线程
    std::cout << "DynamicRuleManager: File watching started" << std::endl;
    return true;
}

void DynamicRuleManager::StopWatching() {
    m_watching = FALSE;
    std::cout << "DynamicRuleManager: File watching stopped" << std::endl;
}

void DynamicRuleManager::UnloadAll() {
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CommClearDynamicRules(m_hDevice);
    }
    m_lastVersion = 0;
    std::cout << "DynamicRuleManager: All rules unloaded" << std::endl;
}

bool DynamicRuleManager::GetRuleStats(std::vector<BA_RULE_STATS>& outStats) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    return CommGetDynamicRuleStats(m_hDevice, outStats);
}

bool DynamicRuleManager::GetRuleList(std::vector<BA_DYNAMIC_RULE>& outRules) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    return CommGetDynamicRuleList(m_hDevice, outRules);
}

ULONG DynamicRuleManager::GetRuleVersion() {
    if (m_hDevice == INVALID_HANDLE_VALUE) return 0;
    ULONG ver = 0;
    CommGetDynamicRuleVersion(m_hDevice, &ver);
    return ver;
}
