#pragma once
#include <string>
#include <vector>

// 规则加载器 - 从Lua文件加载规则
class RuleLoader {
public:
    static bool LoadRulesFromFile(const std::string& filePath);
    static bool LoadRulesFromDirectory(const std::string& dirPath);
};