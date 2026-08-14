#include "RuleLoader.h"
#include "ConsoleOutput.h"
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

// ============================================================================
// LoadRulesFromFile - 读取单个Lua规则文件，解析规则内容
// ============================================================================
bool RuleLoader::LoadRulesFromFile(const std::string& filePath)
{
    PrintInfo("正在加载规则文件: %s", filePath.c_str());

    std::ifstream file(filePath);
    if (!file.is_open())
    {
        PrintFailure("无法打开规则文件: %s", filePath.c_str());
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    file.close();

    if (content.empty())
    {
        PrintWarning("规则文件为空: %s", filePath.c_str());
        return false;
    }

    PrintDebug("规则文件大小: %zu 字节", content.size());

    // 解析规则内容 - 按行读取
    std::istringstream stream(content);
    std::string line;
    int lineCount = 0;
    int ruleCount = 0;

    while (std::getline(stream, line))
    {
        lineCount++;

        // 跳过空行和注释行
        if (line.empty() || line.find("--") == 0)
            continue;

        // 简单检测是否包含规则定义关键字
        if (line.find("RuleId") != std::string::npos ||
            line.find("rule_id") != std::string::npos ||
            line.find("Operation") != std::string::npos ||
            line.find("FullPath") != std::string::npos)
        {
            ruleCount++;
        }
    }

    PrintSuccess("规则文件加载成功: %s (共 %d 行, 检测到 %d 条规则)", filePath.c_str(), lineCount, ruleCount);
    return true;
}

// ============================================================================
// LoadRulesFromDirectory - 遍历目录加载所有.lua文件
// ============================================================================
bool RuleLoader::LoadRulesFromDirectory(const std::string& dirPath)
{
    PrintInfo("正在扫描规则目录: %s", dirPath.c_str());

    // 构造搜索路径
    std::string searchPath = dirPath;
    if (!searchPath.empty() && searchPath.back() != '\\')
        searchPath += '\\';
    searchPath += "*.lua";

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        PrintWarning("未找到规则文件 (*.lua) 在目录: %s", dirPath.c_str());
        return false;
    }

    int totalLoaded = 0;
    int totalFailed = 0;

    do
    {
        // 跳过目录
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        std::string fullPath = dirPath;
        if (fullPath.back() != '\\')
            fullPath += '\\';
        fullPath += findData.cFileName;

        PrintProgress("发现规则文件: %s", findData.cFileName);

        if (LoadRulesFromFile(fullPath))
            totalLoaded++;
        else
            totalFailed++;

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    if (totalLoaded > 0)
        PrintSuccess("规则目录扫描完成: 成功加载 %d 个文件, 失败 %d 个", totalLoaded, totalFailed);
    else
        PrintWarning("规则目录扫描完成: 未成功加载任何规则文件");

    return totalLoaded > 0;
}