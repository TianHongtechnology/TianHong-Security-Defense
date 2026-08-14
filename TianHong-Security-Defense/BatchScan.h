#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>
#include <algorithm>
#include <cctype>
#include <memory>
#include <iterator>
#include <functional>
#include <sstream>

// ============================================================
// 通用数据结构
// ============================================================
enum class ScriptLanguage { PowerShell, CMD, VBS, JavaScript, Cpp, Unknown };

struct RiskReport {
    ScriptLanguage language = ScriptLanguage::Unknown;
    bool isMalicious = false;
    int riskScore = 0;
    std::string riskLevel;
    std::string family;
    std::vector<std::string> reasons;
    std::set<std::string> mitreTechniques;
    std::vector<std::string> apiCalls;
    std::vector<std::string> network;
    std::vector<std::string> files;
    std::vector<std::string> registry;
    std::string scriptLower; // 辅助
};

// ============================================================
// 公用工具函数（加固版：异常安全 + 防回溯爆炸）
// ============================================================
inline std::string toLower(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return lower;
}

inline bool containsAny(const std::string& haystack, const std::vector<std::string>& needles) {
    std::string lower = toLower(haystack);
    for (const auto& n : needles) {
        if (lower.find(n) != std::string::npos) return true;
    }
    return false;
}

inline int countRegexMatches(const std::string& text, const std::string& pattern) {
    if (pattern.empty()) return 0;
    try {
        std::regex re(pattern,
            std::regex_constants::icase |
            std::regex_constants::ECMAScript |
            std::regex_constants::optimize);
        auto begin = std::sregex_iterator(text.begin(), text.end(), re);
        auto end = std::sregex_iterator();
        int count = 0;
        // 防止恶意超大文本导致无上限遍历（强制上限 4000）
        constexpr int kMaxMatches = 4000;
        for (; begin != end && count < kMaxMatches; ++begin) {
            ++count;
        }
        return count;
    }
    catch (const std::regex_error&) {
        return 0;
    }
    catch (...) {
        return 0;
    }
}

inline bool searchRegex(const std::string& text, const std::string& pattern) {
    if (pattern.empty()) return false;
    try {
        std::regex re(pattern,
            std::regex_constants::icase |
            std::regex_constants::ECMAScript |
            std::regex_constants::optimize);
        return std::regex_search(text, re);
    }
    catch (const std::regex_error&) {
        return false;
    }
    catch (...) {
        return false;
    }
}

// 混淆度量结构
struct ObfuscationMetrics {
    bool hasBacktickFlood = false;
    bool hasJoinFormat = false;
    bool hasBase64Decoding = false;
    bool hasCharArray = false;
    bool hasXorOps = false;
    bool hasReflection = false;
    bool hasReverseOps = false;
    bool hasSubstringConcat = false;
    bool hasFunctionNameAccess = false;
    bool hasDotCallChains = false;
    bool hasEncodedCommand = false;
    bool hasCaseEntropy = false;
    bool hasLongRandomVars = false;
    bool hasStringFormatting = false;
    bool hasBacktickEscape = false;
    int totalObfuscationPoints = 0;
};

// ============================================================
// 家族分类器
// ============================================================
class FamilyClassifier {
    static int familyPriority(const std::string& family) {
        if (family.find("CredentialDumper") != std::string::npos) return 100;
        if (family.find("Injector") != std::string::npos) return 90;
        if (family.find("Persistence") != std::string::npos) return 80;
        if (family.find("ReverseShell") != std::string::npos) return 70;
        if (family.find("Downloader") != std::string::npos) return 60;
        if (family.find("Obfuscated") != std::string::npos) return 50;
        return 10;
    }

public:
    static std::string classify(int score,
        const std::set<std::string>& techniques,
        const std::vector<std::string>& apis,
        const std::string& scriptLower) {
        if (score < 30) return "Heur/Trojan.Script.Generic";

        // 行为特征判定
        bool hasCredDump = containsAny(scriptLower, {
            "mimikatz","lsass","sekurlsa","logonpasswords","samdump","wdigest","procdump"
            });

        bool hasPersistence = techniques.count("T1547.001") ||
            techniques.count("T1053.005") ||
            techniques.count("T1543.003") ||
            techniques.count("T1546.003");

        bool hasDownload = techniques.count("T1105") ||
            containsAny(scriptLower, {
                "downloadfile","downloadstring","invoke-webrequest",
                "msxml2.xmlhttp","certutil","bitsadmin","winhttp","urlmon"
                });

        bool hasReverseShellNetwork = containsAny(scriptLower, {
            "tcpclient","socket"
            });
        bool hasReverseShellExecution = containsAny(scriptLower, {
            "wscript.shell","run cmd","wshshell.run",
            "cmd.exe /c","powershell -e"
            });
        bool hasReverseShell = hasReverseShellNetwork && hasReverseShellExecution;

        bool hasObfuscation = techniques.count("T1027") ||
            containsAny(scriptLower, {
                "frombase64string","chr(","-join","findstr","replace(",
                "char(","-bxor","-bor","-band"
                });

        // 仅当存在以下任一“恶意上下文”时，才认定注入行为成立：
        // 同时存在混淆 / 下载 / 凭据窃取 / 持久化
        // MITRE 技术 T1055 且伴随反射或混淆
        bool isolatedInjectionApi = containsAny(scriptLower, {
            "virtualalloc","writeprocessmemory","createremotethread",
            "ntallocatevirtualmemory","rtlcreateuserthread"
            });
        bool hasStrongInjection = false;

        if (techniques.count("T1055") &&
            (techniques.count("T1620") || hasObfuscation || hasDownload || hasCredDump || hasPersistence)) {
            hasStrongInjection = true;
        }
        else if (isolatedInjectionApi &&
            (hasObfuscation || hasDownload || hasCredDump || hasPersistence)) {
            hasStrongInjection = true;
        }
        // 如果没有任何其他恶意行为，单独出现的注入 API 将不会被认定为注入器

        // 构建候选家族（按严重性）
        std::vector<std::string> candidates;
        if (hasCredDump)
            candidates.push_back("Heur/Trojan.Script.CredentialDumper");
        if (hasStrongInjection)
            candidates.push_back("Heur/Trojan.Script.Injector");
        if (hasPersistence) {
            if (hasObfuscation)
                candidates.push_back("Heur/Backdoor.Script.Persistence.Obfuscated");
            else
                candidates.push_back("Heur/Backdoor.Script.Persistence");
        }
        if (hasReverseShell) {
            candidates.push_back("Heur/Backdoor.Script.ReverseShell");
            if (hasDownload)
                candidates.push_back("Heur/Backdoor.Script.Downloader");
        }
        if (hasDownload && !hasReverseShell)
            candidates.push_back("Heur/Trojan.Script.Downloader");
        if (hasObfuscation && candidates.empty())
            candidates.push_back("Heur/Trojan.Script.Obfuscated");
        if (candidates.empty())
            candidates.push_back("Heur/Trojan.Script.Generic");

        return *std::max_element(candidates.begin(), candidates.end(),
            [](const std::string& a, const std::string& b) {
                return familyPriority(a) < familyPriority(b);
            });
    }

    static std::string classifyExtended(
        int score,
        const std::set<std::string>& techniques,
        const std::vector<std::string>& apis,
        const std::string& scriptLower,
        const ObfuscationMetrics& m)
    {
        std::string baseFamily = classify(score, techniques, apis, scriptLower);

        // 通用脚本但混淆较高 → 升级为混淆木马
        if (baseFamily == "Heur/Trojan.Script.Generic" && m.totalObfuscationPoints >= 8) {
            baseFamily = "Heur/Trojan.Script.Obfuscated";
        }

        // 自解析混淆 → 附加自解码标记
        if (m.hasFunctionNameAccess && baseFamily.find("Obfuscated") != std::string::npos &&
            techniques.count("T1027")) {
            baseFamily += ".SelfDecoding";
        }

        // 反射加载且尚未被标记为注入，则升级为反射注入器
        if (m.hasReflection && techniques.count("T1620") &&
            baseFamily.find("Injector") == std::string::npos) {
            // 此时必须有一定恶意上下文（因为单独反射可能只是动态加载）
            if (score >= 40)  // 风险分较高时才升级
                baseFamily = "Heur/Trojan.Script.Reflective.Injector";
        }

        return baseFamily;
    }
};

// ------------------------- 抽象基类 -------------------------
class LanguageDetector {
public:
    virtual RiskReport analyze(const std::string& script) = 0;
    virtual ~LanguageDetector() = default;
protected:
    virtual int scoreObfuscation(const std::string& script) = 0;
    virtual void simulate(const std::string& script, RiskReport& report) = 0;
    virtual void applyRules(RiskReport& report) = 0;
};

// ===================== PowerShell 检测器 =====================
class PowerShellDetector : public LanguageDetector {
public:
    RiskReport analyze(const std::string& script) override {
        RiskReport report;
        report.language = ScriptLanguage::PowerShell;
        report.scriptLower = toLower(script);

        // 计算混淆度量，保存为成员，供后续虚函数内部使用
        metrics = computeObfuscationMetrics(script);

        // 第一步：混淆评分（内部通过 metrics 计算）
        report.riskScore = scoreObfuscation(script);

        // 第二步：行为模拟（内部使用 metrics）
        simulate(script, report);

        // 第三步：综合规则判定（内部使用 metrics）
        applyRules(report);

        // 第四步：误报抑制（管理脚本降级）
        reduceFalsePositives(report, script);

        // 第五步：家族分类（使用扩展分类器）
        report.family = FamilyClassifier::classifyExtended(
            report.riskScore, report.mitreTechniques,
            report.apiCalls, report.scriptLower, metrics);
        report.isMalicious = (report.riskScore >= 30);
        if (report.riskScore >= 80) report.riskLevel = "CRITICAL";
        else if (report.riskScore >= 60) report.riskLevel = "HIGH";
        else if (report.riskScore >= 30) report.riskLevel = "MEDIUM";
        else report.riskLevel = "LOW";
        return report;
    }

protected:
    ObfuscationMetrics metrics;   // 成员变量，在 analyze() 中填充

    // 计算混淆度量（原始实现，略作增强）
    ObfuscationMetrics computeObfuscationMetrics(const std::string& script) {
        ObfuscationMetrics m;
        const std::string lower = toLower(script);

        int backtickCount = std::count(script.begin(), script.end(), '`');
        m.hasBacktickFlood = (backtickCount > script.size() * 0.10);
        m.hasJoinFormat = (lower.find("-join") != std::string::npos ||
            lower.find("-f ") != std::string::npos);
        m.hasBase64Decoding = (lower.find("frombase64string") != std::string::npos);
        m.hasCharArray = (countRegexMatches(script, R"(\[char\]\d+)") > 0);
        m.hasXorOps = searchRegex(script, R"(-bxor|-band|-bor)");
        m.hasReflection = (countRegexMatches(script, R"(\[System\.\w+\]::)") > 3);
        m.hasReverseOps = (searchRegex(script, R"(-replace\s*'.*','.*')") ||
            lower.find(".reverse()") != std::string::npos);
        m.hasSubstringConcat = (countRegexMatches(script, R"(\.SubString\s*\()") > 1);
        m.hasFunctionNameAccess = searchRegex(script, R"(\b(?:FunctionName|MyInvocation)\b)");
        m.hasDotCallChains = (searchRegex(script, R"(\.\s*\()") &&
            !searchRegex(script, R"(\.\s*\$\w+\s*\()"));
        m.hasEncodedCommand = searchRegex(script, R"(-(?:enc|ec|encodedcommand)\s+)");
        m.hasCaseEntropy = [&]() {
            int upperCount = std::count_if(script.begin(), script.end(), ::isupper);
            int alphaCount = std::count_if(script.begin(), script.end(), ::isalpha);
            return (alphaCount > 0 && upperCount > alphaCount * 0.4);
            }();
        m.hasLongRandomVars = (countRegexMatches(script, R"(\$([a-z0-9_]{12,}))") > 2);
        m.hasStringFormatting = (countRegexMatches(script, R"(\{0\}.*\{1\})") > 1 ||
            lower.find("-f ") != std::string::npos);
        m.hasBacktickEscape = (backtickCount > 5 && script.size() < 500);

        // 汇总混淆点数
        m.totalObfuscationPoints =
            (m.hasBacktickFlood ? 3 : 0) + (m.hasBase64Decoding ? 4 : 0) +
            (m.hasCharArray ? 2 : 0) + (m.hasXorOps ? 2 : 0) +
            (m.hasReflection ? 1 : 0) + (m.hasReverseOps ? 2 : 0) +
            (m.hasSubstringConcat ? 2 : 0) + (m.hasFunctionNameAccess ? 5 : 0) +
            (m.hasDotCallChains ? 3 : 0) + (m.hasEncodedCommand ? 6 : 0) +
            (m.hasCaseEntropy ? 3 : 0) + (m.hasLongRandomVars ? 1 : 0) +
            (m.hasStringFormatting ? 1 : 0) + (m.hasBacktickEscape ? 2 : 0);
        return m;
    }

    // ---------- 混淆评分 ----------
    int scoreObfuscation(const std::string& script) override {
        int score = 0;
        const std::string lower = toLower(script);

        if (metrics.hasBacktickFlood) score += 3;
        if (countRegexMatches(script, R"([\"']\s*\+\s*[\"'])") > 3) score += 2;
        if (metrics.hasBase64Decoding) score += 4;
        if (searchRegex(script, R"(&\s*\()")) score += 3;
        if (metrics.hasEncodedCommand) score += 6;
        if (metrics.hasCaseEntropy) score += 3;
        if (metrics.hasCharArray) {
            if (countRegexMatches(script, R"(\[char\]\d+)") > 2) score += 3;
            else score += 1;
        }
        if (metrics.hasXorOps) score += 2;
        if (metrics.hasFunctionNameAccess) score += 5;
        if (metrics.hasSubstringConcat) score += 2;
        if (searchRegex(script, R"(\b(?:Get-Command|gcm|GCS)\b)")) score += 3;
        if (metrics.hasReflection) score += 2;
        if (metrics.hasDotCallChains) score += 3;
        if (metrics.hasReverseOps) score += 2;
        if (metrics.hasJoinFormat && score >= 3) score += 2;

        // 多重编码链
        if (metrics.hasBase64Decoding &&
            countRegexMatches(script, R"(\[System\.Convert\]::FromBase64String)") > 1)
            score += 3;
        // 字符串反转拼接
        if (searchRegex(lower, R"(\(\s*'[^']*'\s*\+\s*'[^']*'\s*\))"))
            score += 2;
        // 大量 [char] 拼接
        if (countRegexMatches(script, R"(\[char\]\d+\s*\+)") > 3)
            score += 2;

        return std::min(score, 35);
    }

    // ---------- 行为模拟 ----------
    void simulate(const std::string& script, RiskReport& report) override {
        std::string lower = report.scriptLower;

        // ======================== API / 危险特征匹配列表 ========================
        const std::vector<std::pair<std::string, std::string>> apiPatterns = {
            // 动态执行与代码注入
            {R"(\bInvoke-Expression\b|(?<![a-z])iex(?![a-z]))", "iex"},
            {R"(\bInvoke-Command\b|(?<![a-z])icm(?![a-z]))", "icm"},
            {R"(\bInvoke-WmiMethod\b)", "Invoke-WmiMethod"},
            {R"(\bInvoke-CimMethod\b)", "Invoke-CimMethod"},
            {R"(\bStart-Process\b|(?<![a-z])saps(?![a-z])|(?<![a-z])start(?![a-z]))", "Start-Process"},
            {R"(\bNew-Object\b)", "New-Object"},
            {R"(\bAdd-Type\b)", "Add-Type"},
            {R"(\[System\.Reflection\.Assembly\]::Load)", "Assembly.Load"},
            {R"(\[Reflection\.Assembly\]::Load)", "Assembly.Load"},
            {R"(\bReflection\.Assembly\b)", "Reflection.Assembly"},
            {R"(\[AppDomain\]::CurrentDomain\.Load)", "AppDomain.Load"},
            {R"(\[System\.Runtime\.InteropServices\.Marshal\]::)", "Marshal"},
            {R"(\[System\.Runtime\.CompilerServices\.RuntimeHelpers\]::)", "RuntimeHelpers"},
            {R"(\[Delegate\]::CreateDelegate)", "CreateDelegate"},
            {R"(\[Activator\]::CreateInstance)", "Activator"},

            // 下载与网络通信
            {R"(\bInvoke-WebRequest\b|(?<![a-z])iwr(?![a-z])|(?<![a-z])curl(?![a-z])|(?<![a-z])wget(?![a-z]))", "Invoke-WebRequest"},
            {R"(\bInvoke-RestMethod\b|(?<![a-z])irm(?![a-z]))", "Invoke-RestMethod"},
            {R"(\bNet\.WebClient\b)", "Net.WebClient"},
            {R"(\bNet\.Http\.HttpClient\b)", "HttpClient"},
            {R"(\bNet\.Sockets\.TcpClient\b)", "TcpClient"},
            {R"(\bNet\.Sockets\.UdpClient\b)", "UdpClient"},
            {R"(\bNet\.Sockets\.Socket\b)", "Socket"},
            {R"(\.DownloadFile\s*\()", "DownloadFile"},
            {R"(\.DownloadString\s*\()", "DownloadString"},
            {R"(\.DownloadData\s*\()", "DownloadData"},
            {R"(\.UploadFile\s*\()", "UploadFile"},
            {R"(\.UploadString\s*\()", "UploadString"},
            {R"(\.OpenRead\s*\()", "OpenRead"},
            {R"(\.OpenWrite\s*\()", "OpenWrite"},
            {R"(\bSystem\.Net\.WebRequest\b)", "WebRequest"},
            {R"(\bSystem\.Net\.FtpWebRequest\b)", "FtpWebRequest"},
            {R"(\bSystem\.Net\.HttpListener\b)", "HttpListener"},
            {R"(\bWinHttp\.WinHttpRequest\b)", "WinHttpRequest"},
            {R"(\bMSXML2\.XMLHTTP\b)", "MSXML2.XMLHTTP"},
            {R"(\bMSXML2\.ServerXMLHTTP\b)", "MSXML2.ServerXMLHTTP"},
            {R"(\bWinHttpRequest\b)", "WinHttpRequest"},
            {R"(\bXMLHTTP\b)", "XMLHTTP"},

            // 持久化、计划任务、服务
            {R"(\bRegister-ScheduledTask\b)", "Register-ScheduledTask"},
            {R"(\bNew-ScheduledTask\b)", "New-ScheduledTask"},
            {R"(\bSet-ScheduledTask\b)", "Set-ScheduledTask"},
            {R"(\bEnable-ScheduledTask\b)", "Enable-ScheduledTask"},
            {R"(\bDisable-ScheduledTask\b)", "Disable-ScheduledTask"},
            {R"(\bUnregister-ScheduledTask\b)", "Unregister-ScheduledTask"},
            {R"(\bRegister-WmiEvent\b)", "Register-WmiEvent"},
            {R"(\bNew-Service\b)", "New-Service"},
            {R"(\bSet-Service\b)", "Set-Service"},
            {R"(\bNew-ItemProperty.*CurrentVersion\\Run)", "Reg-RunKey"},
            {R"(\bSet-ItemProperty.*CurrentVersion\\Run)", "Reg-RunKey"},
            {R"(\bRemove-ItemProperty.*CurrentVersion\\Run)", "Reg-RunKey"},
            {R"(\bNew-Item.*\\Startup)", "StartupFolder"},
            {R"(\bNew-ItemProperty.*Windows\\CurrentVersion\\RunOnce)", "RunOnce"},
            {R"(\bschtasks\b)", "schtasks.exe"},
            {R"(\bsc\s+create\b)", "sc-create"},
            {R"(\bsc\s+config\b)", "sc-config"},
            {R"(\bsc\s+delete\b)", "sc-delete"},

            // 进程、线程与内存操作
            {R"(\bGet-Process\b|(?<![a-z])gps(?![a-z])|(?<![a-z])ps(?![a-z]))", "Get-Process"},
            {R"(\bStop-Process\b|(?<![a-z])spps(?![a-z])|(?<![a-z])kill(?![a-z]))", "Stop-Process"},
            {R"(\bWait-Process\b)", "Wait-Process"},
            {R"(\bVirtualAlloc\b)", "VirtualAlloc"},
            {R"(\bVirtualAllocEx\b)", "VirtualAllocEx"},
            {R"(\bWriteProcessMemory\b)", "WriteProcessMemory"},
            {R"(\bCreateRemoteThread\b)", "CreateRemoteThread"},
            {R"(\bOpenProcess\b)", "OpenProcess"},
            {R"(\bNtCreateThreadEx\b)", "NtCreateThreadEx"},
            {R"(\bRtlCreateUserThread\b)", "RtlCreateUserThread"},
            {R"(\bQueueUserAPC\b)", "QueueUserAPC"},
            {R"(\bSetThreadContext\b)", "SetThreadContext"},
            {R"(\bNtUnmapViewOfSection\b)", "NtUnmapViewOfSection"},
            {R"(\bNtWriteVirtualMemory\b)", "NtWriteVirtualMemory"},
            {R"(\bNtProtectVirtualMemory\b)", "NtProtectVirtualMemory"},
            {R"(\bOpenThread\b)", "OpenThread"},
            {R"(\bSuspendThread\b)", "SuspendThread"},
            {R"(\bResumeThread\b)", "ResumeThread"},
            {R"(\bGetProcAddress\b)", "GetProcAddress"},
            {R"(\bLoadLibrary\b)", "LoadLibrary"},

            // 凭据窃取与敏感信息
            {R"(\bmimikatz\b)", "Mimikatz"},
            {R"(\bInvoke-Mimikatz\b)", "Invoke-Mimikatz"},
            {R"(\bGet-Credential\b)", "Get-Credential"},
            {R"(\bConvertTo-SecureString\b)", "ConvertTo-SecureString"},
            {R"(\bConvertFrom-SecureString\b)", "ConvertFrom-SecureString"},
            {R"(\bRead-Host\s+-AsSecureString)", "Read-Host Secure"},
            {R"(\bPSCredential\b)", "PSCredential"},
            {R"(\bSystem\.Security\.Cryptography\.ProtectedData\b)", "ProtectedData"},
            {R"(\blsass\b)", "lsass"},
            {R"(\bsekurlsa\b)", "sekurlsa"},
            {R"(\bwdigest\b)", "wdigest"},
            {R"(\bLsaRetrievePrivateData\b)", "LsaRetrievePrivateData"},
            {R"(\bLsaOpenPolicy\b)", "LsaOpenPolicy"},
            {R"(\bSamQueryInformationUser\b)", "SamQueryInformationUser"},
            {R"(\bDPAPI\b)", "DPAPI"},
            {R"(\bCryptUnprotectData\b)", "CryptUnprotectData"},

            // 文件与注册表操作
            {R"(\bGet-ItemProperty\b|(?<![a-z])gp(?![a-z]))", "Get-ItemProperty"},
            {R"(\bSet-ItemProperty\b|(?<![a-z])sp(?![a-z]))", "Set-ItemProperty"},
            {R"(\bRemove-Item\b|(?<![a-z])ri(?![a-z])|(?<![a-z])rmdir(?![a-z])|(?<![a-z])del(?![a-z]))", "Remove-Item"},
            {R"(\bCopy-Item\b|(?<![a-z])cp(?![a-z])|(?<![a-z])copy(?![a-z]))", "Copy-Item"},
            {R"(\bMove-Item\b|(?<![a-z])mv(?![a-z])|(?<![a-z])move(?![a-z]))", "Move-Item"},
            {R"(\bGet-ChildItem\b|(?<![a-z])gci(?![a-z])|(?<![a-z])ls(?![a-z])|(?<![a-z])dir(?![a-z]))", "Get-ChildItem"},
            {R"(\bGet-Content\b|(?<![a-z])gc(?![a-z])|(?<![a-z])cat(?![a-z])|(?<![a-z])type(?![a-z]))", "Get-Content"},
            {R"(\bSet-Content\b|(?<![a-z])sc(?![a-z]))", "Set-Content"},
            {R"(\bAdd-Content\b|(?<![a-z])ac(?![a-z]))", "Add-Content"},
            {R"(\bOut-File\b)", "Out-File"},
            {R"(\bExport-Csv\b)", "Export-Csv"},
            {R"(\bExport-Clixml\b)", "Export-Clixml"},
            {R"(\bImport-Clixml\b)", "Import-Clixml"},
            {R"(\bGet-Acl\b)", "Get-Acl"},
            {R"(\bSet-Acl\b)", "Set-Acl"},
            {R"(\bTest-Path\b)", "Test-Path"},
            {R"(\bNew-Item\b|(?<![a-z])ni(?![a-z])|(?<![a-z])mkdir(?![a-z]))", "New-Item"},

            // 反病毒、安全绕过与执行策略
            {R"(\bDisable-Amsi\b)", "Disable-AMSI"},
            {R"(\bSet-MpPreference\b)", "Set-MpPreference"},
            {R"(\bAdd-MpPreference\b)", "Add-MpPreference"},
            {R"(\bRemove-MpPreference\b)", "Remove-MpPreference"},
            {R"(\bSet-ExecutionPolicy\b)", "Set-ExecutionPolicy"},
            {R"(-ExecutionPolicy\s+bypass)", "ExecPolicy Bypass"},
            {R"(\bUnblock-File\b)", "Unblock-File"},
            {R"(\bamsiInitFailed\b)", "amsiInitFailed"},
            {R"(\bamsi\.dll\b)", "amsi.dll"},
            {R"(\bSet-EtwTraceProvider\b)", "ETW bypass"},
            {R"(\bEventWrite\b)", "EventWrite bypass"},
            {R"(\bRemove-EtwTraceProvider\b)", "Remove-EtwTraceProvider"},
            {R"(\bSet-PSReadLineOption\b)", "PSReadLine"},
            {R"(\bGet-ExecutionPolicy\b)", "Get-ExecutionPolicy"},
            {R"(\bSet-StrictMode\s+-Off)", "StrictMode Off"},

            // 日志与痕迹清理
            {R"(\bClear-EventLog\b|(?<![a-z])cl(?![a-z]))", "Clear-EventLog"},
            {R"(\bRemove-EventLog\b)", "Remove-EventLog"},
            {R"(\bLimit-EventLog\b)", "Limit-EventLog"},
            {R"(\bWrite-EventLog\b)", "Write-EventLog"},
            {R"(\bwevtutil\s+cl\b)", "wevtutil cl"},
            {R"(\bwevtutil\s+clear-log\b)", "wevtutil clear-log"},
            {R"(\bRemove-Item\s+.*\.evtx\b)", "Delete .evtx"},
            {R"(\bRemove-Item\s+.*Prefetch\b)", "Remove Prefetch"},

            // 编码、混淆与格式操作
            {R"(\[System\.Convert\]::FromBase64String)", "Base64 decode"},
            {R"(\[System\.Convert\]::ToBase64String)", "Base64 encode"},
            {R"(\[Convert\]::)", ".NET Convert"},
            {R"(-bxor\s)", "-bxor"},
            {R"(-band\s)", "-band"},
            {R"(-bor\s)", "-bor"},
            {R"(-replace\s)", "-replace"},
            {R"(-join\s)", "-join"},
            {R"(-split\s)", "-split"},
            {R"(-f\s)", "-f format op"},
            {R"(\[char\]\d+)", "[char] cast"},
            {R"(\[int\]\s)", "[int] cast"},
            {R"(\[byte\]\s)", "[byte] cast"},
            {R"(\[System\.Text\.Encoding\]::)", "Encoding"},

            // WMI / CIM
            {R"(\bGet-WmiObject\b|(?<![a-z])gwmi(?![a-z]))", "Get-WmiObject"},
            {R"(\bGet-CimInstance\b|(?<![a-z])gcim(?![a-z]))", "Get-CimInstance"},
            {R"(\bSet-WmiInstance\b)", "Set-WmiInstance"},
            {R"(\bRegister-CimIndicationEvent\b)", "CIM Event"},
            {R"(\b__EventFilter\b)", "__EventFilter"},
            {R"(\b__EventConsumer\b)", "__EventConsumer"},
            {R"(\b__FilterToConsumerBinding\b)", "__FilterToConsumerBinding"},
            {R"(\bActiveScriptEventConsumer\b)", "ActiveScriptEventConsumer"},
            {R"(\bCommandLineEventConsumer\b)", "CommandLineEventConsumer"},

            // 远程管理与横向移动
            {R"(\bEnter-PSSession\b|(?<![a-z])etsn(?![a-z]))", "Enter-PSSession"},
            {R"(\bNew-PSSession\b|(?<![a-z])nsn(?![a-z]))", "New-PSSession"},
            {R"(\bInvoke-Command\s+-ComputerName)", "Remote ICM"},
            {R"(\bEnable-PSRemoting\b)", "Enable-PSRemoting"},
            {R"(\bDisable-PSRemoting\b)", "Disable-PSRemoting"},
            {R"(\bCopy-Item.*-ToSession)", "Copy-ToSession"},
            {R"(\bCopy-Item.*-FromSession)", "Copy-FromSession"},
            {R"(\bNew-PSDrive\b)", "New-PSDrive"},
            {R"(\bEnter-PSHostProcess\b)", "Enter-PSHostProcess"},
            {R"(\bGet-PSHostProcessInfo\b)", "PSHostProcess"},
            {R"(\bWinRM\b)", "WinRM"},
            {R"(\bWSMan\b)", "WSMan"},

            // 运行空间与管道
            {R"(\bRunspaceFactory\b)", "RunspaceFactory"},
            {R"(\bCreateRunspace\b)", "CreateRunspace"},
            {R"(\bRunspace\s*::)", "Runspace"},
            {R"(\bPowerShell\s*\.Create\b)", "PowerShell.Create"},
            {R"(\.Invoke\(\))", ".Invoke()"},
            {R"(\bBeginInvoke\b)", "BeginInvoke"},
            {R"(\bEndInvoke\b)", "EndInvoke"},

            // 压缩与打包
            {R"(\bCompress-Archive\b)", "Compress-Archive"},
            {R"(\bExpand-Archive\b)", "Expand-Archive"},
            {R"(\bSystem\.IO\.Compression\b)", "IO.Compression"},
            {R"(\bNew-Object.*ZipFile\b)", "ZipFile"},
            {R"(\bSet-Content.*-Encoding\b)", "Set-Content -Encoding"},

            // 剪贴板与邮件
            {R"(\bSet-Clipboard\b)", "Set-Clipboard"},
            {R"(\bGet-Clipboard\b)", "Get-Clipboard"},
            {R"(\bSend-MailMessage\b)", "Send-MailMessage"},
            {R"(\bNet\.Mail\.SmtpClient\b)", "SmtpClient"},

            // 系统工具调用（间接执行）
            {R"(\bcmd\.exe\b|cmd\s+/c)", "cmd.exe"},
            {R"(\bpowershell\.exe\b)", "powershell.exe"},
            {R"(\bpwsh\.exe\b)", "pwsh.exe"},
            {R"(\bwscript\.exe\b)", "wscript.exe"},
            {R"(\bcscript\.exe\b)", "cscript.exe"},
            {R"(\bmshta\.exe\b)", "mshta.exe"},
            {R"(\brundll32\.exe\b)", "rundll32.exe"},
            {R"(\bregsvr32\.exe\b)", "regsvr32.exe"},
            {R"(\breg\.exe\b)", "reg.exe"},
            {R"(\bwmic\.exe\b)", "wmic.exe"},
            {R"(\bcertutil\.exe\b)", "certutil.exe"},
            {R"(\bbitsadmin\.exe\b)", "bitsadmin.exe"},

            // 其他危险操作
            {R"(\bStop-Computer\b)", "Stop-Computer"},
            {R"(\bRestart-Computer\b)", "Restart-Computer"},
            {R"(\bGet-Service\b|(?<![a-z])gsv(?![a-z]))", "Get-Service"},
            {R"(\bGet-ScheduledTask\b)", "Get-ScheduledTask"},
            {R"(\bGet-EventSubscriber\b)", "Get-EventSubscriber"},
            {R"(\bRegister-ObjectEvent\b)", "Register-ObjectEvent"},
            {R"(\bWait-Event\b)", "Wait-Event"},
            {R"(\bRemove-Event\b)", "Remove-Event"},
            {R"(\bGet-ItemProperty.*ImagePath)", "Service Hijack"},
            {R"(\bBinPath\b)", "Service BinPath"},
            {R"(\bImagePath\b)", "ImagePath"},
            {R"(\bWScript\.Shell\b)", "WScript.Shell"},
            {R"(\bShell\.Application\b)", "Shell.Application"},

            // [OPTIMIZATION] 新增检测项
            {R"(\bInvoke-WebRequest.*-UseBasicParsing.*\.(?:exe|dll|ps1)\b)", "IWR-download-exe"},
            {R"(\[System\.Net\.ServicePointManager\]::ServerCertificateValidationCallback\s*=\s*\{?\$true\}?)", "SSL-Bypass"},
            {R"(\b(?:rundll32\.exe|regsvr32\.exe).*/s\b)", "rundll32-sideload"},
            {R"(\bmsbuild\.exe\b)", "msbuild.exe"},
            {R"(\bcsc\.exe\b)", "csc.exe"},
        };

        for (const auto& [pattern, api] : apiPatterns) {
            if (searchRegex(lower, pattern)) {
                report.apiCalls.push_back(api);
            }
        }

        // 网络行为
        if (searchRegex(lower, R"(\b(?:WebClient|Net\.Http|Invoke-WebRequest|Invoke-RestMethod|System\.Net\.Sockets|TcpClient|UdpClient|Socket)\b)")) {
            report.network.push_back("网络通信");
            report.mitreTechniques.insert("T1105");
        }
        if (searchRegex(lower, R"(\b(?:New-Object\s+System\.Net\.Sockets\.TCPClient|\.Connect\s*\(|\.GetStream\(\)|Socket\s*\()\b)"))
            report.mitreTechniques.insert("T1571");

        // 持久化
        if (searchRegex(lower, R"((?:HKLM|HKCU).*\\CurrentVersion\\Run\b)"))
            report.mitreTechniques.insert("T1547.001");
        if (searchRegex(lower, R"(\bRegister-ScheduledTask\b)"))
            report.mitreTechniques.insert("T1053.005");
        if (searchRegex(lower, R"(\bRegister-WmiEvent\b|\b__EventFilter\b)") || metrics.hasFunctionNameAccess)
            report.mitreTechniques.insert("T1546.003");
        if (searchRegex(lower, R"(\bNew-Service\b|\bsc\s+create\b)"))
            report.mitreTechniques.insert("T1543.003");
        if (searchRegex(lower, R"(\b(?:Register-ScheduledTask|schtasks)\b.*\/xml\b)"))
            report.mitreTechniques.insert("T1053.005");

        // 进程注入 / 反射
        if (searchRegex(lower, R"(\b(?:VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC)\b)"))
            report.mitreTechniques.insert("T1055");
        if (metrics.hasReflection || searchRegex(lower, R"(\b(?:Reflection\.Assembly|Assembly\.Load|AppDomain\.Load|Marshal)\b)"))
            report.mitreTechniques.insert("T1620");

        // [OPTIMIZATION] DLL 反射注入链
        if (searchRegex(lower, R"(\[System\.Reflection\.Assembly\]::Load\s*\(\s*\$?[a-z]+\s*\))")) {
            report.mitreTechniques.insert("T1620");
            if (metrics.hasBase64Decoding || metrics.hasEncodedCommand)
                report.mitreTechniques.insert("T1055");
        }

        // 凭据窃取
        if (searchRegex(lower, R"(\b(?:mimikatz|lsass\.exe|sekurlsa|wdigest|Invoke-Mimikatz|LsaRetrievePrivateData|cryptunprotectdata)\b)"))
            report.mitreTechniques.insert("T1003.001");

        // 安全绕过
        if (searchRegex(lower, R"(\b(?:Disable-Amsi|amsiInitFailed|amsi\.dll)\b)"))
            report.mitreTechniques.insert("T1562.001");
        if (searchRegex(lower, R"(\bAdd-MpPreference\s.*-ExclusionPath\b)"))
            report.mitreTechniques.insert("T1562.001");
        if (searchRegex(lower, R"(\b(?:Set-EtwTraceProvider|EventWrite)\b)"))
            report.mitreTechniques.insert("T1562.006");

        // 隐藏窗口
        if (searchRegex(lower, R"(-WindowStyle\s+Hidden\b|-W\s+Hidden\b)"))
            report.mitreTechniques.insert("T1564.003");

        // 自省混淆执行
        if (metrics.hasFunctionNameAccess)
            report.mitreTechniques.insert("T1027");
        if (searchRegex(lower, R"(\b(?:Get-Command|gcm|GCS)\b)"))
            report.mitreTechniques.insert("T1027.005");
        if (metrics.hasSubstringConcat && metrics.hasDotCallChains)
            report.mitreTechniques.insert("T1027.005");
    }

    // ---------- 规则加权 ----------
    void applyRules(RiskReport& report) override {
        int base = 0;
        auto& reasons = report.reasons;
        std::string lower = report.scriptLower;

        bool hasDynamicInvoke = searchRegex(lower, R"(\b(?:Invoke-Expression|iex)\b)");
        bool hasRemoteCmd = searchRegex(lower, R"(\b(?:Invoke-Command|icm)\b)");

        // IEX/ICM 结合上下文，降低孤立误报
        if (hasDynamicInvoke && (metrics.hasBase64Decoding || metrics.hasEncodedCommand)) {
            base += 25; reasons.push_back("IEX + 编码载荷");
        }
        else if (hasDynamicInvoke && searchRegex(lower, R"(\b(?:Net\.WebClient|DownloadString|DownloadFile)\b)")) {
            base += 25; reasons.push_back("IEX + 下载行为");
        }
        else if (hasDynamicInvoke) {
            base += 10; reasons.push_back("IEX 动态执行");
        }

        if (hasRemoteCmd && searchRegex(lower, R"(\b-ComputerName\b|\b-Session\b)")) {
            base += 20; reasons.push_back("远程命令执行 ICM");
        }

        if (metrics.hasEncodedCommand) {
            base += 35; reasons.push_back("编码命令 -EncodedCommand");
        }

        if (report.mitreTechniques.count("T1105")) {
            base += 20; reasons.push_back("网络下载载荷");
        }
        if (report.mitreTechniques.count("T1571")) {
            base += 20; reasons.push_back("反向Shell网络连接");
        }

        if (report.mitreTechniques.count("T1547.001")) { base += 20; reasons.push_back("注册表Run键持久化"); }
        if (report.mitreTechniques.count("T1053.005")) { base += 15; reasons.push_back("计划任务持久化"); }
        if (report.mitreTechniques.count("T1546.003")) { base += 25; reasons.push_back("WMI事件订阅持久化"); }
        if (report.mitreTechniques.count("T1543.003")) { base += 20; reasons.push_back("恶意服务安装"); }

        if (report.mitreTechniques.count("T1055")) { base += 30; reasons.push_back("进程注入"); }
        if (report.mitreTechniques.count("T1620")) { base += 25; reasons.push_back("反射加载执行"); }

        if (report.mitreTechniques.count("T1003.001")) { base += 35; reasons.push_back("凭据窃取尝试"); }

        if (report.mitreTechniques.count("T1562.001")) { base += 20; reasons.push_back("AMSI/Defender绕过"); }
        if (report.mitreTechniques.count("T1562.006")) { base += 25; reasons.push_back("ETW绕过"); }

        if (report.mitreTechniques.count("T1564.003")) { base += 10; reasons.push_back("隐藏窗口执行"); }
        if (report.mitreTechniques.count("T1027.005")) { base += 10; reasons.push_back("命令发现滥用"); }

        if (metrics.hasFunctionNameAccess && searchRegex(lower, R"(\b(?:invoke-expression|iex)\b)")) {
            base += 20; reasons.push_back("自省混淆动态调用 (FunctionName+iex)");
        }
        if (metrics.hasDotCallChains && searchRegex(lower, R"(\biex\b|\binvoke-expression\b)")) {
            base += 10; reasons.push_back("点运算符执行动态命令");
        }

        // 行为组合加分
        if (report.mitreTechniques.count("T1620") && report.mitreTechniques.count("T1105")) {
            base += 15; reasons.push_back("反射加载+网络下载（Cobalt Strike特征）");
        }
        if (report.mitreTechniques.count("T1003.001") && report.mitreTechniques.count("T1055")) {
            base += 20; reasons.push_back("凭据窃取与进程注入组合");
        }

        // 混淆放大
        int obf = metrics.totalObfuscationPoints;
        if (obf >= 10) {
            if (base > 0) {
                double multiplier = (obf >= 15) ? 1.6 : 1.4;
                base = static_cast<int>(base * multiplier);
                reasons.push_back("高度混淆增强恶意行为权重");
            }
            else {
                base += 12;
                reasons.push_back("高度混淆（可疑）");
            }
        }
        else if (obf >= 4 && base > 0) {
            base += 4;
            reasons.push_back("轻度混淆");
        }

        // 基础误报抑制
        if (report.apiCalls.size() <= 3 && report.mitreTechniques.empty() && base > 15) {
            base = std::min(base, 20);
            reasons.push_back("管理特征明显，降低风险");
        }

        report.riskScore = std::min(base, 100);

        if (report.riskScore >= 30 && report.mitreTechniques.empty() && base < 30) {
            report.riskScore = std::min(report.riskScore, 25);
        }
    }

private:
    // 专门误报抑制：检测常见无恶意的管理脚本模式
    void reduceFalsePositives(RiskReport& report, const std::string& script) {
        const std::string lower = report.scriptLower;

        // 如果只是简单的 Get-* 命令，没有明显恶意行为，大幅降分
        bool onlyGetCommands = !searchRegex(lower, R"(\b(?:Set-|Remove-|New-|Invoke-|Start-|Stop-|Add-|Clear-)\b)")
            && searchRegex(lower, R"(\bGet-\w+\b)");
        bool noNetwork = !searchRegex(lower, R"(\b(?:WebClient|Invoke-WebRequest|Invoke-RestMethod|Download|Upload|TcpClient|Socket)\b)");
        bool noPersist = !searchRegex(lower, R"(\b(?:CurrentVersion\\Run|Register-ScheduledTask|New-Service|sc create)\b)");

        if (onlyGetCommands && noNetwork && noPersist && report.mitreTechniques.empty()) {
            report.riskScore = std::min(report.riskScore, 10);
            report.reasons.push_back("管理脚本（仅查询操作）降级");
        }

        // 常规软件部署脚本（如安装、配置文件修改）降级
        if (searchRegex(lower, R"(\b(?:Install-|Uninstall-|Update-|Configure-)\w+\b)") && report.riskScore > 20) {
            report.riskScore = std::min(report.riskScore, 20);
            report.reasons.push_back("软件部署脚本降级");
        }
    }
};

// ===================== CMD 检测器 =====================
class CMDDetector : public LanguageDetector {
public:
    RiskReport analyze(const std::string& script) override {
        originalScript = script;  // 保存原始脚本，供 applyRules 中某些需要原始大小写的函数使用
        RiskReport report;
        report.language = ScriptLanguage::CMD;
        report.scriptLower = toLower(script);

        report.riskScore = scoreObfuscation(script);
        simulate(script, report);
        applyRules(report);
        report.family = FamilyClassifier::classify(report.riskScore, report.mitreTechniques,
            report.apiCalls, report.scriptLower);
        report.isMalicious = (report.riskScore >= 30);
        if (report.riskScore >= 80) report.riskLevel = "CRITICAL";
        else if (report.riskScore >= 60) report.riskLevel = "HIGH";
        else if (report.riskScore >= 30) report.riskLevel = "MEDIUM";
        else report.riskLevel = "LOW";
        return report;
    }

protected:
    std::string originalScript;

    int scoreObfuscation(const std::string& script) override {
        int score = 0;
        const std::string lower = toLower(script);

        // --- 原有混淆项 ---
        if (searchRegex(script, R"(%\~[a-zA-Z0-9]+)")) score += 2;
        if (countRegexMatches(script, R"(%\w+%)") > 10) score += 3;
        if (countRegexMatches(script, R"(!\w+!)") > 3) score += 2;
        if (searchRegex(script, R"(set\s+\w+=[^&\|]*%\w+%)")) score += 2;
        int caretCount = std::count(script.begin(), script.end(), '^');
        if (caretCount > 10) score += 2;
        else if (caretCount > 5) score += 1;
        int upperCount = std::count_if(script.begin(), script.end(), ::isupper);
        int alphaCount = std::count_if(script.begin(), script.end(), ::isalpha);
        if (alphaCount > 0 && upperCount > alphaCount * 0.5) score += 3;
        if (searchRegex(script, R"(\bfor\s+/f\b)") && countRegexMatches(script, R"(%%[a-z])") > 2) score += 2;
        if (lower.find("findstr") != std::string::npos) score += 1;
        if (countRegexMatches(script, R"(%\w+:\~\d+,\d+%)") > 2) score += 2;
        if (countRegexMatches(script, R"(%\w+:\w+=\w+%)") > 2) score += 1;

        // --- 增强混淆 ---
        if (hasKeywordSplitByEmptyVars(script)) score += 10;
        if (searchRegex(script, R"(%\w+%%\w+%%\w+%)")) score += 4;
        if (countPattern(script, R"(set\s+\w+=[A-Za-z0-9+/]{100,})") > 0) score += 6;
        if (searchRegex(script, R"(%\w+:\~\d+,\d+%)")) {
            score += 4;
            if (searchRegex(script, R"([a-zA-Z]%[a-zA-Z0-9_]+:\~\d+,\d+%[a-zA-Z]+\.exe)")) score += 5;
        }

        return std::min(score, 35);
    }

    void simulate(const std::string& script, RiskReport& report) override {
        std::string lower = report.scriptLower;

        const std::vector<CmdPattern> patterns = {
            {R"(\b(?:powershell|pwsh)\b)", "powershell", "T1059.001"},
            {R"(\bwscript\b)", "wscript", "T1204.002"},
            {R"(\bcscript\b)", "cscript", "T1204.002"},
            {R"(\bmshta\b)", "mshta", "T1218.005"},
            {R"(\brundll32\b)", "rundll32", "T1218.011"},
            {R"(\bregsvr32\b)", "regsvr32", "T1218.010"},
            {R"(\bcmstp\b)", "cmstp", "T1218.003"},
            {R"(\bwmic\b)", "wmic", "T1047"},
            {R"(\bcertutil\b)", "certutil", "T1105"},
            {R"(\bbitsadmin\b)", "bitsadmin", "T1197"},
            {R"(\bschtasks\b)", "schtasks", "T1053.005"},
            {R"(\bsc\b)", "sc", "T1543.003"},
            {R"(\bnet\s+user\b)", "net user", "T1136.001"},
            {R"(\bnet\s+localgroup\b)", "net localgroup", "T1136.001"},
            {R"(\breg\s+add\b)", "reg add", "T1547.001"},
            {R"(\breg\s+delete\b)", "reg delete", "T1070.001"},
            {R"(\bvssadmin\b)", "vssadmin", "T1490"},
            {R"(\bwmic\s+shadowcopy\b)", "wmic shadowcopy", "T1490"},
            {R"(\bfsutil\b)", "fsutil", "T1070.001"},
            {R"(\bwevtutil\b)", "wevtutil", "T1070.001"},
            {R"(\battrib\b)", "attrib", "T1564.001"},
            {R"(\bicacls\b)", "icacls", "T1222.001"},
            {R"(\btakeown\b)", "takeown", "T1222.001"},
            {R"(\bnetsh\s+advfirewall\b)", "netsh advfirewall", "T1562.004"},
            {R"(\\start\s+\"\"\b)", "start \"\"", "T1105"},
            {R"(\bnet\s+share\b)", "net share", "T1021.002"},
            {R"(\bmofcomp\b)", "mofcomp", "T1546.003"},
            {R"(\bpowershell\s+-\s*(?:enc|ec|EncodedCommand)\b)", "powershell -enc", "T1059.001"},
            // 新增：隐藏 Powershell
            {R"(\bpowershell\b.*-windowstyle\s+hidden)", "hidden-powershell", "T1059.001"},
        };

        for (const auto& p : patterns) {
            if (searchRegex(lower, p.regex)) {
                report.apiCalls.push_back(p.api);
                report.mitreTechniques.insert(p.tech);
            }
        }

        if (lower.find("certutil") != std::string::npos && lower.find("-urlcache") != std::string::npos)
            report.network.push_back("Certutil 下载");
        if (lower.find("bitsadmin") != std::string::npos && lower.find("/transfer") != std::string::npos)
            report.network.push_back("Bitsadmin 下载");
        if (lower.find("start ") != std::string::npos && lower.find("http") != std::string::npos)
            report.network.push_back("下载并执行");
        if (searchRegex(script, R"(>+\s*\w+\.(?:exe|dll|vbs|ps1|bat|scr))"))
            report.mitreTechniques.insert("T1105");
        if (lower.find("reg add") != std::string::npos &&
            (lower.find("run") != std::string::npos || lower.find("currentversion") != std::string::npos))
            report.mitreTechniques.insert("T1547.001");

        if (hasKeywordSplitByEmptyVars(script)) {
            report.apiCalls.push_back("ObfuscatedCmdConstruct");
            report.mitreTechniques.insert("T1027");
            report.mitreTechniques.insert("T1059.003");
        }

        std::regex base64VarRe(R"(set\s+\w+=([A-Za-z0-9+/]{100,}))", std::regex_constants::icase);
        auto b64begin = std::sregex_iterator(script.begin(), script.end(), base64VarRe);
        auto b64end = std::sregex_iterator();
        if (std::distance(b64begin, b64end) > 0) {
            report.apiCalls.push_back("Base64BlobVar");
            report.mitreTechniques.insert("T1140");
            report.network.push_back("编码载荷存储");
        }

        if (searchRegex(script, R"(%\w+%%\w+%%\w+%)")) {
            report.apiCalls.push_back("VarConcatCmd");
            report.mitreTechniques.insert("T1059.003");
        }

        if (searchRegex(lower, R"(\bftp\b)")) {
            report.apiCalls.push_back("ftp");
            if (searchRegex(lower, R"(-s\s*:")")) {
                report.apiCalls.push_back("ftp-script");
                report.mitreTechniques.insert("T1105");
                report.network.push_back("FTP 加载远程脚本");
            }
        }

        if (searchRegex(lower, R"(start\s+PowerShell\b.*-windowstyle\s+hidden)")) {
            report.apiCalls.push_back("hidden-powershell");
            report.mitreTechniques.insert("T1564.003");
        }

        if (searchRegex(script, R"([a-zA-Z]%[a-zA-Z0-9_]+:\~\d+,\d+%[a-zA-Z]+\.exe)")) {
            report.apiCalls.push_back("EnvVarObfuscatedExe");
            report.mitreTechniques.insert("T1027");
        }

        if (searchRegex(lower, R"("%~dp0[^"]*\.(bat|ps1|vbs))")) {
            report.apiCalls.push_back("dp0-script-launch");
        }
    }

    void applyRules(RiskReport& report) override {
        int base = 0;
        auto& reasons = report.reasons;
        std::string lower = report.scriptLower;

        if (report.mitreTechniques.count("T1059.001") || searchRegex(lower, R"(\bpowershell\s+-.*(?:enc|bypass|hidden)\b)")) {
            base += 25; reasons.push_back("调用 PowerShell 执行可疑命令");
        }
        if (report.mitreTechniques.count("T1218.005")) { base += 20; reasons.push_back("使用 mshta 执行代码"); }
        if (report.mitreTechniques.count("T1218.003")) { base += 25; reasons.push_back("CMSTP 绕过执行"); }
        if (report.mitreTechniques.count("T1105")) { base += 25; reasons.push_back("网络下载恶意载荷"); }
        if (report.mitreTechniques.count("T1053.005")) { base += 25; reasons.push_back("创建计划任务持久化"); }
        if (report.mitreTechniques.count("T1136.001")) { base += 30; reasons.push_back("创建或删除本地用户/组"); }
        if (report.mitreTechniques.count("T1547.001")) { base += 20; reasons.push_back("注册表 Run 键持久化"); }
        if (report.mitreTechniques.count("T1490")) { base += 20; reasons.push_back("删除卷影副本(防恢复)"); }
        if (report.mitreTechniques.count("T1070.001")) { base += 15; reasons.push_back("清除事件日志或文件痕迹"); }
        if (report.mitreTechniques.count("T1543.003")) { base += 20; reasons.push_back("创建或修改服务"); }
        if (report.mitreTechniques.count("T1562.004")) { base += 10; reasons.push_back("修改防火墙规则"); }
        if (report.mitreTechniques.count("T1546.003")) { base += 25; reasons.push_back("MOF 编译持久化(WMI)"); }

        auto hasApiCall = [&](const std::string& api) {
            return std::find(report.apiCalls.begin(), report.apiCalls.end(), api) != report.apiCalls.end();
            };

        if (hasKeywordSplitByEmptyVars(originalScript)) {
            base += 20; reasons.push_back("使用未定义变量拆分 CMD 命令（高度混淆）");
        }

        if (report.mitreTechniques.count("T1140") && report.mitreTechniques.count("T1027")) {
            base += 20; reasons.push_back("混淆 + 编码载荷（典型下载器/加载器）");
        }
        else if (report.mitreTechniques.count("T1140")) {
            base += 12; reasons.push_back("检测到大型 Base64 编码数据块");
        }

        if (report.mitreTechniques.count("T1059.003") && !report.mitreTechniques.count("T1059.001")) {
            base += 15; reasons.push_back("动态变量拼接构造 CMD 命令");
        }

        if (report.mitreTechniques.count("T1105") && hasApiCall("ftp-script")) {
            base += 20; reasons.push_back("通过 FTP -s 执行远程脚本");
        }

        if (report.mitreTechniques.count("T1059.001") && report.mitreTechniques.count("T1564.003")) {
            base += 25; reasons.push_back("隐藏窗口启动 PowerShell");
        }
        else if (report.mitreTechniques.count("T1564.003")) {
            base += 10; reasons.push_back("隐藏窗口执行命令");
        }

        if (hasApiCall("EnvVarObfuscatedExe")) { base += 18; reasons.push_back("使用环境变量截取混淆可执行文件名"); }
        if (hasApiCall("dp0-script-launch")) { base += 12; reasons.push_back("从当前目录加载 .bat/.ps1 文件"); }
        if (hasApiCall("hidden-powershell") && hasApiCall("dp0-script-launch")) {
            base += 10; reasons.push_back("隐藏执行同目录 PowerShell 脚本");
        }

        int obf = report.riskScore;
        if (obf >= 12) {
            if (base > 0) {
                base = static_cast<int>(base * 1.4);
                reasons.push_back("CMD 脚本高度混淆且具备恶意行为");
            }
            else {
                base += 14;
                reasons.push_back("CMD 脚本高度混淆（需紧急关注）");
            }
        }
        else if (obf >= 5 && base > 0) {
            base += 5; reasons.push_back("CMD 脚本轻度混淆");
        }

        if (report.apiCalls.size() >= 5 && base > 0) {
            base += 10; reasons.push_back("使用多个可疑命令行工具");
        }

        report.riskScore = std::min(base, 100);

        // [OPTIMIZATION] 误报抑制：常见系统查询命令大幅降级
        bool onlyQuery = searchRegex(lower, R"(\b(?:net\s+view|net\s+share|net\s+use|sc\s+query|schtasks\s+\/query|reg\s+query)\b)")
            && !searchRegex(lower, R"(\b(?:net\s+user\s+\w+\s+\/add|reg\s+add|schtasks\s+\/create|sc\s+create)\b)");
        if (onlyQuery && report.riskScore >= 30) {
            report.riskScore = std::min(report.riskScore, 20);
            reasons.push_back("系统查询命令，降级");
        }

        if (report.riskScore >= 30 && report.mitreTechniques.empty() && base < 30) {
            if (report.mitreTechniques.count("T1140") == 0 && !hasKeywordSplitByEmptyVars(originalScript)) {
                report.riskScore = std::min(report.riskScore, 25);
            }
        }
    }

private:
    struct CmdPattern {
        std::string regex;
        std::string api;
        std::string tech;
    };

    bool hasKeywordSplitByEmptyVars(const std::string& script) const {
        static const std::vector<std::string> patterns = {
            R"(s%[^%]+%e%[^%]+%t)",
            R"(e%[^%]+%c%[^%]+%h%[^%]+%o)",
            R"(t%[^%]+%y%[^%]+%p%[^%]+%e)",
            R"(c%[^%]+%o%[^%]+%p%[^%]+%y)",
            R"(s%[^%]+%t%[^%]+%a%[^%]+%r%[^%]+%t)",
            R"(c%[^%]+%a%[^%]+%l%[^%]+%l)",
        };
        for (const auto& p : patterns) {
            if (searchRegex(script, p)) return true;
        }
        return false;
    }

    static int countPattern(const std::string& text, const std::string& pattern) {
        std::regex re(pattern, std::regex_constants::icase);
        auto begin = std::sregex_iterator(text.begin(), text.end(), re);
        auto end = std::sregex_iterator();
        return static_cast<int>(std::distance(begin, end));
    }
};

// ===================== VBS 检测器 =====================
class VBSDetector : public LanguageDetector {
public:
    RiskReport analyze(const std::string& script) override {
        RiskReport report;
        report.language = ScriptLanguage::VBS;
        report.scriptLower = toLower(script);

        report.riskScore = scoreObfuscation(script);
        simulate(script, report);
        applyRules(report);
        report.family = FamilyClassifier::classify(report.riskScore, report.mitreTechniques,
            report.apiCalls, report.scriptLower);
        report.isMalicious = (report.riskScore >= 30);
        if (report.riskScore >= 80) report.riskLevel = "CRITICAL";
        else if (report.riskScore >= 60) report.riskLevel = "HIGH";
        else if (report.riskScore >= 30) report.riskLevel = "MEDIUM";
        else report.riskLevel = "LOW";
        return report;
    }

protected:
    int scoreObfuscation(const std::string& script) override {
        int score = 0;
        const std::string lower = toLower(script);

        if (searchRegex(script, R"(\bchr\s*\(&?\w+\)\s*&)")) score += 3;
        if (countRegexMatches(script, R"(\bchr\b)") > 5) score += 3;
        if (searchRegex(script, R"(\bexecute(?:global)?\s+)")) score += 3;
        if (searchRegex(script, R"(\beval\s*\()")) score += 3;
        if (searchRegex(script, R"(replace\s*\([^,]+,[^,]+,[^,]+\))")) score += 1;
        if (countRegexMatches(script, R"(\b[a-z_][a-z0-9_]{15,}\b)") > 3) score += 2;
        if (searchRegex(script, R"(\bmid\s*\([^)]*\))")) score += 1;
        if (lower.find("strreverse") != std::string::npos) score += 1;
        if (std::count(script.begin(), script.end(), '_') > 10) score += 1;
        if (lower.find("base64") != std::string::npos) score += 2;
        if (lower.find("chrw") != std::string::npos) score += 1;

        return std::min(score, 25);
    }

    void simulate(const std::string& script, RiskReport& report) override {
        std::string lower = report.scriptLower;

        struct ComObj {
            std::string name;
            std::string technique;
            std::string description;
        };
        const std::vector<ComObj> objects = {
            {"wscript.shell", "T1059.005", "WScript.Shell 执行"},
            {"shell.application", "T1218.005", "Shell.Application 打开文件/执行"},
            {"msxml2.xmlhttp", "T1105", "XMLHTTP 请求"},
            {"microsoft.xmlhttp", "T1105", "XMLHTTP 请求"},
            {"winhttp.winhttprequest.5.1", "T1105", "WinHTTP 请求"},
            {"adodb.stream", "T1105", "ADODB.Stream 写入/下载"},
            {"scripting.filesystemobject", "T1070.001", "FileSystemObject 操作"},
            {"wbemscripting.swbemlocator", "T1047", "WMI 连接"},
            {"schedule.service", "T1053.005", "计划任务操作"},
            {"cdo.message", "T1105", "CDO 邮件外传"},
            {"microsoft.xmldom", "T1105", "XML DOM 文档处理"},
            {"mshtml", "T1204.002", "浏览器交互"}
        };

        for (const auto& obj : objects) {
            if (lower.find(obj.name) != std::string::npos) {
                report.apiCalls.push_back(obj.name);
                if (obj.technique != "T1059.005")
                    report.mitreTechniques.insert(obj.technique);
            }
        }

        bool hasShellObj = (lower.find("wscript.shell") != std::string::npos);
        bool hasShellApp = (lower.find("shell.application") != std::string::npos);
        bool hasRunExec = false;
        std::regex runExecRe(R"(\.(?:Run|Exec)\s*\()", std::regex_constants::icase);
        std::string::const_iterator searchStart(script.cbegin());
        std::smatch match;
        while (std::regex_search(searchStart, script.cend(), match, runExecRe)) {
            std::string prefix = script.substr(0, match.position() + (searchStart - script.cbegin()));
            if (prefix.find("ExecQuery") == std::string::npos) {
                hasRunExec = true;
                break;
            }
            searchStart = match.suffix().first;
        }
        if (hasRunExec && (hasShellObj || hasShellApp)) {
            report.mitreTechniques.insert("T1059.005");
            report.apiCalls.push_back("Shell.Run/Exec");
        }

        if ((lower.find("xmlhttp") != std::string::npos || lower.find("winhttp") != std::string::npos) &&
            (lower.find("adodb.stream") != std::string::npos || lower.find("savetofile") != std::string::npos)) {
            report.network.push_back("HTTP 下载链");
            report.mitreTechniques.insert("T1105");
        }

        if (searchRegex(script, R"(\b(?:RegWrite)\b)"))
            report.mitreTechniques.insert("T1547.001");

        if (lower.find("createobject") != std::string::npos && lower.find("filesystemobject") != std::string::npos) {
            if (lower.find("opentextfile") != std::string::npos || lower.find("createtextfile") != std::string::npos)
                report.mitreTechniques.insert("T1105");
        }

        if (lower.find("wbemscripting.swbemlocator") != std::string::npos)
            report.mitreTechniques.insert("T1047");
        if (lower.find("schedule.service") != std::string::npos)
            report.mitreTechniques.insert("T1053.005");
        if (lower.find("cdo.message") != std::string::npos)
            report.mitreTechniques.insert("T1041");
    }

    void applyRules(RiskReport& report) override {
        int base = 0;
        auto& reasons = report.reasons;
        std::string lower = report.scriptLower;

        if (report.mitreTechniques.count("T1105")) { base += 25; reasons.push_back("VBS 通过网络下载文件"); }
        if (report.mitreTechniques.count("T1059.005")) { base += 30; reasons.push_back("使用 WScript.Shell 执行任意命令"); }
        if (report.mitreTechniques.count("T1547.001")) { base += 25; reasons.push_back("写入注册表 Run 键持久化"); }
        if (report.mitreTechniques.count("T1053.005")) { base += 20; reasons.push_back("通过计划任务持久化"); }
        if (report.mitreTechniques.count("T1047")) { base += 25; reasons.push_back("连接 WMI 进行远程操作"); }
        if (report.mitreTechniques.count("T1070.001")) { base += 15; reasons.push_back("文件系统对象可疑文件操作"); }
        if (lower.find("sendkeys") != std::string::npos) { base += 15; reasons.push_back("使用 SendKeys 模拟输入"); }
        if (report.mitreTechniques.count("T1041")) { base += 20; reasons.push_back("尝试通过邮件外传数据"); }

        if (report.apiCalls.size() >= 3) { base += 10; reasons.push_back("组合多个可疑 VBS 对象"); }

        int obf = report.riskScore;
        if (obf >= 12) {
            if (base > 0) {
                base = static_cast<int>(base * 1.4);
                reasons.push_back("VBS 代码高度混淆且存在恶意行为");
            }
            else {
                base += 12; reasons.push_back("VBS 代码高度混淆 (需关注)");
            }
        }
        else if (obf >= 5 && base > 0) {
            base += 5; reasons.push_back("VBS 代码存在轻度混淆");
        }

        report.riskScore = std::min(base, 100);

        // 误报抑制：仅有 FileSystemObject 但无其他危险行为则降级
        if (report.apiCalls.size() == 1 && lower.find("scripting.filesystemobject") != std::string::npos &&
            report.mitreTechniques.size() <= 1 && report.riskScore >= 30) {
            report.riskScore = std::min(report.riskScore, 20);
            reasons.push_back("单纯文件操作降级");
        }

        if (report.riskScore >= 30 && report.mitreTechniques.empty() && base < 30) {
            report.riskScore = std::min(report.riskScore, 25);
        }

        bool onlyShellObj = report.apiCalls.size() == 1 &&
            (lower.find("wscript.shell") != std::string::npos || lower.find("shell.application") != std::string::npos);
        bool onlyShellTech = report.mitreTechniques.size() == 1 &&
            (report.mitreTechniques.count("T1059.005") || report.mitreTechniques.count("T1218.005"));
        if (onlyShellObj && onlyShellTech && report.riskScore >= 30) {
            report.riskScore = std::min(report.riskScore, 20);
            reasons.push_back("单纯 Shell 对象执行 benign 命令降级");
        }
    }
};

// ===================== JavaScript 检测器 =====================
class JavaScriptDetector : public LanguageDetector {
public:
    RiskReport analyze(const std::string& script) override {
        RiskReport report;
        report.language = ScriptLanguage::JavaScript;
        report.scriptLower = toLower(script);

        report.riskScore = scoreObfuscation(script);
        simulate(script, report);
        applyRules(report);

        report.family = FamilyClassifier::classify(
            report.riskScore, report.mitreTechniques,
            report.apiCalls, report.scriptLower);
        report.isMalicious = (report.riskScore >= 30);
        if (report.riskScore >= 80) report.riskLevel = "CRITICAL";
        else if (report.riskScore >= 60) report.riskLevel = "HIGH";
        else if (report.riskScore >= 30) report.riskLevel = "MEDIUM";
        else report.riskLevel = "LOW";
        return report;
    }

protected:
    int scoreObfuscation(const std::string& script) override {
        int score = 0;
        const std::string lower = toLower(script);

        if (searchRegex(script, R"(\beval\s*\()")) score += 3;
        if (searchRegex(script, R"(\bFunction\s*\(\s*\)\s*\{)")) score += 3;
        if (lower.find("settimeout") != std::string::npos || lower.find("setinterval") != std::string::npos) score += 1;

        if (searchRegex(script, R"(String\.fromCharCode\s*\()")) score += 3;
        if (countRegexMatches(script, R"(String\.fromCharCode)") > 2) score += 2;

        if (lower.find("unescape") != std::string::npos) score += 2;
        if (lower.find("decodeuri") != std::string::npos) score += 1;
        if (lower.find("atob") != std::string::npos) score += 3;
        if (lower.find("btoa") != std::string::npos) score += 1;

        if (countRegexMatches(script, R"(\+\s*\"[^\"]*\")") > 5) score += 2;
        if (countRegexMatches(script, R"(\b[a-zA-Z_$][a-zA-Z0-9_$]{20,}\b)") > 3) score += 2;

        if (searchRegex(script, R"(\\x[0-9a-fA-F]{2})")) score += 1;
        if (searchRegex(script, R"(\\u[0-9a-fA-F]{4})")) score += 1;

        if (countRegexMatches(script, R"(/\*.*?\*/)") > 3) score += 1;
        if (searchRegex(script, R"(new\s+ActiveXObject\s*\(\s*\"[^\"]*\"\s*\+\s*\"[^\"]*\")")) score += 4;

        return std::min(score, 30);
    }

    void simulate(const std::string& script, RiskReport& report) override {
        std::string lower = report.scriptLower;

        struct JsObj {
            std::string regex;
            std::string api;
            std::string technique;
        };
        const std::vector<JsObj> objects = {
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"WScript\.Shell\"\s*\))",
             "WScript.Shell", "T1059.005"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"Shell\.Application\"\s*\))",
             "Shell.Application", "T1218.005"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"MSXML2\.XMLHTTP\"\s*\))",
             "MSXML2.XMLHTTP", "T1105"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"Microsoft\.XMLHTTP\"\s*\))",
             "Microsoft.XMLHTTP", "T1105"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"WinHTTP\.WinHTTPRequest\.5\.1\"\s*\))",
             "WinHTTPRequest", "T1105"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"ADODB\.Stream\"\s*\))",
             "ADODB.Stream", "T1105"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"Scripting\.FileSystemObject\"\s*\))",
             "Scripting.FileSystemObject", "T1070.001"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"WbemScripting\.SWbemLocator\"\s*\))",
             "SWbemLocator", "T1047"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"Schedule\.Service\"\s*\))",
             "Schedule.Service", "T1053.005"},
            {R"((?:new\s+ActiveXObject|WScript\.CreateObject)\s*\(\s*\"CDO\.Message\"\s*\))",
             "CDO.Message", "T1041"},
        };

        for (const auto& obj : objects) {
            if (searchRegex(lower, obj.regex)) {
                report.apiCalls.push_back(obj.api);
                report.mitreTechniques.insert(obj.technique);
            }
        }

        if (searchRegex(script, R"(\brequire\s*\(\s*['\"](child_process|http|fs)['\"]\))")) {
            report.apiCalls.push_back("Node.require");
            if (lower.find("exec") != std::string::npos)
                report.mitreTechniques.insert("T1059.005");
        }

        if (report.mitreTechniques.count("T1105") && (lower.find("adodb.stream") != std::string::npos ||
            (lower.find("savetofile") != std::string::npos && lower.find(".open") != std::string::npos))) {
            report.network.push_back("HTTP 下载并写入文件");
            report.mitreTechniques.insert("T1105");
        }

        if (searchRegex(script, R"(\.RegWrite\s*\()")) report.mitreTechniques.insert("T1547.001");
        if (lower.find("sendkeys") != std::string::npos) report.mitreTechniques.insert("T1056.001");
        if (lower.find("wscript.sleep") != std::string::npos && scoreObfuscation(script) > 5)
            report.mitreTechniques.insert("T1497.003");
    }

    void applyRules(RiskReport& report) override {
        int base = 0;
        auto& reasons = report.reasons;
        std::string lower = report.scriptLower;

        if (report.mitreTechniques.count("T1059.005")) { base += 30; reasons.push_back("JavaScript 命令执行 (WScript.Shell)"); }
        if (report.mitreTechniques.count("T1218.005")) { base += 25; reasons.push_back("使用 Shell.Application 执行程序"); }
        if (report.mitreTechniques.count("T1105")) { base += 25; reasons.push_back("JavaScript 下载文件"); }
        if (report.mitreTechniques.count("T1547.001")) { base += 25; reasons.push_back("JavaScript 写入注册表持久化"); }
        if (report.mitreTechniques.count("T1053.005")) { base += 20; reasons.push_back("JavaScript 操作计划任务"); }
        if (report.mitreTechniques.count("T1070.001")) { base += 15; reasons.push_back("JavaScript 文件系统操作(可疑)"); }
        if (report.mitreTechniques.count("T1041")) { base += 20; reasons.push_back("JavaScript 尝试邮件外传数据"); }
        if (report.mitreTechniques.count("T1056.001")) { base += 20; reasons.push_back("JavaScript 模拟键盘输入(记录)"); }
        if (report.apiCalls.size() >= 3) { base += 10; reasons.push_back("JavaScript 组合多个可疑对象"); }

        int obf = report.riskScore;
        if (obf >= 12) {
            if (base > 0) {
                base = static_cast<int>(base * 1.4);
                reasons.push_back("JavaScript 高度混淆且存在恶意行为");
            }
            else {
                base += 12; reasons.push_back("JavaScript 高度混淆(需关注)");
            }
        }
        else if (obf >= 5 && base > 0) {
            base += 5; reasons.push_back("JavaScript 存在轻度混淆");
        }

        report.riskScore = std::min(base, 100);

        // 误报抑制：纯 eval 但无任何危险对象则降级
        if (obf >= 3 && report.apiCalls.empty() && report.mitreTechniques.empty() && report.riskScore >= 30) {
            report.riskScore = std::min(report.riskScore, 20);
            reasons.push_back("无危险对象纯混淆降级");
        }

        if (report.riskScore >= 30 && report.mitreTechniques.empty() && base < 30) {
            report.riskScore = std::min(report.riskScore, 25);
        }

        bool onlyShellObj = report.apiCalls.size() == 1 &&
            (lower.find("wscript.shell") != std::string::npos || lower.find("shell.application") != std::string::npos);
        bool onlyShellTech = report.mitreTechniques.size() == 1 &&
            (report.mitreTechniques.count("T1059.005") || report.mitreTechniques.count("T1218.005"));
        if (onlyShellObj && onlyShellTech && report.riskScore >= 30) {
            report.riskScore = std::min(report.riskScore, 20);
            reasons.push_back("单纯 Shell 对象执行 benign 命令降级");
        }
    }
};

// ============================================================
// 语言自动识别
// ============================================================
inline ScriptLanguage detectLanguage(const std::string& script) {
    std::string lower = toLower(script);

    bool hasCppIndicator = searchRegex(script, R"(#\s*include|#\s*define|int\s+main\s*\(|std::|printf|scanf|using\s+namespace)");
    if (hasCppIndicator) {
        // 仅当存在极强脚本特征时才继续分析（例如 PowerShell 变量、CMD 的 echo off）
        if (!searchRegex(script, R"(\$(?:[a-zA-Z_]\w*|\{))") &&
            lower.find("echo off") == std::string::npos &&
            lower.find("@echo off") == std::string::npos) {
            return ScriptLanguage::Unknown;
        }
    }

    // PowerShell : 变量前缀 $、cmdlet 命名习惯、或特定关键字
    if (searchRegex(script, R"(\$(?:[a-zA-Z_]\w*|\{))") ||
        searchRegex(lower, R"(\b(invoke-|get-|set-|new-|start-|stop-)\w+\b)") ||
        lower.find("cmdlet") != std::string::npos) {
        return ScriptLanguage::PowerShell;
    }

    // 2. CMD : 批处理标志性首行、行标签
    if (lower.find("echo off") != std::string::npos ||
        lower.find("@echo off") != std::string::npos ||
        searchRegex(script, R"(^:\w+$)")) {          // 批处理标签，如 :again
        return ScriptLanguage::CMD;
    }

    // --- VBS 特征评分 ---
    int vbsScore = 0;
    // 典型 VBS 关键字（使用正则提高准确性）
    if (searchRegex(script, R"(\bsub\s+\w+\s*\()"))      vbsScore++;
    if (searchRegex(script, R"(\bfunction\s+\w+\s*\()")) vbsScore++;
    if (searchRegex(script, R"(\bdim\s+\w+)"))          vbsScore++;
    if (searchRegex(script, R"(\bset\s+\w+\s*=)"))      vbsScore++;  // 赋值语句，避免普通单词
    // 高权重特征（ WScript / MsgBox / CreateObject 在 VBS 中非常常见）
    if (lower.find("wscript.") != std::string::npos)    vbsScore += 2;
    if (lower.find("msgbox") != std::string::npos)      vbsScore += 2;
    if (lower.find("createobject") != std::string::npos) vbsScore++;  // 但在 JS 中也可能出现，故只加 1

    // 当 VBS 特征足够明确，且没有明显 JavaScript 专属特征时，返回 VBS
    if (vbsScore >= 2) {
        // 排除 JS 的强特征：var 声明或 ActiveXObject 直接调用
        if (!searchRegex(script, R"(\bvar\s+\w+\s*=)") &&
            !searchRegex(script, R"(\bActiveXObject\b)") &&
            !searchRegex(script, R"(\bWScript\.)") &&
            !searchRegex(script, R"(\bWSH\.)")) {
            return ScriptLanguage::VBS;
        }
        // 否则两者特征共存时，进入 JS 进一步判断
    }

    // --- JavaScript 特征评分 ---
    bool isJS = false;
    // 1) 文件内容直接声明为 JavaScript
    if (lower.find("javascript") != std::string::npos) isJS = true;
    // 2) Windows Script Host 对象（ActiveXObject, WScript, WSH）强烈指示 WSH 环境 JS
    else if (searchRegex(script, R"(\bActiveXObject\b)") ||
        searchRegex(script, R"(\bWScript\.)") ||
        searchRegex(script, R"(\bWSH\.)")) isJS = true;
    // 3) 通用 JS 特征组合：var 声明 + eval / function 定义
    else if (searchRegex(script, R"(\bvar\s+\w+\s*=)") &&
        searchRegex(script, R"(\beval\s*\()")) isJS = true;
    else if (searchRegex(script, R"(\bfunction\s+\w+\s*\()") &&
        searchRegex(script, R"(\bvar\s+\w+\s*=)")) isJS = true;

    if (isJS) return ScriptLanguage::JavaScript;

    if (vbsScore >= 1) {
        // 仅有一个弱 VBS 特征且无其他语言明确指示，保守返回 Unknown
        return ScriptLanguage::Unknown;
    }

    return ScriptLanguage::Unknown;
}

// ============================================================
// 静态内容指纹规则（原 Behavior Sandbox 中的启发式迁移至此）
//
// 高度混淆的脚本（_0x hex-array JS、字符串拆分 VBS、XOR hex 解码
// dropper、Unicode 死代码填充等）会使行为模拟解释器失去作用，行为链
// 检测器看不到任何可判定内容。这里对原始脚本内容做纯静态特征匹配，
// 作为行为链检测之前的第一道语言无关快速防线（含 LNK/HTA/二进制
// 混淆样本）。与语言检测器并行：先跑指纹，未命中再走语言检测器。
// ============================================================
namespace ContentFingerprint {

inline bool Contains(const std::string& s, const std::string& needle) {
    return s.find(needle) != std::string::npos;
}

inline std::string Trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

// Detect Windows shortcut (.lnk) binary by its header magic.
inline bool IsLnkContent(const std::string& s) {
    if (s.size() < 20) return false;
    const auto* p = reinterpret_cast<const unsigned char*>(s.data());
    return p[0] == 0x4C && p[1] == 0x00 && p[2] == 0x00 && p[3] == 0x00 &&
           p[4] == 0x01 && p[5] == 0x14 && p[6] == 0x02 && p[7] == 0x00 &&
           p[12] == 0xC0 && p[19] == 0x46;
}

// Extract a compact ASCII string from LNK binary content. LNK stores
// strings as UTF-16LE, so drop NUL bytes and collapse non-printable
// bytes into single spaces (avoids alignment assumptions).
inline std::string ExtractAsciiFromUtf16(const std::string& s) {
    std::string raw;
    raw.reserve(s.size());
    for (unsigned char c : s) {
        if (c == 0x00) continue;
        if (c >= 0x20 && c < 0x7f) raw.push_back(static_cast<char>(c));
        else raw.push_back(' ');
    }
    std::string out;
    out.reserve(raw.size());
    bool prevSpace = true;
    for (char c : raw) {
        if (c == ' ') {
            if (!prevSpace) { out.push_back(' '); prevSpace = true; }
        } else {
            out.push_back(c);
            prevSpace = false;
        }
    }
    return out;
}

// True if the content is an HTA application: HTML wrapper with an
// inline <script> block (VBScript/JScript) executed by mshta.exe.
inline bool IsHtaContent(const std::string& s) {
    std::string low = toLower(s);
    if (!Contains(low, "<html") && !Contains(low, "<head") &&
        !Contains(low, "<body") && !Contains(low, "<script")) return false;
    return Contains(low, "language=\"vbscript\"") ||
           Contains(low, "language='vbscript'") ||
           Contains(low, "language=\"jscript\"") ||
           Contains(low, "language='jscript'") ||
           Contains(low, "language=\"javascript\"") ||
           Contains(low, "<script>") ||
           Contains(low, "mshta") ||
           Contains(low, "hta:application");
}

// Case-insensitive pattern search that works with both UTF-8 and UTF-16LE.
inline bool IsUTF16LE(const std::string& s) {
    if (s.size() >= 2 && (unsigned char)s[0] == 0xFF && (unsigned char)s[1] == 0xFE)
        return true;
    if (s.size() < 64) return false;
    int zeroCount = 0;
    for (size_t i = 0; i < std::min(s.size(), (size_t)4096); ++i) {
        if ((unsigned char)s[i] == 0) ++zeroCount;
    }
    size_t sampleSize = std::min(s.size(), (size_t)4096);
    return zeroCount * 4 > (int)sampleSize;
}

// Search for an ASCII pattern in a string, handling both UTF-8 and UTF-16LE.
inline bool ContainsPattern(const std::string& s, const std::string& pattern) {
    if (pattern.empty()) return false;
    if (s.find(pattern) != std::string::npos) return true;
    if (!IsUTF16LE(s)) return false;
    size_t plen = pattern.size();
    size_t si = 0;
    size_t pi = 0;
    while (si + 1 < s.size() && pi < plen) {
        unsigned char target = static_cast<unsigned char>(pattern[pi]);
        if ((unsigned char)s[si] == target && (unsigned char)s[si + 1] == 0x00) {
            ++pi;
        }
        si += 2;
    }
    return pi >= plen;
}

inline bool ContainsPatternCI(const std::string& s, const std::string& pattern) {
    if (pattern.empty()) return false;
    std::string lowPattern;
    lowPattern.reserve(pattern.size());
    for (char c : pattern) {
        lowPattern.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (IsUTF16LE(s)) return ContainsPattern(s, lowPattern);
    std::string lowContent;
    lowContent.reserve(s.size());
    for (char c : s) {
        lowContent.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return lowContent.find(lowPattern) != std::string::npos;
}

// Detect the JSON-data-loader family (constructor-style loader with
// obfuscated namespace ending in "UUU" padding + CPU feature lists).
inline bool IsJSONLoaderJS(const std::string& s) {
    if (s.size() > 10 * 1024 * 1024) return false;
    std::string low = toLower(s);
    bool hasLoaderDirective = Contains(low, "\"use ") && Contains(low, "uuuu");
    bool hasJSONBegin = Contains(low, "${json:begin}") || Contains(low, "json:begin");
    if (!hasLoaderDirective && !hasJSONBegin) return false;
    bool hasCPUList = Contains(low, "aesni") || Contains(low, "bmi") ||
                      Contains(low, "f16c") || Contains(low, "fma") ||
                      Contains(low, "movbe") || Contains(low, "sha");
    return hasCPUList;
}

// Detect Unicode-dead-code padding (repeated long non-ASCII string
// concatenations — common anti-analysis noise layer). UTF-8 & UTF-16LE.
inline bool HasUnicodePadding(const std::string& s) {
    if (s.size() < 10000) return false;
    if (s.size() > 20 * 1024 * 1024) return false;
    bool isUTF16LE = (s.size() >= 2 &&
                      (unsigned char)s[0] == 0xFF && (unsigned char)s[1] == 0xFE);
    if (!isUTF16LE && s.size() >= 4) {
        int zeroCount = 0;
        for (size_t i = 0; i < std::min(s.size(), (size_t)4096); ++i) {
            if ((unsigned char)s[i] == 0) ++zeroCount;
        }
        if (zeroCount > 1500) isUTF16LE = true;
    }
    if (isUTF16LE) {
        int highRunLen = 0;
        for (size_t i = 0; i + 1 < s.size(); i += 2) {
            unsigned char lo = (unsigned char)s[i];
            unsigned char hi = (unsigned char)s[i+1];
            if (lo != 0 || hi != 0) {
                ++highRunLen;
                if (highRunLen >= 10) return true;
            } else {
                highRunLen = 0;
            }
        }
        return false;
    } else {
        int highRunLen = 0;
        for (unsigned char c : s) {
            if (c >= 0x80) {
                ++highRunLen;
                if (highRunLen > 30) return true;
            } else {
                highRunLen = 0;
            }
        }
        return false;
    }
}

// Detect Danish "ballas" marker string-split obfuscation in VBS.
inline bool HasDanishSplitObf(const std::string& s) {
    if (s.size() > 5 * 1024 * 1024) return false;
    int ballasCount = 0;
    size_t pos = 0;
    while ((pos = s.find("ballas", pos)) != std::string::npos) {
        ++ballasCount; ++pos;
    }
    if (ballasCount < 20) return false;
    return ContainsPatternCI(s, "get-random") || ContainsPatternCI(s, "new-guid") ||
           ContainsPatternCI(s, "start-sleep") || ContainsPatternCI(s, "out-null") ||
           ContainsPatternCI(s, "activist") || ContainsPatternCI(s, "wscript.shell") ||
           ContainsPatternCI(s, "filesystemobject") || ContainsPatternCI(s, "powershell");
}

// Detect RC4+Base64 JS packer targeting PowerShell execution.
inline bool IsRC4Base64Packer(const std::string& s) {
    if (s.size() > 5 * 1024 * 1024) return false;
    bool hasRC4Func = ContainsPatternCI(s, "_0x") && ContainsPatternCI(s, "fromcharcode") &&
                      ContainsPatternCI(s, "decodeuri");
    if (!hasRC4Func) return false;
    return ContainsPatternCI(s, "powershell") || ContainsPatternCI(s, "wscript.shell") ||
           ContainsPatternCI(s, "cmd.exe") || ContainsPatternCI(s, ".exec");
}

// Detect VBS with heavy comment-based obfuscation (prose comments
// interleaved with code) that creates WScript.Shell and executes PS.
inline bool IsCommentObfVBS(const std::string& s) {
    if (s.size() > 5 * 1024 * 1024) return false;
    bool hasVBS = ContainsPatternCI(s, "createobject") && ContainsPatternCI(s, "wscript.shell") &&
                  ContainsPatternCI(s, "execute");
    if (!hasVBS) return false;
    int commentLines = 0, codeLines = 0;
    std::istringstream iss(s);
    std::string line;
    while (std::getline(iss, line)) {
        std::string trimmed = Trim(line);
        if (trimmed.empty()) continue;
        if (trimmed[0] == '\'') ++commentLines;
        else ++codeLines;
    }
    return commentLines > codeLines / 4 && commentLines > 5;
}

struct ContentFingerprintRule {
    std::string family;
    std::function<bool(const std::string&)> matcher;
    int severity = 80;
};

inline std::vector<ContentFingerprintRule> BuildContentFingerprintRules() {
    std::vector<ContentFingerprintRule> rules;

    // ---------- JS / VBS / HTA / LNK stealer-dropper 家族 ----------
    rules.push_back({"BSD/TrojanSpy.JSDropper.Stealer",
        [](const std::string& s) -> bool {
            std::string low = toLower(s);
            if (!Contains(low, "_0x")) return false;
            if (!Contains(low, "powershell") || !Contains(low, "bypass") ||
                !Contains(low, "hidden")) return false;
            if (!Contains(low, "adodb")) return false;
            if (!Contains(low, "bin.base64") && !Contains(low, "nodetypedvalue") &&
                !Contains(low, "base64tostring")) return false;
            if (!Contains(low, ".ps1") && !Contains(low, "createtextfile")) return false;
            return true;
        }, 88});

    rules.push_back({"BSD/TrojanSpy.VBSDropper.Stealer",
        [](const std::string& s) -> bool {
            std::string low = toLower(s);
            if (!Contains(s, "UEsDBBQ")) return false;
            if (!Contains(low, "savetofile")) return false;
            if (!Contains(low, "shellexecute") &&
                !Contains(low, "shell.application")) return false;
            if (!Contains(low, "createobject")) return false;
            if (!Contains(low, "createtextfile") &&
                !Contains(low, "writeline")) return false;
            return true;
        }, 88});

    // ---------- HTA family ----------
    rules.push_back({"BSD/TrojanDownloader.HTADropper",
        [](const std::string& s) -> bool {
            if (!IsHtaContent(s)) return false;
            std::string low = toLower(s);
            if (!Contains(low, "wscript.shell")) return false;
            if (!Contains(low, "powershell") && !Contains(low, "cmd /c") &&
                !Contains(low, "cmd.exe")) return false;
            bool hasUrl = Contains(low, "http://") || Contains(low, "https://") ||
                          Contains(low, "github.com") || Contains(low, "raw.github");
            bool hasExec = Contains(low, ".run") || Contains(low, ".exec") ||
                           Contains(low, "shellexecute");
            return hasUrl && hasExec;
        }, 86});

    rules.push_back({"BSD/TrojanSpy.HTAStealer",
        [](const std::string& s) -> bool {
            if (!IsHtaContent(s)) return false;
            std::string low = toLower(s);
            if (!Contains(low, "adodb")) return false;
            if (!Contains(low, "savetofile") && !Contains(low, "writetofile") &&
                !Contains(low, "createtextfile")) return false;
            if (!Contains(low, "shellexecute") &&
                !Contains(low, "shell.application") &&
                !Contains(low, "wscript.shell")) return false;
            return Contains(low, "http://") || Contains(low, "https://") ||
                   Contains(low, "github") || Contains(low, "temp");
        }, 88});

    rules.push_back({"BSD/Trojan-Obfuscated.HTA.Generic",
        [](const std::string& s) -> bool {
            if (!IsHtaContent(s)) return false;
            std::string low = toLower(s);
            if (!Contains(low, "execute") && !Contains(low, "executeglobal")) return false;
            int obf = 0;
            if (Contains(low, "strreverse")) obf++;
            if (Contains(low, "array(") && Contains(low, "join(")) obf++;
            if (Contains(low, "chr(")) obf++;
            if (Contains(low, "replace(")) obf++;
            if (obf < 2) return false;
            if (Contains(low, "array(") && Contains(low, "join(") &&
                Contains(low, "chr(")) return true;
            return Contains(low, "powershell") || Contains(low, "cmd /c") ||
                   Contains(low, "wscript.shell") || Contains(low, "shellexecute");
        }, 84});

    rules.push_back({"BSD/Trojan.HTAWebshell",
        [](const std::string& s) -> bool {
            if (!IsHtaContent(s)) return false;
            std::string low = toLower(s);
            if (!Contains(low, "msxml2.xmlhttp") &&
                !Contains(low, "winhttp.winhttprequest") &&
                !Contains(low, "xmlhttprequest") &&
                !Contains(low, "serverxmlhttp")) return false;
            if (!Contains(low, "adodb") && !Contains(low, "filesystemobject") &&
                !Contains(low, "createtextfile")) return false;
            return Contains(low, "http://") || Contains(low, "https://");
        }, 85});

    // ---------- LNK family ----------
    rules.push_back({"BSD/TrojanDownloader.LNKDropper",
        [](const std::string& s) -> bool {
            if (!IsLnkContent(s)) return false;
            std::string asc = ExtractAsciiFromUtf16(s);
            std::string low = toLower(asc);
            if (!Contains(low, "powershell") && !Contains(low, "cmd.exe") &&
                !Contains(low, "wscript") && !Contains(low, "cscript")) return false;
            bool hasBypass = Contains(low, "-ep bypass") ||
                             Contains(low, "-executionpolicy bypass") ||
                             (Contains(low, "executionpolicy") && Contains(low, "bypass"));
            if (!hasBypass) return false;
            bool hasHidden = Contains(low, "-windowstyle hidden") ||
                             Contains(low, "-w hidden") ||
                             Contains(low, "-w 1") ||
                             (Contains(low, "-windowstyle") && Contains(low, "hidden"));
            if (!hasHidden) return false;
            return Contains(low, "iwr") || Contains(low, "invoke-webrequest") ||
                   Contains(low, "downloadfile") || Contains(low, "net.webclient") ||
                   Contains(low, "-outfile") || Contains(low, "start-bitstransfer") ||
                   Contains(low, "http");
        }, 88});

    rules.push_back({"BSD/TrojanSpy.LNKStealer",
        [](const std::string& s) -> bool {
            if (!IsLnkContent(s)) return false;
            std::string asc = ExtractAsciiFromUtf16(s);
            std::string low = toLower(asc);
            if (!Contains(low, "powershell")) return false;
            bool hasDownload = Contains(low, "iwr") ||
                               Contains(low, "invoke-webrequest") ||
                               Contains(low, "downloadfile");
            if (!hasDownload) return false;
            bool hasTemp = Contains(low, "$env:temp") ||
                           Contains(low, "%temp%") ||
                           Contains(low, "env:temp");
            if (!hasTemp) return false;
            return Contains(low, "-outfile") || Contains(low, "; &") ||
                   Contains(low, "& $") || Contains(low, "invoke") ||
                   Contains(low, "-command");
        }, 88});

    rules.push_back({"BSD/Trojan-Obfuscated.LNK.Generic",
        [](const std::string& s) -> bool {
            if (!IsLnkContent(s)) return false;
            std::string asc = ExtractAsciiFromUtf16(s);
            std::string low = toLower(asc);
            if (!Contains(low, "powershell")) return false;
            bool hasEnc = Contains(low, " -enc") ||
                          Contains(low, " -encodedcommand") ||
                          Contains(low, " -e ") ||
                          Contains(low, "-encodedcommand");
            if (!hasEnc) return false;
            return Contains(low, "hidden") || Contains(low, "-w 1") ||
                   Contains(low, "-windowstyle");
        }, 85});

    rules.push_back({"BSD/Trojan.LNKDisguised",
        [](const std::string& s) -> bool {
            if (!IsLnkContent(s)) return false;
            std::string asc = ExtractAsciiFromUtf16(s);
            std::string low = toLower(asc);
            bool hasScript = Contains(low, "powershell") ||
                             Contains(low, "cmd.exe") ||
                             Contains(low, "wscript") ||
                             Contains(low, "cscript") ||
                             Contains(low, "mshta");
            if (!hasScript) return false;
            bool hasDisguiseIcon = Contains(low, "imageres.dll") ||
                                   Contains(low, "shell32.dll") ||
                                   Contains(low, "shell32") ||
                                   Contains(low, "imageres");
            bool hasHidden = Contains(low, "hidden") ||
                             Contains(low, "-windowstyle") ||
                             Contains(low, "-w 1");
            return hasDisguiseIcon && hasHidden;
        }, 82});

    // WinKiller MBR/DBR writer: raw content fingerprint for scripts that
    // attempt direct write to physical disk (MBR/DBR).
    rules.push_back({"BSD/Trojan-Dropper.Win32.MBRWriter",
        [](const std::string& s) -> bool {
            std::string low = toLower(s);
            if (!Contains(low, "physicaldrive") &&
                !Contains(low, "device\\harddisk") &&
                !Contains(low, "/dev/sd") &&
                !Contains(low, "/dev/nvme") &&
                !Contains(low, "/dev/rdisk")) return false;
            bool hasWriteCmd =
                Contains(low, " of=") ||
                Contains(low, "out-file") ||
                Contains(low, "set-content") ||
                Contains(low, "add-content") ||
                Contains(low, "openwrite") ||
                Contains(low, "[io.file]::create") ||
                Contains(low, "[system.io.file]::") ||
                Contains(low, "createfile") ||
                Contains(low, "deviceiocontrol") ||
                Contains(low, "format ") ||
                Contains(low, "format.com") ||
                Contains(low, "fsutil") ||
                Contains(low, "diskpart") ||
                Contains(low, ".run") ||
                Contains(low, ".exec") ||
                Contains(low, "shellexecute") ||
                Contains(low, "savetofile") ||
                Contains(low, "createtextfile") ||
                Contains(low, "writeline") ||
                Contains(low, "write ") ||
                Contains(low, "dd ");
            if (!hasWriteCmd) return false;
            if (Contains(low, "generic_read") &&
                !Contains(low, "generic_write") &&
                !Contains(low, " of=") &&
                !Contains(low, "out-file") &&
                !Contains(low, "savetofile")) {
                return false;
            }
            return true;
        }, 100});

    // ---------- 混淆脚本家族 ----------
    rules.push_back({"BSD/Trojan-Dropper.Script.JSPacker.RC4Dropper",
        [](const std::string& s) -> bool {
            return IsRC4Base64Packer(s);
        }, 90});

    rules.push_back({"BSD/Trojan-Dropper.VBS.CommentObfDropper",
        [](const std::string& s) -> bool {
            return IsCommentObfVBS(s);
        }, 88});

    rules.push_back({"BSD/Trojan-Dropper.VBS.DanishDropper",
        [](const std::string& s) -> bool {
            if (!HasDanishSplitObf(s)) return false;
            return ContainsPatternCI(s, "wscript.shell") || ContainsPatternCI(s, "execute") ||
                   ContainsPatternCI(s, "powershell") || ContainsPatternCI(s, "activist");
        }, 92});

    rules.push_back({"BSD/Trojan-Downloader.Script.JSONLoader",
        [](const std::string& s) -> bool {
            return IsJSONLoaderJS(s);
        }, 88});

    rules.push_back({"BSD/Trojan-Obfuscated.HTA.UnicodePadded",
        [](const std::string& s) -> bool {
            if (!IsHtaContent(s)) return false;
            if (!HasUnicodePadding(s)) return false;
            return ContainsPatternCI(s, "wscript.shell") || ContainsPatternCI(s, "executeglobal") ||
                   ContainsPatternCI(s, "shellexecute") || ContainsPatternCI(s, "powershell") ||
                   ContainsPatternCI(s, "adodb") || ContainsPatternCI(s, "xmlhttp");
        }, 85});

    rules.push_back({"BSD/Trojan-Obfuscated.JS.UnicodePadded",
        [](const std::string& s) -> bool {
            if (IsHtaContent(s)) return false;
            if (!HasUnicodePadding(s)) return false;
            return ContainsPattern(s, "wscript.shell") || ContainsPattern(s, "activexobject") ||
                   ContainsPattern(s, "createobject") || ContainsPattern(s, "powershell") ||
                   ContainsPattern(s, "adodb") || ContainsPattern(s, "xmlhttp") ||
                   ContainsPattern(s, "adodb.stream") || ContainsPattern(s, "filesystemobject");
        }, 85});

    rules.push_back({"BSD/Trojan-Obfuscated.JS.UnicodeDeadCode",
        [](const std::string& s) -> bool {
            if (s.size() < 5 * 1024 * 1024) return false;
            if (s.size() > 50 * 1024 * 1024) return false;
            const size_t kScan = 512 * 1024;
            auto region = [&](size_t begin, bool& lowAscii, bool& hasUnicode) {
                size_t end = std::min(begin + kScan, s.size());
                size_t total = 0, printable = 0, high = 0;
                for (size_t i = begin; i < end; ++i) {
                    ++total;
                    unsigned char c = (unsigned char)s[i];
                    if (c >= 0x20 && c <= 0x7E) ++printable;
                    else if (c >= 0x80) ++high;
                }
                double ascii = total ? (double)printable / (double)total : 0.0;
                double unicode = total ? (double)high / (double)total : 0.0;
                lowAscii = ascii < 0.01;
                hasUnicode = unicode > 0.02;
            };
            bool headLow = false, tailLow = false, headU = false, tailU = false;
            region(0, headLow, headU);
            region(s.size() > kScan ? s.size() - kScan : 0, tailLow, tailU);
            return headLow && tailLow && (headU || tailU);
        }, 80});

    rules.push_back({"BSD/Trojan-Obfuscated.JS.CyrillicCipher",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            if (!Contains(s, "{") || !Contains(s, "}")) return false;
            bool isUTF16LE = (s.size() >= 2 &&
                              (unsigned char)s[0] == 0xFF && (unsigned char)s[1] == 0xFE);
            if (!isUTF16LE && s.size() >= 4) {
                int zeroCount = 0;
                for (size_t i = 0; i < std::min(s.size(), (size_t)4096); ++i) {
                    if ((unsigned char)s[i] == 0) ++zeroCount;
                }
                if (zeroCount > 1500) isUTF16LE = true;
            }
            int cyrillicCount = 0;
            if (isUTF16LE) {
                for (size_t i = 0; i + 1 < s.size(); i += 2) {
                    unsigned char lo = (unsigned char)s[i];
                    unsigned char hi = (unsigned char)s[i+1];
                    if (hi == 0x04 && lo >= 0x00 && lo <= 0xFF) ++cyrillicCount;
                }
            } else {
                for (size_t i = 0; i + 1 < s.size(); ++i) {
                    if ((unsigned char)s[i] >= 0xD0 && (unsigned char)s[i] <= 0xD1 &&
                        (unsigned char)s[i+1] >= 0x80 && (unsigned char)s[i+1] <= 0xBF) {
                        ++cyrillicCount;
                    }
                }
            }
            if (cyrillicCount < 10) return false;
            bool hasDecoderFunc = ContainsPattern(s, "charAt") ||
                                  ContainsPattern(s, "charCodeAt") ||
                                  ContainsPattern(s, "fromcharcode");
            if (hasDecoderFunc) return true;
            if (cyrillicCount >= 30 && ContainsPattern(s, "+=")) return true;
            if (cyrillicCount >= 50 && ContainsPattern(s, "function")) return true;
            return false;
        }, 88});

    rules.push_back({"BSD/Trojan-Dropper.JS.HexArray",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            bool has0xFunc = ContainsPatternCI(s, "_0x") && ContainsPatternCI(s, "fromcharcode");
            if (!has0xFunc) return false;
            return ContainsPatternCI(s, "powershell") || ContainsPatternCI(s, "wscript.shell") ||
                   ContainsPatternCI(s, "cmd.exe") || ContainsPatternCI(s, "decodeuri");
        }, 88});

    // Massive _0x hex-array JS packer with switch-case VM decoder.
    rules.push_back({"BSD/Trojan-Dropper.JS.SwitchVM",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            std::string low = toLower(s);
            int varCount = 0;
            size_t pos = 0;
            while ((pos = low.find("_0x", pos)) != std::string::npos) {
                if (pos + 7 < s.size() &&
                    isxdigit(static_cast<unsigned char>(s[pos+3])) &&
                    isxdigit(static_cast<unsigned char>(s[pos+4])) &&
                    isxdigit(static_cast<unsigned char>(s[pos+5])) &&
                    isxdigit(static_cast<unsigned char>(s[pos+6]))) {
                    ++varCount;
                }
                ++pos;
            }
            if (varCount < 30) return false;
            bool hasSwitchVM = Contains(low, "switch") && Contains(low, "case");
            bool hasSink = Contains(low, "eval(") || Contains(low, "scriptengine") ||
                           (Contains(low, "charcodeat") && Contains(low, "fromcharcode"));
            int concatCount = 0;
            pos = 0;
            while ((pos = low.find("+_0x", pos)) != std::string::npos) { ++concatCount; ++pos; }
            return hasSwitchVM && hasSink && concatCount >= 8;
        }, 90});

    rules.push_back({"BSD/Trojan-Dropper.VBS.PSReconstruct",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            bool hasWS = ContainsPatternCI(s, "wscript.shell");
            bool hasPS = ContainsPatternCI(s, "powershell") || ContainsPatternCI(s, "start-sleep") ||
                         ContainsPatternCI(s, "get-random") || ContainsPatternCI(s, "new-guid");
            bool hasExec = ContainsPatternCI(s, ".run(") || ContainsPatternCI(s, ".run ") ||
                           ContainsPatternCI(s, "call ") || ContainsPatternCI(s, "execute");
            bool hasFSO = ContainsPatternCI(s, "filesystemobject") || ContainsPatternCI(s, "createobject");
            return hasWS && hasPS && (hasExec || hasFSO);
        }, 90});

    // VBS string-split CreateObject dropper (e.g. "S"&"CRipt"&"ing").
    rules.push_back({"BSD/Trojan-Dropper.VBS.StringSplit",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            int splitCount = 0;
            size_t pos = 0;
            while ((pos = s.find("\"&\"", pos)) != std::string::npos) {
                ++splitCount; ++pos;
            }
            pos = 0;
            while ((pos = s.find("\"+\"", pos)) != std::string::npos) {
                ++splitCount; ++pos;
            }
            if (splitCount < 10) return false;
            bool hasCreateObj = ContainsPatternCI(s, "createobject");
            bool hasShell = ContainsPatternCI(s, "wscript.shell") ||
                            ContainsPatternCI(s, "shell.application");
            bool hasFSO = ContainsPatternCI(s, "filesystemobject") ||
                          ContainsPatternCI(s, "getspecialfolder");
            if (!hasCreateObj || (!hasShell && !hasFSO)) return false;
            bool hasLaunch = (ContainsPatternCI(s, ".run(") || ContainsPatternCI(s, ".run ") ||
                              ContainsPatternCI(s, ".exec")) &&
                             (ContainsPatternCI(s, "powershell") || ContainsPatternCI(s, "cmd.exe") ||
                              ContainsPatternCI(s, "wscript") || ContainsPatternCI(s, ".js") ||
                              ContainsPatternCI(s, ".vbs") || ContainsPatternCI(s, "http"));
            bool hasWrite = ContainsPatternCI(s, "createtextfile") ||
                            ContainsPatternCI(s, "openstream") ||
                            ContainsPatternCI(s, ".write") || ContainsPatternCI(s, "writeline");
            return hasLaunch || hasWrite;
        }, 88});

    rules.push_back({"BSD/Trojan.JS.StringConcatObf",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            std::string low = toLower(s);
            int concatCount = 0;
            size_t pos = 0;
            while ((pos = low.find("\"+\"", pos)) != std::string::npos) {
                ++concatCount; ++pos;
            }
            pos = 0;
            while ((pos = low.find("'+'", pos)) != std::string::npos) {
                ++concatCount; ++pos;
            }
            if (concatCount < 3) return false;
            return Contains(low, "wscript") || Contains(low, "powershell") ||
                   Contains(low, "scripting") || Contains(low, "activexobject");
        }, 82});

    // JS/VBS XOR hex-decoder dropper: fromCharCode + parseInt hex string,
    // XOR key, reading own script to extract encoded payload.
    rules.push_back({"BSD/Trojan-Dropper.JS.XORHex",
        [](const std::string& s) -> bool {
            if (s.size() > 5 * 1024 * 1024) return false;
            if (!ContainsPatternCI(s, "fromcharcode")) return false;
            std::string low = toLower(s);
            if (!Contains(low, "^")) return false;
            bool hasRadix16 = false;
            size_t pos = 0;
            while ((pos = low.find("parseint(", pos)) != std::string::npos) {
                size_t close = low.find(')', pos);
                if (close != std::string::npos) {
                    std::string args = low.substr(pos + 9, close - pos - 9);
                    if (args.find("16") != std::string::npos || args.find("0x") != std::string::npos) {
                        hasRadix16 = true;
                        break;
                    }
                    pos = close;
                } else break;
            }
            if (!hasRadix16) return false;
            bool hasXorKey = false;
            pos = 0;
            while ((pos = low.find("0x", pos)) != std::string::npos) {
                if (pos + 4 < low.size() &&
                    isxdigit(static_cast<unsigned char>(low[pos+2])) &&
                    isxdigit(static_cast<unsigned char>(low[pos+3])) &&
                    !isxdigit(static_cast<unsigned char>(low[pos+4]))) {
                    hasXorKey = true;
                    break;
                }
                ++pos;
            }
            if (!hasXorKey) return false;
            return Contains(low, "wscript") || Contains(low, "powershell") ||
                   Contains(low, "cmd.exe") || Contains(low, "createobject") ||
                   Contains(low, "scripting") || Contains(low, "activexobject") ||
                   Contains(low, "eval(") || Contains(low, "run(") || Contains(low, ".write");
        }, 90});

    return rules;
}

// 匹配第一个命中的内容指纹规则；命中则输出 family + severity 并返回 true。
inline bool Match(const std::string& content, std::string& family, int& severity) {
    static const auto rules = BuildContentFingerprintRules();
    for (const auto& r : rules) {
        if (r.matcher(content)) {
            family = r.family;
            severity = r.severity;
            return true;
        }
    }
    return false;
}

} // namespace ContentFingerprint

// ============================================================
// 统一引擎（含文件扫描接口）
// ============================================================
class ScriptDetectionEngine {
public:
    // 直接扫描脚本内容
    RiskReport scan(const std::string& script, ScriptLanguage hint = ScriptLanguage::Unknown) {
        // 静态内容指纹预检：语言无关，覆盖 LNK/HTA/二进制混淆等
        // 无法通过语言检测器识别的样本（原 Behavior Sandbox 迁移至此）。
        {
            std::string fpFamily;
            int fpSeverity = 0;
            if (ContentFingerprint::Match(script, fpFamily, fpSeverity)) {
                RiskReport report;
                report.language = ScriptLanguage::Unknown;
                report.isMalicious = true;
                report.riskScore = fpSeverity;
                report.family = fpFamily;
                if (fpSeverity >= 80) report.riskLevel = "CRITICAL";
                else if (fpSeverity >= 60) report.riskLevel = "HIGH";
                else report.riskLevel = "MEDIUM";
                report.reasons.push_back("内容指纹命中: " + fpFamily);
                return report;
            }
        }

        ScriptLanguage lang = (hint != ScriptLanguage::Unknown) ? hint : detectLanguage(script);

        std::unique_ptr<LanguageDetector> detector;
        switch (lang) {
        case ScriptLanguage::PowerShell: detector = std::make_unique<PowerShellDetector>(); break;
        case ScriptLanguage::CMD:        detector = std::make_unique<CMDDetector>(); break;
        case ScriptLanguage::VBS:        detector = std::make_unique<VBSDetector>(); break;
        case ScriptLanguage::JavaScript: detector = std::make_unique<JavaScriptDetector>(); break;
        default:
            RiskReport report;
            report.language = ScriptLanguage::Unknown;
            report.isMalicious = false;
            report.riskScore = 0;
            report.riskLevel = "LOW";
            report.family = "Unknown.Script";
            report.reasons.push_back("未能识别的脚本语言，跳过分析");
            return report;
        }
        return detector->analyze(script);
    }

    // 文件扫描：自动根据后缀名识别语言，读取内容后交给 scan()
    RiskReport scanFile(const std::string& filePath) {
        // 提取后缀
        std::string ext;
        size_t dotPos = filePath.rfind('.');
        if (dotPos != std::string::npos) {
            ext = toLower(filePath.substr(dotPos));
        }

        ScriptLanguage lang = ScriptLanguage::Unknown;
        if (ext == ".ps1") lang = ScriptLanguage::PowerShell;
        else if (ext == ".bat" || ext == ".cmd") lang = ScriptLanguage::CMD;
        else if (ext == ".vbs") lang = ScriptLanguage::VBS;
        else if (ext == ".js" || ext == ".jse" || ext == ".wsf") lang = ScriptLanguage::JavaScript;
        else if (ext == ".c" || ext == ".cpp" || ext == ".h" || ext == ".hpp") lang = ScriptLanguage::Cpp;
        // 如果后缀不识别，内部将自动探测

        // 读取文件（最大 20MB，防止大文件崩溃）
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            RiskReport error;
            error.language = ScriptLanguage::Unknown;
            error.isMalicious = false;
            error.riskScore = 0;
            error.riskLevel = "ERROR";
            error.reasons.push_back("无法打开文件: " + filePath);
            return error;
        }
        std::streamsize fileSize = file.tellg();
        if (fileSize > 20 * 1024 * 1024) {
            file.close();
            RiskReport skipped;
            skipped.language = ScriptLanguage::Unknown;
            skipped.isMalicious = false;
            skipped.riskScore = 0;
            skipped.riskLevel = "LOW";
            skipped.family = "Unknown.Script";
            skipped.reasons.push_back("文件超过 20MB，跳过分析");
            return skipped;
        }
        file.seekg(0, std::ios::beg);
        std::string content((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();

        return scan(content, lang);
    }
};