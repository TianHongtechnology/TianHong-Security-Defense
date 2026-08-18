#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

/* ============================================================================
 * ServiceMain.cpp — 用户态客户端主入口
 *
 * 负责与内核驱动 (TianHongHips) 通信，提供命令行交互界面
 * 通信模型：双句柄模型
 *   - g_hDevice:     用于发送控制命令（Protect, AddRule 等）
 *   - g_hCommDevice: 用于轮询检测事件（IOCTL_RULE_DETECTED_REQUEST）
 * ========================================================================== */

#include "../shared/SocketProtocol.h"
#include "../shared/Common.h"
#include "../shared/Event.h"
#include "../shared/Ioctl.h"
#include "Comm.h"
#include "ConsoleOutput.h"
#include "RuleLoader.h"
#include "RuleManager.h"
#include "RuleManagerV2.h"

/* 勒索诱捕规则通过 RuleDesc="RansomHoneypot" 识别（驱动端添加规则时设置），
 * 不再依赖 RuleId 范围判断，避免与其它高 RuleId 规则冲突。
 * RuleId 基址定义见 main.cpp 的 RANSOM_HONEYPOT_RULE_ID_BASE。 */

#ifndef PACKET_COMPAT_DEFINED
#define PACKET_COMPAT_DEFINED

enum PacketType
{
    PTConnection = 0,
    PTVirusOperationConfirm = 1,
    PTProtectFile = 2,
    PTHideFile = 3,
    PTCreateProcessRoutine = 4,
    PTThreatScore = 5,
    PTClientMessage = 6
};

enum WarnDlgType
{
    WDT_Normal = 0,
    WDT_Setting = 1,
    WDT_Wifi = 2
};

struct Packet
{
    PacketType PacketTyped;
    char Message[4096];
    int Pid;
    char WarnTitle[128];
    char InfoTitle[32];
    bool NeedTerminate;
    WarnDlgType WarnType;
};

#endif

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <fstream>

#include <algorithm>
#include <map>
#include <wchar.h>

#pragma comment(lib, "crypt32.lib")

using namespace std;

// 从完整进程路径提取文件名（含扩展名），用于替代 PsGetProcessImageFileName 返回的 8.3 短名。
// 例如 "\Device\HarddiskVolume3\Windows\notepad.exe" -> "notepad.exe"
static const char* ExtractFileNameFromPath(const char* path)
{
    if (!path || !path[0])
        return NULL;

    const char* p = path;
    const char* lastSep = NULL;
    // 同时处理 \ 和 / 分隔符
    for (; *p; p++)
    {
        if (*p == '\\' || *p == '/')
            lastSep = p;
    }
    return lastSep ? (lastSep + 1) : path;
}

// 从 ruleDetected 获取最佳进程显示名：优先从 ProcessPath 提取完整文件名，
// 退化到 8.3 短名 ProcessName，再退化到 "Unknown"。
static const char* GetDisplayProcessName(const COMM_RULE_DETECTED* ruleDetected)
{
    const char* name = ExtractFileNameFromPath(ruleDetected->ProcessPath);
    if (name && name[0])
        return name;
    return ruleDetected->ProcessName[0] ? ruleDetected->ProcessName : "Unknown";
}

// 将内核态设备路径转换为 Win32 路径（如 \Device\HarddiskVolume3\Users\Test\... -> C:\Users\Test\...）
static string NormalizeKernelPath(const char* kernelPath)
{
    if (!kernelPath || !kernelPath[0])
        return string();
    string kp(kernelPath);
    // 已经是 Win32 路径则原样返回
    if (kp.size() >= 2 && kp[1] == ':')
        return kp;
    // \Device\HarddiskVolumeN\ -> C:\ 映射
    const char* prefix = "\\Device\\HarddiskVolume";
    size_t plen = strlen(prefix);
    size_t pos = kp.find(prefix);
    if (pos != string::npos) {
        // 提取卷号
        size_t numStart = pos + plen;
        size_t numEnd = numStart;
        while (numEnd < kp.size() && isdigit(kp[numEnd])) numEnd++;
        if (numEnd > numStart) {
            int volNum = atoi(kp.substr(numStart, numEnd - numStart).c_str());
            // 尝试从注册表获取卷号到盘符的映射
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\STORAHCI", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                // 遍历子键查找卷号映射（简化版：直接使用 volNum 推断）
                // Windows 通常将 HarddiskVolumeN 映射到相应盘符
                // 查找所有驱动器盘符
                DWORD mask = GetLogicalDrives();
                char drive = 'C';
                int found = 0;
                while (mask && drive <= 'Z') {
                    if (mask & 1) {
                        if (found == volNum - 1) break;
                        found++;
                    }
                    mask >>= 1;
                    drive++;
                }
                RegCloseKey(hKey);
                // 找不到映射则退化为 C:
                if (drive > 'Z') drive = 'C';
                string win32 = string("\\") + drive + ":\\" + kp.substr(numEnd);
                // 清理双斜杠
                size_t dp = win32.find("\\\\");
                while (dp != string::npos) {
                    win32.erase(dp, 1);
                    dp = win32.find("\\\\", dp);
                }
                return win32;
            }
        }
    }
    return kp;
}

// 将 ANSI（系统默认代码页）字符串转换为 UTF-8。
// 驱动端使用 RtlUnicodeStringToAnsiString 生成路径/键值，Client 需转码后再发送给 Qt UI。
static string AnsiToUtf8(const char* ansiStr)
{
    if (!ansiStr || !ansiStr[0])
        return string();
    int wideLen = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, NULL, 0);
    if (wideLen <= 0)
        return string(ansiStr);

    vector<wchar_t> wideBuf(wideLen);
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, wideBuf.data(), wideLen);

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideBuf.data(), -1, NULL, 0, NULL, NULL);
    if (utf8Len <= 0)
        return string(ansiStr);

    vector<char> utf8Buf(utf8Len);
    WideCharToMultiByte(CP_UTF8, 0, wideBuf.data(), -1, utf8Buf.data(), utf8Len, NULL, NULL);
    return string(utf8Buf.data());
}

// 将 MITRE ATT&CK 威胁类别映射为简短中文告警标题，避免对话框标题过长。
static const char* MapAlertTitle(const char* threatClass)
{
    if (!threatClass || !threatClass[0])
        return "发现可疑进程行为";

    if (strncmp(threatClass, "DefenseEvasion/Injection", 24) == 0)
    {
        if (strstr(threatClass, "RemoteProtectExecutable"))
            return "发现可疑进程试图修改内存保护属性";
        if (strstr(threatClass, "RemoteAPCInjection"))
            return "发现可疑进程试图进行APC注入";
        if (strstr(threatClass, "APCAndSectionMap"))
            return "发现可疑进程试图进行APC+段映射注入";
        if (strstr(threatClass, "ProcessHollowing"))
            return "发现可疑进程试图进行进程镂空";
        if (strstr(threatClass, "ProcessInjection"))
            return "发现可疑进程试图进行进程注入";
        if (strstr(threatClass, "PoolParty"))
            return "发现可疑进程试图进行线程池注入";
        return "发现可疑进程试图进行注入操作";
    }

    /* DefenseEvasion/AVBypass: ntdll unhook/remap、AMSI bypass、direct syscall 等 */
    if (strncmp(threatClass, "DefenseEvasion/Ntdll", 20) == 0 ||
        strncmp(threatClass, "DefenseEvasion/AMSI", 19) == 0 ||
        strncmp(threatClass, "DefenseEvasion/DirectSyscall", 28) == 0 ||
        strncmp(threatClass, "DefenseEvasion/IndirectSyscall", 30) == 0)
    {
        return "发现可疑进程试图绕过安全防护";
    }

    if (strncmp(threatClass, "CommandAndControl", 17) == 0)
    {
        if (strstr(threatClass, "C2Connection"))
            return "发现可疑进程试图建立C2连接";
        return "发现可疑进程存在C2通信行为";
    }

    if (strncmp(threatClass, "Execution", 9) == 0)
        return "发现可疑进程试图执行恶意代码";

    if (strncmp(threatClass, "Persistence", 11) == 0)
        return "发现可疑进程试图建立持久化";

    if (strncmp(threatClass, "PrivilegeEscalation", 20) == 0)
    {
        if (strstr(threatClass, "CVE202141379") || strstr(threatClass, "DACL"))
            return "检查到DACL权限修改攻击（CVE-2021-41379）";
        if (strstr(threatClass, "TrustedInstaller") || strstr(threatClass, "DuplicateHandle"))
            return "检查到TrustedInstaller句柄复制提权";
        return "检查到进程提权行为";
    }

    if (strncmp(threatClass, "CredentialAccess", 16) == 0)
        return "发现可疑进程试图窃取凭据";

    if (strncmp(threatClass, "Discovery", 9) == 0)
        return "发现可疑进程试图进行信息收集";

    if (strncmp(threatClass, "LateralMovement", 15) == 0)
    {
        if (strstr(threatClass, "DCOM"))
            return "发现可疑进程通过DCOM进行横向移动";
        return "发现可疑进程试图进行横向移动";
    }

    if (strncmp(threatClass, "Collection", 10) == 0)
        return "发现可疑进程试图收集敏感数据";

    if (strncmp(threatClass, "Impact", 6) == 0)
        return "发现可疑进程试图造成破坏";

    if (strncmp(threatClass, "Behavior/Ransomware", 19) == 0)
        return "发现可疑进程正在批量加密文件";

    /* Trojan.SilverFox: 行为链特征 */
    if (strncmp(threatClass, "Trojan.SilverFox", 16) == 0)
    {
        if (strstr(threatClass, "HiddenFile"))
            return "发现可疑进程试图隐藏文件";
        if (strstr(threatClass, "PEInImage"))
            return "发现图像文件内含可执行载荷";
        return "检查到行为链威胁";
    }

    /* Trojan.AVBypass: 反病毒绕过 */
    if (strncmp(threatClass, "Trojan.AVBypass", 15) == 0)
    {
        if (strstr(threatClass, "ETW"))
            return "发现可疑进程试图禁用ETW追踪";
        if (strstr(threatClass, "Instrumentation"))
            return "发现可疑进程试图绕过Instrumentation监控";
        if (strstr(threatClass, "InlinePatch"))
            return "发现可疑进程试图patch ETW内核函数";
        return "发现可疑进程试图绕过安全监控";
    }

    /* Trojan.Rootkit: 根kit/高危驱动 */
    if (strncmp(threatClass, "Trojan.Rootkit", 14) == 0)
    {
        if (strstr(threatClass, "HighRiskDriver"))
            return "发现可疑进程加载高危漏洞驱动";
        if (strstr(threatClass, "DriverService"))
            return "发现可疑进程创建高危驱动服务";
        return "发现可疑进程存在根kit行为";
    }

    /* Trojan.Exploit: 内存执行/Shellcode */
    if (strncmp(threatClass, "Trojan.Exploit", 14) == 0)
    {
        if (strstr(threatClass, "SelfExec"))
            return "发现可疑进程自身分配并执行可执行内存";
        if (strstr(threatClass, "AllocExecute"))
            return "发现可疑进程分配可执行内存";
        return "发现可疑进程存在shellcode执行行为";
    }

    return "发现可疑进程行为";
}

// ── 全局变量 ──
HANDLE g_hDevice = INVALID_HANDLE_VALUE;          // 驱动通信句柄（发送命令）
HANDLE g_hCommDevice = INVALID_HANDLE_VALUE;      // 响应查询句柄（轮询检测事件）
HANDLE g_hDiskDevice = INVALID_HANDLE_VALUE;      // 磁盘过滤驱动句柄（MBR保护告警轮询）
HANDLE g_hNetworkDevice = INVALID_HANDLE_VALUE;  // 网络过滤驱动通信句柄
BOOL g_bNetworkProtectionEnabled = FALSE;        // 网络防护是否启用
volatile BOOL g_bRunning = TRUE;                   // 运行标志
static ULONG g_NextRuleId = 1;                     // 自动生成的规则ID（自增）

// ── 前向声明 ──
void PrintUsage();
vector<string> ParseCommandParameters(const string& input);
map<string, string> ParseKeyValueParams(const string& input);
REG_OPERATION ParseRegOperation(const string& opStr);
FILE_OPERATION ParseFileOperation(const string& opStr);
SECURITY_FLAG ParseSecurityFlag(const string& flagStr);
BOOL SendRuleToDriver(HANDLE hDevice, RULE_TYPE ruleType, const map<string, string>& params);
void HandleUserQueries();
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType);
BOOL IsNumeric(const string& str);

// 磁盘过滤驱动相关前向声明
BOOL InstallDiskDriver(BOOL autoInstall);
void HandleDiskAlerts();
void SendDiskAlertToMain(const DISK_FILTER_ALERT* alert);

// 网络过滤驱动相关前向声明
BOOL InstallNetworkDriver(BOOL autoInstall);

// Socket模式全局变量前向声明
static volatile BOOL g_bSocketConnected = FALSE;
static SOCKET g_clientSocket = INVALID_SOCKET;
static char g_szClientAuthToken[65] = {0};      // 从命令行接收的 main.cpp 认证令牌
static volatile ClientAlertResponse g_alertResponse = { 0 };
static volatile ClientProcessCheckResponse g_processCheckResponse = { 0 };
static volatile BOOL g_bProcessCheckBlocking = TRUE;   // 由 main.cpp 的 pIsFullScanSwitch 控制：TRUE=阻塞检查（完整扫描），FALSE=非阻塞告警；默认与 UI 一致（ON）
static volatile ClientDllScanResponse g_dllScanResponse = { 0 };
static volatile BOOL g_bDllScanBlocking = TRUE;        // 由 main.cpp 控制：TRUE=阻塞扫描, FALSE=异步扫描
static ClientRollbackConfirmResponse g_rollbackResponse = { 0 };

// ── 独立于 mainUI 的开关状态 ──
static volatile BOOL g_bFullScanEnabled = TRUE;            // 完整扫描开关
static volatile BOOL g_bUnsignedDllScanEnabled = TRUE;     // 未签名 DLL 扫描开关
static volatile BOOL g_bBehaviorDetectionEnabled = TRUE;   // 行为检测开关
static volatile BOOL g_bR3ProtectionEnabled = TRUE;        // R3 DLL 防护注入开关
static volatile BOOL g_bProcessProtectionEnabled = TRUE;   // 进程保护开关

// ── 告警/进程检查响应状态保护 ──
static CRITICAL_SECTION g_alertResponseCs;          // 保护 g_alertResponse / g_processCheckResponse / pending PID
static volatile INT64   g_pendingAlertPid = -1;     // 当前正在等待的告警 PID
static volatile INT64   g_pendingCheckPid = -1;     // 当前正在等待的进程检查 PID
static volatile INT64   g_pendingDllScanPid = -1;   // 当前正在等待的 DLL 检查 PID
static volatile INT64   g_pendingRollbackPid = -1;  // 当前正在等待的回滚确认 PID

/* ── IsTaskSchedulerStartupTask: 判断任务计划文件是否包含自启动触发器 ──
 * 用于将 "Task Scheduler (Startup only)" 规则真正限制为仅对自启动任务告警。
 * 支持的启动类触发器：LogonTrigger、BootTrigger、RegistrationTrigger、
 * SessionStateChangeTrigger。
 * 任务 XML 可能是 UTF-16LE（带 BOM）或 ASCII/UTF-8，此处兼容处理。
 * 文件不可读时返回 FALSE，允许操作继续（真正的自启动任务在写入触发器后
 * 仍会被后续写操作触发）。 */
static BOOL IsTaskSchedulerStartupTask(const RULE_FILE_DETECTED_RESPONSE* fileResponse)
{
    if (fileResponse == NULL)
        return FALSE;

    CHAR fullPath[MAX_PATH_LEN + MAX_VALUE_NAME_LEN + 2] = { 0 };
    _snprintf_s(fullPath, sizeof(fullPath), _TRUNCATE,
        "%s\\%s", fileResponse->FullPath, fileResponse->FileName);

    FILE* fp = NULL;
    if (fopen_s(&fp, fullPath, "rb") != 0 || fp == NULL)
        return FALSE;

    BYTE buffer[4096] = { 0 };
    size_t bytesRead = fread(buffer, 1, sizeof(buffer) - 2, fp);
    fclose(fp);

    if (bytesRead < 10)
        return FALSE;

    /* UTF-16 LE BOM: 按宽字符搜索触发器名 */
    if (bytesRead >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
    {
        const WCHAR* wideBuf = (const WCHAR*)(buffer + 2);
        int wideLen = (int)((bytesRead - 2) / sizeof(WCHAR));
        if (wideLen > 0)
        {
            const WCHAR* triggersW[] = {
                L"LogonTrigger",
                L"BootTrigger",
                L"RegistrationTrigger",
                L"SessionStateChangeTrigger"
            };
            for (int i = 0; i < 4; i++)
            {
                if (wcsstr(wideBuf, triggersW[i]) != NULL)
                    return TRUE;
            }
        }
    }
    else
    {
        /* ASCII / UTF-8：按多字节字符串搜索 */
        buffer[bytesRead] = '\0';
        const CHAR* triggersA[] = {
            "LogonTrigger",
            "BootTrigger",
            "RegistrationTrigger",
            "SessionStateChangeTrigger"
        };
        for (int i = 0; i < 4; i++)
        {
            if (strstr((const CHAR*)buffer, triggersA[i]) != NULL)
                return TRUE;
        }
    }

    return FALSE;
}

// Socket 通信前向声明
BOOL ConnectToMain();
BOOL SendFatalErrorLogToMain(const char* message);
BOOL SendLogToMain(const char* message);
BOOL SendPacketToMain(const Packet& packet);
int SendAlertAndWaitResponse(INT64 pid, const char* title, const char* message,
    INT64 parentPid = 0, const char* parentName = nullptr, const char* parentPath = nullptr, const char* processPath = nullptr);
BOOL SendAlertNoWait(INT64 pid, const char* title, const char* message,
    INT64 parentPid = 0, const char* parentName = nullptr, const char* parentPath = nullptr, const char* processPath = nullptr);
int SendProcessCheckAndWait(INT64 pid, INT64 parentPid, const char* processPath, const char* processName, const char* parentName);
int SendDllScanAndWait(INT64 pid, INT64 parentPid, const char* processPath, const char* processName, const char* dllPath, int blocking);
int SendRollbackConfirmAndWait(const BA_ROLLBACK_LIST* rollbackList, BA_ROLLBACK_SELECTION* outSelection);

// 清理并退出（确保驱动被卸载）
void CleanupAndExit();

// 驱动安装（autoInstall=TRUE 时跳过用户确认）
BOOL InstallDriver(BOOL autoInstall);

// ============================================================================
// ConsoleCtrlHandler - 拦截控制台关闭事件（Alt+F4/关闭按钮/ESC等）
// ============================================================================
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    case CTRL_LOGOFF_EVENT:
        // 拦截所有关闭事件，仅允许通过 quit 命令退出
        return TRUE;
    default:
        return FALSE;
    }
}

// ============================================================================
// IsNumeric - 检查字符串是否为纯数字
// ============================================================================
BOOL IsNumeric(const string& str)
{
    if (str.empty()) return FALSE;
    for (size_t i = 0; i < str.length(); i++)
    {
        if (str[i] < '0' || str[i] > '9') return FALSE;
    }
    return TRUE;
}

// ============================================================================
// PrintUsage - 打印使用说明
// ============================================================================
void PrintUsage()
{
    SetConsoleColor(ConsoleColor::Cyan);
    printf("\n========================================\n");
    printf("  TianHong HIPS User-mode Console\n");
    printf("========================================\n");
    ResetConsoleColor();

    printf("\n[*] Available commands:\n");
    printf("  Protect <PID>              - Protect specified process (PID must be numeric)\n");
    printf("  Protect                     - Self-protect (protect current process)\n");
    printf("  Protect clear               - Clear all protected processes\n");
    printf("  RegRule add <params>        - Add registry rule\n");
    printf("  RegRule del <RuleID>        - Delete registry rule\n");
    printf("  RegRule clear               - Clear all registry rules\n");
    printf("  FileRule add <params>       - Add file rule\n");
    printf("  FileRule del <RuleID>       - Delete file rule\n");
    printf("  FileRule clear              - Clear all file rules\n");
    printf("  FileRule stats              - Show file rule statistics\n");
    printf("  cache on/off/clear          - Control response cache\n");
    printf("  ba scan                     - Behavior analysis scan\n");
    printf("  ba stats                    - Behavior analysis statistics\n");
    printf("  ba clear                    - Clear behavior analysis data\n");
    printf("  fullscan on/off             - Toggle full scan mode (blocking check)\n");
    printf("  dllscan on/off [blocking]   - Toggle unsigned DLL scan\n");
    printf("  behavior on/off             - Toggle behavior detection\n");
    printf("  memory on/off               - Toggle R3 DLL protection injection\n");
    printf("  processprotect on/off       - Toggle process protection\n");
    printf("  status                      - Show all switch status\n");
    printf("  quit                        - Exit program\n");

    printf("\n[*] Registry rule parameter format (key=value, any order, RuleID auto-generated):\n");
    printf("  RegRule add op=<operation> path=\"<path>\" [value=<value name>] [data=<detect value>] [flag=<security flag>]\n");
    printf("  Example: RegRule add op=REG_OPERATION_SET path=\"\\REGISTRY\\USER\\*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" value=\"*\" data=\"malware.exe\" flag=SEF_ALL_BLOCKED\n");

    printf("\n[*] File rule parameter format (key=value, any order, RuleID auto-generated):\n");
    printf("  FileRule add op=<operation> path=\"<path>\" [file=<filename>] [ext=<extension>] [flag=<security flag>]\n");
    printf("  Example: FileRule add op=FILE_OPERATION_DELETE path=\"C:\\Users\\WDAGUtilityAccount\\Desktop\" file=\"a.txt\" ext=\"*\" flag=SEF_ALL_BLOCKED\n");

    printf("\n[*] Operation options:\n");
    printf("  Registry: REG_OPERATION_SET, REG_OPERATION_DELETE, REG_OPERATION_RENAME, REG_OPERATION_READ, REG_OPERATION_SET_SECURITY\n");
    printf("  File:     FILE_OPERATION_WRITE, FILE_OPERATION_DELETE, FILE_OPERATION_RENAME, FILE_OPERATION_READ\n");

    printf("\n[*] SecurityFlag options:\n");
    printf("  SEF_ALL_BLOCKED, SEF_NOT_SYSTEM_BLOCKED, SEF_UNSIGNED_BLOCKED, SEF_PROCESS_START_BY_EXPLORER_BLOCKED, SEF_ALL_ACCESS\n\n");
}

// ============================================================================
// ParseCommandParameters - 解析命令行参数（支持引号内的空格）
// ============================================================================
vector<string> ParseCommandParameters(const string& input)
{
    vector<string> params;
    string currentParam;
    bool inQuotes = false;

    for (size_t i = 0; i < input.length(); i++)
    {
        char c = input[i];

        if (c == '"')
        {
            inQuotes = !inQuotes;
        }
        else if (c == ' ' && !inQuotes)
        {
            if (!currentParam.empty())
            {
                params.push_back(currentParam);
                currentParam.clear();
            }
        }
        else
        {
            currentParam += c;
        }
    }

    if (!currentParam.empty())
    {
        params.push_back(currentParam);
    }

    return params;
}

// ============================================================================
// ParseKeyValueParams - 解析 key=value 格式的参数（支持引号内的空格）
// 格式: key1=value1 key2="value with spaces" key3=value3
// ============================================================================
map<string, string> ParseKeyValueParams(const string& input)
{
    map<string, string> params;
    string currentKey;
    string currentValue;
    bool inKey = true;
    bool inQuotes = false;

    for (size_t i = 0; i < input.length(); i++)
    {
        char c = input[i];

        if (inKey)
        {
            if (c == '=')
            {
                inKey = false;
            }
            else if (c != ' ')
            {
                currentKey += c;
            }
        }
        else
        {
            if (c == '"')
            {
                inQuotes = !inQuotes;
            }
            else if (c == ' ' && !inQuotes)
            {
                // 一个参数结束，保存
                if (!currentKey.empty())
                {
                    params[currentKey] = currentValue;
                    currentKey.clear();
                    currentValue.clear();
                    inKey = true;
                }
            }
            else
            {
                currentValue += c;
            }
        }
    }

    // 保存最后一个参数
    if (!currentKey.empty())
    {
        params[currentKey] = currentValue;
    }

    return params;
}

// ============================================================================
// ParseRegOperation - 字符串到 REG_OPERATION 枚举转换
// ============================================================================
REG_OPERATION ParseRegOperation(const string& opStr)
{
    if (opStr == "REG_OPERATION_SET")    return REG_OPERATION_SET;
    if (opStr == "REG_OPERATION_DELETE") return REG_OPERATION_DELETE;
    if (opStr == "REG_OPERATION_RENAME") return REG_OPERATION_RENAME;
    if (opStr == "REG_OPERATION_READ")   return REG_OPERATION_READ;
    if (opStr == "REG_OPERATION_SET_SECURITY")     return REG_OPERATION_SET_SECURITY;
    return REG_OPERATION_SET;
}

// ============================================================================
// ParseFileOperation - 字符串到 FILE_OPERATION 枚举转换
// ============================================================================
FILE_OPERATION ParseFileOperation(const string& opStr)
{
    if (opStr == "FILE_OPERATION_WRITE")  return FILE_OPERATION_WRITE;
    if (opStr == "FILE_OPERATION_DELETE") return FILE_OPERATION_DELETE;
    if (opStr == "FILE_OPERATION_RENAME") return FILE_OPERATION_RENAME;
    if (opStr == "FILE_OPERATION_READ")   return FILE_OPERATION_READ;
    return FILE_OPERATION_WRITE;
}

// ============================================================================
// ParseSecurityFlag - 字符串到 SECURITY_FLAG 枚举转换
// ============================================================================
SECURITY_FLAG ParseSecurityFlag(const string& flagStr)
{
    if (flagStr == "SEF_ALL_BLOCKED")                      return SEF_ALL_BLOCKED;
    if (flagStr == "SEF_NOT_SYSTEM_BLOCKED")               return SEF_NOT_SYSTEM_BLOCKED;
    if (flagStr == "SEF_UNSIGNED_BLOCKED")                 return SEF_UNSIGNED_BLOCKED;
    if (flagStr == "SEF_PROCESS_START_BY_EXPLORER_BLOCKED") return SEF_PROCESS_START_BY_EXPLORER_BLOCKED;
    if (flagStr == "SEF_ALL_ACCESS")                       return SEF_ALL_ACCESS;
    return SEF_ALL_BLOCKED;
}

// ============================================================================
// SendRuleToDriver - 发送规则到驱动（注册表规则和文件规则共用）
// 使用 key=value 参数格式，RuleID 自动生成
// 注册表规则参数: op, path, [value=*], [data], [flag=SEF_ALL_BLOCKED]
// 文件规则参数:   op, path, [file=*], [ext=*], [flag=SEF_ALL_BLOCKED]
// ============================================================================
BOOL SendRuleToDriver(HANDLE hDevice, RULE_TYPE ruleType, const map<string, string>& params)
{
    // ── 注册表规则 ──
    if (ruleType == RULE_TYPE_REG)
    {
        // 检查必需参数
        auto itOp = params.find("op");
        auto itPath = params.find("path");
        if (itOp == params.end() || itPath == params.end())
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("[-] Registry rule missing required parameters: op and path\n");
            ResetConsoleColor();
            return FALSE;
        }

        RULE_REG_DATA ruleData = { 0 };

        // 自动生成 RuleID
        ruleData.RuleId = g_NextRuleId++;

        // 解析 Operation
        ruleData.Operation = ParseRegOperation(itOp->second);

        // 解析 FullPath
        const string& fullPath = itPath->second;
        size_t size = min(fullPath.size(), sizeof(ruleData.FullPathWithOutValueName) - 1);
        strncpy_s(ruleData.FullPathWithOutValueName, fullPath.c_str(), size);

        // 解析 ValueName（可选，默认 *）
        auto itValue = params.find("value");
        if (itValue != params.end())
        {
            const string& valueName = itValue->second;
            size = min(valueName.size(), sizeof(ruleData.ValueName) - 1);
            strncpy_s(ruleData.ValueName, valueName.c_str(), size);
        }
        else
        {
            strcpy_s(ruleData.ValueName, "*");
        }

        // 解析 DetectValue（可选）
        auto itData = params.find("data");
        if (itData != params.end())
        {
            const string& detectValue = itData->second;
            size = min(detectValue.size(), sizeof(ruleData.DetectValue) - 1);
            strncpy_s(ruleData.DetectValue, detectValue.c_str(), size);
        }

        // 解析 SecurityFlag（可选，默认 SEF_ALL_BLOCKED）
        auto itFlag = params.find("flag");
        if (itFlag != params.end())
        {
            ruleData.sef = ParseSecurityFlag(itFlag->second);
        }
        else
        {
            ruleData.sef = SEF_ALL_BLOCKED;
        }

        ruleData.IsNeedValueName = TRUE;

        SetConsoleColor(ConsoleColor::Yellow);
        printf("[D] REG DATASEND: ID=%d, PATH=%s, KEYNAME=%s, DETECT=%s, SEC=%d\n",
            ruleData.RuleId, ruleData.FullPathWithOutValueName, ruleData.ValueName, ruleData.DetectValue, ruleData.sef);
        ResetConsoleColor();

        // 构造 RULE_DATA
        RULE_DATA rulePacket = { 0 };
        rulePacket.RuleId = ruleData.RuleId;
        rulePacket.rt = RULE_TYPE_REG;
        rulePacket.sef = ruleData.sef;
        memcpy_s(rulePacket.Data, sizeof(rulePacket.Data), &ruleData, sizeof(RULE_REG_DATA));

        // 构造 COMM_CONTROL_PACKET
        COMM_CONTROL_PACKET requestPacket;
        requestPacket.Type = PACKET_TYPE_ADD_RULE;
        memcpy_s(requestPacket.Data, sizeof(requestPacket.Data), &rulePacket, sizeof(RULE_DATA));

        DWORD bytesReturned = 0;

        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_ADD_RULE,
            &requestPacket,
            sizeof(COMM_CONTROL_PACKET),
            NULL, 0,
            &bytesReturned,
            NULL);

        if (success)
        {
            SetConsoleColor(ConsoleColor::Green);
            printf("[+] Registry rule added successfully: RuleID=%d\n", ruleData.RuleId);
            ResetConsoleColor();
            return TRUE;
        }
        else
        {
            DWORD error = GetLastError();
            SetConsoleColor(ConsoleColor::Red);
            printf("[-] DeviceIoControl failed (IOCTL_ADD_RULE): %d\n", error);
            ResetConsoleColor();
            return FALSE;
        }
    }
    // ── 文件规则 ──
    else if (ruleType == RULE_TYPE_FILE)
    {
        // 检查必需参数
        auto itOp = params.find("op");
        auto itPath = params.find("path");
        if (itOp == params.end() || itPath == params.end())
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("[-] File rule missing required parameters: op and path\n");
            ResetConsoleColor();
            return FALSE;
        }

        RULE_FILE_DATA ruleData = { 0 };

        // 自动生成 RuleID
        ruleData.RuleId = g_NextRuleId++;

        // 解析 Operation
        ruleData.Operation = ParseFileOperation(itOp->second);

        // 解析 FullPath
        const string& fullPath = itPath->second;
        size_t size = min(fullPath.size(), sizeof(ruleData.FullPath) - 1);
        strncpy_s(ruleData.FullPath, fullPath.c_str(), size);

        // 解析 FileName（可选，默认 *）
        auto itFile = params.find("file");
        if (itFile != params.end())
        {
            const string& fileName = itFile->second;
            size = min(fileName.size(), sizeof(ruleData.FileName) - 1);
            strncpy_s(ruleData.FileName, fileName.c_str(), size);
        }
        else
        {
            strcpy_s(ruleData.FileName, "*");
        }

        // 解析 FileExt（可选，默认 *）
        auto itExt = params.find("ext");
        if (itExt != params.end())
        {
            const string& fileExt = itExt->second;
            size = min(fileExt.size(), sizeof(ruleData.FileExt) - 1);
            strncpy_s(ruleData.FileExt, fileExt.c_str(), size);
        }
        else
        {
            strcpy_s(ruleData.FileExt, "*");
        }

        // 解析 SecurityFlag（可选，默认 SEF_ALL_BLOCKED）
        auto itFlag = params.find("flag");
        if (itFlag != params.end())
        {
            ruleData.sef = ParseSecurityFlag(itFlag->second);
        }
        else
        {
            ruleData.sef = SEF_ALL_BLOCKED;
        }

        SetConsoleColor(ConsoleColor::Yellow);
        printf("[D] FILE DATASEND: ID=%d, OP=%d, PATH=%s, FILENAME=%s, EXT=%s, SEC=%d\n",
            ruleData.RuleId, ruleData.Operation, ruleData.FullPath, ruleData.FileName, ruleData.FileExt, ruleData.sef);
        ResetConsoleColor();

        // 构造 COMM_CONTROL_PACKET
        COMM_CONTROL_PACKET requestPacket;
        requestPacket.Type = PACKET_TYPE_ADD_FILE_RULE;
        memcpy_s(requestPacket.Data, sizeof(requestPacket.Data), &ruleData, sizeof(RULE_FILE_DATA));

        DWORD bytesReturned = 0;

        BOOL success = DeviceIoControl(
            hDevice,
            IOCTL_ADD_FILE_RULE,
            &requestPacket,
            sizeof(COMM_CONTROL_PACKET),
            NULL, 0,
            &bytesReturned,
            NULL);

        if (success)
        {
            SetConsoleColor(ConsoleColor::Green);
            printf("[+] File rule added successfully: RuleID=%d\n", ruleData.RuleId);
            ResetConsoleColor();
            return TRUE;
        }
        else
        {
            DWORD error = GetLastError();
            SetConsoleColor(ConsoleColor::Red);
            printf("[-] DeviceIoControl failed (IOCTL_ADD_FILE_RULE): %d\n", error);
            ResetConsoleColor();
            return FALSE;
        }
    }

    return FALSE;
}
// ============================================================================
// InstallDriver - 尝试安装驱动（磁盘过滤驱动方式）
// autoInstall=TRUE 时跳过用户确认（traffic/relay 模式自动安装）
// 返回: TRUE=安装成功并已启动, FALSE=失败
// ============================================================================
BOOL InstallDriver(BOOL autoInstall)
{
    if (!autoInstall)
    {
        SetConsoleColor(ConsoleColor::Yellow);
        printf("Driver not loaded, attempt to install? (Y/N): ");
        ResetConsoleColor();

        char answer[10];
        fgets(answer, sizeof(answer), stdin);
        if (answer[0] != 'Y' && answer[0] != 'y')
        {
            printf("User cancelled installation\n");
            return FALSE;
        }
    }
    else
    {
        printf("Relay mode: auto-installing driver...\n");
    }

    // 获取当前 exe 目录
    char exePath[MAX_PATH];
    char exeDir[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    strcpy_s(exeDir, exePath);
    char* lastSlash = strrchr(exeDir, '\\');
    if (lastSlash) *lastSlash = '\0';

    // 构建 .sys 路径
    char sysPath[MAX_PATH];
    char sysDestPath[MAX_PATH];

    sprintf_s(sysPath, "%s\\" THSD_DRIVER_FILENAME_A, exeDir);

    // 复制 .sys 到 System32\drivers
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, sizeof(sysDir));
    sprintf_s(sysDestPath, "%s\\drivers\\" THSD_DRIVER_FILENAME_A, sysDir);

    if (GetFileAttributesA(sysPath) != INVALID_FILE_ATTRIBUTES)
    {
        printf("Copying driver file: %s -> %s\n", sysPath, sysDestPath);
        // 先尝试删除目标文件（可能被旧驱动占用）
        DeleteFileA(sysDestPath);
        if (!CopyFileA(sysPath, sysDestPath, FALSE))
        {
            DWORD err = GetLastError();
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to copy driver file: %d (0x%X)\n", err, err);
            if (err == ERROR_SHARING_VIOLATION || err == ERROR_ACCESS_DENIED)
                printf("Driver file may be in use, run first: sc stop " THSD_SERVICE_NAME_A "\n");
            ResetConsoleColor();
            SendLogToMain("[驱动加载] TianHongHips 主驱动加载失败: 复制 .sys 文件失败");
            return FALSE;
        }
        printf("Driver file copied successfully\n");
    }
    else
    {
        printf("Warning: .sys file not found: %s\n", sysPath);
    }

    printf("Installing driver...\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL)
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("Cannot open Service Control Manager (error: %d)\n", GetLastError());
        printf("Please run this program as administrator\n");
        ResetConsoleColor();
        SendLogToMain("[驱动加载] TianHongHips 主驱动加载失败: 无法打开服务控制管理器");
        return FALSE;
    }

    // 检查服务是否已存在
    SC_HANDLE svc = OpenServiceA(scm, THSD_SERVICE_NAME_A, SERVICE_ALL_ACCESS);
    if (svc == NULL)
    {
        // 创建文件系统 minifilter 驱动服务
        printf("Creating service...\n");
        // 注意：Minifilter 必须使用 SERVICE_FILE_SYSTEM_DRIVER 类型
        // 依赖 FltMgr 确保 Filter Manager 先加载
        svc = CreateServiceA(
            scm,
            THSD_SERVICE_NAME_A,
            THSD_SERVICE_NAME_A,
            SERVICE_ALL_ACCESS,
            SERVICE_FILE_SYSTEM_DRIVER,    // 文件系统驱动（Minifilter）
            SERVICE_DEMAND_START,            // 按需启动
            SERVICE_ERROR_NORMAL,
            sysDestPath,
            "FsFilter",                      // 文件系统过滤加载组
            NULL,                            // lpdwTagId
            "FltMgr",                        // lpDependencies: 依赖 Filter Manager
            NULL,                            // lpServiceStartName: LocalSystem
            NULL);                           // lpPassword
        }

    if (svc == NULL)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
        {
            printf("Service already exists\n");
            svc = OpenServiceA(scm, THSD_SERVICE_NAME_A, SERVICE_ALL_ACCESS);
        }
        if (svc == NULL)
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to create/open service: %d\n", err);
            ResetConsoleColor();
            CloseServiceHandle(scm);
            SendLogToMain("[驱动加载] TianHongHips 主驱动加载失败: 创建或打开服务失败");
            return FALSE;
        }
    }

    // 设置 Minifilter 实例注册表项（Altitude 等）
    // 这些值通常由 INF 文件设置，但 sc create 不会处理 INF
    // 无论服务是否新建，都确保注册表项存在
    {
        HKEY hKey;
        DWORD dwDisposition;
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\" THSD_SERVICE_NAME_A "\\Instances\\" THSD_INSTANCE_NAME_A,
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "Altitude", 0, REG_SZ, (BYTE*)"370000", 7);
            DWORD flags = 0;
            RegSetValueExA(hKey, "Flags", 0, REG_DWORD, (BYTE*)&flags, sizeof(flags));
            RegCloseKey(hKey);
        }
        if (RegCreateKeyExA(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\" THSD_SERVICE_NAME_A "\\Instances",
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "DefaultInstance", 0, REG_SZ, (BYTE*)THSD_INSTANCE_NAME_A, sizeof(THSD_INSTANCE_NAME_A));
            RegCloseKey(hKey);
        }
        printf("Minifilter instance registry entries set (Altitude=370000)\n");
    }

    if (svc != NULL)
    {
        // 若服务被禁用，先改为按需启动，否则 StartService 会返回 1058
        DWORD dwBytesNeeded = 0;
        DWORD dwConfigSize = 0;
        if (QueryServiceConfigA(svc, NULL, 0, &dwBytesNeeded) == FALSE &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            LPQUERY_SERVICE_CONFIGA pConfig = (LPQUERY_SERVICE_CONFIGA)LocalAlloc(LPTR, dwBytesNeeded);
            if (pConfig != NULL)
            {
                if (QueryServiceConfigA(svc, pConfig, dwBytesNeeded, &dwConfigSize))
                {
                    if (pConfig->dwStartType == SERVICE_DISABLED)
                    {
                        printf("服务当前为禁用状态，正在改为按需启动...\n");
                        if (!ChangeServiceConfigA(svc,
                            SERVICE_NO_CHANGE,
                            SERVICE_DEMAND_START,
                            SERVICE_NO_CHANGE,
                            NULL, NULL, NULL, NULL, NULL, NULL, NULL))
                        {
                            printf("修改服务启动类型失败: %d\n", GetLastError());
                        }
                    }
                }
                LocalFree(pConfig);
            }
        }

        // 启动服务
        printf("Starting service...\n");
        if (StartServiceA(svc, 0, NULL))
        {
            SetConsoleColor(ConsoleColor::Green);
            printf("Service start request accepted, waiting for initialization...\n");
            ResetConsoleColor();

            /* StartServiceA 返回成功仅表示 SCM 已接受启动请求，
             * minifilter 驱动仍需 FltMgr 加载 -> DriverEntry -> FltRegisterFilter
             * -> FltStartFiltering -> 创建通信设备，整个过程可能耗时数秒。
             * 用 QueryServiceStatus 轮询等待服务进入 SERVICE_RUNNING，
             * 避免固定 Sleep 太短导致后续 CreateFile 失败。 */
            const int SVC_WAIT_RETRIES = 30;
            const int SVC_WAIT_INTERVAL_MS = 500;
            BOOL serviceRunning = FALSE;
            for (int i = 0; i < SVC_WAIT_RETRIES; i++)
            {
                SERVICE_STATUS svcStatus;
                if (QueryServiceStatus(svc, &svcStatus))
                {
                    if (svcStatus.dwCurrentState == SERVICE_RUNNING)
                    {
                        serviceRunning = TRUE;
                        printf("Service is now RUNNING (after %d ms)\n",
                               (i + 1) * SVC_WAIT_INTERVAL_MS);
                        break;
                    }
                    if (svcStatus.dwCurrentState == SERVICE_STOPPED)
                    {
                        /* 服务启动后立即停止，说明 DriverEntry 失败 */
                        SetConsoleColor(ConsoleColor::Red);
                        printf("Service stopped during startup (exit code: %u)\n",
                               svcStatus.dwWin32ExitCode);
                        ResetConsoleColor();
                        CloseServiceHandle(svc);
                        CloseServiceHandle(scm);
                        return FALSE;
                    }
                }
                Sleep(SVC_WAIT_INTERVAL_MS);
            }

            if (!serviceRunning)
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("Service did not reach RUNNING state within %d ms\n",
                       SVC_WAIT_RETRIES * SVC_WAIT_INTERVAL_MS);
                ResetConsoleColor();
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                SendLogToMain("[驱动加载] TianHongHips 主驱动加载失败: 服务启动超时");
                return FALSE;
            }
        }
        else
        {
            DWORD err = GetLastError();
            if (err == ERROR_SERVICE_ALREADY_RUNNING)
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("Service is already running\n");
                ResetConsoleColor();
            }
            else
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("Failed to start service: %d (0x%X)\n", err, err);
                if (err == ERROR_FILE_NOT_FOUND) {
                    printf("Driver file not found: %s\n", sysDestPath);
                }
                else if (err == ERROR_INVALID_IMAGE_HASH) {
                    printf("Driver is unsigned. Enable test signing: bcdedit /set testsigning on\n");
                }
                else if (err == ERROR_SERVICE_DISABLED) {
                    printf("Service is disabled. Run: sc config " THSD_SERVICE_NAME_A " start= demand\n");
                }
                else {
                    printf("Check Event Viewer for detailed errors\n");
                }
                ResetConsoleColor();
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                SendLogToMain("[驱动加载] TianHongHips 主驱动加载失败: 启动服务失败");
                return FALSE;
            }
        }

        CloseServiceHandle(svc);
    }

    CloseServiceHandle(scm);

    /* 服务进入 RUNNING 状态后，通信设备可能还需要一小段时间才完成创建。
     * 调用方会重试 CreateFile，这里不再固定 Sleep，让调用方的重试循环处理。 */
    printf("Driver service is running, waiting for device to be ready...\n");
    SendLogToMain("[驱动加载] TianHongHips 主驱动服务已启动");
    Sleep(500);

    return TRUE;
}

// ============================================================================
// InstallDiskDriver - 安装磁盘过滤驱动（TianHongHips.Disk 服务）
// 与 InstallDriver 类似但使用 SERVICE_KERNEL_DRIVER 类型（非 minifilter）
// 服务名: TianHongHips.Disk
// 驱动文件: TianHongDefenseKernelProtection.Disk.sys
// ============================================================================
BOOL InstallDiskDriver(BOOL autoInstall)
{
    if (!autoInstall)
    {
        SetConsoleColor(ConsoleColor::Yellow);
        printf("Disk filter driver not loaded, attempt to install? (Y/N): ");
        ResetConsoleColor();

        char answer[10];
        fgets(answer, sizeof(answer), stdin);
        if (answer[0] != 'Y' && answer[0] != 'y')
        {
            printf("User cancelled disk driver installation\n");
            return FALSE;
        }
    }
    else
    {
        printf("Auto-installing disk filter driver...\n");
    }

    // 获取当前 exe 目录
    char exePath[MAX_PATH];
    char exeDir[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    strcpy_s(exeDir, exePath);
    char* lastSlash = strrchr(exeDir, '\\');
    if (lastSlash) *lastSlash = '\0';

    // 构建 .sys 路径
    char sysPath[MAX_PATH];
    char sysDestPath[MAX_PATH];
    sprintf_s(sysPath, "%s\\" THSD_DISK_DRIVER_FILENAME_A, exeDir);

    // 复制 .sys 到 System32\drivers
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, sizeof(sysDir));
    sprintf_s(sysDestPath, "%s\\drivers\\" THSD_DISK_DRIVER_FILENAME_A, sysDir);

    if (GetFileAttributesA(sysPath) != INVALID_FILE_ATTRIBUTES)
    {
        printf("Copying disk driver file: %s -> %s\n", sysPath, sysDestPath);
        DeleteFileA(sysDestPath);
        if (!CopyFileA(sysPath, sysDestPath, FALSE))
        {
            DWORD err = GetLastError();
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to copy disk driver file: %d (0x%X)\n", err, err);
            ResetConsoleColor();
            SendLogToMain("[驱动错误] TianHongHips.Disk 磁盘过滤驱动 .sys 文件复制失败（请以管理员权限运行）");
            return FALSE;
        }
        printf("Disk driver file copied successfully\n");
    }
    else
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("Error: disk driver .sys not found: %s\n", sysPath);
        ResetConsoleColor();
        SendLogToMain("[驱动错误] TianHongHips.Disk 磁盘过滤驱动 .sys 文件缺失（MBR保护已禁用），请确保驱动文件与 Client 在同一目录");
        return FALSE;
    }

    printf("Installing disk filter driver...\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL)
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("Cannot open SCM (error: %d)\n", GetLastError());
        ResetConsoleColor();
        SendLogToMain("[驱动错误] TianHongHips.Disk 无法打开服务控制管理器（请以管理员权限运行）");
        return FALSE;
    }

    // 检查服务是否已存在
    SC_HANDLE svc = OpenServiceA(scm, THSD_DISK_SERVICE_NAME_A, SERVICE_ALL_ACCESS);
    if (svc == NULL)
    {
        // 创建 WDM 内核驱动服务（非 minifilter，使用 SERVICE_KERNEL_DRIVER）
        printf("Creating disk filter service...\n");
        svc = CreateServiceA(
            scm,
            THSD_DISK_SERVICE_NAME_A,
            THSD_DISK_SERVICE_NAME_A,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,        // 内核驱动（非文件系统驱动）
            SERVICE_DEMAND_START,          // 按需启动
            SERVICE_ERROR_NORMAL,
            sysDestPath,
            NULL,                          // 无加载组
            NULL,                          // lpdwTagId
            NULL,                          // 无依赖
            NULL,                          // LocalSystem
            NULL);                         // 无密码
    }

    if (svc == NULL)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
        {
            printf("Disk filter service already exists\n");
            svc = OpenServiceA(scm, THSD_DISK_SERVICE_NAME_A, SERVICE_ALL_ACCESS);
        }
        if (svc == NULL)
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to create/open disk filter service: %d\n", err);
            ResetConsoleColor();
            char logMsg[256];
            sprintf_s(logMsg, "[驱动错误] TianHongHips.Disk 创建/打开服务失败 (错误码: %d)", err);
            SendLogToMain(logMsg);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    // 若服务被禁用，改为按需启动
    {
        DWORD dwBytesNeeded = 0;
        DWORD dwConfigSize = 0;
        if (QueryServiceConfigA(svc, NULL, 0, &dwBytesNeeded) == FALSE &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            LPQUERY_SERVICE_CONFIGA pConfig = (LPQUERY_SERVICE_CONFIGA)LocalAlloc(LPTR, dwBytesNeeded);
            if (pConfig != NULL)
            {
                if (QueryServiceConfigA(svc, pConfig, dwBytesNeeded, &dwConfigSize))
                {
                    if (pConfig->dwStartType == SERVICE_DISABLED)
                    {
                        printf("Disk filter service disabled, enabling...\n");
                        ChangeServiceConfigA(svc, SERVICE_NO_CHANGE,
                            SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                    }
                }
                LocalFree(pConfig);
            }
        }
    }

    // 启动服务
    printf("Starting disk filter service...\n");
    if (StartServiceA(svc, 0, NULL))
    {
        printf("Disk filter service start accepted, waiting...\n");
        const int SVC_WAIT_RETRIES = 20;
        const int SVC_WAIT_INTERVAL_MS = 500;
        BOOL serviceRunning = FALSE;
        for (int i = 0; i < SVC_WAIT_RETRIES; i++)
        {
            SERVICE_STATUS svcStatus;
            if (QueryServiceStatus(svc, &svcStatus))
            {
                if (svcStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    serviceRunning = TRUE;
                    printf("Disk filter service RUNNING (after %d ms)\n",
                           (i + 1) * SVC_WAIT_INTERVAL_MS);
                    break;
                }
                if (svcStatus.dwCurrentState == SERVICE_STOPPED)
                {
                    SetConsoleColor(ConsoleColor::Red);
                    printf("Disk filter service stopped during startup (exit: %u)\n",
                        svcStatus.dwWin32ExitCode);
                    ResetConsoleColor();
                    char logMsg[256];
                    sprintf_s(logMsg, "[驱动错误] TianHongHips.Disk 服务启动后立即停止 (退出码: %u)，可能需要开启测试签名(bcdedit /set testsigning on)",
                        svcStatus.dwWin32ExitCode);
                    SendLogToMain(logMsg);
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return FALSE;
                }
            }
            Sleep(SVC_WAIT_INTERVAL_MS);
        }
        if (!serviceRunning)
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Disk filter did not reach RUNNING within %d ms\n",
                SVC_WAIT_RETRIES * SVC_WAIT_INTERVAL_MS);
            ResetConsoleColor();
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("Disk filter service already running\n");
        }
        else
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to start disk filter service: %d\n", err);
            ResetConsoleColor();
            char logMsg[256];
            sprintf_s(logMsg, "[驱动错误] TianHongHips.Disk 启动服务失败 (错误码: %d)，可能需要开启测试签名(bcdedit /set testsigning on)", err);
            SendLogToMain(logMsg);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    Sleep(500);
    /* 详细日志在主流程中发送（包含 attachedDiskCount 等信息），此处不重复输出 */
    return TRUE;
}

// ============================================================================
// InstallNetworkDriver - 安装网络过滤驱动（TianHongHips.Network 服务）
// 使用 WFP 监控出站网络连接，检测 DoH/C2/数据外传
// ============================================================================
BOOL InstallNetworkDriver(BOOL autoInstall)
{
    if (!autoInstall)
    {
        SetConsoleColor(ConsoleColor::Yellow);
        printf("Network filter driver not loaded, attempt to install? (Y/N): ");
        ResetConsoleColor();

        char answer[10];
        fgets(answer, sizeof(answer), stdin);
        if (answer[0] != 'Y' && answer[0] != 'y')
        {
            printf("User cancelled network driver installation\n");
            return FALSE;
        }
    }
    else
    {
        printf("Auto-installing network filter driver...\n");
    }

    // 获取当前 exe 目录
    char exePath[MAX_PATH];
    char exeDir[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, sizeof(exePath));
    strcpy_s(exeDir, exePath);
    char* lastSlash = strrchr(exeDir, '\\');
    if (lastSlash) *lastSlash = '\0';

    // 构建 .sys 路径
    char sysPath[MAX_PATH];
    char sysDestPath[MAX_PATH];
    sprintf_s(sysPath, "%s\\" THSD_NETWORK_DRIVER_FILENAME_A, exeDir);

    // 复制 .sys 到 System32\drivers
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, sizeof(sysDir));
    sprintf_s(sysDestPath, "%s\\drivers\\" THSD_NETWORK_DRIVER_FILENAME_A, sysDir);

    if (GetFileAttributesA(sysPath) != INVALID_FILE_ATTRIBUTES)
    {
        printf("Copying network driver file: %s -> %s\n", sysPath, sysDestPath);
        DeleteFileA(sysDestPath);
        if (!CopyFileA(sysPath, sysDestPath, FALSE))
        {
            DWORD err = GetLastError();
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to copy network driver file: %d (0x%X)\n", err, err);
            ResetConsoleColor();
            SendLogToMain("[驱动错误] TianHongHips.Network 网络过滤驱动 .sys 文件复制失败（请以管理员权限运行）");
            return FALSE;
        }
        printf("Network driver file copied successfully\n");
    }
    else
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("Error: network driver .sys not found: %s\n", sysPath);
        ResetConsoleColor();
        SendLogToMain("[驱动错误] TianHongHips.Network 网络过滤驱动 .sys 文件缺失（网络防护已禁用），请确保驱动文件与 Client 在同一目录");
        return FALSE;
    }

    printf("Installing network filter driver...\n");

    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL)
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("Cannot open SCM (error: %d)\n", GetLastError());
        ResetConsoleColor();
        SendLogToMain("[驱动错误] TianHongHips.Network 无法打开服务控制管理器（请以管理员权限运行）");
        return FALSE;
    }

    SC_HANDLE svc = OpenServiceA(scm, THSD_NETWORK_SERVICE_NAME_A, SERVICE_ALL_ACCESS);
    if (svc == NULL)
    {
        printf("Creating network filter service...\n");
        svc = CreateServiceA(
            scm,
            THSD_NETWORK_SERVICE_NAME_A,
            THSD_NETWORK_SERVICE_NAME_A,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            sysDestPath,
            NULL, NULL, NULL, NULL, NULL);
    }

    if (svc == NULL)
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS)
        {
            printf("Network filter service already exists\n");
            svc = OpenServiceA(scm, THSD_NETWORK_SERVICE_NAME_A, SERVICE_ALL_ACCESS);
        }
        if (svc == NULL)
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to create/open network filter service: %d\n", err);
            ResetConsoleColor();
            char logMsg[256];
            sprintf_s(logMsg, "[驱动错误] TianHongHips.Network 创建/打开服务失败 (错误码: %d)", err);
            SendLogToMain(logMsg);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    // 若服务被禁用，改为按需启动
    {
        DWORD dwBytesNeeded = 0;
        DWORD dwConfigSize = 0;
        if (QueryServiceConfigA(svc, NULL, 0, &dwBytesNeeded) == FALSE &&
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            LPQUERY_SERVICE_CONFIGA pConfig = (LPQUERY_SERVICE_CONFIGA)LocalAlloc(LPTR, dwBytesNeeded);
            if (pConfig != NULL)
            {
                if (QueryServiceConfigA(svc, pConfig, dwBytesNeeded, &dwConfigSize))
                {
                    if (pConfig->dwStartType == SERVICE_DISABLED)
                    {
                        printf("Network filter service disabled, enabling...\n");
                        ChangeServiceConfigA(svc, SERVICE_NO_CHANGE,
                            SERVICE_DEMAND_START, SERVICE_NO_CHANGE,
                            NULL, NULL, NULL, NULL, NULL, NULL, NULL);
                    }
                }
                LocalFree(pConfig);
            }
        }
    }

    // 启动服务
    printf("Starting network filter service...\n");
    if (StartServiceA(svc, 0, NULL))
    {
        printf("Network filter service start accepted, waiting...\n");
        const int SVC_WAIT_RETRIES = 20;
        const int SVC_WAIT_INTERVAL_MS = 500;
        BOOL serviceRunning = FALSE;
        for (int i = 0; i < SVC_WAIT_RETRIES; i++)
        {
            SERVICE_STATUS svcStatus;
            if (QueryServiceStatus(svc, &svcStatus))
            {
                if (svcStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    serviceRunning = TRUE;
                    printf("Network filter service RUNNING (after %d ms)\n",
                        (i + 1) * SVC_WAIT_INTERVAL_MS);
                    break;
                }
                if (svcStatus.dwCurrentState == SERVICE_STOPPED)
                {
                    SetConsoleColor(ConsoleColor::Red);
                    printf("Network filter service stopped during startup (exit: %u)\n",
                        svcStatus.dwWin32ExitCode);
                    ResetConsoleColor();
                    char logMsg[256];
                    sprintf_s(logMsg, "[驱动错误] TianHongHips.Network 服务启动后立即停止 (退出码: %u)，可能需要开启测试签名(bcdedit /set testsigning on)",
                        svcStatus.dwWin32ExitCode);
                    SendLogToMain(logMsg);
                    CloseServiceHandle(svc);
                    CloseServiceHandle(scm);
                    return FALSE;
                }
            }
            Sleep(SVC_WAIT_INTERVAL_MS);
        }
        if (!serviceRunning)
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Network filter did not reach RUNNING within %d ms\n",
                SVC_WAIT_RETRIES * SVC_WAIT_INTERVAL_MS);
            ResetConsoleColor();
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }
    else
    {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_ALREADY_RUNNING)
        {
            printf("Network filter service already running\n");
        }
        else
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("Failed to start network filter service: %d\n", err);
            ResetConsoleColor();
            char logMsg[256];
            sprintf_s(logMsg, "[驱动错误] TianHongHips.Network 启动服务失败 (错误码: %d)，可能需要开启测试签名(bcdedit /set testsigning on)", err);
            SendLogToMain(logMsg);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return FALSE;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    // 打开设备句柄
    g_hNetworkDevice = CreateFileW(THSD_NETWORK_USER_DEVICE_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_hNetworkDevice == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        SetConsoleColor(ConsoleColor::Yellow);
        printf("Warning: cannot open network filter device: %d\n", err);
        ResetConsoleColor();
        // 重试
        for (int i = 0; i < 10; i++)
        {
            Sleep(500);
            g_hNetworkDevice = CreateFileW(THSD_NETWORK_USER_DEVICE_PATH_W,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (g_hNetworkDevice != INVALID_HANDLE_VALUE) break;
        }
    }

    if (g_hNetworkDevice != INVALID_HANDLE_VALUE)
    {
        // 启用网络防护
        ULONG enable = 1;
        DWORD bytesReturned;
        DeviceIoControl(g_hNetworkDevice, IOCTL_NETWORK_SET_ENABLED,
            &enable, sizeof(enable), NULL, 0, &bytesReturned, NULL);
        g_bNetworkProtectionEnabled = TRUE;
        printf("Network filter device opened and protection enabled\n");
        SendLogToMain("[驱动加载] TianHongHips.Network 网络过滤驱动已启动");
    }
    else
    {
        printf("Warning: network filter device not available, DoH/C2 detection disabled\n");
        SendLogToMain("[驱动警告] TianHongHips.Network 服务已启动但无法打开设备句柄（DoH/C2检测已禁用），请检查 DbgView 中的驱动加载日志");
    }

    return TRUE;
}

// ============================================================================
// SendDiskAlertToMain - 将 MBR 写入告警转发给 main.cpp
// 通过 TCP socket 发送 ALERT 消息，复用 ClientAlertData 结构
// ============================================================================
void SendDiskAlertToMain(const DISK_FILTER_ALERT* alert)
{
    if (g_clientSocket == INVALID_SOCKET || !g_bSocketConnected)
        return;

    ClientAlertData alertData;
    ZeroMemory(&alertData, sizeof(alertData));
    alertData.pid = alert->pid;
    alertData.parentPid = 0;

    /* 标题标识为 MBR 防护告警，main.cpp 据此选择对应的防护开关检查 */
    strncpy_s(alertData.title, sizeof(alertData.title),
        "[MBR防护] 检测到引导区写入尝试", _TRUNCATE);

    /* 构建告警消息 */
    char msg[2048];
    sprintf_s(msg, sizeof(msg),
        "检测到进程尝试写入磁盘引导区（MBR保护）\n\n"
        "进程名：%s (PID: %lld)\n"
        "进程路径：%s\n"
        "目标磁盘：PhysicalDrive%lu\n"
        "设备名：%s\n"
        "写入偏移：%lld 字节\n"
        "写入长度：%lu 字节\n\n"
        "该写入已被拦截。是否允许此操作？",
        alert->processName[0] ? alert->processName : "Unknown",
        alert->pid,
        alert->processPath[0] ? alert->processPath : "Unknown",
        alert->diskNumber,
        alert->deviceName,
        alert->byteOffset.QuadPart,
        alert->writeLength);
    strncpy_s(alertData.message, sizeof(alertData.message), msg, _TRUNCATE);

    alertData.processPath[0] = '\0';
    alertData.parentName[0] = '\0';
    alertData.parentPath[0] = '\0';

    Packet pkt;
    ZeroMemory(&pkt, sizeof(pkt));
    pkt.PacketTyped = PTClientMessage;
    strncpy_s(pkt.InfoTitle, sizeof(pkt.InfoTitle), CLIENT_MSG_ALERT, _TRUNCATE);
    pkt.Pid = (int)alert->pid;
    memcpy(pkt.Message, &alertData, sizeof(alertData));

    int sent = send(g_clientSocket, (char*)&pkt, sizeof(pkt), 0);
    if (sent <= 0)
    {
        printf("[DISK-ALERT] Failed to send MBR alert to main: WSAGetLastError=%d\n",
            WSAGetLastError());
    }
    else
    {
        printf("[DISK-ALERT] MBR write alert sent to main (PID=%lld Disk=%lu)\n",
            alert->pid, alert->diskNumber);
    }
}

// ============================================================================
// HandleDiskAlerts - 后台线程，轮询磁盘过滤驱动的 MBR 写入告警 + 日志
// ============================================================================
void HandleDiskAlerts()
{
    SetConsoleColor(ConsoleColor::Cyan);
    printf("[*] Disk alert polling thread started\n");
    ResetConsoleColor();

    DISK_FILTER_ALERT alert;
    DISK_FILTER_LOG   diskLog;
    DWORD bytesReturned = 0;
    DWORD pollCount = 0;

    while (g_bRunning)
    {
        if (g_hDiskDevice == INVALID_HANDLE_VALUE)
        {
            Sleep(1000);
            continue;
        }

        pollCount++;

        /* ── 1. 轮询 MBR 写入告警 ── */
        ZeroMemory(&alert, sizeof(alert));
        bytesReturned = 0;

        BOOL success = DeviceIoControl(
            g_hDiskDevice,
            IOCTL_DISK_FILTER_POLL_ALERT,
            NULL, 0,
            &alert, sizeof(alert),
            &bytesReturned,
            NULL
        );

        if (!success)
        {
            Sleep(200);
            continue;
        }

        if (bytesReturned >= sizeof(alert))
        {
            /* 收到 MBR 写入告警 */
            SetConsoleColor(ConsoleColor::Red);
            printf("============================================\n");
            printf("[MBR-ALERT] Boot region write detected!\n");
            printf("  Process: %s (PID: %lld)\n", alert.processName, alert.pid);
            printf("  Path: %s\n", alert.processPath);
            printf("  Disk: PhysicalDrive%lu\n", alert.diskNumber);
            printf("  Offset: %lld bytes\n", alert.byteOffset.QuadPart);
            printf("  Length: %lu bytes\n", alert.writeLength);
            printf("  [Write BLOCKED, alerting user]\n");
            printf("============================================\n");
            ResetConsoleColor();

            /* 转发告警到 main.cpp */
            SendDiskAlertToMain(&alert);
        }
        else
        {
            /* 无告警，短暂等待 */
            Sleep(200);
        }

        /* ── 2. 轮询磁盘驱动日志，转发到 main UI ──
         * 每次循环拉取所有待处理日志（最多 32 条，防止单次循环耗时过长），
         * 通过 CLIENT_MSG_LOG 通道转发，main.cpp 接收后显示为 "[驱动] ..." */
        for (int logIdx = 0; logIdx < 32; logIdx++)
        {
            ZeroMemory(&diskLog, sizeof(diskLog));
            bytesReturned = 0;

            success = DeviceIoControl(
                g_hDiskDevice,
                IOCTL_DISK_FILTER_POLL_LOG,
                NULL, 0,
                &diskLog, sizeof(diskLog),
                &bytesReturned,
                NULL
            );

            if (!success || bytesReturned < sizeof(diskLog))
            {
                break;  /* 无更多日志或出错 */
            }

            /* 控制台输出（便于调试） */
            SetConsoleColor(ConsoleColor::DarkGray);
            printf("%s\n", diskLog.Message);
            ResetConsoleColor();

            /* 转发到 main UI（复用 LOG 通道，main.cpp 会显示为 "[驱动] ..."） */
            if (g_bSocketConnected)
            {
                Packet logPkt = {};
                logPkt.PacketTyped = PTClientMessage;
                strcpy_s(logPkt.InfoTitle, CLIENT_MSG_LOG);
                strncpy_s(logPkt.Message, diskLog.Message, _TRUNCATE);
                SendPacketToMain(logPkt);
            }
        }
    }

    printf("[*] Disk alert polling thread exiting\n");
}

// ============================================================================
// HandleUserQueries - 后台线程，轮询驱动检测事件
// 使用 MessageBox 弹窗询问用户，避免与控制台输出冲突
// ============================================================================
void HandleUserQueries()
{
    SetConsoleColor(ConsoleColor::Cyan);
    printf("[*] Background query thread started, polling for driver events...\n");
    ResetConsoleColor();

    // 本地控制台输出保留；不再向 mainUI 发送诊断日志，避免日志刷屏
    COMM_RESPONSE_PACKET requestPacket;
    COMM_RESPONSE_PACKET responsePacket;
    DWORD bytesReturned = 0;
    DWORD pollCount = 0;
    BOOL lastSuccess = TRUE;
    DWORD lastError = 0;

    while (g_bRunning)
    {
        pollCount++;

            // ── 轮询网络过滤驱动事件，转发给主驱动做行为分析 ──
            if (g_hNetworkDevice != INVALID_HANDLE_VALUE && g_hDevice != INVALID_HANDLE_VALUE)
            {
                NETWORK_EVENT_DATA netEvt;
                DWORD bytesReturned;
                while (DeviceIoControl(g_hNetworkDevice, IOCTL_NETWORK_POLL_EVENT,
                    NULL, 0, &netEvt, sizeof(netEvt), &bytesReturned, NULL) &&
                    bytesReturned == sizeof(netEvt))
                {
                    // 将 NETWORK_EVENT_DATA 转换为 ETW_NETWORK_EVENT_DATA 格式
                    // 网络驱动的事件类型值与主驱动 Common.h 不一致，需要映射：
                    //   网络驱动: DOH=0, C2=1, HTTP_POST=2, DNS_QUERY=3, DNS_TUNNEL=5, C2_PORT=6, TCP_CONNECT=7
                    //   主驱动ETW: TCP_CONNECT=1, DOH/DNS需映射到对应EventId
                    ETW_NETWORK_EVENT_DATA etwEvt;
                    ZeroMemory(&etwEvt, sizeof(etwEvt));
                    etwEvt.CallerPid = netEvt.CallerPid;
                    // 映射网络驱动事件类型到ETW事件ID
                    switch (netEvt.EventType)
                    {
                    case 0: /* NET_EVENT_DOH_CONNECT      */ etwEvt.EventId = 1; break; // DoH → TCP connect
                    case 1: /* NET_EVENT_C2_CONNECT       */ etwEvt.EventId = 1; break; // C2连接 → TCP connect
                    case 2: /* NET_EVENT_HTTP_POST_LARGE  */ etwEvt.EventId = 1; break; // 大流量POST → TCP connect
                    case 3: /* NET_EVENT_DNS_QUERY        */ etwEvt.EventId = 4; break; // DNS查询
                    case 5: /* NET_EVENT_DNS_TUNNEL       */ etwEvt.EventId = 4; break; // DNS隧道
                    case 6: /* NET_EVENT_C2_PORT          */ etwEvt.EventId = 1; break; // C2端口 → TCP connect
                    case 7: /* NET_EVENT_TCP_CONNECT      */ etwEvt.EventId = 1; break; // TCP连接
                    default: etwEvt.EventId = netEvt.EventType; break;
                    }
                    etwEvt.Protocol = netEvt.Protocol;
                    etwEvt.LocalPort = netEvt.LocalPort;
                    etwEvt.RemotePort = netEvt.RemotePort;
                    memcpy(etwEvt.RemoteAddress, netEvt.RemoteAddress, 16);
                    etwEvt.RemoteAddressType = netEvt.RemoteAddressType;
                    etwEvt.IsOutbound = netEvt.IsOutbound;
                    etwEvt.ProcessNameOffset = netEvt.ProcessNameOffset;
                    etwEvt.PayloadSize = (netEvt.PayloadSize < sizeof(etwEvt.Payload)) ?
                        netEvt.PayloadSize : sizeof(etwEvt.Payload);
                    memcpy(etwEvt.Payload, netEvt.Payload, etwEvt.PayloadSize);

                    // 转发给主驱动
                    DeviceIoControl(g_hDevice, IOCTL_BEHAVIOR_ETW_NETWORK_EVENT,
                        &etwEvt, sizeof(etwEvt), NULL, 0, &bytesReturned, NULL);

                    printf("[NET-EVENT] PID=%lld Type=%lu(ETW=%lu) Port=%lu AddrType=%lu\n",
                        netEvt.CallerPid, netEvt.EventType, etwEvt.EventId,
                        netEvt.RemotePort, netEvt.RemoteAddressType);
                }
            }

        // 检查是否有待处理的请求
        ZeroMemory(&requestPacket, sizeof(requestPacket));
        lastError = 0;
        BOOL success = DeviceIoControl(
            g_hCommDevice,
            IOCTL_RULE_DETECTED_REQUEST,
            NULL, 0,
            &requestPacket, sizeof(requestPacket),
            &bytesReturned,
            NULL
        );
        lastSuccess = success;

        if (!success)
        {
            lastError = GetLastError();
            Sleep(100);
            continue;
        }

        // 诊断信息仅在 Client 控制台输出，不再转发到 mainUI
        {
            static BOOL bFirstEvent = TRUE;
            if (bFirstEvent)
            {
                bFirstEvent = FALSE;
                COMM_RULE_DETECTED* dbgRule = (COMM_RULE_DETECTED*)requestPacket.Data;
                printf("[DIAG] First event: Type=%d, RuleType=%d, RuleId=%d, bytesReturned=%lu\n",
                    (int)requestPacket.Type, dbgRule->RuleType, dbgRule->RuleId, bytesReturned);
            }
        }

        if (pollCount <= 5) {
            printf("[DIAG] Packet #%lu: Type=%d, bytesReturned=%lu\n",
                pollCount, (int)requestPacket.Type, bytesReturned);
            if (requestPacket.Type == RESPONSE_RULE_DETECTED) {
                COMM_RULE_DETECTED* dbgRule = (COMM_RULE_DETECTED*)requestPacket.Data;
                printf("[DIAG]   RuleType=%d, RuleId=%d, Pid=%d\n",
                    dbgRule->RuleType, dbgRule->RuleId, dbgRule->ProcessPid);
            }
            fflush(stdout);
        }

        if (requestPacket.Type == RESPONSE_RULE_DETECTED)
        {
            COMM_RULE_DETECTED* ruleDetected = (COMM_RULE_DETECTED*)requestPacket.Data;

            // 行为分析日志：直接打印到控制台，不弹窗
            if (ruleDetected->RuleType == RULE_TYPE_BEHAVIOR)
            {
                BEHAVIOR_DETECTED_RESPONSE* behResponse = (BEHAVIOR_DETECTED_RESPONSE*)ruleDetected->Data;

                SetConsoleColor(ConsoleColor::Yellow);
                printf("============================================\n");
                printf("[BA-ALERT] Behavior analysis threat detected\n");
                printf("  Threat class: %s\n", behResponse->ThreatClass);
                printf("  Threat description: %s\n", behResponse->Description);
                printf("  Process path: %s\n", behResponse->ProcessPath);
                printf("  Process PID:  %lld\n", behResponse->Pid);
                printf("  Confidence:   %.1f%%\n", behResponse->Confidence * 100.0);
                if (behResponse->EvidenceCount > 0) {
                    printf("  Evidence:\n");
                    for (int ei = 0; ei < behResponse->EvidenceCount; ei++) {
                        printf("    - %s\n", behResponse->Evidence[ei]);
                    }
                }
                printf("  [Process suspended, awaiting user decision]\n");
                printf("============================================\n");
                ResetConsoleColor();

                /* Show MessageBox for user decision: Allow or Terminate */
                char baMsg[4096];
                char baTitle[256];
                /* 句柄层实时注入检测（DefenseEvasion/Injection:XXX.T1055）属于内存防护范畴，
                 * message 使用 [内存防护] 前缀让主程序检查 pMemorySwitch；
                 * 勒索行为分析（Behavior/Ransomware:XXX）使用 [勒索防护] 前缀；
                 * 行为分析定时器检测到的其他威胁使用 [行为分析] 前缀。 */
                const char* baChineseTag;
                if (behResponse->ThreatClass[0] &&
                    strncmp(behResponse->ThreatClass, "DefenseEvasion/Injection", 24) == 0)
                    baChineseTag = "内存防护";
                else if (behResponse->ThreatClass[0] &&
                         (strncmp(behResponse->ThreatClass, "DefenseEvasion/Ntdll", 20) == 0 ||
                          strncmp(behResponse->ThreatClass, "DefenseEvasion/AMSI", 19) == 0 ||
                          strncmp(behResponse->ThreatClass, "DefenseEvasion/DirectSyscall", 28) == 0 ||
                          strncmp(behResponse->ThreatClass, "DefenseEvasion/IndirectSyscall", 30) == 0))
                    baChineseTag = "内存防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "Behavior/Ransomware", 19) == 0)
                    baChineseTag = "勒索防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "LateralMovement/DCOM", 20) == 0)
                    baChineseTag = "DCOM防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "Trojan.SilverFox", 16) == 0)
                    baChineseTag = "行为防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "Trojan.AVBypass", 15) == 0)
                    baChineseTag = "反绕过防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "Trojan.Rootkit", 14) == 0)
                    baChineseTag = "根kit防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "Trojan.Exploit", 14) == 0)
                    baChineseTag = "漏洞利用防护";
                else if (behResponse->ThreatClass[0] &&
                         strncmp(behResponse->ThreatClass, "PrivilegeEscalation", 20) == 0)
                    baChineseTag = "进程保护";
                else
                    baChineseTag = "行为分析";

                string baDescUtf8 = AnsiToUtf8(behResponse->Description);
                string baThreatClassUtf8 = AnsiToUtf8(behResponse->ThreatClass);

                /* title 使用映射后的简洁中文，不含 Confidence，避免弹窗标题过长 */
                const char* baTitleSrc = MapAlertTitle(behResponse->ThreatClass);
                sprintf_s(baTitle, sizeof(baTitle), "%s", baTitleSrc);

                /* 使用 baChineseTag 作为正文前缀，让主程序正确识别防护类型 */
                string baProcessPathUtf8 = AnsiToUtf8(NormalizeKernelPath(behResponse->ProcessPath).c_str());
                string baParentNameUtf8 = AnsiToUtf8(ruleDetected->ParentName);
                int baOffset = sprintf_s(baMsg, sizeof(baMsg),
                    "[content]\r\n"
                    "[%s] 检测到威胁\r\n\r\n"
                    "威胁类型：%s\r\n"
                    "置信度：%.1f%%\r\n"
                    "进程路径：%s\r\n"
                    "父进程：%s (PID=%d)\r\n",
                    baChineseTag,
                    baThreatClassUtf8.empty() ? "Unknown" : baThreatClassUtf8.c_str(),
                    behResponse->Confidence * 100.0,
                    baProcessPathUtf8.empty() ? "Unknown" : baProcessPathUtf8.c_str(),
                    baParentNameUtf8.empty() ? "Unknown" : baParentNameUtf8.c_str(),
                    ruleDetected->ParentPid);

                if (behResponse->EvidenceCount > 0) {
                    int maxEv = behResponse->EvidenceCount;
                    if (maxEv > BA_ALERT_EVIDENCE_MAX) maxEv = BA_ALERT_EVIDENCE_MAX;

                    baOffset += sprintf_s(baMsg + baOffset, sizeof(baMsg) - baOffset,
                        "\r\n行为证据：");

                    for (int ei = 0; ei < maxEv; ei++) {
                        string evUtf8 = AnsiToUtf8(behResponse->Evidence[ei]);
                        if (evUtf8.empty()) continue;
                        if (evUtf8.size() >= 2 && evUtf8.compare(0, 2, "W:") == 0) continue;
                        baOffset += sprintf_s(baMsg + baOffset, sizeof(baMsg) - baOffset,
                            "\r\n  - %s", evUtf8.c_str());
                    }
                }

                baOffset += sprintf_s(baMsg + baOffset, sizeof(baMsg) - baOffset,
                    "\r\n\r\n进程树已被挂起，请选择：\r\n"
                    "  允许 = 恢复进程树\r\n"
                    "  阻止 = 终止进程树，并询问是否回滚已释放的文件/注册表修改");

                /* traffic 模式：必须转发告警到主程序的 Qt alert 对话框，
                 * 禁止在 Client 侧弹出本地 MessageBox。转发失败或超时按
                 * timeout/block 处理（decision=1）。 */
                int baChoice;
                if (g_bSocketConnected)
                {
                    if (behResponse->SilentMode)
                    {
                        /* 静默模式：不阻塞询问用户，直接通知主程序弹窗并记录日志，
                         * 然后自动阻止。 */
                        SetConsoleColor(ConsoleColor::Cyan);
                        printf("[ALERT-FWD] Silent mode: sending ALERT to mainUI PID=%lld class=%s\n",
                            behResponse->Pid, behResponse->ThreatClass);
                        ResetConsoleColor();

                        char silentTitle[256];
                        snprintf(silentTitle, sizeof(silentTitle), "[Silent] %s", baTitle);

                        SendAlertNoWait(
                            behResponse->Pid,
                            silentTitle,
                            baMsg,
                            ruleDetected->ParentPid,
                            ruleDetected->ParentName,
                            ruleDetected->ParentName,
                            behResponse->ProcessPath);

                        baChoice = IDNO;
                    }
                    else
                    {
                        SetConsoleColor(ConsoleColor::Cyan);
                        printf("[ALERT-FWD] Sending ALERT to mainUI PID=%lld class=%s\n",
                            behResponse->Pid, behResponse->ThreatClass);
                        ResetConsoleColor();

                        int socketResult = SendAlertAndWaitResponse(
                            behResponse->Pid, baTitle, baMsg,
                            ruleDetected->ParentPid,
                            ruleDetected->ParentName,
                            ruleDetected->ParentName,
                            behResponse->ProcessPath);

                        SetConsoleColor(ConsoleColor::Cyan);
                        if (socketResult < 0)
                            printf("[ALERT-FWD] SendAlertAndWaitResponse failed (socket error), treat as block\n");
                        else if (socketResult == 2)
                            printf("[ALERT-FWD] SendAlertAndWaitResponse timeout, treat as block\n");
                        else
                            printf("[ALERT-FWD] Received decision=%d (0=Allow,1=Block) PID=%lld\n",
                                socketResult, behResponse->Pid);
                        ResetConsoleColor();

                        if (socketResult < 0)
                        {
                            baChoice = IDNO;
                        }
                        else if (socketResult == 2)
                        {
                            baChoice = IDNO; /* timeout -> block */
                        }
                        else
                        {
                            /* main.cpp 发送的 decision：0=Allow, 1=Block
                             * MessageBox 语义：IDYES=Allow, IDNO=Block */
                            baChoice = (socketResult == 0) ? IDYES : IDNO;
                        }
                    }
                }
                else
                {
                    /* 非 traffic 模式：不再弹出本地 Windows MessageBox，直接默认阻止。
                     * 弹窗统一由主程序的 NewMessageBox 处理；socket 未连接时按静默
                     * 阻止策略执行，避免在控制台服务侧弹窗阻塞。 */
                    SetConsoleColor(ConsoleColor::Yellow);
                    printf("[ALERT-FWD] Socket not connected, default block PID=%lld (no local MessageBox)\n",
                        behResponse->Pid);
                    ResetConsoleColor();

                    baChoice = IDNO;
                }

                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* baResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;

                if (baChoice == IDYES) {
                    baResult->nts = STATUS_SUCCESS;
                    strcpy_s(baResult->Data, "User allowed");
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[>] User allowed (PID=%lld)\n", behResponse->Pid);
                } else {
                    baResult->nts = STATUS_ACCESS_DENIED;
                    strcpy_s(baResult->Data, "User terminated");
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[>] User terminated process tree (PID=%lld) - Will cleanup released files\n", behResponse->Pid);
                }
                ResetConsoleColor();

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else if (ruleDetected->RuleType == RULE_TYPE_PROCESS_CHECK)
            {
                SetConsoleColor(ConsoleColor::Yellow);
                printf("[PROCESS-CHECK] PID=%d Path=%s Blocking=%d\n",
                    ruleDetected->ProcessPid,
                    ruleDetected->ProcessPath[0] ? ruleDetected->ProcessPath : "Unknown",
                    g_bProcessCheckBlocking ? 1 : 0);
                ResetConsoleColor();

                int allow = 1;

                if (g_bProcessCheckBlocking && g_bSocketConnected)
                {
                    /* 阻塞检查模式（完整扫描）：将进程信息发给 main.cpp 并等待扫描结果。
                     * 驱动端已将新进程挂起，这里根据主程序决策返回 Allow/Block。
                     * 由 ProtectionSettingPage 的 pIsFullScanSwitch 控制。 */
                    allow = SendProcessCheckAndWait(
                        (INT64)ruleDetected->ProcessPid,
                        (INT64)ruleDetected->ParentPid,
                        ruleDetected->ProcessPath,
                        GetDisplayProcessName(ruleDetected),
                        ruleDetected->ParentName[0] ? ruleDetected->ParentName : "Unknown");
                }
                else
                {
                    /* 非阻塞检查模式（快速扫描）：只把进程信息作为 ALERT 发给 main.cpp
                     * 记录/弹窗，不等待响应，立即放行被挂起的进程。
                     * 真正的阻断由 HIPS/文件防护/行为检测等后续机制负责。 */
                    if (g_bSocketConnected)
                    {
                        char title[128];
                        char message[3960];
                        string procNameUtf8 = AnsiToUtf8(GetDisplayProcessName(ruleDetected));
                        string procPathUtf8 = AnsiToUtf8(ruleDetected->ProcessPath[0] ? ruleDetected->ProcessPath : "Unknown");
                        string parentNameUtf8 = AnsiToUtf8(ruleDetected->ParentName[0] ? ruleDetected->ParentName : "Unknown");
                        const char* pName = procNameUtf8.empty() ? "Unknown" : procNameUtf8.c_str();
                        const char* pPath = procPathUtf8.empty() ? "Unknown" : procPathUtf8.c_str();
                        const char* parName = parentNameUtf8.empty() ? "Unknown" : parentNameUtf8.c_str();

                        snprintf(title, sizeof(title),
                            "[进程启动检查] PID=%d %s",
                            ruleDetected->ProcessPid, pName);

                        snprintf(message, sizeof(message),
                            "[进程启动检查]\n进程: %s (PID=%d)\n路径: %s\n父进程: %s (PID=%d)\n",
                            pName, ruleDetected->ProcessPid, pPath, parName, ruleDetected->ParentPid);

                        SendAlertNoWait((INT64)ruleDetected->ProcessPid, title, message,
                            (INT64)ruleDetected->ParentPid,
                            ruleDetected->ParentName,
                            ruleDetected->ParentName,
                            ruleDetected->ProcessPath);

                    }

                }

                /* 返回驱动：Allow 时恢复进程，Block 时由驱动终止进程 */
                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* checkResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;
                checkResult->nts = (allow != 0) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
                strcpy_s(checkResult->Data, (allow != 0) ? "Allow" : "Block");

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else if (ruleDetected->RuleType == RULE_TYPE_DLL_SCAN)
            {
                SetConsoleColor(ConsoleColor::Yellow);
                const char* processPathStr = ruleDetected->ProcessPath[0] ? ruleDetected->ProcessPath : "Unknown";
                const char* dllPathStr = ruleDetected->DllPath[0] ? ruleDetected->DllPath : "Unknown";
                int isSideLoad = ruleDetected->IsSideLoad;
                printf("[DLL-SCAN] PID=%d Path=%s DLL=%s SideLoad=%d\n",
                    ruleDetected->ProcessPid,
                    processPathStr,
                    dllPathStr,
                    isSideLoad);
                ResetConsoleColor();

                int allow = 0;

                if (g_bSocketConnected)
                        {
                            char title[128];
                            char message[3960];
                            string procNameUtf8 = AnsiToUtf8(GetDisplayProcessName(ruleDetected));
                            string procPathUtf8 = AnsiToUtf8(ruleDetected->ProcessPath[0] ? ruleDetected->ProcessPath : "Unknown");
                            string dllPathUtf8 = AnsiToUtf8(ruleDetected->DllPath);
                            const char* pName = procNameUtf8.empty() ? "Unknown" : procNameUtf8.c_str();
                            const char* pPath = procPathUtf8.empty() ? "Unknown" : procPathUtf8.c_str();
                            const char* dPath = dllPathUtf8.empty() ? "Unknown" : dllPathUtf8.c_str();

                            snprintf(title, sizeof(title),
                                "[DLL 防护] PID=%d %s",
                                ruleDetected->ProcessPid,
                                pName);

                            snprintf(message, sizeof(message),
                                "[DLL 防护]\n发现未签名 DLL 加载！\n"
                                "进程: %s (PID=%d)\n路径: %s\n加载 DLL: %s\n",
                                pName,
                                ruleDetected->ProcessPid,
                                pPath,
                                dPath);

                            SendAlertNoWait((INT64)ruleDetected->ProcessPid, title, message,
                                (INT64)ruleDetected->ParentPid,
                                ruleDetected->ParentName,
                                ruleDetected->ParentName,
                                ruleDetected->ProcessPath);
                        }

                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* checkResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;
                checkResult->nts = (allow != 0) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
                strcpy_s(checkResult->Data, (allow != 0) ? "Allow" : "Block");

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else if (ruleDetected->RuleType == RULE_TYPE_ROLLBACK_CONFIRM)
            {
                /* 回滚确认：从驱动收到 BA_ROLLBACK_LIST，转发到 main.cpp 弹窗
                 * 等待用户选择后，将 BA_ROLLBACK_SELECTION 返回驱动 */
                BA_ROLLBACK_LIST* rollbackList = (BA_ROLLBACK_LIST*)ruleDetected->Data;

                SetConsoleColor(ConsoleColor::Yellow);
                printf("[ROLLBACK] Received rollback list: rootPid=%lld items=%d class=%s\n",
                    rollbackList->rootPid, rollbackList->itemCount, rollbackList->threatClass);
                ResetConsoleColor();

                BA_ROLLBACK_SELECTION sel = {0};
                int rbResult = SendRollbackConfirmAndWait(rollbackList, &sel);

                if (rbResult == 1)
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[ROLLBACK] User decision: %s (items=%d)\n",
                        sel.decision == 1 ? "ROLLBACK" : "IGNORE", sel.itemCount);
                    ResetConsoleColor();
                }
                else
                {
                    /* 超时/失败：默认忽略 */
                    sel.decision = 0;
                    sel.itemCount = 0;
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[ROLLBACK] Timeout/failure, default ignore\n");
                    ResetConsoleColor();
                }

                /* 返回驱动：将 BA_ROLLBACK_SELECTION 放入 Data */
                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* rbResultPacket = (COMM_RESPONSE_RESULT*)responsePacket.Data;
                rbResultPacket->nts = STATUS_SUCCESS;
                memcpy(rbResultPacket->Data, &sel, sizeof(BA_ROLLBACK_SELECTION));

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else if (ruleDetected->RuleType == RULE_TYPE_INJECTION_LOG)
            {
                /* 注入日志：转发到 main.cpp 日志显示（不再在 Client 控制台输出调试信息） */
                INJECTION_LOG_DATA* logData = (INJECTION_LOG_DATA*)ruleDetected->Data;

                /* 勒索防护 Paging IO 告警：驱动端检测到诱捕文件被 Paging IO 写入，
                 * 需要终止可疑进程并通知 MainUI 弹窗提示。 */
                if (strncmp(logData->Message, "[勒索防护-PAGING]", 17) == 0)
                {
                    /* 解析 PID */
                    INT64 pagingPid = 0;
                    const char* pidStr = strstr(logData->Message, "PID=");
                    if (pidStr)
                        pagingPid = _atoi64(pidStr + 4);

                    /* PID 0/4 是系统进程，不终止 */
                    if (pagingPid > 4)
                    {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pagingPid);
                        if (hProc)
                        {
                            TerminateProcess(hProc, 1);
                            CloseHandle(hProc);
                            SetConsoleColor(ConsoleColor::Red);
                            printf("[勒索防护-PAGING] 已终止进程 PID=%lld (Paging IO 写入诱捕文件)\n", pagingPid);
                            ResetConsoleColor();
                        }
                    }

                    /* 发送告警到 MainUI（通过 LOG 通道，MainUI 识别 [勒索防护-PAGING] 弹窗） */
                    if (g_bSocketConnected)
                    {
                        Packet alertPkt = {};
                        alertPkt.PacketTyped = PTClientMessage;
                        strcpy_s(alertPkt.InfoTitle, CLIENT_MSG_LOG);
                        strncpy_s(alertPkt.Message, logData->Message, _TRUNCATE);
                        SendPacketToMain(alertPkt);
                    }
                }
                else if (g_bSocketConnected)
                {
                    /* 普通注入日志：转发到 main.cpp */
                    Packet packet = {};
                    packet.PacketTyped = PTClientMessage;
                    strcpy_s(packet.InfoTitle, CLIENT_MSG_LOG);
                    strncpy_s(packet.Message, logData->Message, _TRUNCATE);
                    SendPacketToMain(packet);
                }

                /* 发送响应释放驱动端请求 */
                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* logResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;
                logResult->nts = STATUS_SUCCESS;
                strcpy_s(logResult->Data, "Log received");

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else if (ruleDetected->RuleType == RULE_TYPE_ROLLBACK_LOG)
            {
                /* 回滚记录（溢出丢磁盘）：驱动 g_baDroppedFiles/g_baRegOps 溢出时上报，
                 * 转发到 main.cpp 持久化到行为磁盘缓存（300MB 上限），供回滚参考。 */
                PBA_ROLLBACK_LOG_RECORD rbRec = (PBA_ROLLBACK_LOG_RECORD)ruleDetected->Data;

                if (g_bSocketConnected)
                {
                    Packet rbPkt = {};
                    rbPkt.PacketTyped = PTClientMessage;
                    strcpy_s(rbPkt.InfoTitle, CLIENT_MSG_ROLLBACK_LOG);
                    memcpy(rbPkt.Message, rbRec, sizeof(BA_ROLLBACK_LOG_RECORD));
                    SendPacketToMain(rbPkt);
                }

                /* 发送响应释放驱动端请求 */
                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* rbResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;
                rbResult->nts = STATUS_SUCCESS;
                strcpy_s(rbResult->Data, "Rollback log received");

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else if (ruleDetected->RuleType == RULE_TYPE_NTDLL_RELOAD)
            {
                /* ntdll 重载/Unhook 检测事件（AVBypass）：
                 * 此类事件的 Data 是 NTDLL_RELOAD_EVENT_DATA，不是 RULE_FILE_DETECTED_RESPONSE。
                 * R0 callback 检测到后转发给用户态，由用户态弹窗询问是否终止进程。
                 * R0 未启用时由 R3 hook 拦截，同样弹窗请求 terminate。
                 * 使用 [内存防护] 前缀让主程序检查 pMemorySwitch 开关。 */
                PNTDLL_RELOAD_EVENT_DATA pEvent = (PNTDLL_RELOAD_EVENT_DATA)ruleDetected->Data;

                SetConsoleColor(ConsoleColor::Yellow);
                printf("[NTDLL-RELOAD] PID=%lld Proc=%s Base=0x%llX Flags=0x%X IsHooked=%d\n",
                    (INT64)pEvent->ProcessId, pEvent->ProcessName,
                    (INT64)pEvent->ImageBase, pEvent->Flags, pEvent->IsHooked);
                ResetConsoleColor();

                /* 驱动端字段为 ANSI（RtlUnicodeStringToAnsiString），需先转 UTF-8
                 * 再混入 UTF-8 字符串字面量，否则 sprintf_s 产物编码混杂导致乱码。 */
                string procNameUtf8 = AnsiToUtf8(pEvent->ProcessName);
                string fullPathUtf8 = AnsiToUtf8(pEvent->FullImagePath);
                string procImgPathUtf8 = AnsiToUtf8(pEvent->ProcessImagePath);

                char ntdllMsg[1024];
                sprintf_s(ntdllMsg, sizeof(ntdllMsg),
                    "进程：%s (PID=%lld)\r\n"
                    "路径：%s\r\n"
                    "基址：0x%llX\r\n"
                    "标志：0x%X (IsHooked=%d, Reload=%d)\r\n\r\n"
                    "ntdll重载常用于绕过API hook，属于AVBypass行为。\r\n"
                    "请选择：\r\n"
                    "  允许 = 继续运行进程\r\n"
                    "  阻止 = 终止进程",
                    procNameUtf8.empty() ? "Unknown" : procNameUtf8.c_str(),
                    (INT64)pEvent->ProcessId,
                    fullPathUtf8.empty() ? "Unknown" : fullPathUtf8.c_str(),
                    (INT64)pEvent->ImageBase, pEvent->Flags, pEvent->IsHooked, pEvent->ReloadCount);

                /* 阻塞式询问用户是否终止进程 */
                int ntdllChoice = IDNO;  /* 默认阻止 */
                if (g_bSocketConnected)
                {
                    int socketResult = SendAlertAndWaitResponse(
                        (INT64)pEvent->ProcessId,
                        "发现ntdll重载绕过行为",
                        ntdllMsg,
                        (INT64)pEvent->ParentProcessId,
                        pEvent->ProcessName,
                        pEvent->ProcessImagePath,
                        pEvent->ProcessImagePath);

                    if (socketResult < 0)
                    {
                        SetConsoleColor(ConsoleColor::Yellow);
                        printf("[NTDLL-RELOAD] Alert forwarding failed, default block\n");
                        ResetConsoleColor();
                        ntdllChoice = IDNO;
                    }
                    else if (socketResult == 2)
                    {
                        ntdllChoice = IDNO; /* timeout -> block */
                    }
                    else
                    {
                        /* main.cpp 发送的 decision：0=Allow, 1=Block */
                        ntdllChoice = (socketResult == 0) ? IDYES : IDNO;
                    }
                }

                /* 用户选择阻止时终止进程 */
                if (ntdllChoice == IDNO)
                {
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[NTDLL-RELOAD] Terminating process PID=%lld (AVBypass)\n",
                        (INT64)pEvent->ProcessId);
                    ResetConsoleColor();

                    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pEvent->ProcessId);
                    if (hProc)
                    {
                        if (!TerminateProcess(hProc, 1))
                        {
                            SetConsoleColor(ConsoleColor::Yellow);
                            printf("[NTDLL-RELOAD] Failed to terminate PID=%lld err=%d\n",
                                (INT64)pEvent->ProcessId, GetLastError());
                            ResetConsoleColor();
                        }
                        CloseHandle(hProc);
                    }
                }

                /* FireAndForget：发送响应释放驱动端请求 */
                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* ntdllResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;
                ntdllResult->nts = (ntdllChoice == IDNO) ? STATUS_ACCESS_DENIED : STATUS_SUCCESS;
                strcpy_s(ntdllResult->Data,
                    (ntdllChoice == IDNO) ? "NtdllReload blocked - process terminated" : "NtdllReload allowed");

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }
            else
            {
                /* HIPS rules: 组织告警信息。
                 * 驱动端字段为 ANSI（RtlUnicodeStringToAnsiString），需先转 UTF-8 再发给 Qt UI。
                 * 进程名/父进程/路径已在 alert dialog 顶部显示，正文不再重复。 */
                char msg[4096];
                char title[256];
                string opDescUtf8 = ruleDetected->RuleDesc[0]
                    ? AnsiToUtf8(ruleDetected->RuleDesc)
                    : string("Suspicious operation");

                if (ruleDetected->RuleType == 0) {
                    RULE_REG_DETECTED_RESPONSE* regResponse = (RULE_REG_DETECTED_RESPONSE*)ruleDetected->Data;

                    string fullPathUtf8 = AnsiToUtf8(regResponse->FullPath);
                    string changeNameUtf8 = AnsiToUtf8(regResponse->ChangeName);
                    string changeValueUtf8 = AnsiToUtf8(regResponse->ChangeValue);

                    // 根据是否有值变更推断操作类型
                    const char* regOp = (regResponse->IsChangeValueEnabled && regResponse->ChangeValue[0])
                        ? "修改" : (regResponse->IsChangeNameEnabled && regResponse->ChangeName[0])
                        ? "创建" : "修改";

                    sprintf_s(title, sizeof(title), "[注册表防护 · %s]", regOp);

                    int offset = sprintf_s(msg, sizeof(msg),
                        "[注册表防护 · %s] 进程尝试%s注册表项。\r\n\r\n"
                        "目标路径：%s",
                        regOp, regOp,
                        fullPathUtf8.c_str());

                    if (regResponse->IsChangeNameEnabled && regResponse->ChangeName[0]) {
                        offset += sprintf_s(msg + offset, sizeof(msg) - offset,
                            "\r\n目标键值：%s", changeNameUtf8.c_str());
                    }
                    if (regResponse->IsChangeValueEnabled && regResponse->ChangeValue[0]) {
                        offset += sprintf_s(msg + offset, sizeof(msg) - offset,
                            "\r\n写入数据：%s", changeValueUtf8.c_str());
                    }

                    offset += sprintf_s(msg + offset, sizeof(msg) - offset,
                        "\r\n\r\n触犯规则：Registry#%d %s",
                        ruleDetected->RuleId, opDescUtf8.c_str());
                } else {
                    RULE_FILE_DETECTED_RESPONSE* fileResponse = (RULE_FILE_DETECTED_RESPONSE*)ruleDetected->Data;

                    string fullPathUtf8 = AnsiToUtf8(fileResponse->FullPath);
                    string fileNameUtf8 = AnsiToUtf8(fileResponse->FileName);

                    /* 勒索诱捕事件：通过 RuleDesc 识别（驱动端添加规则时设置
                     * Description="RansomHoneypot"）。相比 RuleId 范围判断更可靠，
                     * 不受 RuleId 分配策略变化影响，也不会与其它高 RuleId 规则冲突。 */
                    if (ruleDetected->RuleDesc[0] != '\0' &&
                        strstr(ruleDetected->RuleDesc, "RansomHoneypot") != NULL)
                    {
                        sprintf_s(title, sizeof(title), "[勒索防护] 已阻止文件诱捕触发");
                        sprintf_s(msg, sizeof(msg),
                            "[勒索防护] 检测到勒索软件行为（文件诱捕触发）\r\n\r\n"
                            "进程 %s (PID=%d) 正在修改/删除诱捕文件，疑似勒索软件行为。\r\n\r\n"
                            "目标路径：%s\\%s\r\n\r\n"
                            "触犯规则：RansomHoneypot#%d",
                            GetDisplayProcessName(ruleDetected),
                            ruleDetected->ProcessPid,
                            fullPathUtf8.c_str(), fileNameUtf8.c_str(),
                            ruleDetected->RuleId);
                    }
                    else
                    {
                        string changePathUtf8 = AnsiToUtf8(fileResponse->ChangePath);

                        // 推断文件操作类型
                        const char* fileOp = "写入";
                        if (fileResponse->IsChangePathEnabled && fileResponse->ChangePath[0])
                            fileOp = "重命名";
                        else if (opDescUtf8.find("DELETE") != string::npos ||
                                 opDescUtf8.find("delete") != string::npos)
                            fileOp = "删除";

                        sprintf_s(title, sizeof(title), "[文件防护 · %s]", fileOp);

                        int offset = sprintf_s(msg, sizeof(msg),
                            "[文件防护 · %s] 进程尝试%s文件。\r\n\r\n"
                            "目标路径：%s\\%s",
                            fileOp, fileOp,
                            fullPathUtf8.c_str(), fileNameUtf8.c_str());

                        if (fileResponse->IsChangePathEnabled && fileResponse->ChangePath[0]) {
                            offset += sprintf_s(msg + offset, sizeof(msg) - offset,
                                "\r\n重命名为：%s", changePathUtf8.c_str());
                        }

                        offset += sprintf_s(msg + offset, sizeof(msg) - offset,
                            "\r\n\r\n触犯规则：File#%d %s",
                            ruleDetected->RuleId, opDescUtf8.c_str());
                    }
                }

                /* Console log */
                SetConsoleColor(ConsoleColor::Red);
                printf("[HIPS-ALERT] RuleType=%s RuleID=%d PID=%d\n",
                    (ruleDetected->RuleType == 0) ? "Registry" : "File",
                    ruleDetected->RuleId, ruleDetected->ProcessPid);
                ResetConsoleColor();

                int userChoice;
                BOOL autoAllowedTaskScheduler = FALSE;

                /* Task Scheduler (Startup only) 规则：仅对包含自启动触发器的
                 * 任务文件告警；普通计划任务自动允许，避免合法任务修改持续弹窗。 */
                if (ruleDetected->RuleType == 1 &&
                    strstr(ruleDetected->RuleDesc, "Task Scheduler") != NULL)
                {
                    RULE_FILE_DETECTED_RESPONSE* fileResponse =
                        (RULE_FILE_DETECTED_RESPONSE*)ruleDetected->Data;
                    if (!IsTaskSchedulerStartupTask(fileResponse))
                    {
                        autoAllowedTaskScheduler = TRUE;
                        userChoice = IDYES;
                        SetConsoleColor(ConsoleColor::Cyan);
                        printf("[HIPS-AUTO] Task Scheduler non-startup task auto-allowed: %s\\%s\n",
                            fileResponse->FullPath, fileResponse->FileName);
                        ResetConsoleColor();
                    }
                }

                if (autoAllowedTaskScheduler)
                {
                    /* 已在上方自动允许 Task Scheduler 非自启动任务 */
                }
                else
                {
                    /* traffic 模式：必须转发告警到主程序的 Qt alert 对话框，
                     * 禁止在 Client 侧弹出本地 MessageBox。转发失败或超时按
                     * timeout/block 处理（decision=1）。 */
                    if (g_bSocketConnected)
                    {
                        int socketResult = SendAlertAndWaitResponse(
                            (INT64)ruleDetected->ProcessPid, title, msg,
                            (INT64)ruleDetected->ParentPid,
                            ruleDetected->ParentName,
                            ruleDetected->ParentName,
                            ruleDetected->ProcessPath);
                        if (socketResult < 0)
                        {
                            SetConsoleColor(ConsoleColor::Yellow);
                            printf("[!] Alert forwarding failed, treat as timeout/block\n");
                            ResetConsoleColor();
                            userChoice = IDNO;
                        }
                        else if (socketResult == 2)
                        {
                            userChoice = IDNO; /* timeout -> block */
                        }
                        else
                        {
                            /* main.cpp 发送的 decision：0=Allow, 1=Block
                             * MessageBox 语义：IDYES=Allow, IDNO=Block */
                            userChoice = (socketResult == 0) ? IDYES : IDNO;
                        }
                    }
                    else
                    {
                        /* 非 traffic 模式：不再弹出本地 Windows MessageBox，直接默认阻止。
                         * 告警弹窗统一由主程序 NewMessageBox 处理；socket 未连接时静默阻止。 */
                        SetConsoleColor(ConsoleColor::Yellow);
                        printf("[HIPS-ALERT] Socket not connected, default block RuleID=%d PID=%d (no local MessageBox)\n",
                            ruleDetected->RuleId, ruleDetected->ProcessPid);
                        ResetConsoleColor();

                        userChoice = IDNO;
                    }
                }

                ZeroMemory(&responsePacket, sizeof(responsePacket));
                responsePacket.Type = RESPONSE_RESULT;
                COMM_RESPONSE_RESULT* responseResult = (COMM_RESPONSE_RESULT*)responsePacket.Data;

                if (userChoice == IDYES) {
                    responseResult->nts = STATUS_SUCCESS;
                    strcpy_s(responseResult->Data, "User allowed");
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[>] User allowed (RuleID=%d)\n", ruleDetected->RuleId);
                } else {
                    responseResult->nts = STATUS_ACCESS_DENIED;
                    strcpy_s(responseResult->Data, "User blocked");
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[>] User blocked (RuleID=%d)\n", ruleDetected->RuleId);

                    /* 勒索诱捕事件：用户选择拦截时立即终止进程，防止勒索软件继续
                     * 加密其他文件。仅靠 STATUS_ACCESS_DENIED 只能阻止单次操作，
                     * 勒索软件会立即尝试下一个文件。
                     * 通过 RuleDesc 识别诱捕规则，与上方告警分支判断方式一致。 */
                    if (ruleDetected->RuleDesc[0] != '\0' &&
                        strstr(ruleDetected->RuleDesc, "RansomHoneypot") != NULL)
                    {
                        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE,
                                                    (DWORD)ruleDetected->ProcessPid);
                        if (hProc != NULL)
                        {
                            if (TerminateProcess(hProc, 1))
                            {
                                SetConsoleColor(ConsoleColor::Red);
                                printf("[!] Ransomware process terminated: PID=%d (%s)\n",
                                       ruleDetected->ProcessPid,
                                       GetDisplayProcessName(ruleDetected));
                                ResetConsoleColor();
                            }
                            else
                            {
                                SetConsoleColor(ConsoleColor::Yellow);
                                printf("[!] Failed to terminate ransomware process: PID=%d err=%d\n",
                                       ruleDetected->ProcessPid, GetLastError());
                                ResetConsoleColor();
                            }
                            CloseHandle(hProc);
                        }
                        else
                        {
                            SetConsoleColor(ConsoleColor::Yellow);
                            printf("[!] Cannot open ransomware process for termination: PID=%d err=%d\n",
                                   ruleDetected->ProcessPid, GetLastError());
                            ResetConsoleColor();
                        }
                    }
                }
                ResetConsoleColor();

                if (!DeviceIoControl(
                    g_hCommDevice,
                    IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                    &responsePacket, sizeof(responsePacket),
                    NULL, 0,
                    &bytesReturned,
                    NULL
                ))
                {
                    DWORD error = GetLastError();
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] DeviceIoControl failed (IOCTL_RULE_DETECTED_SEND_USER_RESPONSE): %d\n", error);
                    ResetConsoleColor();
                }
            }  /* end else (non-behavior) */
        }
    }

    SetConsoleColor(ConsoleColor::Cyan);
    printf("[*] Background query thread exited\n");
    ResetConsoleColor();
}

// ============================================================================
// SyncNetworkDiskETWRules - 同步 Network/Disk/ETW 动态规则到主驱动
// 在 Network/Disk 驱动启动后调用，加载 rules/behavior/ 下的 network/disk/etw_network.toml
// ============================================================================
void SyncNetworkDiskETWRules(HANDLE hDevice)
{
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL)
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("[-] SyncNetworkDiskETWRules: invalid device handle\n");
        ResetConsoleColor();
        return;
    }

    SetConsoleColor(ConsoleColor::Cyan);
    printf("[*] Syncing Network/Disk/ETW dynamic rules...\n");
    ResetConsoleColor();

    // 使用 DynamicRuleManagerV2 加载 rules/behavior/ 目录下的所有 TOML 规则
    // 包括 network.toml (RuleId 5001-5005), disk.toml (RuleId 6001-6006), etw_network.toml (RuleId 7001-7006)
    DynamicRuleManagerV2 netDiskRuleManager;
    if (netDiskRuleManager.Init(hDevice, "x64\\Release\\Resources\\rules\\behavior"))
    {
        SetConsoleColor(ConsoleColor::Green);
        printf("[+] Network/Disk/ETW dynamic rules synced successfully\n");
        ResetConsoleColor();
        SendLogToMain("[规则同步] Network/Disk/ETW 动态规则已同步到主驱动");
    }
    else
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("[-] SyncNetworkDiskETWRules: failed to load dynamic rules\n");
        ResetConsoleColor();
        SendLogToMain("[规则错误] Network/Disk/ETW 动态规则同步失败");
    }
}

// ============================================================================
// LoadHipsRules - 从 rules/hips/ 目录加载 HIPS 规则（TOML 格式）
// 所有 HIPS 规则均通过此函数从 TOML 文件加载，不再使用嵌入式 C 数组
// R0 启用时通过 IOCTL_ADD_RULE/IOCTL_ADD_FILE_RULE 下发到驱动
// R0 禁用时由 R3 DLL 加载
// ============================================================================
void LoadHipsRules(HANDLE hDevice)
{
    if (hDevice == INVALID_HANDLE_VALUE || hDevice == NULL)
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("[-] LoadHipsRules: invalid device handle\n");
        ResetConsoleColor();
        return;
    }

    // 构建 rules/hips/ 路径（相对于工作目录）
    char hipsDir[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, hipsDir);
    strncat_s(hipsDir, "\\..\\x64\\Release\\Resources\\rules\\hips", MAX_PATH - strlen(hipsDir) - 1);

    // 也尝试直接路径
    const char* altPaths[] = {
        "x64\\Release\\Resources\\rules\\hips",
        "Resources\\rules\\hips",
        NULL
    };
    bool dirFound = false;
    for (int pi = 0; altPaths[pi]; pi++) {
        struct __stat64 st;
        if (_stat64(altPaths[pi], &st) == 0 && (st.st_mode & _S_IFDIR)) {
            strncpy_s(hipsDir, MAX_PATH, altPaths[pi], _TRUNCATE);
            dirFound = true;
            break;
        }
    }
    if (!dirFound) {
        // 使用相对路径尝试
        strncpy_s(hipsDir, MAX_PATH, "x64\\Release\\Resources\\rules\\hips", _TRUNCATE);
    }

    SetConsoleColor(ConsoleColor::Cyan);
    printf("[*] Loading HIPS rules from: %s\n", hipsDir);
    ResetConsoleColor();

    // 扫描 .toml 文件
    std::string pattern = std::string(hipsDir) + "\\*.toml";
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);

    int totalLoaded = 0;
    int totalFailed = 0;

    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::string filePath = std::string(hipsDir) + "\\" + findData.cFileName;

            // 简单 TOML 解析：逐行读取 [rule] 块
            std::ifstream ifs(filePath.c_str());
            if (!ifs.is_open()) continue;

            std::string line;
            std::string currentRuleBlock;
            bool inRule = false;
            ULONG ruleId = 0;
            std::string ruleType;
            std::string opStr, pathStr, valueStr, flagStr;
            bool haveOp = false, havePath = false;

            auto flushRule = [&]() {
                if (!inRule || !haveOp || !havePath) {
                    currentRuleBlock.clear();
                    inRule = false;
                    return;
                }
                // 构造参数 map
                std::map<std::string, std::string> params;
                params["op"] = opStr;
                params["path"] = pathStr;
                if (!valueStr.empty()) params["value"] = valueStr;
                else params["value"] = "*";
                if (!flagStr.empty()) params["flag"] = flagStr;
                else params["flag"] = "SEF_ALL_BLOCKED";

                RULE_TYPE rt = (ruleType == "file") ? RULE_TYPE_FILE : RULE_TYPE_REG;
                if (SendRuleToDriver(hDevice, rt, params)) {
                    totalLoaded++;
                } else {
                    totalFailed++;
                    printf("  [-] Failed to load rule from %s\n", findData.cFileName);
                }
                currentRuleBlock.clear();
                inRule = false;
            };

            while (std::getline(ifs, line)) {
                // 去除前后空白
                size_t start = line.find_first_not_of(" \t\r\n");
                if (start == std::string::npos) continue;
                line = line.substr(start);
                size_t end = line.find_last_not_of(" \t\r\n");
                if (end != std::string::npos) line = line.substr(0, end + 1);

                // 跳过注释和空行
                if (line.empty() || line[0] == '#') continue;

                // 检测 [rule] 段开始
                if (line == "[rule]") {
                    flushRule();
                    inRule = true;
                    ruleId = 0;
                    ruleType = "reg";
                    opStr.clear(); pathStr.clear(); valueStr.clear(); flagStr.clear();
                    haveOp = false; havePath = false;
                    continue;
                }

                // 检测分隔符 ---
                if (line == "---") {
                    flushRule();
                    continue;
                }

                if (!inRule) continue;

                // 解析 key = value
                size_t eqPos = line.find('=');
                if (eqPos == std::string::npos) continue;
                std::string key = line.substr(0, eqPos);
                std::string val = line.substr(eqPos + 1);
                // 去引号
                if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
                    val = val.substr(1, val.size() - 2);
                if (val.size() >= 2 && val.front() == '\'' && val.back() == '\'')
                    val = val.substr(1, val.size() - 2);

                // 去除 key/val 空白
                {
                    size_t ks = key.find_first_not_of(" \t");
                    if (ks != std::string::npos) key = key.substr(ks);
                    size_t ke = key.find_last_not_of(" \t");
                    if (ke != std::string::npos) key = key.substr(0, ke + 1);
                    size_t vs = val.find_first_not_of(" \t");
                    if (vs != std::string::npos) val = val.substr(vs);
                    size_t ve = val.find_last_not_of(" \t");
                    if (ve != std::string::npos) val = val.substr(0, ve + 1);
                }

                if (key == "rule_id") ruleId = (ULONG)atoi(val.c_str());
                else if (key == "rule_type") ruleType = val;
                else if (key == "op") { opStr = val; haveOp = true; }
                else if (key == "path") { pathStr = val; havePath = true; }
                else if (key == "value") valueStr = val;
                else if (key == "flag") flagStr = val;
            }
            flushRule();
            ifs.close();

        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }

    SetConsoleColor(totalFailed == 0 ? ConsoleColor::Green : ConsoleColor::Yellow);
    printf("[+] HIPS rules loaded: %d succeeded, %d failed from %s\n",
        totalLoaded, totalFailed, hipsDir);
    ResetConsoleColor();
    char logBuf[256];
    sprintf_s(logBuf, "[规则加载] HIPS 规则已从 %s 加载 %d 条", hipsDir, totalLoaded);
    SendLogToMain(logBuf);
}

// ============================================================================
// Socket 通信函数 - 与 main.cpp 通过 socket 通信
// ============================================================================

// ── Socket 发送函数 ──
BOOL SendPacketToMain(const Packet& packet)
{
    if (g_clientSocket == INVALID_SOCKET || !g_bSocketConnected)
        return FALSE;

    int totalSize = sizeof(Packet);
    int sent = send(g_clientSocket, (const char*)&packet, totalSize, 0);
    if (sent == SOCKET_ERROR)
    {
        g_bSocketConnected = FALSE;
        closesocket(g_clientSocket);
        g_clientSocket = INVALID_SOCKET;
        return FALSE;
    }
    // 确保完整发送
    while (sent < totalSize)
    {
        int ret = send(g_clientSocket, (const char*)&packet + sent, totalSize - sent, 0);
        if (ret == SOCKET_ERROR)
        {
            g_bSocketConnected = FALSE;
            closesocket(g_clientSocket);
            g_clientSocket = INVALID_SOCKET;
            return FALSE;
        }
        sent += ret;
    }
    return TRUE;
}

// ── Socket 接收线程 ──
DWORD WINAPI ClientRecvThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    while (g_bSocketConnected)
    {
        Packet packet;
        int totalSize = sizeof(Packet);
        int received = 0;

        // 接收完整 Packet
        while (received < totalSize)
        {
            int ret = recv(g_clientSocket, (char*)&packet + received, totalSize - received, 0);
            if (ret <= 0)
            {
                g_bSocketConnected = FALSE;
                closesocket(g_clientSocket);
                g_clientSocket = INVALID_SOCKET;
                return 0;
            }
            received += ret;
        }

        if (packet.PacketTyped == PTClientMessage)
        {
            if (strcmp(packet.InfoTitle, CLIENT_MSG_COMMAND) == 0)
            {
                // 执行 main.cpp 发来的远程命令（仅支持安全/只读类命令）
                char cmdBuf[1024] = { 0 };
                strncpy_s(cmdBuf, packet.Message, _TRUNCATE);

                string input(cmdBuf);
                string result;

                if (input == "help")
                {
                    result = "Supported remote commands: help, cache on/off/clear, ba scan, ba stats, ba clear";
                }
                else if (input == "cache on")
                {
                    if (CommSetResponseCache(g_hDevice, 1))
                        result = "[+] Response cache enabled";
                    else
                        result = "[-] Failed to enable response cache";
                }
                else if (input == "cache off")
                {
                    if (CommSetResponseCache(g_hDevice, 0))
                        result = "[+] Response cache disabled";
                    else
                        result = "[-] Failed to disable response cache";
                }
                else if (input == "cache clear")
                {
                    if (CommSetResponseCache(g_hDevice, 2))
                        result = "[+] Response cache cleared";
                    else
                        result = "[-] Failed to clear response cache";
                }
                else if (input == "ba stats")
                {
                    BA_STATS stats;
                    if (CommBehaviorGetStats(g_hDevice, &stats))
                    {
                        char buf[512];
                        snprintf(buf, sizeof(buf),
                            "Behavior analysis statistics:\n"
                            "  Active processes: %d\n"
                            "  History events:   %d\n"
                            "  Active indicators:%d\n"
                            "  Total events:     %lld",
                            stats.processCount, stats.historyCount,
                            stats.indicatorCount, stats.tickCounter);
                        result = buf;
                    }
                    else
                    {
                        result = "[-] Failed to get behavior analysis statistics";
                    }
                }
                else if (input == "ba clear")
                {
                    if (CommBehaviorClear(g_hDevice))
                        result = "[+] Behavior analysis data cleared";
                    else
                        result = "[-] Failed to clear behavior analysis data";
                }
                else if (input == "ba scan")
                {
                    BA_THREAT_RESULT* results = (BA_THREAT_RESULT*)malloc(sizeof(BA_THREAT_RESULT) * 64);
                    INT resultCount = 0;
                    if (results == NULL)
                    {
                        result = "[-] Memory allocation failed";
                    }
                    else if (CommBehaviorEvaluate(g_hDevice, results, 64, &resultCount))
                    {
                        if (resultCount == 0)
                        {
                            result = "[+] Behavior analysis scan complete, no threats found";
                        }
                        else
                        {
                            stringstream ss;
                            ss << "Behavior analysis scan complete, " << resultCount << " threat(s) found:\n";
                            for (INT i = 0; i < resultCount; i++)
                            {
                                ss << "[#" << (i + 1) << "] " << results[i].threatClass << "\n";
                                ss << "  PID:         " << results[i].pid << "\n";
                                ss << "  Path:        " << results[i].processPath << "\n";
                                ss << "  Description: " << results[i].description << "\n";
                                ss << "  Confidence:  " << (results[i].confidence * 100.0) << "%\n";
                            }
                            result = ss.str();
                        }
                    }
                    else
                    {
                        result = "[-] Failed to run behavior analysis scan";
                    }
                    if (results) free(results);
                }
                else
                {
                    result = "[-] Unknown or unsupported remote command: " + input;
                }

                Packet respPkt = {};
                respPkt.PacketTyped = PTClientMessage;
                strcpy_s(respPkt.InfoTitle, CLIENT_MSG_RESULT);
                if (result.length() >= sizeof(respPkt.Message))
                {
                    strncpy_s(respPkt.Message, result.substr(0, sizeof(respPkt.Message) - 1).c_str(),
                        _TRUNCATE);
                }
                else
                {
                    strncpy_s(respPkt.Message, result.c_str(), _TRUNCATE);
                }
                SendPacketToMain(respPkt);
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_HEARTBEAT) == 0)
            {
                Packet respPkt = {};
                respPkt.PacketTyped = PTClientMessage;
                strcpy_s(respPkt.InfoTitle, CLIENT_MSG_HEARTBEAT);
                strcpy_s(respPkt.Message, "OK");
                SendPacketToMain(respPkt);
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_ALERT_RESPONSE) == 0)
            {
                ClientAlertResponse resp = {};
                if (sizeof(packet.Message) >= sizeof(ClientAlertResponse))
                {
                    memcpy(&resp, packet.Message, sizeof(ClientAlertResponse));

                    // 在临界区内写入，并校验 PID 与当前等待的告警是否匹配，
                    // 防止过期响应或并发告警导致决策错配。
                    EnterCriticalSection(&g_alertResponseCs);
                    if (g_pendingAlertPid != -1 && resp.pid == g_pendingAlertPid)
                    {
                        g_alertResponse.pid = resp.pid;
                        g_alertResponse.decision = resp.decision;
                        printf("[ALERT-RESPONSE] ClientRecvThread: accepted PID=%lld decision=%d\n",
                            resp.pid, resp.decision);
                    }
                    else
                    {
                        printf("[ALERT-RESPONSE] ClientRecvThread: dropped stale/mismatched response PID=%lld pending=%lld\n",
                            resp.pid, g_pendingAlertPid);
                    }
                    LeaveCriticalSection(&g_alertResponseCs);
                }
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_PROCESS_CHECK_RESP) == 0)
            {
                ClientProcessCheckResponse resp = {};
                if (sizeof(packet.Message) >= sizeof(ClientProcessCheckResponse))
                {
                    memcpy(&resp, packet.Message, sizeof(ClientProcessCheckResponse));

                    EnterCriticalSection(&g_alertResponseCs);
                    if (g_pendingCheckPid != -1 && resp.pid == g_pendingCheckPid)
                    {
                        g_processCheckResponse.pid = resp.pid;
                        g_processCheckResponse.allow = resp.allow;
                        printf("[PROCESS-CHECK] ClientRecvThread: accepted PROCESS_CHECK_RESP PID=%lld allow=%d\n",
                            resp.pid, resp.allow);
                    }
                    else
                    {
                        printf("[PROCESS-CHECK] ClientRecvThread: dropped stale/mismatched response PID=%lld pending=%lld\n",
                            resp.pid, g_pendingCheckPid);
                    }
                    LeaveCriticalSection(&g_alertResponseCs);
                }
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_DLL_SCAN_RESP) == 0)
            {
                ClientDllScanResponse resp = {};
                if (sizeof(packet.Message) >= sizeof(ClientDllScanResponse))
                {
                    memcpy(&resp, packet.Message, sizeof(ClientDllScanResponse));

                    EnterCriticalSection(&g_alertResponseCs);
                    if (g_pendingDllScanPid != -1 && resp.pid == g_pendingDllScanPid)
                    {
                        g_dllScanResponse.pid = resp.pid;
                        g_dllScanResponse.allow = resp.allow;
                        printf("[DLL-SCAN] ClientRecvThread: accepted DLL_SCAN_RESP PID=%lld allow=%d\n",
                            resp.pid, resp.allow);
                    }
                    else
                    {
                        printf("[DLL-SCAN] ClientRecvThread: dropped stale/mismatched response PID=%lld pending=%lld\n",
                            resp.pid, g_pendingDllScanPid);
                    }
                    LeaveCriticalSection(&g_alertResponseCs);
                }
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_ROLLBACK_CONFIRM_RESP) == 0)
            {
                ClientRollbackConfirmResponse resp = {};
                if (sizeof(packet.Message) >= sizeof(ClientRollbackConfirmResponse))
                {
                    memcpy(&resp, packet.Message, sizeof(ClientRollbackConfirmResponse));

                    EnterCriticalSection(&g_alertResponseCs);
                    if (g_pendingRollbackPid != -1 && resp.pid == g_pendingRollbackPid)
                    {
                        g_rollbackResponse.pid = resp.pid;
                        g_rollbackResponse.selection = resp.selection;
                        printf("[ROLLBACK] ClientRecvThread: accepted ROLLBACK_CONFIRM_RESP PID=%lld decision=%d\n",
                            resp.pid, resp.selection.decision);
                    }
                    else
                    {
                        printf("[ROLLBACK] ClientRecvThread: dropped stale/mismatched response PID=%lld pending=%lld\n",
                            resp.pid, g_pendingRollbackPid);
                    }
                    LeaveCriticalSection(&g_alertResponseCs);
                }
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_SET_FULL_SCAN) == 0)
            {
                int enabled = 0;
                memcpy(&enabled, packet.Message, sizeof(int));
                g_bProcessCheckBlocking = (enabled != 0) ? TRUE : FALSE;
                printf("[PROCESS-CHECK] Full-scan (blocking) mode set to %s by main.cpp\n",
                    g_bProcessCheckBlocking ? "ENABLED" : "DISABLED");
            }
            else if (strcmp(packet.InfoTitle, "SET_UNSIGNED_DLL_SCAN") == 0)
            {
                int enabled = 0;
                int blocking = 0;
                memcpy(&enabled, packet.Message, sizeof(int));
                memcpy(&blocking, (char*)packet.Message + sizeof(int), sizeof(int));
                g_bDllScanBlocking = (blocking != 0) ? TRUE : FALSE;
                printf("[DLL-SCAN] Unsigned DLL scan set to %s, blocking=%s by main.cpp\n",
                    enabled ? "ENABLED" : "DISABLED",
                    g_bDllScanBlocking ? "YES" : "NO");

                if (g_hDevice != INVALID_HANDLE_VALUE)
                {
                    BOOLEAN kernelSettings[2];
                    kernelSettings[0] = (enabled != 0) ? TRUE : FALSE;
                    kernelSettings[1] = (blocking != 0) ? TRUE : FALSE;

                    DWORD bytesReturned = 0;
                    BOOL success = DeviceIoControl(
                        g_hDevice,
                        IOCTL_SET_UNSIGNED_DLL_SCAN,
                        kernelSettings,
                        sizeof(kernelSettings),
                        NULL,
                        0,
                        &bytesReturned,
                        NULL);

                    if (success)
                    {
                        printf("[DLL-SCAN] Synced settings to kernel: enable=%s, blocking=%s\n",
                            kernelSettings[0] ? "YES" : "NO",
                            kernelSettings[1] ? "YES" : "NO");
                    }
                    else
                    {
                        DWORD error = GetLastError();
                        printf("[DLL-SCAN] Failed to sync settings to kernel: error=%d\n", error);
                    }
                }
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_QUIT) == 0)
            {
                printf("[.] Received QUIT from main, cleaning up...\n");
                g_bSocketConnected = FALSE;
                closesocket(g_clientSocket);
                g_clientSocket = INVALID_SOCKET;
                CleanupAndExit();
                return 0;
            }
        }
    }
    return 0;
}

// ── 连接到 main.cpp ──
BOOL ConnectToMain()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return FALSE;

    g_clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_clientSocket == INVALID_SOCKET)
    {
        WSACleanup();
        return FALSE;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(CLIENT_SOCKET_IP);
    serverAddr.sin_port = htons(CLIENT_SOCKET_PORT);

    if (connect(g_clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(g_clientSocket);
        g_clientSocket = INVALID_SOCKET;
        WSACleanup();
        return FALSE;
    }

    g_bSocketConnected = TRUE;

    // 发送 READY 消息，附带认证令牌
    Packet readyPkt = {};
    readyPkt.PacketTyped = PTClientMessage;
    strcpy_s(readyPkt.InfoTitle, CLIENT_MSG_READY);
    if (strlen(g_szClientAuthToken) > 0)
        strcpy_s(readyPkt.Message, g_szClientAuthToken);
    else
        strcpy_s(readyPkt.Message, "ClientReady");
    SendPacketToMain(readyPkt);

    // 等待主程序 AUTH_OK 认证响应（3 秒超时）
    DWORD recvTimeout = 3000;
    setsockopt(g_clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvTimeout, sizeof(recvTimeout));

    Packet authPkt = {};
    int totalRecv = 0;
    int packetSize = sizeof(Packet);
    while (totalRecv < packetSize)
    {
        int ret = recv(g_clientSocket, (char*)&authPkt + totalRecv, packetSize - totalRecv, 0);
        if (ret <= 0)
            break;
        totalRecv += ret;
    }

    // 取消接收超时
    recvTimeout = 0;
    setsockopt(g_clientSocket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&recvTimeout, sizeof(recvTimeout));

    BOOL authOk = (totalRecv == packetSize &&
                   authPkt.PacketTyped == PTClientMessage &&
                   strcmp(authPkt.InfoTitle, CLIENT_MSG_AUTH_OK) == 0);

    if (!authOk)
    {
        SetConsoleColor(ConsoleColor::Red);
        printf("[-] Main program authentication failed or timeout\n");
        ResetConsoleColor();
        closesocket(g_clientSocket);
        g_clientSocket = INVALID_SOCKET;
        g_bSocketConnected = FALSE;
        WSACleanup();
        return FALSE;
    }

    // 启动接收线程
    CreateThread(NULL, 0, ClientRecvThread, NULL, 0, NULL);

    return TRUE;
}

// ── 向 main.cpp 发送致命错误日志（无需完整认证握手）──
// 用于 Client 启动/驱动加载失败等无法继续的场景，避免 ConnectToMain 的 AUTH_OK
// 等待超时导致错误信息无法送达主程序。
BOOL SendFatalErrorLogToMain(const char* message)
{
    if (message == NULL || message[0] == '\0')
        return FALSE;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return FALSE;

    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
    {
        WSACleanup();
        return FALSE;
    }

    sockaddr_in serverAddr = {};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(CLIENT_SOCKET_IP);
    serverAddr.sin_port = htons(CLIENT_SOCKET_PORT);

    if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    Packet errPkt = {};
    errPkt.PacketTyped = PTClientMessage;
    strcpy_s(errPkt.InfoTitle, CLIENT_MSG_LOG);
    strncpy_s(errPkt.Message, message, _TRUNCATE);

    // 发送日志包并确保数据到达主程序后再关闭，避免 accept/recv 尚未就绪导致包丢失
    if (send(sock, (const char*)&errPkt, sizeof(Packet), 0) == SOCKET_ERROR)
    {
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    shutdown(sock, SD_SEND);
    Sleep(800);

    closesocket(sock);
    WSACleanup();
    return TRUE;
}

// ============================================================================
// SendLogToMain - 通过已连接的 socket 发送日志到 main UI（非致命日志）
// 复用 g_clientSocket，不需要新建连接。若 socket 未连接则丢弃日志。
// ============================================================================
BOOL SendLogToMain(const char* message)
{
    if (message == NULL || message[0] == '\0')
        return FALSE;

    if (!g_bSocketConnected || g_clientSocket == INVALID_SOCKET)
        return FALSE;

    Packet logPkt = {};
    logPkt.PacketTyped = PTClientMessage;
    strcpy_s(logPkt.InfoTitle, CLIENT_MSG_LOG);
    strncpy_s(logPkt.Message, message, _TRUNCATE);

    return SendPacketToMain(logPkt);
}

// ── 通过 PID 查询进程完整路径（用户态），失败时 buf 保持空字符串 ──
static void ResolveProcessPathByPid(INT64 pid, char* buf, size_t bufSize)
{
    if (bufSize > 0) buf[0] = '\0';
    if (pid <= 4) return;  /* System/Idle 进程跳过 */
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!hProc) return;
    WCHAR wpath[520] = { 0 };
    DWORD wsize = 520;
    if (QueryFullProcessImageNameW(hProc, 0, wpath, &wsize))
    {
        WideCharToMultiByte(CP_UTF8, 0, wpath, -1, buf, (int)bufSize, NULL, NULL);
        buf[bufSize - 1] = '\0';
    }
    CloseHandle(hProc);
}

// ── 发送告警并等待用户决策 ──
int SendAlertAndWaitResponse(INT64 pid, const char* title, const char* message,
    INT64 parentPid, const char* parentName, const char* parentPath, const char* processPath)
{
    if (!g_bSocketConnected || g_clientSocket == INVALID_SOCKET)
        return -1;

    ClientAlertData alertData = {};
    alertData.pid = pid;
    alertData.parentPid = parentPid;
    strncpy_s(alertData.title, title, _TRUNCATE);
    /* parentName 和 processPath 来自驱动端（ANSI/GBK），需转 UTF-8 后再发给 Qt UI。
     * title 和 message 由调用方构建时已确保为 UTF-8，无需再转。 */
    string parentNameUtf8 = AnsiToUtf8(parentName ? parentName : "");
    strncpy_s(alertData.parentName, parentNameUtf8.empty() ? "" : parentNameUtf8.c_str(), _TRUNCATE);
    /* 驱动端 COMM_RULE_DETECTED 未提供父进程路径，调用方可能用 parentName 占位。
     * 这里通过 parentPid 在用户态查询父进程完整路径，确保日志显示父进程路径+PID。 */
    char resolvedParentPath[520] = { 0 };
    if (parentPid > 0)
        ResolveProcessPathByPid(parentPid, resolvedParentPath, sizeof(resolvedParentPath));
    const char* finalParentPath = (resolvedParentPath[0] != '\0') ? resolvedParentPath : parentPath;
    string parentPathUtf8 = (resolvedParentPath[0] != '\0') ? string(resolvedParentPath) : AnsiToUtf8(finalParentPath ? finalParentPath : "");
    strncpy_s(alertData.parentPath, parentPathUtf8.empty() ? "" : parentPathUtf8.c_str(), _TRUNCATE);
    string procPathUtf8 = AnsiToUtf8(processPath ? processPath : "");
    strncpy_s(alertData.processPath, procPathUtf8.empty() ? "" : procPathUtf8.c_str(), _TRUNCATE);
    strncpy_s(alertData.message, message, _TRUNCATE);

    Packet packet = {};
    packet.PacketTyped = PTClientMessage;
    strcpy_s(packet.InfoTitle, CLIENT_MSG_ALERT);
    packet.Pid = (int)pid;
    memcpy(packet.Message, &alertData, sizeof(ClientAlertData));

    // 在锁内重置响应状态并登记当前等待的 PID，避免并发告警导致响应错配
    EnterCriticalSection(&g_alertResponseCs);
    g_alertResponse.pid = -1;
    g_alertResponse.decision = -1;
    g_pendingAlertPid = pid;
    LeaveCriticalSection(&g_alertResponseCs);

    DWORD sendTick = GetTickCount();

    if (!SendPacketToMain(packet))
    {
        EnterCriticalSection(&g_alertResponseCs);
        g_pendingAlertPid = -1;
        LeaveCriticalSection(&g_alertResponseCs);
        return -1;
    }

    SetConsoleColor(ConsoleColor::DarkGray);
    printf("[ALERT-FWD] Sent alert to mainUI PID=%lld title=\"%s\"\n",
        pid, title);
    ResetConsoleColor();

    // 等待响应（35秒超时，比驱动同步超时多5秒）
    for (int i = 0; i < 350 && g_bSocketConnected; i++)
    {
        INT64 respPid = -1;
        int     respDecision = -1;
        EnterCriticalSection(&g_alertResponseCs);
        respPid = g_alertResponse.pid;
        respDecision = g_alertResponse.decision;
        LeaveCriticalSection(&g_alertResponseCs);

        if (respPid == pid && respDecision != -1)
        {
            DWORD elapsed = GetTickCount() - sendTick;
            SetConsoleColor(ConsoleColor::DarkGray);
            printf("[ALERT-FWD] Response received PID=%lld decision=%d elapsed=%lums\n",
                pid, respDecision, elapsed);
            ResetConsoleColor();

            if (respDecision == 0 && elapsed < 500)
            {
                SetConsoleColor(ConsoleColor::Yellow);
                printf("[ALERT-FWD] WARNING: Allow decision arrived very quickly (%lums), "
                       "possible auto-allow from mainUI (protection disabled or auto-allow list)\n",
                    elapsed);
                ResetConsoleColor();
            }

            return respDecision;
        }
        Sleep(100);
    }

    DWORD elapsed = GetTickCount() - sendTick;
    SetConsoleColor(ConsoleColor::DarkGray);
    printf("[ALERT-FWD] No response received for PID=%lld after %lums, timeout\n",
        pid, elapsed);
    ResetConsoleColor();

    EnterCriticalSection(&g_alertResponseCs);
    g_pendingAlertPid = -1;
    LeaveCriticalSection(&g_alertResponseCs);
    return 2; // timeout
}

// ── 发送告警但不等待用户决策（非阻塞通知）──
// 用于把匹配/可疑事件直接通知主程序 UI，由主程序自行弹窗/记录，
// 不阻塞驱动/Client 流程，避免同步等待导致的卡死崩溃。
BOOL SendAlertNoWait(INT64 pid, const char* title, const char* message,
    INT64 parentPid, const char* parentName, const char* parentPath, const char* processPath)
{
    if (!g_bSocketConnected || g_clientSocket == INVALID_SOCKET)
        return FALSE;

    ClientAlertData alertData = {};
    alertData.pid = pid;
    alertData.parentPid = parentPid;
    strncpy_s(alertData.title, title, _TRUNCATE);
    /* parentName 和 processPath 来自驱动端（ANSI/GBK），需转 UTF-8 后再发给 Qt UI。
     * title 和 message 由调用方构建时已确保为 UTF-8，无需再转。 */
    string parentNameUtf8 = AnsiToUtf8(parentName ? parentName : "");
    strncpy_s(alertData.parentName, parentNameUtf8.empty() ? "" : parentNameUtf8.c_str(), _TRUNCATE);
    /* 驱动端 COMM_RULE_DETECTED 未提供父进程路径，调用方可能用 parentName 占位。
     * 这里通过 parentPid 在用户态查询父进程完整路径，确保日志显示父进程路径+PID。 */
    char resolvedParentPath[520] = { 0 };
    if (parentPid > 0)
        ResolveProcessPathByPid(parentPid, resolvedParentPath, sizeof(resolvedParentPath));
    const char* finalParentPath = (resolvedParentPath[0] != '\0') ? resolvedParentPath : parentPath;
    string parentPathUtf8 = (resolvedParentPath[0] != '\0') ? string(resolvedParentPath) : AnsiToUtf8(finalParentPath ? finalParentPath : "");
    strncpy_s(alertData.parentPath, parentPathUtf8.empty() ? "" : parentPathUtf8.c_str(), _TRUNCATE);
    string procPathUtf8 = AnsiToUtf8(processPath ? processPath : "");
    strncpy_s(alertData.processPath, procPathUtf8.empty() ? "" : procPathUtf8.c_str(), _TRUNCATE);
    strncpy_s(alertData.message, message, _TRUNCATE);

    Packet packet = {};
    packet.PacketTyped = PTClientMessage;
    strcpy_s(packet.InfoTitle, CLIENT_MSG_ALERT);
    packet.Pid = (int)pid;
    memcpy(packet.Message, &alertData, sizeof(ClientAlertData));

    return SendPacketToMain(packet);
}

// ── 发送进程检查并等待结果 ──
int SendProcessCheckAndWait(INT64 pid, INT64 parentPid, const char* processPath, const char* processName, const char* parentName)
{
    if (!g_bSocketConnected || g_clientSocket == INVALID_SOCKET)
    {
        printf("[PROCESS-CHECK] SendProcessCheckAndWait: socket not connected, default block PID=%lld\n", pid);
        return 0;
    }

    ClientProcessCheckData checkData = {};
    checkData.pid = pid;
    checkData.parentPid = parentPid;
    strncpy_s(checkData.processPath, processPath ? processPath : "", _TRUNCATE);
    strncpy_s(checkData.processName, processName ? processName : "", _TRUNCATE);
    strncpy_s(checkData.parentName, parentName ? parentName : "", _TRUNCATE);

    Packet packet = {};
    packet.PacketTyped = PTClientMessage;
    strcpy_s(packet.InfoTitle, CLIENT_MSG_PROCESS_CHECK);
    packet.Pid = (int)pid;
    memcpy(packet.Message, &checkData, sizeof(ClientProcessCheckData));

    // 在锁内重置响应状态并登记当前等待的 PID，避免并发请求导致响应错配
    EnterCriticalSection(&g_alertResponseCs);
    g_processCheckResponse.pid = -1;
    g_processCheckResponse.allow = -1;
    g_pendingCheckPid = pid;
    LeaveCriticalSection(&g_alertResponseCs);

    if (!SendPacketToMain(packet))
    {
        printf("[PROCESS-CHECK] SendProcessCheckAndWait: SendPacketToMain failed PID=%lld\n", pid);
        EnterCriticalSection(&g_alertResponseCs);
        g_pendingCheckPid = -1;
        LeaveCriticalSection(&g_alertResponseCs);
        return 0;
    }

    printf("[PROCESS-CHECK] SendProcessCheckAndWait: waiting response PID=%lld\n", pid);

    // 等待响应（30秒超时，与驱动端35秒超时错开）
    for (int i = 0; i < 300 && g_bSocketConnected; i++)
    {
        INT64 respPid = -1;
        int     respAllow = -1;
        EnterCriticalSection(&g_alertResponseCs);
        respPid = g_processCheckResponse.pid;
        respAllow = g_processCheckResponse.allow;
        LeaveCriticalSection(&g_alertResponseCs);

        if (respPid == pid && respAllow != -1)
        {
            printf("[PROCESS-CHECK] SendProcessCheckAndWait: received response PID=%lld allow=%d\n",
                pid, respAllow);
            return respAllow;
        }
        Sleep(100);
    }

    EnterCriticalSection(&g_alertResponseCs);
    g_pendingCheckPid = -1;
    LeaveCriticalSection(&g_alertResponseCs);

    printf("[PROCESS-CHECK] SendProcessCheckAndWait: TIMEOUT PID=%lld, default block\n", pid);
    return 0; // timeout: block
}

// ── 发送 DLL 检查并等待结果 ──
int SendDllScanAndWait(INT64 pid, INT64 parentPid, const char* processPath, const char* processName, const char* dllPath, int blocking)
{
    if (!g_bSocketConnected || g_clientSocket == INVALID_SOCKET)
    {
        printf("[DLL-SCAN] SendDllScanAndWait: socket not connected, default block PID=%lld\n", pid);
        return 0;
    }

    ClientDllScanData checkData = {};
    checkData.pid = pid;
    checkData.parentPid = parentPid;
    checkData.blocking = blocking;
    strncpy_s(checkData.processPath, processPath ? processPath : "", _TRUNCATE);
    strncpy_s(checkData.processName, processName ? processName : "", _TRUNCATE);
    strncpy_s(checkData.dllPath, dllPath ? dllPath : "", _TRUNCATE);

    Packet packet = {};
    packet.PacketTyped = PTClientMessage;
    strcpy_s(packet.InfoTitle, CLIENT_MSG_DLL_SCAN);
    packet.Pid = (int)pid;
    memcpy(packet.Message, &checkData, sizeof(ClientDllScanData));

    EnterCriticalSection(&g_alertResponseCs);
    g_dllScanResponse.pid = -1;
    g_dllScanResponse.allow = -1;
    g_pendingDllScanPid = pid;
    LeaveCriticalSection(&g_alertResponseCs);

    if (!SendPacketToMain(packet))
    {
        printf("[DLL-SCAN] SendDllScanAndWait: SendPacketToMain failed PID=%lld\n", pid);
        EnterCriticalSection(&g_alertResponseCs);
        g_pendingDllScanPid = -1;
        LeaveCriticalSection(&g_alertResponseCs);
        return 0;
    }

    printf("[DLL-SCAN] SendDllScanAndWait: waiting response PID=%lld\n", pid);

    for (int i = 0; i < 300 && g_bSocketConnected; i++)
    {
        INT64 respPid = -1;
        int respAllow = -1;
        EnterCriticalSection(&g_alertResponseCs);
        respPid = g_dllScanResponse.pid;
        respAllow = g_dllScanResponse.allow;
        LeaveCriticalSection(&g_alertResponseCs);

        if (respPid == pid && respAllow != -1)
        {
            printf("[DLL-SCAN] SendDllScanAndWait: received response PID=%lld allow=%d\n",
                pid, respAllow);
            return respAllow;
        }
        Sleep(100);
    }

    EnterCriticalSection(&g_alertResponseCs);
    g_pendingDllScanPid = -1;
    LeaveCriticalSection(&g_alertResponseCs);

    printf("[DLL-SCAN] SendDllScanAndWait: TIMEOUT PID=%lld, default block\n", pid);
    return 0;
}

// ── 发送回滚确认并等待用户选择结果 ──
// 返回: 0=超时/失败(默认忽略), 1=用户已响应(outSelection 已填充)
int SendRollbackConfirmAndWait(const BA_ROLLBACK_LIST* rollbackList, BA_ROLLBACK_SELECTION* outSelection)
{
    if (outSelection == NULL) return 0;
    RtlZeroMemory(outSelection, sizeof(BA_ROLLBACK_SELECTION));

    if (rollbackList == NULL || !g_bSocketConnected || g_clientSocket == INVALID_SOCKET)
    {
        printf("[ROLLBACK] SendRollbackConfirmAndWait: socket not connected, default ignore\n");
        return 0;
    }

    /* BA_ROLLBACK_LIST 直接放入 Packet.Message（约 3772 字节 < 4096） */
    Packet packet = {};
    packet.PacketTyped = PTClientMessage;
    strcpy_s(packet.InfoTitle, CLIENT_MSG_ROLLBACK_CONFIRM);
    packet.Pid = (int)rollbackList->rootPid;
    memcpy(packet.Message, rollbackList, sizeof(BA_ROLLBACK_LIST));

    INT64 pid = rollbackList->rootPid;

    EnterCriticalSection(&g_alertResponseCs);
    g_rollbackResponse.pid = -1;
    g_rollbackResponse.selection.decision = -1;
    g_pendingRollbackPid = pid;
    LeaveCriticalSection(&g_alertResponseCs);

    if (!SendPacketToMain(packet))
    {
        printf("[ROLLBACK] SendRollbackConfirmAndWait: SendPacketToMain failed PID=%lld\n", pid);
        EnterCriticalSection(&g_alertResponseCs);
        g_pendingRollbackPid = -1;
        LeaveCriticalSection(&g_alertResponseCs);
        return 0;
    }

    printf("[ROLLBACK] SendRollbackConfirmAndWait: waiting response PID=%lld items=%d\n",
        pid, rollbackList->itemCount);

    /* 等待响应（55 秒超时，与驱动端 60 秒超时错开） */
    for (int i = 0; i < 550 && g_bSocketConnected; i++)
    {
        INT64 respPid = -1;
        INT32 respDecision = -1;
        BA_ROLLBACK_SELECTION respSel = {0};
        EnterCriticalSection(&g_alertResponseCs);
        respPid = g_rollbackResponse.pid;
        respDecision = g_rollbackResponse.selection.decision;
        respSel = g_rollbackResponse.selection;
        LeaveCriticalSection(&g_alertResponseCs);

        if (respPid == pid && respDecision != -1)
        {
            *outSelection = respSel;
            printf("[ROLLBACK] SendRollbackConfirmAndWait: received response PID=%lld decision=%d\n",
                pid, respDecision);
            return 1;
        }
        Sleep(100);
    }

    EnterCriticalSection(&g_alertResponseCs);
    g_pendingRollbackPid = -1;
    LeaveCriticalSection(&g_alertResponseCs);

    printf("[ROLLBACK] SendRollbackConfirmAndWait: TIMEOUT PID=%lld, default ignore\n", pid);
    return 0;
}

int main(int argc, char* argv[])
{
    // 检查是否为 --traffic 模式，并解析 --auth-token
    BOOL bTrafficMode = FALSE;
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--traffic") == 0)
        {
            bTrafficMode = TRUE;
        }
        else if (strcmp(argv[i], "--auth-token") == 0 && i + 1 < argc)
        {
            strncpy_s(g_szClientAuthToken, argv[i + 1], _TRUNCATE);
            i++;
        }
    }

    // traffic 模式下隐藏控制台窗口，避免用户误关闭窗口导致 Client 退出
    if (bTrafficMode)
    {
        HWND hConsoleWnd = GetConsoleWindow();
        if (hConsoleWnd != NULL)
        {
            ShowWindow(hConsoleWnd, SW_HIDE);
        }
    }

    // ── 初始化告警/进程检查响应状态临界区 ──
    // 必须在任何后台线程（ClientRecvThread / HandleUserQueries）启动前完成，
    // 否则对 g_alertResponse / g_processCheckResponse 的访问会出现数据竞争。
    if (!InitializeCriticalSectionAndSpinCount(&g_alertResponseCs, 4000))
    {
        printf("[-] Failed to initialize alert response critical section\n");
        return 1;
    }

    // ── 创建驱动通信句柄（用于发送命令） ──
    g_hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_hDevice == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        SetConsoleColor(ConsoleColor::Red);
        printf("Failed to get driver communication handle: %d\n", error);
        ResetConsoleColor();

        if (error == ERROR_FILE_NOT_FOUND)
        {
            printf("Driver not loaded (" THSD_SERVICE_NAME_A ")\n");

            // 中转模式下不询问用户，尝试自动安装
            if (bTrafficMode)
            {
                printf("Relay mode: attempting automatic driver installation...\n");
                if (InstallDriver(TRUE))
                {
                    // 驱动服务启动后需要一定时间创建设备，重试打开
                    const int OPEN_RETRIES = 30;
                    const int OPEN_INTERVAL_MS = 500;
                    for (int retry = 0; retry < OPEN_RETRIES; retry++)
                    {
                        if (!g_bRunning) {
                            printf("[-] Driver device open cancelled\n");
                            break;
                        }
                        Sleep(OPEN_INTERVAL_MS);
                        g_hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
                        if (g_hDevice != INVALID_HANDLE_VALUE)
                            break;
                    }

                    if (g_hDevice == INVALID_HANDLE_VALUE)
                    {
                        DWORD reconnectError = GetLastError();
                        printf("Relay mode: cannot connect to driver after installation: %d\n", reconnectError);

                        char errMsg[512];
                        snprintf(errMsg, sizeof(errMsg),
                            "[驱动加载失败] 驱动服务已启动但无法打开设备 " THSD_SERVICE_NAME_A "，错误码=%d，"
                            "可能驱动初始化失败或设备名冲突。", reconnectError);
                        SendFatalErrorLogToMain(errMsg);

                        return 1;
                    }
                }
                else
                {
                    /* 驱动安装失败：在退出前尝试连接 main.cpp 报告错误，
                     * 让 UI 给用户明确反馈（test signing、权限、文件缺失等）。 */
                    SetConsoleColor(ConsoleColor::Yellow);
                    printf("Relay mode: driver installation failed, reporting to main program...\n");
                    ResetConsoleColor();

                    {
                        char errMsg[512];
                        snprintf(errMsg, sizeof(errMsg),
                            "[驱动加载失败] KernelProtectionClient 无法加载 " THSD_SERVICE_NAME_A " 驱动，"
                            "请检查：1) 是否以管理员运行；2) 驱动文件签名是否正常或系统版本是否兼容；"
                            "3) 驱动文件 " THSD_DRIVER_FILENAME_A " 是否存在；4) 是否有杀毒软件拦截。");
                        SendFatalErrorLogToMain(errMsg);
                    }

                    return 1;
                }
            }
            else
            {
                // 非traffic模式下询问用户
                // 尝试安装驱动
                if (InstallDriver(FALSE))
                {
                    // 驱动服务启动后重试打开设备
                    printf("[*] Reconnecting to driver...\n");
                    const int OPEN_RETRIES_CLI = 10;
                    const int OPEN_INTERVAL_CLI = 500;
                    for (int retry = 0; retry < OPEN_RETRIES_CLI; retry++)
                    {
                        g_hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
                        if (g_hDevice != INVALID_HANDLE_VALUE)
                            break;
                        Sleep(OPEN_INTERVAL_CLI);
                    }

                    if (g_hDevice == INVALID_HANDLE_VALUE)
                    {
                        SetConsoleColor(ConsoleColor::Red);
                        printf("[-] Cannot connect to driver after installation: %d\n", GetLastError());
                        ResetConsoleColor();
                        getchar();
                        return 1;
                    }
                }
                else
                {
                    ResetConsoleColor();
                    getchar();
                    return 1;
                }
            }
        }
        else
        {
            /* 驱动设备存在但打开失败（权限不足、被占用等） */
            if (bTrafficMode)
            {
                SetConsoleColor(ConsoleColor::Yellow);
                printf("[-] Relay mode: cannot open driver device, reporting to main program...\n");
                ResetConsoleColor();

                {
                    char errMsg[512];
                    snprintf(errMsg, sizeof(errMsg),
                        "[驱动加载失败] 无法打开驱动设备 " THSD_SERVICE_NAME_A "，错误码=%d，"
                        "请检查是否以管理员运行或驱动是否被其他程序占用。", error);
                    SendFatalErrorLogToMain(errMsg);
                }
            }

            if (!bTrafficMode) getchar();
            return 1;
        }
    }

    SetConsoleColor(ConsoleColor::Green);
    printf("[+] Driver communication handle created (g_hDevice)\n");
    ResetConsoleColor();

    // ── 创建响应查询句柄（用于轮询检测事件） ──
    g_hCommDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_hCommDevice == INVALID_HANDLE_VALUE)
    {
        DWORD error = GetLastError();
        SetConsoleColor(ConsoleColor::Red);
        printf("[-] Failed to get response query handle: %d\n", error);
        ResetConsoleColor();

        CloseHandle(g_hDevice);
        getchar();
        return 1;
    }

    SetConsoleColor(ConsoleColor::Green);
    printf("[+] Response query handle created (g_hCommDevice)\n");
    ResetConsoleColor();

    // ── socket 模式：连接 main.cpp ──
    // 必须在驱动安装之前建立 socket 连接，
    // 否则驱动安装过程中的 SendLogToMain 日志会被静默丢弃
    if (bTrafficMode)
    {
        SetConsoleColor(ConsoleColor::Yellow);
        printf("[*] Connecting to main program via socket...\n");
        ResetConsoleColor();

        if (ConnectToMain())
        {
            SetConsoleColor(ConsoleColor::Green);
            printf("[+] Connected to main program, relay mode activated\n");
            ResetConsoleColor();
            printf("[*] Main program will relay commands, this program acts as relay\n");
            printf("[*] Auto-switch to normal CLI when main exits\n\n");
        }
        else
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("[-] Cannot connect/authenticate to main program, exiting relay mode\n");
            ResetConsoleColor();
            if (g_hDevice != INVALID_HANDLE_VALUE)
                CloseHandle(g_hDevice);
            if (g_hCommDevice != INVALID_HANDLE_VALUE)
                CloseHandle(g_hCommDevice);
            return 1;
        }
    }

    // ── 安装并连接磁盘过滤驱动（TianHongHips.Disk）──
    // 尝试打开磁盘过滤设备，若不存在则安装驱动
    g_hDiskDevice = CreateFile(THSD_DISK_USER_DEVICE_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_hDiskDevice == INVALID_HANDLE_VALUE)
    {
        DWORD diskErr = GetLastError();
        if (diskErr == ERROR_FILE_NOT_FOUND)
        {
            printf("[*] Disk filter device not found, attempting to install...\n");
            if (InstallDiskDriver(bTrafficMode))
            {
                // 重试打开设备
                for (int i = 0; i < 10; i++)
                {
                    g_hDiskDevice = CreateFile(THSD_DISK_USER_DEVICE_PATH_W,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (g_hDiskDevice != INVALID_HANDLE_VALUE)
                        break;
                    Sleep(500);
                }
            }
        }
    }

    if (g_hDiskDevice != INVALID_HANDLE_VALUE)
    {
        // 默认启用 MBR 保护
        BOOLEAN enableMbr = TRUE;
        DWORD bytesReturned = 0;
        DeviceIoControl(g_hDiskDevice, IOCTL_DISK_FILTER_SET_ENABLED,
            &enableMbr, sizeof(enableMbr), NULL, 0, &bytesReturned, NULL);

        // 查询防护状态验证 attach 是否成功
        // 注意：reinit 回调异步执行，attach 可能尚未完成，需重试
        DISK_FILTER_STATUS diskStatus;
        BOOL statusOk = FALSE;
        for (int retry = 0; retry < 10; retry++)
        {
            ZeroMemory(&diskStatus, sizeof(diskStatus));
            bytesReturned = 0;
            if (DeviceIoControl(g_hDiskDevice, IOCTL_DISK_FILTER_GET_STATUS,
                NULL, 0, &diskStatus, sizeof(diskStatus), &bytesReturned, NULL)
                && bytesReturned >= sizeof(diskStatus))
            {
                if (diskStatus.attachedDiskCount > 0)
                {
                    statusOk = TRUE;
                    break;
                }
            }
            Sleep(300); // 等待 reinit 回调完成 attach
        }

        if (statusOk)
        {
            char logBuf[256];
            sprintf_s(logBuf, "[MBR防护] 初始化成功，已防护 %lu 个磁盘", diskStatus.attachedDiskCount);
            SendLogToMain(logBuf);
            SetConsoleColor(ConsoleColor::Green);
            printf("[+] MBR protection ACTIVE: attachedDisks=%lu volumes=%lu blocked=%lu\n",
                diskStatus.attachedDiskCount, diskStatus.attachedVolumeCount,
                diskStatus.totalBlockedWrites);
            ResetConsoleColor();
        }
        else
        {
            SetConsoleColor(ConsoleColor::Red);
            printf("[!] MBR protection WARNING: attachedDisks=0 (filter NOT attached to any disk!)\n");
            printf("[!] Driver loaded but MBR writes will NOT be intercepted.\n");
            printf("[!] Check DbgView for 'Attach FAILED' logs (device name may not match).\n");
            ResetConsoleColor();
            SendLogToMain("[MBR防护] 初始化警告：驱动已加载但未附加到磁盘，MBR 写入将无法拦截");
        }
    }
    else
    {
        DWORD diskErr = GetLastError();
        SetConsoleColor(ConsoleColor::Yellow);
        printf("[!] Disk filter driver not available (MBR protection disabled), error=0x%X\n", diskErr);
        ResetConsoleColor();
        {
            char logBuf[256];
            sprintf_s(logBuf, "[MBR防护] 初始化失败（错误码=0x%X），MBR 保护已禁用", diskErr);
            SendLogToMain(logBuf);
        }
    }

    // 安装网络过滤驱动
    InstallNetworkDriver(TRUE);

    // HIPS 规则已从 TOML 文件动态加载（LoadHipsRules），不再使用嵌入式规则

    // 从 rules/hips/ 目录加载动态 HIPS 规则（覆盖/补充内嵌规则）
    LoadHipsRules(g_hDevice);

    // 同步 Network/Disk/ETW 动态规则到主驱动
    SyncNetworkDiskETWRules(g_hDevice);

    // 将 Client 自身加入驱动保护列表，防止被误拦截/终止
    {
        ULONG selfPid = GetCurrentProcessId();
        char pidBuf[32];
        sprintf_s(pidBuf, "%lu", selfPid);

        COMM_CONTROL_PACKET requestPacket;
        requestPacket.Type = PACKET_TYPE_PROTECT_PROCESS;
        strncpy_s(requestPacket.Data, pidBuf, _TRUNCATE);

        DWORD bytesReturned = 0;
        DeviceIoControl(
            g_hDevice,
            IOCTL_PROTECT_PROCESS,
            &requestPacket, sizeof(COMM_CONTROL_PACKET),
            NULL, 0, &bytesReturned, NULL);
    }

    printf("\n");
    SetConsoleColor(ConsoleColor::Cyan);
    printf("========================================\n");
    printf("  TianHong HIPS User-mode Console\n");
    printf("  Type 'quit' to exit\n");
    printf("========================================\n\n");
    ResetConsoleColor();

    // ── 禁用控制台关闭按钮（Alt+F4/关闭按钮/ESC） ──
    SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE);

    // 移除控制台系统菜单中的关闭菜单项
    HWND hConsoleWnd = GetConsoleWindow();
    if (hConsoleWnd != NULL)
    {
        HMENU hMenu = GetSystemMenu(hConsoleWnd, FALSE);
        if (hMenu != NULL)
        {
            DeleteMenu(hMenu, SC_CLOSE, MF_BYCOMMAND);
        }
    }

    // ── 创建后台线程处理驱动查询（必须在 socket 连接之后）──
    // 确保线程启动时 g_bSocketConnected 已正确设置，
    // 避免驱动注入日志在 socket 未就绪时被静默丢弃
    thread queryThread(HandleUserQueries);

    // ── 初始化动态规则管理器（Phase 3）──
    // 加载 rules/behavior/ 目录下的 TOML 规则文件
    DynamicRuleManagerV2 dynamicRuleManager;
    dynamicRuleManager.Init(g_hDevice, "x64\\Release\\Resources\\rules\\behavior");
    dynamicRuleManager.StartWatching();

    // ── 创建磁盘过滤告警轮询线程 ──
    // 仅在磁盘驱动设备成功打开时启动
    thread diskAlertThread;
    if (g_hDiskDevice != INVALID_HANDLE_VALUE)
    {
        diskAlertThread = thread(HandleDiskAlerts);
    }

    // ── 主循环：读取用户命令 ──
    while (g_bRunning)
    {
        // socket 模式：主线程只保持存活，实际命令处理在 ClientRecvThread 中
        if (bTrafficMode && g_bSocketConnected)
        {
            Sleep(100);
            continue;
        }

        // traffic 模式下一旦与主程序断开，直接退出（无控制台可供交互）
        if (bTrafficMode && !g_bSocketConnected)
        {
            g_bRunning = FALSE;
            break;
        }

        printf("> ");
        string input;
        getline(cin, input);

        if (input.empty())
            continue;

        // ── 处理 quit 命令 ──
        if (input == "quit" || input == "exit")
        {
            g_bRunning = FALSE;
            break;
        }

        // ── 处理 hips load 命令 ──
        if (input == "hips load")
        {
            LoadHipsRules(g_hDevice);
            continue;
        }

        // ── 处理 Protect 命令 ──
        if (input.find("Protect ") == 0 || input.find("protect ") == 0)
        {
            size_t spacePos = input.find(" ");
            if (spacePos == string::npos)
            {
                // 没有 PID 参数 → 自保（保护当前进程）
                ULONG selfPid = GetCurrentProcessId();
                char pidBuf[32];
                sprintf_s(pidBuf, "%lu", selfPid);

                COMM_CONTROL_PACKET requestPacket;
                requestPacket.Type = PACKET_TYPE_PROTECT_PROCESS;
                strncpy_s(requestPacket.Data, pidBuf, _TRUNCATE);

                DWORD bytesReturned = 0;
                BOOL success = DeviceIoControl(
                    g_hDevice,
                    IOCTL_PROTECT_PROCESS,
                    &requestPacket, sizeof(COMM_CONTROL_PACKET),
                    NULL, 0, &bytesReturned, NULL);

                if (success)
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] Self-protection enabled, current process PID=%lu added to protection list\n", selfPid);
                    ResetConsoleColor();
                }
                else
                {
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] Self-protection request failed: %d\n", GetLastError());
                    ResetConsoleColor();
                }
                continue;
            }

            string pidStr = input.substr(spacePos + 1);
            if (pidStr.empty())
            {
                // 空 PID → 自保
                ULONG selfPid = GetCurrentProcessId();
                char pidBuf[32];
                sprintf_s(pidBuf, "%lu", selfPid);

                COMM_CONTROL_PACKET requestPacket;
                requestPacket.Type = PACKET_TYPE_PROTECT_PROCESS;
                strncpy_s(requestPacket.Data, pidBuf, _TRUNCATE);

                DWORD bytesReturned = 0;
                BOOL success = DeviceIoControl(
                    g_hDevice,
                    IOCTL_PROTECT_PROCESS,
                    &requestPacket, sizeof(COMM_CONTROL_PACKET),
                    NULL, 0, &bytesReturned, NULL);

                if (success)
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] Self-protection enabled, current process PID=%lu added to protection list\n", selfPid);
                    ResetConsoleColor();
                }
                else
                {
                    SetConsoleColor(ConsoleColor::Red);
                    printf("[-] Self-protection request failed: %d\n", GetLastError());
                    ResetConsoleColor();
                }
                continue;
            }

            // 处理 Protect clear
            if (pidStr == "clear")
            {
                if (CommClearProtectedPids(g_hDevice))
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] All protected PIDs cleared\n");
                    ResetConsoleColor();
                }
                continue;
            }

            // PID 必须是纯数字，不允许字符串输入
            if (!IsNumeric(pidStr))
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] PID must be numeric, string input not allowed\n");
                ResetConsoleColor();
                continue;
            }

            // 准备请求数据包
            COMM_CONTROL_PACKET requestPacket;
            requestPacket.Type = PACKET_TYPE_PROTECT_PROCESS;
            strncpy_s(requestPacket.Data, pidStr.c_str(), _TRUNCATE);

            DWORD bytesReturned = 0;

            BOOL success = DeviceIoControl(
                g_hDevice,
                IOCTL_PROTECT_PROCESS,
                &requestPacket,
                sizeof(COMM_CONTROL_PACKET),
                NULL, 0,
                &bytesReturned,
                NULL);

            if (success)
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Process protection request sent: PID=%s\n", pidStr.c_str());
                ResetConsoleColor();
            }
            else
            {
                DWORD error = GetLastError();
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] DeviceIoControl failed (IOCTL_PROTECT_PROCESS): %d\n", error);
                ResetConsoleColor();
            }
        }
        // ── 处理 RegRule add 命令 ──
        else if (input.find("RegRule add ") == 0)
        {
            string paramsStr = input.substr(string("RegRule add ").length());
            map<string, string> params = ParseKeyValueParams(paramsStr);

            SetConsoleColor(ConsoleColor::Yellow);
            printf("[D] Parsed parameters:\n");
            for (const auto& kv : params)
            {
                printf("  %s = '%s'\n", kv.first.c_str(), kv.second.c_str());
            }
            ResetConsoleColor();

            SendRuleToDriver(g_hDevice, RULE_TYPE_REG, params);
        }
        // ── 处理 RegRule del 命令 ──
        else if (input.find("RegRule del ") == 0)
        {
            string ruleIdStr = input.substr(string("RegRule del ").length());
            ULONG ruleId = (ULONG)atoi(ruleIdStr.c_str());

            if (CommRemoveRule(g_hDevice, ruleId))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Registry rule deleted: RuleId=%lu\n", ruleId);
                ResetConsoleColor();
            }
            else
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] Failed to delete registry rule: RuleId=%lu\n", ruleId);
                ResetConsoleColor();
            }
        }
        // ── 处理 RegRule clear 命令 ──
        else if (input == "RegRule clear")
        {
            if (CommClearRules(g_hDevice))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] All registry rules cleared\n");
                ResetConsoleColor();
            }
            else
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] Failed to clear registry rules\n");
                ResetConsoleColor();
            }
        }
        // ── 处理 FileRule add 命令 ──
        else if (input.find("FileRule add ") == 0)
        {
            string paramsStr = input.substr(string("FileRule add ").length());
            map<string, string> params = ParseKeyValueParams(paramsStr);

            SetConsoleColor(ConsoleColor::Yellow);
            printf("[D] Parsed parameters:\n");
            for (const auto& kv : params)
            {
                printf("  %s = '%s'\n", kv.first.c_str(), kv.second.c_str());
            }
            ResetConsoleColor();

            SendRuleToDriver(g_hDevice, RULE_TYPE_FILE, params);
        }
        // ── 处理 FileRule del 命令 ──
        else if (input.find("FileRule del ") == 0)
        {
            string ruleIdStr = input.substr(string("FileRule del ").length());
            if (ruleIdStr.empty())
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] Please enter RuleID\n");
                ResetConsoleColor();
                continue;
            }

            ULONG ruleId = stoul(ruleIdStr);

            COMM_CONTROL_PACKET requestPacket;
            requestPacket.Type = PACKET_TYPE_REMOVE_FILE_RULE;
            memcpy_s(requestPacket.Data, sizeof(requestPacket.Data), &ruleId, sizeof(ULONG));

            DWORD bytesReturned = 0;

            BOOL success = DeviceIoControl(
                g_hDevice,
                IOCTL_REMOVE_FILE_RULE,
                &requestPacket,
                sizeof(COMM_CONTROL_PACKET),
                NULL, 0,
                &bytesReturned,
                NULL);

            if (success)
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] File rule deleted: RuleID=%d\n", ruleId);
                ResetConsoleColor();
            }
            else
            {
                DWORD error = GetLastError();
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] DeviceIoControl failed (IOCTL_REMOVE_FILE_RULE): %d\n", error);
                ResetConsoleColor();
            }
        }
        // ── 处理 FileRule clear 命令 ──
        else if (input == "FileRule clear")
        {
            COMM_CONTROL_PACKET requestPacket;
            requestPacket.Type = PACKET_TYPE_CLEAR_FILE_RULES;

            DWORD bytesReturned = 0;

            BOOL success = DeviceIoControl(
                g_hDevice,
                IOCTL_CLEAR_FILE_RULES,
                &requestPacket,
                sizeof(COMM_CONTROL_PACKET),
                NULL, 0,
                &bytesReturned,
                NULL);

            if (success)
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] All file rules cleared\n");
                ResetConsoleColor();
            }
            else
            {
                DWORD error = GetLastError();
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] DeviceIoControl failed (IOCTL_CLEAR_FILE_RULES): %d\n", error);
                ResetConsoleColor();
            }
        }
        // ── 处理 FileRule stats 命令 ──
        else if (input == "FileRule stats")
        {
            COMM_CONTROL_PACKET requestPacket;
            DWORD bytesReturned = 0;

            BOOL success = DeviceIoControl(
                g_hDevice,
                IOCTL_GET_FILE_RULE_STATS,
                NULL, 0,
                &requestPacket,
                sizeof(COMM_CONTROL_PACKET),
                &bytesReturned,
                NULL);

            if (success)
            {
                FILE_RULE_STATS* stats = (FILE_RULE_STATS*)&requestPacket.Data;

                SetConsoleColor(ConsoleColor::Cyan);
                printf("========== File Rule Statistics ==========\n");
                ResetConsoleColor();
                printf("[*] Total rules:        %d\n", stats->TotalRules);
                printf("[*] Active rules:       %d\n", stats->ActiveRules);
                printf("[*] Blocked operations: %d\n", stats->BlockedOperations);
                printf("[*] Allowed operations: %d\n", stats->AllowedOperations);
                printf("\n");
            }
            else
            {
                DWORD error = GetLastError();
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] DeviceIoControl failed (IOCTL_GET_FILE_RULE_STATS): %d\n", error);
                ResetConsoleColor();
            }
        }
        // ── 处理 cache 命令 ──
        else if (input == "cache on")
        {
            if (CommSetResponseCache(g_hDevice, 1))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Response cache enabled (same process + same rule reuses last decision)\n");
                ResetConsoleColor();
            }
        }
        else if (input == "cache off")
        {
            if (CommSetResponseCache(g_hDevice, 0))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Response cache disabled\n");
                ResetConsoleColor();
            }
        }
        else if (input == "cache clear")
        {
            if (CommSetResponseCache(g_hDevice, 2))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Response cache cleared\n");
                ResetConsoleColor();
            }
        }
        // ── 动态行为分析命令 ──
        else if (input == "ba scan")
        {
            /* 堆分配避免栈溢出: 每个 BA_THREAT_RESULT ~5.5KB，64个 ~352KB */
            BA_THREAT_RESULT* results = (BA_THREAT_RESULT*)malloc(sizeof(BA_THREAT_RESULT) * 64);
            INT resultCount = 0;
            INT i, j;

            if (results == NULL) {
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] Memory allocation failed\n");
                ResetConsoleColor();
            }
            else if (CommBehaviorEvaluate(g_hDevice, results, 64, &resultCount))
            {
                if (resultCount == 0)
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] Behavior analysis scan complete, no threats found\n");
                    ResetConsoleColor();
                }
                else
                {
                    printf("\n");
                    SetConsoleColor(ConsoleColor::Yellow);
                    printf("  ╔══════════════════════════════════════════════════════════════╗\n");
                    printf("  ║              Behavior Analysis — Threat Report (%d)              ║\n", resultCount);
                    printf("  ╚══════════════════════════════════════════════════════════════╝\n");
                    ResetConsoleColor();

                    for (i = 0; i < resultCount; i++)
                    {
                        printf("\n");
                        SetConsoleColor(ConsoleColor::Red);
                        printf("  [Threat #%d] %s\n", i + 1, results[i].threatClass);
                        ResetConsoleColor();
                        printf("    PID:            %lld\n", results[i].pid);
                        printf("    Process path:   %s\n", results[i].processPath);
                        printf("    Description:    %s\n", results[i].description);
                        printf("    Confidence:     %.1f%%\n", results[i].confidence * 100.0);

                        if (results[i].evidenceCount > 0 && results[i].evidenceCount <= BA_MAX_EVIDENCE)
                        {
                            SetConsoleColor(ConsoleColor::Cyan);
                            printf("    Evidence:\n");
                            ResetConsoleColor();
                            for (j = 0; j < results[i].evidenceCount; j++)
                            {
                                printf("      - %s\n", results[i].evidence[j]);
                            }
                        }
                    }
                    printf("\n");
                }
            }

            if (results) free(results);
        }
        else if (input == "ba stats")
        {
            BA_STATS stats;
            if (CommBehaviorGetStats(g_hDevice, &stats))
            {
                printf("\n");
                SetConsoleColor(ConsoleColor::Cyan);
                printf("  ╔════════════════════════════════════════════╗\n");
                printf("  ║       Behavior Analysis — Statistics       ║\n");
                printf("  ╚════════════════════════════════════════════╝\n");
                ResetConsoleColor();
                printf("  Active processes: %d\n", stats.processCount);
                printf("  History events:   %d\n", stats.historyCount);
                printf("  Active indicators:%d\n", stats.indicatorCount);
                printf("  Total events:     %lld\n", stats.tickCounter);
                printf("\n");
            }
        }
        else if (input == "ba clear")
        {
            if (CommBehaviorClear(g_hDevice))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Behavior analysis data cleared\n");
                ResetConsoleColor();
            }
        }
        // ── 处理 fullscan 命令 ──
        else if (input == "fullscan on")
        {
            g_bFullScanEnabled = TRUE;
            g_bProcessCheckBlocking = TRUE;
            printf("[+] Full scan mode enabled (blocking check)\n");
        }
        else if (input == "fullscan off")
        {
            g_bFullScanEnabled = FALSE;
            g_bProcessCheckBlocking = FALSE;
            printf("[+] Full scan mode disabled (non-blocking alert)\n");
        }
        // ── 处理 dllscan 命令 ──
        else if (input.find("dllscan ") == 0)
        {
            string subCmd = input.substr(string("dllscan ").length());
            if (subCmd == "on")
            {
                g_bUnsignedDllScanEnabled = TRUE;
                if (CommSetUnsignedDllScan(g_hDevice, TRUE, g_bDllScanBlocking))
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] Unsigned DLL scan enabled, blocking=%s\n",
                        g_bDllScanBlocking ? "YES" : "NO");
                    ResetConsoleColor();
                }
            }
            else if (subCmd == "off")
            {
                g_bUnsignedDllScanEnabled = FALSE;
                if (CommSetUnsignedDllScan(g_hDevice, FALSE, g_bDllScanBlocking))
                {
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] Unsigned DLL scan disabled\n");
                    ResetConsoleColor();
                }
            }
            else if (subCmd.find("on ") == 0 || subCmd.find("off ") == 0)
            {
                size_t spacePos = subCmd.find(" ");
                string mode = subCmd.substr(0, spacePos);
                string blockingStr = subCmd.substr(spacePos + 1);
                BOOL blocking = (blockingStr == "blocking");

                if (mode == "on")
                    g_bUnsignedDllScanEnabled = TRUE;
                else if (mode == "off")
                    g_bUnsignedDllScanEnabled = FALSE;

                if (CommSetUnsignedDllScan(g_hDevice, g_bUnsignedDllScanEnabled, blocking))
                {
                    g_bDllScanBlocking = blocking;
                    SetConsoleColor(ConsoleColor::Green);
                    printf("[+] Unsigned DLL scan %s, blocking=%s\n",
                        g_bUnsignedDllScanEnabled ? "enabled" : "disabled",
                        blocking ? "YES" : "NO");
                    ResetConsoleColor();
                }
            }
            else
            {
                SetConsoleColor(ConsoleColor::Red);
                printf("[-] Usage: dllscan on/off [blocking]\n");
                printf("    Example: dllscan on blocking\n");
                printf("    Example: dllscan off\n");
                ResetConsoleColor();
            }
        }
        // ── 处理 behavior 命令 ──
        else if (input == "behavior on")
        {
            g_bBehaviorDetectionEnabled = TRUE;
            if (CommSetBehaviorDetection(g_hDevice, TRUE))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Behavior detection enabled\n");
                ResetConsoleColor();
            }
        }
        else if (input == "behavior off")
        {
            g_bBehaviorDetectionEnabled = FALSE;
            if (CommSetBehaviorDetection(g_hDevice, FALSE))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Behavior detection disabled\n");
                ResetConsoleColor();
            }
        }
        // ── 处理 memory 命令 ──
        else if (input == "memory on")
        {
            g_bR3ProtectionEnabled = TRUE;
            if (CommSetR3Protection(g_hDevice, TRUE))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] R3 DLL protection injection enabled\n");
                ResetConsoleColor();
            }
        }
        else if (input == "memory off")
        {
            g_bR3ProtectionEnabled = FALSE;
            if (CommSetR3Protection(g_hDevice, FALSE))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] R3 DLL protection injection disabled\n");
                ResetConsoleColor();
            }
        }
        // ── 处理 processprotect 命令 ──
        else if (input == "processprotect on")
        {
            g_bProcessProtectionEnabled = TRUE;
            if (CommSetProcessProtection(g_hDevice, TRUE))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Process protection enabled\n");
                ResetConsoleColor();
            }
        }
        else if (input == "processprotect off")
        {
            g_bProcessProtectionEnabled = FALSE;
            if (CommSetProcessProtection(g_hDevice, FALSE))
            {
                SetConsoleColor(ConsoleColor::Green);
                printf("[+] Process protection disabled\n");
                ResetConsoleColor();
            }
        }
        // ── 处理 status 命令 ──
        else if (input == "status")
        {
            printf("\n");
            SetConsoleColor(ConsoleColor::Cyan);
            printf("========== Switch Status ==========\n");
            ResetConsoleColor();
            printf("  Full scan mode:          %s\n", g_bFullScanEnabled ? "ON" : "OFF");
            printf("  Unsigned DLL scan:       %s\n", g_bUnsignedDllScanEnabled ? "ON" : "OFF");
            printf("  DLL scan blocking:       %s\n", g_bDllScanBlocking ? "YES" : "NO");
            printf("  Behavior detection:      %s\n", g_bBehaviorDetectionEnabled ? "ON" : "OFF");
            printf("  R3 protection injection: %s\n", g_bR3ProtectionEnabled ? "ON" : "OFF");
            printf("  Process protection:      %s\n", g_bProcessProtectionEnabled ? "ON" : "OFF");
            printf("  Response cache:          %s\n", "check with 'cache on/off/clear'");
            printf("\n");
        }
        // ── 未知命令 ──
        else
        {
            PrintUsage();
        }
    }

    // ── 清理退出 ──
    g_bRunning = FALSE;

    SetConsoleColor(ConsoleColor::Yellow);
    printf("[.] Waiting for background thread to exit...\n");
    ResetConsoleColor();

    /* 先关闭设备句柄，使 HandleUserQueries 中的 DeviceIoControl 立即返回失败，
     * 否则线程会阻塞在 IOCTL_RULE_DETECTED_REQUEST 上，join 永远无法完成 */
    if (g_hCommDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hCommDevice);
        g_hCommDevice = INVALID_HANDLE_VALUE;
    }

    if (queryThread.joinable())
    {
        queryThread.join();
    }

    // 等待磁盘告警线程退出
    if (diskAlertThread.joinable())
    {
        diskAlertThread.join();
    }

    // 关闭磁盘驱动设备句柄
    if (g_hDiskDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hDiskDevice);
        g_hDiskDevice = INVALID_HANDLE_VALUE;
    }

    CleanupAndExit();

    return 0;
}

// ============================================================================
// CleanupAndExit - 清理资源并退出（确保驱动被卸载）
// 可从任意线程调用，用于保证驱动在程序退出时被正确卸载
// ============================================================================
void CleanupAndExit()
{
    g_bRunning = FALSE;
    g_bSocketConnected = FALSE;

    // 卸载驱动
    SetConsoleColor(ConsoleColor::Yellow);
    printf("[.] Uninstalling driver...\n");
    ResetConsoleColor();

    /* 通过 IOCTL 通知驱动准备卸载（停止定时器、卸载 Minifilter）*/
    if (g_hDevice != INVALID_HANDLE_VALUE)
    {
        printf("[.] Sending IOCTL_PREPARE_UNLOAD to driver...\n");
        DWORD bytesReturned;
        BOOL ok = DeviceIoControl(g_hDevice, IOCTL_PREPARE_UNLOAD,
            NULL, 0, NULL, 0, &bytesReturned, NULL);
        if (ok)
            printf("[+] IOCTL_PREPARE_UNLOAD succeeded\n");
        else
            printf("[-] IOCTL_PREPARE_UNLOAD failed: %d\n", GetLastError());
        CloseHandle(g_hDevice);
        g_hDevice = INVALID_HANDLE_VALUE;
    }
    else
    {
        printf("[!] g_hDevice is INVALID_HANDLE_VALUE, skipping IOCTL_PREPARE_UNLOAD\n");
    }

    if (g_hCommDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hCommDevice);
        g_hCommDevice = INVALID_HANDLE_VALUE;
    }

    /* 停止并删除主驱动服务（TianHongHips） */
    {
        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (hSCM)
        {
            SC_HANDLE hMainSvc = OpenServiceA(hSCM, THSD_SERVICE_NAME_A,
                                              SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
            if (hMainSvc)
            {
                SERVICE_STATUS mainStatus;
                if (ControlService(hMainSvc, SERVICE_CONTROL_STOP, &mainStatus))
                {
                    printf("[.] Stopping TianHongHips service...\n");
                    SendLogToMain("[驱动卸载] 正在停止 TianHongHips 主驱动服务...");
                    for (int i = 0; i < 50; i++)
                    {
                        Sleep(100);
                        if (QueryServiceStatus(hMainSvc, &mainStatus) &&
                            mainStatus.dwCurrentState == SERVICE_STOPPED)
                            break;
                    }
                }
                if (DeleteService(hMainSvc))
                {
                    printf("[+] TianHongHips service deleted\n");
                    SendLogToMain("[驱动卸载] TianHongHips 主驱动服务已删除");
                }
                else
                {
                    printf("[-] DeleteService TianHongHips failed: %lu\n", GetLastError());
                }
                CloseServiceHandle(hMainSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }

    /* 停止并删除磁盘过滤驱动服务（TianHongHips.Disk） */
    {
        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (hSCM)
        {
            SC_HANDLE hDiskSvc = OpenServiceA(hSCM, THSD_DISK_SERVICE_NAME_A,
                                              SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
            if (hDiskSvc)
            {
                SERVICE_STATUS diskStatus;
                if (ControlService(hDiskSvc, SERVICE_CONTROL_STOP, &diskStatus))
                {
                    printf("[.] Stopping TianHongHips.Disk service...\n");
                    for (int i = 0; i < 50; i++)
                    {
                        Sleep(100);
                        if (QueryServiceStatus(hDiskSvc, &diskStatus) &&
                            diskStatus.dwCurrentState == SERVICE_STOPPED)
                            break;
                    }
                }
                if (DeleteService(hDiskSvc))
                {
                    printf("[+] TianHongHips.Disk service deleted\n");
                    SendLogToMain("[驱动卸载] TianHongHips.Disk 磁盘过滤驱动已卸载");
                }
                else
                {
                    printf("[-] DeleteService TianHongHips.Disk failed: %lu\n", GetLastError());
                }
                CloseServiceHandle(hDiskSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }

    /* 停止并删除网络过滤驱动服务（TianHongHips.Network） */
    {
        if (g_hNetworkDevice != INVALID_HANDLE_VALUE)
        {
            ULONG disable = 0;
            DWORD bytesReturned;
            DeviceIoControl(g_hNetworkDevice, IOCTL_NETWORK_SET_ENABLED,
                &disable, sizeof(disable), NULL, 0, &bytesReturned, NULL);
            CloseHandle(g_hNetworkDevice);
            g_hNetworkDevice = INVALID_HANDLE_VALUE;
        }

        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
        if (hSCM)
        {
            SC_HANDLE hNetSvc = OpenServiceA(hSCM, THSD_NETWORK_SERVICE_NAME_A,
                                              SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
            if (hNetSvc)
            {
                SERVICE_STATUS netStatus;
                if (ControlService(hNetSvc, SERVICE_CONTROL_STOP, &netStatus))
                {
                    printf("[.] Stopping TianHongHips.Network service...\n");
                    for (int i = 0; i < 50; i++)
                    {
                        Sleep(100);
                        if (QueryServiceStatus(hNetSvc, &netStatus) &&
                            netStatus.dwCurrentState == SERVICE_STOPPED)
                            break;
                    }
                }
                if (DeleteService(hNetSvc))
                {
                    printf("[+] TianHongHips.Network service deleted\n");
                    SendLogToMain("[驱动卸载] TianHongHips.Network 网络过滤驱动已卸载");
                }
                else
                {
                    printf("[-] DeleteService TianHongHips.Network failed: %lu\n", GetLastError());
                }
                CloseServiceHandle(hNetSvc);
            }
            CloseServiceHandle(hSCM);
        }
    }

    SetConsoleColor(ConsoleColor::Green);
    printf("[>] Program exiting\n");
    ResetConsoleColor();

    // 清理 socket 连接
    if (g_clientSocket != INVALID_SOCKET)
    {
        closesocket(g_clientSocket);
        g_clientSocket = INVALID_SOCKET;
    }
    WSACleanup();

    // 清理告警/进程检查响应状态临界区
    DeleteCriticalSection(&g_alertResponseCs);

    exit(0);
}
