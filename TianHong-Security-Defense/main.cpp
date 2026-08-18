#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include "PublicIncluding.h"
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")

#include "VirusScanPage.h"
#include "ProtectionSettingPage.h"
#include "MainPage.h"
#include "LoggerPage.h"
#include "WhitelistPage.h"
#include <QFileIconProvider>
#include "PublicFunction.h"
#include "PEScan.h"
#include "../TianHongDefenseKernelProtectionClient/shared/SocketProtocol.h"
#include "ActiveIcon.h"
#include "ElaIconButton.h"
#include "ElaPushButton.h"
#include "ElaTheme.h"
#include <QDialog>

// ETW Threat-Intelligence consumer support
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <iphlpapi.h>
#include <wincrypt.h>
#include <shellapi.h>  // CommandLineToArgvW
#include <psapi.h>     // EnumProcessModules / GetModuleInformation / GetModuleBaseName
#pragma comment(lib, "psapi.lib")
#include <unordered_set>
#include <vector>
#include <memory>
#include <algorithm>
#include <cctype>

#include "Sandbox.h"
#include "BatchScan.h"

// clamav
typedef cl_error_t(*cl_init_type)(unsigned int initoptions);
typedef cl_engine* (*cl_engine_new_type)(void);
typedef int (*cl_load_type)(const char* path, struct cl_engine* engine,
	unsigned int* signo, unsigned int options);
typedef int (*cl_engine_compile_type)(struct cl_engine* engine);
typedef int (*cl_scanfile_type)(const char* filename, const char** virname, unsigned long int* scanned,
	const struct cl_engine* engine, cl_scan_options* options);//传入文件路径；病毒引擎，执行扫描，返回值：CL_VIRUS表示有病毒；CL_CLEAN表示无病毒；
typedef cl_error_t(*cl_engine_free_type)(struct cl_engine* engine);

struct InjectedProcessInfo {
	DWORD pid;
	HANDLE hProcess;        // 进程句柄（已复制）
	HANDLE hToken;           // 原进程主令牌（可能为NULL）
	std::string commandLine;
	std::string processPath;
	time_t expireTime;
};

std::vector<InjectedProcessInfo> g_InjectedProcesses;
CRITICAL_SECTION g_csProcessList;

cl_init_type pcl_init;
cl_engine_new_type pcl_engine_new;
cl_load_type pcl_load;
cl_engine_compile_type pcl_engine_compile;
cl_scanfile_type pcl_scanfile;
cl_engine_free_type pcl_engine_free;

HMODULE g_hClamAVModule = NULL;  // libclamav.dll 模块句柄，用于清理时 FreeLibrary

cl_engine* mClamAVEngine;
cl_scan_options mClamOptions;
unsigned int mClamScanned = 0;

// sha256
string* VirusNameList;
string* VirusSha256List;
int Sha256Count = 0;
string* WhiteSha256List;
int WhiteSha256Count = 0;
std::unordered_map<std::string, std::string> WhiteSha256ListCache;  // 临时白名单: sha256(小写) -> 文件路径
std::vector<std::string> WhiteDirListCache;  // 临时目录白名单: 目录绝对路径（小写、末尾带'\'），命中则该目录下所有文件免扫
std::set<std::string> WhitePathListCache;    // 强化白名单: 文件路径(小写)，命中则该路径文件免扫（无论sha256如何变化）
std::unordered_set<std::string> HasBeenScanedSha256WhiteList;
std::unordered_map<std::string, std::string> HasBeenScanedSha256BlackList;
std::vector<std::string> HasBeenScanedTypeBlackList;
CRITICAL_SECTION g_csScanCache;  // 保护 HasBeenScanedSha256WhiteList / HasBeenScanedSha256BlackList / WhiteSha256ListCache 的并发访问

// PE
LightGBMClassifier mPEModel;

BOOL Windows_IsNowUAC;
HDESK Windows_OrgDesktop, Windows_UacDesktop;

YR_COMPILER* Yara_Compiler;
YR_RULES* Yara_Rules; // YARA 规则
YR_RULES* Yara_MemRules; // YARA 规则Memory版

BOOL Process_IsInjectorReady = FALSE;
int Process_InjectHelperId = 0;

SOCKET Tran_OrgServer, Tran_OrgServerInjector; // 服务器socket
SOCKET Tran_OrgServerClient;           // Client 专用 server socket
SOCKET Tran_ClientSocket;              // Client 连接 socket
SOCKET Tran_Client[MAX_CLIENT_COUNT + 100], Tran_ClientInjector;             // 客户端socket
sockaddr_in Tran_ClientAddr[MAX_CLIENT_COUNT + 100], Tran_ClientAddrInjector, Tran_ServerAddr, Tran_ServerAddrInjector;
volatile BOOL g_bClientConnected = FALSE; // Client 是否已连接
std::atomic<BOOL> g_bClientLoadFailed(FALSE); // Client 报告驱动加载失败
std::atomic<BOOL> g_bR0EnableCancelled(FALSE); // 用户在中转启用过程中取消/关闭

// KernelProtectionClient 本地 IPC 认证
char g_szExpectedClientAuthToken[65] = {0};   // 预期认证令牌（64 位十六进制 + '\0'）
DWORD g_dwAuthenticatedClientPid = 0;         // 已认证 Client 的 PID
wchar_t g_wszClientExePath[MAX_PATH] = {0};   // 已认证 Client 可执行文件完整路径
wchar_t g_wszMainExeDir[MAX_PATH] = {0};      // 主程序所在目录

DWORD WINAPI ClientAcceptT(LPVOID lpParam);
DWORD WINAPI ClientRecvT(LPVOID lpParam);

int Tran_ClientPid[MAX_CLIENT_COUNT + 100];

wchar_t wcSystemRootPath[32767 + 10] = { 0 };
wchar_t wcWindowsPath[32767 + 10] = { 0 };
wchar_t wcSysWow64Path[32767 + 10] = { 0 };
char* DeskPath;

string RansomDetectPath[999];
int RansomDetectPathCount = 0;
string RansomDetectPathDic[999];
int RansomDetectPathDicCount = 0;
BOOL IsOpenExtortionCatch = TRUE;

// 需保护文件句柄
HANDLE FileProtect[100] = { NULL };
int FileProctectCount = 0;

BOOL ClamAV_IsReady = FALSE;
BOOL PE_IsReady = FALSE;
BOOL Yara_IsReady = FALSE;
BOOL Yara_MemIsReady = FALSE;
BOOL Sha256Black_IsReady = FALSE;
BOOL Sha256White_IsReady = FALSE;

short isLoadReady = 0; // 0初始，2表示自动加载的引擎（YARA、PE）已完成

BOOL ExcepExit = FALSE; // 是否异常退出

HANDLE FileWarnMutex;
HANDLE HandleMutex;        // 危险操作Mutex
HANDLE CreateCheckMutex;

vector<std::pair<int, string>> ProcessEventId; // 用于等待hook完成

MainPage* pMainPage;
VirusScanPage* pVirusScanPage;
ProtectionSettingPage* pProtectionSettingPage;
LoggerPage* pLoggerPage;
WhitelistPage* pWhitelistPage;

MainWindow* pMainWindow;

// GdiPlus
ULONG_PTR gdiplusToken;
Gdiplus::GdiplusStartupOutput gdiplusStartupOutput;
Gdiplus::GdiplusStartupInput gdiplusStartupInput;
BOOL isGdiReady = FALSE;

// KernelProtectionClient 进程句柄（驱动防护模式自动启动）
HANDLE g_hClientProcess = NULL;
HANDLE g_hClientThread = NULL;

// 静默模式全局状态
BOOL g_bSilentModeEnabled = FALSE;
BOOL g_bExtractFilesEnabled = FALSE;

extern std::atomic<ScanState> mScanState; // 扫描状态

struct PIDArrayDataItem {
	int pid;
	string content;

	PIDArrayDataItem(int p, const string& c) : pid(p), content(c) {}

	bool operator==(const PIDArrayDataItem& other) const {
		return pid == other.pid && content == other.content;
	}
};

class PIDArrayWithIndex {
private:
	std::vector<PIDArrayDataItem> data;
	std::unordered_map<int, std::vector<size_t>> index;
	bool indexDirty = false;  // 索引是否需要更新
	mutable CRITICAL_SECTION cs;  // 线程安全保护

public:
	PIDArrayWithIndex() {
		InitializeCriticalSection(&cs);
	}
	~PIDArrayWithIndex() {
		DeleteCriticalSection(&cs);
	}
	// 禁止拷贝（CRITICAL_SECTION 不可拷贝）
	PIDArrayWithIndex(const PIDArrayWithIndex&) = delete;
	PIDArrayWithIndex& operator=(const PIDArrayWithIndex&) = delete;

	void Add(int pid, const string& content) {
		EnterCriticalSection(&cs);
		// 去重：如果 PID + content 已存在，不再添加
		if (FindLocked(pid, content)) {
			LeaveCriticalSection(&cs);
			return;
		}
		data.emplace_back(pid, content);
		if (!indexDirty) {
			// 如果索引是最新的，直接更新
			index[pid].push_back(data.size() - 1);
		}
		LeaveCriticalSection(&cs);
	}

	bool Find(int pid, const string& content) {
		EnterCriticalSection(&cs);
		bool result = FindLocked(pid, content);
		LeaveCriticalSection(&cs);
		return result;
	}

	/* 仅按 PID 查找：同一 PID 已在自动列表中则返回 true。
	 * 用于避免同一进程的不同操作（WRITE/DELETE/RENAME 等）反复弹窗。 */
	bool FindByPid(int pid) {
		EnterCriticalSection(&cs);
		if (indexDirty) {
			RebuildIndexLocked();
		}
		bool result = (index.find(pid) != index.end());
		LeaveCriticalSection(&cs);
		return result;
	}

	void Del(int pid)
	{
		EnterCriticalSection(&cs);
		// 直接遍历删除
		auto new_end = std::remove_if(data.begin(), data.end(),
			[pid](const PIDArrayDataItem& item) {
				return item.pid == pid;
			});
		data.erase(new_end, data.end());

		// 标记索引需要重建
		indexDirty = true;
		LeaveCriticalSection(&cs);
	}

	// 获取所有条目（用于同步到 R0）— 返回副本，调用者无需持有锁
	std::vector<PIDArrayDataItem> GetAllEntries() const
	{
		EnterCriticalSection(&cs);
		std::vector<PIDArrayDataItem> result = data;
		LeaveCriticalSection(&cs);
		return result;
	}

	size_t Size() const
	{
		EnterCriticalSection(&cs);
		size_t result = data.size();
		LeaveCriticalSection(&cs);
		return result;
	}

private:
	// 内部查找（调用者必须持有 cs）
	bool FindLocked(int pid, const string& content) {
		if (indexDirty) {
			RebuildIndexLocked();
		}

		auto it = index.find(pid);
		if (it == index.end()) return false;

		for (size_t idx : it->second) {
			if (data[idx].content == content) {
				return true;
			}
		}
		return false;
	}

	// 内部重建索引（调用者必须持有 cs）
	void RebuildIndexLocked()
	{
		index.clear();
		for (size_t i = 0; i < data.size(); ++i) {
			index[data[i].pid].push_back(i);
		}
		indexDirty = false;
	}
};

PIDArrayWithIndex AutoAllowList, AutoPreventList;

// ═══════════════════════════════════════════════════════════════════════════
// R0驱动防护模式支持
// 当启用R0防护后，进程检查由驱动负责，R3只做DLL注入
// R3/R0白名单和自动放行/拦截列表需要同步
// ═══════════════════════════════════════════════════════════════════════════
HANDLE g_hR0DriverDevice = INVALID_HANDLE_VALUE;  // R0驱动通信句柄
BOOL g_bR0ProtectionEnabled = FALSE;              // R0防护是否启用
BOOL g_bPendingDllPathSet = FALSE;                // 待发送DLL路径到驱动（等Client就绪后触发）
std::atomic<BOOL> g_bDriverReady(FALSE);           // 驱动已就绪（Client 发送 READY 后置位）
CRITICAL_SECTION g_csR0Sync;                      // R0同步锁

// ═══════════════════════════════════════════════════════════════════════════
// ETW Threat-Intelligence Consumer
// 用户态订阅 Microsoft-Windows-Threat-Intelligence provider，将远程内存操作
// 事件通过 IOCTL 下发到内核 BehaviorAnalysis 引擎。
// ═══════════════════════════════════════════════════════════════════════════
static HANDLE g_hEtwTiThread = NULL;
static TRACEHANDLE g_hEtwTiSession = 0;
static EVENT_TRACE_PROPERTIES* g_pEtwTiProperties = NULL;
static GUID g_EtwTiProviderGuid =
    { 0xF4E1897C, 0xBB5D, 0x5668, { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 } };
static volatile BOOL g_bEtwTiRunning = FALSE;

// 去重：最近已下发的 (CallerPid, TargetPid, BaseAddress, EventId) 集合
static CRITICAL_SECTION g_csEtwTiDedup;
struct EtwTiDedupKey {
    INT64 callerPid;
    INT64 targetPid;
    INT64 baseAddress;
    ULONG eventId;
    ULONGLONG timestamp;
    bool operator==(const EtwTiDedupKey& other) const {
        return callerPid == other.callerPid && targetPid == other.targetPid &&
               baseAddress == other.baseAddress && eventId == other.eventId;
    }
};
struct EtwTiDedupHash {
    size_t operator()(const EtwTiDedupKey& k) const {
        return std::hash<INT64>()(k.callerPid ^ k.targetPid ^ k.baseAddress ^ (INT64)k.eventId);
    }
};
static std::unordered_map<EtwTiDedupKey, ULONGLONG, EtwTiDedupHash> g_EtwTiDedupMap;

#define ETW_TI_DEDUP_WINDOW_MS 2000
#define ETW_TI_DEDUP_MAX_ENTRIES 8192

// 速率限制：每个 (CallerPid, TargetPid) 对，在窗口期内最多下发 N 个事件
// 防止异常进程短时间内产生海量 ETW 事件导致 IOCTL 风暴
static CRITICAL_SECTION g_csEtwTiRateLimit;
static BOOL g_bEtwTiCsInitialized = FALSE; // ETW-TI 临界区是否已初始化
struct EtwTiRateKey {
    INT64 callerPid;
    INT64 targetPid;
    bool operator==(const EtwTiRateKey& other) const {
        return callerPid == other.callerPid && targetPid == other.targetPid;
    }
};
struct EtwTiRateHash {
    size_t operator()(const EtwTiRateKey& k) const {
        return std::hash<INT64>()(k.callerPid ^ k.targetPid);
    }
};
struct EtwTiRateValue {
    ULONGLONG windowStart;
    ULONG count;
};
static std::unordered_map<EtwTiRateKey, EtwTiRateValue, EtwTiRateHash> g_EtwTiRateLimitMap;

#define ETW_TI_RATE_LIMIT_WINDOW_MS 1000
#define ETW_TI_RATE_LIMIT_MAX_EVENTS 64
#define ETW_TI_RATE_LIMIT_MAX_ENTRIES 4096

#define ETW_TI_DEVICE_OPEN_RETRIES 8
#define ETW_TI_DEVICE_OPEN_RETRY_INTERVAL_MS 300
#define ETW_TI_DRIVER_WAIT_RETRIES 15
#define ETW_TI_DRIVER_WAIT_INTERVAL_MS 500

// keyword mask for remote memory operations
#define TI_KEYWORD_ALLOCVM_REMOTE           0x00000004
#define TI_KEYWORD_PROTECTVM_REMOTE         0x00000040
#define TI_KEYWORD_WRITEVM_REMOTE           0x00008000
#define TI_KEYWORD_QUEUEUSERAPC_REMOTE      0x00001000
#define TI_KEYWORD_SETTHREADCONTEXT_REMOTE  0x00004000
#define TI_KEYWORD_MAPVIEW_REMOTE           0x00000400

// keyword mask for self memory operations (same-process protection changes)
#define TI_KEYWORD_ALLOCVM_SELF             0x00000001
#define TI_KEYWORD_PROTECTVM_SELF           0x00000010
#define TI_KEYWORD_WRITEVM_SELF             0x00002000

// -- ETW Network Threat-Intelligence Consumer --
// 用户态订阅 Microsoft-Windows-TCPIP provider，将网络连接事件通过 IOCTL 下发到内核 BehaviorAnalysis 引擎进行 C2 检测。
// ═══════════════════════════════════════════════════════════════════════════
static HANDLE g_hEtwTiNetworkThread = NULL;
static TRACEHANDLE g_hEtwTiNetworkSession = 0;
static EVENT_TRACE_PROPERTIES* g_pEtwTiNetworkProperties = NULL;
// Microsoft-Windows-TCPIP provider GUID
static GUID g_EtwTiNetworkProviderGuid =
    { 0x7d4c140a, 0x66c8, 0x5c6c, { 0xb7, 0xc0, 0x8b, 0x0f, 0x3b, 0x7c, 0x1a, 0x3c } };
static volatile BOOL g_bEtwTiNetworkRunning = FALSE;

// 去重：最近已下发的 (CallerPid, RemoteAddr, RemotePort, EventId) 集合
static CRITICAL_SECTION g_csEtwTiNetDedup;
struct EtwTiNetDedupKey {
    INT64 callerPid;
    ULONG remoteAddrHash;
    ULONG remotePort;
    ULONG eventId;
    bool operator==(const EtwTiNetDedupKey& other) const {
        return callerPid == other.callerPid && remoteAddrHash == other.remoteAddrHash &&
               remotePort == other.remotePort && eventId == other.eventId;
    }
};
struct EtwTiNetDedupHash {
    size_t operator()(const EtwTiNetDedupKey& k) const {
        return std::hash<INT64>()(k.callerPid ^ k.remoteAddrHash ^ (INT64)k.remotePort ^ (INT64)k.eventId);
    }
};
static std::unordered_map<EtwTiNetDedupKey, ULONGLONG, EtwTiNetDedupHash> g_EtwTiNetDedupMap;

#define ETW_TI_NET_DEDUP_WINDOW_MS 5000
#define ETW_TI_NET_DEDUP_MAX_ENTRIES 4096

// 速率限制：每个 CallerPid 在窗口期内最多下发 N 个网络事件
static CRITICAL_SECTION g_csEtwTiNetRateLimit;
struct EtwTiNetRateKey {
    INT64 callerPid;
    bool operator==(const EtwTiNetRateKey& other) const {
        return callerPid == other.callerPid;
    }
};
struct EtwTiNetRateHash {
    size_t operator()(const EtwTiNetRateKey& k) const {
        return std::hash<INT64>()(k.callerPid);
    }
};
struct EtwTiNetRateValue {
    ULONGLONG windowStart;
    ULONG count;
};
static std::unordered_map<EtwTiNetRateKey, EtwTiNetRateValue, EtwTiNetRateHash> g_EtwTiNetRateLimitMap;

#define ETW_TI_NET_RATE_LIMIT_WINDOW_MS 1000
#define ETW_TI_NET_RATE_LIMIT_MAX_EVENTS 32
#define ETW_TI_NET_RATE_LIMIT_MAX_ENTRIES 2048

// -- ETW Syscall Consumer --
// 用户态订阅 Microsoft-Windows-Kernel-Syscall provider（或 SystemTraceProvider
// 的 EVENT_TRACE_FLAG_SYSTEMCALL），将 syscall 返回地址/调用来源通过 IOCTL
// 下发到内核，检测 direct / indirect syscall，重点识别绕过 R3 EDR/安全软件
// 用户态 Hook 的行为。
// ═══════════════════════════════════════════════════════════════════════════
static HANDLE g_hEtwSyscallThread = NULL;
static TRACEHANDLE g_hEtwSyscallSession = 0;
static EVENT_TRACE_PROPERTIES* g_pEtwSyscallProperties = NULL;
// Microsoft-Windows-Kernel-Syscall provider GUID（若系统不存在该 provider，
// 可改用 SystemTraceProvider + EVENT_TRACE_FLAG_SYSTEMCALL）
static GUID g_EtwSyscallProviderGuid =
    { 0xE02A841C, 0x75C3, 0x4223, { 0xBF, 0xC7, 0x91, 0x26, 0x6A, 0x1F, 0x5D, 0x7A } };
// 经典系统 trace provider（用于 EVENT_TRACE_FLAG_SYSTEMCALL）
static GUID g_SystemTraceProviderGuid =
    { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39 } };
static volatile BOOL g_bEtwSyscallRunning = FALSE;

/* GUID 比较辅助函数，避免依赖 IsEqualGUID 宏是否已定义 */
static BOOL IsEqualGuid(const GUID* a, const GUID* b)
{
    return (a != NULL && b != NULL &&
            a->Data1 == b->Data1 &&
            a->Data2 == b->Data2 &&
            a->Data3 == b->Data3 &&
            memcmp(a->Data4, b->Data4, sizeof(a->Data4)) == 0);
}

static CRITICAL_SECTION g_csEtwSyscallRateLimit;
struct EtwSyscallRateKey {
    INT64 callerPid;
    bool operator==(const EtwSyscallRateKey& other) const {
        return callerPid == other.callerPid;
    }
};
struct EtwSyscallRateHash {
    size_t operator()(const EtwSyscallRateKey& k) const {
        return std::hash<INT64>()(k.callerPid);
    }
};
struct EtwSyscallRateValue {
    ULONGLONG windowStart;
    ULONG count;
};
static std::unordered_map<EtwSyscallRateKey, EtwSyscallRateValue, EtwSyscallRateHash> g_EtwSyscallRateLimitMap;

// -- 模块缓存（按 PID），避免每个 syscall 事件都 EnumProcessModulesEx --
struct EtwSyscallModuleInfo {
    std::wstring name;
    ULONG_PTR    base;
    ULONG_PTR    end;
};
struct EtwSyscallModuleCache {
    ULONGLONG lastUpdateMs;
    std::vector<EtwSyscallModuleInfo> modules;
};
static CRITICAL_SECTION g_csEtwSyscallModuleCache;
static std::unordered_map<DWORD, EtwSyscallModuleCache> g_EtwSyscallModuleCacheMap;
#define ETW_SYSCALL_MODULE_CACHE_TTL_MS 1000
#define ETW_SYSCALL_MODULE_CACHE_MAX_PIDS 512

#define ETW_SYSCALL_RATE_LIMIT_WINDOW_MS 1000
#define ETW_SYSCALL_RATE_LIMIT_MAX_EVENTS 128
#define ETW_SYSCALL_RATE_LIMIT_MAX_ENTRIES 2048

#ifndef EVENT_TRACE_TYPE_SYSCALL
#define EVENT_TRACE_TYPE_SYSCALL 50  // Classic ETW system call enter event
#endif
#ifndef EVENT_ENABLE_PROPERTY_STACK_TRACE
#define EVENT_ENABLE_PROPERTY_STACK_TRACE 0x00000004
#endif

// ═══════════════════════════════════════════════════════════════════════════
// DCOM Lateral Movement Detection
// 监控进程创建，检测 DCOM 横向移动攻击 (MITRE T1021.003)
// 攻击者通过 DCOM 远程激活 COM 对象（MMC20.Application、ShellWindows、Excel.Application 等）
// 在目标机器上执行代码。检测模式：dllhost.exe/svchost.exe(RPCSS) 作为父进程
// 派生可疑子进程。
// ═══════════════════════════════════════════════════════════════════════════
static HANDLE g_hDcomMonitorThread = NULL;
static volatile BOOL g_bDcomMonitorRunning = FALSE;

// DCOM 检测类型
#define DCOM_TYPE_MMC20             1
#define DCOM_TYPE_SHELLWINDOWS      2
#define DCOM_TYPE_EXCEL             3
#define DCOM_TYPE_OUTLOOK           4
#define DCOM_TYPE_WMI               5
#define DCOM_TYPE_GENERIC_CHILD     6

// 常见被 R3 EDR/安全软件 Hook 的 ntdll 导出函数名。syscall 号随 Windows
// 构建变化，因此从 ntdll.dll 导出动态解析，而非硬编码。
// 覆盖内存注入、进程/令牌操作、文件系统、注册表、WorkerFactory(PoolParty)、
// ALPC、作业对象、同步对象、符号链接、I/O 完成端口、安全描述符、驱动加载、
// 系统调试、注册表 Hive 操作、事务等攻击面，共 100+ 函数。
static const CHAR* s_hookedNtdllExports[] = {
    /* ── 内存 / 注入 (核心) ── */
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtReadVirtualMemory",
    "NtCreateThreadEx",
    "NtCreateThread",
    "NtQueueApcThread",
    "NtQueueApcThreadEx",
    "NtSetContextThread",
    "NtGetContextThread",
    "NtResumeThread",
    "NtSuspendThread",
    "NtOpenProcess",
    "NtOpenThread",
    "NtCreateSection",
    "NtOpenSection",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtDuplicateObject",
    "NtSetInformationThread",
    "NtQueryInformationThread",
    "NtQueryInformationProcess",
    "NtFreeVirtualMemory",
    "NtQueryVirtualMemory",
    "NtFlushInstructionCache",
    "NtAlertThread",
    "NtAlertResumeThread",
    "NtTestAlert",
    "NtContinue",

    /* ── 进程操作 ── */
    "NtCreateUserProcess",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtTerminateProcess",
    "NtSetInformationProcess",
    "NtQuerySystemInformation",
    "NtClose",

    /* ── 令牌操作 ── */
    "NtAdjustPrivilegesToken",
    "NtOpenProcessToken",
    "NtOpenThreadToken",
    "NtSetInformationToken",
    "NtQueryInformationToken",
    "NtDuplicateToken",
    "NtCreateToken",
    "NtFilterToken",
    "NtImpersonateAnonymousToken",

    /* ── 文件系统 ── */
    "NtCreateFile",
    "NtDeleteFile",
    "NtQueryDirectoryFile",
    "NtQueryDirectoryFileEx",
    "NtDeviceIoControlFile",
    "NtReadFile",
    "NtWriteFile",
    "NtQueryInformationFile",
    "NtSetInformationFile",
    "NtFsControlFile",

    /* ── 注册表 ── */
    "NtCreateKey",
    "NtOpenKey",
    "NtDeleteKey",
    "NtSetValueKey",
    "NtDeleteValueKey",
    "NtQueryValueKey",
    "NtEnumerateValueKey",
    "NtRenameKey",
    "NtLoadKey",
    "NtLoadKeyEx",
    "NtUnloadKey",
    "NtRestoreKey",
    "NtReplaceKey",
    "NtSaveKey",
    "NtSaveKeyEx",

    /* ── WorkerFactory (PoolParty 注入) ── */
    "NtCreateWorkerFactory",
    "NtQueryInformationWorkerFactory",
    "NtSetInformationWorkerFactory",
    "NtShutdownWorkerFactory",
    "NtWaitForWorkViaWorkerFactory",

    /* ── 作业对象 ── */
    "NtCreateJobObject",
    "NtAssignProcessToJobObject",
    "NtQueryInformationJobObject",
    "NtSetInformationJobObject",

    /* ── ALPC / 命名管道 / 端口 ── */
    "NtCreateNamedPipeFile",
    "NtCreateMailslotFile",
    "NtCreatePort",
    "NtCreateWaitablePort",
    "NtConnectPort",
    "NtRequestWaitReplyPort",
    "NtAlpcSendWaitReceivePort",

    /* ── 同步对象 ── */
    "NtDelayExecution",
    "NtWaitForSingleObject",
    "NtWaitForMultipleObjects",
    "NtCreateEvent",
    "NtCreateMutant",
    "NtCreateSemaphore",
    "NtCreateTimer",
    "NtSetTimer",
    "NtSetTimerResolution",
    "NtQueryTimerResolution",

    /* ── 安全描述符 ── */
    "NtSetSecurityObject",
    "NtQuerySecurityObject",
    "NtAccessCheck",

    /* ── 驱动 / 系统 ── */
    "NtLoadDriver",
    "NtSystemDebugControl",
    "NtRaiseHardError",
    "NtShutdownSystem",
    "NtSetSystemInformation",
    "NtPowerInformation",

    /* ── 符号链接 ── */
    "NtCreateSymbolicLinkObject",

    /* ── I/O 完成端口 ── */
    "NtCreateIoCompletion",
    "NtSetIoCompletion",
    "NtRemoveIoCompletion",

    /* ── 目录对象 ── */
    "NtCreateDirectoryObject",
    "NtOpenDirectoryObject",
    "NtQueryDirectoryObject",

    /* ── 进程/线程枚举 ── */
    "NtGetNextProcess",
    "NtGetNextThread",

    /* ── 注册表事务 ── */
    "NtCreateKeyTransacted",
    "NtOpenKeyTransacted",
    "NtCreateTransaction",
    "NtOpenTransaction",
    "NtCommitTransaction",
    "NtRollbackTransaction",

    /* ── VBS Enclave ── */
    "NtCreateEnclave",
    "NtInitializeEnclave",
    "NtCallEnclave",

    /* ── 其他 ── */
    "NtCreatePagingFile",
    "NtQuerySystemTime",
    "NtQueryPerformanceCounter",
    "NtSetThreadExecutionState",

    NULL
};

static std::unordered_set<ULONG> s_hookedSyscallNumbers;
static CRITICAL_SECTION g_csHookedSyscallNumbers;

/* 从 ntdll.dll 导出函数开头提取 syscall 号。
 * 常见模式：
 *   mov r10, rcx
 *   mov eax, imm32   <- syscall number
 *   ...
 * 返回 TRUE 表示成功解析。 */
static BOOL EtwSyscallResolveNumberFromExport(PVOID procAddr, ULONG* pNumber)
{
    if (procAddr == NULL || pNumber == NULL)
        return FALSE;

    PBYTE p = (PBYTE)procAddr;
    /* 跳过可能的 hotpatch / hook 跳转让：
     *   EB XX           jmp rel8 (hook detour)
     *   E9 XX XX XX XX  jmp rel32
     * 若遇到则跟随跳转（只跟一层，避免无限循环）。 */
    if (p[0] == 0xEB && p[1] >= 2 && p[1] <= 16) {
        p += 2 + (signed char)p[1];
    } else if (p[0] == 0xE9) {
        LONG rel = *(LONG*)(p + 1);
        p += 5 + rel;
    }

    /* 扫描前 32 字节寻找 mov eax, imm32 (B8 xx xx xx xx) */
    for (int i = 0; i < 32; i++) {
        if (p[i] == 0xB8) {
            *pNumber = *(ULONG*)(p + i + 1);
            return TRUE;
        }
    }
    return FALSE;
}

static void EtwSyscallBuildHookedSyscallSet()
{
    InitializeCriticalSection(&g_csHookedSyscallNumbers);
    s_hookedSyscallNumbers.clear();

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL)
        return;

    for (int i = 0; s_hookedNtdllExports[i] != NULL; i++) {
        FARPROC proc = GetProcAddress(hNtdll, s_hookedNtdllExports[i]);
        if (proc == NULL)
            continue;
        ULONG number = 0;
        if (EtwSyscallResolveNumberFromExport(proc, &number)) {
            s_hookedSyscallNumbers.insert(number);
        }
    }

    Log_AddLogSimple(QString("已解析 %1 个 ntdll.dll hook 系统调用号").arg((int)s_hookedSyscallNumbers.size()), LOG_SUCCESS);
}

static BOOL EtwSyscallIsHookedSyscall(ULONG syscallNumber)
{
    EnterCriticalSection(&g_csHookedSyscallNumbers);
    BOOL found = (s_hookedSyscallNumbers.find(syscallNumber) != s_hookedSyscallNumbers.end());
    LeaveCriticalSection(&g_csHookedSyscallNumbers);
    return found;
}

// keyword mask for network events
#define TI_KEYWORD_NETWORK_CONNECT    0x00000001
#define TI_KEYWORD_NETWORK_ACCEPT     0x00000002
#define TI_KEYWORD_NETWORK_UDP        0x00000004
#define TI_KEYWORD_NETWORK_DNS        0x00000008

/* 内核态 Common.h 中定义的 ETW 内存事件结构与 IOCTL 控制码。
 * 由于用户态项目未直接引用 Common.h，这里保持一份副本，
 * 必须与 KernelProtection\shared\Common.h 严格一致。 */
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81C, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x81C) << 2) | (0) = 0x00222070
#define IOCTL_BEHAVIOR_ETW_MEMORY_EVENT     0x00222070
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81D, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x81D) << 2) | (0) = 0x00222074
#define IOCTL_BEHAVIOR_ETW_NETWORK_EVENT    0x00222074
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81F, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x81F) << 2) | (0) = 0x0022207C
#define IOCTL_BEHAVIOR_ETW_SYSCALL_EVENT    0x0022207C
#pragma pack(push, 8)
typedef struct _ETW_MEMORY_EVENT_DATA {
    INT64   CallerPid;          // Process that initiated the operation
    INT64   TargetPid;          // Remote target process (0 if local)
    INT64   BaseAddress;        // Allocated/protected base address
    INT64   RegionSize;         // Region size in bytes
    ULONG   AllocationType;     // NtAllocateVirtualMemory AllocationType (MEM_COMMIT etc.)
    ULONG   Protection;         // PAGE_EXECUTE_* / PAGE_READWRITE etc.
    ULONG   EventId;            // ETW event ID: 1=AllocVM remote, 2=ProtectVM remote, etc.
    ULONG   PayloadSize;        // 实际捕获的内存内容字节数
    UCHAR   Payload[256];       // 远程写入/保护内存的前 256 字节（用于 shellcode 深度分析）
} ETW_MEMORY_EVENT_DATA, *PETW_MEMORY_EVENT_DATA;

typedef struct _ETW_NETWORK_EVENT_DATA {
    INT64   CallerPid;          // Process that initiated the network operation
    ULONG   EventId;            // 1=TCP connect, 2=TCP accept, 3=UDP send, 4=DNS query
    ULONG   Protocol;           // IPPROTO_TCP=6, IPPROTO_UDP=17
    ULONG   LocalPort;          // Host byte order
    ULONG   RemotePort;         // Host byte order
    UCHAR   RemoteAddress[16];  // IPv4/IPv6 address
    ULONG   RemoteAddressType;  // 0=IPv4, 1=IPv6
    ULONG   IsOutbound;         // TRUE=outbound, FALSE=inbound
    ULONG   ProcessNameOffset;  // Offset to process name in payload
    ULONG   PayloadSize;        // Valid payload bytes
    UCHAR   Payload[128];       // Process name + extra context
} ETW_NETWORK_EVENT_DATA, *PETW_NETWORK_EVENT_DATA;

// ETW syscall event for direct/indirect syscall detection
// (must match KernelProtection\shared\Common.h)
typedef struct _ETW_SYSCALL_EVENT_DATA {
    INT64   CallerPid;                  // Process that made the syscall
    INT64   ThreadId;                   // Thread ID
    INT64   ReturnAddress;              // RIP in user mode before entering kernel
    INT64   SyscallInstructionAddress;  // Address of syscall/sysenter instruction
    INT64   CallOriginAddress;          // Address that called/jmp'd to the syscall instruction (call stack top)
    ULONG   SyscallNumber;              // Windows syscall number
    ULONG   EventId;                    // ETW provider event ID
    ULONG   IsDirectSyscall;            // Return address module is not ntdll.dll (or unknown)
    ULONG   IsIndirectSyscall;          // Return address is in ntdll.dll but call origin is not
    ULONG   IsHookedSyscall;            // Syscall number is commonly hooked by R3 EDR/security software
    CHAR    ReturnAddressModule[64];    // Module name containing ReturnAddress (e.g., "ntdll.dll")
    CHAR    SyscallInstructionModule[64]; // Module name containing syscall instruction
    CHAR    ProcessName[64];            // Source process image name
} ETW_SYSCALL_EVENT_DATA, *PETW_SYSCALL_EVENT_DATA;
#pragma pack(pop)

// Ntdll reload / unhook detection event (kernel -> user)
// (must match KernelProtection\shared\Common.h)
#pragma pack(push, 8)
typedef struct _NTDLL_RELOAD_EVENT_DATA {
    INT64   ProcessId;                // Target process PID
    INT64   ParentProcessId;          // Parent process PID (0 if unknown)
    ULONG_PTR ImageBase;              // Base address of loaded ntdll.dll
    ULONG   ImageSize;                // Size of ntdll.dll image
    ULONG   LoadSequence;             // Load sequence number (increments per load)
    ULONG   Flags;                    // Reload flags: UNHOOK/REMAP/PATH
    ULONG   IsFromSystemPath;         // TRUE if loaded from system directory
    ULONG   IsHooked;                 // TRUE if ntdll appears to be hooked (based on heuristic)
    ULONG   ReloadCount;              // Number of times ntdll has been reloaded in this process
    INT64   EventSequence;            // 全局递增事件序列号
    CHAR    FullImagePath[MAX_PATH];  // Full path to loaded ntdll.dll
    CHAR    ProcessImagePath[MAX_PATH]; // Full path to the process executable
    CHAR    ProcessName[64];          // Process image name
} NTDLL_RELOAD_EVENT_DATA, *PNTDLL_RELOAD_EVENT_DATA;
#pragma pack(pop)

// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x820) << 2) | (0) = 0x00222080
#define IOCTL_BEHAVIOR_NTDLL_RELOAD_EVENT          0x00222080

// DCOM lateral movement detection (must match KernelProtection\shared\Common.h)
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x824, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x824) << 2) | (0) = 0x00222090
#define IOCTL_SET_DCOM_PROTECTION_ENABLED          0x00222090
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x825, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x825) << 2) | (0) = 0x00222094
#define IOCTL_BEHAVIOR_DCOM_EVENT                  0x00222094

// DCOM lateral movement detection event (R3 -> kernel)
// (must match KernelProtection\shared\Common.h)
#pragma pack(push, 8)
typedef struct _DCOM_EVENT_DATA {
    INT64   CallerPid;              // Process that initiated DCOM activation
    INT64   TargetPid;              // Target process spawned via DCOM (0 if unknown)
    INT64   ParentPid;              // Parent process PID
    ULONG   EventType;              // 1=MMC20.Application, 2=ShellWindows, 3=ShellBrowserWindow, 4=Excel.Application, 5=Outlook.Application, 6=Generic DCOM child
    ULONG   IsRemoteActivation;     // TRUE if DCOM activation came from remote machine
    CHAR    CallerProcessName[64];  // Process that initiated the DCOM call
    CHAR    TargetProcessName[64];  // Process spawned via DCOM
    CHAR    TargetProcessPath[MAX_PATH]; // Full path of target process
    CHAR    DcomObjectCLSID[64];   // DCOM object CLSID or ProgID (e.g. "MMC20.Application")
    CHAR    RemoteAddress[46];      // Remote IP address if remote activation (IPv4/IPv6 string)
} DCOM_EVENT_DATA, *PDCOM_EVENT_DATA;
#pragma pack(pop)

typedef enum _RULE_TYPE {
    RULE_TYPE_REG = 0,
    RULE_TYPE_FILE,
    RULE_TYPE_BEHAVIOR,
    RULE_TYPE_INJECTION_LOG,   // 驱动注入日志（Fire-and-Forget）
    RULE_TYPE_PROCESS_CHECK,   // 进程启动命令行/静态扫描检查
    RULE_TYPE_DLL_SCAN,        // 签名程序加载未签名 DLL 检查
    RULE_TYPE_NTDLL_RELOAD     // ntdll.dll 重载/Unhook 检测事件
} RULE_TYPE;

#define NTDLL_RELOAD_FLAG_UNHOOK     0x00000001
#define NTDLL_RELOAD_FLAG_REMAP      0x00000002
#define NTDLL_RELOAD_FLAG_PATH       0x00000004

// 勒索诱捕规则 RuleId 基址（用于区分诱捕规则与其它文件规则）
#define RANSOM_HONEYPOT_RULE_ID_BASE 0x70000000
// 每个诱捕路径产生 3 条规则（WRITE / DELETE / RENAME）
#define RANSOM_HONEYPOT_RULES_PER_PATH 3

// forward declarations
static DWORD WINAPI EtwTiConsumerThread(LPVOID lpParam);
static DWORD WINAPI EtwTiNetworkConsumerThread(LPVOID lpParam);
static DWORD WINAPI EtwSyscallConsumerThread(LPVOID lpParam);
static BOOL EtwTiStartConsumer();
static void EtwTiStopConsumer();
static BOOL EtwSyscallStartConsumer();
static void EtwSyscallStopConsumer();
static BOOL SendEtwMemoryEventToDriver(PETW_MEMORY_EVENT_DATA pEvent);
static BOOL SendEtwNetworkEventToDriver(PETW_NETWORK_EVENT_DATA pEvent);
static BOOL SendEtwSyscallEventToDriver(PETW_SYSCALL_EVENT_DATA pEvent);
static BOOL R0SendFileEventResponse(LONG responseStatus);
static DWORD WINAPI DcomMonitorThread(LPVOID lpParam);

// R0进程检查请求结构（驱动 -> 主程序）
typedef struct _R0_PROCESS_CHECK_REQUEST {
    INT64   pid;              // 新进程PID
    INT64   parentPid;        // 父进程PID
    CHAR    processPath[520]; // 进程路径
    CHAR    parentPath[520];  // 父进程路径
    CHAR    processName[64];  // 进程名
    CHAR    parentName[64];   // 父进程名
    CHAR    commandLine[1024];// 命令行参数
} R0_PROCESS_CHECK_REQUEST;

// R0进程检查响应结构（主程序 -> 驱动）
typedef struct _R0_PROCESS_CHECK_RESPONSE {
    INT64   pid;              // 进程PID
    INT     action;           // 0=允许, 1=终止, 2=挂起等待用户决策
    INT     shouldInject;     // 是否需要R3注入DLL（R3总防护开启时）
    CHAR    reason[256];      // 原因描述
} R0_PROCESS_CHECK_RESPONSE;

// R0白名单同步结构
typedef struct _R0_WHITELIST_ENTRY {
    INT64   pid;              // 进程PID（0表示通配）
    CHAR    pattern[256];     // 匹配模式（路径/名称）
    INT     type;             // 0=白名单(允许), 1=黑名单(阻止)
} R0_WHITELIST_ENTRY;

// 驱动规则检测响应（与 KernelProtection\shared\Common.h 保持一致）
#define RULE_ID_BEHAVIOR_ANALYSIS  0x7FFFFFFF
typedef struct _COMM_RULE_DETECTED {
    int             RuleId;
    int             RuleType;       // 0=REG, 1=FILE
    int             ProcessPid;
    CHAR            ProcessName[64];    // triggering process image name
    int             ParentPid;          // parent process PID
    CHAR            ParentName[64];     // parent process image name
    CHAR            ProcessPath[512];   // triggering process image full path
    CHAR            DllPath[512];       // DLL path (for RULE_TYPE_DLL_SCAN)
    CHAR            RuleDesc[128];      // matched rule description
    CHAR            Data[5120];
} COMM_RULE_DETECTED;

BOOL ScanProcessFile(string FilePath, BOOL NeedTerminateProcess = FALSE, HANDLE ProcessHandle = NULL, BOOL bSuppressThreatDialog = FALSE, std::string* pVirusName = nullptr);
BOOL ScanProcessFileWithProgress(std::string FilePath, BOOL NeedTerminateProcess,
	HANDLE ProcessHandle, BOOL* pUserRejected = nullptr, std::string* pVirusName = nullptr);
void R0SetDllInjectPath();  // 前向声明：向驱动发送 DLL 注入路径
void SendProcessCheckBlockingSettingToClient(); // 前向声明：同步“是否阻塞检查”开关到 Client
void SendUnsignedDllScanSettingToClient();      // 前向声明：同步内存防护（含 DLL 扫描）开关到 Client

// ── 驱动 IOCTL（与 KernelProtection\shared\Common.h 保持一致）──
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x814) << 2) | (0) = 0x00222050
#define IOCTL_SET_DLL_INJECT_PATH         0x00222050
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x800) << 2) | (0) = 0x00222000
#define IOCTL_PROTECT_PROCESS             0x00222000
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x813) << 2) | (0) = 0x0022204C
#define IOCTL_PREPARE_UNLOAD              0x0022204C
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x815) << 2) | (0) = 0x00222054
#define IOCTL_SET_R3_PROTECTION_ENABLED   0x00222054
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x816, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x816) << 2) | (0) = 0x00222058
#define IOCTL_SET_BEHAVIOR_DETECTION_ENABLED 0x00222058
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x817, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x817) << 2) | (0) = 0x0022205C
#define IOCTL_SET_PROCESS_PROTECTION_ENABLED 0x0022205C
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x818, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x818) << 2) | (0) = 0x00222060
#define IOCTL_SET_TRUSTED_PID             0x00222060
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x819, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x819) << 2) | (0) = 0x00222064
#define IOCTL_SYNC_WHITELIST_TO_DRIVER    0x00222064
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81B, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x81B) << 2) | (0) = 0x0022206C
#define IOCTL_SET_PROCESS_PPL             0x0022206C

// 进程签名 / PPL 设置输入结构（与 KernelProtection\shared\Common.h 保持一致）
typedef struct _PROCESS_SIGNATURE {
    ULONG Pid;
    UCHAR SignerType;      // 0=None, 1=ProtectedLight, 2=Protected
    UCHAR SignatureSigner; // 0=None, 1=Authenticode, 2=CodeGen, 3=Antimalware, ...
} PROCESS_SIGNATURE;

// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x81E, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x81E) << 2) | (0) = 0x00222078
#define IOCTL_SET_UNSIGNED_DLL_SCAN       0x00222078
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x822, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x822) << 2) | (0) = 0x00222088
#define IOCTL_SET_SILENT_MODE             0x00222088
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x823, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x823) << 2) | (0) = 0x0022208C
#define IOCTL_SET_MEMORY_PROTECTION_ENABLED 0x0022208C
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x802) << 2) | (0) = 0x00222008
#define IOCTL_RULE_DETECTED_REQUEST                0x00222008
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x803) << 2) | (0) = 0x0022200C
#define IOCTL_RULE_DETECTED_SEND_USER_RESPONSE     0x0022200C
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x804) << 2) | (0) = 0x00222010
#define IOCTL_ADD_FILE_RULE                        0x00222010
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x805) << 2) | (0) = 0x00222014
#define IOCTL_REMOVE_FILE_RULE                     0x00222014
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = ((0x22) << 16) | ((0) << 14) | ((0x807) << 2) | (0) = 0x0022201C
#define IOCTL_CLEAR_FILE_RULES                     0x0022201C
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82E, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_SILVERFOX_ENABLED                0x002220B8
// CTL_CODE(FILE_DEVICE_UNKNOWN, 0x82F, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_AVBYPASS_ENABLED                 0x002220BC

// ── 文件规则相关枚举与结构（与 KernelProtection\shared\Common.h 保持一致）──
typedef enum _FILE_OPERATION_MAIN {
    FILE_OP_WRITE = 0,
    FILE_OP_DELETE,
    FILE_OP_RENAME,
    FILE_OP_READ
} FILE_OPERATION_MAIN;

typedef enum _SECURITY_FLAG_MAIN {
    SEF_MAIN_ALL_BLOCKED = 0,
    SEF_MAIN_NOT_SYSTEM_BLOCKED,
    SEF_MAIN_UNSIGNED_BLOCKED,
    SEF_MAIN_PROCESS_START_BY_EXPLORER_BLOCKED,
    SEF_MAIN_ALL_ACCESS
} SECURITY_FLAG_MAIN;

#define MAIN_MAX_PATH_LEN       1024
#define MAIN_MAX_VALUE_NAME_LEN 256
#define MAIN_MAX_CTL_PACKET_LEN 16384  // 必须与内核 MAX_CTL_PACKET_LEN 一致，否则 IOCTL 因缓冲区不足全部失败

typedef struct _MAIN_RULE_FILE_DATA {
    ULONG           RuleId;
    FILE_OPERATION_MAIN Operation;
    CHAR            FullPath[MAIN_MAX_PATH_LEN];
    CHAR            FileName[MAIN_MAX_VALUE_NAME_LEN];
    CHAR            FileExt[32];
    SECURITY_FLAG_MAIN sef;
    CHAR            Description[128];
} MAIN_RULE_FILE_DATA;

// ── 注册表规则相关枚举与结构（与 KernelProtection\shared\Common.h 保持一致）──
typedef enum _REG_OPERATION_MAIN {
    REG_OP_SET = 0,
    REG_OP_DELETE,
    REG_OP_RENAME,
    REG_OP_READ
} REG_OPERATION_MAIN;

// REG_OPERATION / SECURITY_FLAG / RULE_REG_DATA 需与内核 Common.h 保持一致
// 数值必须与内核侧完全相同，仅名称不同以避免命名冲突
typedef enum _REG_OPERATION {
    REG_KERNEL_SET = 0,         // 对应 REG_OPERATION_SET
    REG_KERNEL_DELETE,          // 对应 REG_OPERATION_DELETE
    REG_KERNEL_RENAME,          // 对应 REG_OPERATION_RENAME
    REG_KERNEL_READ,            // 对应 REG_OPERATION_READ
    REG_KERNEL_SET_SECURITY     // 对应 REG_OPERATION_SET_SECURITY
} REG_OPERATION;

typedef enum _SECURITY_FLAG {
    SEF_ALL_BLOCKED = 0,
    SEF_NOT_SYSTEM_BLOCKED,
    SEF_UNSIGNED_BLOCKED,
    SEF_PROCESS_START_BY_EXPLORER_BLOCKED,
    SEF_ALL_ACCESS
} SECURITY_FLAG;

#define MAX_PATH_LEN      1024
#define MAX_VALUE_NAME_LEN 256
#define MAX_DETECT_VALUE_LEN 256

typedef struct _RULE_REG_DATA {
    ULONG           RuleId;
    REG_OPERATION   Operation;
    CHAR            FullPathWithOutValueName[MAX_PATH_LEN];
    CHAR            ValueName[MAX_VALUE_NAME_LEN];
    CHAR            DetectValue[MAX_DETECT_VALUE_LEN];
    BOOLEAN         IsNeedValueName;
    SECURITY_FLAG   sef;
    CHAR            Description[128];
} RULE_REG_DATA;

typedef struct _MAIN_RULE_REG_DATA {
    ULONG           RuleId;
    REG_OPERATION_MAIN Operation;
    CHAR            FullPathWithOutValueName[MAIN_MAX_PATH_LEN];
    CHAR            ValueName[MAIN_MAX_VALUE_NAME_LEN];
    CHAR            DetectValue[256];
    BOOLEAN         IsNeedValueName;
    SECURITY_FLAG_MAIN sef;
    CHAR            Description[128];
} MAIN_RULE_REG_DATA;

typedef struct _MAIN_COMM_CONTROL_PACKET {
    ULONG           Type;
    CHAR            Data[MAIN_MAX_CTL_PACKET_LEN];
} MAIN_COMM_CONTROL_PACKET;

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((LONG)0xC0000022L)
#endif

typedef struct _MAIN_COMM_RESPONSE_RESULT {
    LONG            nts;
    CHAR            Data[5120];
} MAIN_COMM_RESPONSE_RESULT;

typedef struct _MAIN_COMM_RESPONSE_PACKET {
    ULONG           Type;
    CHAR            Data[MAIN_MAX_CTL_PACKET_LEN];
} MAIN_COMM_RESPONSE_PACKET;

typedef struct _MAIN_RULE_FILE_DETECTED_RESPONSE {
    CHAR            FullPath[MAIN_MAX_PATH_LEN];
    CHAR            FileName[MAIN_MAX_VALUE_NAME_LEN];
    CHAR            FileExt[32];
    CHAR            ChangePath[4096];
    BOOLEAN         IsChangePathEnabled;
} MAIN_RULE_FILE_DETECTED_RESPONSE;

// R0 白名单同步数据结构（与 KernelProtection\shared\Common.h 保持一致）
#define R0_WHITELIST_MAX_ENTRIES  128
#define R0_WHITELIST_NAME_LEN     128
#define R0_WHITELIST_TYPE_ALLOW   0
#define R0_WHITELIST_TYPE_PREVENT 1

typedef struct _R0_WHITELIST_SYNC_ENTRY {
    INT64  Pid;
    CHAR   Name[R0_WHITELIST_NAME_LEN];
} R0_WHITELIST_SYNC_ENTRY;

typedef struct _R0_WHITELIST_SYNC_DATA {
    ULONG                   Type;
    ULONG                   Count;
    R0_WHITELIST_SYNC_ENTRY Entries[R0_WHITELIST_MAX_ENTRIES];
} R0_WHITELIST_SYNC_DATA;

// ═══════════════════════════════════════════════════════════════════════════
// R0白名单同步函数：将AutoAllowList/AutoPreventList同步到驱动
// ═══════════════════════════════════════════════════════════════════════════
static BOOL R0SendWhitelistToDriver(ULONG type, const PIDArrayWithIndex& list)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return FALSE;

    R0_WHITELIST_SYNC_DATA syncData = { 0 };
    syncData.Type = type;

    auto entries = list.GetAllEntries();
    syncData.Count = (ULONG)std::min(entries.size(), (size_t)R0_WHITELIST_MAX_ENTRIES);

    for (ULONG i = 0; i < syncData.Count; i++)
    {
        syncData.Entries[i].Pid = entries[i].pid;
        strncpy_s(syncData.Entries[i].Name, sizeof(syncData.Entries[i].Name),
                  entries[i].content.c_str(), _TRUNCATE);
    }

    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        g_hR0DriverDevice,
        IOCTL_SYNC_WHITELIST_TO_DRIVER,
        &syncData,
        (DWORD)(FIELD_OFFSET(R0_WHITELIST_SYNC_DATA, Entries) +
                syncData.Count * sizeof(R0_WHITELIST_SYNC_ENTRY)),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步白名单到驱动失败 (type=%1): %2")
                         .arg(type)
                         .arg(GetLastError()), LOG_ERROR);
        return FALSE;
    }

    Log_AddLogSimple(QString("同步白名单到驱动成功 (type=%1, count=%2)")
                    .arg(type)
                    .arg(syncData.Count), LOG_SUCCESS);
    return TRUE;
}

BOOL R0SyncWhitelistToDriver()
{
    BOOL result = TRUE;
    result &= R0SendWhitelistToDriver(R0_WHITELIST_TYPE_ALLOW, AutoAllowList);
    result &= R0SendWhitelistToDriver(R0_WHITELIST_TYPE_PREVENT, AutoPreventList);
    return result;
}

// 检查进程是否在白名单/黑名单中（R0调用）
// 返回: 1=允许, -1=阻止, 0=需要进一步检查
int R0CheckAutoList(INT64 pid, const char* processPath, const char* processName)
{
    string pathStr = processPath ? processPath : "";
    string nameStr = processName ? processName : "";

    // 检查自动允许列表
    if (AutoAllowList.Find((int)pid, nameStr) || AutoAllowList.Find((int)pid, pathStr))
        return 1;

    // 检查自动阻止列表
    if (AutoPreventList.Find((int)pid, nameStr) || AutoPreventList.Find((int)pid, pathStr))
        return -1;

    return 0; // 需要进一步检查
}

// R0进程扫描检查（借鉴RecvT中的进程扫描逻辑）
// 返回: RelActWarnType
RelActWarnType R0PerformProcessScan(INT64 pid, const char* processPath, HANDLE hProcess)
{
    string filePath = processPath ? processPath : "";

    if (filePath.empty() && hProcess)
    {
        filePath = Process_GetProcessPath(hProcess);
    }

    if (filePath.empty())
        return AW_Allow;

    // 扫描进程文件
    BOOL scanResult = ScanProcessFile(filePath, FALSE, hProcess);

    if (!scanResult)
    {
        // 扫描通过，允许
        return AW_Allow;
    }

    // 扫描发现问题，需要用户决策
    return AW_Prevent;
}

// 添加到自动允许/阻止列表并同步到R0
void R0AddToAutoList(INT64 pid, const char* title, BOOL isAllow)
{
    if (isAllow)
    {
        AutoAllowList.Add((int)pid, title ? title : "");
    }
    else
    {
        AutoPreventList.Add((int)pid, title ? title : "");
    }

    // 同步到驱动
    R0SyncWhitelistToDriver();
}

// 生成 64 位十六进制随机认证令牌
static BOOL GenerateClientAuthToken(char* outToken, DWORD len)
{
    if (len < 65 || !outToken)
        return FALSE;

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return FALSE;

    BYTE random[32] = {0};
    BOOL ok = CryptGenRandom(hProv, sizeof(random), random);
    CryptReleaseContext(hProv, 0);
    if (!ok)
        return FALSE;

    for (int i = 0; i < 32; i++)
    {
        sprintf_s(outToken + i * 2, len - (DWORD)i * 2, "%02x", random[i]);
    }
    outToken[64] = '\0';
    return TRUE;
}

// 通过 TCP 连接表查找 Client 端点：本地端口为 Client 临时端口，远程端口为 12347
static DWORD GetClientPidByTcpPort(USHORT remotePortNetwork)
{
    const DWORD localAddr = 0x0100007F; // 127.0.0.1 in network byte order as DWORD
    const USHORT serverPort = htons(12347);

    // 连接刚建立时 TCP 表可能尚未更新，允许短暂重试
    for (int attempt = 0; attempt < 5; attempt++)
    {
        DWORD dwSize = 0;
        DWORD dwResult = GetTcpTable2(NULL, &dwSize, FALSE);
        if (dwResult != ERROR_INSUFFICIENT_BUFFER)
        {
            Sleep(50);
            continue;
        }

        PMIB_TCPTABLE2 pTcpTable = (PMIB_TCPTABLE2)HeapAlloc(GetProcessHeap(), 0, dwSize);
        if (!pTcpTable)
        {
            Sleep(50);
            continue;
        }

        dwResult = GetTcpTable2(pTcpTable, &dwSize, FALSE);
        DWORD pid = 0;
        if (dwResult == NO_ERROR)
        {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++)
            {
                MIB_TCPROW2& row = pTcpTable->table[i];
                // 查找客户端端点：本地端口为 Client 临时端口，远程端口为服务端 12347
                if (row.dwLocalAddr == localAddr &&
                    row.dwLocalPort == remotePortNetwork &&
                    row.dwRemoteAddr == localAddr &&
                    row.dwRemotePort == serverPort)
                {
                    pid = row.dwOwningPid;
                    break;
                }
            }
        }
        HeapFree(GetProcessHeap(), 0, pTcpTable);

        if (pid != 0)
            return pid;

        Sleep(50);
    }
    return 0;
}

// 校验远端 PID 的进程镜像路径是否为主程序同目录下的 KernelProtectionClient
static BOOL ValidateClientProcessPath(DWORD pid)
{
    if (pid == 0 || g_wszClientExePath[0] == L'\0')
        return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess)
        return FALSE;

    wchar_t path[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    BOOL ok = QueryFullProcessImageNameW(hProcess, 0, path, &size);
    CloseHandle(hProcess);
    if (!ok)
        return FALSE;

    BOOL matched = (_wcsicmp(path, g_wszClientExePath) == 0);
    if (!matched)
    {
        Log_AddLogSimple(QString("Client 认证失败：路径不匹配 expected=%1, actual=%2")
                        .arg(QString::fromWCharArray(g_wszClientExePath))
                        .arg(QString::fromWCharArray(path)), LOG_ERROR);
    }
    return matched;
}

// 对刚 accept 的 Client socket 进行本地身份认证
static BOOL AuthenticateClientConnection(SOCKET clientSock, const sockaddr_in* clientAddr)
{
    UNREFERENCED_PARAMETER(clientSock);

    DWORD remotePid = GetClientPidByTcpPort(clientAddr->sin_port);
    if (remotePid == 0)
    {
        Log_AddLogSimple("Client 认证失败：无法从 TCP 表确定远程 PID", LOG_ERROR);
        return FALSE;
    }

    if (!ValidateClientProcessPath(remotePid))
    {
        Log_AddLogSimple(QString("Client PID %1 路径验证失败").arg((int)remotePid), LOG_ERROR);
        return FALSE;
    }

    g_dwAuthenticatedClientPid = remotePid;
    Log_AddLogSimple(QString("Client PID %1 认证成功").arg((int)remotePid), LOG_SUCCESS);
    return TRUE;
}

// 启动 KernelProtectionClient --traffic 模式
BOOL StartKernelProtectionClient()
{
    if (g_hClientProcess != NULL)
    {
        // 已启动，检查是否仍在运行
        DWORD exitCode;
        if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode == STILL_ACTIVE)
        {
            return TRUE; // 已经在运行
        }
        // 进程已退出，清理句柄
        CloseHandle(g_hClientProcess);
        g_hClientProcess = NULL;
        if (g_hClientThread)
        {
            CloseHandle(g_hClientThread);
            g_hClientThread = NULL;
        }
    }

    // 生成并保存本次 Client 连接的认证令牌
    if (!GenerateClientAuthToken(g_szExpectedClientAuthToken, sizeof(g_szExpectedClientAuthToken)))
    {
        Log_AddLogSimple("生成 Client 认证令牌失败", LOG_ERROR);
        return FALSE;
    }

    // 获取主程序目录与 Client 可执行文件完整路径
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t* lastSlash = wcsrchr(exePath, L'\\');
    if (lastSlash)
    {
        *(lastSlash + 1) = L'\0';
        wcscpy_s(g_wszMainExeDir, exePath);
        wcscpy_s(g_wszClientExePath, g_wszMainExeDir);
        wcscat_s(g_wszClientExePath, L"TianHongDefenseKernelProtectionClient.exe");
    }
    else
    {
        Log_AddLogSimple("获取主程序目录失败", LOG_ERROR);
        return FALSE;
    }

    // 检查文件是否存在
    if (_waccess(g_wszClientExePath, 0) != 0)
    {
        Log_AddLogSimple("找不到 KernelProtectionClient.exe，无法启动驱动防护模式", LOG_ERROR);
        return FALSE;
    }

    // 启动 Client --traffic 模式，附带认证令牌（创建控制台窗口但立即隐藏，保留 stdout 同时防止误关闭）
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // 隐藏窗口
    PROCESS_INFORMATION pi = { 0 };
    wchar_t cmdLine[MAX_PATH + 128];
    swprintf_s(cmdLine, MAX_PATH + 128, L"\"%s\" --traffic --auth-token %S", g_wszClientExePath, g_szExpectedClientAuthToken);

    BOOL success = CreateProcessW(
        g_wszClientExePath,
        cmdLine,
        NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE,  // 创建新控制台窗口，由 STARTUPINFO 控制为隐藏
        NULL, NULL,
        &si, &pi);

    if (success)
    {
        g_hClientProcess = pi.hProcess;
        g_hClientThread = pi.hThread;
        Log_AddLogSimple("KernelProtectionClient --traffic 已启动", LOG_SUCCESS);
        return TRUE;
    }
    else
    {
        Log_AddLogSimple(QString("启动 KernelProtectionClient 失败: %1").arg(GetLastError()), LOG_ERROR);
        return FALSE;
    }
}

// 通过 SCM 强制停止并删除驱动服务
static void ForceUnloadAndDeleteService()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
    {
        Log_AddLogSimple(QString("OpenSCManager 失败: %1").arg(GetLastError()), LOG_ERROR);
        return;
    }

    SC_HANDLE hService = OpenServiceW(hSCM, THSD_SERVICE_NAME_W,
                                      SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hService == NULL)
    {
        /* 服务不存在（例如启动时因找不到 .sys 文件未安装成功）属于正常情况，
         * 静默处理，不算卸载失败。仅对其他错误打印日志。 */
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_DOES_NOT_EXIST)
        {
            Log_AddLogSimple(QString("OpenService TianHongHips 失败: %1").arg(err), LOG_ERROR);
        }
        CloseServiceHandle(hSCM);
        return;
    }

    // 尝试停止服务（对驱动服务等价于卸载驱动）
    SERVICE_STATUS status;
    if (ControlService(hService, SERVICE_CONTROL_STOP, &status))
    {
        Log_AddLogSimple("SCM 已发送停止服务请求", LOG_INFO);
        // 等待服务实际停止（最多 5 秒）
        for (int i = 0; i < 50; i++)
        {
            Sleep(100);
            if (QueryServiceStatus(hService, &status) &&
                status.dwCurrentState == SERVICE_STOPPED)
            {
                break;
            }
        }
    }

    // 删除服务条目，避免残留导致下次启动冲突
    if (DeleteService(hService))
    {
        Log_AddLogSimple("已删除 TianHongHips 服务条目", LOG_SUCCESS);
    }
    else
    {
        Log_AddLogSimple(QString("DeleteService 失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    CloseServiceHandle(hService);

    // 同样停止并删除磁盘过滤驱动服务（TianHongHips.Disk）
    SC_HANDLE hDiskService = OpenServiceW(hSCM, THSD_DISK_SERVICE_NAME_W,
                                          SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hDiskService != NULL)
    {
        SERVICE_STATUS diskStatus;
        if (ControlService(hDiskService, SERVICE_CONTROL_STOP, &diskStatus))
        {
            Log_AddLogSimple("SCM 已发送停止 TianHongHips.Disk 服务请求", LOG_INFO);
            for (int i = 0; i < 50; i++)
            {
                Sleep(100);
                if (QueryServiceStatus(hDiskService, &diskStatus) &&
                    diskStatus.dwCurrentState == SERVICE_STOPPED)
                {
                    break;
                }
            }
        }

        if (DeleteService(hDiskService))
        {
            Log_AddLogSimple("已删除 TianHongHips.Disk 服务条目", LOG_SUCCESS);
        }
        else
        {
            Log_AddLogSimple(QString("DeleteService TianHongHips.Disk 失败: %1").arg(GetLastError()), LOG_ERROR);
        }

        CloseServiceHandle(hDiskService);
    }

    // 同样停止并删除网络过滤驱动服务（TianHongHips.Network）
    SC_HANDLE hNetService = OpenServiceW(hSCM, THSD_NETWORK_SERVICE_NAME_W,
                                         SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (hNetService != NULL)
    {
        SERVICE_STATUS netStatus;
        if (ControlService(hNetService, SERVICE_CONTROL_STOP, &netStatus))
        {
            Log_AddLogSimple("SCM 已发送停止 TianHongHips.Network 服务请求", LOG_INFO);
            for (int i = 0; i < 50; i++)
            {
                Sleep(100);
                if (QueryServiceStatus(hNetService, &netStatus) &&
                    netStatus.dwCurrentState == SERVICE_STOPPED)
                {
                    break;
                }
            }
        }

        if (DeleteService(hNetService))
        {
            Log_AddLogSimple("已删除 TianHongHips.Network 服务条目", LOG_SUCCESS);
        }
        else
        {
            Log_AddLogSimple(QString("DeleteService TianHongHips.Network 失败: %1").arg(GetLastError()), LOG_ERROR);
        }

        CloseServiceHandle(hNetService);
    }

    CloseServiceHandle(hSCM);
}

// 停止 KernelProtectionClient
void StopKernelProtectionClient()
{
    /* 先关闭 R0 驱动设备句柄，释放对主驱动的引用。
     * 若该句柄保持打开，Client 的 CleanupAndExit 停止主驱动服务时，
     * 驱动对象引用计数无法降到 0，主驱动无法卸载（磁盘/网络驱动无此句柄，故可正常卸载）。 */
    if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_hR0DriverDevice);
        g_hR0DriverDevice = INVALID_HANDLE_VALUE;
        Log_AddLogSimple("R0 驱动设备句柄已关闭（释放主驱动引用）", LOG_INFO);
    }

    if (g_hClientProcess != NULL)
    {
        // 先尝试通过 socket 通知退出
        if (g_bClientConnected && Tran_ClientSocket != INVALID_SOCKET)
        {
            Packet quitPkt = {};
            quitPkt.PacketTyped = PTClientMessage;
            strcpy_s(quitPkt.InfoTitle, sizeof(quitPkt.InfoTitle), "QUIT");
            if (send(Tran_ClientSocket, (const char*)&quitPkt, sizeof(Packet), 0) == SOCKET_ERROR)
            {
                Log_AddLogSimple("通知 Client 退出时 send 失败", LOG_ERROR);
            }
            Sleep(1000);  // 等待 Client 执行清理（包括卸载驱动）
            closesocket(Tran_ClientSocket);
            Tran_ClientSocket = INVALID_SOCKET;
            g_bClientConnected = FALSE;
        }

        // 等待进程退出（最多5秒）
        WaitForSingleObject(g_hClientProcess, 5000);

        // 如果还在运行，强制终止
        DWORD exitCode;
        if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode == STILL_ACTIVE)
        {
            TerminateProcess(g_hClientProcess, 0);
            Sleep(500);
        }

        CloseHandle(g_hClientProcess);
        g_hClientProcess = NULL;

        if (g_hClientThread)
        {
            CloseHandle(g_hClientThread);
            g_hClientThread = NULL;
        }

        Log_AddLogSimple("KernelProtectionClient 已停止", LOG_INFO);
    }

    ForceUnloadAndDeleteService();
}

// ── 驱动初始化参数同步（R0 启用时调用）──
// 向驱动同步工作路径、R3 防护开关、行为检测开关、R0 进程检查开关及受信任 PID。
void R0SetDllInjectPath()
{
    /* 打开驱动设备 */
    HANDLE hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE)
    {
        Log_AddLogSimple(QString("无法打开驱动设备进行初始化同步: %1 (将在Client就绪后重试)").arg(GetLastError()), LOG_WARN);
        return;
    }

    /* 获取 DLL 基础路径（不含后缀，驱动会根据进程位数拼接 32/64） */
    wstring dllBasePath = Process_GetCurrentProcessPathWithDll();
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_DLL_INJECT_PATH,
        (LPVOID)dllBasePath.c_str(),
        (DWORD)((dllBasePath.length() + 1) * sizeof(WCHAR)),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步工作路径到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步 R3 DLL 防护开关状态到驱动。 */
    BOOL bR3Enabled = (pProtectionSettingPage && pProtectionSettingPage->pDllProtectionSwitch &&
                       pProtectionSettingPage->pDllProtectionSwitch->getIsToggled());
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_R3_PROTECTION_ENABLED,
        &bR3Enabled,
        sizeof(bR3Enabled),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步R3 DLL防护状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步行为检测开关状态到驱动：默认禁用，需用户显式开启才进行评估。 */
    BOOL bBehaviorEnabled = (pProtectionSettingPage && pProtectionSettingPage->pBehaviorDetectionSwitch &&
                             pProtectionSettingPage->pBehaviorDetectionSwitch->getIsToggled());
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_BEHAVIOR_DETECTION_ENABLED,
        &bBehaviorEnabled,
        sizeof(bBehaviorEnabled),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步行为检测状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步静默模式状态到驱动：静默模式下行为分析直接阻止，不弹窗询问用户。 */
    BOOL bSilentModeEnabled = g_bSilentModeEnabled ? TRUE : FALSE;
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_SILENT_MODE,
        &bSilentModeEnabled,
        sizeof(bSilentModeEnabled),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步静默模式状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步内存防护开关状态到驱动：控制句柄剥离/注入拦截。 */
    BOOL bMemoryProtectionEnabled = (pProtectionSettingPage && pProtectionSettingPage->pMemorySwitch &&
                                     pProtectionSettingPage->pMemorySwitch->getIsToggled());
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_MEMORY_PROTECTION_ENABLED,
        &bMemoryProtectionEnabled,
        sizeof(bMemoryProtectionEnabled),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步内存防护状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步 R0 独立进程检查开关状态到驱动：由进程防护开关（pProcessSwitch）控制。 */
    BOOL bProcessProtectionEnabled = (pProtectionSettingPage && pProtectionSettingPage->pProcessSwitch &&
                                      pProtectionSettingPage->pProcessSwitch->getIsToggled());
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_PROCESS_PROTECTION_ENABLED,
        &bProcessProtectionEnabled,
        sizeof(bProcessProtectionEnabled),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步R0进程检查状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步 DCOM 防护开关状态到驱动：控制 DCOM 横向移动检测。 */
    BOOL bDcomEnabled = (pProtectionSettingPage && pProtectionSettingPage->pDcomProtectionSwitch &&
                         pProtectionSettingPage->pDcomProtectionSwitch->getIsToggled());
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_DCOM_PROTECTION_ENABLED,
        &bDcomEnabled,
        sizeof(bDcomEnabled),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步DCOM防护状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步 SilverFox 检测开关状态到驱动。 */
    BOOL bSilverFoxEnabled = TRUE;  /* 默认启用 */
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_SILVERFOX_ENABLED,
        &bSilverFoxEnabled,
        sizeof(bSilverFoxEnabled),
        NULL, 0,
        &bytesReturned, NULL);
    if (!ok)
    {
        Log_AddLogSimple(QString("同步SilverFox检测状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步 AVBypass 检测开关状态到驱动。 */
    BOOL bAVBypassEnabled = TRUE;  /* 默认启用 */
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_AVBYPASS_ENABLED,
        &bAVBypassEnabled,
        sizeof(bAVBypassEnabled),
        NULL, 0,
        &bytesReturned, NULL);
    if (!ok)
    {
        Log_AddLogSimple(QString("同步AVBypass检测状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 同步受信任主程序 PID 到驱动：防止 R0 注入检测把主程序自己的 DLL 注入行为误报为攻击。 */
    DWORD currentPid = GetCurrentProcessId();
    ok = DeviceIoControl(
        hDevice,
        IOCTL_SET_TRUSTED_PID,
        &currentPid,
        sizeof(currentPid),
        NULL, 0,
        &bytesReturned, NULL);

    if (!ok)
    {
        Log_AddLogSimple(QString("同步受信任主程序 PID 到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
    }

    /* 将主程序自身 PID 注册到驱动保护列表（g_ProtectedPids），
     * 使 OB 回调对外部进程剥离高危权限，防止外部进程终止/注入主程序。 */
    {
        MAIN_COMM_CONTROL_PACKET protectPacket = { 0 };
        char pidBuf[32];
        sprintf_s(pidBuf, "%lu", currentPid);
        protectPacket.Type = 0;
        strncpy_s(protectPacket.Data, pidBuf, _TRUNCATE);

        DWORD br = 0;
        BOOL protectOk = DeviceIoControl(
            hDevice,
            IOCTL_PROTECT_PROCESS,
            &protectPacket, sizeof(protectPacket),
            NULL, 0,
            &br, NULL);

        if (!protectOk)
        {
            Log_AddLogSimple(QString("注册主程序 PID 到驱动保护列表失败: %1").arg(GetLastError()), LOG_WARN);
        }
    }

    /* 所有同步成功：输出一条规范化初始化事件日志。 */
    Log_AddLogSimple(QString("驱动初始化同步完成：R3=%1 行为检测=%2 内存防护=%3 R0进程检查=%4 受信任PID=%5")
                    .arg(bR3Enabled ? "启用" : "禁用")
                    .arg(bBehaviorEnabled ? "启用" : "禁用")
                    .arg(bMemoryProtectionEnabled ? "启用" : "禁用")
                    .arg(bProcessProtectionEnabled ? "启用" : "禁用")
                    .arg(currentPid), LOG_SUCCESS);

    CloseHandle(hDevice);

    /* 同步“是否阻塞检查”开关状态到 Client（如果 Client 已连接）。
     * 该开关由 pIsFullScanSwitch 控制，决定 R0 进程检查是阻塞等待扫描结果
     * 还是非阻塞仅告警。 */
    SendProcessCheckBlockingSettingToClient();
}

// ═══════════════════════════════════════════════════════════════════════════
// ETW Threat-Intelligence Consumer 实现
// ═══════════════════════════════════════════════════════════════════════════

static ULONGLONG EtwTiGetTickCountMs()
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (ULONGLONG)(count.QuadPart * 1000ULL / freq.QuadPart);
}

/* 判断进程短名是否为已知系统进程，避免把系统组件正常内存操作发给内核 */
static BOOL EtwTiIsKnownSystemProcess(DWORD pid)
{
    static const WCHAR* s_knownNames[] = {
        L"System", L"Registry",
        L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe",
        L"dwm.exe", L"fontdrvhost.exe", L"conhost.exe", L"dllhost.exe",
        L"audiodg.exe", L"spoolsv.exe", L"taskhostw.exe", L"taskhost.exe",
        L"taskeng.exe", L"runtimebroker.exe", L"backgroundtaskhost.exe",
        L"wmiprvse.exe", L"searchindexer.exe", L"msmpeng.exe",
        L"SearchProtocolHost.exe", L"SearchFilterHost.exe", L"SearchApp.exe",
        L"SearchHost.exe", L"ShellExperienceHost.exe", L"StartMenuExperienceHost.exe",
        L"TextInputHost.exe", L"LockApp.exe", L"ApplicationFrameHost.exe",
        L"SystemSettings.exe", L"SecurityHealthService.exe", L"sihost.exe",
        L"ctfmon.exe", L"cortana.exe", L"tiworker.exe", L"trustedinstaller.exe",
        L"usocoreworker.exe", L"usoclient.exe", L"waasmedic.exe", L"mousocoreworker.exe",
        L"compattelrunner.exe", L"updateassistant.exe",
        L"WindowsUpdateElevatedInstaller.exe",
        L"taskbar.exe", L"widgetservice.exe",
        NULL
    };

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL)
        return FALSE;

    WCHAR imageName[MAX_PATH] = {0};
    DWORD len = MAX_PATH;
    BOOL isSystem = FALSE;
    if (QueryFullProcessImageNameW(hProcess, 0, imageName, &len)) {
        LPCWSTR fileName = wcsrchr(imageName, L'\\');
        if (fileName) fileName++;
        else fileName = imageName;

        for (int i = 0; s_knownNames[i]; i++) {
            if (_wcsicmp(fileName, s_knownNames[i]) == 0) {
                isSystem = TRUE;
                break;
            }
        }

        /* 路径在 Windows\System32 / SysWOW64 / WinSxS 下的进程也视为系统进程 */
        if (!isSystem) {
            _wcslwr(imageName);
            if (wcsstr(imageName, L"\\windows\\system32\\") ||
                wcsstr(imageName, L"\\windows\\syswow64\\") ||
                wcsstr(imageName, L"\\windows\\winsxs\\") ||
                wcsstr(imageName, L"\\windows\\explorer.exe")) {
                isSystem = TRUE;
            }
        }
    }
    CloseHandle(hProcess);
    return isSystem;
}

static void EtwTiCleanupDedup()
{
    EnterCriticalSection(&g_csEtwTiDedup);
    ULONGLONG now = EtwTiGetTickCountMs();
    for (auto it = g_EtwTiDedupMap.begin(); it != g_EtwTiDedupMap.end(); ) {
        if (now - it->second > ETW_TI_DEDUP_WINDOW_MS)
            it = g_EtwTiDedupMap.erase(it);
        else
            ++it;
    }

    /* 生产级兜底：map 超过上限时直接清空，防止极端情况下内存无限增长 */
    if (g_EtwTiDedupMap.size() > ETW_TI_DEDUP_MAX_ENTRIES) {
        g_EtwTiDedupMap.clear();
    }
    LeaveCriticalSection(&g_csEtwTiDedup);
}

static void EtwTiCleanupRateLimit()
{
    EnterCriticalSection(&g_csEtwTiRateLimit);
    ULONGLONG now = EtwTiGetTickCountMs();
    for (auto it = g_EtwTiRateLimitMap.begin(); it != g_EtwTiRateLimitMap.end(); ) {
        if (now - it->second.windowStart > ETW_TI_RATE_LIMIT_WINDOW_MS)
            it = g_EtwTiRateLimitMap.erase(it);
        else
            ++it;
    }

    if (g_EtwTiRateLimitMap.size() > ETW_TI_RATE_LIMIT_MAX_ENTRIES) {
        g_EtwTiRateLimitMap.clear();
    }
    LeaveCriticalSection(&g_csEtwTiRateLimit);
}

static BOOL EtwTiShouldForward(INT64 callerPid, INT64 targetPid, INT64 baseAddress, ULONG eventId)
{
    EtwTiDedupKey key = { callerPid, targetPid, baseAddress, eventId, 0 };
    ULONGLONG now = EtwTiGetTickCountMs();
    BOOL forward = TRUE;
    static volatile LONG s_dedupCallCount = 0;

    /* 每 1000 次去重检查清理一次过期条目，防止 map 无限增长 */
    if ((InterlockedIncrement(&s_dedupCallCount) % 1000) == 0) {
        EtwTiCleanupDedup();
    }

    EnterCriticalSection(&g_csEtwTiDedup);
    auto it = g_EtwTiDedupMap.find(key);
    if (it != g_EtwTiDedupMap.end()) {
        if (now - it->second <= ETW_TI_DEDUP_WINDOW_MS)
            forward = FALSE;
        else
            it->second = now;
    } else {
        g_EtwTiDedupMap[key] = now;
    }
    LeaveCriticalSection(&g_csEtwTiDedup);

    return forward;
}

/* 速率限制：单个 (caller, target) 在 1 秒内超过阈值则丢弃，防止 IOCTL 风暴 */
static BOOL EtwTiShouldThrottle(INT64 callerPid, INT64 targetPid)
{
    EtwTiRateKey key = { callerPid, targetPid };
    ULONGLONG now = EtwTiGetTickCountMs();
    BOOL throttle = FALSE;
    static volatile LONG s_rateCleanupCount = 0;

    EnterCriticalSection(&g_csEtwTiRateLimit);

    /* 每 1000 次检查，或 map 超过上限时清理过期条目 */
    if ((InterlockedIncrement(&s_rateCleanupCount) % 1000) == 0 ||
        g_EtwTiRateLimitMap.size() > ETW_TI_RATE_LIMIT_MAX_ENTRIES) {
        ULONGLONG nowCleanup = EtwTiGetTickCountMs();
        for (auto it = g_EtwTiRateLimitMap.begin(); it != g_EtwTiRateLimitMap.end(); ) {
            if (nowCleanup - it->second.windowStart > ETW_TI_RATE_LIMIT_WINDOW_MS)
                it = g_EtwTiRateLimitMap.erase(it);
            else
                ++it;
        }
        if (g_EtwTiRateLimitMap.size() > ETW_TI_RATE_LIMIT_MAX_ENTRIES) {
            g_EtwTiRateLimitMap.clear();
        }
    }
    auto it = g_EtwTiRateLimitMap.find(key);
    if (it != g_EtwTiRateLimitMap.end()) {
        if (now - it->second.windowStart <= ETW_TI_RATE_LIMIT_WINDOW_MS) {
            if (it->second.count >= ETW_TI_RATE_LIMIT_MAX_EVENTS) {
                throttle = TRUE;
            } else {
                it->second.count++;
            }
        } else {
            it->second.windowStart = now;
            it->second.count = 1;
        }
    } else {
        EtwTiRateValue val = { now, 1 };
        g_EtwTiRateLimitMap[key] = val;
    }
    LeaveCriticalSection(&g_csEtwTiRateLimit);

    return throttle;
}

static BOOL SendEtwMemoryEventToDriver(PETW_MEMORY_EVENT_DATA pEvent)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE) {
        /* 驱动尚未打开时直接丢弃；驱动启用后再启动 Consumer 可避免此情况 */
        return FALSE;
    }

    /* 跳过系统进程发起的操作，减少正常系统行为产生的噪音 */
    if (EtwTiIsKnownSystemProcess((DWORD)pEvent->CallerPid))
        return TRUE;

    /* 跳过对系统进程的常见合法操作（如调试器、系统组件） */
    if (pEvent->TargetPid != 0 && EtwTiIsKnownSystemProcess((DWORD)pEvent->TargetPid))
        return TRUE;

    /* 去重：同一 (caller, target, address, event) 在窗口期内只发一次 */
    if (!EtwTiShouldForward(pEvent->CallerPid, pEvent->TargetPid, pEvent->BaseAddress, pEvent->EventId))
        return TRUE;

    /* 速率限制：防止单个进程对产生事件风暴 */
    if (EtwTiShouldThrottle(pEvent->CallerPid, pEvent->TargetPid))
        return TRUE;

    DWORD bytesReturned = 0;
    return DeviceIoControl(
        g_hR0DriverDevice,
        IOCTL_BEHAVIOR_ETW_MEMORY_EVENT,
        pEvent,
        sizeof(ETW_MEMORY_EVENT_DATA),
        NULL, 0,
        &bytesReturned, NULL);
}

// ═══════════════════════════════════════════════════════════════════════════
// ETW Network Threat-Intelligence Consumer - 网络事件辅助函数
// ═══════════════════════════════════════════════════════════════════════════

static ULONGLONG EtwTiNetworkGetTickCountMs()
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (ULONGLONG)(count.QuadPart * 1000ULL / freq.QuadPart);
}

static void EtwTiNetworkCleanupDedup()
{
    EnterCriticalSection(&g_csEtwTiNetDedup);
    ULONGLONG now = EtwTiNetworkGetTickCountMs();
    for (auto it = g_EtwTiNetDedupMap.begin(); it != g_EtwTiNetDedupMap.end(); ) {
        if (now - it->second > ETW_TI_NET_DEDUP_WINDOW_MS)
            it = g_EtwTiNetDedupMap.erase(it);
        else
            ++it;
    }

    if (g_EtwTiNetDedupMap.size() > ETW_TI_NET_DEDUP_MAX_ENTRIES) {
        g_EtwTiNetDedupMap.clear();
    }
    LeaveCriticalSection(&g_csEtwTiNetDedup);
}

static void EtwTiNetworkCleanupRateLimit()
{
    EnterCriticalSection(&g_csEtwTiNetRateLimit);
    ULONGLONG now = EtwTiNetworkGetTickCountMs();
    for (auto it = g_EtwTiNetRateLimitMap.begin(); it != g_EtwTiNetRateLimitMap.end(); ) {
        if (now - it->second.windowStart > ETW_TI_NET_RATE_LIMIT_WINDOW_MS)
            it = g_EtwTiNetRateLimitMap.erase(it);
        else
            ++it;
    }

    if (g_EtwTiNetRateLimitMap.size() > ETW_TI_NET_RATE_LIMIT_MAX_ENTRIES) {
        g_EtwTiNetRateLimitMap.clear();
    }
    LeaveCriticalSection(&g_csEtwTiNetRateLimit);
}

static BOOL EtwTiNetworkShouldForward(INT64 callerPid, ULONG remoteAddrHash, ULONG remotePort, ULONG eventId)
{
    EtwTiNetDedupKey key = { callerPid, remoteAddrHash, remotePort, eventId };
    ULONGLONG now = EtwTiNetworkGetTickCountMs();
    BOOL forward = TRUE;
    static volatile LONG s_netDedupCallCount = 0;

    if ((InterlockedIncrement(&s_netDedupCallCount) % 1000) == 0) {
        EtwTiNetworkCleanupDedup();
    }

    EnterCriticalSection(&g_csEtwTiNetDedup);
    auto it = g_EtwTiNetDedupMap.find(key);
    if (it != g_EtwTiNetDedupMap.end()) {
        if (now - it->second <= ETW_TI_NET_DEDUP_WINDOW_MS)
            forward = FALSE;
        else
            it->second = now;
    } else {
        g_EtwTiNetDedupMap[key] = now;
    }
    LeaveCriticalSection(&g_csEtwTiNetDedup);

    return forward;
}

static BOOL EtwTiNetworkShouldThrottle(INT64 callerPid)
{
    EtwTiNetRateKey key = { callerPid };
    ULONGLONG now = EtwTiNetworkGetTickCountMs();
    BOOL throttle = FALSE;
    static volatile LONG s_netRateCleanupCount = 0;

    EnterCriticalSection(&g_csEtwTiNetRateLimit);

    if ((InterlockedIncrement(&s_netRateCleanupCount) % 1000) == 0 ||
        g_EtwTiNetRateLimitMap.size() > ETW_TI_NET_RATE_LIMIT_MAX_ENTRIES) {
        ULONGLONG nowCleanup = EtwTiNetworkGetTickCountMs();
        for (auto it = g_EtwTiNetRateLimitMap.begin(); it != g_EtwTiNetRateLimitMap.end(); ) {
            if (nowCleanup - it->second.windowStart > ETW_TI_NET_RATE_LIMIT_WINDOW_MS)
                it = g_EtwTiNetRateLimitMap.erase(it);
            else
                ++it;
        }
        if (g_EtwTiNetRateLimitMap.size() > ETW_TI_NET_RATE_LIMIT_MAX_ENTRIES) {
            g_EtwTiNetRateLimitMap.clear();
        }
    }
    auto it = g_EtwTiNetRateLimitMap.find(key);
    if (it != g_EtwTiNetRateLimitMap.end()) {
        if (now - it->second.windowStart <= ETW_TI_NET_RATE_LIMIT_WINDOW_MS) {
            if (it->second.count >= ETW_TI_NET_RATE_LIMIT_MAX_EVENTS) {
                throttle = TRUE;
            } else {
                it->second.count++;
            }
        } else {
            it->second.windowStart = now;
            it->second.count = 1;
        }
    } else {
        EtwTiNetRateValue val = { now, 1 };
        g_EtwTiNetRateLimitMap[key] = val;
    }
    LeaveCriticalSection(&g_csEtwTiNetRateLimit);

    return throttle;
}

static BOOL SendEtwNetworkEventToDriver(PETW_NETWORK_EVENT_DATA pEvent)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    /* 跳过系统进程发起的网络操作 */
    if (EtwTiIsKnownSystemProcess((DWORD)pEvent->CallerPid))
        return TRUE;

    ULONG remoteAddrHash = 0;
    if (pEvent->RemoteAddressType == 0) {
        /* IPv4: 取前 4 字节 */
        memcpy(&remoteAddrHash, pEvent->RemoteAddress, 4);
    } else {
        /* IPv6: 简单哈希 */
        for (ULONG i = 0; i < 16; i++)
            remoteAddrHash ^= (ULONG)pEvent->RemoteAddress[i] << ((i % 4) * 8);
    }

    /* 去重 */
    if (!EtwTiNetworkShouldForward(pEvent->CallerPid, remoteAddrHash, pEvent->RemotePort, pEvent->EventId))
        return TRUE;

    /* 速率限制 */
    if (EtwTiNetworkShouldThrottle(pEvent->CallerPid))
        return TRUE;

    DWORD bytesReturned = 0;
    return DeviceIoControl(
        g_hR0DriverDevice,
        IOCTL_BEHAVIOR_ETW_NETWORK_EVENT,
        pEvent,
        sizeof(ETW_NETWORK_EVENT_DATA),
        NULL, 0,
        &bytesReturned, NULL);
}

// ═══════════════════════════════════════════════════════════════════════════
// ETW Network Threat-Intelligence Consumer - 事件解析与消费线程
// ═══════════════════════════════════════════════════════════════════════════

static BOOL EtwTiGetNetworkEventPropertyInt64(PEVENT_RECORD pRecord, LPCWSTR propName, INT64* pValue)
{
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propName;
    desc.ArrayIndex = 0;
    ULONG size = sizeof(INT64);
    return (TdhGetProperty(pRecord, 0, NULL, 1, &desc, size, (PBYTE)pValue) == ERROR_SUCCESS);
}

static BOOL EtwTiGetNetworkEventPropertyUlong(PEVENT_RECORD pRecord, LPCWSTR propName, ULONG* pValue)
{
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propName;
    desc.ArrayIndex = 0;
    ULONG size = sizeof(ULONG);
    return (TdhGetProperty(pRecord, 0, NULL, 1, &desc, size, (PBYTE)pValue) == ERROR_SUCCESS);
}

static VOID WINAPI EtwTiNetworkEventRecordCallback(PEVENT_RECORD pRecord)
{
    if (pRecord == NULL || pRecord->UserData == NULL)
        return;

    USHORT eventId = pRecord->EventHeader.EventDescriptor.Id;
    /* TCP/IP provider event IDs: 1=TCP Connect, 2=TCP Accept, 3=UDP Send, 4=DNS Query */
    if (eventId != 1 && eventId != 2 && eventId != 3 && eventId != 4)
        return;

    ETW_NETWORK_EVENT_DATA ev = {0};
    ev.EventId = eventId;

    /* 解析网络事件字段 */
    EtwTiGetNetworkEventPropertyInt64(pRecord, L"ProcessId", (INT64*)&ev.CallerPid);
    EtwTiGetNetworkEventPropertyUlong(pRecord, L"Protocol", &ev.Protocol);
    EtwTiGetNetworkEventPropertyUlong(pRecord, L"LocalPort", &ev.LocalPort);
    EtwTiGetNetworkEventPropertyUlong(pRecord, L"RemotePort", &ev.RemotePort);

    INT64 remoteAddr = 0;
    if (EtwTiGetNetworkEventPropertyInt64(pRecord, L"RemoteAddress", &remoteAddr)) {
        ev.RemoteAddressType = 0; /* IPv4 */
        memcpy(ev.RemoteAddress, &remoteAddr, 4);
    }

    ULONG isOutbound = 0;
    EtwTiGetNetworkEventPropertyUlong(pRecord, L"IsOutbound", &isOutbound);
    ev.IsOutbound = isOutbound;

    /* 获取进程名 */
    WCHAR processName[MAX_PATH] = {0};
    DWORD pid = (DWORD)ev.CallerPid;
    if (pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess != NULL) {
            DWORD len = MAX_PATH;
            if (QueryFullProcessImageNameW(hProcess, 0, processName, &len)) {
                LPCWSTR fileName = wcsrchr(processName, L'\\');
                if (fileName) fileName++;
                else fileName = processName;

                int nameLen = (int)wcslen(fileName) * sizeof(WCHAR);
                if (nameLen > (int)sizeof(ev.Payload) - 1)
                    nameLen = sizeof(ev.Payload) - 1;
                memcpy(ev.Payload, fileName, nameLen);
                ev.PayloadSize = nameLen;
            }
            CloseHandle(hProcess);
        }
    }

    SendEtwNetworkEventToDriver(&ev);
}

static DWORD WINAPI EtwTiNetworkConsumerThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    EVENT_TRACE_LOGFILE logFile = {0};
    logFile.LoggerName = (LPWSTR)L"TianHongEtwTiNetworkSession";
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwTiNetworkEventRecordCallback;

    TRACEHANDLE hTrace = OpenTrace(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        Log_AddLogSimple(QString("ETW-TI Network OpenTrace failed: %1").arg(GetLastError()), LOG_ERROR);
        g_bEtwTiNetworkRunning = FALSE;
        return 1;
    }

    Log_AddLogSimple("ETW-TI Network 消费线程已启动", LOG_INFO);
    g_bEtwTiNetworkRunning = TRUE;

    ProcessTrace(&hTrace, 1, 0, 0);

    CloseTrace(hTrace);
    g_bEtwTiNetworkRunning = FALSE;
    Log_AddLogSimple("ETW-TI Network 消费线程已停止", LOG_ERROR);
    return 0;
}

static BOOL EtwTiStartNetworkConsumer()
{
    /* 清理可能残留的旧 session */
    {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"TianHongEtwTiNetworkSession");
        EVENT_TRACE_PROPERTIES* pCleanup = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
        if (pCleanup) {
            ZeroMemory(pCleanup, bufferSize);
            pCleanup->Wnode.BufferSize = bufferSize;
            pCleanup->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            pCleanup->Wnode.ClientContext = 1;
            pCleanup->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            pCleanup->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wcscpy((PWCHAR)((PBYTE)pCleanup + pCleanup->LoggerNameOffset),
                   L"TianHongEtwTiNetworkSession");
            ControlTrace(0, L"TianHongEtwTiNetworkSession", pCleanup, EVENT_TRACE_CONTROL_STOP);
            free(pCleanup);
        }
    }

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"TianHongEtwTiNetworkSession");
    g_pEtwTiNetworkProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (g_pEtwTiNetworkProperties == NULL)
        return FALSE;

    ZeroMemory(g_pEtwTiNetworkProperties, bufferSize);
    g_pEtwTiNetworkProperties->Wnode.BufferSize = bufferSize;
    g_pEtwTiNetworkProperties->Wnode.ClientContext = 1;
    g_pEtwTiNetworkProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_pEtwTiNetworkProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_pEtwTiNetworkProperties->MaximumFileSize = 0;
    g_pEtwTiNetworkProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy((PWCHAR)((PBYTE)g_pEtwTiNetworkProperties + g_pEtwTiNetworkProperties->LoggerNameOffset),
           L"TianHongEtwTiNetworkSession");

    ULONG status = StartTrace(&g_hEtwTiNetworkSession, L"TianHongEtwTiNetworkSession", g_pEtwTiNetworkProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        Log_AddLogSimple(QString("ETW-TI Network StartTrace 失败: %1").arg(status), LOG_ERROR);
        free(g_pEtwTiNetworkProperties);
        g_pEtwTiNetworkProperties = NULL;
        return FALSE;
    }

    ENABLE_TRACE_PARAMETERS enableParams = {0};
    enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    status = EnableTraceEx2(
        g_hEtwTiNetworkSession,
        &g_EtwTiNetworkProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        TI_KEYWORD_NETWORK_CONNECT | TI_KEYWORD_NETWORK_ACCEPT |
        TI_KEYWORD_NETWORK_UDP | TI_KEYWORD_NETWORK_DNS,
        0, 0, &enableParams);

    if (status != ERROR_SUCCESS) {
        Log_AddLogSimple(QString("ETW-TI Network EnableTraceEx2 失败: %1").arg(status), LOG_ERROR);
        ControlTrace(g_hEtwTiNetworkSession, L"TianHongEtwTiNetworkSession", g_pEtwTiNetworkProperties, EVENT_TRACE_CONTROL_STOP);
        free(g_pEtwTiNetworkProperties);
        g_pEtwTiNetworkProperties = NULL;
        return FALSE;
    }

    InitializeCriticalSection(&g_csEtwTiNetDedup);
    InitializeCriticalSection(&g_csEtwTiNetRateLimit);

    g_hEtwTiNetworkThread = CreateThread(NULL, 0, EtwTiNetworkConsumerThread, NULL, 0, NULL);
    if (g_hEtwTiNetworkThread == NULL) {
        Log_AddLogSimple(QString("ETW-TI Network CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
        DeleteCriticalSection(&g_csEtwTiNetDedup);
        DeleteCriticalSection(&g_csEtwTiNetRateLimit);
        ControlTrace(g_hEtwTiNetworkSession, L"TianHongEtwTiNetworkSession", g_pEtwTiNetworkProperties, EVENT_TRACE_CONTROL_STOP);
        free(g_pEtwTiNetworkProperties);
        g_pEtwTiNetworkProperties = NULL;
        return FALSE;
    }

    Log_AddLogSimple("ETW-TI Network provider 已启用", LOG_SUCCESS);
    return TRUE;
}

static void EtwTiStopNetworkConsumer()
{
    g_bEtwTiNetworkRunning = FALSE;

    if (g_hEtwTiNetworkSession != 0 && g_pEtwTiNetworkProperties != NULL) {
        ControlTrace(g_hEtwTiNetworkSession, L"TianHongEtwTiNetworkSession", g_pEtwTiNetworkProperties, EVENT_TRACE_CONTROL_STOP);
    }

    if (g_hEtwTiNetworkThread != NULL) {
        WaitForSingleObject(g_hEtwTiNetworkThread, 3000);
        CloseHandle(g_hEtwTiNetworkThread);
        g_hEtwTiNetworkThread = NULL;
    }

    if (g_pEtwTiNetworkProperties != NULL) {
        free(g_pEtwTiNetworkProperties);
        g_pEtwTiNetworkProperties = NULL;
    }

    DeleteCriticalSection(&g_csEtwTiNetDedup);
    DeleteCriticalSection(&g_csEtwTiNetRateLimit);
    g_EtwTiNetDedupMap.clear();
    g_EtwTiNetRateLimitMap.clear();
    g_hEtwTiNetworkSession = 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// ETW Syscall Consumer - direct / indirect syscall 检测
// ═══════════════════════════════════════════════════════════════════════════
static BOOL EtwTiGetEventPropertyInt64(PEVENT_RECORD pRecord, LPCWSTR propName, INT64* pValue);
static BOOL EtwTiGetEventPropertyUlong(PEVENT_RECORD pRecord, LPCWSTR propName, ULONG* pValue);

static ULONGLONG EtwSyscallGetTickCountMs()
{
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (ULONGLONG)(count.QuadPart * 1000ULL / freq.QuadPart);
}

static BOOL EtwSyscallShouldThrottle(INT64 callerPid)
{
    EtwSyscallRateKey key = { callerPid };
    ULONGLONG now = EtwSyscallGetTickCountMs();
    BOOL throttle = FALSE;

    EnterCriticalSection(&g_csEtwSyscallRateLimit);
    for (auto it = g_EtwSyscallRateLimitMap.begin(); it != g_EtwSyscallRateLimitMap.end(); ) {
        if (now - it->second.windowStart > ETW_SYSCALL_RATE_LIMIT_WINDOW_MS)
            it = g_EtwSyscallRateLimitMap.erase(it);
        else
            ++it;
    }
    if (g_EtwSyscallRateLimitMap.size() > ETW_SYSCALL_RATE_LIMIT_MAX_ENTRIES) {
        g_EtwSyscallRateLimitMap.clear();
    }

    auto it = g_EtwSyscallRateLimitMap.find(key);
    if (it != g_EtwSyscallRateLimitMap.end()) {
        if (now - it->second.windowStart <= ETW_SYSCALL_RATE_LIMIT_WINDOW_MS) {
            if (it->second.count >= ETW_SYSCALL_RATE_LIMIT_MAX_EVENTS) {
                throttle = TRUE;
            } else {
                it->second.count++;
            }
        } else {
            it->second.windowStart = now;
            it->second.count = 1;
        }
    } else {
        EtwSyscallRateValue val = { now, 1 };
        g_EtwSyscallRateLimitMap[key] = val;
    }
    LeaveCriticalSection(&g_csEtwSyscallRateLimit);

    return throttle;
}

static BOOL SendEtwSyscallEventToDriver(PETW_SYSCALL_EVENT_DATA pEvent)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (pEvent == NULL || pEvent->CallerPid == 0) {
        return FALSE;
    }

    /* 跳过系统进程，避免正常系统行为噪音 */
    if (EtwTiIsKnownSystemProcess((DWORD)pEvent->CallerPid))
        return TRUE;

    /* 速率限制 */
    if (EtwSyscallShouldThrottle(pEvent->CallerPid))
        return TRUE;

    DWORD bytesReturned = 0;
    return DeviceIoControl(
        g_hR0DriverDevice,
        IOCTL_BEHAVIOR_ETW_SYSCALL_EVENT,
        pEvent,
        sizeof(ETW_SYSCALL_EVENT_DATA),
        NULL, 0,
        &bytesReturned, NULL);
}

/* 根据地址解析所属模块名（带按 PID 缓存，降低高频 syscall 事件开销）。
 * 若目标进程不可读，则返回空字符串。 */
static void EtwSyscallResolveModuleName(DWORD pid, ULONG_PTR address, CHAR* outName, DWORD outNameLen)
{
    if (outName == NULL || outNameLen == 0)
        return;
    outName[0] = '\0';
    if (address == 0 || pid == 0)
        return;

    ULONGLONG now = EtwSyscallGetTickCountMs();
    BOOL needRefresh = TRUE;
    std::vector<EtwSyscallModuleInfo> modules;

    EnterCriticalSection(&g_csEtwSyscallModuleCache);

    /* 限制缓存 PID 数量，防止内存无限增长 */
    if (g_EtwSyscallModuleCacheMap.size() > ETW_SYSCALL_MODULE_CACHE_MAX_PIDS) {
        g_EtwSyscallModuleCacheMap.clear();
    }

    auto it = g_EtwSyscallModuleCacheMap.find(pid);
    if (it != g_EtwSyscallModuleCacheMap.end()) {
        if (now - it->second.lastUpdateMs <= ETW_SYSCALL_MODULE_CACHE_TTL_MS) {
            needRefresh = FALSE;
            modules = it->second.modules;
        }
    }

    if (!needRefresh) {
        for (const auto& mod : modules) {
            if (address >= mod.base && address < mod.end) {
                size_t copied = mod.name.length();
                if (copied >= outNameLen) copied = outNameLen - 1;
                WideCharToMultiByte(CP_ACP, 0, mod.name.c_str(), (int)copied,
                                    outName, (int)outNameLen, NULL, NULL);
                outName[copied] = '\0';
                break;
            }
        }
        LeaveCriticalSection(&g_csEtwSyscallModuleCache);
        return;
    }

    LeaveCriticalSection(&g_csEtwSyscallModuleCache);

    /* 缓存未命中或过期，重新枚举模块 */
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL)
        return;

    modules.clear();
    HMODULE hMods[2048] = {0};
    DWORD cbNeeded = 0;
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        DWORD count = cbNeeded / sizeof(HMODULE);
        if (count > _countof(hMods))
            count = _countof(hMods);

        for (DWORD i = 0; i < count; i++) {
            MODULEINFO modInfo = {0};
            if (!GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo)))
                continue;

            EtwSyscallModuleInfo info;
            info.base = (ULONG_PTR)modInfo.lpBaseOfDll;
            info.end = info.base + modInfo.SizeOfImage;

            WCHAR modNameW[MAX_PATH] = {0};
            if (GetModuleBaseNameW(hProcess, hMods[i], modNameW, MAX_PATH)) {
                info.name = modNameW;
            } else {
                info.name = L"";
            }
            modules.push_back(info);
        }
    }
    CloseHandle(hProcess);

    /* 更新缓存 */
    EnterCriticalSection(&g_csEtwSyscallModuleCache);
    EtwSyscallModuleCache cache;
    cache.lastUpdateMs = now;
    cache.modules = modules;
    g_EtwSyscallModuleCacheMap[pid] = cache;

    for (const auto& mod : modules) {
        if (address >= mod.base && address < mod.end) {
            size_t copied = mod.name.length();
            if (copied >= outNameLen) copied = outNameLen - 1;
            WideCharToMultiByte(CP_ACP, 0, mod.name.c_str(), (int)copied,
                                outName, (int)outNameLen, NULL, NULL);
            outName[copied] = '\0';
            break;
        }
    }
    LeaveCriticalSection(&g_csEtwSyscallModuleCache);
}

/* 从 EVENT_RECORD 扩展数据中提取用户态调用栈。
 * 返回 TRUE 表示成功提取到至少一帧；outIs64Bit 表示栈帧位宽。
 * 注意：调用栈需要在开启 trace 时启用 EVENT_ENABLE_PROPERTY_STACK_TRACE。 */
static BOOL EtwSyscallExtractStackTrace(
    PEVENT_RECORD pRecord,
    ULONG_PTR* stackFrames,
    ULONG maxFrames,
    ULONG* outFrameCount,
    BOOL* outIs64Bit)
{
    if (pRecord == NULL || stackFrames == NULL || outFrameCount == NULL)
        return FALSE;

    *outFrameCount = 0;
    if (outIs64Bit) *outIs64Bit = FALSE;

    for (USHORT i = 0; i < pRecord->ExtendedDataCount; i++) {
        PEVENT_HEADER_EXTENDED_DATA_ITEM pItem = &pRecord->ExtendedData[i];
        if (pItem == NULL || pItem->DataSize == 0)
            continue;

        if (pItem->ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
            PBYTE pData = (PBYTE)pItem->DataPtr;
            if (pData == NULL)
                continue;
            ULONG64 matchId = *(ULONG64*)pData;
            ULONG frameCount = *(ULONG*)(pData + sizeof(ULONG64));
            ULONG64* pAddresses = (ULONG64*)(pData + sizeof(ULONG64) + sizeof(ULONG));

            ULONG copyCount = (frameCount < maxFrames ? frameCount : maxFrames);
            for (ULONG j = 0; j < copyCount; j++) {
                stackFrames[j] = (ULONG_PTR)pAddresses[j];
            }
            *outFrameCount = copyCount;
            if (outIs64Bit) *outIs64Bit = TRUE;
            return TRUE;

        } else if (pItem->ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32) {
            PBYTE pData = (PBYTE)pItem->DataPtr;
            if (pData == NULL)
                continue;
            ULONG64 matchId = *(ULONG64*)pData;
            ULONG frameCount = *(ULONG*)(pData + sizeof(ULONG64));
            ULONG* pAddresses = (ULONG*)(pData + sizeof(ULONG64) + sizeof(ULONG));

            ULONG copyCount = (frameCount < maxFrames ? frameCount : maxFrames);
            for (ULONG j = 0; j < copyCount; j++) {
                stackFrames[j] = (ULONG_PTR)pAddresses[j];
            }
            *outFrameCount = copyCount;
            if (outIs64Bit) *outIs64Bit = FALSE;
            return TRUE;
        }
    }
    return FALSE;
}

/* 通过 TDH 读取事件属性。对 Microsoft-Windows-Kernel-Syscall provider 与
 * SystemTraceProvider 分别尝试多组常见属性名，提高跨版本兼容性。 */
static void EtwSyscallParseEventProperties(PEVENT_RECORD pRecord, PETW_SYSCALL_EVENT_DATA pEv)
{
    if (pRecord == NULL || pEv == NULL)
        return;

    GUID providerId = pRecord->EventHeader.ProviderId;

    /* 进程/线程 ID：优先事件头，再用 TDH */
    pEv->CallerPid = (INT64)pRecord->EventHeader.ProcessId;
    pEv->ThreadId = (INT64)pRecord->EventHeader.ThreadId;

    EtwTiGetEventPropertyInt64(pRecord, L"ProcessId", &pEv->CallerPid);
    EtwTiGetEventPropertyInt64(pRecord, L"ThreadId", &pEv->ThreadId);

    /* Syscall Number：尝试多组常见名称 */
    if (!EtwTiGetEventPropertyUlong(pRecord, L"SysCallNum", &pEv->SyscallNumber)) {
        if (!EtwTiGetEventPropertyUlong(pRecord, L"SyscallNumber", &pEv->SyscallNumber)) {
            if (!EtwTiGetEventPropertyUlong(pRecord, L"SystemCallIndex", &pEv->SyscallNumber)) {
                EtwTiGetEventPropertyUlong(pRecord, L"Index", &pEv->SyscallNumber);
            }
        }
    }

    /* Return Address */
    INT64 retAddr = 0;
    if (EtwTiGetEventPropertyInt64(pRecord, L"ReturnAddress", &retAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"CallerReturnAddress", &retAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"SystemCallReturnAddress", &retAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"ReturnAddr", &retAddr)) {
        pEv->ReturnAddress = retAddr;
    }

    /* Syscall Instruction Address */
    INT64 instAddr = 0;
    if (EtwTiGetEventPropertyInt64(pRecord, L"SysCallAddress", &instAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"SystemCallAddress", &instAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"SyscallInstruction", &instAddr)) {
        pEv->SyscallInstructionAddress = instAddr;
    }

    /* Call Origin (caller of the syscall instruction) */
    INT64 originAddr = 0;
    if (EtwTiGetEventPropertyInt64(pRecord, L"CallOrigin", &originAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"CallerAddress", &originAddr) ||
        EtwTiGetEventPropertyInt64(pRecord, L"CallingAddress", &originAddr)) {
        pEv->CallOriginAddress = originAddr;
    }

    /* Microsoft-Windows-Kernel-Syscall provider 的 UserData 兜底解析：
     * 常见布局：ULONG SyscallNumber, PVOID ReturnAddress, ... */
    if (pEv->SyscallNumber == 0 && pRecord->UserDataLength >= sizeof(ULONG)) {
        pEv->SyscallNumber = *(ULONG*)pRecord->UserData;
    }
    if (pEv->ReturnAddress == 0 && pRecord->UserDataLength >= sizeof(ULONG) + sizeof(PVOID)) {
        if (pRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) {
            pEv->ReturnAddress = *(ULONG*)((PBYTE)pRecord->UserData + sizeof(ULONG));
        } else {
            pEv->ReturnAddress = *(ULONG64*)((PBYTE)pRecord->UserData + sizeof(ULONG));
        }
    }

    /* SystemTraceProvider (EVENT_TRACE_FLAG_SYSTEMCALL) 兜底：
     * 该 provider 不保证字段名，UserData 通常为：ULONG SyscallNumber + PVOID ReturnAddress */
    if (IsEqualGuid(&providerId, &g_SystemTraceProviderGuid)) {
        if (pEv->SyscallNumber == 0 && pRecord->UserDataLength >= sizeof(ULONG))
            pEv->SyscallNumber = *(ULONG*)pRecord->UserData;
        if (pEv->ReturnAddress == 0 && pRecord->UserDataLength >= sizeof(ULONG) + sizeof(PVOID)) {
            if (pRecord->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)
                pEv->ReturnAddress = *(ULONG*)((PBYTE)pRecord->UserData + sizeof(ULONG));
            else
                pEv->ReturnAddress = *(ULONG64*)((PBYTE)pRecord->UserData + sizeof(ULONG));
        }
    }
}

/* 判定一个模块是否为 Windows 中合法存放 syscall 指令的系统模块。
 * 除 ntdll.dll 外，win32u.dll、wow64 系列等也包含 syscall 指令，
 * 因此不能简单地把“不在 ntdll”当作 direct syscall。 */
static BOOL EtwSyscallIsLegitimateSyscallModule(const CHAR* moduleName)
{
    if (moduleName == NULL || moduleName[0] == '\0')
        return FALSE;
    return (
        strstr(moduleName, "ntdll.dll") != NULL ||
        strstr(moduleName, "win32u.dll") != NULL ||
        strstr(moduleName, "wow64.dll") != NULL ||
        strstr(moduleName, "wow64cpu.dll") != NULL ||
        strstr(moduleName, "wow64win.dll") != NULL
    );
}

/* 判定调用者模块是否为正常会调用 ntdll/win32u syscall 的合法系统模块。
 * 攻击者 jmp 到 ntdll 的 syscall 指令时，调用者通常位于无模块支撑的内存或
 * 非系统模块；而 kernelbase/kernel32/user32 等正常调用 ntdll 不应被判为 indirect。 */
static BOOL EtwSyscallIsLegitimateCallerModule(const CHAR* moduleName)
{
    if (moduleName == NULL || moduleName[0] == '\0')
        return FALSE;  /* 无模块信息视为不可信 */
    return (
        strstr(moduleName, "ntdll.dll") != NULL ||
        strstr(moduleName, "win32u.dll") != NULL ||
        strstr(moduleName, "kernel32.dll") != NULL ||
        strstr(moduleName, "kernelbase.dll") != NULL ||
        strstr(moduleName, "user32.dll") != NULL ||
        strstr(moduleName, "gdi32.dll") != NULL ||
        strstr(moduleName, "gdiplus.dll") != NULL ||
        strstr(moduleName, "advapi32.dll") != NULL ||
        strstr(moduleName, "shell32.dll") != NULL ||
        strstr(moduleName, "combase.dll") != NULL ||
        strstr(moduleName, "rpcrt4.dll") != NULL ||
        strstr(moduleName, "crypt32.dll") != NULL ||
        strstr(moduleName, "ucrtbase.dll") != NULL ||
        strstr(moduleName, "msvcrt.dll") != NULL ||
        strstr(moduleName, "clr.dll") != NULL ||
        strstr(moduleName, "coreclr.dll") != NULL ||
        strstr(moduleName, "wow64.dll") != NULL ||
        strstr(moduleName, "wow64cpu.dll") != NULL ||
        strstr(moduleName, "wow64win.dll") != NULL
    );
}

/* 综合 stack trace、syscall 指令模块和调用来源模块判定 direct / indirect syscall。
 * Direct syscall:   syscall 指令本身不在合法 syscall 模块（攻击者自己实现 syscall）。
 * Indirect syscall: syscall 指令在合法模块，但调用者（stack frame 0 的调用者）
 *                    不在合法 syscall 模块，也不在正常调用 ntdll/win32u 的系统模块中；
 *                    即攻击者 jmp/call 到合法模块的 syscall 指令以绕过 Hook。
 * 若 stack trace 不可用，则退回到 CallOriginAddress 字段判断。 */
static void EtwSyscallClassify(
    DWORD pid,
    PETW_SYSCALL_EVENT_DATA pEv,
    const ULONG_PTR* stackFrames,
    ULONG frameCount)
{
    if (pEv == NULL)
        return;

    CHAR retModule[64] = {0};
    CHAR instModule[64] = {0};
    EtwSyscallResolveModuleName(pid, (ULONG_PTR)pEv->ReturnAddress, retModule, sizeof(retModule));
    EtwSyscallResolveModuleName(pid, (ULONG_PTR)pEv->SyscallInstructionAddress, instModule, sizeof(instModule));
    strncpy_s(pEv->ReturnAddressModule, sizeof(pEv->ReturnAddressModule), retModule, _TRUNCATE);
    strncpy_s(pEv->SyscallInstructionModule, sizeof(pEv->SyscallInstructionModule), instModule, _TRUNCATE);

    _strlwr(retModule);
    _strlwr(instModule);
    BOOL instIsLegit = EtwSyscallIsLegitimateSyscallModule(instModule);

    /* Direct syscall: syscall 指令本身就不在合法 syscall 模块 */
    if (!instIsLegit) {
        pEv->IsDirectSyscall = 1;
        return;
    }

    /* Indirect syscall 判定：syscall 指令在合法模块，但调用来源既不是合法 syscall
     * 模块，也不是正常调用 syscall 的系统 DLL（如 kernelbase），则视为攻击者
     * jmp 到合法 syscall 指令以绕过 Hook。优先使用 stack trace 的上一层帧。 */
    ULONG_PTR callerAddress = 0;
    if (frameCount >= 2 && stackFrames[1] != 0) {
        callerAddress = stackFrames[1];
    } else if (pEv->CallOriginAddress != 0) {
        callerAddress = (ULONG_PTR)pEv->CallOriginAddress;
    }

    if (callerAddress != 0) {
        CHAR callerModule[64] = {0};
        EtwSyscallResolveModuleName(pid, callerAddress, callerModule, sizeof(callerModule));
        _strlwr(callerModule);
        BOOL callerIsLegit = EtwSyscallIsLegitimateSyscallModule(callerModule) ||
                             EtwSyscallIsLegitimateCallerModule(callerModule);

        /* syscall 指令在合法模块，但调用者不在合法/正常调用者模块：indirect */
        if (!callerIsLegit) {
            pEv->IsIndirectSyscall = 1;
            pEv->CallOriginAddress = (INT64)callerAddress;
            return;
        }
    }

    /* 退化判断：syscall 指令在合法模块，但 CallOrigin 已知且不是合法调用者 */
    if (pEv->CallOriginAddress != 0) {
        CHAR originModule[64] = {0};
        EtwSyscallResolveModuleName(pid, (ULONG_PTR)pEv->CallOriginAddress,
            originModule, sizeof(originModule));
        _strlwr(originModule);
        if (!EtwSyscallIsLegitimateSyscallModule(originModule) &&
            !EtwSyscallIsLegitimateCallerModule(originModule)) {
            pEv->IsIndirectSyscall = 1;
        }
    }
}

/* 解析 ETW syscall 事件并下发到驱动。
 * 支持 Microsoft-Windows-Kernel-Syscall provider 与 SystemTraceProvider
 * (EVENT_TRACE_FLAG_SYSTEMCALL)，通过 TDH + 扩展数据中的 stack trace 实现
 * 对 direct / indirect syscall 的完整判定。 */
static VOID WINAPI EtwSyscallEventRecordCallback(PEVENT_RECORD pRecord)
{
    if (pRecord == NULL || pRecord->UserData == NULL)
        return;

    USHORT eventId = pRecord->EventHeader.EventDescriptor.Id;

    /* Microsoft-Windows-Kernel-Syscall: 1=SyscallEnter, 2=SyscallExit
     * SystemTraceProvider: EVENT_TRACE_TYPE_SYSCALL == 50 (enter) */
    BOOL isEnterEvent = FALSE;
    if (IsEqualGuid(&pRecord->EventHeader.ProviderId, &g_EtwSyscallProviderGuid)) {
        if (eventId == 1) isEnterEvent = TRUE;
    } else if (IsEqualGuid(&pRecord->EventHeader.ProviderId, &g_SystemTraceProviderGuid)) {
        if (eventId == EVENT_TRACE_TYPE_SYSCALL) isEnterEvent = TRUE;
    }

    if (!isEnterEvent)
        return;  /* 只处理进入内核的系统调用事件 */

    ETW_SYSCALL_EVENT_DATA ev = {0};
    EtwSyscallParseEventProperties(pRecord, &ev);

    if (ev.CallerPid == 0)
        return;

    DWORD pid = (DWORD)ev.CallerPid;

    /* 提前过滤系统进程，减少后续模块解析与 TDH 开销 */
    if (EtwTiIsKnownSystemProcess(pid))
        return;

    /* 提取调用栈（若 trace session 启用了 stack walk） */
    ULONG_PTR stackFrames[64] = {0};
    ULONG frameCount = 0;
    BOOL is64BitStack = FALSE;
    EtwSyscallExtractStackTrace(pRecord, stackFrames, _countof(stackFrames),
                                &frameCount, &is64BitStack);

    /* 判定是否为常被 R3 EDR Hook 的系统调用 */
    ev.IsHookedSyscall = EtwSyscallIsHookedSyscall(ev.SyscallNumber);

    /* 判定 direct / indirect syscall */
    EtwSyscallClassify(pid, &ev, stackFrames, frameCount);

    /* 只转发直接/间接 syscall，避免海量正常事件 */
    if (!ev.IsDirectSyscall && !ev.IsIndirectSyscall)
        return;

    /* 获取进程名 */
    WCHAR processName[MAX_PATH] = {0};
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        DWORD len = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, processName, &len)) {
            LPCWSTR fileName = wcsrchr(processName, L'\\');
            if (fileName) fileName++;
            else fileName = processName;
            QString qsName = QString::fromWCharArray(fileName);
            QByteArray ba = qsName.toLocal8Bit();
            strncpy_s(ev.ProcessName, sizeof(ev.ProcessName), ba.constData(), _TRUNCATE);
        }
        CloseHandle(hProcess);
    }

    SendEtwSyscallEventToDriver(&ev);
}

static DWORD WINAPI EtwSyscallConsumerThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    EVENT_TRACE_LOGFILE logFile = {0};
    logFile.LoggerName = (LPWSTR)L"TianHongEtwSyscallSession";
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwSyscallEventRecordCallback;

    TRACEHANDLE hTrace = OpenTrace(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        Log_AddLogSimple(QString("ETW-Syscall OpenTrace 失败: %1").arg(GetLastError()), LOG_ERROR);
        g_bEtwSyscallRunning = FALSE;
        return 1;
    }

    Log_AddLogSimple("ETW-Syscall 消费线程已启动", LOG_SUCCESS);
    g_bEtwSyscallRunning = TRUE;

    ProcessTrace(&hTrace, 1, 0, 0);

    CloseTrace(hTrace);
    g_bEtwSyscallRunning = FALSE;
    Log_AddLogSimple("ETW-Syscall 消费线程已停止", LOG_ERROR);
    return 0;
}

static BOOL EtwSyscallStartConsumer()
{
    /* 动态解析当前系统上常被 R3 EDR Hook 的 syscall 号 */
    EtwSyscallBuildHookedSyscallSet();

    /* 清理可能残留的旧 session */
    {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"TianHongEtwSyscallSession");
        EVENT_TRACE_PROPERTIES* pCleanup = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
        if (pCleanup) {
            ZeroMemory(pCleanup, bufferSize);
            pCleanup->Wnode.BufferSize = bufferSize;
            pCleanup->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            pCleanup->Wnode.ClientContext = 1;
            pCleanup->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            pCleanup->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wcscpy((PWCHAR)((PBYTE)pCleanup + pCleanup->LoggerNameOffset),
                   L"TianHongEtwSyscallSession");
            ControlTrace(0, L"TianHongEtwSyscallSession", pCleanup, EVENT_TRACE_CONTROL_STOP);
            free(pCleanup);
        }
    }

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"TianHongEtwSyscallSession");
    g_pEtwSyscallProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (g_pEtwSyscallProperties == NULL)
        return FALSE;

    ZeroMemory(g_pEtwSyscallProperties, bufferSize);
    g_pEtwSyscallProperties->Wnode.BufferSize = bufferSize;
    g_pEtwSyscallProperties->Wnode.ClientContext = 1;
    g_pEtwSyscallProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_pEtwSyscallProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_pEtwSyscallProperties->MaximumFileSize = 0;
    g_pEtwSyscallProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy((PWCHAR)((PBYTE)g_pEtwSyscallProperties + g_pEtwSyscallProperties->LoggerNameOffset),
           L"TianHongEtwSyscallSession");

    ULONG status = StartTrace(&g_hEtwSyscallSession, L"TianHongEtwSyscallSession", g_pEtwSyscallProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        Log_AddLogSimple(QString("ETW-Syscall StartTrace 失败: %1").arg(status), LOG_ERROR);
        free(g_pEtwSyscallProperties);
        g_pEtwSyscallProperties = NULL;
        return FALSE;
    }

    ENABLE_TRACE_PARAMETERS enableParams = {0};
    enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    enableParams.EnableProperty = EVENT_ENABLE_PROPERTY_STACK_TRACE;

    /* Microsoft-Windows-Kernel-Syscall provider：keywords=0, level=VERBOSE */
    status = EnableTraceEx2(
        g_hEtwSyscallSession,
        &g_EtwSyscallProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0, 0, 0, &enableParams);

    if (status != ERROR_SUCCESS) {
        Log_AddLogSimple(QString("ETW-Syscall EnableTraceEx2 失败: %1（该 provider 在当前 Windows 版本上可能不可用）").arg(status), LOG_ERROR);
        ControlTrace(g_hEtwSyscallSession, L"TianHongEtwSyscallSession", g_pEtwSyscallProperties, EVENT_TRACE_CONTROL_STOP);
        free(g_pEtwSyscallProperties);
        g_pEtwSyscallProperties = NULL;
        return FALSE;
    }

    InitializeCriticalSection(&g_csEtwSyscallRateLimit);
    InitializeCriticalSection(&g_csEtwSyscallModuleCache);

    g_hEtwSyscallThread = CreateThread(NULL, 0, EtwSyscallConsumerThread, NULL, 0, NULL);
    if (g_hEtwSyscallThread == NULL) {
        Log_AddLogSimple(QString("ETW-Syscall CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
        DeleteCriticalSection(&g_csEtwSyscallRateLimit);
        DeleteCriticalSection(&g_csEtwSyscallModuleCache);
        g_EtwSyscallModuleCacheMap.clear();
        ControlTrace(g_hEtwSyscallSession, L"TianHongEtwSyscallSession", g_pEtwSyscallProperties, EVENT_TRACE_CONTROL_STOP);
        free(g_pEtwSyscallProperties);
        g_pEtwSyscallProperties = NULL;
        return FALSE;
    }

    Log_AddLogSimple("ETW-Syscall provider 已启用", LOG_SUCCESS);
    return TRUE;
}

static void EtwSyscallStopConsumer()
{
    g_bEtwSyscallRunning = FALSE;

    if (g_hEtwSyscallSession != 0 && g_pEtwSyscallProperties != NULL) {
        ControlTrace(g_hEtwSyscallSession, L"TianHongEtwSyscallSession", g_pEtwSyscallProperties, EVENT_TRACE_CONTROL_STOP);
    }

    if (g_hEtwSyscallThread != NULL) {
        WaitForSingleObject(g_hEtwSyscallThread, 3000);
        CloseHandle(g_hEtwSyscallThread);
        g_hEtwSyscallThread = NULL;
    }

    if (g_pEtwSyscallProperties != NULL) {
        free(g_pEtwSyscallProperties);
        g_pEtwSyscallProperties = NULL;
    }

    DeleteCriticalSection(&g_csEtwSyscallRateLimit);
    g_EtwSyscallRateLimitMap.clear();
    DeleteCriticalSection(&g_csEtwSyscallModuleCache);
    g_EtwSyscallModuleCacheMap.clear();
    DeleteCriticalSection(&g_csHookedSyscallNumbers);
    s_hookedSyscallNumbers.clear();
    g_hEtwSyscallSession = 0;
}

// ═══════════════════════════════════════════════════════════════════════════
// DCOM 横向移动检测线程
// 通过 WMI Win32_Process 创建事件监控进程创建，
// 检测 DCOM 横向移动特征：dllhost.exe/svchost.exe/wmiprvse.exe 派生可疑子进程
// ═══════════════════════════════════════════════════════════════════════════
static DWORD WINAPI DcomMonitorThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    // DCOM 代理进程名（父进程）
    static const char* dcomHosts[] = {
        "dllhost.exe",
        "svchost.exe",
        "wmiprvse.exe",
        NULL
    };

    // 可疑子进程名
    static const char* suspiciousChildren[] = {
        "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "mmc.exe",
        "excel.exe", "outlook.exe", "winword.exe", "powershell_ise.exe",
        "certutil.exe", "bitsadmin.exe", "msiexec.exe",
        NULL
    };

    // DCOM 对象到事件类型映射
    struct DcomMapping {
        const char* childProc;
        const char* parentProc;
        int eventType;
        const char* dcomObject;
    };
    static const DcomMapping dcomMappings[] = {
        {"mmc.exe",       "dllhost.exe",   DCOM_TYPE_MMC20,         "MMC20.Application"},
        {"excel.exe",     "dllhost.exe",   DCOM_TYPE_EXCEL,         "Excel.Application"},
        {"outlook.exe",   "dllhost.exe",   DCOM_TYPE_OUTLOOK,       "Outlook.Application"},
        {"cmd.exe",       "wmiprvse.exe",  DCOM_TYPE_WMI,           "WMI"},
        {"powershell.exe","wmiprvse.exe",  DCOM_TYPE_WMI,           "WMI"},
        {"wscript.exe",   "wmiprvse.exe",  DCOM_TYPE_WMI,           "WMI"},
        {"cscript.exe",   "wmiprvse.exe",  DCOM_TYPE_WMI,           "WMI"},
        {NULL, NULL, 0, NULL}
    };

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    BOOL bComInitialized = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    if (!bComInitialized) {
        Log_AddLogSimple("DCOM-Monitor 初始化 COM 失败", LOG_ERROR);
        return 1;
    }

    // 使用 WMI 监听进程创建事件
    IWbemLocator* pLocator = NULL;
    IWbemServices* pServices = NULL;
    IEnumWbemClassObject* pEnum = NULL;
    BSTR wqlQuery = NULL;
    BSTR bstrLang = NULL;

    hr = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLocator);
    if (FAILED(hr) || !pLocator) goto dcom_cleanup;

    {
        BSTR bstrNs = SysAllocString(L"ROOT\\CIMV2");
        hr = pLocator->ConnectServer(bstrNs, NULL, NULL, NULL,
                                      0, NULL, NULL, &pServices);
        SysFreeString(bstrNs);
    }
    if (FAILED(hr) || !pServices) goto dcom_cleanup;

    CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                       RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    // 创建事件查询：使用 __InstanceCreationEvent 监听 Win32_Process 创建
    wqlQuery = SysAllocString(L"SELECT TargetInstance FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");

    // 使用半同步轮询方式（比异步 sink 更可靠）
    // ExecNotificationQuery 参数: (strQueryLanguage, strQuery, lFlags, pCtx, ppEnum)
    bstrLang = SysAllocString(L"WQL");
    hr = pServices->ExecNotificationQuery(
        bstrLang, wqlQuery,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL, &pEnum);
    SysFreeString(bstrLang);
    SysFreeString(wqlQuery);
    wqlQuery = NULL;

    if (FAILED(hr) || !pEnum) goto dcom_cleanup;

    CoSetProxyBlanket(pEnum, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
                       RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    Log_AddLogSimple("DCOM-Monitor 线程已启动，监控进程创建以检测 DCOM 横向移动", LOG_SUCCESS);

    while (g_bDcomMonitorRunning)
    {
        IWbemClassObject* pObj = NULL;
        ULONG uCount = 0;

        // 使用 1 秒超时，确保线程能周期性检查 g_bDcomMonitorRunning 以便干净退出
        hr = pEnum->Next(1000, 1, &pObj, &uCount);
        if (hr == WBEM_S_FALSE || hr == WBEM_S_TIMEDOUT || uCount == 0)
        {
            continue;
        }
        if (FAILED(hr)) break;

        // 提取进程信息
        VARIANT varProc;
        VariantInit(&varProc);
        hr = pObj->Get(L"TargetInstance", 0, &varProc, NULL, NULL);
        if (SUCCEEDED(hr) && varProc.vt == VT_UNKNOWN)
        {
            IWbemClassObject* pProc = NULL;
            hr = varProc.punkVal->QueryInterface(IID_IWbemClassObject, (LPVOID*)&pProc);
            if (SUCCEEDED(hr) && pProc)
            {
                VARIANT varName, varPid, varParentPid, varCmdLine;
                VariantInit(&varName); VariantInit(&varPid);
                VariantInit(&varParentPid); VariantInit(&varCmdLine);

                pProc->Get(L"Name", 0, &varName, NULL, NULL);
                pProc->Get(L"ProcessId", 0, &varPid, NULL, NULL);
                pProc->Get(L"ParentProcessId", 0, &varParentPid, NULL, NULL);
                pProc->Get(L"CommandLine", 0, &varCmdLine, NULL, NULL);

                DWORD childPid = (varPid.vt == VT_I4) ? (DWORD)varPid.lVal : 0;
                DWORD parentPid = (varParentPid.vt == VT_I4) ? (DWORD)varParentPid.lVal : 0;
                QString childName = (varName.vt == VT_BSTR) ? QString::fromWCharArray(varName.bstrVal) : "";
                QString cmdLine = (varCmdLine.vt == VT_BSTR) ? QString::fromWCharArray(varCmdLine.bstrVal) : "";

                childName = childName.toLower();

                // 获取父进程名
                QString parentName;
                HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
                if (hParent)
                {
                    WCHAR parentPath[MAX_PATH] = {0};
                    DWORD pathLen = MAX_PATH;
                    if (QueryFullProcessImageNameW(hParent, 0, parentPath, &pathLen))
                    {
                        QString fullPath = QString::fromWCharArray(parentPath);
                        int lastSlash = fullPath.lastIndexOf('\\');
                        if (lastSlash >= 0)
                            parentName = fullPath.mid(lastSlash + 1).toLower();
                    }
                    CloseHandle(hParent);
                }

                // 检查是否为 DCOM 横向移动
                bool isDcomAttack = false;
                int eventType = DCOM_TYPE_GENERIC_CHILD;
                QString dcomObject = "Unknown";

                // 精确匹配已知 DCOM 攻击模式
                for (int i = 0; dcomMappings[i].childProc; i++)
                {
                    if (childName == dcomMappings[i].childProc &&
                        parentName == dcomMappings[i].parentProc)
                    {
                        eventType = dcomMappings[i].eventType;
                        dcomObject = dcomMappings[i].dcomObject;
                        isDcomAttack = true;
                        break;
                    }
                }

                // 通用检测：dllhost.exe/svchost.exe 派生可疑子进程
                if (!isDcomAttack)
                {
                    bool parentIsDcomHost = false;
                    for (int i = 0; dcomHosts[i]; i++)
                    {
                        if (parentName == dcomHosts[i])
                        {
                            parentIsDcomHost = true;
                            break;
                        }
                    }

                    bool childIsSuspicious = false;
                    for (int i = 0; suspiciousChildren[i]; i++)
                    {
                        if (childName == suspiciousChildren[i])
                        {
                            childIsSuspicious = true;
                            break;
                        }
                    }

                    if (parentIsDcomHost && childIsSuspicious)
                    {
                        isDcomAttack = true;
                        eventType = DCOM_TYPE_GENERIC_CHILD;
                        dcomObject = parentName;
                    }
                }

                if (isDcomAttack && g_bClientConnected)
                {
                    // 获取目标进程完整路径
                    QString targetPath;
                    HANDLE hChild = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, childPid);
                    if (hChild)
                    {
                        WCHAR childPath[MAX_PATH] = {0};
                        DWORD childPathLen = MAX_PATH;
                        if (QueryFullProcessImageNameW(hChild, 0, childPath, &childPathLen))
                            targetPath = QString::fromWCharArray(childPath);
                        CloseHandle(hChild);
                    }

                    // 构建 DCOM 事件数据并发送到内核
                    DCOM_EVENT_DATA dcomData = {};
                    dcomData.CallerPid = (INT64)parentPid;
                    dcomData.TargetPid = (INT64)childPid;
                    dcomData.ParentPid = (INT64)parentPid;
                    dcomData.EventType = (ULONG)eventType;
                    dcomData.IsRemoteActivation = 1;

                    QByteArray parentNameUtf8 = parentName.toUtf8();
                    QByteArray childNameUtf8 = childName.toUtf8();
                    QByteArray targetPathUtf8 = targetPath.toUtf8();
                    QByteArray dcomObjUtf8 = dcomObject.toUtf8();

                    strncpy_s(dcomData.CallerProcessName, sizeof(dcomData.CallerProcessName), parentNameUtf8.constData(), _TRUNCATE);
                    strncpy_s(dcomData.TargetProcessName, sizeof(dcomData.TargetProcessName), childNameUtf8.constData(), _TRUNCATE);
                    strncpy_s(dcomData.TargetProcessPath, sizeof(dcomData.TargetProcessPath), targetPathUtf8.constData(), _TRUNCATE);
                    strncpy_s(dcomData.DcomObjectCLSID, sizeof(dcomData.DcomObjectCLSID), dcomObjUtf8.constData(), _TRUNCATE);

                    // 通过 IOCTL 发送到内核行为分析引擎
                    if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
                    {
                        DWORD bytesReturned = 0;
                        DeviceIoControl(g_hR0DriverDevice, IOCTL_BEHAVIOR_DCOM_EVENT,
                            &dcomData, sizeof(dcomData), NULL, 0, &bytesReturned, NULL);
                    }

                    // 同时构建告警消息发送到 Client
                    QString alertTitle = QString("发现DCOM横向移动: %1").arg(dcomObject);
                    QString alertMsg = QString(
                        "[DCOM防护] 检测到DCOM横向移动攻击\r\n\r\n"
                        "DCOM对象：%1\r\n"
                        "父进程：%2 (PID=%3)\r\n"
                        "子进程：%4 (PID=%5)\r\n"
                        "子进程路径：%6\r\n"
                        "命令行：%7\r\n\r\n"
                        "攻击者通过DCOM远程激活COM对象执行代码，\r\n"
                        "属于横向移动行为 (T1021.003)。\r\n"
                        "请选择：\r\n"
                        "  允许 = 继续运行\r\n"
                        "  阻止 = 终止子进程")
                        .arg(dcomObject)
                        .arg(parentName)
                        .arg(parentPid)
                        .arg(childName)
                        .arg(childPid)
                        .arg(targetPath.isEmpty() ? "Unknown" : targetPath)
                        .arg(cmdLine.isEmpty() ? "N/A" : cmdLine);

                    // 通过 socket 发送告警到 Client（非阻塞通知）
                    Packet alertPacket = {};
                    alertPacket.PacketTyped = PTClientMessage;
                    strcpy_s(alertPacket.InfoTitle, sizeof(alertPacket.InfoTitle), CLIENT_MSG_ALERT);
                    alertPacket.Pid = (int)childPid;

                    ClientAlertData alertData = {};
                    alertData.pid = (INT64)childPid;
                    alertData.parentPid = (INT64)parentPid;
                    QByteArray titleUtf8 = alertTitle.toUtf8();
                    QByteArray msgUtf8 = alertMsg.toUtf8();
                    strncpy_s(alertData.title, sizeof(alertData.title), titleUtf8.constData(), _TRUNCATE);
                    strncpy_s(alertData.message, sizeof(alertData.message), msgUtf8.constData(), _TRUNCATE);
                    strncpy_s(alertData.parentName, sizeof(alertData.parentName), parentNameUtf8.constData(), _TRUNCATE);
                    strncpy_s(alertData.processPath, sizeof(alertData.processPath), targetPathUtf8.constData(), _TRUNCATE);

                    memcpy(alertPacket.Message, &alertData, sizeof(ClientAlertData));

                    if (Tran_ClientSocket != INVALID_SOCKET)
                    {
                        int sendResult = send(Tran_ClientSocket, (const char*)&alertPacket, sizeof(Packet), 0);
                        if (sendResult == SOCKET_ERROR)
                        {
                            Log_AddLogSimple(QString("发送DCOM告警到Client失败: %1").arg(WSAGetLastError()), LOG_ERROR);
                        }
                    }

                    Log_AddLogSimple(QString("[DCOM-Monitor] 检测到: %1 由 %2 派生 (PID=%3)")
                                     .arg(childName).arg(parentName).arg(childPid), LOG_WARN);
                }

                VariantClear(&varName);
                VariantClear(&varPid);
                VariantClear(&varParentPid);
                VariantClear(&varCmdLine);
                if (pProc) pProc->Release();
            }
        }
        VariantClear(&varProc);
        if (pObj) pObj->Release();
    }

dcom_cleanup:
    if (pEnum) pEnum->Release();
    if (pServices) pServices->Release();
    if (pLocator) pLocator->Release();

    if (bComInitialized)
        CoUninitialize();

    Log_AddLogSimple("DCOM-Monitor 线程已退出", LOG_INFO);
    return 0;
}

static BOOL EtwTiGetEventPropertyInt64(PEVENT_RECORD pRecord, LPCWSTR propName, INT64* pValue)
{
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propName;
    desc.ArrayIndex = 0;
    ULONG size = sizeof(INT64);
    return (TdhGetProperty(pRecord, 0, NULL, 1, &desc, size, (PBYTE)pValue) == ERROR_SUCCESS);
}

static BOOL EtwTiGetEventPropertyUlong(PEVENT_RECORD pRecord, LPCWSTR propName, ULONG* pValue)
{
    PROPERTY_DATA_DESCRIPTOR desc = {0};
    desc.PropertyName = (ULONGLONG)propName;
    desc.ArrayIndex = 0;
    ULONG size = sizeof(ULONG);
    return (TdhGetProperty(pRecord, 0, NULL, 1, &desc, size, (PBYTE)pValue) == ERROR_SUCCESS);
}

static VOID WINAPI EtwTiEventRecordCallback(PEVENT_RECORD pRecord)
{
    if (pRecord == NULL || pRecord->UserData == NULL)
        return;

    USHORT eventId = pRecord->EventHeader.EventDescriptor.Id;
    if (eventId != 1 && eventId != 2 && eventId != 3 && eventId != 4 && eventId != 5 &&
        eventId != 14 && eventId != 21 && eventId != 22 && eventId != 23)
        return;

    ETW_MEMORY_EVENT_DATA ev = {0};
    ev.EventId = eventId;

    /* ETW-TI 事件字段在不同 Windows 版本/更新中命名可能不同，
     * 这里按常见名称尝试解析，失败再回退到 EventHeader.ProcessId。
     * 关键字段缺失时继续下发（地址/大小为 0 不影响威胁判定核心逻辑）。 */
    if (!EtwTiGetEventPropertyInt64(pRecord, L"CallingProcessId", &ev.CallerPid)) {
        if (!EtwTiGetEventPropertyInt64(pRecord, L"CallerProcessId", &ev.CallerPid)) {
            ev.CallerPid = (INT64)pRecord->EventHeader.ProcessId;
        }
    }
    if (!EtwTiGetEventPropertyInt64(pRecord, L"TargetProcessId", &ev.TargetPid)) {
        if (!EtwTiGetEventPropertyInt64(pRecord, L"ProcessId", &ev.TargetPid)) {
            ev.TargetPid = 0;
        }
    }
    EtwTiGetEventPropertyInt64(pRecord, L"BaseAddress", &ev.BaseAddress);
    EtwTiGetEventPropertyInt64(pRecord, L"RegionSize", &ev.RegionSize);
    EtwTiGetEventPropertyUlong(pRecord, L"AllocationType", &ev.AllocationType);

    /* Protection 字段可能叫 ProtectionMask 或 Protection */
    if (!EtwTiGetEventPropertyUlong(pRecord, L"ProtectionMask", &ev.Protection)) {
        if (!EtwTiGetEventPropertyUlong(pRecord, L"Protection", &ev.Protection)) {
            EtwTiGetEventPropertyUlong(pRecord, L"NewProtection", &ev.Protection);
        }
    }

    /* 如果 CallerPid 仍是 0，使用事件头部记录的进程 ID */
    if (ev.CallerPid == 0)
        ev.CallerPid = (INT64)pRecord->EventHeader.ProcessId;

    /* 捕获远程写入/改保护/分配内存及自身改保护的前 256 字节，用于 shellcode 深度分析 */
    {
        DWORD readPid = (DWORD)ev.TargetPid;
        if (readPid == 0) readPid = (DWORD)ev.CallerPid;  /* 自身操作时 TargetPid=0 */
        if (readPid != 0 &&
            (eventId == 14 || eventId == 2 || eventId == 22 ||
             eventId == 1 || eventId == 21))
        {
            HANDLE hTarget = OpenProcess(PROCESS_VM_READ, FALSE, readPid);
            if (hTarget != NULL)
            {
                SIZE_T bytesRead = 0;
                SIZE_T toRead = (ev.RegionSize < 256) ? (SIZE_T)ev.RegionSize : 256;
                if (toRead > 0 &&
                    ReadProcessMemory(hTarget, (LPCVOID)ev.BaseAddress, ev.Payload, toRead, &bytesRead))
                {
                    ev.PayloadSize = (ULONG)bytesRead;
                }
                CloseHandle(hTarget);
            }
        }
    }

    SendEtwMemoryEventToDriver(&ev);
}

static DWORD WINAPI EtwTiConsumerThread(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);

    EVENT_TRACE_LOGFILE logFile = {0};
    logFile.LoggerName = (LPWSTR)L"TianHongEtwTiSession";
    logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logFile.EventRecordCallback = EtwTiEventRecordCallback;

    TRACEHANDLE hTrace = OpenTrace(&logFile);
    if (hTrace == INVALID_PROCESSTRACE_HANDLE) {
        Log_AddLogSimple(QString("ETW-TI OpenTrace 失败: %1").arg(GetLastError()), LOG_ERROR);
        g_bEtwTiRunning = FALSE;
        return 1;
    }

    Log_AddLogSimple("ETW-TI 消费线程已启动", LOG_SUCCESS);
    g_bEtwTiRunning = TRUE;

    ProcessTrace(&hTrace, 1, 0, 0);

    CloseTrace(hTrace);
    g_bEtwTiRunning = FALSE;
    Log_AddLogSimple("ETW-TI 消费线程已停止", LOG_ERROR);
    return 0;
}

static BOOL EtwTiIsDriverServiceRunning()
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM == NULL)
        return FALSE;

    SC_HANDLE hService = OpenServiceW(hSCM, THSD_SERVICE_NAME_W, SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        CloseServiceHandle(hSCM);
        return FALSE;
    }

    BOOL running = FALSE;
    SERVICE_STATUS status = {0};
    if (QueryServiceStatus(hService, &status)) {
        running = (status.dwCurrentState == SERVICE_RUNNING);
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCM);
    return running;
}

static BOOL EtwTiStartConsumer()
{
    /* 先等待驱动服务进入运行态，再尝试打开设备；
     * 避免 KernelProtectionClient 刚启动、驱动尚未初始化完成时，
     * 立即 CreateFile 导致 ERROR_FILE_NOT_FOUND。 */
    if (!EtwTiIsDriverServiceRunning()) {
        int waitRetry = 0;
        Log_AddLogSimple("ETW-TI 等待驱动服务就绪...", LOG_WARN);
        for (waitRetry = 0; waitRetry < ETW_TI_DRIVER_WAIT_RETRIES; waitRetry++) {
            Sleep(ETW_TI_DRIVER_WAIT_INTERVAL_MS);

            if (g_bClientLoadFailed.load()) {
                Log_AddLogSimple("ETW-TI 等待驱动服务被中断：Client 报告驱动加载失败", LOG_WARN);
                return FALSE;
            }

            if (g_bR0EnableCancelled.load()) {
                Log_AddLogSimple("ETW-TI 等待驱动服务被中断：用户取消启用", LOG_WARN);
                return FALSE;
            }

            // 如果 KernelProtectionClient 进程已退出，说明启动失败，不再空等
            if (g_hClientProcess != NULL) {
                DWORD exitCode = 0;
                if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                    g_bClientLoadFailed.store(TRUE);
                    Log_AddLogSimple("ETW-TI 等待驱动服务被中断：KernelProtectionClient 已退出", LOG_WARN);
                    return FALSE;
                }
            }

            if (EtwTiIsDriverServiceRunning()) {
                break;
            }
        }

        if (!EtwTiIsDriverServiceRunning()) {
            Log_AddLogSimple("ETW-TI 等待驱动服务超时", LOG_WARN);
            return FALSE;
        }

        Log_AddLogSimple("ETW-TI 检测到驱动服务已就绪", LOG_INFO);
    }

    /* 确保驱动设备句柄已打开 */
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE) {
        int retry = 0;
        for (retry = 0; retry < ETW_TI_DEVICE_OPEN_RETRIES; retry++) {
            g_hR0DriverDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (g_hR0DriverDevice != INVALID_HANDLE_VALUE) {
                break;
            }

            if (g_bClientLoadFailed.load()) {
                Log_AddLogSimple("ETW-TI 等待驱动设备被中断：Client 报告驱动加载失败", LOG_ERROR);
                return FALSE;
            }

            if (g_bR0EnableCancelled.load()) {
                Log_AddLogSimple("ETW-TI 等待驱动设备被中断：用户取消启用", LOG_ERROR);
                return FALSE;
            }

            // 如果 KernelProtectionClient 进程已退出，说明启动失败，不再空等
            if (g_hClientProcess != NULL) {
                DWORD exitCode = 0;
                if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                    g_bClientLoadFailed.store(TRUE);
                    Log_AddLogSimple("ETW-TI 等待驱动设备被中断：KernelProtectionClient 已退出", LOG_WARN);
                    return FALSE;
                }
            }

            Sleep(ETW_TI_DEVICE_OPEN_RETRY_INTERVAL_MS);
        }

        if (g_hR0DriverDevice == INVALID_HANDLE_VALUE) {
            Log_AddLogSimple(QString("ETW-TI 无法打开驱动设备: %1").arg(GetLastError()), LOG_ERROR);
            return FALSE;
        }
    }

    /* 将当前进程提升为 PS_PROTECTED_ANTIMALWARE_LIGHT，使 ETW-TI provider
     * 允许该进程订阅 Microsoft-Windows-Threat-Intelligence。 */
    {
        PROCESS_SIGNATURE sig = { 0 };
        sig.Pid = GetCurrentProcessId();
        sig.SignerType = 1;        // PsProtectedTypeProtectedLight
        sig.SignatureSigner = 3;   // PsProtectedSignerAntimalware
        DWORD bytesReturned = 0;
        if (!DeviceIoControl(g_hR0DriverDevice, IOCTL_SET_PROCESS_PPL,
            &sig, sizeof(sig), NULL, 0, &bytesReturned, NULL)) {
            Log_AddLogSimple(QString("ETW-TI 设置 PPL 失败: %1").arg(GetLastError()), LOG_ERROR);
        } else {
            Log_AddLogSimple("ETW-TI 已为当前进程设置 PS_PROTECTED_ANTIMALWARE_LIGHT", LOG_SUCCESS);
        }
    }

    // 尽早初始化 ETW-TI 临界区，确保后续任何失败路径都能安全调用 EtwTiStopConsumer
    if (!g_bEtwTiCsInitialized)
    {
        InitializeCriticalSection(&g_csEtwTiDedup);
        InitializeCriticalSection(&g_csEtwTiRateLimit);
        g_bEtwTiCsInitialized = TRUE;
    }

    /* 清理可能残留的旧 session，避免 StartTrace 返回 ERROR_ALREADY_EXISTS
     * 或后续 EnableTraceEx2 因为 session 状态异常而失败。 */
    {
        ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"TianHongEtwTiSession");
        EVENT_TRACE_PROPERTIES* pCleanup = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
        if (pCleanup) {
            ZeroMemory(pCleanup, bufferSize);
            pCleanup->Wnode.BufferSize = bufferSize;
            pCleanup->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            pCleanup->Wnode.ClientContext = 1;
            pCleanup->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
            pCleanup->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            wcscpy((PWCHAR)((PBYTE)pCleanup + pCleanup->LoggerNameOffset),
                   L"TianHongEtwTiSession");
            ControlTrace(0, L"TianHongEtwTiSession", pCleanup, EVENT_TRACE_CONTROL_STOP);
            free(pCleanup);
        }
    }

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(L"TianHongEtwTiSession");
    g_pEtwTiProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (g_pEtwTiProperties == NULL)
        return FALSE;

    ZeroMemory(g_pEtwTiProperties, bufferSize);
    g_pEtwTiProperties->Wnode.BufferSize = bufferSize;
    g_pEtwTiProperties->Wnode.ClientContext = 1;
    g_pEtwTiProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_pEtwTiProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_pEtwTiProperties->MaximumFileSize = 0;
    g_pEtwTiProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wcscpy((PWCHAR)((PBYTE)g_pEtwTiProperties + g_pEtwTiProperties->LoggerNameOffset),
           L"TianHongEtwTiSession");

    ULONG status = StartTrace(&g_hEtwTiSession, L"TianHongEtwTiSession", g_pEtwTiProperties);
    if (status != ERROR_SUCCESS && status != ERROR_ALREADY_EXISTS) {
        Log_AddLogSimple(QString("ETW-TI StartTrace 失败: %1").arg(status), LOG_ERROR);
        free(g_pEtwTiProperties);
        g_pEtwTiProperties = NULL;
        return FALSE;
    }

    ENABLE_TRACE_PARAMETERS enableParams = {0};
    enableParams.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;

    status = EnableTraceEx2(
        g_hEtwTiSession,
        &g_EtwTiProviderGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        TI_KEYWORD_ALLOCVM_REMOTE | TI_KEYWORD_PROTECTVM_REMOTE |
        TI_KEYWORD_WRITEVM_REMOTE | TI_KEYWORD_QUEUEUSERAPC_REMOTE |
        TI_KEYWORD_SETTHREADCONTEXT_REMOTE | TI_KEYWORD_MAPVIEW_REMOTE |
        TI_KEYWORD_ALLOCVM_SELF | TI_KEYWORD_PROTECTVM_SELF |
        TI_KEYWORD_WRITEVM_SELF,
        0, 0, &enableParams);

    if (status != ERROR_SUCCESS) {
        if (status == ERROR_FILE_NOT_FOUND) {
            Log_AddLogSimple(QString("ETW-TI EnableTraceEx2 失败: %1（Threat-Intelligence provider 不可用，基于句柄/线程的检测仍然有效）").arg(status), LOG_ERROR);
        } else if (status == ERROR_ACCESS_DENIED) {
            Log_AddLogSimple(QString("ETW-TI EnableTraceEx2 失败: %1（访问被拒绝。对于 Microsoft-Windows-Threat-Intelligence，进程必须具有 PS_PROTECTED_ANTIMALWARE_LIGHT 保护，或内核调试必须将 EPROCESS->Protection 修补为 0x31）").arg(status), LOG_ERROR);
        } else {
            Log_AddLogSimple(QString("ETW-TI EnableTraceEx2 失败: %1").arg(status), LOG_ERROR);
        }
        ControlTrace(g_hEtwTiSession, L"TianHongEtwTiSession", g_pEtwTiProperties, EVENT_TRACE_CONTROL_STOP);
        free(g_pEtwTiProperties);
        g_pEtwTiProperties = NULL;
        g_hEtwTiSession = 0;
        return FALSE;
    }

    g_hEtwTiThread = CreateThread(NULL, 0, EtwTiConsumerThread, NULL, 0, NULL);
    if (g_hEtwTiThread == NULL) {
        Log_AddLogSimple(QString("ETW-TI CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
        ControlTrace(g_hEtwTiSession, L"TianHongEtwTiSession", g_pEtwTiProperties, EVENT_TRACE_CONTROL_STOP);
        free(g_pEtwTiProperties);
        g_pEtwTiProperties = NULL;
        g_hEtwTiSession = 0;
        return FALSE;
    }

    /* 启动网络 ETW Consumer，用于 C2 检测 */
    if (!EtwTiStartNetworkConsumer()) {
        Log_AddLogSimple("ETW-TI Network 消费线程启动失败，网络 C2 检测已禁用", LOG_ERROR);
    }

    /* 启动 syscall ETW Consumer，用于 direct/indirect syscall 检测 */
    if (!EtwSyscallStartConsumer()) {
        Log_AddLogSimple("ETW-Syscall 消费线程启动失败，直接/间接系统调用检测已禁用", LOG_ERROR);
    }

    /* 启动 DCOM 横向移动检测线程（仅在 DCOM 防护开关开启时） */
    if (pProtectionSettingPage && pProtectionSettingPage->pDcomProtectionSwitch &&
        pProtectionSettingPage->pDcomProtectionSwitch->getIsToggled() && !g_bDcomMonitorRunning)
    {
        g_bDcomMonitorRunning = TRUE;
        g_hDcomMonitorThread = CreateThread(NULL, 0, DcomMonitorThread, NULL, 0, NULL);
        if (g_hDcomMonitorThread == NULL) {
            Log_AddLogSimple(QString("DCOM-Monitor CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
            g_bDcomMonitorRunning = FALSE;
        }
    }

    Log_AddLogSimple("ETW-TI Threat-Intelligence provider 已启用", LOG_SUCCESS);
    return TRUE;
}

static void EtwTiStopConsumer()
{
    g_bEtwTiRunning = FALSE;

    /* 停止 syscall ETW Consumer */
    EtwSyscallStopConsumer();

    /* 停止网络 ETW Consumer */
    EtwTiStopNetworkConsumer();

    /* 停止 DCOM 横向移动检测线程 */
    g_bDcomMonitorRunning = FALSE;
    if (g_hDcomMonitorThread != NULL) {
        WaitForSingleObject(g_hDcomMonitorThread, 3000);
        CloseHandle(g_hDcomMonitorThread);
        g_hDcomMonitorThread = NULL;
    }

    if (g_hEtwTiSession != 0 && g_pEtwTiProperties != NULL) {
        ControlTrace(g_hEtwTiSession, L"TianHongEtwTiSession", g_pEtwTiProperties, EVENT_TRACE_CONTROL_STOP);
    }

    if (g_hEtwTiThread != NULL) {
        WaitForSingleObject(g_hEtwTiThread, 3000);
        CloseHandle(g_hEtwTiThread);
        g_hEtwTiThread = NULL;
    }

    if (g_pEtwTiProperties != NULL) {
        free(g_pEtwTiProperties);
        g_pEtwTiProperties = NULL;
    }

    if (g_bEtwTiCsInitialized)
    {
        DeleteCriticalSection(&g_csEtwTiDedup);
        DeleteCriticalSection(&g_csEtwTiRateLimit);
        g_bEtwTiCsInitialized = FALSE;
    }

    g_EtwTiDedupMap.clear();
    g_EtwTiRateLimitMap.clear();
    g_hEtwTiSession = 0;
}

// ── 向 Client 同步"进程启动前是否完整扫描（阻塞检查）"开关状态 ──
// 对应 ProtectionSettingPage 的 pIsFullScanSwitch：
//   ON  = 阻塞检查（完整扫描，等待 main.cpp 扫描结果后决定放行/终止）
//   OFF = 非阻塞检查（快速告警，仅通知 main.cpp 记录/弹窗，立即放行）
void SendProcessCheckBlockingSettingToClient()
{
    if (!g_bClientConnected || Tran_ClientSocket == INVALID_SOCKET)
        return;

    BOOL bBlocking = (pProtectionSettingPage && pProtectionSettingPage->pIsFullScanSwitch &&
                      pProtectionSettingPage->pIsFullScanSwitch->getIsToggled());

    Packet pkt = {};
    pkt.PacketTyped = PTClientMessage;
    strcpy_s(pkt.InfoTitle, sizeof(pkt.InfoTitle), "SET_FULL_SCAN");
    int enabled = bBlocking ? 1 : 0;
    memcpy(pkt.Message, &enabled, sizeof(int));

    int sent = send(Tran_ClientSocket, (const char*)&pkt, sizeof(Packet), 0);
    if (sent == SOCKET_ERROR)
    {
        Log_AddLogSimple(QString("同步进程检查阻塞模式到 Client 失败: %1").arg(WSAGetLastError()), LOG_ERROR);
    }
    else
    {
        Log_AddLogSimple(QString("同步进程检查阻塞模式到 Client: %1")
                      .arg(bBlocking ? "阻塞（完整扫描）" : "非阻塞（快速告警）"), LOG_INFO);
    }
}

// ── 向 Client 同步内存防护（含 DLL 扫描）开关状态 ──
// 对应 ProtectionSettingPage 的 pMemorySwitch：
//   pMemorySwitch ON  = 启用内存防护，同时启用 DLL 侧载扫描
//   pMemorySwitch OFF = 禁用内存防护，同时禁用 DLL 侧载扫描
void SendUnsignedDllScanSettingToClient()
{
    if (!g_bClientConnected || Tran_ClientSocket == INVALID_SOCKET)
        return;

    BOOL bEnable = (pProtectionSettingPage && pProtectionSettingPage->pMemorySwitch &&
                    pProtectionSettingPage->pMemorySwitch->getIsToggled());
    BOOL bBlocking = (pProtectionSettingPage && pProtectionSettingPage->pIsFullScanSwitch &&
                      pProtectionSettingPage->pIsFullScanSwitch->getIsToggled());

    Packet pkt = {};
    pkt.PacketTyped = PTClientMessage;
    strcpy_s(pkt.InfoTitle, sizeof(pkt.InfoTitle), "SET_UNSIGNED_DLL_SCAN");
    int values[2] = { bEnable ? 1 : 0, bBlocking ? 1 : 0 };
    memcpy(pkt.Message, values, sizeof(values));

    int sent = send(Tran_ClientSocket, (const char*)&pkt, sizeof(Packet), 0);
    if (sent == SOCKET_ERROR)
    {
        Log_AddLogSimple(QString("同步内存防护（含 DLL 扫描）设置到 Client 失败: %1").arg(WSAGetLastError()), LOG_ERROR);
    }
    else
    {
        Log_AddLogSimple(QString("同步内存防护（含 DLL 扫描）设置到 Client: 启用=%1, 阻塞=%2")
                      .arg(bEnable ? "是" : "否")
                      .arg(bBlocking ? "是" : "否"), LOG_INFO);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 勒索诱捕文件 R0 同步与清理函数
// RANSOM_HONEYPOT_RULE_ID_BASE / RANSOM_HONEYPOT_RULES_PER_PATH 定义见文件头部
// ═══════════════════════════════════════════════════════════════════════════

// ── 向驱动添加单条文件规则 ──
static BOOL R0AddFileRule(ULONG ruleId, FILE_OPERATION_MAIN op,
                          const char* fullPath, const char* fileName,
                          const char* fileExt, SECURITY_FLAG_MAIN sef,
                          const char* desc)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return FALSE;

    MAIN_COMM_CONTROL_PACKET pkt = {};
    pkt.Type = 2; // PACKET_TYPE_ADD_FILE_RULE

    MAIN_RULE_FILE_DATA* rule = (MAIN_RULE_FILE_DATA*)pkt.Data;
    rule->RuleId = ruleId;
    rule->Operation = op;
    rule->sef = sef;
    strncpy_s(rule->FullPath, MAIN_MAX_PATH_LEN, fullPath ? fullPath : "", _TRUNCATE);
    strncpy_s(rule->FileName, MAIN_MAX_VALUE_NAME_LEN, fileName ? fileName : "*", _TRUNCATE);
    strncpy_s(rule->FileExt, 32, fileExt ? fileExt : "*", _TRUNCATE);
    strncpy_s(rule->Description, 128, desc ? desc : "", _TRUNCATE);

    DWORD bytesReturned = 0;
    return DeviceIoControl(g_hR0DriverDevice, IOCTL_ADD_FILE_RULE,
                           &pkt, sizeof(pkt), NULL, 0, &bytesReturned, NULL);
}

// ── 从驱动移除单条文件规则 ──
static BOOL R0RemoveFileRule(ULONG ruleId)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return FALSE;

    MAIN_COMM_CONTROL_PACKET pkt = {};
    pkt.Type = 3; // PACKET_TYPE_REMOVE_FILE_RULE
    ULONG* pRuleId = (ULONG*)pkt.Data;
    *pRuleId = ruleId;

    DWORD bytesReturned = 0;
    return DeviceIoControl(g_hR0DriverDevice, IOCTL_REMOVE_FILE_RULE,
                           &pkt, sizeof(pkt), NULL, 0, &bytesReturned, NULL);
}

// ── 清除驱动中所有文件规则 ──
static BOOL R0ClearFileRules()
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return FALSE;

    MAIN_COMM_CONTROL_PACKET pkt = {};
    pkt.Type = 4; // PACKET_TYPE_CLEAR_FILE_RULES

    DWORD bytesReturned = 0;
    return DeviceIoControl(g_hR0DriverDevice, IOCTL_CLEAR_FILE_RULES,
                           &pkt, sizeof(pkt), NULL, 0, &bytesReturned, NULL);
}

// ── 发送文件事件响应给驱动（Allow / Prevent）──
static BOOL R0SendFileEventResponse(LONG responseStatus)
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return FALSE;

    MAIN_COMM_RESPONSE_PACKET pkt = {};
    pkt.Type = 0; // RESPONSE_RESULT
    MAIN_COMM_RESPONSE_RESULT* result = (MAIN_COMM_RESPONSE_RESULT*)pkt.Data;
    result->nts = responseStatus;

    DWORD bytesReturned = 0;
    return DeviceIoControl(g_hR0DriverDevice, IOCTL_RULE_DETECTED_SEND_USER_RESPONSE,
                           &pkt, sizeof(pkt), NULL, 0, &bytesReturned, NULL);
}

// ── 同步勒索诱捕文件路径到驱动（添加 WRITE/DELETE/RENAME 规则）──
static void SyncRansomHoneypotToDriver()
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return;

    int added = 0;

    for (int i = 0; i < RansomDetectPathCount && i < 70; i++)
    {
        const string& filePath = RansomDetectPath[i];
        if (filePath.empty())
            continue;

        // 从完整路径中拆分出目录和文件名
        size_t lastSlash = filePath.find_last_of("\\/");
        string dir, file;
        if (lastSlash != string::npos)
        {
            dir = filePath.substr(0, lastSlash);
            file = filePath.substr(lastSlash + 1);
        }
        else
        {
            dir = filePath;
            file = "*";
        }

        ULONG baseId = RANSOM_HONEYPOT_RULE_ID_BASE + (ULONG)i * RANSOM_HONEYPOT_RULES_PER_PATH;
        const char* desc = "RansomHoneypot";

        if (R0AddFileRule(baseId,     FILE_OP_WRITE,  dir.c_str(), file.c_str(), "*", SEF_MAIN_NOT_SYSTEM_BLOCKED, desc)) added++;
        if (R0AddFileRule(baseId + 1, FILE_OP_DELETE, dir.c_str(), file.c_str(), "*", SEF_MAIN_NOT_SYSTEM_BLOCKED, desc)) added++;
        if (R0AddFileRule(baseId + 2, FILE_OP_RENAME, dir.c_str(), file.c_str(), "*", SEF_MAIN_NOT_SYSTEM_BLOCKED, desc)) added++;
    }

    // 对诱捕目录也添加规则（监控目录内任意文件的写入/删除/重命名）
    for (int i = 0; i < RansomDetectPathDicCount && i < 70; i++)
    {
        const string& dirPath = RansomDetectPathDic[i];
        if (dirPath.empty())
            continue;

        ULONG baseId = RANSOM_HONEYPOT_RULE_ID_BASE + 70 * RANSOM_HONEYPOT_RULES_PER_PATH
                       + (ULONG)i * RANSOM_HONEYPOT_RULES_PER_PATH;
        const char* desc = "RansomHoneypotDir";

        if (R0AddFileRule(baseId,     FILE_OP_WRITE,  dirPath.c_str(), "*", "*", SEF_MAIN_NOT_SYSTEM_BLOCKED, desc)) added++;
        if (R0AddFileRule(baseId + 1, FILE_OP_DELETE, dirPath.c_str(), "*", "*", SEF_MAIN_NOT_SYSTEM_BLOCKED, desc)) added++;
        if (R0AddFileRule(baseId + 2, FILE_OP_RENAME, dirPath.c_str(), "*", "*", SEF_MAIN_NOT_SYSTEM_BLOCKED, desc)) added++;
    }

    Log_AddLogSimple(QString("已同步 %1 条勒索诱捕规则到驱动").arg(added), LOG_SUCCESS);
}

// ── 从驱动移除勒索诱捕规则 ──
static void UnsyncRansomHoneypotFromDriver()
{
    if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
        return;

    int removed = 0;

    for (int i = 0; i < RansomDetectPathCount && i < 70; i++)
    {
        ULONG baseId = RANSOM_HONEYPOT_RULE_ID_BASE + (ULONG)i * RANSOM_HONEYPOT_RULES_PER_PATH;
        if (R0RemoveFileRule(baseId)) removed++;
        if (R0RemoveFileRule(baseId + 1)) removed++;
        if (R0RemoveFileRule(baseId + 2)) removed++;
    }

    for (int i = 0; i < RansomDetectPathDicCount && i < 70; i++)
    {
        ULONG baseId = RANSOM_HONEYPOT_RULE_ID_BASE + 70 * RANSOM_HONEYPOT_RULES_PER_PATH
                       + (ULONG)i * RANSOM_HONEYPOT_RULES_PER_PATH;
        if (R0RemoveFileRule(baseId)) removed++;
        if (R0RemoveFileRule(baseId + 1)) removed++;
        if (R0RemoveFileRule(baseId + 2)) removed++;
    }

    Log_AddLogSimple(QString("已从驱动移除 %1 条勒索诱捕规则").arg(removed), LOG_SUCCESS);
}

// ── 清理勒索诱捕文件和目录 ──
static void CleanupRansomHoneypotFiles()
{
    for (int i = 0; i < RansomDetectPathCount; i++)
    {
        DeleteFileA(RansomDetectPath[i].c_str());
    }

    for (int i = 0; i < RansomDetectPathDicCount; i++)
    {
        RemoveDirectoryA(RansomDetectPathDic[i].c_str());
    }
}

// ── 重建勒索诱捕文件和目录 ──
static void RebuildRansomHoneypotFiles()
{
    for (int i = 0; i < RansomDetectPathDicCount; i++)
    {
        CreateDirectoryA(RansomDetectPathDic[i].c_str(), NULL);
    }

    srand(static_cast<unsigned int>(time(0)));

    const int minSize = 10 * 1024;       // 10KB
    const int maxSize = 10 * 1024 * 1024; // 10MB

    BOOL allOk = TRUE;
    for (int i = 0; i < RansomDetectPathCount; i++)
    {
        int fileSize = rand() % (maxSize - minSize + 1) + minSize;

        ofstream outFile(RansomDetectPath[i].c_str(), ios::binary);
        if (!outFile)
        {
            allOk = FALSE;
            break;
        }

        for (int j = 0; j < fileSize; ++j)
        {
            outFile.put(static_cast<char>(rand() % (126 - 33 + 1) + 33));
        }
        outFile.close();
    }

    if (!allOk)
    {
        Log_AddLogSimple("勒索诱捕文件重建部分失败", LOG_ERROR);
    }
}

// ── 同步勒索诱捕文件路径到所有已连接的 R3 DLL 客户端 ──
// 开关切换时调用，确保已连接的 DLL 能及时获取最新诱捕文件路径。
// 仅在 R0 未启用时需要（R0 启用时由驱动规则监控，不走 DLL）。
// force=true 时跳过 g_bR0ProtectionEnabled 检查，用于 R0 启用后清空 R3 监控列表。
static void SyncRansomHoneypotToR3Clients(bool enable, bool force = false)
{
    if (g_bR0ProtectionEnabled && !force)
        return;  // R0 启用时走驱动规则，不需要通知 DLL（force 例外）

    int totalPaths = enable ? (RansomDetectPathCount + RansomDetectPathDicCount) : 0;

    for (int i = 0; i < MAX_CLIENT_COUNT; i++)
    {
        if (Tran_Client[i] == NULL || Tran_Client[i] == INVALID_SOCKET)
            continue;
        if (Tran_IsSocketClosed(Tran_Client[i]))
            continue;

        /* 先发送文件数量，DLL 收到后开始接收路径 */
        Tran_SendPacket(Tran_Client[i], (char*)"", PTHideFile, (char*)"HideFileCount", totalPaths);

        if (!enable)
            continue;  /* 关闭时只需通知数量为 0，DLL 会清空监控列表 */

        /* 发送诱捕文件路径 */
        for (int j = 0; j < RansomDetectPathCount; j++)
        {
            Tran_SendPacket(Tran_Client[i], (char*)(RansomDetectPath[j]).c_str(), PTHideFile, (char*)"", 0);
            Tran_SendPacket(Tran_Client[i], (char*)File_GetShortFileName(RansomDetectPath[j]).c_str(), PTHideFile, (char*)"", 0);
        }

        /* 发送诱捕目录路径 */
        for (int j = 0; j < RansomDetectPathDicCount; j++)
        {
            Tran_SendPacket(Tran_Client[i], (char*)(RansomDetectPathDic[j]).c_str(), PTHideFile, (char*)"", 0);
            Tran_SendPacket(Tran_Client[i], (char*)File_GetShortFileName(RansomDetectPathDic[j]).c_str(), PTHideFile, (char*)"", 0);
        }
    }
}

// ── 通知 R3 DLL R0 驱动启用/禁用状态 ──
// DLL 收到通知后，在注册表/文件拦截 hook 中过滤 R0 已处理的规则类型，
// 避免重复弹窗。R0 负责日志和弹窗，R3 只做静默过滤。
static void NotifyR3DllAboutR0Status(BOOL r0Enabled)
{
    for (int i = 0; i < MAX_CLIENT_COUNT; i++)
    {
        if (Tran_Client[i] == NULL || Tran_Client[i] == INVALID_SOCKET)
            continue;
        if (Tran_IsSocketClosed(Tran_Client[i]))
            continue;

        // 使用 PTConnection 包发送 R0 状态，WarnTitle="R0Status"，Pid=1表示启用，0表示禁用
        Tran_SendPacket(Tran_Client[i], (char*)"", PTConnection, (char*)"R0Status", r0Enabled);
    }
}

// 驱动防护按钮状态变化槽函数
void OnDriverProtectionToggled(bool checked)
{
    if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionSwitch)
    {
        pProtectionSettingPage->pDriverProtectionSwitch->setVisible(false);
    }

    if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionRing)
    {
        pProtectionSettingPage->pDriverProtectionRing->setVisible(true);
        pProtectionSettingPage->pDriverProtectionRing->setIsBusying(true);
    }

    if (checked)
    {
        g_bPendingDllPathSet = TRUE;
        g_bClientLoadFailed.store(FALSE);
        g_bR0EnableCancelled.store(FALSE);
        g_bDriverReady.store(FALSE);
        Log_AddLogSimple("驱动防护模式已启用，正在启动 KernelProtectionClient...", LOG_SUCCESS);

        QtConcurrent::run([=]() {
            bool processStarted = StartKernelProtectionClient();
            bool etwOk = FALSE;
            bool kernelRecvOk = FALSE;

            if (processStarted)
            {
                // 等待 Client 完成认证并发送 READY（意味着驱动已加载完成）
                // 超时需覆盖 InstallDriver 内部等待驱动服务 RUNNING（最多 15s）
                // + 设备 CreateFile 重试（最多 15s）+ socket 连接/认证（约 5s）
                const DWORD READY_TIMEOUT_MS = 60000;
                const DWORD READY_WAIT_INTERVAL_MS = 500;
                DWORD dwStartTick = GetTickCount();
                BOOL clientReady = FALSE;
                while (GetTickCount() - dwStartTick < READY_TIMEOUT_MS)
                {
                    if (g_bDriverReady.load())
                    {
                        clientReady = TRUE;
                        break;
                    }

                    if (g_bClientLoadFailed.load())
                    {
                        Log_AddLogSimple("Client 报告驱动加载失败，取消启用 R0 防护", LOG_ERROR);
                        break;
                    }

                    if (g_bR0EnableCancelled.load())
                    {
                        Log_AddLogSimple("用户取消启用 R0 防护", LOG_WARN);
                        break;
                    }

                    if (g_hClientProcess != NULL)
                    {
                        DWORD exitCode = 0;
                        if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode != STILL_ACTIVE)
                        {
                            g_bClientLoadFailed.store(TRUE);
                            Log_AddLogSimple("KernelProtectionClient 在就绪前已退出", LOG_ERROR);
                            break;
                        }
                    }

                    Sleep(READY_WAIT_INTERVAL_MS);
                }

                // 处理循环退出时 Client 恰好在最后一轮 Sleep 期间就绪的边界情况
                if (!clientReady && g_bDriverReady.load())
                {
                    clientReady = TRUE;
                }

                if (clientReady)
                {
                    // 若 READY 处理器尚未设置 DLL 路径，则在这里补设；否则直接复用
                    if (g_bPendingDllPathSet)
                    {
                        R0SetDllInjectPath();
                        g_bPendingDllPathSet = FALSE;
                    }

                    etwOk = EtwTiStartConsumer();
                    kernelRecvOk = TRUE; /* 事件接收由 KernelProtectionClient 负责，
                                          * main.cpp 不再直接轮询 IOCTL_RULE_DETECTED_REQUEST，
                                          * 避免与 Client 竞争消费驱动事件。 */

                    // 驱动设备已打开即认为 R0 防护启用。
                    // ETW-TI Threat-Intelligence provider 需要 PS_PROTECTED_ANTIMALWARE_LIGHT，
                    // 当前驱动实现拒绝直接写入 EPROCESS->Protection，因此该 provider 可能不可用。
                    // 缺少 ETW-TI 时，ObRegisterCallbacks / PsSetCreateThreadNotifyRoutine /
                    // PsSetLoadImageNotifyRoutine 等内核回调仍然工作，只是少了一部分高级注入检测。
                    if (kernelRecvOk && g_hR0DriverDevice != INVALID_HANDLE_VALUE)
                    {
                        g_bR0ProtectionEnabled = TRUE;
                        if (!etwOk)
                        {
                            Log_AddLogSimple("R0 防护已启用，但 ETW-TI Threat-Intelligence provider 未启用（不影响内核回调防护）", LOG_SUCCESS);
                        }

                        // R0 启用时，若勒索防护开关和文件防护开关均已开启，同步诱捕规则到驱动
                        if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionSwitch &&
                            pProtectionSettingPage->pRansomProtectionSwitch->getIsToggled() &&
                            pProtectionSettingPage->pFileSwitch &&
                            pProtectionSettingPage->pFileSwitch->getIsToggled())
                        {
                            SyncRansomHoneypotToDriver();
                            // R0 规则已同步到驱动，清空 R3 DLL 监控列表避免双路同时拦截冲突
                            SyncRansomHoneypotToR3Clients(false, true);
                        }

                        // 通知 DLL R0 已启用，DLL 侧过滤 R0 已处理的规则类型
                        NotifyR3DllAboutR0Status(TRUE);
                    }
                    else
                    {
                        Log_AddLogSimple(QString("R0 驱动启用失败：etwOk=%1 kernelRecvOk=%2 device=%3")
                                      .arg(etwOk).arg(kernelRecvOk)
                                      .arg(g_hR0DriverDevice != INVALID_HANDLE_VALUE ? "ok" : "invalid"), LOG_ERROR);
                        g_bPendingDllPathSet = FALSE;
                    }
                }
                else
                {
                    Log_AddLogSimple("KernelProtectionClient 未在预期时间内就绪，取消启用 R0 防护", LOG_WARN);
                    g_bPendingDllPathSet = FALSE;
                }
            }
            else
            {
                g_bPendingDllPathSet = FALSE;
            }

            QMetaObject::invokeMethod(qApp, [=]() {
                if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionSwitch)
                {
                    pProtectionSettingPage->pDriverProtectionSwitch->setVisible(true);
                    if (!g_bR0ProtectionEnabled)
                    {
                        pProtectionSettingPage->pDriverProtectionSwitch->setIsToggled(false);
                    }
                }

                if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionRing)
                {
                    pProtectionSettingPage->pDriverProtectionRing->setVisible(false);
                    pProtectionSettingPage->pDriverProtectionRing->setIsBusying(false);
                }
            }, Qt::QueuedConnection);
        });
    }
    else
    {
        g_bR0ProtectionEnabled = FALSE;
        g_bPendingDllPathSet = FALSE;

        // 通知 DLL R0 已禁用，DLL 恢复正常的注册表/文件拦截
        NotifyR3DllAboutR0Status(FALSE);

        // 若用户在中转启用过程中关闭开关，立即恢复按钮显示并通知工作线程结束等待
        if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionRing &&
            pProtectionSettingPage->pDriverProtectionRing->isVisible())
        {
            g_bR0EnableCancelled.store(TRUE);

            if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionSwitch)
            {
                bool oldBlock = pProtectionSettingPage->pDriverProtectionSwitch->signalsBlocked();
                pProtectionSettingPage->pDriverProtectionSwitch->blockSignals(true);
                pProtectionSettingPage->pDriverProtectionSwitch->setVisible(true);
                pProtectionSettingPage->pDriverProtectionSwitch->setIsToggled(false);
                pProtectionSettingPage->pDriverProtectionSwitch->blockSignals(oldBlock);
            }
            pProtectionSettingPage->pDriverProtectionRing->setVisible(false);
            pProtectionSettingPage->pDriverProtectionRing->setIsBusying(false);
        }

        // 如果 Client 已经因为驱动加载失败而退出，避免记录"正在停止"这种不准确的日志
        BOOL clientAlreadyStopped = FALSE;
        if (g_bClientLoadFailed.load())
        {
            clientAlreadyStopped = TRUE;
        }
        else if (g_hClientProcess != NULL)
        {
            // 若 Client 正在退出，短暂等待避免误判为仍在运行
            WaitForSingleObject(g_hClientProcess, 300);

            DWORD exitCode = 0;
            if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode != STILL_ACTIVE)
            {
                clientAlreadyStopped = TRUE;
            }
        }
        else
        {
            clientAlreadyStopped = TRUE;
        }

        if (clientAlreadyStopped)
        {
            Log_AddLogSimple("驱动防护模式已禁用，KernelProtectionClient 已停止", LOG_INFO);
        }
        else
        {
            Log_AddLogSimple("驱动防护模式已禁用，正在停止 KernelProtectionClient...", LOG_INFO);
        }

        QtConcurrent::run([=]() {
            if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
            {
                BOOL bR3Enabled = FALSE;
                DWORD bytesReturned = 0;
                DeviceIoControl(
                    g_hR0DriverDevice,
                    IOCTL_SET_R3_PROTECTION_ENABLED,
                    &bR3Enabled,
                    sizeof(bR3Enabled),
                    NULL, 0,
                    &bytesReturned, NULL);

                BOOL bBehaviorEnabled = FALSE;
                DeviceIoControl(
                    g_hR0DriverDevice,
                    IOCTL_SET_BEHAVIOR_DETECTION_ENABLED,
                    &bBehaviorEnabled,
                    sizeof(bBehaviorEnabled),
                    NULL, 0,
                    &bytesReturned, NULL);

                BOOL bProcessProtectionEnabled = FALSE;
                DeviceIoControl(
                    g_hR0DriverDevice,
                    IOCTL_SET_PROCESS_PROTECTION_ENABLED,
                    &bProcessProtectionEnabled,
                    sizeof(bProcessProtectionEnabled),
                    NULL, 0,
                    &bytesReturned, NULL);

                // R0 禁用前，移除勒索诱捕规则
                UnsyncRansomHoneypotFromDriver();
                // R0 规则已移除，若勒索防护和文件防护仍开启，恢复 R3 DLL 监控
                if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionSwitch &&
                    pProtectionSettingPage->pRansomProtectionSwitch->getIsToggled() &&
                    pProtectionSettingPage->pFileSwitch &&
                    pProtectionSettingPage->pFileSwitch->getIsToggled())
                {
                    SyncRansomHoneypotToR3Clients(true, true);
                }
            }

            EtwTiStopConsumer();
            StopKernelProtectionClient();

            QMetaObject::invokeMethod(qApp, [=]() {
                if (pProtectionSettingPage && pProtectionSettingPage->pBehaviorDetectionSwitch)
                {
                    pProtectionSettingPage->pBehaviorDetectionSwitch->setIsToggled(false);
                }

                if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionSwitch)
                {
                    pProtectionSettingPage->pDriverProtectionSwitch->setVisible(true);
                }

                if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionRing)
                {
                    pProtectionSettingPage->pDriverProtectionRing->setVisible(false);
                    pProtectionSettingPage->pDriverProtectionRing->setIsBusying(false);
                }
            }, Qt::QueuedConnection);
        });
    }
}

LONG WINAPI catchExceptionFileter(_EXCEPTION_POINTERS* pExceptionInfo)
{
	// 防止重复处理
	static volatile LONG processing = FALSE;
	if (InterlockedExchange(&processing, TRUE)) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CString Info;

	// 获取异常代码描述
	LPCTSTR szExceptionType = _T("未知异常");
	DWORD dwCode = pExceptionInfo->ExceptionRecord->ExceptionCode;

	switch (dwCode) {
	case EXCEPTION_ACCESS_VIOLATION:         szExceptionType = _T("内存访问违例"); break;
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:    szExceptionType = _T("数组越界"); break;
	case EXCEPTION_BREAKPOINT:                szExceptionType = _T("断点异常"); break;
	case EXCEPTION_DATATYPE_MISALIGNMENT:     szExceptionType = _T("数据类型未对齐"); break;
	case EXCEPTION_FLT_DIVIDE_BY_ZERO:        szExceptionType = _T("浮点数除零"); break;
	case EXCEPTION_INT_DIVIDE_BY_ZERO:        szExceptionType = _T("整数除零"); break;
	case EXCEPTION_STACK_OVERFLOW:            szExceptionType = _T("栈溢出"); break;
	}

	Info.Format(L"天宏安全防御发现一个错误：\n"
		L"异常类型：%s\n"
		L"异常地址：0x%p\n"
		L"错误代码：0x%08X (%d)\n\n"
		L"程序将尝试保存数据并退出...",
		szExceptionType,
		pExceptionInfo->ExceptionRecord->ExceptionAddress,
		dwCode, dwCode);

	// 使用更安全的 MessageBox 选项
	MessageBox(GetActiveWindow(), Info, L"程序错误",
		MB_TOPMOST | MB_ICONERROR | MB_SETFOREGROUND);

	ExcepExit = TRUE;

	// 尝试清理资源
	if (pMainWindow) {
		pMainWindow->CloseWindow();
	}

	// 通知KernelProtectionClient退出
    if (g_bClientConnected && Tran_ClientSocket != INVALID_SOCKET)
    {
        Packet quitPkt = {};
        quitPkt.PacketTyped = PTClientMessage;
        strcpy_s(quitPkt.InfoTitle, sizeof(quitPkt.InfoTitle), "QUIT");
        if (send(Tran_ClientSocket, (const char*)&quitPkt, sizeof(Packet), 0) == SOCKET_ERROR)
        {
            Log_AddLogSimple("通知 Client 退出时 send 失败", LOG_ERROR);
        }
        closesocket(Tran_ClientSocket);
        Tran_ClientSocket = INVALID_SOCKET;
        g_bClientConnected = FALSE;
    }

	// 让异常继续传递，以便生成 crash dump
	return EXCEPTION_CONTINUE_SEARCH;
}

// 前向声明（定义在文件后部）
bool IsSystemAbusedProgram(const std::wstring& procPath, const std::wstring& exeName,
    const std::wstring& systemRootPath, const std::wstring& sysWow64Path);
bool CheckMaliciousProcess(const std::string& processPath, const std::string& processArgs);

// ═══════════════════════════════════════════════════════════════════════════
// 提取命令宿主（cmd/powershell/wscript/cscript/mshta/regsvr32/rundll32）
// 命令行中实际要执行的文件/脚本/DLL，用于对真实载荷做静态扫描。
// ═══════════════════════════════════════════════════════════════════════════
static std::vector<std::wstring> ExtractCommandLineTargetFiles(const std::wstring& procPath, const std::wstring& cmdLine)
{
    std::vector<std::wstring> result;
    if (cmdLine.empty()) return result;

    bool isCmdHost =
        IsSystemAbusedProgram(procPath, L"cmd.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"WindowsPowerShell\\v1.0\\powershell.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"powershell.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"pwsh.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"WScript.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"CScript.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"mshta.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"regsvr32.exe", wcSystemRootPath, wcSysWow64Path) ||
        IsSystemAbusedProgram(procPath, L"rundll32.exe", wcSystemRootPath, wcSysWow64Path);

    if (!isCmdHost) return result;

    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmdLine.c_str(), &argc);
    if (!argv) return result;

    auto IsSwitch = [](const std::wstring& s) -> bool {
        return !s.empty() && (s[0] == L'/' || s[0] == L'-');
    };

    auto StripQuotes = [](std::wstring s) -> std::wstring {
        if (!s.empty() && (s.front() == L'\"' || s.front() == L'\'')) s.erase(s.begin());
        if (!s.empty() && (s.back() == L'\"' || s.back() == L'\'')) s.pop_back();
        return s;
    };

    auto AddIfFile = [&](const std::wstring& token) {
        std::wstring path = StripQuotes(token);
        if (path.empty()) return;
        if (IsSwitch(path)) return;
        if (path.find(L"://") != std::wstring::npos) return;          // URL/协议
        if (_wcsicmp(path.c_str(), procPath.c_str()) == 0) return;    // 跳过宿主自身
        DWORD attr = GetFileAttributesW(path.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0) {
            result.push_back(path);
        }
    };

    auto ExtractPathsFromString = [&](const std::wstring& str) {
        // 匹配引号内路径或无引号本地/UNC路径
        std::wregex re(L"\"([^\"]+)\"|'([^']+)'|([A-Za-z]:\\\\[^\\s\"]+|\\\\\\\\[^\\s\"]+)");
        std::wsmatch m;
        std::wstring::const_iterator start = str.cbegin();
        while (std::regex_search(start, str.cend(), m, re)) {
            std::wstring candidate = m[1].matched ? m[1].str() : (m[2].matched ? m[2].str() : m[3].str());
            AddIfFile(candidate);
            start = m.suffix().first;
            if (result.size() >= 8) break;
        }
    };

    if (IsSystemAbusedProgram(procPath, L"cmd.exe", wcSystemRootPath, wcSysWow64Path)) {
        if (argc >= 3) {
            std::wstring opt = argv[1];
            std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
            if (opt == L"/c" || opt == L"/k" || opt == L"-c" || opt == L"-k") {
                ExtractPathsFromString(argv[2]);
            }
        }
    }
    else if (IsSystemAbusedProgram(procPath, L"WindowsPowerShell\\v1.0\\powershell.exe", wcSystemRootPath, wcSysWow64Path) ||
             IsSystemAbusedProgram(procPath, L"powershell.exe", wcSystemRootPath, wcSysWow64Path) ||
             IsSystemAbusedProgram(procPath, L"pwsh.exe", wcSystemRootPath, wcSysWow64Path)) {
        for (int i = 1; i < argc - 1; ++i) {
            std::wstring opt = argv[i];
            std::transform(opt.begin(), opt.end(), opt.begin(), ::tolower);
            if (opt == L"-file" || opt == L"/file") {
                AddIfFile(argv[i + 1]);
                break;
            }
            if (opt == L"-command" || opt == L"/command" || opt == L"-c") {
                ExtractPathsFromString(argv[i + 1]);
                break;
            }
        }
    }
    else {
        // WScript/CScript/mshta/regsvr32/rundll32：第一个非开关参数即为目标文件/DLL
        for (int i = 1; i < argc; ++i) {
            if (IsSwitch(argv[i])) continue;
            std::wstring arg = argv[i];
            // rundll32 参数格式：dll路径,EntryPoint
            if (IsSystemAbusedProgram(procPath, L"rundll32.exe", wcSystemRootPath, wcSysWow64Path)) {
                size_t commaPos = arg.find(L',');
                if (commaPos != std::wstring::npos) arg = arg.substr(0, commaPos);
            }
            AddIfFile(arg);
            if (IsSystemAbusedProgram(procPath, L"regsvr32.exe", wcSystemRootPath, wcSysWow64Path) ||
                IsSystemAbusedProgram(procPath, L"rundll32.exe", wcSystemRootPath, wcSysWow64Path) ||
                IsSystemAbusedProgram(procPath, L"mshta.exe", wcSystemRootPath, wcSysWow64Path)) {
                break;
            }
        }
    }

    LocalFree(argv);
    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// PowerShell 混淆命令行解析与解码
// ═══════════════════════════════════════════════════════════════════════════

// Base64 解码（支持 PowerShell 的 -EncodedCommand 格式）
// PowerShell 使用 UTF-16LE 编码的 Base64，需要特殊处理
static std::string Base64DecodePowerShell(const std::string& base64Input)
{
    std::string output;
    if (base64Input.empty()) return output;

    // 移除空白字符和填充符
    std::string cleaned;
    cleaned.reserve(base64Input.size());
    for (char c : base64Input) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
            cleaned.push_back(c);
        }
    }

    // 补齐到 4 的倍数
    while (cleaned.size() % 4 != 0) {
        cleaned.push_back('=');
    }

    static const std::string b64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::vector<unsigned char> bytes;
    bytes.reserve(cleaned.size() * 3 / 4);

    for (size_t i = 0; i < cleaned.size(); i += 4) {
        auto idx = [&](char c) -> int {
            size_t pos = b64_chars.find(c);
            if (pos == std::string::npos) return -1;
            return static_cast<int>(pos);
        };

        int a = idx(cleaned[i]);
        int b = (i + 1 < cleaned.size()) ? idx(cleaned[i + 1]) : 0;
        int c = (i + 2 < cleaned.size()) ? idx(cleaned[i + 2]) : -1;
        int d = (i + 3 < cleaned.size()) ? idx(cleaned[i + 3]) : -1;

        if (a < 0 || b < 0) break;

        bytes.push_back(static_cast<unsigned char>((a << 2) | (b >> 4)));
        if (c >= 0) {
            bytes.push_back(static_cast<unsigned char>((b << 4) | (c >> 2)));
        }
        if (d >= 0 && c >= 0) {
            bytes.push_back(static_cast<unsigned char>((c << 6) | d));
        }
    }

    // 将 UTF-16LE 转换为 UTF-8
    if (bytes.size() >= 2 && (bytes.size() % 2) == 0) {
        // 可能是 UTF-16LE（PowerShell 的 EncodedCommand 格式）
        std::wstring utf16;
        utf16.reserve(bytes.size() / 2);
        for (size_t i = 0; i < bytes.size(); i += 2) {
            wchar_t ch = static_cast<wchar_t>(bytes[i]) | (static_cast<wchar_t>(bytes[i + 1]) << 8);
            utf16.push_back(ch);
        }
        int needed = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, NULL, NULL);
        if (needed > 0) {
            output.resize(needed - 1);
            WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, &output[0], needed, NULL, NULL);
            return output;
        }
    }

    // 如果不是 UTF-16LE，直接当 UTF-8 返回
    output.assign(bytes.begin(), bytes.end());
    return output;
}

// 提取 PowerShell 命令行中的 -EncodedCommand / -enc 参数值
static std::string ExtractPowerShellEncodedCommand(const std::string& cmdLine)
{
    std::string result;
    std::string lower = cmdLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // 查找 -EncodedCommand 或 -enc 后面的 Base64 字符串
    size_t pos = 0;
    while ((pos = lower.find("-encodedcommand", pos)) != std::string::npos ||
           (pos = lower.find("-enc", pos)) != std::string::npos) {
        // 跳过参数名本身
        if (lower.substr(pos, 3) == "-en") {
            // -encodedcommand
            pos += 15;
        } else {
            // -enc
            pos += 4;
        }

        // 跳过空白和冒号
        while (pos < lower.size() && (lower[pos] == ' ' || lower[pos] == ':' || lower[pos] == '\t')) {
            pos++;
        }

        // 提取 Base64 字符串
        std::string b64;
        while (pos < lower.size() &&
               ((lower[pos] >= 'a' && lower[pos] <= 'z') ||
                (lower[pos] >= 'A' && lower[pos] <= 'Z') ||
                (lower[pos] >= '0' && lower[pos] <= '9') ||
                lower[pos] == '+' || lower[pos] == '/' || lower[pos] == '=')) {
            b64 += cmdLine[pos];  // 使用原始大小写
            pos++;
        }

        if (b64.size() >= 20) {  // Base64 至少有一定长度才有意义
            result = Base64DecodePowerShell(b64);
            if (!result.empty()) {
                return result;
            }
        }

        pos++;
    }

    return result;
}

// 检测 PowerShell 混淆模式
static bool DetectPowerShellObfuscation(const std::string& cmdLine, std::string& obfuscationType)
{
    std::string lower = cmdLine;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // -EncodedCommand / -enc：Base64 编码命令
    if (lower.find("-encodedcommand") != std::string::npos ||
        lower.find("-enc ") != std::string::npos ||
        lower.find("-enc:") != std::string::npos) {
        obfuscationType = "Base64编码命令";
        return true;
    }

    // -f 格式化字符串混淆
    if (lower.find("-f ") != std::string::npos || lower.find("-f`") != std::string::npos) {
        // 检测是否配合 [char] 或 [byte] 数组
        if (lower.find("[char]") != std::string::npos || lower.find("[byte]") != std::string::npos) {
            obfuscationType = "格式化字符串混淆";
            return true;
        }
    }

    // -replace 替换混淆
    if (lower.find("-replace") != std::string::npos && lower.find("'") != std::string::npos) {
        obfuscationType = "字符串替换混淆";
        return true;
    }

    // 变量拼接混淆（$x + $y）
    int plusCount = 0;
    for (size_t i = 0; i < lower.size(); i++) {
        if (lower[i] == '$' && i + 1 < lower.size() && isalpha(lower[i + 1])) {
            plusCount++;
        }
    }
    if (plusCount >= 5 && lower.find('+') != std::string::npos) {
        obfuscationType = "变量拼接混淆";
        return true;
    }

    // 反引号转义混淆
    if (std::count(lower.begin(), lower.end(), '`') > 5) {
        obfuscationType = "反引号转义混淆";
        return true;
    }

    // IEX / Invoke-Expression 动态执行
    if (lower.find("iex") != std::string::npos || lower.find("invoke-expression") != std::string::npos) {
        obfuscationType = "动态执行混淆";
        return true;
    }

    return false;
}

// 使用 BatchScan 分析命令行内容（静态内容指纹 + 语言检测器启发式）。
// 原静态指纹规则已从 Behavior Sandbox 迁移至 BatchScan，命令行路径需
// 同步改走 ScriptDetectionEngine 以确保迁移后检测不丢失。
static ScriptSandbox::DetectionResult AnalyzeCommandLineWithSandbox(const std::string& content, const std::string& fileExt = "")
{
    ScriptSandbox::DetectionResult result = { false, "Clean", 0, {}, {} };

    try {
        // 限制分析长度，避免过长命令导致性能问题
        std::string limited = content.substr(0, 8192);

        ScriptDetectionEngine engine;
        ScriptLanguage langHint = ScriptLanguage::Unknown;
        if (!fileExt.empty()) {
            if (fileExt == ".ps1" || fileExt == ".psm1" || fileExt == ".psd1" ||
                fileExt == ".ps1xml" || fileExt == ".psc1" || fileExt == ".cdxml")
                langHint = ScriptLanguage::PowerShell;
            else if (fileExt == ".bat" || fileExt == ".cmd")
                langHint = ScriptLanguage::CMD;
            else if (fileExt == ".vbs" || fileExt == ".vbe")
                langHint = ScriptLanguage::VBS;
            else if (fileExt == ".js" || fileExt == ".jse" || fileExt == ".wsf")
                langHint = ScriptLanguage::JavaScript;
        }
        RiskReport report = engine.scan(limited, langHint);

        if (report.isMalicious) {
            result.malicious = true;
            result.family = report.family;
            result.severity_score = report.riskScore;
            result.triggered_rules = report.reasons;
            result.execution_log.push_back("BatchScan: " + report.family +
                " (risk=" + std::to_string(report.riskScore) + ")");
        }
    } catch (...) {
        // 分析异常不影响主流程
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════════════
// 命令行风险检测（R3 DLL 与 R0 驱动进程创建检查共用）
// 输入：进程 PID、进程路径、命令行文本
// 输出：是否命中风险、告警标题、告警内容
// ═══════════════════════════════════════════════════════════════════════════
struct CommandLineRiskResult {
    bool detected;
    bool autoBlock;   // 命令行可疑：无需用户确认，直接拦截（上升到进程树 suspend 级别）
    std::string alertTitle;
    std::string sendOut;
};

static CommandLineRiskResult DetectCommandLineRisk(int pid, const std::string& procPath, const std::string& cmdLine)
{
    CommandLineRiskResult result = { false, false, "", "" };

    if (cmdLine.empty() || procPath.empty())
        return result;

    static int StartTime = 0;
    static int OpenCMDCount = 0;

    std::string sendOut;
    std::string alertTitle;
    bool beenInHandling = FALSE;

    std::wstring wsProcPath = QString::fromLocal8Bit(procPath.c_str()).toStdWString();
    const std::string& sCmd = cmdLine;

    if (IsSystemAbusedProgram(wsProcPath, L"cmd.exe", wcSystemRootPath, wcSysWow64Path))
    {
        int NowTime = time(NULL);

        if (StartTime == 0) StartTime = NowTime;

        OpenCMDCount++;

        if (OpenCMDCount > 4 && double(NowTime - StartTime) / OpenCMDCount < 1)
        {
            beenInHandling = TRUE;
            alertTitle = "检测到有进程正在大量弹出cmd弹窗，建议阻止";
            sendOut = "[窗口防护·警告] 允许进程大量弹出cmd弹窗，可能影响使用电脑。\r\n\r\n命令：" + sCmd;
        }
        else
        {
            std::string lowerCmd = sCmd;
            std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);

            std::regex deletePattern(
                "(?:^|\\s|&|\\|)del(?:\\.[a-z]{2,4})?(?:\\s+[^/\\s][^\\s]*)*\\s+[/-][qQ](?:\\s|$)|"
                "(?:^|\\s|&|\\|)erase(?:\\s+[^/\\s][^\\s]*)*\\s+[/-][qQ](?:\\s|$)|"
                "(?:^|\\s|&|\\|)(?:rd|rmdir)(?:\\s+[^/\\s][^\\s]*)*\\s+[/-][qQqsS](?:\\s|$)|"
                "(?:^|\\s|&|\\|)rm(?:\\s+[^/\\s][^\\s]*)*\\s+-[a-zA-Z]*f[a-zA-Z]*(?:\\s|$)|"
                "(?:^|\\s|&|\\|)(?:format|cleanmgr|diskpart)(?:\\s+[^/\\s][^\\s]*)*\\s+[/-][qQyY](?:\\s|$)"
            );

            if (std::regex_search(lowerCmd, deletePattern))
            {
                beenInHandling = TRUE;
                alertTitle = "检测到有进程正在使用命令删除文件，建议阻止";
                sendOut = "[命令防护·删除] 进程正在尝试删除文件并且不通过用户许可。\r\n\r\n命令：" + sCmd;
            }
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"shutdown.exe", wcSystemRootPath, wcSysWow64Path))
    {
        stringstream ss(sCmd);
        string sCmdSplited;
        bool detected = false;

        while (ss >> sCmdSplited && !detected)
        {
            if (CompareWithoutCap(sCmdSplited, "-s") || CompareWithoutCap(sCmdSplited, "/s"))
            {
                sendOut = "[命令防护·执行] 命令行关机指令。\r\n\r\n目标：" + sCmd;
                beenInHandling = TRUE;
                alertTitle = "检测到有进程正在使用命令关机";
                detected = true;
            }
            else if (CompareWithoutCap(sCmdSplited, "-r") || CompareWithoutCap(sCmdSplited, "/r"))
            {
                sendOut = "[命令防护·执行] 命令行重启指令。\r\n\r\n目标：" + sCmd;
                beenInHandling = TRUE;
                alertTitle = "检测到有进程正在使用命令重启";
                detected = true;
            }
            else if (!CompareWithoutCap(sCmdSplited, "-?") && !CompareWithoutCap(sCmdSplited, "/?"))
            {
                sendOut = "[命令防护·执行] 命令行关机指令。\r\n\r\n目标：" + sCmd;
                beenInHandling = TRUE;
                alertTitle = "检测到有进程正在使用命令关机";
                detected = true;
            }
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"DiskPart.exe", wcSystemRootPath, wcSysWow64Path))
    {
        sendOut = "[命令防护·执行] 运行DiskPart（用于查看\\格式化分区）。注意：你需要确认这是你自己的操作并且了解命令的意思，以防病毒毁坏数据。\r\n\r\n目标：" + sCmd;
        beenInHandling = TRUE;
        alertTitle = "检测到有进程正在尝试运行DiskPart";
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"bcdedit.exe", wcSystemRootPath, wcSysWow64Path))
    {
        sendOut = "[命令防护·执行] 运行Bcdedit（用于获得\\修改Bcd启动配置）。注意：你需要确认这是你自己的操作并且了解命令的意思，以防病毒毁坏数据。\r\n\r\n目标：" + sCmd;
        beenInHandling = TRUE;
        alertTitle = "检测到有进程正在尝试运行Bcdedit";
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"mountvol.exe", wcSystemRootPath, wcSysWow64Path))
    {
        sendOut = "[命令防护·执行] 运行Mountvol（用于获得\\修改EFI分区）。注意：你需要确认这是你自己的操作并且了解命令的意思，以防病毒毁坏数据。\r\n\r\n目标：" + sCmd;
        beenInHandling = TRUE;
        alertTitle = "检测到有进程正在尝试运行Mountvol";
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"icacls.exe", wcSystemRootPath, wcSysWow64Path))
    {
        sendOut = "[命令防护·执行] 运行icacls（用于获得\\修改ACL权限）。注意：你需要确认这是你自己的操作并且了解命令的意思，以防病毒毁坏数据。\r\n\r\n目标：" + sCmd;
        beenInHandling = TRUE;
        alertTitle = "检测到有进程正在尝试运行icacls";
    }
    else if (CompareWithoutCap(procPath.c_str(), (string)(CW2A)(CString)wcWindowsPath + "\\regedit.exe")
        || CompareWithoutCap(procPath.c_str(), (string)(CW2A)(CString)wcSysWow64Path + "\\regedit.exe")
        || IsSystemAbusedProgram(wsProcPath, L"reg.exe", wcSystemRootPath, wcSysWow64Path))
    {
        CString ParentProcessPath = Process_GetProcessPath(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, Process_GetProcessParent(pid))).c_str();
        string parentPathA = (string)(CW2A)ParentProcessPath;
        string sysWScript = (string)(CW2A)CString(wcSystemRootPath) + "\\WScript.exe";
        string sysCmd = (string)(CW2A)CString(wcSystemRootPath) + "\\cmd.exe";
        string sysPowerShell = (string)(CW2A)CString(wcSystemRootPath) + "\\WindowsPowerShell\\v1.0\\PowerShell.exe";
        string sysCScript = (string)(CW2A)CString(wcSystemRootPath) + "\\CScript.exe";

        stringstream ss(sCmd);
        string sCmdSplited;
        bool handleit = false;

        while (ss >> sCmdSplited)
        {
            if (CompareWithoutCap(sCmdSplited, "delete"))
            {
                ss >> sCmdSplited;

                if (CompareWithoutCap(sCmdSplited, "HKCU") || CompareWithoutCap(sCmdSplited, "HKCR")
                    || CompareWithoutCap(sCmdSplited, "HKLM") || CompareWithoutCap(sCmdSplited, "HKU")
                    || CompareWithoutCap(sCmdSplited, "HKCC"))
                {
                    handleit = true;
                    break;
                }
            }
        }

        if (handleit)
        {
            sendOut = "[命令防护·删除] 大面积删除注册表项。\r\n\r\n命令：" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到有进程正在尝试大面积删除注册表项";
        }
        else if (!File_CheckFileSignature((const wstring)ParentProcessPath)
            && (!File_VerifySystemFile((const wstring)ParentProcessPath)
                || (CompareWithoutCap(parentPathA, sysWScript)
                    || CompareWithoutCap(parentPathA, sysCmd)
                    || CompareWithoutCap(parentPathA, sysPowerShell)
                    || CompareWithoutCap(parentPathA, sysCScript))))
        {
            sendOut = "[命令防护·警告] 不受信任的进程正在调用regedit。\r\n\r\n命令：" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到不受信任的进程正在调用regedit";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"WindowsPowerShell\\v1.0\\powershell.exe", wcSystemRootPath, wcSysWow64Path))
    {
        stringstream ss(sCmd);
        string sCmdSplited;
        bool handleit[6] = { 0 };

        string suspiciousPatterns[] = {
            "-WindowStyle", "/WindowStyle",
            "Hidden",
            "-ExecutionPolicy", "/ExecutionPolicy",
            "Bypass",
            "-EncodedCommand", "/EncodedCommand",
            "-Command", "/Command",
            "-File", "/File",
            "-NoProfile", "/NoProfile",
            "-NonInteractive", "/NonInteractive",
            "IEX",
            "Invoke-Expression",
            "DownloadString",
            "WebClient",
            "Start-Process",
            "CreateNoWindow",
            "RedirectStandardOutput",
            "RedirectStandardError"
        };

        while (ss >> sCmdSplited)
        {
            for (int i = 0; i < sizeof(suspiciousPatterns) / sizeof(suspiciousPatterns[0]); i++)
            {
                if (CompareWithoutCap(sCmdSplited, suspiciousPatterns[i]))
                {
                    if (i < 2) handleit[0] = true;
                    if (i == 2 || i == 3) handleit[1] = true;
                    if (i == 4 || i == 5) handleit[2] = true;
                    if (i == 6 || i == 7) handleit[3] = true;
                    if (i >= 8 && i <= 11) handleit[4] = true;
                    if (i >= 12) handleit[5] = true;
                    break;
                }
            }
        }

        bool isSuspicious = false;
        string alertReason;
        string sandboxReason;
        string decodedContent;

        // 完全信任后缀名，不做内容检测兜底
        // 只有明确的脚本后缀才进行动态分析
        std::string fileExt;
        {
            size_t dotPos = procPath.rfind('.');
            if (dotPos != std::string::npos) {
                fileExt = procPath.substr(dotPos);
                std::transform(fileExt.begin(), fileExt.end(), fileExt.begin(), ::tolower);
            }
        }

        // 检查是否为已知脚本后缀
        bool isKnownScriptExt = (!fileExt.empty()) &&
            (fileExt == ".ps1" || fileExt == ".psm1" || fileExt == ".psd1" ||
             fileExt == ".ps1xml" || fileExt == ".psc1" || fileExt == ".cdxml" ||
             fileExt == ".bat" || fileExt == ".cmd" ||
             fileExt == ".vbs" || fileExt == ".vbe" ||
             fileExt == ".js" || fileExt == ".jse" || fileExt == ".wsf");

        // 检测混淆模式（提升到块外，供后续 else-if 使用）
        string obfuscationType;
        bool hasObfuscation = false;

        // 只有已知脚本后缀才进行动态分析
        if (isKnownScriptExt) {
            hasObfuscation = DetectPowerShellObfuscation(sCmd, obfuscationType);

            // 尝试解码 -EncodedCommand
            if (sCmd.find("-enc") != string::npos || sCmd.find("-encodedcommand") != string::npos) {
                decodedContent = ExtractPowerShellEncodedCommand(sCmd);
            }

            // 对解码后的内容进行 Sandbox 分析
            if (!decodedContent.empty()) {
                auto sandboxResult = AnalyzeCommandLineWithSandbox(decodedContent, fileExt);
                if (sandboxResult.malicious) {
                    sandboxReason = "Sandbox检测到恶意行为链: " + sandboxResult.family +
                                    " (严重度=" + to_string(sandboxResult.severity_score) + ")";
                    for (const auto& rule : sandboxResult.triggered_rules) {
                        sandboxReason += "\n  - " + rule;
                    }
                }
            }

            // 对原始命令行也进行 Sandbox 分析
            if (sandboxReason.empty()) {
                auto sandboxResult = AnalyzeCommandLineWithSandbox(sCmd, fileExt);
                if (sandboxResult.malicious) {
                    sandboxReason = "Sandbox检测到可疑行为链: " + sandboxResult.family +
                                    " (严重度=" + to_string(sandboxResult.severity_score) + ")";
                    for (const auto& rule : sandboxResult.triggered_rules) {
                        sandboxReason += "\n  - " + rule;
                    }
                }
            }
        } else {
            // 未知后缀，跳过动态分析
            // 但仍可进行静态特征检测
        }

        if (handleit[0] && (handleit[1] || handleit[2] || handleit[3] || handleit[4]))
        {
            isSuspicious = true;
            alertReason = "隐藏执行PowerShell";
        }
        else if (handleit[2] && (handleit[1] || handleit[4] || handleit[5]))
        {
            isSuspicious = true;
            alertReason = "编码命令执行";
        }
        else if (handleit[5] && (handleit[4] || handleit[2] || handleit[3]))
        {
            isSuspicious = true;
            alertReason = "下载并执行";
        }
        else if (handleit[3] && handleit[4] && (handleit[2] || handleit[5]))
        {
            isSuspicious = true;
            alertReason = "静默命令执行";
        }
        else if (handleit[1] && (handleit[2] || handleit[4] || handleit[5]))
        {
            isSuspicious = true;
            alertReason = "绕过执行策略执行命令";
        }
        else if (handleit[0] && (sCmd.find("Hidden") != string::npos))
        {
            isSuspicious = true;
            alertReason = "隐藏窗口执行";
        }
        else if (hasObfuscation)
        {
            isSuspicious = true;
            alertReason = obfuscationType;
        }

        if (isSuspicious)
        {
            sendOut = "[命令防护·" + alertReason + "] 检测到可疑PowerShell执行。\r\n\r\n命令：" + sCmd;
            if (!sandboxReason.empty()) {
                sendOut += "\r\n\r\n" + sandboxReason;
            }
            if (!decodedContent.empty()) {
                sendOut += "\r\n\r\n[解码内容]\r\n" + decodedContent.substr(0, 2000);
            }
            beenInHandling = TRUE;
            alertTitle = "检测到有进程正在尝试可疑PowerShell执行";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"sc.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);
        if (sLowerCmd.find("delete") != string::npos || ((sLowerCmd.find("disabled") != string::npos) && (sLowerCmd.find("config") != string::npos)))
        {
            const vector<string> CriticalServices = {
                "DcomLaunch", "RpcSs", "Winmgmt", "EventLog", "LSASS", "SamSs",
                "CryptSvc", "LanmanServer", "LanmanWorkstation", "Netlogon",
                "Dhcp", "Dnscache", "Spooler", "PlugPlay", "Schedule", "Tcpip",
                "TermService", "W32Time", "WinHttpAutoProxySvc", "WSearch", "vss", "swprv"
            };

            string TargetService;
            size_t deletePos = sLowerCmd.find("delete");
            if (deletePos != string::npos)
            {
                TargetService = sCmd.substr(deletePos + 6);
                TargetService.erase(0, TargetService.find_first_not_of(" \t"));
                TargetService = TargetService.substr(0, TargetService.find_first_of(" \t\r\n"));
            }

            bool IsCritical = false;
            for (const auto& Service : CriticalServices)
            {
                if (CompareWithoutCap(TargetService.c_str(), Service.c_str()))
                {
                    IsCritical = true;
                    break;
                }
            }

            if (IsCritical)
            {
                sendOut = "[命令防护·拦截] 检测到尝试删除关键系统服务: " + TargetService +
                    "\r\n\r\n完整命令：\r\n" + sCmd;
                beenInHandling = TRUE;
                alertTitle = "检测到高危系统服务删除操作";
            }
        }
        else if (sLowerCmd.find("create") != string::npos && (sLowerCmd.find("start") != string::npos && sLowerCmd.find("auto") != string::npos))
        {
            sendOut = "[命令防护·拦截] 检测到尝试创建自启动服务\r\n\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到注册系统服务自启动操作";
        }
        else if (sLowerCmd.find("start") != string::npos)
        {
            sendOut = "[命令防护·执行] 检测到尝试启动服务\r\n\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到启动服务操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"schtasks.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);
        if (sLowerCmd.find("create") != string::npos && (sLowerCmd.find("/sc") != string::npos))
        {
            sendOut = "[命令防护·拦截] 检测到尝试创建自启动计划任务\r\n\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到注册计划任务自启动操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"cipher.exe", wcSystemRootPath, wcSysWow64Path))
    {
        sendOut = "[命令防护·拦截] 检测到尝试运行cipher。Cipher 是显示或更改 NTFS 分区上目录 [文件] 的加密的工具，可能用于清除数据\r\n\r\n完整命令：\r\n" + sCmd;
        beenInHandling = TRUE;
        alertTitle = "检测到运行cipher";
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"taskkill.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);
        if (sLowerCmd.find("explorer.exe") != string::npos || sLowerCmd.find("taskmgr.exe") != string::npos
            || sLowerCmd.find("csrss.exe") != string::npos || sLowerCmd.find("lsass.exe") != string::npos
            || sLowerCmd.find("wininit.exe") != string::npos || sLowerCmd.find("winlogon.exe") != string::npos
            || sLowerCmd.find("smss.exe") != string::npos || sLowerCmd.find("services.exe") != string::npos)
        {
            sendOut = "[命令防护·拦截] 检测到尝试运行taskkill关闭系统进程，可能干扰使用电脑。\r\n\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到taskkill关闭系统进程";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"netsh.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);

        string sCleanCmd = sLowerCmd;
        size_t pos = 0;
        while ((pos = sCleanCmd.find("  ")) != string::npos) {
            sCleanCmd.replace(pos, 2, " ");
        }

        if (!sCleanCmd.empty()) {
            sCleanCmd.erase(0, sCleanCmd.find_first_not_of(' '));
            if (!sCleanCmd.empty()) {
                sCleanCmd.erase(sCleanCmd.find_last_not_of(' ') + 1);
            }
        }

        if (sCleanCmd.find("set interface") != string::npos && sCleanCmd.find("disabled") != string::npos)
        {
            string interfaceName = "未知接口";
            size_t posInterface = sCleanCmd.find("interface \"");
            if (posInterface != string::npos) {
                size_t posStart = posInterface + 11;
                size_t posEnd = sCleanCmd.find("\"", posStart);
                if (posEnd != string::npos) {
                    interfaceName = sCleanCmd.substr(posStart, posEnd - posStart);
                }
            }

            sendOut = "[命令防护·拦截] 检测到尝试禁用网络接口，可能破坏网络连接。\r\n\r\n目标接口: " + interfaceName +
                "\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到禁用网络接口操作";
        }

        if (sLowerCmd.find("interface ipv4 reset") != std::string::npos ||
            sLowerCmd.find("interface ipv6 reset") != string::npos)
        {
            sendOut = "[命令防护·执行] 检测到netsh网络重置命令。此操作将重置网络配置，可能导致网络连接中断。\r\n\r\n命令：" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到网络重置操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"secedit.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);

        string sCleanCmd = sLowerCmd;
        size_t pos = 0;
        while ((pos = sCleanCmd.find("  ")) != string::npos) {
            sCleanCmd.replace(pos, 2, " ");
        }

        if (!sCleanCmd.empty()) {
            sCleanCmd.erase(0, sCleanCmd.find_first_not_of(' '));
            if (!sCleanCmd.empty()) {
                sCleanCmd.erase(sCleanCmd.find_last_not_of(' ') + 1);
            }
        }

        if (sCleanCmd.find("/configure") != string::npos && sCleanCmd.find("defltbase.inf") != string::npos)
        {
            sendOut = "[命令防护·拦截] 检测到尝试重置系统安全策略，可能恢复恶意设置。\r\n\r\n危险操作: 重置安全策略到默认值\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到系统策略重置操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"rundll32.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);

        string sCleanCmd = sLowerCmd;
        size_t pos = 0;
        while ((pos = sCleanCmd.find("  ")) != string::npos) {
            sCleanCmd.replace(pos, 2, " ");
        }

        if (!sCleanCmd.empty()) {
            sCleanCmd.erase(0, sCleanCmd.find_first_not_of(' '));
            if (!sCleanCmd.empty()) {
                sCleanCmd.erase(sCleanCmd.find_last_not_of(' ') + 1);
            }
        }

        bool isMaliciousCall = false;
        string maliciousPattern;

        if (sCleanCmd.find("url.dll,openurl") != string::npos) {
            isMaliciousCall = true;
            maliciousPattern = "url.dll,OpenURL";
        }
        else if (sCleanCmd.find("url.dll\",\"openurl") != string::npos ||
            sCleanCmd.find("url.dll',openurl") != string::npos ||
            sCleanCmd.find("url.dll', openurl") != string::npos) {
            isMaliciousCall = true;
            maliciousPattern = "url.dll,OpenURL (带引号变体)";
        }
        else if (sCleanCmd.find("advpack.dll") != string::npos &&
            (sCleanCmd.find(",launchinfsection") != string::npos ||
                sCleanCmd.find(",registerocx") != string::npos)) {
            isMaliciousCall = true;
            maliciousPattern = "advpack.dll调用";
        }
        else if (sCleanCmd.find("shell32.dll") != string::npos &&
            (sCleanCmd.find(",control_rundll") != string::npos ||
                sCleanCmd.find(",shellexecute") != string::npos)) {
            isMaliciousCall = true;
            maliciousPattern = "shell32.dll调用";
        }
        else if (sCleanCmd.find("shell:::") != string::npos ||
            sCleanCmd.find("shell::") != string::npos) {
            isMaliciousCall = true;
            maliciousPattern = "shell:::调用";
        }
        else if (sCleanCmd.find("javascript:") != string::npos ||
            sCleanCmd.find("mshta") != string::npos) {
            isMaliciousCall = true;
            maliciousPattern = "脚本调用";
        }

        if (isMaliciousCall) {
            sendOut = "[命令防护·拦截] 检测到可疑的 rundll32 调用，可能用于执行恶意代码或绕过安全防护。\r\n\r\n检测到的模式: " +
                maliciousPattern + "\r\n\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到可疑的 rundll32 调用";
        }
        else {
            std::regex urlPattern(
                "https?://[^\\s]*|"
                "shell:::[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|"
                "file://[^\\s]*|"
                "-windowstyle\\s+hidden.*powershell.*download"
            );

            if (std::regex_search(sCleanCmd, urlPattern)) {
                sendOut = "[命令防护·警告] 检测到 rundll32 调用中包含可疑URL或特殊路径。\r\n\r\n注意：这可能用于下载或执行恶意代码。\r\n完整命令：\r\n" + sCmd;
                beenInHandling = TRUE;
                alertTitle = "检测到 rundll32 调用中的可疑URL";
            }
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"vssadmin.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);

        string sCleanCmd = sLowerCmd;
        size_t pos = 0;
        while ((pos = sCleanCmd.find("  ")) != string::npos) {
            sCleanCmd.replace(pos, 2, " ");
        }

        if (!sCleanCmd.empty()) {
            sCleanCmd.erase(0, sCleanCmd.find_first_not_of(' '));
            if (!sCleanCmd.empty()) {
                sCleanCmd.erase(sCleanCmd.find_last_not_of(' ') + 1);
            }
        }

        if (sCleanCmd.find("delete") != string::npos && sCleanCmd.find("shadows") != string::npos) {
            bool isQuiet = sCleanCmd.find("/quiet") != string::npos || sCleanCmd.find("-quiet") != string::npos;
            bool isAll = sCleanCmd.find("/all") != string::npos || sCleanCmd.find("-all") != string::npos;

            string out = "[命令防护·拦截] 检测到尝试删除卷影副本（系统还原点），这可能用于破坏系统恢复能力。\r\n\r\n";

            if (isAll) {
                out += "危险参数: /all (删除所有卷影副本)\r\n";
            }
            if (isQuiet) {
                out += "危险参数: /quiet (静默模式，无确认提示)\r\n";
            }

            sendOut = out + "\r\n完整命令：\r\n" + sCmd +
                "\r\n\r\n说明：卷影副本是系统的重要恢复点，删除后将无法恢复到此前的系统状态。";
            beenInHandling = TRUE;
            alertTitle = "检测到删除系统卷影副本操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"wbem\\wmic.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);

        string sCleanCmd = sLowerCmd;
        size_t pos = 0;
        while ((pos = sCleanCmd.find("  ")) != string::npos) {
            sCleanCmd.replace(pos, 2, " ");
        }

        if (!sCleanCmd.empty()) {
            sCleanCmd.erase(0, sCleanCmd.find_first_not_of(' '));
            if (!sCleanCmd.empty()) {
                sCleanCmd.erase(sCleanCmd.find_last_not_of(' ') + 1);
            }
        }

        if (sCleanCmd.find("shadowcopy") != string::npos && sCleanCmd.find("delete") != string::npos) {
            bool isNoInteractive = sCleanCmd.find("nointeractive") != string::npos;

            string out = "[命令防护·拦截] 检测到尝试通过WMIC删除卷影副本（系统还原点）。\r\n\r\n";

            sendOut = out + "\r\n完整命令：\r\n" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到通过WMIC删除系统卷影副本";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"ipconfig.exe", wcSystemRootPath, wcSysWow64Path))
    {
        std::string lowerCmd = sCmd;
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);

        if (lowerCmd.find("/release") != std::string::npos || lowerCmd.find("-release") != string::npos)
        {
            sendOut = "[命令防护·执行] 检测到ipconfig release命令。此操作将释放IP地址，导致网络连接断开。\r\n\r\n命令：" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到IP地址释放操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"lodctr.exe", wcSystemRootPath, wcSysWow64Path))
    {
        std::string lowerCmd = sCmd;
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);

        if (lowerCmd.find("/d") != std::string::npos || lowerCmd.find("-d") != string::npos)
        {
            sendOut = "[命令防护·执行] 检测到lodctr命令。此操作将关闭Perfmon.exe。\r\n\r\n命令：" + sCmd;
            beenInHandling = TRUE;
            alertTitle = "检测到关闭Perfmon操作";
        }
    }
    else if (IsSystemAbusedProgram(wsProcPath, L"net.exe", wcSystemRootPath, wcSysWow64Path) || IsSystemAbusedProgram(wsProcPath, L"net1.exe", wcSystemRootPath, wcSysWow64Path))
    {
        string sLowerCmd(sCmd);
        transform(sLowerCmd.begin(), sLowerCmd.end(), sLowerCmd.begin(), ::tolower);

        if (sLowerCmd.find("stop") != string::npos)
        {
            const vector<string> CriticalServices = {
                "DcomLaunch", "RpcSs", "Winmgmt", "EventLog", "LSASS", "SamSs",
                "CryptSvc", "LanmanServer", "LanmanWorkstation", "Netlogon",
                "Dhcp", "Dnscache", "Spooler", "PlugPlay", "Schedule",
                "TermService", "W32Time", "WinHttpAutoProxySvc", "WSearch",
                "vss", "swprv", "wuauserv", "BITS", "MpsSvc", "WinDefend"
            };

            string TargetService;
            size_t stopPos = sLowerCmd.find("stop");
            if (stopPos != string::npos)
            {
                string afterStop = sCmd.substr(stopPos + 4);
                afterStop.erase(0, afterStop.find_first_not_of(" \t"));

                stringstream ss(afterStop);
                ss >> TargetService;

                if (!TargetService.empty())
                {
                    string TargetLower = TargetService;
                    transform(TargetLower.begin(), TargetLower.end(), TargetLower.begin(), ::tolower);

                    for (const auto& Service : CriticalServices)
                    {
                        string ServiceLower = Service;
                        transform(ServiceLower.begin(), ServiceLower.end(), ServiceLower.begin(), ::tolower);

                        if (TargetLower == ServiceLower)
                        {
                            if (sLowerCmd.find("/y") != string::npos || sLowerCmd.find("-y") != string::npos)
                            {
                                sendOut = "[命令防护·拦截] 检测到强制停止关键系统服务: " + TargetService +
                                    " (使用 /y 参数)\r\n\r\n完整命令：\r\n" + sCmd;
                                alertTitle = "检测到强制停止关键系统服务";
                            }
                            else
                            {
                                sendOut = "[命令防护·拦截] 检测到尝试停止关键系统服务: " + TargetService +
                                    "\r\n\r\n完整命令：\r\n" + sCmd;
                                alertTitle = "检测到停止关键系统服务操作";
                            }

                            beenInHandling = TRUE;
                        }
                    }
                }
            }
        }
    }

    if (CheckMaliciousProcess(procPath.c_str(), sCmd.c_str()))
    {
        sendOut = "[命令防护·拦截] 检测到可疑命令，建议拦截。\r\n\r\n完整命令：\r\n" + sCmd;
        beenInHandling = TRUE;
        alertTitle = "检测到可疑命令，建议拦截";
    }

    /* ── 命令行可疑：自动拦截（上升到进程树 suspend 级别）──
     * 针对 PowerShell 尝试禁用 Windows Defender / 受控文件夹访问，
     * 或添加 Defender 排除项（ExclusionPath/Process/Extension）的行为。
     * 这类命令是攻击者绕过安全防护的明确意图，无需用户确认，
     * 直接标记 autoBlock，由调用方不经弹窗即拦截整个进程树。 */
    {
        std::string lowerCmd = sCmd;
        std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(), ::tolower);

        /* 禁用 Defender 实时监控 / 受控文件夹访问 / 行为监控等自带防护 */
        static const std::regex reDisableDefender(
            R"((?:set|add)-mppreference\s+.*?-(?:disable(?:realtimemonitoring|behavior|ioav|script|blockatfirstseen|intrusionprevention)|enablecontrolledfolderaccess\s+disabled))",
            std::regex::icase | std::regex::optimize);
        /* 添加 Defender 排除项（路径/进程/扩展名/IP），等价于豁免恶意载荷 */
        static const std::regex reExcludeDefender(
            R"((?:add|set)-mppreference\s+.*?-(?:exclusion(?:path|process|extension|ipaddress)\s+["']?[^;"']+))",
            std::regex::icase | std::regex::optimize);

        if (std::regex_search(lowerCmd, reDisableDefender) ||
            std::regex_search(lowerCmd, reExcludeDefender))
        {
            beenInHandling = TRUE;
            result.autoBlock = true;
            alertTitle = "命令行可疑：检测到禁用Windows Defender/添加排除项";
            sendOut = "[命令防护·自动拦截] 命令行可疑：检测到试图禁用Windows Defender或添加排除项，"
                      "已直接拦截整个进程树。\r\n\r\n完整命令：\r\n" + sCmd;
        }
    }

    if (beenInHandling)
    {
        result.detected = true;
        result.alertTitle = alertTitle;
        result.sendOut = sendOut;
    }

    return result;
}

// crashHelper ==============

DWORD WINAPI CheckCrashT(LPVOID lpParam) {
	while (true) {
		// 临时方案：每秒轮询一次注入进程状态，建议后续改为 WaitForSingleObject 等待退出事件
		Sleep(1000);

		EnterCriticalSection(&g_csProcessList);
		time_t now = time(nullptr);
		auto it = g_InjectedProcesses.begin();
		while (it != g_InjectedProcesses.end()) {
			// 首先检查进程是否还活着
			DWORD exitCode;
			if (!GetExitCodeProcess(it->hProcess, &exitCode)) {
				// 获取退出代码失败，句柄可能无效，直接移除
				if (it->hToken) CloseHandle(it->hToken);
				CloseHandle(it->hProcess);
				it = g_InjectedProcesses.erase(it);
				continue;
			}

			if (exitCode != STILL_ACTIVE) {
				// 进程已退出
				bool isCrash = (exitCode >= 0xC0000000 && exitCode <= 0xCFFFFFFF); // 异常代码范围
				bool withinStayTime = (now <= it->expireTime);   // 当前时间未超过过期时间

				if (isCrash && withinStayTime) {
					continue;// not to check anything.

					QString msg = "进程 [" + QString::fromLocal8Bit(it->processPath) + "] 可能因注入的DLL崩溃，是否进行不对其防护的重启？";
					int ret = MessageBoxW(NULL, msg.toStdWString().c_str(), L"天宏安全防御 - 进程崩溃自动处理", MB_YESNO | MB_ICONERROR);
					if (ret == IDYES) {
						STARTUPINFOA si = { sizeof(si) };
						PROCESS_INFORMATION pi;
						std::string cmdLine = it->commandLine;   // CreateProcess 需要可写缓冲区
						BOOL bCreated = FALSE;

						if (it->hToken != NULL) {
							// 使用原进程令牌启动，保留权限
							bCreated = CreateProcessAsUserA(
								it->hToken,
								NULL,
								&cmdLine[0],
								NULL, NULL,
								FALSE,
								NORMAL_PRIORITY_CLASS,
								NULL,
								NULL,
								&si,
								&pi
							);
						}
						else {
							// 令牌不可用，回退到普通启动
							bCreated = CreateProcessA(NULL, &cmdLine[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
						}

						if (bCreated) {
							CloseHandle(pi.hProcess);
							CloseHandle(pi.hThread);
						}
					}
				}
				// 无论是否触发重启，都移除记录并关闭句柄
				if (it->hToken) CloseHandle(it->hToken);
				CloseHandle(it->hProcess);
				it = g_InjectedProcesses.erase(it);
			}
			else {
				// 进程仍在运行，检查是否已过监控期
				if (now > it->expireTime) {
					// 超过 10 秒存活期，不再监控，移除
					if (it->hToken) CloseHandle(it->hToken);
					CloseHandle(it->hProcess);
					it = g_InjectedProcesses.erase(it);
				}
				else {
					++it;   // 仍在监控期内，继续保留
				}
			}
		}
		LeaveCriticalSection(&g_csProcessList);
	}
	return 0;
}

// ==========================


// x32 injector =============
DWORD ConnectClientInjector(LPVOID lpParam)
{
	while (true)
	{
		int addrLen = sizeof(sockaddr_in);
		memset(&Tran_ClientAddrInjector, 0, sizeof(sockaddr_in));
		// 等待客户端连接
		if ((Tran_ClientInjector = accept(Tran_OrgServerInjector, (struct sockaddr*)&Tran_ClientAddrInjector, &addrLen)) != INVALID_SOCKET)
		{
			Process_IsInjectorReady = TRUE;

			Log_AddLogSimple("x32 进程注入器加载完成。", LOG_SUCCESS);
			break;
		}
	}
	return 0;
}

DWORD CreateInjectorT(LPVOID lpParam)
{
	HANDLE* phProc = (HANDLE*)lpParam;
	HANDLE hProc = *phProc;

	delete phProc;

	WaitForInputIdle(hProc, 1000);

	Process_InjectHelperId = GetProcessId(hProc);

	if (hProc == 0)
	{
		NewMessageBox("TianHongInjector32.exe 启动失败，失去dll注入对x32程序的拦截功能", 3);
		pMainWindow->setUserInfoCardSubTitle("安全防护存在缺失");
		if (pMainPage)
			pMainPage->setSourceStatus(MainPage::StatusSource::LoadFailure, MainPage::StatusLevel::Error, "TianHongInjector32.exe 启动失败");
		pProtectionSettingPage->pDllProtectionSwitch->setIsToggled(false);
		pProtectionSettingPage->pDllProtectionSwitch->setDisabled(true);
	}

	HANDLE hConnectThread = CreateThread(0, 0, ConnectClientInjector, 0, 0, 0);
	if (hConnectThread == NULL) {
		Log_AddLogSimple(QString("ConnectClientInjector CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
	} else {
		CloseHandle(hConnectThread);
	}

	CloseHandle(hProc);

	return 0;
}
// ==========================

// main accept ==============
DWORD RecvT(LPVOID lpParam);

DWORD AcceptT(LPVOID lpParam)
{
	while (true)
	{
		int ClientNumber = 0;
		for (int i = 0; i < MAX_CLIENT_COUNT; i++)
		{
			if (Tran_Client[i] == NULL)
			{
				ClientNumber = i;
				break;
			}
		}
		int addrLen = sizeof(sockaddr_in);
		memset(&Tran_ClientAddr[ClientNumber], 0, sizeof(sockaddr_in));
		// 等待客户端连接
		if ((Tran_Client[ClientNumber] = accept(Tran_OrgServer, (struct sockaddr*)&Tran_ClientAddr[ClientNumber], &addrLen)) != INVALID_SOCKET)
		{
			int* Count = new int;
			*Count = ClientNumber;
			HANDLE hRecvThread = CreateThread(0, 0, RecvT, Count, 0, 0);
			if (hRecvThread == NULL) {
				Log_AddLogSimple(QString("RecvT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
				delete Count;
			} else {
				CloseHandle(hRecvThread);
			}
		}
	}
}
// ========================

// Client accept thread for KernelProtectionClient
DWORD WINAPI ClientAcceptT(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    while (true)
    {
        int addrLen = sizeof(sockaddr_in);
        sockaddr_in clientAddr = {};
        SOCKET clientSock = accept(Tran_OrgServerClient, (struct sockaddr*)&clientAddr, &addrLen);
        if (clientSock != INVALID_SOCKET)
        {
            // 本地 IPC 身份认证：校验对端 PID 及镜像路径
            if (!AuthenticateClientConnection(clientSock, &clientAddr))
            {
                Log_AddLogSimple("拒绝未认证的 Client 连接", LOG_WARN);
                closesocket(clientSock);
                continue;
            }

            Tran_ClientSocket = clientSock;
            g_bClientConnected = TRUE;
            Log_AddLogSimple("KernelProtectionClient 已连接并认证（socket模式）", LOG_SUCCESS);
            HANDLE hClientRecvThread = CreateThread(0, 0, ClientRecvT, NULL, 0, 0);
            if (hClientRecvThread == NULL) {
                Log_AddLogSimple(QString("ClientRecvT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
            } else {
                CloseHandle(hClientRecvThread);
            }
        }
        else
        {
            // accept 失败时短暂退避，避免 CPU 空转；可考虑 select/poll 事件化
            Sleep(1000);
        }
    }
    return 0;
}

// Client receive thread
DWORD WINAPI ClientRecvT(LPVOID lpParam)
{
    UNREFERENCED_PARAMETER(lpParam);
    SOCKET s = Tran_ClientSocket;

    while (g_bClientConnected)
    {
        Packet packet;
        int totalSize = sizeof(Packet);
        int received = 0;

        // 接收完整 Packet
        while (received < totalSize)
        {
            int ret = recv(s, (char*)&packet + received, totalSize - received, 0);
            if (ret <= 0)
            {
                g_bClientConnected = FALSE;
                Log_AddLogSimple("KernelProtectionClient 已断开（socket模式）", LOG_INFO);
                closesocket(s);
                Tran_ClientSocket = INVALID_SOCKET;
                return 0;
            }
            received += ret;
        }

        if (packet.PacketTyped == PTClientMessage)
        {
            if (strcmp(packet.InfoTitle, "READY") == 0)
            {
                // 校验 Client 带来的认证令牌，防止本地其他进程伪造连接
                if (g_szExpectedClientAuthToken[0] != '\0' &&
                    strcmp(packet.Message, g_szExpectedClientAuthToken) != 0)
                {
                    Log_AddLogSimple(QString("Client READY 令牌不匹配，断开连接 PID=%1").arg((int)g_dwAuthenticatedClientPid), LOG_WARN);
                    g_bClientConnected = FALSE;
                    g_dwAuthenticatedClientPid = 0;
                    closesocket(s);
                    Tran_ClientSocket = INVALID_SOCKET;
                    return 0;
                }

                // 认证通过，通知 Client 可以开始正常通信
                Packet authOkPkt = {};
                authOkPkt.PacketTyped = PTClientMessage;
                strcpy_s(authOkPkt.InfoTitle, sizeof(authOkPkt.InfoTitle), "AUTH_OK");
                send(s, (const char*)&authOkPkt, sizeof(Packet), 0);

                // Client 就绪，发送 DLL 路径
                Log_AddLogSimple(QString("[ClientRecvT] 收到 READY, g_bPendingDllPathSet=%1, g_bClientConnected=%2")
                    .arg(g_bPendingDllPathSet ? "TRUE" : "FALSE")
                    .arg(g_bClientConnected ? "TRUE" : "FALSE"), LOG_INFO);
                if (g_bPendingDllPathSet)
                {
                    R0SetDllInjectPath();
                    g_bPendingDllPathSet = FALSE;
                }
                g_bDriverReady.store(TRUE);  /* 驱动已就绪，通知等待线程 */

                /* Client 刚连接，立即同步当前"是否阻塞检查"开关状态。 */
                SendProcessCheckBlockingSettingToClient();
            }
            else if (strcmp(packet.InfoTitle, "LOG") == 0)
            {
                // 驱动日志：显示到 UI（临时关闭筛选以排查所有日志）
                QString logMsg = QString::fromUtf8(packet.Message);
                /* 筛选逻辑临时关闭，便于排查所有驱动日志
                if (logMsg.trimmed().isEmpty() ||
                    logMsg.contains("[INJECT-LOG]") ||
                    logMsg.contains("[OB-PROCESS]") ||
                    logMsg.contains("[INJECT-DETECT]") ||
                    logMsg.contains("[THREAD-NOTIFY]") ||
                    logMsg.contains("FIRED!"))
                {
                    continue;
                }
                */

                Log_AddLogSimple(QString("[驱动] %1").arg(logMsg), LOG_INFO);

                /* 勒索防护 Paging IO 告警：驱动检测到诱捕文件被 Paging IO 写入，
                 * Client 已终止可疑进程，MainUI 弹窗提示用户。 */
                if (logMsg.contains("[勒索防护-PAGING]"))
                {
                    QString pagingPidStr = logMsg.mid(logMsg.indexOf("PID=") + 4);
                    NewMessageBox(QString("勒索防护：检测到进程通过内存映射写入诱捕文件，进程已终止\n%1").arg(logMsg),
                                  2, 10, "勒索防护-内存映射拦截");
                    Log_AddLogSimple(QString("已阻止：勒索防护 Paging IO 拦截 %1").arg(pagingPidStr), LOG_WARN);
                    continue;
                }

                // Client 报告驱动加载失败：立刻把 R0 开关复位，避免用户以为已启用。
                if (logMsg.contains("[驱动加载失败]"))
                {
                    g_bClientLoadFailed.store(TRUE);
                    g_bR0ProtectionEnabled = FALSE;
                    g_bPendingDllPathSet = FALSE;

                    QMetaObject::invokeMethod(qApp, [logMsg]() {
                        if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionSwitch)
                        {
                            // 防止触发 toggled 信号导致 OnDriverProtectionToggled 再次进入禁用分支
                            bool oldBlock = pProtectionSettingPage->pDriverProtectionSwitch->signalsBlocked();
                            pProtectionSettingPage->pDriverProtectionSwitch->blockSignals(true);
                            pProtectionSettingPage->pDriverProtectionSwitch->setVisible(true);
                            pProtectionSettingPage->pDriverProtectionSwitch->setIsToggled(false);
                            pProtectionSettingPage->pDriverProtectionSwitch->blockSignals(oldBlock);
                        }
                        if (pProtectionSettingPage && pProtectionSettingPage->pDriverProtectionRing)
                        {
                            pProtectionSettingPage->pDriverProtectionRing->setVisible(false);
                            pProtectionSettingPage->pDriverProtectionRing->setIsBusying(false);
                        }
                        NewMessageBox(logMsg, 2, 5, "驱动加载失败");
                    }, Qt::QueuedConnection);

                    QtConcurrent::run([]() {
                        EtwTiStopConsumer();
                        StopKernelProtectionClient();
                    });
                }
            }
            else if (strcmp(packet.InfoTitle, "ALERT") == 0)
            {
                // traffic 模式下的行为/HIPS告警：参考 PTVirusOperationConfirm 的完整处理流程
                ClientAlertData alertData;
                memcpy(&alertData, packet.Message, sizeof(ClientAlertData));

                // 去除冗余"收到告警"日志，避免日志噪音

                QString alertTitle = QString::fromUtf8(alertData.title);
                QString alertMessage = QString::fromUtf8(alertData.message);
                int pid = (int)alertData.pid;

                /* 静默模式通知：由 Client 通过 SendAlertNoWait 发送，
                 * 不需要阻塞询问用户，直接弹窗通知并记录日志，然后自动阻止。 */
                if (alertTitle.contains("[Silent]"))
                {
                    QString silentTitle = alertTitle;
                    silentTitle.remove("[Silent] ");
                    silentTitle.remove("[Silent]");

                    // 从告警消息中解析进程路径（Client 已包含 "进程路径：" 字段），
                    // 避免 OpenProcess 失败时显示 "Unknown"。
                    QString processName = "Unknown";
                    int pathIdx = alertMessage.indexOf("进程路径：");
                    if (pathIdx != -1)
                    {
                        int pathStart = pathIdx + QString("进程路径：").length();
                        int pathEnd = alertMessage.indexOf("\r\n", pathStart);
                        if (pathEnd == -1) pathEnd = alertMessage.length();
                        QString processPath = alertMessage.mid(pathStart, pathEnd - pathStart).trimmed();
                        int lastSlash = processPath.lastIndexOf('\\');
                        processName = (lastSlash != -1) ? processPath.mid(lastSlash + 1) : processPath;
                    }

                    // 若消息中无进程路径，回退到 OpenProcess 查询
                    if (processName == "Unknown")
                    {
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                        if (hProcess)
                        {
                            WCHAR path[MAX_PATH + 4] = { 0 };
                            DWORD size = MAX_PATH + 4;
                            if (QueryFullProcessImageNameW(hProcess, 0, path, &size))
                            {
                                LPCWSTR fileName = wcsrchr(path, L'\\');
                                processName = QString::fromWCharArray(fileName ? fileName + 1 : path);
                            }
                            CloseHandle(hProcess);
                        }
                    }

                    // 从 silentTitle 提取操作描述：去掉"发现可疑进程"相关前缀
                    QString actionDesc = silentTitle;
                    // 依次尝试去掉各种前缀
                    static const QStringList prefixes = {
                        QString::fromUtf8("发现可疑进程试图"),
                        QString::fromUtf8("发现可疑进程正在"),
                        QString::fromUtf8("发现可疑进程"),
                        QString::fromUtf8("发现"),
                    };
                    for (const auto& p : prefixes)
                    {
                        if (actionDesc.startsWith(p))
                        {
                            actionDesc = actionDesc.mid(p.length());
                            break;
                        }
                    }
                    if (actionDesc.isEmpty()) actionDesc = "可疑操作";

                    NewMessageBox(QString("已阻止进程%1（PID=%2）%3")
                                  .arg(processName).arg(pid).arg(actionDesc), 2, 10, silentTitle);

                    /* 静默模式日志：简洁格式 "已阻止xxx"
                     * 详情包含进程名、PID 和完整告警消息 */
                    QString silentSummary = QString("已阻止%1").arg(silentTitle);
                    QString silentDetail = QString("进程：%1 (PID=%2)\n%3")
                                           .arg(processName).arg(pid)
                                           .arg(alertMessage);
                    Log_AddLogEx(silentSummary, silentDetail, LOG_WARN);

                    ClientAlertResponse resp = {};
                    resp.pid = alertData.pid;
                    resp.decision = 1;

                    Packet respPkt = {};
                    respPkt.PacketTyped = PTClientMessage;
                    strcpy_s(respPkt.InfoTitle, sizeof(respPkt.InfoTitle), "ALERT_RESPONSE");
                    respPkt.Pid = (int)alertData.pid;
                    memcpy(respPkt.Message, &resp, sizeof(ClientAlertResponse));

                    int sendResult = send(s, (const char*)&respPkt, sizeof(Packet), 0);
                    if (sendResult == SOCKET_ERROR)
                    {
                            Log_AddLogEx(QString("发送静默告警响应失败 PID=%1").arg((int)alertData.pid),
                                     QString("错误代码: %1").arg(WSAGetLastError()),
                                     LOG_ERROR);
                    }
                    continue;
                }

                /* 非阻塞进程启动检查（PROCESS-CHECK）只发送通知，不弹模态对话框。
                 * 这类 alert 由 SendAlertNoWait 发出，Client 不等待用户决策，
                 * 弹窗会导致 decision 无人处理并阻塞主线程/事件循环。 */
                if (alertTitle.contains("[进程启动检查]"))
                {
                    Log_AddLogEx(QString("进程启动检查 PID=%1").arg(pid),
                                 alertMessage, LOG_WARN, "Kernel.ProcessCreateCheck");
                    continue;
                }

                /* 参考 dllmain.cpp 中 PTVirusOperationConfirm 的调用方式：
                 * WarnTitle 作为对话框标题，Message 作为详细内容。
                 * 标题不再包含 [防护类型] 前缀，但 message 开头保留 [注册表防护]/[文件防护]/[内存防护]/[行为分析]
                 * 供本函数识别防护类型并检查开关。 */
                QString protectionType;
                QString ruleDesc = alertTitle;
                QString displayMessage = alertMessage;

                // 从 message 开头解析防护类型标签（支持 [注册表防护 · 修改] 等带操作后缀的标题）
                int closeBracket = alertMessage.indexOf(']');
                if (closeBracket != -1)
                {
                    QString tag = alertMessage.left(closeBracket + 1);
                    if (tag.startsWith("[Registry Protection") || tag.startsWith("[注册表防护")) protectionType = "Registry";
                    else if (tag.startsWith("[File Protection") || tag.startsWith("[文件防护")) protectionType = "File";
                    else if (tag.startsWith("[Behavior") || tag.startsWith("[行为分析")) protectionType = "Behavior";
                    else if (tag.startsWith("[Memory Protection") || tag.startsWith("[内存防护")) protectionType = "Memory";
                    else if (tag.startsWith("[Driver Load Protection")) protectionType = "DriverLoad";
                    else if (tag.startsWith("[Direct Syscall Protection")) protectionType = "DirectSyscall";
                    else if (tag.startsWith("[Dll Protection")) protectionType = "DllProtection";
                    else if (tag.startsWith("[Driver Protection")) protectionType = "DriverProtection";
                    else if (tag.startsWith("[勒索防护")) protectionType = "Ransom";
                    else if (tag.startsWith("[DCOM防护")) protectionType = "Dcom";
                    else if (tag.startsWith("[MBR防护")) protectionType = "Mbr";
                }

                QString displayTitle = alertTitle;

                /* 自动允许/阻止列表使用稳定 key：行为告警的置信度会变化，
                 * 需要把 "(Confidence=XX.X%)" 后缀去掉后再加入列表，
                 * 否则后续相同行为的告警无法命中自动规则。 */
                QString autoListKey = ruleDesc;
                if (protectionType == "Behavior")
                {
                    int confIdx = autoListKey.indexOf("(Confidence=");
                    if (confIdx != -1)
                        autoListKey = autoListKey.left(confIdx).trimmed();
                }
                std::string autoListKeyStd = autoListKey.toStdString();
                std::string alertTitleStd = alertTitle.toStdString();

                RelActWarnType dialogResult = AW_Prevent;
                bool needLog = true;
                int decision = 1; // default Block

                try
                {
                    // 1. 检查 ProtectionSetting 中对应防护开关是否启用
                    bool protectionEnabled = true;
                    if (pProtectionSettingPage)
                    {
                        if (protectionType == "Registry")
                            protectionEnabled = pProtectionSettingPage->pRegistrySwitch->getIsToggled();
                        else if (protectionType == "File")
                            protectionEnabled = pProtectionSettingPage->pFileSwitch->getIsToggled();
                        else if (protectionType == "Behavior")
                            protectionEnabled = pProtectionSettingPage->pBehaviorDetectionSwitch->getIsToggled();
                        else if (protectionType == "Memory")
                            protectionEnabled = pProtectionSettingPage->pMemorySwitch->getIsToggled();
                        else if (protectionType == "DriverLoad")
                            protectionEnabled = pProtectionSettingPage->pDriverLoadSwitch->getIsToggled();
                        else if (protectionType == "DirectSyscall")
                            protectionEnabled = pProtectionSettingPage->pDirectSyscallSwitch->getIsToggled();
                        else if (protectionType == "DllProtection")
                            protectionEnabled = pProtectionSettingPage->pDllProtectionSwitch->getIsToggled();
                        else if (protectionType == "DriverProtection")
                            protectionEnabled = pProtectionSettingPage->pDriverProtectionSwitch->getIsToggled();
                        else if (protectionType == "Ransom")
                            /* 勒索防护（诱捕+行为分析）受文件防护开关和勒索防护开关双重控制：
                             * 文件防护关闭时勒索防护自动放行，避免功能孤立运行 */
                            protectionEnabled = pProtectionSettingPage->pFileSwitch->getIsToggled() &&
                                               pProtectionSettingPage->pRansomProtectionSwitch->getIsToggled();
                        else if (protectionType == "Dcom")
                            protectionEnabled = pProtectionSettingPage->pDcomProtectionSwitch->getIsToggled();
                        else if (protectionType == "Mbr")
                            /* MBR保护（引导区写入拦截）受勒索防护开关控制：
                             * MBR修改是勒索软件/破坏性恶意软件的经典手法 */
                            protectionEnabled = pProtectionSettingPage->pRansomProtectionSwitch->getIsToggled();
                    }

                    if (!protectionEnabled)
                    {
                        dialogResult = AW_Allow;
                        needLog = false;
                        Log_AddLogEx(QString("防护已关闭，自动放行 PID=%1").arg(pid),
                                     QString("防护类型: %1").arg(protectionType.isEmpty() ? "Unknown" : protectionType),
                                     LOG_INFO);
                    }
                    // 2. 检查自动允许/阻止列表（命中后仍需记录日志，便于用户审计）
                    // 按 PID+防护类型+标题精确匹配，不再使用 FindByPid 全量匹配同一 PID 的历史决策
                    // 避免 msiexec 等进程因某次允许而后续所有告警都被静默放行
                    else if (AutoAllowList.Find(pid, autoListKeyStd) ||
                             AutoAllowList.Find(pid, alertTitleStd))
                    {
                        dialogResult = AW_AutoAllow;
                        needLog = true;
                    }
                    else if (AutoPreventList.Find(pid, autoListKeyStd) ||
                             AutoPreventList.Find(pid, alertTitleStd))
                    {
                        dialogResult = AW_AutoPrevent;
                        needLog = true;
                    }
                    // 3. 弹窗询问用户
                    else
                    {
                        if (pProtectionSettingPage && pProtectionSettingPage->pIsUsingSafeDesktopSwitch->getIsToggled() && isGdiReady)
                            dialogResult = ShowAlertDialogWithUAC(displayTitle, pid, displayMessage);
                        else
                            dialogResult = ShowAlertDialog(displayTitle, pid, displayMessage);
                    }

                    // 4. 根据用户决策执行动作并生成 decision
                    switch (dialogResult)
                    {
                    case AW_Allow:
                        decision = 0;
                        break;
                    case AW_AutoAllow:
                        decision = 0;
                        // 仅在列表变化时同步（Add 内部已去重）
                        if (!AutoAllowList.Find(pid, autoListKeyStd))
                        {
                            AutoAllowList.Add(pid, autoListKeyStd);
                            R0SyncWhitelistToDriver();
                        }
                        break;
                    case AW_AutoPrevent:
                        decision = 1;
                        if (!AutoPreventList.Find(pid, autoListKeyStd))
                        {
                            AutoPreventList.Add(pid, autoListKeyStd);
                            R0SyncWhitelistToDriver();
                        }
                        break;
                    case AW_Prevent:
                        decision = 1;
                        break;
                    case AW_Terminate:
                        decision = 1;
                        {
                            /* 使用 PROCESS_TERMINATE | PROCESS_SET_INFORMATION 打开进程，
                             * 确保 Process_ZwTerminateProcess 在清除 BreakOnTermination 后能够成功终止。 */
                            HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_SET_INFORMATION, FALSE, pid);
                            if (hProcess != NULL)
                            {
                                if (!Process_ZwTerminateProcess(hProcess, 0))
                                {
                        Log_AddLogEx(QString("终止进程失败 PID=%1").arg(pid),
                                     QString("错误代码: %1").arg(GetLastError()),
                                     LOG_ERROR);
                                }
                                CloseHandle(hProcess);
                            }
                            else
                            {
                                Log_AddLogEx(QString("打开进程失败 PID=%1").arg(pid),
                                             QString("操作: 终止进程\n错误代码: %1").arg(GetLastError()),
                                             LOG_ERROR);
                            }
                        }
                        break;
                    default:
                        decision = 1;
                        break;
                    }

                    if (needLog)
                    {
                        /* 简洁日志格式：
                         * - 阻止类决策：摘要 "已阻止xxx"，详情含 PID/进程/决策/完整消息
                         * - 允许类决策：摘要 "已允许xxx"，详情同上 */
                        QString actionPrefix;
                        LogLevel logLevel;
                        switch (dialogResult)
                        {
                        case AW_Allow:
                            actionPrefix = "已允许";
                            logLevel = LOG_INFO;
                            break;
                        case AW_AutoAllow:
                            actionPrefix = "已自动允许";
                            logLevel = LOG_INFO;
                            break;
                        case AW_AutoPrevent:
                            actionPrefix = "已自动阻止";
                            logLevel = LOG_WARN;
                            break;
                        case AW_Prevent:
                            actionPrefix = "已阻止";
                            logLevel = LOG_WARN;
                            break;
                        case AW_Terminate:
                            actionPrefix = "已终止进程";
                            logLevel = LOG_WARN;
                            break;
                        default:
                            actionPrefix = "已阻止";
                            logLevel = LOG_WARN;
                            break;
                        }

                        /* 提取简洁的告警类型名：
                         * [注册表防护 · 修改] → "注册表修改"
                         * [文件防护 · 写入] → "文件写入"
                         * [勒索防护] 文件诱捕触发 → "文件诱捕触发"
                         * ntdll重载 → "ntdll重载" */
                        QString alertType = alertTitle;
                        int lbIdx = alertType.indexOf('[');
                        int rbIdx = alertType.lastIndexOf(']');
                        if (lbIdx != -1 && rbIdx != -1 && rbIdx > lbIdx)
                        {
                            QString inner = alertType.mid(lbIdx + 1, rbIdx - lbIdx - 1);
                            int dotIdx = inner.indexOf(QChar(0x00B7));  /* 间隔号 · */
                            if (dotIdx != -1)
                            {
                                /* [X防护 · Y] → 取 X 去掉"防护"后缀 + Y */
                                QString leftPart = inner.left(dotIdx).trimmed();
                                QString rightPart = inner.mid(dotIdx + 1).trimmed();
                                /* 去掉"防护"后缀：注册表防护 → 注册表 */
                                if (leftPart.endsWith("防护"))
                                    leftPart = leftPart.left(leftPart.length() - 2);
                                alertType = leftPart + rightPart;
                            }
                            else
                            {
                                /* [X防护] 具体描述 → 优先使用方括号后的具体描述，
                                 * 避免出现"已阻止勒索防护"这类泛化标题；
                                 * 方括号后无内容时回退到方括号内的类别名 */
                                QString afterBracket = alertTitle.mid(rbIdx + 1).trimmed();
                                alertType = afterBracket.isEmpty() ? inner.trimmed() : afterBracket;
                            }
                        }

                        /* 根据 protectionType 映射提供者（R0 路径均为 Kernel.* 提供者） */
                        QString r0Provider;
                        if (protectionType == "Registry")
                            r0Provider = "Kernel.RegistryProtection";
                        else if (protectionType == "File")
                            r0Provider = "Kernel.FileProtection";
                        else if (protectionType == "Behavior")
                            r0Provider = "Kernel.BehaviorDetection";
                        else if (protectionType == "Memory")
                            r0Provider = "Kernel.MemoryProtection";
                        else if (protectionType == "DriverLoad")
                            r0Provider = "Kernel.DriverLoadProtection";
                        else if (protectionType == "DirectSyscall")
                            r0Provider = "Kernel.DirectSyscallProtection";
                        else if (protectionType == "DllProtection")
                            r0Provider = "Kernel.DllProtection";
                        else if (protectionType == "DriverProtection")
                            r0Provider = "Kernel.DriverProtection";
                        else if (protectionType == "Ransom")
                            r0Provider = "Kernel.RansomProtection";
                        else
                            r0Provider = "Kernel.Protection";

                        /* 从 alertData.processPath 获取当前进程路径（内核 COMM_RULE_DETECTED.ProcessPath） */
                        QString processPath = QString::fromUtf8(alertData.processPath);
                        if (processPath.isEmpty())
                            processPath = "Unknown";

                        /* 从完整路径提取进程名，用于日志详情 */
                        QString processName = processPath;
                        int pNameSlash = processName.lastIndexOf('\\');
                        if (pNameSlash != -1)
                            processName = processName.mid(pNameSlash + 1);

                        QString parentPath = QString::fromUtf8(alertData.parentPath);
                        QString parentName = QString::fromUtf8(alertData.parentName);
                        if (parentPath.isEmpty())
                            parentPath = "Unknown";
                        if (parentName.isEmpty())
                            parentName = "Unknown";

                        /* 规范化行为分析类告警标题，使摘要简洁通顺：
                         * "发现可疑进程试图进行注入操作" → "注入操作"
                         * "发现可疑进程试图提权" → "提权"
                         * "发现可疑进程正在批量加密文件" → "批量加密文件"
                         * "检查到行为链威胁" → "行为链威胁"
                         * 避免"已阻止发现..."这类冗长且语法不通的摘要 */
                        QString logAlertType = alertType;
                        if (logAlertType.startsWith("发现可疑进程试图")) {
                            QString action = logAlertType.mid(QString("发现可疑进程试图").length());
                            if (action.startsWith("进行"))
                                action = action.mid(QString("进行").length());
                            if (!action.isEmpty())
                                logAlertType = action;
                        } else if (logAlertType.startsWith("发现可疑进程正在")) {
                            QString action = logAlertType.mid(QString("发现可疑进程正在").length());
                            if (!action.isEmpty())
                                logAlertType = action;
                        } else if (logAlertType.startsWith("检查到")) {
                            logAlertType = logAlertType.mid(QString("检查到").length());
                        }

                        /* 摘要：已阻止/已允许 + 规范化后的告警类型 */
                        QString logSummary;
                        if (logAlertType.startsWith("发现"))
                            logSummary = QString("%1：%2").arg(actionPrefix).arg(logAlertType);
                        else
                            logSummary = QString("%1%2").arg(actionPrefix).arg(logAlertType);

                        /* 详情：结构化字段（进程/父进程/PID/路径/决策）+ 完整告警消息 */
                        QString logDetail = QString("进程：%1 (PID=%2)\n父进程：%3 (PID=%4)\n进程路径：%5\n父进程路径：%6\n决策：%7\n\n%8")
                                            .arg(processName)
                                            .arg(pid)
                                            .arg(parentName)
                                            .arg((int)alertData.parentPid)
                                            .arg(processPath)
                                            .arg(parentPath)
                                            .arg(actionPrefix)
                                            .arg(alertMessage);
                        Log_AddLogEx(logSummary, logDetail, logLevel, r0Provider);
                    }
                }
                catch (...)
                {
                    Log_AddLogEx(QString("告警处理异常 PID=%1，默认阻止").arg(pid),
                                 QString("告警标题: %1").arg(alertTitle),
                                 LOG_ERROR);
                    dialogResult = AW_Prevent;
                    needLog = true;
                    decision = 1;
                }

                // 无论处理过程是否异常，都必须向 Client 返回决策，防止超时崩溃
                ClientAlertResponse resp = {};
                resp.pid = alertData.pid;
                resp.decision = decision;

                Packet respPkt = {};
                respPkt.PacketTyped = PTClientMessage;
                strcpy_s(respPkt.InfoTitle, sizeof(respPkt.InfoTitle), "ALERT_RESPONSE");
                respPkt.Pid = (int)alertData.pid;
                memcpy(respPkt.Message, &resp, sizeof(ClientAlertResponse));

                int sendResult = send(s, (const char*)&respPkt, sizeof(Packet), 0);
                if (sendResult == SOCKET_ERROR)
                {
                        Log_AddLogEx(QString("发送告警响应失败 PID=%1").arg((int)alertData.pid),
                                     QString("错误代码: %1").arg(WSAGetLastError()),
                                     LOG_ERROR);
                }
            }
            else if (strcmp(packet.InfoTitle, "RESULT") == 0)
            {
                // 命令结果
                Log_AddLogSimple(QString::fromUtf8(packet.Message), LOG_INFO);
            }
            else if (strcmp(packet.InfoTitle, "HEARTBEAT") == 0)
            {
                // 心跳响应
            }
            else if (strcmp(packet.InfoTitle, "PROCESS_CHECK") == 0)
            {
                // 进程检查请求（R0 驱动在 R3 未启用时转发的新进程检查）
                ClientProcessCheckData checkData;
                memcpy(&checkData, packet.Message, sizeof(ClientProcessCheckData));

                INT64 reqPid = checkData.pid;
                int pid = (int)reqPid;
                std::string procPath = checkData.processPath ? checkData.processPath : "";
                std::string procName = checkData.processName ? checkData.processName : "";
                std::string cmdLine;

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
                if (hProcess != NULL)
                {
                    cmdLine = Process_GetProcessCommandLine(hProcess);
                    std::string win32Path = Process_GetProcessPath(hProcess);
                    if (!win32Path.empty())
                    {
                        procPath = win32Path;
                    }
                    CloseHandle(hProcess);
                }

                int allow = 1;

                int autoListResult = R0CheckAutoList(pid, procPath.c_str(), procName.c_str());
                if (autoListResult == 1)
                {
                    allow = 1;
                }
                else if (autoListResult == -1)
                {
                    allow = 0;
                    Log_AddLogSimple(QString("已自动阻止进程启动 PID=%1").arg(reqPid), LOG_WARN);
                }
                else
                {
                    bool fileScanEnabled = (pProtectionSettingPage != nullptr &&
                        pProtectionSettingPage->pFileSwitch != nullptr &&
                        pProtectionSettingPage->pFileSwitch->getIsToggled());
                    bool blockingCheck = (pProtectionSettingPage != nullptr &&
                        pProtectionSettingPage->pIsFullScanSwitch != nullptr &&
                        pProtectionSettingPage->pIsFullScanSwitch->getIsToggled());
                    if (fileScanEnabled && !procPath.empty())
                    {
                        // 阻塞模式：使用带进度对话框的扫描，支持超时弹窗与用户取消（拒绝运行）
                        // 非阻塞模式：使用普通扫描（不弹窗，由 R0 端决定是否告警）
                        BOOL userRejected = FALSE;
                        std::string virusName;
                        BOOL scanResult = blockingCheck
                            ? ScanProcessFileWithProgress(procPath, FALSE, NULL, &userRejected, &virusName)
                            : ScanProcessFile(procPath, FALSE, NULL);

                        if (userRejected)
                        {
                            allow = 0;
                            Log_AddLogSimple(QString("用户已取消扫描并拒绝进程运行 PID=%1").arg(reqPid), LOG_WARN, "Kernel.ProcessCreateCheck");
                        }
                        else if (scanResult)
                        {
                            // 发现病毒：立即终止被挂起的进程，不等用户选择或驱动响应往返
                            {
                                HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                                if (hKill)
                                {
                                    TerminateProcess(hKill, 1);
                                    CloseHandle(hKill);
                                }
                            }
                            allow = 0;
                            Log_AddLogSimple(QString("已阻止恶意进程启动 PID=%1").arg(reqPid), LOG_WARN, "Kernel.ProcessCreateCheck");
                            // 进度对话框已关闭，此时弹出 ThreatDialog 不会导致嵌套事件循环冲突
                            if (blockingCheck && !virusName.empty())
                            {
                                QString fp = QString::fromLocal8Bit(procPath.c_str());
                                QString vn = QString::fromLocal8Bit(virusName.c_str());
                                QtConcurrent::run([fp, vn]() {
                                    ShowThreatDialog(fp, vn);
                                });
                            }
                        }
                        else if (allow && !cmdLine.empty())
                        {
                            std::wstring wsProcPath2 = QString::fromLocal8Bit(procPath.c_str()).toStdWString();
                            std::wstring wsCmdLine = QString::fromLocal8Bit(cmdLine.c_str()).toStdWString();
                            std::vector<std::wstring> cmdTargets = ExtractCommandLineTargetFiles(wsProcPath2, wsCmdLine);
                            for (const auto& targetW : cmdTargets)
                            {
                                std::string targetA = QString::fromStdWString(targetW).toLocal8Bit().toStdString();
                                BOOL targetRejected = FALSE;
                                std::string targetVirusName;
                                BOOL targetScanResult = blockingCheck
                                    ? ScanProcessFileWithProgress(targetA, FALSE, NULL, &targetRejected, &targetVirusName)
                                    : ScanProcessFile(targetA, FALSE, NULL);

                                if (targetRejected)
                                {
                                    allow = 0;
                                    Log_AddLogSimple(QString("用户已取消扫描并拒绝进程运行 PID=%1").arg(reqPid), LOG_WARN, "Kernel.ProcessCreateCheck");
                                    break;
                                }
                                if (targetScanResult)
                                {
                                    // 发现病毒：立即终止被挂起的进程，不等用户选择或驱动响应往返
                                    {
                                        HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                                        if (hKill)
                                        {
                                            TerminateProcess(hKill, 1);
                                            CloseHandle(hKill);
                                        }
                                    }
                                    allow = 0;
                                    Log_AddLogSimple(QString("已阻止恶意进程启动 PID=%1").arg(reqPid), LOG_WARN, "Kernel.ProcessCreateCheck");
                                    if (blockingCheck && !targetVirusName.empty())
                                    {
                                        QString tfp = QString::fromLocal8Bit(targetA.c_str());
                                        QString tvn = QString::fromLocal8Bit(targetVirusName.c_str());
                                        QtConcurrent::run([tfp, tvn]() {
                                            ShowThreatDialog(tfp, tvn);
                                        });
                                    }
                                    break;
                                }
                            }
                        }
                    }

                    if (allow)
                    {
                        CommandLineRiskResult risk = DetectCommandLineRisk(pid, procPath, cmdLine);
                        if (risk.detected)
                        {
                            if (risk.autoBlock)
                            {
                                /* 命令行可疑：无需用户确认，直接阻止并终止进程 */
                                allow = 0;
                                Log_AddLogSimple(QString("已自动阻止命令行可疑进程 PID=%1").arg(reqPid),
                                    LOG_WARN, "Kernel.CommandLineRisk");
                                {
                                    HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                                    if (hKill)
                                    {
                                        TerminateProcess(hKill, 1);
                                        CloseHandle(hKill);
                                    }
                                }
                            }
                            else if (AutoAllowList.Find(pid, risk.alertTitle))
                            {
                                allow = 1;
                            }
                            else if (AutoPreventList.Find(pid, risk.alertTitle))
                            {
                                allow = 0;
                                Log_AddLogSimple(QString("已阻止危险命令行进程 PID=%1").arg(reqPid), LOG_WARN, "Kernel.CommandLineRisk");
                            }
                            else
                            {
                                try
                                {
                                    RelActWarnType result = ShowAlertDialog(
                                        QString::fromUtf8(risk.alertTitle.c_str()),
                                        pid,
                                        QString::fromUtf8(risk.sendOut.c_str()));
                                    if (result == AW_Allow || result == AW_AutoAllow)
                                    {
                                        allow = 1;
                                        if (result == AW_AutoAllow)
                                        {
                                            R0AddToAutoList(pid, risk.alertTitle.c_str(), TRUE);
                                        }
                                    }
                                    else
                                    {
                                        allow = 0;
                                        if (result == AW_AutoPrevent)
                                        {
                                            R0AddToAutoList(pid, risk.alertTitle.c_str(), FALSE);
                                        }
                                        /* 用户选择拦截：直接终止被挂起的进程，确保即使
                                         * 驱动响应往返失败也能可靠结束进程 */
                                        {
                                            HANDLE hKill = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
                                            if (hKill)
                                            {
                                                TerminateProcess(hKill, 1);
                                                CloseHandle(hKill);
                                            }
                                        }
                                    }
                                }
                                catch (...)
                                {
                                    Log_AddLogSimple(QString("进程检查异常，默认阻止 PID=%1").arg(reqPid), LOG_ERROR, "Kernel.ProcessCreateCheck");
                                    allow = 0;
                                }
                            }
                        }
                    }
                }

                ClientProcessCheckResponse resp = {};
                resp.pid = checkData.pid;
                resp.allow = allow;

                Packet respPkt = {};
                respPkt.PacketTyped = PTClientMessage;
                strcpy_s(respPkt.InfoTitle, sizeof(respPkt.InfoTitle), "PROCESS_CHECK_RESP");
                respPkt.Pid = (int)checkData.pid;
                memcpy(respPkt.Message, &resp, sizeof(ClientProcessCheckResponse));

                int sendResult = send(s, (const char*)&respPkt, sizeof(Packet), 0);
                if (sendResult == SOCKET_ERROR)
                {
                    Log_AddLogSimple(QString("进程检查响应发送失败 PID=%1 错误=%2").arg(reqPid).arg(WSAGetLastError()), LOG_ERROR);
                }

                // 同时通知驱动端（R0 发来的 PROCESS_CHECK 需要回写决策）
                LONG driverStatus = allow ? 0 : STATUS_ACCESS_DENIED;
                R0SendFileEventResponse(driverStatus);
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_DLL_SCAN) == 0)
            {
                ClientDllScanData dllScanData;
                memcpy(&dllScanData, packet.Message, sizeof(ClientDllScanData));

                INT64 reqPid = dllScanData.pid;
                int pid = (int)reqPid;
                std::string dllPath = dllScanData.dllPath ? dllScanData.dllPath : "";
                std::string procPath = dllScanData.processPath ? dllScanData.processPath : "";

                Log_AddLogSimple(QString("[DLL-SCAN] 收到扫描请求 PID=%1 DLL=%2 阻塞=%3")
                              .arg(pid)
                              .arg(QString::fromUtf8(dllPath.c_str()))
                              .arg(dllScanData.blocking ? "是" : "否"), LOG_INFO);

                int allow = 1;
                bool memoryProtectionEnabled = (pProtectionSettingPage != nullptr &&
                    pProtectionSettingPage->pMemorySwitch != nullptr &&
                    pProtectionSettingPage->pMemorySwitch->getIsToggled());

                if (dllScanData.blocking)
                {
                    if (memoryProtectionEnabled && !dllPath.empty())
                    {
                        BOOL scanResult = ScanProcessFile(dllPath, FALSE, NULL);
                        if (scanResult)
                        {
                            allow = 0;
                            Log_AddLogSimple(QString("已阻止进程启动（DLL检测到病毒） PID=%1").arg(pid), LOG_WARN, "Kernel.DllScan");
                        }
                        else
                        {
                            allow = 1;
                        }
                    }
                }

                ClientDllScanResponse resp = {};
                resp.pid = dllScanData.pid;
                resp.allow = allow;
                resp.isSideLoad = dllScanData.isSideLoad;

                /* 同目录未签名 DLL 告警：通知用户该进程的签名已被降级 */
                if (dllScanData.isSideLoad && memoryProtectionEnabled)
                {
                    string sideLoadMsg = "[DLL 防护·签名降级]\n"
                        "检测到同目录未签名 DLL，进程签名已降级为不可信\n\n"
                        "进程: " + procPath + "\n"
                        "加载 DLL: " + dllPath + "\n"
                        "原因：同目录未签名 DLL 侧加载（Side-Load）";
                    Log_AddLogSimple(QString("[DLL-SCAN] 同目录未签名 DLL，签名降级 PID=%1 DLL=%2")
                        .arg(pid).arg(QString::fromUtf8(dllPath.c_str())), LOG_WARN, "Kernel.DllScan");
                    /* 发送告警（不阻塞，fire-and-forget） */
                    if (g_bClientConnected && Tran_ClientSocket != INVALID_SOCKET)
                    {
                        Packet sidePkt = {};
                        sidePkt.PacketTyped = PTClientMessage;
                        strcpy_s(sidePkt.InfoTitle, sizeof(sidePkt.InfoTitle), "DLL_SIDEPLOIT_ALERT");
                        sidePkt.Pid = pid;
                        strncpy_s(sidePkt.Message, sizeof(sidePkt.Message), sideLoadMsg.c_str(), _TRUNCATE);
                        send(Tran_ClientSocket, (const char*)&sidePkt, sizeof(Packet), 0);
                    }
                }

                Packet respPkt = {};
                respPkt.PacketTyped = PTClientMessage;
                strcpy_s(respPkt.InfoTitle, sizeof(respPkt.InfoTitle), CLIENT_MSG_DLL_SCAN_RESP);
                respPkt.Pid = (int)dllScanData.pid;
                memcpy(respPkt.Message, &resp, sizeof(ClientDllScanResponse));

                int sendResult = send(s, (const char*)&respPkt, sizeof(Packet), 0);
                if (sendResult == SOCKET_ERROR)
                {
                    Log_AddLogSimple(QString("[DLL-SCAN] 发送失败 PID=%1 err=%2")
                        .arg(reqPid).arg(WSAGetLastError()), LOG_ERROR);
                }
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_ROLLBACK_LOG) == 0)
            {
                /* 回滚记录（溢出丢磁盘）：驱动 g_baDroppedFiles/g_baRegOps 溢出上报，
                 * 主程序持久化到行为磁盘缓存（300MB 上限），供回滚时结合当前 list 执行。 */
                BA_ROLLBACK_LOG_RECORD rbRec;
                memcpy(&rbRec, packet.Message, sizeof(BA_ROLLBACK_LOG_RECORD));
                BehaviorCacheAppendRollbackRecord(rbRec);
            }
            else if (strcmp(packet.InfoTitle, CLIENT_MSG_ROLLBACK_CONFIRM) == 0)
            {
                BA_ROLLBACK_LIST rollbackList;
                memcpy(&rollbackList, packet.Message, sizeof(BA_ROLLBACK_LIST));

                int reqPid = (int)rollbackList.rootPid;
                int itemCount = rollbackList.itemCount;

                Log_AddLogSimple(QString("[ROLLBACK-CONFIRM] 收到回滚确认请求 PID=%1 项目数=%2")
                                 .arg(reqPid).arg(itemCount), LOG_INFO);

                // 静默模式：不弹出窗口，自动执行回滚
                if (g_bSilentModeEnabled)
                {
                    ClientRollbackConfirmResponse resp;
                    resp.pid = rollbackList.rootPid;
                    resp.selection.decision = 1;          // 自动回滚
                    resp.selection.itemCount = itemCount;
                    for (int i = 0; i < itemCount && i < BA_MAX_ROLLBACK_ITEMS; i++)
                        resp.selection.selected[i] = 1;   // 全选

                    Packet respPkt = {};
                    respPkt.PacketTyped = PTClientMessage;
                    strcpy_s(respPkt.InfoTitle, sizeof(respPkt.InfoTitle), CLIENT_MSG_ROLLBACK_CONFIRM_RESP);
                    respPkt.Pid = (int)rollbackList.rootPid;
                    memcpy(respPkt.Message, &resp, sizeof(ClientRollbackConfirmResponse));

                    int sendResult = send(s, (const char*)&respPkt, sizeof(Packet), 0);
                    if (sendResult == SOCKET_ERROR)
                    {
                        Log_AddLogSimple(QString("[ROLLBACK-CONFIRM] 静默回滚发送失败 PID=%1 错误=%2")
                                         .arg(reqPid).arg(WSAGetLastError()), LOG_ERROR);
                    }
                    else
                    {
                        Log_AddLogSimple(QString("[ROLLBACK-CONFIRM] 静默模式自动回滚 PID=%1 项目数=%2")
                                         .arg(reqPid).arg(itemCount), LOG_INFO);
                    }
                    continue;
                }

                SOCKET sockForResp = s;
                auto pList = std::make_shared<BA_ROLLBACK_LIST>(rollbackList);
                // 捕获父窗口（可能是nullptr），用Qt::UniqueConnection防止重复触发
                QWidget* parentWin = qApp->activeWindow();
                QMetaObject::invokeMethod(qApp, [pList, sockForResp, parentWin]() {
                    if (!pList || !parentWin) return;
                    ShowRollbackConfirmPopup(pList.get(), [pList, sockForResp](const BA_ROLLBACK_SELECTION& sel) {
                        if (!pList) return;
                        ClientRollbackConfirmResponse resp;
                        resp.pid = pList->rootPid;
                        resp.selection = sel;

                        Packet respPkt = {};
                        respPkt.PacketTyped = PTClientMessage;
                        strcpy_s(respPkt.InfoTitle, sizeof(respPkt.InfoTitle), CLIENT_MSG_ROLLBACK_CONFIRM_RESP);
                        respPkt.Pid = (int)pList->rootPid;
                        memcpy(respPkt.Message, &resp, sizeof(ClientRollbackConfirmResponse));

                        int sendResult = send(sockForResp, (const char*)&respPkt, sizeof(Packet), 0);
                        if (sendResult == SOCKET_ERROR)
                        {
                            Log_AddLogSimple(QString("[ROLLBACK-CONFIRM] 发送响应失败 PID=%1 错误=%2")
                                             .arg((int)pList->rootPid).arg(WSAGetLastError()), LOG_ERROR);
                        }
                        else
                        {
                            Log_AddLogSimple(QString("[ROLLBACK-CONFIRM] 已发送响应 PID=%1 决策=%2 选中=%3")
                                             .arg((int)pList->rootPid)
                                             .arg(sel.decision)
                                             .arg(sel.itemCount), LOG_INFO);
                        }
                    }, parentWin);
                }, Qt::UniqueConnection);
            }
        }
    }

    if (s != INVALID_SOCKET)
    {
        closesocket(s);
        Tran_ClientSocket = INVALID_SOCKET;
    }
    return 0;
}

// Load animation ===========
// 事件过滤器类
/*class LoadDialogEventFilter : public QObject
{
protected:
	bool eventFilter(QObject* obj, QEvent* event) override
	{
		if (event->type() == QEvent::KeyPress) {
			QKeyEvent* keyEvent = static_cast<QKeyEvent*>(event);

			// 屏蔽 Esc 键
			if (keyEvent->key() == Qt::Key_Escape) {
				return true;
			}

			// 屏蔽 Enter 键
			if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter) {
				return true;
			}

			// 屏蔽 Alt+F4
			if (keyEvent->key() == Qt::Key_F4 && (keyEvent->modifiers() & Qt::AltModifier)) {
				return true;
			}
		}

		// 屏蔽关闭事件
		if (event->type() == QEvent::Close) {
			event->ignore();
			return true;
		}

		return QObject::eventFilter(obj, event);
	}
};*/

// YARA加载线程
DWORD WINAPI LoadYaraThread(LPVOID lpParam)
{
	wstring basePath = Process_GetCurrentProcessPath().c_str();
	string sPath = (string)(CW2A)(basePath + L"\\Resources\\DataBase\\Malware.yarac").c_str();
	string sMemPath = (string)(CW2A)(basePath + L"\\Resources\\DataBase\\MalwareMemory.yarac").c_str();

	if (IS_LOAD_YARAC)
	{
		// 直接加载编译好的规则文件
		int result = yr_rules_load(sPath.c_str(), &Yara_Rules);

		if (result != ERROR_SUCCESS)
		{
			char errorMsg[256];
			sprintf_s(errorMsg, "启用YARA引擎失败。\n加载编译规则失败 (错误代码: %d)。", result);
			NewMessageBox(errorMsg, 3, 3);
		}
		else
		{
			Yara_IsReady = TRUE;
		}

		result = yr_rules_load(sMemPath.c_str(), &Yara_MemRules);

		if (result != ERROR_SUCCESS)
		{
			char errorMsg[256];
			sprintf_s(errorMsg, "启用YARA引擎失败。\n加载Memory编译规则失败 (错误代码: %d)。", result);
			NewMessageBox(errorMsg, 3, 3);
		}
		else
		{
			Yara_MemIsReady = TRUE;

			Log_AddLogSimple("YARA Memory规则加载成功。", LOG_SUCCESS);
		}
	}
	else
	{
		// 打开规则文件
		FILE* rules_file = fopen(sPath.c_str(), "r");

		if (!rules_file)
		{
			NewMessageBox("启用YARA引擎失败。\n打开规则文件失败。", 3);
		}
		else
		{
			if (yr_compiler_create(&Yara_Compiler) != ERROR_SUCCESS)
			{
				NewMessageBox("启用YARA引擎失败。\n问题在yr_compiler_create上。", 3);
			}
			else
			{
				int rel = 0;
				rel = yr_compiler_add_file(Yara_Compiler, rules_file, NULL, sPath.c_str());

				// 加载规则
				if (rel != ERROR_SUCCESS)
				{
					NewMessageBox("启用YARA引擎失败。\n问题在yr_compiler_add_file上。", 3);
				}
				else
				{
					// 获得规则
					if (yr_compiler_get_rules(Yara_Compiler, &Yara_Rules) != ERROR_SUCCESS)
					{
						NewMessageBox("启用YARA引擎失败。\n\n问题在yr_compiler_get_rules上。", 3);
					}
					else
					{
						Yara_IsReady = TRUE;

						Log_AddLogSimple("YARA规则加载成功。", LOG_SUCCESS);
					}
				}
			}

			fclose(rules_file);
		}
	}

	if (!Yara_IsReady) Log_AddLogSimple("Yara规则加载失败。", LOG_ERROR);
	if (!Yara_MemIsReady) Log_AddLogSimple("Yara Memory规则加载失败。", LOG_ERROR);

	isLoadReady++;

	return 0;
}

// ClamAV加载线程
// lpParam: 非NULL表示手动加载模式，不增加isLoadReady计数
DWORD WINAPI LoadClamAVThread(LPVOID lpParam)
{
	HMODULE hClamAV = LoadLibrary((Process_GetCurrentProcessPath() + L"\\libclamav.dll").c_str());
	if (!hClamAV)
	{
		Log_AddLogSimple("ClamAV规则加载失败: 无法加载 libclamav.dll", LOG_ERROR);
		if (lpParam == NULL) isLoadReady++;
		return 0;
	}
	g_hClamAVModule = hClamAV;

	pcl_init = (cl_init_type)GetProcAddress(hClamAV, "cl_init");
	pcl_engine_new = (cl_engine_new_type)GetProcAddress(hClamAV, "cl_engine_new");
	pcl_load = (cl_load_type)GetProcAddress(hClamAV, "cl_load");
	pcl_engine_compile = (cl_engine_compile_type)GetProcAddress(hClamAV, "cl_engine_compile");
	pcl_scanfile = (cl_scanfile_type)GetProcAddress(hClamAV, "cl_scanfile");
	pcl_engine_free = (cl_engine_free_type)GetProcAddress(hClamAV, "cl_engine_free");

	if (pcl_init && pcl_engine_new && pcl_load && pcl_engine_compile && pcl_scanfile && pcl_engine_free)
	{
		if (pcl_init(0) == CL_SUCCESS)
		{
			mClamAVEngine = pcl_engine_new();
			if (pcl_load(((string)(CW2A)(CString)Process_GetCurrentProcessPath().c_str() + "\\Resources\\DataBase\\ClamAVDataBase").c_str(), mClamAVEngine, &mClamScanned, CL_DB_STDOPT) == CL_SUCCESS)
			{
				if (pcl_engine_compile(mClamAVEngine) != CL_SUCCESS)
				{
					pcl_engine_free(mClamAVEngine);
				}
				else
				{
					memset(&mClamOptions, 0, sizeof(struct cl_scan_options));
					mClamOptions.parse |= ~0; // 启用所有解析器
					mClamOptions.general |= CL_SCAN_GENERAL_HEURISTICS;

					ClamAV_IsReady = TRUE;

					Log_AddLogSimple("ClamAV规则加载成功。", LOG_SUCCESS);
				}
			}
		}
	}

	if (!ClamAV_IsReady) Log_AddLogSimple("ClamAV规则加载失败。", LOG_ERROR);

	// 仅在自动加载模式（启动时）增加isLoadReady计数
	if (lpParam == NULL)
	{
		isLoadReady++;
	}

	return 0;
}

// PE Engine加载线程
DWORD WINAPI LoadPEEngineThread(LPVOID lpParam)
{
	string modelPath = (string)(CW2A)(Process_GetCurrentProcessPath().c_str() + (wstring)L"\\Resources\\DataBase\\Heur.data").c_str();
	if (mPEModel.LoadModel(modelPath)) {
		PE_IsReady = TRUE;

		Log_AddLogSimple("PE启发引擎加载成功。", LOG_SUCCESS);
	}
	else
	{
		Log_AddLogSimple("PE启发引擎加载失败。", LOG_ERROR);
	}
	
	isLoadReady++;

	return 0;
}
// ==========================

// UAC ======================
/*
DWORD SetUACWindowT(LPVOID lpParam)
{
	CreateWallpaperWithDim(Windows_UacDesktop);
	return 0;
}

// 创建仅允许管理员访问的安全描述符
SECURITY_ATTRIBUTES CreateAdminOnlySecurity()
{
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES) };
	PSECURITY_DESCRIPTOR pSD = new SECURITY_DESCRIPTOR;

	// SDDL字符串说明:
	// D: - DACL开始
	// (A;;0x1ff5ff;;;BA) - 允许管理员完全访问(0x1ff5ff = DESKTOP_ALL_ACCESS)
	// (A;;0x1ff5ff;;;SY) - 允许系统完全访问
	// 其他用户无任何权限
	if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
		L"D:(A;;0x1ff5ff;;;BA)(A;;0x1ff5ff;;;SY)",
		SDDL_REVISION_1,
		&pSD,
		nullptr))
	{
		sa.lpSecurityDescriptor = pSD;
		sa.bInheritHandle = FALSE;
	}

	return sa;
}

// 创建安全桌面
HDESK CreateSecureDesktop()
{
	SECURITY_ATTRIBUTES sa = CreateAdminOnlySecurity();

	HDESK hDesktop = CreateDesktopW(
		L"TianHongSafeDesktop$93dca56def6ca",
		nullptr,
		NULL,
		0,
		GENERIC_ALL,
		&sa);

	if (sa.lpSecurityDescriptor)
		delete sa.lpSecurityDescriptor;

	return hDesktop;
}
*/
// =========================

// inject to explorer ======

DWORD InjectT(LPVOID lpParam)
{
	HANDLE hProcessSnapShot = NULL;
	PROCESSENTRY32 pe32 = { 0 };

	hProcessSnapShot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (hProcessSnapShot == (HANDLE)-1) return false;

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hProcessSnapShot, &pe32))
	{
		do
		{
			if (!wcscmp(L"explorer.exe", pe32.szExeFile))
			{
				if (!Process_InjectDll(pe32.th32ProcessID))
				{
					NewMessageBox("Dll注入失败...\r\n无法进行DLL主动防护，你可以重启本软件以重试。", 3, 10);
				}

				::CloseHandle(hProcessSnapShot);
				return true;
			}
		} while (Process32Next(hProcessSnapShot, &pe32));
	}

	if (hProcessSnapShot) ::CloseHandle(hProcessSnapShot);

	return false;
}

// =========================

DWORD AddCertThread(LPVOID lpParam)
{
	ShellExecute(NULL, L"open", (Process_GetCurrentProcessPath() + L"\\Resources\\BinaryFiles\\certmgr.exe").c_str(), (L"-add -c \"" + Process_GetCurrentProcessPath() + L"\\Resources\\BinaryFiles\\root.spc\" -s -r localMachine root").c_str(), L"", SW_HIDE);
	// AddCertificateToTrustedRoot("root.spc");
	return 0;
}

void CheckAndDeleteKey(const char* keyPath)
{
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_CLASSES_ROOT, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		RegDeleteTreeA(HKEY_CLASSES_ROOT, keyPath);
		RegCloseKey(hKey);
	}
}

// 添加iot文件的图标
void RegAddIOT()
{
	// 定义文件扩展名和描述
	const char* ext = ".iot";
	LPCWSTR description = L"天宏安全防御加密过的病毒文件";
	std::wstring iconPathStr = Process_GetCurrentProcessPath() + L"\\Resources\\Image\\IOTIcon.ico";

	// 检查并删除现有的 .iot 扩展名键
	CheckAndDeleteKey(ext);
	CheckAndDeleteKey("iotfile");

	// 创建注册表键 HKEY_CLASSES_ROOT\\.iot
	HKEY hKey;
	if (RegCreateKeyExA(HKEY_CLASSES_ROOT, ext, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS)
	{
		// 设置默认值为 iotfile
		RegSetValueExA(hKey, "", 0, REG_SZ, (BYTE*)"iotfile", (DWORD)(strlen("iotfile") + 1));

		// 关闭注册表键
		RegCloseKey(hKey);
	}
	else
	{
		// mlog.LogWrite(Bad, "无法创建注册表键 - HKEY_CLASSES_ROOT\\.iot");
		return;
	}

	CheckAndDeleteKey("iotfile");
	// 创建注册表键 HKEY_CLASSES_ROOT\\iotfile
	if (RegCreateKeyExA(HKEY_CLASSES_ROOT, "iotfile", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS)
	{
		// 设置默认值
		RegSetValueExW(hKey, L"", 0, REG_SZ, (BYTE*)description, (lstrlen(description) + 1) * sizeof(WCHAR));

		// 创建 DefaultIcon 键
		HKEY hDefaultIconKey;
		if (RegCreateKeyExA(hKey, "DefaultIcon", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hDefaultIconKey, NULL) == ERROR_SUCCESS)
		{
			// 设置图标路径
			RegSetValueExW(hDefaultIconKey, L"", 0, REG_SZ, (BYTE*)iconPathStr.c_str(), (lstrlen(iconPathStr.c_str()) + 1) * sizeof(WCHAR));

			// 关闭注册表键
			RegCloseKey(hDefaultIconKey);
		}

		// 关闭注册表键
		RegCloseKey(hKey);
	}
	else
	{
		// mlog.LogWrite(Bad, "无法创建注册表键 - HKEY_CLASSES_ROOT\\iotfile");
		return;
	}

}

struct DetectionRule {
	std::regex pattern;
	int weight;
	std::string description;
};

// 预编译的正则表达式规则
static const std::vector<DetectionRule>& GetDetectionRules() {
	static const std::vector<DetectionRule> rules = []() {
		std::vector<DetectionRule> localRules;

		try {
			// 所有正则表达式在这里一次性编译
			localRules.push_back({
				std::regex(R"(ftp\s+-["']*s["']*\s*[:=]\s*.+)",
					std::regex::icase | std::regex::optimize),
				10,  // 降低权重，因为有更多规则
				"FTP with s parameter (script file)"
				});

			localRules.push_back({
				std::regex(R"(ftp\s+-["']*s["']*\s*[:=]\s*.*?\.(?:dll|exe|bat|cmd|com|scr|ps1|vbs|js|jse|vbe|wsf|wsh|msi|msh))",
					std::regex::icase | std::regex::optimize),
				15,
				"FTP with s parameter to executable file"
				});

			localRules.push_back({
				std::regex(R"(ftp\s+-["']*s["']*\s*[:=]\s*.*?\.(?:txt|log|ini|inf|cfg|config|xml|json|yaml|yml|reg|dat|db|sql))",
					std::regex::icase | std::regex::optimize),
				8,
				"FTP with s parameter to config/data file"
				});

			localRules.push_back({
				std::regex(R"(ftp\s+-["']*i["']*\s+.+?-(?:n|s|[:=]))",
					std::regex::icase | std::regex::optimize),
				8,
				"FTP with i parameter and other suspicious flags"
				});

			localRules.push_back({
				std::regex(R"(ftp\s+.+?(?:http|https|ftp)://)",
					std::regex::icase | std::regex::optimize),
				12,
				"FTP with URL"
				});

			localRules.push_back({
				std::regex(R"(powershell\s+(?:-[eEeCcNn]|-EncodedCommand|-ExecutionPolicy\s+bypass))",
					std::regex::icase | std::regex::optimize),
				15,
				"Suspicious PowerShell execution"
				});

			localRules.push_back({
				std::regex(R"(cmd\.exe\s+/[cCsS]\s+["'].*?[<>&|][^"']*["'])",
					std::regex::icase | std::regex::optimize),
				12,
				"CMD with special characters in command"
				});

			localRules.push_back({
				std::regex(R"(rundll32\s+(?:\.\\|\\\\[^\\]+\\).*?\.dll\s*,\s*\w+)",
					std::regex::icase | std::regex::optimize),
				12,
				"Rundll32 with network or relative path"
				});

			localRules.push_back({
				std::regex(R"((?:mshta|regsvr32)\s+(?:http|https|ftp)://)",
					std::regex::icase | std::regex::optimize),
				15,
				"Mshta/Regsvr32 with URL"
				});

			localRules.push_back({
				std::regex(R"(schtasks\s+.*?/create\s+.*?/tr\s+.*?(powershell|cmd|wscript))",
					std::regex::icase | std::regex::optimize),
				14,
				"Schtasks creating suspicious task"
				});

			localRules.push_back({
				std::regex(R"(wmic\s+.*?(?:process|service)\s+.*?(?:call|create|delete))",
					std::regex::icase | std::regex::optimize),
				8,
				"WMIC process/service manipulation"
				});

			localRules.push_back({
				std::regex(R"(certutil\s+-(?:decode|encode|urlcache|verifyctl))",
					std::regex::icase | std::regex::optimize),
				8,
				"Certutil with suspicious flags"
				});

			localRules.push_back({
				std::regex(R"(bitsadmin\s+.*?/(?:transfer|rawreturn))",
					std::regex::icase | std::regex::optimize),
				8,
				"Bitsadmin transfer"
				});

			localRules.push_back({
				std::regex(R"(regsvr32\s+.*?/s\s+.*?\.(dll|ocx|scr))",
					std::regex::icase | std::regex::optimize),
				8,
				"Regsvr32 silent registration"
				});

			localRules.push_back({
				std::regex(R"(msbuild\s+.*?\.(csproj|vbproj|proj))",
					std::regex::icase | std::regex::optimize),
				10,
				"MSBuild with project file"
				});

			localRules.push_back({
				std::regex(R"(cscript|wscript)\s+.*?\.(js|vbs|jse|vbe)\s+//e:jscript)",
					std::regex::icase | std::regex::optimize),
				10,
				"CScript/WScript with JScript engine"
				});

			localRules.push_back({
				std::regex(R"(/(?:c|k)\s+.*?echo\s+.*?>.*?\.(exe|dll|bat))",
					std::regex::icase | std::regex::optimize),
				5,
				"CMD echo to executable file"
				});

			localRules.push_back({
				std::regex(R"(-(?:w|windowstyle)\s+hidden)",
					std::regex::icase | std::regex::optimize),
				5,
				"Hidden window style"
				});

			localRules.push_back({
				std::regex(R"((?:frombase64string|convertfrom-base64|base64).{30,})",
					std::regex::icase | std::regex::optimize),
				5,
				"Base64 encoded content"
				});

			localRules.push_back({
				std::regex(R"(\$\{[^}]+\}|%[^%]+%|\$env:[^\\s]+)",
					std::regex::icase | std::regex::optimize),
				4,
				"Environment variable expansion"
				});

			localRules.push_back({
				std::regex(R"(iex\s*\(|invoke-expression)",
					std::regex::icase | std::regex::optimize),
				12,
				"Invoke-Expression usage"
				});

			localRules.push_back({
				std::regex(R"(\|[^|]*\$\{[^}]*\}[^|]*\||\|\s*foreach-object)",
					std::regex::icase | std::regex::optimize),
				7,
				"Pipeline with variable expansion or ForEach-Object"
				});

			localRules.push_back({
				std::regex(R"(\\.\\.*\\.*?\.(?:ps1|js|vbs|lnk))",
					std::regex::icase | std::regex::optimize),
				8,
				"Network path to script file"
				});

			localRules.push_back({
				std::regex(R"(taskkill\s+.*?/f\s+.*?/im\s+(?:av|defender|security))",
					std::regex::icase | std::regex::optimize),
				12,
				"Taskkill targeting security software"
				});

			localRules.push_back({
				std::regex(R"(net\s+.*?(?:user|group)\s+.*?(?:add|delete))",
					std::regex::icase | std::regex::optimize),
				9,
				"Net user/group add/delete"
				});

			// PowerShell Add-MpPreference / Set-MpPreference 绕过Windows Defender
			// 包括 ExclusionPath, ExclusionProcess, ExclusionExtension,
			// DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableScriptScanning 等
			localRules.push_back({
				std::regex(R"((?:add|set)-mppreference\s+.*?-(?:exclusion(?:path|process|extension|ipaddress)|disable(?:realtimemonitoring|behavior|ioav|script|blockatfirstseen|intrusionprevention|catchupfullscan|catchupquickscan|emailscanning|restorepoint|scanningnetworkfiles|archive)|submit(?:samplesconsent|samples)|reporting|mapstozones|lowthreat|highthreat|moderatethreat|severe))",
					std::regex::icase | std::regex::optimize),
				15,
				"PowerShell MpPreference Defender bypass"
				});

			// 增强: 捕获 MpPreference 的常见拼写错误 (add-WpPreference, add-MpPrefernce 等)
			// 以及 -ExclusionPath 的常见拼写错误 (-Exculsive, -Exclusion 等)
			localRules.push_back({
				std::regex(R"((?:add|set)-[mw]ppref[ae]r[ae]nce\s+.*?-(?:exclu[a-z]*|disable[a-z]*|submit[a-z]*|reporting|mapstozones|lowthreat|highthreat|moderatethreat|severe))",
					std::regex::icase | std::regex::optimize),
				14,
				"PowerShell MpPreference bypass (fuzzy match)"
				});

			// 裸 -exclusion 参数 (不完整但高度可疑，如 -exclusion c:\)
			localRules.push_back({
				std::regex(R"(-exclusion\s+\S)",
					std::regex::icase | std::regex::optimize),
				12,
				"PowerShell Defender exclusion path (generic)"
				});

	}
		catch (const std::regex_error& e) {
			// 记录错误但继续使用有效的规则
			std::cerr << "Warning: Failed to compile some regex patterns: "
				<< e.what() << " (code: " << e.code() << ")" << std::endl;
		}

		return localRules;
		}();

	return rules;
}

// 可疑术语列表
static const std::vector<std::string>& GetSuspiciousTerms() {
	static const std::vector<std::string> suspiciousTerms = {
		"downloadstring", "downloadfile", "webclient", "net.webclient",
		"shellcode", "meterpreter", "reverse_shell", "bind_shell",
		"add-mppreference", "set-mppreference", "add-wppreference",
		"set-wppreference", "-mppreference", "disable-realtime",
		"disable-windowsupdate", "disable-firewall", "bypassuac",
		"-exclusionpath", "-exclusionprocess", "-exclusionextension",
		"-exclusion", "-exclusive",  /* 常见拼写错误: -Exculsive */
		"-disablerealtimemonitoring", "-disablebehavior", "-disableioav",
		"-disablescriptscanning", "-disableblockatfirstseen",
		"uacbypass", "privilege::debug", "sekurlsa::", "mimikatz",
		"procdump", "lsadump", "credential", "password", "hash",
		"goldenticket", "silverticket", "pass-the-hash", "ptt",
		"wmiexec", "psexec", "smbexec", "atexec", "dcomexec",
		"kerberoasting", "asreproasting", "dcsync", "ntds.dit"
	};

	return suspiciousTerms;
}

// 可疑路径列表
static const std::vector<std::string>& GetSuspiciousPaths() {
	static const std::vector<std::string> suspiciousPaths = {
		"temp\\", "appdata\\", "users\\", "public\\",
		"programdata\\", "windows\\temp\\", "recycler\\",
		":\\$recycle.bin\\", "\\program files (x86)\\",
		"\\local settings\\", "\\application data\\"
	};

	return suspiciousPaths;
}

// 转换为小写的辅助函数
static std::string ToLower(const std::string& str) {
	std::string lowerStr = str;
	std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
		[](unsigned char c) { return std::tolower(c); });
	return lowerStr;
}

// 检查是否包含子字符串（不区分大小写）
static bool ContainsCaseInsensitive(const std::string& str, const std::string& substr) {
	if (substr.empty()) return false;

	auto it = std::search(
		str.begin(), str.end(),
		substr.begin(), substr.end(),
		[](char ch1, char ch2) {
			return std::tolower(ch1) == std::tolower(ch2);
		}
	);
	return it != str.end();
}

// RecvThread - 主检测函数
bool CheckMaliciousProcess(const std::string& processPath, const std::string& processArgs) {
	// 参数检查
	if (processArgs.empty()) {
		return false;
	}

	// 长度限制
	if (processArgs.length() > 100000) { // 根据实际情况调整
		return true; // 超长参数本身可疑
	}

	int totalScore = 0;

	try {
		// 转换为小写（仅一次）
		std::string argsLower = ToLower(processArgs);

		// 1. 使用预编译的正则表达式规则
		const auto& rules = GetDetectionRules();
		for (const auto& rule : rules) {
			try {
				if (std::regex_search(argsLower, rule.pattern)) {
					totalScore += rule.weight;

					// 达到阈值提前返回，提高性能
					if (totalScore >= 15) {
						return true;
					}
				}
			}
			catch (const std::regex_error&) {
				// 单个正则匹配失败，继续检查其他规则
				continue;
			}
		}

		// 2. 检查可疑术语
		const auto& suspiciousTerms = GetSuspiciousTerms();
		for (const auto& term : suspiciousTerms) {
			if (argsLower.find(term) != std::string::npos) {
				totalScore += 6;

				if (totalScore >= 15) {
					return true;
				}
			}
		}

		// 3. 参数长度检查
		if (argsLower.length() > 1500) {
			totalScore += 3;

			if (totalScore >= 15) {
				return true;
			}
		}

		// 4. 检查可疑路径
		if (!processPath.empty()) {
			std::string pathLower = ToLower(processPath);
			const auto& suspiciousPaths = GetSuspiciousPaths();

			for (const auto& path : suspiciousPaths) {
				if (pathLower.find(path) != std::string::npos) {
					totalScore += 4;

					if (totalScore >= 15) {
						return true;
					}
					break; // 找到一个可疑路径即可
				}
			}
		}

	}
	catch (const std::bad_alloc& e) {
		// 内存分配失败，可能是参数太大
		std::cerr << "Memory allocation failed in CheckMaliciousProcess: " << e.what() << std::endl;
		return true;
	}

	return totalScore >= 15;
}

// RecvThread - 检测函数
bool IsSystemAbusedProgram(const wstring& procPath, const wstring& exeName, const wstring& systemRootPath, const wstring& sysWow64Path)
{
	wstring systemPath = systemRootPath + L"\\" + exeName;
	wstring wow64Path = sysWow64Path + L"\\" + exeName;

	string procPathA = (string)(CW2A)(CString)procPath.c_str();
	return CompareWithoutCap(procPathA,
		(string)(CW2A)(CString)systemPath.c_str()) ||
		CompareWithoutCap(procPathA,
			(string)(CW2A)(CString)wow64Path.c_str());
}

// main - spfolderLoad
std::string GetSpecialFolderPath(KNOWNFOLDERID csidl) {
	std::string path;
	wchar_t* buffer = nullptr;

	if (SUCCEEDED((SHGetKnownFolderPath(
		csidl,  // 文件夹ID
		0,
		NULL,
		&buffer)))) {

		path = ConvertLPWSTRToLPSTR(buffer);
		CoTaskMemFree(buffer);
	}

	return path;
}

// main - DetectFile
void AddDetectFile(string Path)
{
	if (RansomDetectPathDicCount >= 70 || RansomDetectPathCount >= 70) return;

	RansomDetectPathDic[RansomDetectPathDicCount] = (string)Path + "\\." + GenerateFileName();

	RansomDetectPath[RansomDetectPathCount] = RansomDetectPathDic[RansomDetectPathDicCount] + "\\" + GenerateFileName() + ".docx";
	RansomDetectPath[RansomDetectPathCount + 1] = RansomDetectPathDic[RansomDetectPathDicCount] + "\\" + GenerateFileName() + ".pdf";
	RansomDetectPath[RansomDetectPathCount + 2] = RansomDetectPathDic[RansomDetectPathDicCount] + "\\" + GenerateFileName() + ".xls";
	RansomDetectPath[RansomDetectPathCount + 3] = (string)Path + "\\." + GenerateFileName() + ".pptx";
	RansomDetectPath[RansomDetectPathCount + 4] = (string)Path + "\\." + GenerateFileName() + ".txt";

	RansomDetectPathDicCount += 1;
	RansomDetectPathCount += 5;
}

// 扫描进程文件
BOOL ScanProcessFile(string FilePath, BOOL NeedTerminateProcess, HANDLE ProcessHandle, BOOL bSuppressThreatDialog, std::string* pVirusName)
{
	if (pProtectionSettingPage->pProcessSwitch->getIsToggled())
	{
		// 临时目录白名单检查（命中则该目录下所有文件免扫，无需计算SHA256）
		if (Whitelist_IsPathInTempDir(FilePath))
		{
			return FALSE;
		}

		// 强化白名单检查（命中则该路径文件免扫，无论sha256如何变化）
		if (Whitelist_IsPathEnhanced(FilePath))
		{
			return FALSE;
		}

		string thisSha256 = Encrypt_CalculateFileSHA256(FilePath);
		std::transform(thisSha256.begin(), thisSha256.end(), thisSha256.begin(),
			[](unsigned char c) { return static_cast<char>(std::tolower(c)); });

		RelScanVirus isVirus = UnDefined;

		if (Sha256White_IsReady)
		{
			if (std::binary_search(WhiteSha256List, WhiteSha256List + WhiteSha256Count, thisSha256))
			{
				return FALSE;
			}
		}

		EnterCriticalSection(&g_csScanCache);
		// 临时白名单（用户添加）检查
		if (WhiteSha256ListCache.find(thisSha256) != WhiteSha256ListCache.end())
		{
			LeaveCriticalSection(&g_csScanCache);
			return FALSE;
		}
		// 已扫描白名单缓存检查
		if (HasBeenScanedSha256WhiteList.find(thisSha256) != HasBeenScanedSha256WhiteList.end())
		{
			LeaveCriticalSection(&g_csScanCache);
			isVirus = ByScanedWhiteList;
			return FALSE;
		}

		auto itBlack = HasBeenScanedSha256BlackList.find(thisSha256);
		if (itBlack != HasBeenScanedSha256BlackList.end())
		{
			string virusNameFound = itBlack->second;  // 在持锁期间拷贝，避免迭代器失效
			LeaveCriticalSection(&g_csScanCache);
			isVirus = ByScanedBlackList;
			if (pVirusName) *pVirusName = virusNameFound;

			BOOL isShow = TRUE;

				if (NeedTerminateProcess)
				{
					if (ProcessHandle)
					{
						if (!Process_ZwTerminateProcess(ProcessHandle, 0))
						{
							isShow = FALSE;



							Log_AddLogEx(QString("拦截创建进程失败（病毒）"),
							             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: (失败)拦截创建进程")
							                .arg(QString::fromLocal8Bit(FilePath))
							                .arg(QString::fromLocal8Bit(virusNameFound)),
							             LOG_ERROR, "Kernel.ProcessCreateCheck");

							QString fp = QString::fromLocal8Bit(FilePath.c_str());
							QString vn = QString::fromLocal8Bit(virusNameFound.c_str());

							QMetaObject::invokeMethod(pMainPage, [ProcessHandle, FilePath, fp, vn]() {

								int entryId = pMainPage->mInfoBar->addEntry(
									"拦截创建进程失败，您的计算机面临风险。",
									"",
									InfoBar::Error,
									true,
									"重试",
									[ProcessHandle, fp, vn, entryId]() {
										if (!Process_ZwTerminateProcess(ProcessHandle, 0))
										{
											// 重试失败
											Log_AddLogEx(QString("拦截创建进程重试失败（病毒）"),
										             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: (重试后仍然失败)拦截创建进程")
										                .arg(fp, vn),
										             LOG_ERROR, "Kernel.ProcessCreateCheck");
										}
										else
										{
											// 重试成功
											Log_AddLogEx(QString("已拦截创建进程（病毒）"),
										             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: 拦截创建进程")
										                .arg(fp, vn),
										             LOG_INFO, "Kernel.ProcessCreateCheck");

											// 成功后移除条目
											pMainPage->mInfoBar->removeEntryById(entryId);
										}
									}
								);
								}, Qt::QueuedConnection);
						}
					}
				}

				if (isShow)
			{
				/* 当由 ScanProcessFileWithProgress（带进度对话框的阻塞扫描）调用时，
				 * 不在此处弹出 ThreatDialog —— 否则 ThreatDialog 的嵌套事件循环
				 * 会吞掉进度对话框的完成事件导致 Loading 永不退出 + 0xc0000005 崩溃。
				 * 由调用方在进度对话框关闭后再处理威胁。 */
				BOOL userIsolated = FALSE;
				if (!bSuppressThreatDialog)
				{
					// 同步等待用户选择：用户选"隔离文件"时返回 TRUE，文件已被加密，
					// 不再向 InfoBar 添加冗余隔离请求
					QtConcurrent::run([=, &userIsolated]() {
						userIsolated = ShowThreatDialog(QString::fromLocal8Bit(FilePath.c_str()), virusNameFound.c_str());
						}).waitForFinished();
				}

				Log_AddLogEx(QString("已拦截创建进程（病毒）"),
				             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: 拦截创建进程")
				                .arg(QString::fromLocal8Bit(FilePath))
				                .arg(QString::fromLocal8Bit(virusNameFound)),
				             LOG_INFO, "Kernel.ProcessCreateCheck");

				// 用户已在 ThreatDialog 中隔离文件，不再添加 InfoBar 条目
				if (!userIsolated)
				{
					QMetaObject::invokeMethod(pMainPage, [FilePath, virusNameFound]() {
						pMainPage->setSourceStatus(MainPage::StatusSource::Threat, MainPage::StatusLevel::Critical, "检测到未处理威胁");

						ElaMenu* menu = new ElaMenu();
						QString fp = QString::fromLocal8Bit(FilePath.c_str());

						int entryIndex = pMainPage->mInfoBar->addEntry(
							QString::fromLocal8Bit(virusNameFound.c_str()), QString::fromLocal8Bit(FilePath.c_str()), InfoBar::Error, true, "隔离文件", nullptr, menu);

						menu->addAction("隔离文件", [fp, entryIndex]() {
							Encrypt_EncrptFile((wstring)(CString)fp.toLocal8Bit().data());
							Log_AddLogSimple("已隔离文件: " + fp, LOG_SUCCESS);
							pMainPage->mInfoBar->removeEntryById(entryIndex);
							pMainPage->setSourceStatus(MainPage::StatusSource::Threat, MainPage::StatusLevel::Success);
							});

						menu->addAction("暂不处理", [fp, entryIndex]() {
							Log_AddLogSimple("暂不处理: " + fp, LOG_INFO);
							pMainPage->mInfoBar->removeEntryById(entryIndex);
							pMainPage->setSourceStatus(MainPage::StatusSource::Threat, MainPage::StatusLevel::Success);
							});
						}, Qt::QueuedConnection);
				}
				else
				{
					// 用户已隔离文件，清除该文件可能残留的 InfoBar 条目
					QMetaObject::invokeMethod(pMainPage, [FilePath]() {
						pMainPage->mInfoBar->removeEntriesByPath(QString::fromLocal8Bit(FilePath.c_str()));
						}, Qt::QueuedConnection);
				}
			}


				return TRUE;
		}
		LeaveCriticalSection(&g_csScanCache);

		string VirusName;

		if (isVirus == UnDefined)
		{
			isVirus = IsntVirus; // 假定文件不是病毒
			BOOL isVir = FALSE;

			VirusName = Scan_GeneralScan(FilePath, thisSha256);

			if (VirusName != "Empty") isVir = TRUE;

			if (!isVir && pVirusScanPage && pVirusScanPage->pScriptEngineSwitch && pVirusScanPage->pScriptEngineSwitch->getIsToggled())
			{
				string scriptResult = Scan_ScriptBatch(FilePath);
				if (scriptResult != "Empty")
				{
					VirusName = scriptResult;
					isVir = TRUE;
				}
			}

			if (isVir)
			{
				if (pVirusName) *pVirusName = VirusName;
				BOOL isShow = TRUE;

				if (NeedTerminateProcess)
				{
					if (ProcessHandle)
					{
						if (!Process_ZwTerminateProcess(ProcessHandle, 0))
						{
							isShow = FALSE;

						Log_AddLogEx(QString("拦截创建进程失败（病毒）"),
						             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: (失败)拦截创建进程")
						                .arg(QString::fromLocal8Bit(FilePath))
						                .arg(QString::fromLocal8Bit(VirusName)),
						             LOG_ERROR, "Kernel.ProcessCreateCheck");

							QString fp = QString::fromLocal8Bit(FilePath.c_str());
							QString vn = QString::fromLocal8Bit(VirusName.c_str());

							QMetaObject::invokeMethod(pMainPage, [ProcessHandle, FilePath, fp, vn]() {

								int entryId = pMainPage->mInfoBar->addEntry(
									"拦截创建进程失败，您的计算机面临风险。",
									"",
									InfoBar::Error,
									true,
									"重试",
									[ProcessHandle, fp, vn, entryId]() {
										if (!Process_ZwTerminateProcess(ProcessHandle, 0))
										{
											// 重试失败
											Log_AddLogEx(QString("拦截创建进程重试失败（病毒）"),
										             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: (重试后仍然失败)拦截创建进程")
										                .arg(fp, vn),
										             LOG_ERROR, "Kernel.ProcessCreateCheck");
										}
										else
										{
											// 重试成功
											Log_AddLogEx(QString("已拦截创建进程（病毒）"),
										             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: 拦截创建进程")
										                .arg(fp, vn),
										             LOG_INFO, "Kernel.ProcessCreateCheck");

											// 成功后移除条目
											pMainPage->mInfoBar->removeEntryById(entryId);
										}
									}
								);
								}, Qt::QueuedConnection);
						}
					}
				}

				if (isShow)
			{
				BOOL userIsolated = FALSE;
				if (!bSuppressThreatDialog)
				{
					// 同步等待用户选择：用户选"隔离文件"时返回 TRUE，文件已被加密，
					// 不再向 InfoBar 添加冗余隔离请求
					QtConcurrent::run([=, &userIsolated]() {
						userIsolated = ShowThreatDialog(QString::fromLocal8Bit(FilePath.c_str()), VirusName.c_str());
						}).waitForFinished();
				}

				Log_AddLogEx(QString("已拦截创建进程（病毒）"),
				             QString("路径: %1\n类型: %2\n级别: 病毒\n结果: 拦截创建进程")
				                .arg(QString::fromLocal8Bit(FilePath))
				                .arg(QString::fromLocal8Bit(VirusName)),
				             LOG_INFO, "Kernel.ProcessCreateCheck");

				// 用户已在 ThreatDialog 中隔离文件，不再添加 InfoBar 条目
				if (!userIsolated)
				{
					QMetaObject::invokeMethod(pMainPage, [FilePath, VirusName]() {
						pMainPage->setSourceStatus(MainPage::StatusSource::Threat, MainPage::StatusLevel::Critical, "检测到未处理威胁");

						ElaMenu* menu = new ElaMenu();
						QString fp = QString::fromLocal8Bit(FilePath.c_str());

						int entryIndex = pMainPage->mInfoBar->addEntry(
							QString::fromLocal8Bit(VirusName.c_str()), QString::fromLocal8Bit(FilePath.c_str()), InfoBar::Error, true, "隔离文件", nullptr, menu);

						menu->addAction("隔离文件", [fp, entryIndex]() {
							Encrypt_EncrptFile((wstring)(CString)fp.toLocal8Bit().data());
							Log_AddLogSimple("已隔离文件: " + fp, LOG_SUCCESS);
							pMainPage->mInfoBar->removeEntryById(entryIndex);
							pMainPage->setSourceStatus(MainPage::StatusSource::Threat, MainPage::StatusLevel::Success);
							});

						menu->addAction("暂不处理", [fp, entryIndex]() {
							Log_AddLogSimple("暂不处理: " + fp, LOG_INFO);
							pMainPage->mInfoBar->removeEntryById(entryIndex);
							pMainPage->setSourceStatus(MainPage::StatusSource::Threat, MainPage::StatusLevel::Success);
							});
						}, Qt::QueuedConnection);
				}
				else
				{
					// 用户已隔离文件，清除该文件可能残留的 InfoBar 条目
					QMetaObject::invokeMethod(pMainPage, [FilePath]() {
						pMainPage->mInfoBar->removeEntriesByPath(QString::fromLocal8Bit(FilePath.c_str()));
						}, Qt::QueuedConnection);
				}
			}

				isVirus = ByCommonScaned; // 确认为病毒，常规扫描方式
			}
		}

		if (isVirus == IsntVirus)
		{
			EnterCriticalSection(&g_csScanCache);
			HasBeenScanedSha256WhiteList.insert(thisSha256);
			LeaveCriticalSection(&g_csScanCache);
			return FALSE;
		}

		if (isVirus == ByCommonScaned)
		{
			EnterCriticalSection(&g_csScanCache);
			HasBeenScanedSha256BlackList[thisSha256] = VirusName;
			LeaveCriticalSection(&g_csScanCache);
			return TRUE;
		}
	}

	return FALSE;
}

struct ScanProcessPack
{
	string Path;
	BOOL NeedTerminateProcess;
	HANDLE ProcessHandle;
	HANDLE hCompleteEvent;                        // 扫描完成事件
	std::shared_ptr<std::atomic<bool>> pAbortFlag;         // 独立取消标志，每个扫描任务拥有自己的标志
	BOOL bSuppressThreatDialog;                   // 为 TRUE 时不弹出 ThreatDialog（由进度对话框路径使用）
	std::shared_ptr<std::string> pVirusName;               // 输出：检测到的病毒名（shared_ptr 保证线程安全生命周期）
};

// -------------------- DragFilter 类（独立定义）--------------------
class DragFilter : public QObject
{
public:
	DragFilter(QDialog* dlg, QObject* parent = nullptr)
		: QObject(parent), m_dialog(dlg) {
	}

protected:
	bool eventFilter(QObject* obj, QEvent* event) override
	{
		if (event->type() == QEvent::MouseButtonPress)
		{
			QMouseEvent* me = static_cast<QMouseEvent*>(event);
			if (me->button() == Qt::LeftButton)
			{
				m_dragPos = me->globalPos() - m_dialog->frameGeometry().topLeft();
				m_isDragging = true;
			}
		}
		else if (event->type() == QEvent::MouseMove)
		{
			QMouseEvent* me = static_cast<QMouseEvent*>(event);
			if (m_isDragging && (me->buttons() & Qt::LeftButton))
			{
				m_dialog->move(me->globalPos() - m_dragPos);
			}
		}
		else if (event->type() == QEvent::MouseButtonRelease)
		{
			m_isDragging = false;
		}
		return false;
	}

private:
	QDialog* m_dialog;
	QPoint m_dragPos;
	bool m_isDragging = false;
};

static BOOL ShowScanProgressDialogOnMainThread(HANDLE hCompleteEvent, HANDLE hScanThread,
	const QString& filePath,
	std::shared_ptr<std::atomic<bool>> pAbortFlag,
	BOOL* pUserRejected = nullptr);

// ==================== 异步线程函数（支持独立取消）====================
// hCompleteEvent 所有权归调用方/对话框：线程仅 SetEvent，不 CloseHandle。
// 调用方在确认线程退出且 notifier 销毁后负责 CloseHandle。
// 线程关闭句柄会导致 QWinEventNotifier 访问已关闭/已复用的句柄 → 堆损坏(0xC000070A)。
DWORD WINAPI ScanProcessFileASyncT(LPVOID lpParam)
{
	// 获取参数包的所有权
	std::unique_ptr<ScanProcessPack> pPack(static_cast<ScanProcessPack*>(lpParam));
	ScanProcessPack Pack = *pPack;  // 拷贝一份，因为 pPack 即将释放

	// 检查取消标志
	if (Pack.pAbortFlag && Pack.pAbortFlag->load())
	{
		if (Pack.hCompleteEvent)
		{
			SetEvent(Pack.hCompleteEvent);
			// 不关闭 hCompleteEvent，由调用方/对话框负责关闭
		}
		return 0;
	}

	// 执行实际扫描（可能耗时）
	DWORD result = ScanProcessFile(Pack.Path, Pack.NeedTerminateProcess, Pack.ProcessHandle, Pack.bSuppressThreatDialog, Pack.pVirusName.get());

	// 再次检查是否被取消
	if (Pack.pAbortFlag && Pack.pAbortFlag->load())
		result = 0;

	// 通知等待者扫描已完成（不关闭句柄，避免与 QWinEventNotifier 竞争）
	if (Pack.hCompleteEvent)
	{
		SetEvent(Pack.hCompleteEvent);
	}

	return result;
}

// ==================== 简单异步扫描（带超时）====================
BOOL ScanProcessFileASync(std::string FilePath, BOOL NeedTerminateProcess,
	HANDLE ProcessHandle, int iTimeOut)
{
	// 注意：此函数不使用完成事件，仅用于快速扫描模式
	auto pAbortFlag = std::make_shared<std::atomic<bool>>(false);

	ScanProcessPack* pPack = new ScanProcessPack;
	pPack->NeedTerminateProcess = NeedTerminateProcess;
	pPack->Path = FilePath;
	pPack->ProcessHandle = ProcessHandle;
	pPack->hCompleteEvent = NULL;
	pPack->pAbortFlag = pAbortFlag;   // 共享标志，但本函数中从不设置它
	pPack->bSuppressThreatDialog = FALSE;  // 快速扫描模式：允许弹 ThreatDialog
	pPack->pVirusName = nullptr;          // 此函数不输出病毒名（shared_ptr 默认为空）

	HANDLE hScan = CreateThread(NULL, 0, ScanProcessFileASyncT, pPack, 0, NULL);
	if (!hScan)
	{
		delete pPack;
		return ScanProcessFile(FilePath, NeedTerminateProcess, ProcessHandle);
	}

	DWORD dResult = WaitForSingleObject(hScan, iTimeOut);
	if (dResult == WAIT_TIMEOUT)
	{
		// 超时：不强制终止线程，只是不再等待。线程会继续运行并在完成后自动释放资源。
		CloseHandle(hScan);
		return FALSE;
	}

	DWORD dExitCode = 0;
	BOOL ok = GetExitCodeThread(hScan, &dExitCode);
	CloseHandle(hScan);
	return ok ? static_cast<BOOL>(dExitCode) : FALSE;
}

// ==================== 带进度对话框的扫描（支持多线程）====================
BOOL ScanProcessFileWithProgress(std::string FilePath, BOOL NeedTerminateProcess,
	HANDLE ProcessHandle, BOOL* pUserRejected, std::string* pVirusName)
{
	if (pUserRejected) *pUserRejected = FALSE;
	if (pVirusName) pVirusName->clear();

	// 创建独立取消标志
	auto pAbortFlag = std::make_shared<std::atomic<bool>>(false);
	// 使用 shared_ptr 管理病毒名，保证扫描线程写入时的生命周期安全
	// （即使用户取消后扫描线程仍在运行，string 也不会被提前销毁）
	auto pVirusNameShared = std::make_shared<std::string>();

	HANDLE hCompleteEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (!hCompleteEvent)
		return ScanProcessFile(FilePath, NeedTerminateProcess, ProcessHandle, FALSE, pVirusName);

	ScanProcessPack* pPack = new ScanProcessPack;
	pPack->NeedTerminateProcess = NeedTerminateProcess;
	pPack->Path = FilePath;
	pPack->ProcessHandle = ProcessHandle;
	pPack->hCompleteEvent = hCompleteEvent;
	pPack->pAbortFlag = pAbortFlag;   // 每个任务独立的标志
	pPack->bSuppressThreatDialog = TRUE;  // 进度对话框路径：不在扫描线程内弹 ThreatDialog
	pPack->pVirusName = pVirusNameShared;   // shared_ptr 保证线程安全生命周期

	HANDLE hScan = CreateThread(NULL, 0, ScanProcessFileASyncT, pPack, 0, NULL);
	if (!hScan)
	{
		CloseHandle(hCompleteEvent);
		delete pPack;
		return ScanProcessFile(FilePath, NeedTerminateProcess, ProcessHandle, FALSE, pVirusName);
	}

	// 先等待 1 秒，看是否能快速完成
	HANDLE waits[2] = { hCompleteEvent, hScan };
	DWORD waitResult = WaitForMultipleObjects(2, waits, FALSE, 1000);

	if (waitResult == WAIT_OBJECT_0 || waitResult == WAIT_OBJECT_0 + 1)
	{
		// 1秒内完成
		// 线程已退出，线程不再关闭 hCompleteEvent，由本函数负责关闭
		WaitForSingleObject(hScan, INFINITE);
		DWORD exitCode = 0;
		BOOL ok = GetExitCodeThread(hScan, &exitCode);
		CloseHandle(hScan);
		CloseHandle(hCompleteEvent);  // 线程不再关闭，由调用方负责
		// pPack 已在线程中删除，此处不能再 delete
		if (pVirusName) *pVirusName = *pVirusNameShared;
		return ok ? static_cast<BOOL>(exitCode) : FALSE;
	}

	// 超时，需要显示进度对话框（转移句柄所有权给对话框）
	QString fp = QString::fromLocal8Bit(FilePath.c_str());
	BOOL result = FALSE;

	// 在主线程显示对话框，并传递独立取消标志
	QMetaObject::invokeMethod(QApplication::instance(), [&]() -> BOOL {
		result = ShowScanProgressDialogOnMainThread(hCompleteEvent, hScan, fp, pAbortFlag, pUserRejected);
		// 对话框已负责关闭 hScanThread 和 hCompleteEvent
		hCompleteEvent = NULL;  // 标记所有权已转移给对话框
		hScan = NULL;           // 标记所有权已转移给对话框
		return result;
		}, Qt::BlockingQueuedConnection);

	// 安全兜底：hCompleteEvent 和 hScan 所有权已转移给对话框，正常情况下已为 NULL
	if (hScan) CloseHandle(hScan);
	// 注意：pPack 已在线程中删除，不能再次 delete
	// 将扫描线程写入的病毒名拷贝给调用方
	// 注意：如果用户取消后线程仍在运行，pVirusNameShared 的读取是安全的
	// （shared_ptr 保证 string 生命周期，但值可能不完整——这是可接受的，因为用户已取消）
	if (pVirusName) *pVirusName = *pVirusNameShared;
	return result;
}

// ==================== 进度对话框（现代化UI，支持独立取消）====================
static BOOL ShowScanProgressDialogOnMainThread(HANDLE hCompleteEvent, HANDLE hScanThread,
	const QString& filePath,
	std::shared_ptr<std::atomic<bool>> pAbortFlag,
	BOOL* pUserRejected)
{
	BOOL scanResult = FALSE;
	bool userCancelled = false;
	bool userRejected = false;  // 用户点击"取消扫描（拒绝运行）"
	bool handlesClosed = false;
	bool scanCompleted = false;
	bool threadExited = false;  // 扫描线程是否已退出（用于判断是否可安全关闭 hCompleteEvent）

	// ---------- 创建 UI ----------
	QDialog* dlg = new QDialog(nullptr);
	dlg->setWindowFlags(Qt::WindowStaysOnTopHint | Qt::FramelessWindowHint | Qt::Dialog);
	// 不设置 WA_DeleteOnClose：若对话框被 ESC/意外关闭，WA_DeleteOnClose 会立即删除 dlg，
	// 但局部变量(notifier/safetyTimer)仍引用 dlg 的子对象，导致 use-after-free 堆损坏(0xC000070A)。
	// 改为由函数末尾 deleteLater() 统一管理生命周期。
	dlg->setAttribute(Qt::WA_TranslucentBackground);
	dlg->setFixedSize(480, 320);
	dlg->setWindowModality(Qt::ApplicationModal);
	dlg->setWindowTitle("天宏安全防御");

	QWidget* mainWidget = new QWidget(dlg);
	mainWidget->setObjectName("scanMainWidget");

	QVBoxLayout* dlgLayout = new QVBoxLayout(dlg);
	dlgLayout->setContentsMargins(0, 0, 0, 0);
	dlgLayout->addWidget(mainWidget);

	// 顶部渐变线
	QFrame* topLine = new QFrame(mainWidget);
	topLine->setFixedHeight(4);
	topLine->setObjectName("scanTopLine");

	QVBoxLayout* mainLayout = new QVBoxLayout();
	mainLayout->setSpacing(10);
	mainLayout->setContentsMargins(24, 16, 24, 18);

	// 图标 + 标题行
	QHBoxLayout* titleRow = new QHBoxLayout();
	QLabel* iconLabel = new QLabel(mainWidget);
	iconLabel->setObjectName("scanIconLabel");
	QIcon fileIcon = QFileIconProvider().icon(QFileInfo(filePath));
	if (fileIcon.isNull())
		fileIcon = QApplication::style()->standardIcon(QStyle::SP_FileIcon);
	iconLabel->setPixmap(fileIcon.pixmap(40, 40));
	titleRow->addWidget(iconLabel, 0, Qt::AlignVCenter);

	QLabel* tipLabel = new QLabel("正在扫描，请耐心等待…", mainWidget);
	tipLabel->setObjectName("scanTipLabel");
	tipLabel->setStyleSheet("font-size: 16px; font-weight: bold;");
	titleRow->addWidget(tipLabel, 1, Qt::AlignVCenter | Qt::AlignLeft);
	titleRow->addStretch();
	mainLayout->addLayout(titleRow);

	// 文件名
	QFileInfo fileInfo(filePath);
	QLabel* fileNameLabel = new QLabel(fileInfo.fileName(), mainWidget);
	fileNameLabel->setObjectName("scanFileNameLabel");
	fileNameLabel->setWordWrap(true);
	fileNameLabel->setStyleSheet("font-size: 13px; padding: 0 4px;");
	mainLayout->addWidget(fileNameLabel);

	// 进度条
	QProgressBar* progressBar = new QProgressBar(mainWidget);
	progressBar->setRange(0, 0);
	progressBar->setFixedHeight(6);
	progressBar->setTextVisible(false);
	progressBar->setObjectName("scanProgressBar");
	mainLayout->addWidget(progressBar);

	// 状态提示
	QLabel* statusLabel = new QLabel("扫描中…完成后将自动放行安全文件", mainWidget);
	statusLabel->setObjectName("scanStatusLabel");
	statusLabel->setStyleSheet("font-size: 12px;");
	mainLayout->addWidget(statusLabel);

	mainLayout->addStretch();

	// 按钮区
	QHBoxLayout* btnLayout = new QHBoxLayout();
	btnLayout->setSpacing(10);

	QPushButton* rejectBtn = new QPushButton("取消扫描（拒绝运行）", mainWidget);
	rejectBtn->setObjectName("scanRejectBtn");
	rejectBtn->setFixedSize(170, 34);
	rejectBtn->setCursor(Qt::PointingHandCursor);

	QPushButton* allowBtn = new QPushButton("直接运行", mainWidget);
	allowBtn->setObjectName("scanAllowBtn");
	allowBtn->setFixedSize(120, 34);
	allowBtn->setCursor(Qt::PointingHandCursor);

	btnLayout->addStretch();
	btnLayout->addWidget(rejectBtn);
	btnLayout->addWidget(allowBtn);
	mainLayout->addLayout(btnLayout);

	// 品牌
	QLabel* brandLabel = new QLabel("天宏安全防御 · 进程保护", mainWidget);
	brandLabel->setObjectName("scanBrandLabel");
	brandLabel->setStyleSheet("font-size: 11px; color: #999;");
	mainLayout->addWidget(brandLabel, 0, Qt::AlignLeft);

	QVBoxLayout* contentLayout = new QVBoxLayout(mainWidget);
	contentLayout->setContentsMargins(0, 0, 0, 0);
	contentLayout->setSpacing(0);
	contentLayout->addWidget(topLine);
	contentLayout->addLayout(mainLayout);

	// 主题样式
	auto applyTheme = [dlg, topLine, tipLabel, fileNameLabel, statusLabel, brandLabel, progressBar, rejectBtn, allowBtn, mainWidget]() {
		ElaThemeType::ThemeMode tm = eTheme->getThemeMode();
		bool isDark = (tm == ElaThemeType::Dark);
		QString baseBg = ElaThemeColor(tm, WindowBase).name();
		QString textColor = ElaThemeColor(tm, BasicText).name();
		QString subTextColor = isDark ? "#9CA3AF" : "#6B7280";

		dlg->setStyleSheet(QString("QDialog { background: transparent; border-radius: 14px; }"));
		mainWidget->setStyleSheet(QString(
			"#scanMainWidget { background: %1; border-radius: 14px; "
			"border: 1px solid %2; }").arg(baseBg, isDark ? "#3a3a3a" : "#e0e0e0"));

		topLine->setStyleSheet(QString(
			"background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
			"stop:0 #0078d4, stop:0.5 #2196f3, stop:1 #00bcd4);"
			"border: none; border-top-left-radius: 14px; border-top-right-radius: 14px;"));

		tipLabel->setStyleSheet(QString("font-size: 16px; font-weight: bold; color: %1;").arg(textColor));
		fileNameLabel->setStyleSheet(QString("font-size: 13px; color: %1; padding: 0 4px;").arg(subTextColor));
		statusLabel->setStyleSheet(QString("font-size: 12px; color: %1;").arg(subTextColor));
		brandLabel->setStyleSheet("font-size: 11px; color: #999;");

		QString trackBg = isDark ? "#3a3a3a" : "#e8e8e8";
		progressBar->setStyleSheet(QString(
			"QProgressBar { border: none; border-radius: 3px; background: %1; }"
			"QProgressBar::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
			"stop:0 #0078d4, stop:1 #00bcd4); border-radius: 3px; }").arg(trackBg));

		rejectBtn->setStyleSheet(QString(
			"QPushButton { background-color: #e74c3c; color: white; border: none;"
			"border-radius: 6px; font-size: 13px; font-weight: bold; }"
			"QPushButton:hover { background-color: #c0392b; }"
			"QPushButton:pressed { background-color: #a93226; }"));

		allowBtn->setStyleSheet(QString(
			"QPushButton { background-color: %1; color: white; border: none;"
			"border-radius: 6px; font-size: 13px; }"
			"QPushButton:hover { background-color: %2; }"
			"QPushButton:pressed { background-color: %3; }")
			.arg(isDark ? "#27ae60" : "#2e7d32",
			     isDark ? "#229954" : "#1b5e20",
			     isDark ? "#1e8449" : "#0d3f12"));
	};
	applyTheme();
	QObject::connect(eTheme, &ElaTheme::themeModeChanged, dlg, [applyTheme, dlg](ElaThemeType::ThemeMode) {
		applyTheme();
		dlg->update();
	});

	// 对话框拖动
	dlg->installEventFilter(new DragFilter(dlg, dlg));

	// ---------- 事件循环与句柄管理 ----------
	// 所有权规则：
	//   hCompleteEvent -> 对话框负责关闭（在 delete notifier 之后，确保 Qt 不再访问句柄）
	//   hScanThread    -> 对话框负责关闭（等待线程退出后 CloseHandle）
	//   notifier       -> 对话框负责删除
	// 扫描线程仅调用 SetEvent，不关闭 hCompleteEvent，
	// 避免与 QWinEventNotifier 竞争导致堆损坏(0xC000070A)
	QEventLoop loop;
	QWinEventNotifier* notifier = nullptr;

	// 统一的清理函数：禁用 notifier + 等待线程退出 + 关闭 hScanThread
	auto cleanupForExit = [&]() {
		if (handlesClosed) return;
		handlesClosed = true;
		// 先禁用 notifier，防止线程 SetEvent 后 notifier 仍被触发
		if (notifier) notifier->setEnabled(false);
		// 设置取消标志
		if (pAbortFlag)
			pAbortFlag->store(true);
		// 等待扫描线程退出（线程仅 SetEvent，不关闭 hCompleteEvent）
		if (hScanThread) {
			DWORD waitRes = WaitForSingleObject(hScanThread, 10000);
			if (waitRes == WAIT_OBJECT_0)
				threadExited = true;  // 线程已退出，可安全关闭 hCompleteEvent
			CloseHandle(hScanThread);
			hScanThread = NULL;
		}
		// 注意：不在此处关闭 hCompleteEvent，需在 delete notifier 之后关闭
	};

	// 处理 ESC 键/意外关闭：QDialog 默认 ESC 触发 rejected()，
	// 将其等同于"直接运行"（取消扫描，放行进程），防止 loop 卡死
	QObject::connect(dlg, &QDialog::rejected, [&]() {
		if (userCancelled) return;
		userCancelled = true;
		userRejected = false;
		scanResult = FALSE;
		cleanupForExit();
		loop.quit();
	});

	// "直接运行"：取消扫描，放行进程
	QObject::connect(allowBtn, &QPushButton::clicked, [&]() {
		if (userCancelled) return;
		userCancelled = true;
		userRejected = false;
		scanResult = FALSE;
		cleanupForExit();
		loop.quit();
	});

	// "取消扫描（拒绝运行）"：取消扫描，阻止进程
	QObject::connect(rejectBtn, &QPushButton::clicked, [&]() {
		if (userCancelled) return;
		userCancelled = true;
		userRejected = true;
		scanResult = TRUE;  // 视为威胁，阻止运行
		cleanupForExit();
		loop.quit();
	});

	// 监听扫描完成事件
	if (hCompleteEvent) {
		notifier = new QWinEventNotifier(hCompleteEvent, dlg);
		QObject::connect(notifier, &QWinEventNotifier::activated, [&]() {
			if (handlesClosed) return;
			scanCompleted = true;
			// 先禁用 notifier，防止后续操作期间仍被触发
			notifier->setEnabled(false);
			if (hScanThread) {
				// 等待扫描线程完全退出后再读取退出码，
				// 否则 GetExitCodeThread 返回 STILL_ACTIVE(259) 被误判为病毒(非零=TRUE)
				WaitForSingleObject(hScanThread, 10000);
				threadExited = true;  // 线程已调用 SetEvent 并退出
				DWORD exitCode = 0;
				if (GetExitCodeThread(hScanThread, &exitCode) && exitCode != STILL_ACTIVE)
					scanResult = static_cast<BOOL>(exitCode);
				CloseHandle(hScanThread);
				hScanThread = NULL;
			}
			handlesClosed = true;
			loop.quit();
			});
	}

	// 安全定时器（60秒超时，防止界面卡死）
	QTimer* safetyTimer = new QTimer(dlg);
	safetyTimer->setSingleShot(true);
	QObject::connect(safetyTimer, &QTimer::timeout, [&]() {
		cleanupForExit();
		if (loop.isRunning())
			loop.quit();
		});
	safetyTimer->start(60000);

	// 居中显示
	QScreen* screen = QGuiApplication::primaryScreen();
	if (screen) {
		QRect screenRect = screen->availableGeometry();
		dlg->move(screenRect.center() - dlg->rect().center());
	}

	dlg->show();
	dlg->raise();
	dlg->activateWindow();

	loop.exec();   // 进入事件循环

	// 设置用户拒绝标志
	if (pUserRejected)
		*pUserRejected = userRejected ? TRUE : FALSE;

	// 最终清理（如果 loop.exec() 因未知原因退出但清理未执行）
	cleanupForExit();
	if (notifier) {
		delete notifier;  // 先销毁 notifier，确保 Qt 内部取消注册 hCompleteEvent
		notifier = nullptr;
	}
	// notifier 已销毁，线程已退出（或已超时），可安全关闭 hCompleteEvent
	// 若线程未退出（超时），泄露句柄以避免 use-after-free
	if (hCompleteEvent && threadExited) {
		CloseHandle(hCompleteEvent);
		hCompleteEvent = NULL;
	}
	dlg->deleteLater();

	return scanResult;
}

// ==================== 自动选择扫描模式（全量/快速）====================
BOOL ScanProcessAutoChooseSync(std::string FilePath, BOOL NeedTerminateProcess,
	HANDLE ProcessHandle, int iTimeOut = 1000)
{
	// 注意：pProtectionSettingPage 等外部变量需要保证线程安全（如加锁）
	// 这里保留原有逻辑，但建议对全局列表进行互斥保护
	if (pProtectionSettingPage->pIsFullScanSwitch->getIsToggled())
	{
		// 全扫描模式：使用带进度对话框的扫描（有bug，回退）
		return ScanProcessFile(FilePath, NeedTerminateProcess, ProcessHandle);
	}
	else
	{
		// 快速扫描模式：使用简单异步扫描（超时直接返回 FALSE）
		return ScanProcessFileASync(FilePath, NeedTerminateProcess, ProcessHandle, iTimeOut);
	}
}

/**
 * @brief 在启动时主动加载 BatchScan 动态规则文件（heuristic + sandbox）
 *        使用内部静态 guard 防止重复读写。
 *        若规则文件不存在则回退到内嵌规则，仅记录 ERROR 警告。
 */
static void InitBatchScanRules()
{
    // 静态 guard：保证整个进程生命周期内只执行一次
    static bool s_loaded = false;
    if (s_loaded) return;
    s_loaded = true;

    std::string exeDir;
    {
        char buf[MAX_PATH] = {0};
        DWORD n = GetModuleFileNameA(NULL, buf, MAX_PATH);
        if (n > 0) {
            std::string p(buf);
            size_t pos = p.rfind('\\');
            if (pos != std::string::npos) exeDir = p.substr(0, pos);
        }
    }
    if (exeDir.empty()) return;

    const std::string heurPath = exeDir + "\\Resources\\rules\\batchscan\\heuristics.toml";
    const std::string sandPath = exeDir + "\\Resources\\rules\\batchscan\\sandbox.toml";

    // 触发 Lazy static 初始化（BatchScan.h 中的 Match() 内部静态变量）
    // 通过构造一个空的 ScriptDetectionEngine 并调用 scanFile 触发文件读取
    (void)heurPath; // 由 DynamicRuleLoader 内部路径拼接驱动，此处仅作占位说明
    (void)sandPath;

    // 主动验证文件是否存在，并输出对应日志
    {
        std::ifstream f(heurPath, std::ios::binary);
        if (f.good()) {
            Log_AddLogSimple("启发式规则加载成功（来自 heuristics.toml）。", LOG_SUCCESS);
        } else {
            Log_AddLogSimple("启发式规则文件未找到（heuristics.toml），将使用内嵌默认规则。", LOG_ERROR);
        }
    }
    {
        std::ifstream f(sandPath, std::ios::binary);
        if (f.good()) {
            Log_AddLogSimple("沙盒行为链规则加载成功（来自 sandbox.toml）。", LOG_SUCCESS);
        } else {
            Log_AddLogSimple("沙盒行为链规则文件未找到（sandbox.toml），将使用内嵌默认规则。", LOG_ERROR);
        }
    }
}

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);

    // 判断是否由 Toast 点击协议启动
    bool launchedFromToast = false;
    for (int i = 1; i < argc; ++i)
    {
        QString arg = QString::fromLocal8Bit(argv[i]);
        if (arg.contains("tianhongsecuritydefense", Qt::CaseInsensitive))
        {
            launchedFromToast = true;
            break;
        }
    }

    eApp->init();

	pMainWindow = new MainWindow;
	pMainWindow->InitWindow();

	// 杀软初始化
	HANDLE hSingleMutex = ::CreateMutex(NULL, FALSE, L"TianHongMain$2b8ed8912e");
	Windows_OrgDesktop = GetThreadDesktop(GetCurrentThreadId());

	if (hSingleMutex == NULL || GetLastError() == ERROR_ALREADY_EXISTS)
	{
		MessageBox(NULL, L"发现已有程序运行，退出", NULL, MB_TOPMOST | MB_ICONINFORMATION);
		if (hSingleMutex) CloseHandle(hSingleMutex);
		exit(0);
	}
	else
	{
		// 启动时主动加载 BatchScan 动态规则（有 guard，仅执行一次）
		InitBatchScanRules();

		LPTOP_LEVEL_EXCEPTION_FILTER pException = SetUnhandledExceptionFilter(catchExceptionFileter);

		if (IsWindows11())
		{
			if (MessageBox(NULL, L"天宏安全防御对 Windows 11 并不兼容，可能导致运行时出现奇奇怪怪的bug，是否继续运行？", L"运行前注意事项", MB_ICONWARNING | MB_TOPMOST | MB_YESNO) == IDNO)
			{
				exit(1);
			}
		}

		HANDLE hCertThread = CreateThread(0, 0, AddCertThread, 0, 0, 0);

		// 检查文件完整性
		vector<wstring> invalidfile = File_CheckFolderSignature(Process_GetCurrentProcessPath());
		vector<wstring> NeedDeepScanFile =
		{
			L"\\TianHong-Security-Defense.exe",
			L"\\Resources\\BinaryFiles\\certmgr.exe",
			L"\\Resources\\BinaryFiles\\TianHongDefense32.dll",
			L"\\Resources\\BinaryFiles\\TianHongDefense64.dll",
			L"\\Resources\\BinaryFiles\\TianHongInjector32.exe"
		};

		if (!invalidfile.empty())
		{
			for (wstring file : invalidfile)
			{
				if (MessageBox(NULL, (file + L" 为签名无效文件，这可能存在隐患。\n\n当然，你可以点击\"确认\"继续运行程序。").c_str(), L"程序完整性校验警告", MB_TOPMOST | MB_ICONWARNING | MB_YESNO) == IDNO)
				{
					WaitForSingleObject(hCertThread, 10000);

					exit(1);
				}
				else break;
			}
		}
		else
		{
			for (wstring file : NeedDeepScanFile)
			{
				if (!File_CheckFileSignature(Process_GetCurrentProcessPath() + file, L"TianHongTechnology"))
				{
					if (MessageBox(NULL, (file + L" 为签名无效文件，这可能存在隐患。\n\n当然，你可以点击\"确认\"继续运行程序。").c_str(), L"程序完整性校验警告", MB_TOPMOST | MB_ICONWARNING | MB_YESNO) == IDNO)
					{
						WaitForSingleObject(hCertThread, 10000);

						exit(1);
					}
				}
				else break;
			}
		}

		if (hCertThread) CloseHandle(hCertThread);

		GetSystemDirectoryW(wcSystemRootPath, 32767);
		GetWindowsDirectoryW(wcWindowsPath, 32767);
		GetSystemWow64DirectoryW(wcSysWow64Path, 32767);


		DeskPath = new char[MAX_PATH];
		SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, DeskPath);

		ifstream VirusSha256;
		VirusSha256.open((char*)(CW2A)((CString)Process_GetCurrentProcessPath().c_str() + L"\\Resources\\DataBase\\malware.sha256"), ios::in);

		if (!VirusSha256.is_open())
		{
			NewMessageBox("病毒库打开失败: virus.sha256。", 3);
		}
		else
		{
			size_t FileLineCount = 0;
			string scanLineStr;

			// 确保文件指针回到开头
			VirusSha256.clear();
			VirusSha256.seekg(0);

			while (getline(VirusSha256, scanLineStr))
			{
				++FileLineCount;
			}

			// 重置文件指针以便后续操作
			VirusSha256.clear();
			VirusSha256.seekg(0);

			VirusNameList = new string[FileLineCount + 100];
			VirusSha256List = new string[FileLineCount + 100];

			string ReadBuf;

			bool isReadingName = true;

			while (VirusSha256 >> ReadBuf)
			{
				if (isReadingName)
				{
					VirusNameList[Sha256Count] = ReadBuf;
					isReadingName = false;
				}
				else
				{
					VirusSha256List[Sha256Count] = ReadBuf;
					isReadingName = true;
					Sha256Count++;
				}
			}
			Sha256Black_IsReady = TRUE;
			// NewMessageBox("静态病毒库读取完成。", 4);
		}

		ifstream WhiteSha256;
		WhiteSha256.open((char*)(CW2A)((CString)Process_GetCurrentProcessPath().c_str() + L"\\Resources\\DataBase\\white.sha256"), ios::in);

		if (!WhiteSha256.is_open())
		{
			NewMessageBox("病毒库打开失败: white.sha256。", 3);
		}
		else
		{
			size_t FileLineCount = 0;
			string scanLineStr;

			// 确保文件指针回到开头
			WhiteSha256.clear();
			WhiteSha256.seekg(0);

			while (getline(WhiteSha256, scanLineStr))
			{
				++FileLineCount;
			}

			// 重置文件指针以便后续操作
			WhiteSha256.clear();
			WhiteSha256.seekg(0);

			WhiteSha256List = new string[FileLineCount + 100];

			string ReadBuf;

			while (WhiteSha256 >> ReadBuf)
			{
				std::transform(ReadBuf.begin(), ReadBuf.end(), ReadBuf.begin(),
					[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
				WhiteSha256List[WhiteSha256Count] = ReadBuf;
				WhiteSha256Count++;
			}
			std::sort(WhiteSha256List, WhiteSha256List + WhiteSha256Count);
			Sha256White_IsReady = TRUE;
			// NewMessageBox("静态白名单库读取完成。", 4);
			Log_AddLogSimple("静态白名单库读取完成。", LOG_SUCCESS);
		}

		// 临时白名单加载已移至 InitializeCriticalSection(&g_csScanCache) 之后，
		// 由 Whitelist_LoadTemporary() 统一处理，避免在 CS 未初始化时调用 EnterCriticalSection 导致崩溃

		DWORD backCode = 0;
		Process_GetDebugPrivilege(SE_DEBUG_NAME, &backCode);
		Process_GetDebugPrivilege(SE_SYSTEM_PROFILE_NAME, &backCode);
		Process_GetDebugPrivilege(SE_IMPERSONATE_NAME, &backCode);

		Log_AddLogSimple("提权完成！", LOG_SUCCESS);

		WSADATA wsaData;

		// 初始化 Winsock
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		{
			NewMessageBox("初始化sock失败！", 3);
			Log_AddLogSimple("初始化sock失败！", LOG_ERROR);
		}

		// 创建 socket
		if ((Tran_OrgServer = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET || (Tran_OrgServerInjector = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			NewMessageBox("创建sock失败！", 3);
			Log_AddLogSimple("创建sock失败！", LOG_ERROR);
		}

		// 设置服务器地址和端口
		Tran_ServerAddr.sin_family = AF_INET;
		Tran_ServerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
		Tran_ServerAddr.sin_port = htons(12345);
		Tran_ServerAddrInjector.sin_family = AF_INET;
		Tran_ServerAddrInjector.sin_addr.s_addr = inet_addr("127.0.0.1");
		Tran_ServerAddrInjector.sin_port = htons(12346);

		// 绑定地址和端口
		if (::bind(Tran_OrgServer, (struct sockaddr*)&Tran_ServerAddr, sizeof(Tran_ServerAddr)) == SOCKET_ERROR)
		{
			NewMessageBox("绑定地址和端口失败！", 3);
			Log_AddLogSimple("绑定地址和端口失败！", LOG_ERROR);
		}

		// 绑定地址和端口
		if (::bind(Tran_OrgServerInjector, (struct sockaddr*)&Tran_ServerAddrInjector, sizeof(Tran_ServerAddrInjector)) == SOCKET_ERROR)
		{
			NewMessageBox("绑定地址和端口失败！", 3);
			Log_AddLogSimple("绑定地址和端口失败！", LOG_ERROR);
		}

		// 监听连接
		if (listen(Tran_OrgServer, 10) == SOCKET_ERROR || listen(Tran_OrgServerInjector, 3) == SOCKET_ERROR)
		{
			NewMessageBox("监听连接失败！", 3);
			Log_AddLogSimple("监听连接失败！", LOG_ERROR);
		}
		// else NewMessageBox("R3 Hook组网完成。", 1);

		// 创建 Client socket
		if ((Tran_OrgServerClient = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		{
			NewMessageBox("Client socket 创建失败！", 3);
			Log_AddLogSimple("Client socket 创建失败！", LOG_ERROR);
		}

		// 绑定 Client socket 到端口 12347
		sockaddr_in Tran_ServerAddrClient = {};
		Tran_ServerAddrClient.sin_family = AF_INET;
		Tran_ServerAddrClient.sin_addr.s_addr = inet_addr("127.0.0.1");
		Tran_ServerAddrClient.sin_port = htons(12347);

		if (::bind(Tran_OrgServerClient, (struct sockaddr*)&Tran_ServerAddrClient, sizeof(Tran_ServerAddrClient)) == SOCKET_ERROR)
		{
			NewMessageBox("Client socket 绑定失败！", 3);
			Log_AddLogSimple("Client socket 绑定失败！", LOG_ERROR);
		}

		if (listen(Tran_OrgServerClient, 3) == SOCKET_ERROR)
		{
			NewMessageBox("Client socket 监听失败！", 3);
			Log_AddLogSimple("Client socket 监听失败！", LOG_ERROR);
		}

		// 启动 Client accept 线程
		HANDLE hClientAcceptThread = CreateThread(0, 0, ClientAcceptT, NULL, 0, 0);
		if (hClientAcceptThread == NULL) {
			Log_AddLogSimple(QString("ClientAcceptT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
		} else {
			CloseHandle(hClientAcceptThread);
		}

		HANDLE hChild;
		STARTUPINFOW lpi{};
		PROCESS_INFORMATION lpw{};

		CreateProcessW((Process_GetCurrentProcessPath() + L"\\Resources\\BinaryFiles\\TianHongInjector32.exe").c_str(), NULL, NULL, NULL, FALSE, SW_HIDE, NULL, NULL, &lpi, &lpw);

		CloseHandle(lpw.hThread);

		if (lpw.hProcess)
		{
			/* 将 injector32 进程 PID 注册到驱动保护列表 */
			if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
			{
				MAIN_COMM_CONTROL_PACKET injPkt = { 0 };
				char injPidBuf[32];
				sprintf_s(injPidBuf, "%lu", lpw.dwProcessId);
				injPkt.Type = 0;
				strncpy_s(injPkt.Data, injPidBuf, _TRUNCATE);
				DWORD br = 0;
				DeviceIoControl(g_hR0DriverDevice, IOCTL_PROTECT_PROCESS,
					&injPkt, sizeof(injPkt), NULL, 0, &br, NULL);
			}

			HANDLE* hPro = new HANDLE;
			*hPro = lpw.hProcess;

			HANDLE hInjectorThread = CreateThread(0, 0, CreateInjectorT, hPro, 0, 0);
			if (hInjectorThread == NULL) {
				Log_AddLogSimple(QString("CreateInjectorT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
				delete hPro;
			} else {
				CloseHandle(hInjectorThread);
			}
		}
		else
		{
			NewMessageBox("TianHongInjector32.exe 启动失败，失去dll注入对x32程序的拦截功能", 3);
			Log_AddLogSimple("TianHongInjector32.exe 启动失败，失去dll注入对x32程序的拦截功能。", LOG_ERROR);
			pMainWindow->setUserInfoCardSubTitle("安全防护存在缺失");
			pMainPage->setSourceStatus(MainPage::StatusSource::LoadFailure, MainPage::StatusLevel::Error, "TianHongInjector32.exe 启动失败");
			pProtectionSettingPage->pDllProtectionSwitch->setIsToggled(false);
			pProtectionSettingPage->pDllProtectionSwitch->setDisabled(true);
		}

		// 设置勒索拦截
		AddDetectFile(DeskPath);
		AddDetectFile(GetSpecialFolderPath(FOLDERID_AccountPictures));
		AddDetectFile(GetSpecialFolderPath(FOLDERID_Documents));
		AddDetectFile(GetSpecialFolderPath(FOLDERID_ProgramData));
		AddDetectFile(GetSpecialFolderPath(FOLDERID_LocalAppData));
		AddDetectFile(GetSpecialFolderPath(FOLDERID_Windows));
		AddDetectFile(GetSpecialFolderPath(FOLDERID_System));
		AddDetectFile(GetSpecialFolderPath(FOLDERID_SystemX86));

		/*
		int CleanAgree = 0;

		if (_access(((string)DeskPath + "\\.USERDATAYSUWD").c_str(), 0) == 0 || _access(((string)DeskPath + "\\.ASIsDATAsSCkwxWq.xls").c_str(), 0) == 0)
		{
			if (MessageBox(NULL, L"勒索防护文件夹已存在，是否重置？\n\n是：重置文件夹；否：关闭勒索防护", L"提示", MB_TOPMOST | MB_ICONQUESTION | MB_YESNO) == IDYES) CleanAgree = 1;
			else CleanAgree = -1;
		}
		if (CleanAgree == 1 || CleanAgree == 0)
		{
			if (CleanAgree == 1)
			{
				for (int i = 0; i < RansomDetectPathDicCount; i++)
				{
					RemoveDirectoryA((RansomDetectPathDic[i]).c_str());
				}

				for (int i = 0; i < RansomDetectPathCount; i++)
				{
					DeleteFileA((RansomDetectPath[i]).c_str());
				}
			}

			*/

		if (IsOpenExtortionCatch)
		{
			RebuildRansomHoneypotFiles();
			Log_AddLogSimple("勒索防护设置完成。", LOG_SUCCESS);
		}
		else
		{
			Log_AddLogSimple("勒索拦截未开启。", LOG_WARN);
		}
		/*
	}
	else
	{
		IsOpenExtortionCatch = FALSE;
	}
	*/

		HasBeenScanedSha256WhiteList.reserve(4096);
		HasBeenScanedSha256BlackList.reserve(4096);
		HasBeenScanedTypeBlackList.reserve(4096);
		InitializeCriticalSection(&g_csScanCache);

		// 加载持久化的临时白名单（必须在 g_csScanCache 初始化后调用）
		Whitelist_LoadTemporary();
		Whitelist_LoadTemporaryDir();
		Whitelist_LoadEnhancedPath();

		HANDLE hAcceptThread = CreateThread(0, 0, AcceptT, 0, 0, 0);
		if (hAcceptThread == NULL) {
			Log_AddLogSimple(QString("AcceptT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
		} else {
			CloseHandle(hAcceptThread);
		}

		InitializeCriticalSection(&g_csProcessList);
		InitializeCriticalSection(&g_csR0Sync);  // R0同步锁
		HANDLE hCheckCrashThread = CreateThread(NULL, 0, CheckCrashT, NULL, 0, NULL);
		if (hCheckCrashThread == NULL) {
			Log_AddLogSimple(QString("CheckCrashT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
		} else {
			CloseHandle(hCheckCrashThread);
		}

		// binary文件检查
		if (_waccess((Process_GetCurrentProcessPathWithDll() + L"32.dll").c_str(), 0) != 0)
		{
			NewMessageBox("TianHong32.dll 缺失，失去对x32程序的拦截功能", 3);
			pLoggerPage->LogModel->appendRow(new QStandardItem("TianHong32.dll 缺失，失去对x32程序的拦截功能。"));
			pMainWindow->setUserInfoCardSubTitle("安全防护存在缺失");
			pMainPage->setSourceStatus(MainPage::StatusSource::LoadFailure, MainPage::StatusLevel::Error, "TianHong32.dll 缺失");
			pProtectionSettingPage->pDllProtectionSwitch->setIsToggled(false);
			pProtectionSettingPage->pDllProtectionSwitch->setDisabled(true);
		}

		if (_waccess((Process_GetCurrentProcessPathWithDll() + L"64.dll").c_str(), 0) != 0)
		{
			NewMessageBox("TianHong64.dll 缺失，失去对x64程序的拦截功能", 3);
			pLoggerPage->LogModel->appendRow(new QStandardItem("TianHong64.dll 缺失，失去对x64程序的拦截功能。"));
			pMainWindow->setUserInfoCardSubTitle("安全防护存在缺失");
			pMainPage->setSourceStatus(MainPage::StatusSource::LoadFailure, MainPage::StatusLevel::Error, "TianHong64.dll 缺失");
			pProtectionSettingPage->pDllProtectionSwitch->setIsToggled(false);
			pProtectionSettingPage->pDllProtectionSwitch->setDisabled(true);
		}

		yr_initialize(); // 初始化yara

		HANDLE hYaraThread = CreateThread(NULL, 0, LoadYaraThread, NULL, 0, 0);
		if (hYaraThread == NULL) {
			Log_AddLogSimple(QString("LoadYaraThread CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
		} else {
			CloseHandle(hYaraThread);
		}
		// ClamAV改为手动加载，不在启动时自动加载
		HANDLE hPEEngineThread = CreateThread(NULL, 0, LoadPEEngineThread, NULL, 0, 0);
		if (hPEEngineThread == NULL) {
			Log_AddLogSimple(QString("LoadPEEngineThread CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
		} else {
			CloseHandle(hPEEngineThread);
		}

		if (INJECT) {
			HANDLE hInjectThread = CreateThread(0, 0, InjectT, 0, 0, 0);
			if (hInjectThread == NULL) {
				Log_AddLogSimple(QString("InjectT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
			} else {
				CloseHandle(hInjectThread);
			}
		}

		string sPEPath = (string)(CW2A)(Process_GetCurrentProcessPath().c_str() + (wstring)L"\\Resources\\DataBase\\Heur.data").c_str();

		FileWarnMutex = CreateMutex(0, 0, L"TianHongFileHandle$1247dub32s9");
		HandleMutex = CreateMutex(0, 0, L"TianHongActionHandle$d234nfi2xvc0");
		CreateCheckMutex = CreateMutex(0, 0, L"TianHongCreateCheck$2sInsdiN2U8");

		// 文件占用
		FileProtect[0] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\BinaryFiles\\TianHongDefense32.dll").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[1] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\BinaryFiles\\TianHongDefense64.dll").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[2] = CreateFileW((Process_GetCurrentProcessPath() + L"\\TianHong-Security-Defense.exe").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[3] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\BinaryFiles\\InjectHelper32.exe").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[4] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\virus.sha256").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (IS_LOAD_YARAC)
		{
			FileProtect[5] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Malware.yarac").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			FileProtect[6] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\MalwareMemory.yarac").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		}
		else
		{
			FileProtect[5] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Malware.yara").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
			FileProtect[6] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\MalwareMemory.yara").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		}
		FileProtect[7] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Heur.data.base").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[8] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Heur.data.base.names").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[9] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Heur.data.extra").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[10] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Heur.data.extra.names").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[11] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\Heur.data.config").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		FileProtect[12] = CreateFileW((Process_GetCurrentProcessPath() + L"\\Resources\\DataBase\\white.sha256").c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

		gdiplusStartupInput.GdiplusVersion = 1;

		// 调用GDI+初始化函数
		ULONG_PTR status = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, &gdiplusStartupOutput);

		if (status == ERROR_SUCCESS) isGdiReady = TRUE;
		else
		{
			isGdiReady = FALSE;
			NewMessageBox("GDI+启动失败。", 3);
			pLoggerPage->LogModel->appendRow(new QStandardItem("GDI+启动失败。"));
		}

		// 创建一个新的 UAC 桌面
		// Windows_UacDesktop = CreateSecureDesktop();
		// CreateThread(0, 0, SetUACWindowT, 0, 0, 0);

		RegAddIOT();

		pMainWindow->show();

		// 若由 Toast 点击协议启动，前置窗口并导航到主页面
		if (launchedFromToast)
		{
			pMainWindow->raise();
			pMainWindow->activateWindow();
			if (pMainPage)
			{
				QString pageKey = pMainPage->property("ElaPageKey").toString();
				if (!pageKey.isEmpty())
					pMainWindow->navigation(pageKey);
			}
		}
	}

	Log_AddLogSimple("天宏安全防御初始化完成。", LOG_SUCCESS);

    return a.exec();
}

// 主界面初始化
void MainWindow::InitWindow()
{
    // UI 初始化
    char currentUser[256] = { 0 }; // 用于存储用户名的缓冲区
    DWORD dwSize = sizeof(currentUser); // 缓冲区大小

    // 调用GetUserName函数获取用户名
    if (GetUserNameA(currentUser, &dwSize))
    {
        setUserInfoCardTitle(currentUser);
    }
    else
    {
        setUserInfoCardTitle("User");
    }

    setWindowIcon(QIcon(".\\Resources\\Image\\TianHong-Security-Defense.ico"));
    setUserInfoCardPixmap(QPixmap(".\\Resources\\Image\\TianHong-Security-Defense.ico"));
    setUserInfoCardSubTitle("安全防护已启用");
    setWindowTitle("天宏安全防御    V3测试版不代表最终品质 · 欢迎提出意见修改");

    pVirusScanPage = new VirusScanPage(this);
    pProtectionSettingPage = new ProtectionSettingPage(this);
    pMainPage = new MainPage(this);
	pLoggerPage = new LoggerPage(this);
    pWhitelistPage = new WhitelistPage(this);

    // 连接驱动防护按钮信号：启用时自动启动Client，禁用时停止Client
    QObject::connect(pProtectionSettingPage->pDriverProtectionSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) { OnDriverProtectionToggled(checked); });

    // 连接 R3 DLL 防护按钮信号：实时同步开关状态到驱动，
    // 确保禁用 R3 DLL 防护时驱动不再注入 DLL。
    QObject::connect(pProtectionSettingPage->pDllProtectionSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            BOOL bR3Enabled = checked ? TRUE : FALSE;
            DWORD bytesReturned = 0;

            HANDLE hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDevice != INVALID_HANDLE_VALUE)
            {
                BOOL ok = DeviceIoControl(
                    hDevice,
                    IOCTL_SET_R3_PROTECTION_ENABLED,
                    &bR3Enabled,
                    sizeof(bR3Enabled),
                    NULL, 0,
                    &bytesReturned, NULL);
                if (ok)
                {
                    Log_AddLogSimple(QString("R3 DLL防护状态已同步到驱动: %1").arg(bR3Enabled ? "启用" : "禁用"), LOG_SUCCESS);
                }
                else
                {
                    Log_AddLogSimple(QString("同步R3 DLL防护状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
                }
                CloseHandle(hDevice);
            }
            else
            {
                /* R0 未启用时不需要同步到驱动（驱动未加载），静默忽略 */
            }
        });

    // 连接行为检测开关信号：实时同步开关状态到驱动。
    // 行为检测默认禁用且当前处于调试模式（只记录不拦截），
    // 用户明确启用后驱动才会进行行为评估。
    QObject::connect(pProtectionSettingPage->pBehaviorDetectionSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            BOOL bBehaviorEnabled = checked ? TRUE : FALSE;
            DWORD bytesReturned = 0;

            HANDLE hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDevice != INVALID_HANDLE_VALUE)
            {
                BOOL ok = DeviceIoControl(
                    hDevice,
                    IOCTL_SET_BEHAVIOR_DETECTION_ENABLED,
                    &bBehaviorEnabled,
                    sizeof(bBehaviorEnabled),
                    NULL, 0,
                    &bytesReturned, NULL);
                if (ok)
                {
                    Log_AddLogSimple(QString("行为检测状态已同步到驱动: %1").arg(bBehaviorEnabled ? "启用" : "禁用"), LOG_SUCCESS);
                }
                else
                {
                    Log_AddLogSimple(QString("同步行为检测状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
                }
                CloseHandle(hDevice);
            }
            else
            {
                /* R0 未启用时不需要同步到驱动（驱动未加载），静默忽略 */
            }
        });

    // 连接进程防护开关信号：实时同步 R0 独立进程检查开关状态到驱动。
    // 进程防护开关同时控制静态文件扫描和 R0 独立进程创建检查。
    QObject::connect(pProtectionSettingPage->pProcessSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            BOOL bProcessProtectionEnabled = checked ? TRUE : FALSE;
            DWORD bytesReturned = 0;

            HANDLE hDevice = CreateFile(THSD_USER_DEVICE_PATH_W,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDevice != INVALID_HANDLE_VALUE)
            {
                BOOL ok = DeviceIoControl(
                    hDevice,
                    IOCTL_SET_PROCESS_PROTECTION_ENABLED,
                    &bProcessProtectionEnabled,
                    sizeof(bProcessProtectionEnabled),
                    NULL, 0,
                    &bytesReturned, NULL);
                if (ok)
                {
                    Log_AddLogSimple(QString("R0进程检查状态已同步到驱动: %1").arg(bProcessProtectionEnabled ? "启用" : "禁用"), LOG_SUCCESS);
                }
                else
                {
                    Log_AddLogSimple(QString("同步R0进程检查状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
                }
                CloseHandle(hDevice);
            }
            else
            {
                /* R0 未启用时不需要同步到驱动（驱动未加载），静默忽略 */
            }
        });

    // 连接"是否阻塞检查"开关信号：实时同步到 Client，决定 R0 进程检查是
    // 阻塞等待 main.cpp 扫描结果（完整扫描）还是非阻塞仅告警（快速检查）。
    QObject::connect(pProtectionSettingPage->pIsFullScanSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            UNREFERENCED_PARAMETER(checked);
            SendProcessCheckBlockingSettingToClient();
        });

    // 连接内存防护（含 DLL 扫描）开关信号：实时同步到 Client 和驱动
    QObject::connect(pProtectionSettingPage->pMemorySwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            UNREFERENCED_PARAMETER(checked);
            SendUnsignedDllScanSettingToClient();

            /* R0 未启用时不需要同步到驱动（驱动未加载） */
            if (g_hR0DriverDevice == INVALID_HANDLE_VALUE)
                return;

            BOOL bMemEnable = checked ? TRUE : FALSE;
            DWORD bytesReturned = 0;
            BOOL ok = DeviceIoControl(
                g_hR0DriverDevice,
                IOCTL_SET_MEMORY_PROTECTION_ENABLED,
                &bMemEnable,
                sizeof(bMemEnable),
                NULL, 0,
                &bytesReturned, NULL);
            if (ok)
            {
                Log_AddLogSimple(QString("内存防护状态已同步到驱动: %1").arg(bMemEnable ? "启用" : "禁用"), LOG_SUCCESS);
            }
            else
            {
                Log_AddLogSimple(QString("同步内存防护状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
            }
        });

    // 连接 DCOM 防护开关信号：实时同步开关状态到驱动，并启停 DCOM 横向移动检测线程。
    // DCOM 横向移动 (T1021.003) 通过远程激活 COM 对象执行代码，检测线程通过 WMI
    // 监控 dllhost.exe/svchost.exe/wmiprvse.exe 派生可疑子进程。
    QObject::connect(pProtectionSettingPage->pDcomProtectionSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            /* 同步开关状态到驱动 */
            if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
            {
                DWORD bytesReturned = 0;
                BOOL bDcomEnable = checked ? TRUE : FALSE;
                BOOL ok = DeviceIoControl(
                    g_hR0DriverDevice,
                    IOCTL_SET_DCOM_PROTECTION_ENABLED,
                    &bDcomEnable,
                    sizeof(bDcomEnable),
                    NULL, 0,
                    &bytesReturned, NULL);
                if (ok)
                {
                    Log_AddLogSimple(QString("DCOM防护状态已同步到驱动: %1").arg(bDcomEnable ? "启用" : "禁用"), LOG_SUCCESS);
                }
                else
                {
                    Log_AddLogSimple(QString("同步DCOM防护状态到驱动失败: %1").arg(GetLastError()), LOG_ERROR);
                }
            }

            /* 启停 DCOM 横向移动检测线程 */
            if (checked && !g_bDcomMonitorRunning)
            {
                g_bDcomMonitorRunning = TRUE;
                g_hDcomMonitorThread = CreateThread(NULL, 0, DcomMonitorThread, NULL, 0, NULL);
                if (g_hDcomMonitorThread == NULL) {
                    Log_AddLogSimple(QString("DCOM-Monitor CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
                    g_bDcomMonitorRunning = FALSE;
                }
            }
            else if (!checked && g_bDcomMonitorRunning)
            {
                g_bDcomMonitorRunning = FALSE;
                if (g_hDcomMonitorThread != NULL) {
                    WaitForSingleObject(g_hDcomMonitorThread, 3000);
                    CloseHandle(g_hDcomMonitorThread);
                    g_hDcomMonitorThread = NULL;
                }
                Log_AddLogSimple("DCOM 横向移动检测线程已停止", LOG_INFO);
            }
        });

    // 连接静默模式开关：启用后告警自动阻止并使用 NewMessageBox 弹窗通知
    QObject::connect(pProtectionSettingPage->pSilentModeSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            g_bSilentModeEnabled = checked ? TRUE : FALSE;
            Log_AddLogSimple(QString("静默模式已%1").arg(checked ? "启用" : "禁用"), LOG_INFO);

            if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
            {
                DWORD bytesReturned = 0;
                BOOL bEnable = checked ? TRUE : FALSE;
                DeviceIoControl(
                    g_hR0DriverDevice,
                    IOCTL_SET_SILENT_MODE,
                    &bEnable,
                    sizeof(bEnable),
                    NULL, 0,
                    &bytesReturned, NULL);
            }
        });

    // 连接提取文件资源扫描开关：仅影响文件/文件夹扫描，进程扫描始终不提取
    QObject::connect(pProtectionSettingPage->pExtractFilesSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            g_bExtractFilesEnabled = checked ? TRUE : FALSE;
            Log_AddLogSimple(QString("提取文件资源扫描已%1").arg(checked ? "启用" : "禁用"), LOG_INFO);
        });

    // 连接勒索防护（文件诱捕）开关：
    // 开启时创建诱捕文件，若 R0 已启用且文件防护也开启则同步规则到驱动；
    // 关闭时先从驱动移除规则（若 R0 启用），再清理诱捕文件。
    // 勒索防护受文件防护开关控制：文件防护关闭时不同步规则到驱动。
    // 采用异步执行 + loading 动画：文件 IO 放后台线程，socket/IPC 通信回主线程执行。
    QObject::connect(pProtectionSettingPage->pRansomProtectionSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            // 隐藏开关，显示 loading 动画
            if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionSwitch)
            {
                pProtectionSettingPage->pRansomProtectionSwitch->setVisible(false);
            }
            if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionRing)
            {
                pProtectionSettingPage->pRansomProtectionRing->setVisible(true);
                pProtectionSettingPage->pRansomProtectionRing->setIsBusying(true);
            }

            // 文件 IO（创建/清理诱捕文件）放后台线程，避免阻塞 UI
            QtConcurrent::run([=]() {
                if (checked)
                {
                    /* 开启：先创建诱捕文件（后台 IO），再回主线程同步规则 */
                    IsOpenExtortionCatch = TRUE;
                    RebuildRansomHoneypotFiles();
                    Log_AddLogSimple("勒索防护（文件诱捕）已启用，诱捕文件已重建", LOG_SUCCESS);

                    // 回主线程执行 socket/IPC 通信（Tran_SendPacket 非线程安全）
                    QMetaObject::invokeMethod(qApp, [=]() {
                        if (g_bR0ProtectionEnabled && g_hR0DriverDevice != INVALID_HANDLE_VALUE &&
                            pProtectionSettingPage && pProtectionSettingPage->pFileSwitch &&
                            pProtectionSettingPage->pFileSwitch->getIsToggled())
                        {
                            SyncRansomHoneypotToDriver();
                        }
                        /* R0 未启用时通知 R3 DLL 同步诱捕路径 */
                        if (!g_bR0ProtectionEnabled &&
                            pProtectionSettingPage && pProtectionSettingPage->pFileSwitch &&
                            pProtectionSettingPage->pFileSwitch->getIsToggled())
                        {
                            SyncRansomHoneypotToR3Clients(true);
                        }

                        // 恢复 UI
                        if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionSwitch)
                            pProtectionSettingPage->pRansomProtectionSwitch->setVisible(true);
                        if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionRing)
                        {
                            pProtectionSettingPage->pRansomProtectionRing->setVisible(false);
                            pProtectionSettingPage->pRansomProtectionRing->setIsBusying(false);
                        }
                    }, Qt::QueuedConnection);
                }
                else
                {
                    /* 关闭：先回主线程移除规则（IPC），再后台清理文件 */
                    QMetaObject::invokeMethod(qApp, [=]() {
                        if (g_bR0ProtectionEnabled && g_hR0DriverDevice != INVALID_HANDLE_VALUE)
                        {
                            UnsyncRansomHoneypotFromDriver();
                        }
                        if (!g_bR0ProtectionEnabled)
                        {
                            SyncRansomHoneypotToR3Clients(false);
                        }

                        // 规则移除后再后台清理文件（避免清理时触发告警）
                        QtConcurrent::run([=]() {
                            CleanupRansomHoneypotFiles();
                            IsOpenExtortionCatch = FALSE;
                            Log_AddLogSimple("勒索防护（文件诱捕）已关闭，诱捕文件已清理", LOG_INFO);

                            QMetaObject::invokeMethod(qApp, [=]() {
                                if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionSwitch)
                                    pProtectionSettingPage->pRansomProtectionSwitch->setVisible(true);
                                if (pProtectionSettingPage && pProtectionSettingPage->pRansomProtectionRing)
                                {
                                    pProtectionSettingPage->pRansomProtectionRing->setVisible(false);
                                    pProtectionSettingPage->pRansomProtectionRing->setIsBusying(false);
                                }
                            }, Qt::QueuedConnection);
                        });
                    }, Qt::QueuedConnection);
                }
            });
        });

    // 连接文件防护开关：文件防护关闭时同步移除勒索诱捕规则，开启时恢复。
    // 勒索防护（诱捕+行为分析）受文件防护开关控制。
    QObject::connect(pProtectionSettingPage->pFileSwitch, &ElaToggleSwitch::toggled,
        [](bool checked) {
            if (!pProtectionSettingPage || !pProtectionSettingPage->pRansomProtectionSwitch ||
                !pProtectionSettingPage->pRansomProtectionSwitch->getIsToggled())
                return;  /* 勒索防护开关未开启时不处理 */

            if (checked)
            {
                /* 文件防护开启：若 R0 启用则同步诱捕规则到驱动 */
                if (g_bR0ProtectionEnabled && g_hR0DriverDevice != INVALID_HANDLE_VALUE)
                {
                    SyncRansomHoneypotToDriver();
                }
                else
                {
                    SyncRansomHoneypotToR3Clients(true);
                }
            }
            else
            {
                /* 文件防护关闭：移除诱捕规则并通知 DLL 清空监控 */
                if (g_bR0ProtectionEnabled && g_hR0DriverDevice != INVALID_HANDLE_VALUE)
                {
                    UnsyncRansomHoneypotFromDriver();
                }
                else
                {
                    SyncRansomHoneypotToR3Clients(false);
                }
                Log_AddLogSimple("文件防护已关闭，勒索诱捕规则已同步移除", LOG_INFO);
            }
        });

    addPageNode("主页", pMainPage, ElaIconType::DiceD20);
    addPageNode("病毒查杀", pVirusScanPage, ElaIconType::VirusCovidSlash);
    addPageNode("防护设置", pProtectionSettingPage, ElaIconType::Shield); // ElaIconType::HexagonCheck
	addPageNode("日志", pLoggerPage, ElaIconType::Ballot);
    addPageNode("白名单", pWhitelistPage, ElaIconType::SquareCheck);

	// 拦截默认关闭事件
	_closeDialog = new ElaContentDialog(this);
	_closeDialog->setLeftButtonText("取消");
	_closeDialog->setMiddleButtonText("最小化");
	_closeDialog->setRightButtonText("退出");

    QWidget* exitCentralWidget = new QWidget(_closeDialog);
    QHBoxLayout* exitMainLayout = new QHBoxLayout(exitCentralWidget);
    exitMainLayout->setContentsMargins(5, 5, 5, 5);
    exitMainLayout->setSpacing(16);

    ElaIconButton* exitIcon = new ElaIconButton(ElaIconType::PowerOff, 48, 64, 64, exitCentralWidget);
    exitIcon->setEnabled(false);
    exitIcon->setAttribute(Qt::WA_TransparentForMouseEvents);
    exitMainLayout->addWidget(exitIcon, 0, Qt::AlignTop);

    QWidget* exitTextWidget = new QWidget(exitCentralWidget);
    QVBoxLayout* exitTextLayout = new QVBoxLayout(exitTextWidget);
    exitTextLayout->setContentsMargins(0, 0, 0, 0);
    exitTextLayout->setSpacing(6);
    ElaText* exitTitle = new ElaText("退出程序", exitTextWidget);
    exitTitle->setTextStyle(ElaTextType::Title);
    ElaText* exitSubTitle = new ElaText("确定要退出程序吗？", exitTextWidget);
    exitSubTitle->setTextStyle(ElaTextType::Body);
    exitTextLayout->addWidget(exitTitle);
    exitTextLayout->addWidget(exitSubTitle);
    exitTextLayout->addStretch();
    exitMainLayout->addWidget(exitTextWidget, 1);

	_closeDialog->setCentralWidget(exitCentralWidget);

	connect(_closeDialog, &ElaContentDialog::rightButtonClicked, this, [=]()
		{
			if (mScanState == ssRunning || mScanState == ssStoppingPreparing)
			{
				if (mScanState == ssRunning) mScanState = ssStoppingPreparing;

				NewMessageBox("正在终止查杀以退出程序...\n\n请耐心等待。", 4);

				QTimer* checkTimer = new QTimer(this);

				QObject::connect(checkTimer, &QTimer::timeout, this, [=]() {
					if (mScanState == ssStopping || mScanState == ssEnding || mScanState == ssPrepared)
					{
						checkTimer->stop();

						CloseWindow();
					}
					});

				checkTimer->start(100); // 每100ms检查一次
			}
			else CloseWindow();
		});

	connect(_closeDialog, &ElaContentDialog::middleButtonClicked, this, [=]() {
		_closeDialog->close();
		showMinimized();
		});

	// 主题切换时刷新退出对话框
	connect(eTheme, &ElaTheme::themeModeChanged, this, [=]() {
		_closeDialog->update();
		const auto buttons = _closeDialog->findChildren<ElaPushButton*>();
		for (auto* btn : buttons) {
			btn->update();
		}
		});

	this->setIsDefaultClosed(false);

	connect(this, &MainWindow::closeButtonClicked, this, [=]() {
		_closeDialog->exec();
		});

	setStackSwitchMode(ElaWindowType::Popup);
}

void MainWindow::CloseWindow()
{
    static bool s_isClosing = false;
    if (s_isClosing) return;
    s_isClosing = true;

	if (isLoadReady != 2)
	{
		NewMessageBox("正在等待资源加载完成以安全退出程序...", 4);

		QTimer::singleShot(100, this, [this]() {
			s_isClosing = false;
			CloseWindow();
			});
		return;
	}

	/* 根据 ElaTheme 适配退出遮罩和加载对话框颜色 */
	ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
	bool isDark = (themeMode == ElaThemeType::Dark);
	QColor overlayColor = isDark ? QColor(0, 0, 0, 150) : QColor(255, 255, 255, 150);
	QColor dialogBg = ElaThemeColor(themeMode, DialogBase);
	QColor textColor = ElaThemeColor(themeMode, BasicText);

	if (!_exitOverlay)
	{
		_exitOverlay = new QWidget(this);
		_exitOverlay->setAttribute(Qt::WA_TransparentForMouseEvents, false);
	}

	if (_exitOverlay)
	{
		_exitOverlay->setStyleSheet(QString("background-color: rgba(%1, %2, %3, %4);")
			.arg(overlayColor.red()).arg(overlayColor.green()).arg(overlayColor.blue()).arg(overlayColor.alpha()));
		_exitOverlay->setGeometry(this->rect());
		_exitOverlay->show();
		_exitOverlay->raise();
	}

	if (!_exitLoadingDialog)
	{
		_exitLoadingDialog = new QDialog(this);
		_exitLoadingDialog->setWindowTitle("正在退出");
		_exitLoadingDialog->setFixedSize(320, 160);
		_exitLoadingDialog->setWindowFlags(Qt::Dialog | Qt::CustomizeWindowHint);
		_exitLoadingDialog->setAttribute(Qt::WA_DeleteOnClose, false);

		QVBoxLayout* layout = new QVBoxLayout(_exitLoadingDialog);
		layout->setContentsMargins(20, 20, 20, 20);
		layout->setSpacing(16);

		ElaProgressRing* progressRing = new ElaProgressRing(_exitLoadingDialog);
		progressRing->setIsBusying(true);
		progressRing->setIsTransparent(true);
		progressRing->setFixedHeight(36);
		progressRing->setFixedWidth(36);
		progressRing->setBusyingWidth(3);

		QLabel* textLabel = new QLabel("正在安全退出程序...", _exitLoadingDialog);
		textLabel->setAlignment(Qt::AlignCenter);
		textLabel->setObjectName("exitLoadingLabel");

		layout->addStretch();
		layout->addWidget(progressRing, 0, Qt::AlignCenter);
		layout->addWidget(textLabel, 0, Qt::AlignCenter);
		layout->addStretch();
	}

	/* 每次显示时刷新主题色（可能在运行期间切换过主题） */
	if (_exitLoadingDialog)
	{
		_exitLoadingDialog->setStyleSheet(QString(
			"QDialog { background-color: %1; border: none; border-radius: 8px; }"
			"#exitLoadingLabel { font-size: 14px; color: %2; border: none; background: transparent; }")
			.arg(dialogBg.name()).arg(textColor.name()));
	}

	if (_exitLoadingDialog)
	{
		_exitLoadingDialog->show();
		_exitLoadingDialog->raise();
		_exitLoadingDialog->activateWindow();
		QApplication::processEvents();
	}

	QtConcurrent::run([this]() {
		/* 退出伊始即关闭 R0 驱动设备句柄，释放对主驱动的引用。
		 * 关键：必须在下方发送 QUIT（第9470行）之前关闭，因为客户端收到 QUIT 会
		 * 立即执行 CleanupAndExit 停止主驱动；若此处句柄仍打开，驱动对象引用计数
		 * 无法降到 0，主驱动无法卸载（磁盘/网络驱动无该句柄，故可正常卸载）。 */
		if (g_hR0DriverDevice != INVALID_HANDLE_VALUE)
		{
			CloseHandle(g_hR0DriverDevice);
			g_hR0DriverDevice = INVALID_HANDLE_VALUE;
			Log_AddLogSimple("R0 驱动设备句柄已关闭（释放主驱动引用）", LOG_INFO);
		}

		if (IsOpenExtortionCatch)
		{
			for (int i = 0; i < RansomDetectPathCount; i++)
			{
				DeleteFileA((RansomDetectPath[i]).c_str());
			}

			for (int i = 0; i < RansomDetectPathDicCount; i++)
			{
				RemoveDirectoryA((RansomDetectPathDic[i]).c_str());
			}
		}

		// 保存临时白名单（sha256 + 路径）
		CString csPath = Process_GetCurrentProcessPath().c_str();
		csPath += L"\\Resources\\DataBase\\whitecache.sha256";
		string cachePath = (char*)(CW2A)csPath;
		ofstream cacheOut(cachePath, ios::out | ios::trunc);
		if (cacheOut.is_open()) {
			std::string cacheContent;
			EnterCriticalSection(&g_csScanCache);
			for (const auto& kv : WhiteSha256ListCache) {
				cacheContent += kv.first;
				cacheContent += '\t';
				cacheContent += kv.second;
				cacheContent += '\n';
			}
			LeaveCriticalSection(&g_csScanCache);
			cacheOut.write(cacheContent.c_str(), static_cast<std::streamsize>(cacheContent.size()));
			cacheOut.close();
		}

		if (g_bClientConnected && Tran_ClientSocket != INVALID_SOCKET)
		{
			Packet quitPkt = {};
		quitPkt.PacketTyped = PTClientMessage;
		strcpy_s(quitPkt.InfoTitle, sizeof(quitPkt.InfoTitle), "QUIT");
		if (send(Tran_ClientSocket, (const char*)&quitPkt, sizeof(Packet), 0) == SOCKET_ERROR)
			{
				Log_AddLogSimple("通知 Client 退出时 send 失败", LOG_ERROR);
			}
			closesocket(Tran_ClientSocket);
			Tran_ClientSocket = INVALID_SOCKET;
			g_bClientConnected = FALSE;
		}

		if (g_hClientProcess != NULL)
		{
			/* 等待 Client 执行 CleanupAndExit（含 IOCTL_PREPARE_UNLOAD + 关闭 g_hDevice）
			 * 给足时间让 Client 完成驱动清理，避免驱动因句柄未释放而无法卸载。 */
			WaitForSingleObject(g_hClientProcess, 8000);
			DWORD exitCode;
			if (GetExitCodeProcess(g_hClientProcess, &exitCode) && exitCode == STILL_ACTIVE)
			{
				/* Client 未正常退出，尝试通过已关闭的 g_hR0DriverDevice 无法再发 IOCTL，
				 * 只能依赖 SCM 强制停止服务。此时驱动可能残留，需手动 sc delete 清理。 */
				Log_AddLogSimple("Client 未在 8 秒内退出，强制终止（驱动卸载可能不完整）", LOG_WARN);
				TerminateProcess(g_hClientProcess, 0);
			}
			CloseHandle(g_hClientProcess);
			g_hClientProcess = NULL;
			if (g_hClientThread)
			{
				CloseHandle(g_hClientThread);
				g_hClientThread = NULL;
			}
		}

		/* 停止 ETW 消费线程，释放线程句柄和临界区资源 */
		EtwTiStopConsumer();

		/* 释放 ClamAV 模块句柄，避免资源泄漏 */
		if (g_hClamAVModule) {
			FreeLibrary(g_hClamAVModule);
			g_hClamAVModule = NULL;
		}

		StopKernelProtectionClient();

		QMetaObject::invokeMethod(qApp, [this]() {
			if (_exitLoadingDialog)
			{
				_exitLoadingDialog->close();
			}

			if (_exitOverlay)
			{
				_exitOverlay->hide();
				_exitOverlay->deleteLater();
				_exitOverlay = nullptr;
			}

			MainWindow::closeWindow();
			/* 确保 Qt 事件循环退出，否则 main() 无法返回 */
			qApp->quit();
		}, Qt::QueuedConnection);
	});
}

struct WaitHookStruct
{
	HANDLE hHookReady;
	int Count;
	HANDLE hProcess;
	int Pid;
	string sCmd;
	string ProcPath;

};

DWORD WaitForHookT(LPVOID lpParam)
{
	WaitHookStruct* pStruct = (WaitHookStruct*)lpParam;
	WaitHookStruct Struct = *pStruct;
	delete pStruct;

	// Process_ResumeProcess(hProcess, false); // 恢复进程以恢复dll线程完成dll hook初始化

	DWORD waitResult = WaitForSingleObject(Struct.hHookReady, 7000);

	Log_AddLogSimple(((QString)"%1 已纳入防护体系。").arg(QString::fromLocal8Bit(Struct.sCmd)), LOG_SUCCESS);

	if (waitResult == WAIT_OBJECT_0)
	{
		Tran_SendPacket(Tran_Client[Struct.Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE); // 成功完成：给父进程发信号可以resume主线程
		// ===== 记录被注入进程，并尝试复制令牌 =====
		HANDLE hDup = NULL;
		DuplicateHandle(GetCurrentProcess(), Struct.hProcess,
			GetCurrentProcess(), &hDup,
			PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
			FALSE, 0);
		if (hDup) {
			InjectedProcessInfo info;
			info.pid = Struct.Pid;
			info.hProcess = hDup;
			info.commandLine = Struct.sCmd;
			info.processPath = Struct.ProcPath;
			info.expireTime = time(nullptr) + 10;   // 监控10秒
			info.hToken = NULL;

			// 打开原进程令牌并复制
			HANDLE hToken;
			if (OpenProcessToken(Struct.hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
				DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation,
					TokenPrimary, &info.hToken);
				CloseHandle(hToken);
			}

			EnterCriticalSection(&g_csProcessList);
			g_InjectedProcesses.push_back(info);
			LeaveCriticalSection(&g_csProcessList);
		}
		// ==========================================

		/* 预留：DLL 注入完成后对目标进程进行动态内存扫描。
		 * 当前未启用，因为 ProcessRansomwareDetectorT / Setting_IsActiveAutoScan
		 * 尚未在该上下文中实现；避免代码残留导致编译错误。 */
	}
	else
	{
		// 超时未完成：检查是否收到 CallResumeEvent（DLL已注入但事件未及时设置）
		BOOL bResume = FALSE;
		WaitForSingleObject(CreateCheckMutex, 30000);
		for (auto it = ProcessEventId.begin(); it != ProcessEventId.end(); )
		{
			if (it->first == Struct.Pid)
			{
				HANDLE hEvent = OpenEventA(EVENT_MODIFY_STATE, FALSE, it->second.c_str());
				if (hEvent != NULL)
				{
					// 检查事件是否已被设置（非手动重置事件）
					DWORD waitRes = WaitForSingleObject(hEvent, 0);
					if (waitRes == WAIT_OBJECT_0)
					{
						// 事件已设置，DLL注入成功
						bResume = TRUE;
					}
					CloseHandle(hEvent);
				}
				it = ProcessEventId.erase(it);
				break;
			}
			else
			{
				++it;
			}
		}
		ReleaseMutex(CreateCheckMutex);

		if (bResume)
		{
			Tran_SendPacket(Tran_Client[Struct.Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE);
		}
		else
		{
			Tran_SendPacket(Tran_Client[Struct.Count], (char*)"", PTCreateProcessRoutine, (char*)"", -1); // 超时未完成：给父进程发信号可以resume主线程，但说明hook可能未成功
		}
	}

	if (Struct.hHookReady) CloseHandle(Struct.hHookReady);
	if (Struct.hProcess) CloseHandle(Struct.hProcess);

	return 0;
}

DWORD RecvT(LPVOID lpParam)
{
	int* pCount = (int*)lpParam;
	int Count = *pCount;

	delete lpParam;

	Tran_SendPacket(Tran_Client[Count], (char*)"", PTConnection, (char*)"IsSyscallDetectionEnable", pProtectionSettingPage->pDirectSyscallSwitch->getIsToggled());
	Tran_SendPacket(Tran_Client[Count], (char*)"", PTConnection, (char*)"MainProcess", GetCurrentProcessId());
	Sleep(2);  // 合并相邻 Sleep(1)，总延时不变
	Tran_SendPacket(Tran_Client[Count], (char*)"", PTConnection, (char*)"Injector", Process_InjectHelperId);
	Sleep(1);

	if (IsOpenExtortionCatch && !g_bR0ProtectionEnabled)
	{
		// R0 未启用时，走 R3 路径发送诱捕文件路径给 DLL
		Tran_SendPacket(Tran_Client[Count], (char*)"", PTHideFile, (char*)"HideFileCount", RansomDetectPathCount + RansomDetectPathDicCount);
		Sleep(1);

		for (int i = 0; i < RansomDetectPathCount; i++)
		{
			Tran_SendPacket(Tran_Client[Count], (char*)(RansomDetectPath[i]).c_str(), PTHideFile, (char*)"", 0);
			Tran_SendPacket(Tran_Client[Count], (char*)File_GetShortFileName(RansomDetectPath[i]).c_str(), PTHideFile, (char*)"", 0);
		}

		for (int i = 0; i < RansomDetectPathDicCount; i++)
		{
			Tran_SendPacket(Tran_Client[Count], (char*)(RansomDetectPathDic[i]).c_str(), PTHideFile, (char*)"", 0);
			Tran_SendPacket(Tran_Client[Count], (char*)File_GetShortFileName(RansomDetectPathDic[i]).c_str(), PTHideFile, (char*)"", 0);
		}
	}
	else
	{
		// R0 已启用或勒索防护未开启，不通过 R3 DLL 监控诱捕文件
		Tran_SendPacket(Tran_Client[Count], (char*)"", PTHideFile, (char*)"HideFileCount", 0);
	}
	Sleep(1);

	while (true)
	{
		Packet PacketRecv;

		if (Tran_IsSocketClosed(Tran_Client[Count])) break;
		else if (Tran_RecvPacket(Tran_Client[Count], PacketRecv) > 0)
		{
			switch (PacketRecv.PacketTyped)
			{
			case PTConnection:
			{
				Tran_ClientPid[Count] = PacketRecv.Pid;
				break;
			}
			case PTVirusOperationConfirm:
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, PacketRecv.Pid);

				if (hProcess)
				{
					// 特例：如果是返回脚本路径的请求，并且需要终止进程，则直接终止进程并记录日志（因为这类请求由扫描脚本文件时发出的，如果需要终止进程就说明直接终止进程并记录日志就行了）。
					if (strcmp(PacketRecv.WarnTitle, "ReturnScriptPath") == 0)
					{
						Process_ZwTerminateProcess(hProcess, 0);

						ShowThreatDialog(PacketRecv.Message, "ADV·脚本病毒");

						QString log;

						log += "[路径] ";
						log += QString::fromLocal8Bit(PacketRecv.Message);
						log += " [类型] ";
						log += "ADV·可疑行为特征脚本病毒";
						log += " [级别] ";
						log += "脚本病毒";
						log += " [结果] ";
						log += "[终止进程]";

						Log_AddLogEx(QString("已终止进程（脚本病毒）"),
					             QString("路径: %1\n类型: ADV·可疑行为特征脚本病毒\n级别: 脚本病毒")
					                .arg(QString::fromLocal8Bit(PacketRecv.Message)),
					             LOG_WARN, "User.ScriptScan");

						string str;
						str += "进程 ";
						string strPath = PacketRecv.Message;
						str += strPath.substr(strPath.find_last_of('\\') + 1, strPath.length() - strPath.find_last_of('\\'));
						str += " (";
						str += std::to_string(PacketRecv.Pid);
						str += ") 动态扫描完成，已发现威胁并拦截。";
						NewMessageBox(str.c_str(), 5);

						break;
					}

					if (PacketRecv.NeedTerminate) Process_SuspendProcess(hProcess, FALSE);

					string FilePath; // 文件路径

					// 特例：如果是扫描脚本文件的请求，则直接使用传来的路径进行处理，而不是通过进程句柄获取路径
					if (strcmp(PacketRecv.WarnTitle, "AskForScanScript") == 0)
					{
						FilePath = PacketRecv.Message;

						if (!ScanProcessFile(FilePath, TRUE, hProcess))
						{
							Process_ResumeProcess(hProcess, false);
							Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", TRUE);
						}

						CloseHandle(hProcess);
						break;
					}
					else FilePath = Process_GetProcessPath(hProcess);

					QString Log;

					Log += "[路径] ";
					Log += QString::fromLocal8Bit(FilePath);
					Log += " [类型] ";
					Log += QString::fromLocal8Bit(PacketRecv.InfoTitle);
					Log += " [信息] ";
					Log += QString::fromLocal8Bit(PacketRecv.WarnTitle);
					Log += " [结果] ";

					// 特例：Susp 恶意行为特征（R3 DLL 检测）
				if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("BehaviorDetection")))
				{
					bool behaviorEnabled = (pProtectionSettingPage && pProtectionSettingPage->pBehaviorDetectionSwitch &&
											pProtectionSettingPage->pBehaviorDetectionSwitch->getIsToggled());
					if (!behaviorEnabled)
				{
					// 行为分析开关未开启：恢复进程并允许运行
					if (PacketRecv.NeedTerminate) Process_ResumeProcess(hProcess, FALSE);
					Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", FALSE);
					CloseHandle(hProcess);
					Log_AddLogEx(QString("行为分析已关闭，自动允许"),
					             QString("路径: %1\n信息: %2")
					                .arg(QString::fromLocal8Bit(FilePath))
					                .arg(QString::fromLocal8Bit(PacketRecv.WarnTitle)),
					             LOG_INFO, "User.BehaviorDetection");
					break;
				}

					Process_ZwTerminateProcess(hProcess, 0);

					NewMessageBox("威胁终止：进程 " + QString::fromLocal8Bit(FilePath), 5);

					ShowThreatDialog(QString::fromLocal8Bit(FilePath.c_str()), QString::fromLocal8Bit(PacketRecv.WarnTitle));

					CloseHandle(hProcess);

					Log += "[终止进程]";

					Log_AddLogEx(QString("已终止进程（威胁行为）"),
					             QString("路径: %1\n类型: %2\n信息: %3")
					                .arg(QString::fromLocal8Bit(FilePath))
					                .arg(QString::fromLocal8Bit(PacketRecv.InfoTitle))
					                .arg(QString::fromLocal8Bit(PacketRecv.WarnTitle)),
					             LOG_WARN, "User.BehaviorDetection");

					break;
				}

					RelActWarnType RAT;

				if (g_bSilentModeEnabled)
				{
					RAT = AW_Prevent;
				}
				// 正规处理逻辑：如果对应防护项未开启，则直接允许；否则如果在自动允许列表中，则自动允许；如果在自动阻止列表中，则自动阻止；否则弹窗询问用户。
				else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("注册表防护")) && !pProtectionSettingPage->pRegistrySwitch->getIsToggled()) RAT = AW_Allow;
					else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("注册表防护")) && g_bR0ProtectionEnabled) RAT = AW_Allow;
					else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("文件防护")) && !pProtectionSettingPage->pFileSwitch->getIsToggled()) RAT = AW_Allow;
					else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("文件防护")) && g_bR0ProtectionEnabled) RAT = AW_Allow;
					else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("内存防护")) && !pProtectionSettingPage->pMemorySwitch->getIsToggled()) RAT = AW_Allow;
					else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("驱动防护")) && !pProtectionSettingPage->pDriverLoadSwitch->getIsToggled()) RAT = AW_Allow;
					else if ((QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("勒索病毒") || QString::fromLocal8Bit(PacketRecv.InfoTitle) == QString::fromUtf8("勒索防护")) && !(pProtectionSettingPage && pProtectionSettingPage->pFileSwitch && pProtectionSettingPage->pFileSwitch->getIsToggled() && pProtectionSettingPage->pRansomProtectionSwitch && pProtectionSettingPage->pRansomProtectionSwitch->getIsToggled())) RAT = AW_Allow;
					else if (AutoAllowList.Find(PacketRecv.Pid, PacketRecv.WarnTitle))
					{
						RAT = AW_Allow;
					}
					else if (AutoPreventList.Find(PacketRecv.Pid, PacketRecv.WarnTitle))
					{
						RAT = AW_Prevent;
					}
					else
					{
						WaitForSingleObject(HandleMutex, 30000);  /* 30秒超时，避免死锁 */
						if (pProtectionSettingPage->pIsUsingSafeDesktopSwitch->getIsToggled() && isGdiReady)
						{
							RAT = ShowAlertDialogWithUAC(QString::fromLocal8Bit(PacketRecv.WarnTitle), PacketRecv.Pid, QString::fromLocal8Bit(PacketRecv.Message));
						}
						else RAT = ShowAlertDialog(QString::fromLocal8Bit(PacketRecv.WarnTitle), PacketRecv.Pid, QString::fromLocal8Bit(PacketRecv.Message));
						ReleaseMutex(HandleMutex);

					}

					switch (RAT)
					{
					case AW_Allow:
						if (PacketRecv.NeedTerminate) Process_ResumeProcess(hProcess, FALSE);

						Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", TRUE);
						Log += "[允许]";
						break;
					case AW_AutoAllow:
						if (PacketRecv.NeedTerminate) Process_ResumeProcess(hProcess, FALSE);

						Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", TRUE);
						Log += "[自动允许]";
						AutoAllowList.Add(PacketRecv.Pid, PacketRecv.WarnTitle);
						break;
					case AW_AutoPrevent:
						if (PacketRecv.NeedTerminate) Process_ZwTerminateProcess(hProcess, 0);

						Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", FALSE);
						Log += "[自动阻止]";
						AutoPreventList.Add(PacketRecv.Pid, PacketRecv.WarnTitle);
						break;
					case AW_Prevent:
						if (PacketRecv.NeedTerminate) Process_ZwTerminateProcess(hProcess, 0);

						Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", FALSE);
						Log += "[阻止]";
						break;
					case AW_Terminate:
						if (!Process_ZwTerminateProcess(hProcess, 0))
						{
							Log += "[(失败)终止进程]";
							Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", FALSE); // Fail 时不予resume
						}
						else Log += "[终止进程]";
						break;
					default:
						break;
					}

					/* 将 Log 字符串转为详情，摘要根据决策结果生成。
				 * 摘要优先使用 WarnTitle（具体行为，如"注入"），避免出现"已阻止内存防护"
				 * 这类泛化标题；WarnTitle 为空时回退到 InfoTitle（类别）。 */
				QString r3Category = QString::fromLocal8Bit(PacketRecv.InfoTitle);
				QString r3Action = QString::fromLocal8Bit(PacketRecv.WarnTitle);

				/* WarnTitle 为空时，从 Message 提取具体行为描述，避免使用泛化类别名
				 * 生成"已阻止内存防护"这类无意义标题。Message 格式通常为
				 * "[ADV·恶意拦截] 具体行为描述！..."，提取 ']' 后到 '！' 或换行的内容。 */
				if (r3Action.isEmpty())
				{
					QString msg = QString::fromLocal8Bit(PacketRecv.Message);
					int closeBracket = msg.indexOf(']');
					if (closeBracket != -1)
					{
						QString rest = msg.mid(closeBracket + 1).trimmed();
						int endIdx = rest.indexOf(QChar('！'));
						if (endIdx == -1) endIdx = rest.indexOf('\r');
						if (endIdx == -1) endIdx = rest.indexOf(QChar('。'));
						r3Action = (endIdx > 0) ? rest.left(endIdx).trimmed() : rest;
					}
				}

				/* 根据 InfoTitle 类别映射提供者（R3 路径均为 User.* 提供者） */
				QString r3Provider;
				if (r3Category == QString::fromUtf8("内存防护"))
					r3Provider = "User.MemoryProtection";
				else if (r3Category == QString::fromUtf8("文件防护"))
					r3Provider = "User.FileProtection";
				else if (r3Category == QString::fromUtf8("注册表防护"))
					r3Provider = "User.RegistryProtection";
				else if (r3Category == QString::fromUtf8("驱动防护"))
					r3Provider = "User.DriverLoadProtection";
				else if (r3Category == QString::fromUtf8("BehaviorDetection"))
					r3Provider = "User.BehaviorDetection";
				else if (r3Category == QString::fromUtf8("勒索病毒") || r3Category == QString::fromUtf8("勒索防护"))
					r3Provider = "User.RansomProtection";
				else
					r3Provider = "User.Protection";

				QString r3Summary;
				LogLevel r3Level = LOG_INFO;
					if (Log.contains("[阻止]") || Log.contains("[自动阻止]"))
					{
						r3Summary = r3Action.isEmpty()
					                ? QString("已阻止%1").arg(r3Category)
					                : QString("已阻止：%1").arg(r3Action);
						r3Level = LOG_WARN;
					}
					else if (Log.contains("[终止进程]") || Log.contains("[(失败)终止进程]"))
					{
						r3Summary = r3Action.isEmpty()
					                ? QString("已终止进程（%1）").arg(r3Category)
					                : QString("已终止进程：%1").arg(r3Action);
						r3Level = LOG_WARN;
					}
					else if (Log.contains("[允许]") || Log.contains("[自动允许]"))
					{
						r3Summary = r3Action.isEmpty()
					                ? QString("已允许%1").arg(r3Category)
					                : QString("已允许：%1").arg(r3Action);
						r3Level = LOG_INFO;
					}
					else
					{
						r3Summary = r3Action.isEmpty()
					                ? (r3Category + " 操作完成")
					                : QString("%1 操作完成").arg(r3Action);
					}

					/* 提取结果值并去除方括号，使详情显示更简洁 */
					QString r3Result = Log.section("[结果]", 1).trimmed();
					r3Result.remove('[').remove(']');

					/* 从 Message 中提取目标进程路径（仅内存防护跨进程注入告警含此信息）。
					 * Message 格式: "[ADV·内存防护] 进程 <src> (PID=x) 向远程进程 <tgt> (PID=y) 的 ..."
					 * 提取 "向远程进程 " 之后、" (PID=" 之前的部分作为目标路径。
					 * 其他类型告警无目标路径，留空。 */
					QString r3TargetPath;
					QString r3Message = QString::fromLocal8Bit(PacketRecv.Message);
					{
						int pos = r3Message.indexOf(QString::fromUtf8("向远程进程 "));
						if (pos != -1)
						{
							QString rest = r3Message.mid(pos + 6); /* "向远程进程 " = 6 QChars (5中文+1空格) */
							int endIdx = rest.indexOf(QStringLiteral(" (PID="));
							if (endIdx > 0)
								r3TargetPath = rest.left(endIdx).trimmed();
						}
					}

					QString r3Detail = QString("路径: %1\n目标路径: %2\n类型: %3\n信息: %4\n结果: %5")
					                    .arg(QString::fromLocal8Bit(FilePath))
					                    .arg(r3TargetPath.isEmpty() ? QStringLiteral("-") : r3TargetPath)
					                    .arg(r3Category)
					                    .arg(r3Action)
					                    .arg(r3Result);
					Log_AddLogEx(r3Summary, r3Detail, r3Level, r3Provider);

					CloseHandle(hProcess);

				}
				else Tran_SendPacket(Tran_Client[Count], (char*)"", PTVirusOperationConfirm, (char*)"OperationConfirm", FALSE);

				break;
			}
			case PTCreateProcessRoutine:
			{
				string ProcPath;
				string sCmd;
				HANDLE hProcess = NULL;
				BOOL isNtCreateUserProcessEnter = FALSE;

				// 注意：g_bR0ProtectionEnabled 只在 OnDriverProtectionToggled 中设置，
				// 不在此处根据开关状态重新同步。否则在 R0 异步启动流程完成前，
				// g_bR0ProtectionEnabled 会被提前设为 TRUE，导致：
				//   1. SyncRansomHoneypotToR3Clients 检查到 R0 启用而跳过 R3 通知
				//   2. 但 R0 诱捕规则尚未同步到驱动
				//   3. 出现 R0/R3 双路都不监控诱捕文件的"保护空窗"

				if (strcmp(PacketRecv.WarnTitle, "CallResumeEvent") == 0) // 处理Hook完成后的事件
				{
					WaitForSingleObject(CreateCheckMutex, 30000);  /* 30秒超时，避免死锁 */

					for (auto it = ProcessEventId.begin(); it != ProcessEventId.end(); )
					{
						if (it->first == PacketRecv.Pid)
						{
							HANDLE hEvent = OpenEventA(
								EVENT_MODIFY_STATE,  // 需要修改状态的权限
								FALSE,              // 不继承句柄
								it->second.c_str()   // 与注入器相同的事件名称
							);

							if (hEvent != NULL)
							{
								SetEvent(hEvent);
								CloseHandle(hEvent);
							}

							it = ProcessEventId.erase(it);

							break;
						}
						else
						{
							++it;
						}
					}

					ReleaseMutex(CreateCheckMutex);

					break;
				}
				else if (strcmp(PacketRecv.WarnTitle, "NtCreateUserProcess") == 0)
				{
					/* R0 启用时，NtCreateUserProcess 路径直接放行，由 R0 的
					 * ProcessCreateNotifyRoutine 挂起新进程并发送 PROCESS_CHECK
					 * 给 main.cpp 做完整扫描（含命令行目标文件 vbs/js 等）。
					 * R3 在此处做无效扫描反而有害：
					 *   1. sCmd 此时拿不到真实命令行（进程尚未初始化）
					 *   2. 宿主 wscript.exe 是系统白名单文件，R3 扫描必然放行
					 *   3. 重复扫描增加延迟，与 R0 PROCESS_CHECK 形成竞争 */
					if (g_bR0ProtectionEnabled)
					{
						Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE);
						break;
					}

					ProcPath = PacketRecv.Message;
					sCmd = ProcPath;
					isNtCreateUserProcessEnter = TRUE;
				}
				else // NtResumeThread 进入
				{
					/* R0 驱动防护启用时，驱动层 ProcessCreateNotifyRoutine 已经挂起新进程
					 * 并独立通过 PROCESS_CHECK 完成扫描/拦截；R3 在此处等待 PEB 初始化会
					 * 与 R0 的挂起死锁（子进程被挂起，PEB 永远不会初始化），导致父进程
					 * CreateProcess 卡死。直接放行，让 R0 负责后续处理。 */
					if (g_bR0ProtectionEnabled)
					{
						Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE);
						break;
					}

					hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PacketRecv.Pid);

					if (hProcess)
					{
						Process_WaitForProcessPebInitialized(hProcess);

						// Process_SuspendProcess(hProcess, false);

						sCmd = Process_GetProcessCommandLine(hProcess);

						ProcPath = Process_GetProcessPath(hProcess);
					}
					else
					{
						Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE); // Fail 时不予resume
						break;
					}
				}

				bool IsBeenInWaitingProcessInjection = false;

				if (sCmd.length() > 0)
				{
					RelActWarnType RAWT;

					if (hProcess)
					{
						// 统一调用 DetectCommandLineRisk 进行命令行风险检测
						CommandLineRiskResult riskResult = DetectCommandLineRisk(PacketRecv.Pid, ProcPath, sCmd);
						string sendOut = riskResult.sendOut;
						string alertTitle = riskResult.alertTitle;
						bool beenInHandling = riskResult.detected;

						if (beenInHandling)
						{
							int ParentPid = Process_GetProcessParent(PacketRecv.Pid);

							if (ParentPid <= 0)
							{
								ParentPid = PacketRecv.Pid;
							}

							if (riskResult.autoBlock)
							{
								/* 命令行可疑：无需弹窗，直接终止进程并阻止恢复 */
								RAWT = AW_Prevent;
								Log_AddLogSimple(QString("已自动阻止命令行可疑命令 PID=%1").arg(PacketRecv.Pid),
									LOG_WARN, "Kernel.CommandLineRisk");
							}
							else if (AutoAllowList.Find(ParentPid, alertTitle))
							{
								RAWT = AW_Allow;
							}
							else if (AutoPreventList.Find(ParentPid, alertTitle))
							{
								RAWT = AW_Prevent;
							}
							else
							{
								WaitForSingleObject(HandleMutex, 30000);  /* 30秒超时，避免死锁 */
								if (pProtectionSettingPage->pIsUsingSafeDesktopSwitch->getIsToggled() && isGdiReady)
								{
									RAWT = ShowAlertDialogWithUAC(alertTitle.c_str(), PacketRecv.Pid, sendOut.c_str());
								}
								else RAWT = ShowAlertDialog(alertTitle.c_str(), PacketRecv.Pid, sendOut.c_str());
								ReleaseMutex(HandleMutex);
							}

							BOOL Allow = FALSE;

							switch (RAWT)
							{
							case AW_Allow:
								Allow = TRUE;
								break;
							case AW_AutoAllow:
								Allow = TRUE;
								AutoAllowList.Add(ParentPid, alertTitle);
								break;
							case AW_AutoPrevent:
								AutoPreventList.Add(ParentPid, alertTitle);
								break;
							default:
								break;
							}

							if (!Allow && hProcess)
							{
								Process_ZwTerminateProcess(hProcess, 0);

								Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE);

								// 定义已知的命令行执行器进程名
								const std::vector<std::string> knownExecutors = {
									"cmd.exe",
									"powershell.exe"
								};

								// 辅助函数：检查进程是否为命令行执行器
								auto IsCommandExecutor = [&knownExecutors](const std::string& processPath) -> bool {
									if (processPath.empty()) return false;

									// 从完整路径中提取文件名
									size_t lastSlash = processPath.find_last_of("\\/");
									std::string processName;
									if (lastSlash != std::string::npos) {
										processName = processPath.substr(lastSlash + 1);
									}
									else {
										processName = processPath;
									}

									// 转换为小写比较
									std::string lowerName = processName;
									std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

									for (const auto& executor : knownExecutors) {
										if (lowerName == executor) {
											return true;
										}
									}
									return false;
									};

								// 获取直接父进程
								int parentPid = Process_GetProcessParent(PacketRecv.Pid);
								if (parentPid > 0)
								{
									// 打开父进程
									HANDLE hParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, parentPid);
									if (hParentProcess)
									{
										// 获取父进程路径
										string parentProcessPath = Process_GetProcessPath(hParentProcess);

										// 检查父进程是否为命令行执行器
										if (IsCommandExecutor(parentProcessPath))
										{
											// 父进程是命令行执行器，追溯祖父进程
											int grandParentPid = Process_GetProcessParent(parentPid);
											if (grandParentPid > 0)
											{
												HANDLE hGrantParentProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, grandParentPid);

												if (hGrantParentProcess)
												{
													// 构造完整的 explorer.exe 路径
													WCHAR szExplorerPath[MAX_PATH] = { 0 };
													wcscpy_s(szExplorerPath, MAX_PATH, wcWindowsPath);
													wcscat_s(szExplorerPath, MAX_PATH, L"\\explorer.exe");

													// 不区分大小写比较路径，如果不是Explorer就kill
													if (!(_wcsicmp((CString)Process_GetProcessPath(hProcess).c_str(), szExplorerPath) == 0))
													{
														// 查找祖父进程对应的客户端索引
														int clientIndex = -1;
														for (int i = 0; i < MAX_CLIENT_COUNT; i++)
														{
															if (Tran_ClientPid[i] == grandParentPid)
															{
																clientIndex = i;
																break;
															}
														}

														// 发送警告给祖父进程
														if (clientIndex != -1 && Tran_Client[clientIndex] != NULL)
														{
															Tran_SendPacket(Tran_Client[clientIndex], (char*)"", PTThreatScore, (char*)"", FALSE);
														}
													}
												}
											}
										}

										// 发送警告给父进程
										int clientIndex = -1;
										for (int i = 0; i < MAX_CLIENT_COUNT; i++)
										{
											if (Tran_ClientPid[i] == parentPid)
											{
												clientIndex = i;
												break;
											}
										}

										// 发送警告给父进程
										if (clientIndex != -1 && Tran_Client[clientIndex] != NULL)
										{
											Tran_SendPacket(Tran_Client[clientIndex], (char*)"", PTThreatScore, (char*)"", FALSE);
										}

										CloseHandle(hParentProcess);
									}
								}

								CloseHandle(hProcess);

								Log_AddLogEx(QString("已结束命令进程"),
							             QString("路径: %1\n类型: 风险命令\n信息: %2\n结果: 结束命令进程")
							                .arg(QString::fromLocal8Bit(ProcPath))
							                .arg(alertTitle),
							             LOG_INFO, "Kernel.CommandLineRisk");

								continue;
							}
							else if (!Allow)
							{
								Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE);

								Log_AddLogEx(QString("已阻止命令进程恢复"),
							             QString("路径: %1\n类型: 风险命令\n信息: %2\n结果: 阻止命令进程恢复")
							                .arg(QString::fromLocal8Bit(ProcPath))
							                .arg(alertTitle),
							             LOG_INFO, "Kernel.CommandLineRisk");
							}
						}
					}

					if (isNtCreateUserProcessEnter)
					{
						if (pProtectionSettingPage->pIsFullScanSwitch->getIsToggled())
						{
							BOOL blocked = ScanProcessFile(ProcPath);

							/* 扫描命令行目标文件（vbs/js 脚本、DLL 等）：
							 * 宿主 wscript.exe/cscript.exe 是系统文件，SHA256 命中白名单，
							 * 但命令行中实际要执行的 .vbs/.js 脚本才是真正的载荷，必须额外扫描。
							 * 与 PROCESS_CHECK 路径保持一致，使用 ExtractCommandLineTargetFiles 提取。 */
							if (!blocked && !sCmd.empty())
							{
								std::wstring wsProcPathNt = QString::fromLocal8Bit(ProcPath.c_str()).toStdWString();
								std::wstring wsCmdLineNt = QString::fromLocal8Bit(sCmd.c_str()).toStdWString();
								std::vector<std::wstring> cmdTargets = ExtractCommandLineTargetFiles(wsProcPathNt, wsCmdLineNt);
								for (const auto& targetW : cmdTargets)
								{
									std::string targetA = QString::fromStdWString(targetW).toLocal8Bit().toStdString();
									if (ScanProcessFile(targetA))
									{
										blocked = TRUE;
										Log_AddLogSimple(QString("NtCreateUserProcess 拦截恶意脚本/载荷: %1").arg(QString::fromLocal8Bit(targetA.c_str())), LOG_WARN, "Kernel.ProcessCreateCheck");
										break;
									}
								}
							}

							if (!blocked)
								Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE);
							else
								Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE);
						}
						else Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE);
						break;
					}
					else
					{
						// Check Virus
						if (!ScanProcessAutoChooseSync(ProcPath, TRUE, hProcess))
						{
							if (!pProtectionSettingPage->pDllProtectionSwitch->getIsToggled() || g_bR0ProtectionEnabled)
							{
								Process_ResumeProcess(hProcess, false); // 恢复进程

								Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", TRUE);

								// R0启用时，驱动通过work item延迟注入DLL，R3无需递归注入
							}
							else
							{
								string eventName = GenerateUniqueEventName(PacketRecv.Pid);

								HANDLE hHookReady = CreateEventA(
									NULL,               // 默认安全属性
									TRUE,               // 手动重置事件
									FALSE,             // 初始状态为非信号态
									eventName.c_str()   // 唯一事件名称
								); // 通过event+等待规避hook存在短时间无效问题

								if (!hHookReady)
								{
									Process_ZwTerminateProcess(hProcess, 0);

									Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE);

									NewMessageBox("由于 [" + std::to_wstring(PacketRecv.Pid) + L"] " + (wstring)(CString)ProcPath.c_str() + L" 可能脱离控制，已将其拦截。", 2);

									break;
								}

								WaitForSingleObject(CreateCheckMutex, 30000);  /* 30秒超时，避免死锁 */

								ProcessEventId.emplace_back(PacketRecv.Pid, eventName);

								ReleaseMutex(CreateCheckMutex);

								int Rel = Process_InjectDll(PacketRecv.Pid);
								if (Rel && Rel != 2)
								{
									WaitHookStruct* WaitHookInfo = new WaitHookStruct;
									WaitHookInfo->Pid = PacketRecv.Pid;
									WaitHookInfo->hHookReady = hHookReady;
									WaitHookInfo->Count = Count;
									WaitHookInfo->ProcPath = ProcPath;
									WaitHookInfo->sCmd = sCmd;
									WaitHookInfo->hProcess = hProcess;
									HANDLE hWaitHookThread = CreateThread(0, 0, WaitForHookT, WaitHookInfo, 0, 0);
									if (hWaitHookThread == NULL) {
										Log_AddLogSimple(QString("WaitForHookT CreateThread 失败: %1").arg(GetLastError()), LOG_ERROR);
										CloseHandle(hHookReady);
										delete WaitHookInfo;
										Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", -1);
									} else {
										CloseHandle(hWaitHookThread);
										IsBeenInWaitingProcessInjection = true;
									}
								}
								else
								{
									Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", -1);
									if (hHookReady) CloseHandle(hHookReady);
								}
							}
						}
						else
						{
							Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE); // 别等了，进程已被kill
						}
					}
				}
				else
				{
					if (hProcess)
					{
						// Fail 时 直接 Terminate
						Process_ZwTerminateProcess(hProcess, 0);

						Tran_SendPacket(Tran_Client[Count], (char*)"", PTCreateProcessRoutine, (char*)"", FALSE);
					}
				}

				if (hProcess && !IsBeenInWaitingProcessInjection) CloseHandle(hProcess);

				break;
			}
			default:
				break;
			}
		}

		Sleep(10);
	}

	// 清理客户端连接资源
	if (Tran_Client[Count] != NULL)
	{
		closesocket(Tran_Client[Count]);
	}

	AutoAllowList.Del(Tran_ClientPid[Count]);
	AutoPreventList.Del(Tran_ClientPid[Count]);

	Tran_Client[Count] = NULL;
	Tran_ClientPid[Count] = 0;

	return 0;
}

