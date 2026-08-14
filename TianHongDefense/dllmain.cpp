// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "PublicFunction.h"
#include "detours.h"

#include <mmsystem.h>
#include <mfapi.h>
#include <mfidl.h>
#include <functional>
#include <algorithm>
#include <unordered_map>
#include <comdef.h>
#include <combaseapi.h>
#include <taskschd.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")

#ifdef _WIN32
    #ifdef _WIN64
        #define calling __cdecl
        #pragma comment(lib, "Detours.lib")
    #else
        #define calling __stdcall
        #pragma comment(lib, "Detours32.lib")
    #endif
#endif //_WIN32


// Nt Function Type Define

typedef NTSTATUS(calling* NtQueryInformationThread)(HANDLE ThreadHandle, ULONG ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
typedef NTSTATUS(calling* NtQueryInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS(calling* NtQueryVirtualMemory_t)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
    );

const ULONG MemoryBasicInformationValue = 0;

typedef NTSTATUS(calling* NtCreateSection)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG SectionPageProtection,
    IN ULONG AllocationAttributes,
    IN HANDLE FileHandle OPTIONAL
    );
typedef NTSTATUS(calling* NtCreateUserProcess)(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
    PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
    );
typedef NTSTATUS(calling* NtResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS(calling* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef NTSTATUS(calling* NtResumeProcess)(IN HANDLE ProcessHandle);
typedef NTSTATUS(calling* NtCreateProcessEx)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
);
typedef NTSTATUS(calling* NtSetValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
    );
typedef NTSTATUS(calling* NtWriteFile)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
    );
typedef NTSTATUS(calling* NtRaiseHardError)(
    _In_ NTSTATUS ErrorStatus,
    _In_ ULONG NumberOfParameters,
    _In_ ULONG UnicodeStringParameterMask,
    _In_reads_(NumberOfParameters) PULONG_PTR Parameters,
    _In_ ULONG ValidResponseOptions,
    _Out_ PULONG Response
    );
typedef NTSTATUS(calling* PspTerminateThreadByPointer)(HANDLE Thread, NTSTATUS ExitStatus, BOOLEAN DirectTerminate);
typedef NTSTATUS(calling* PspTerminateProcess)(HANDLE Process, NTSTATUS ExitStatus);
typedef NTSTATUS(calling* NtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(calling* NtDebugActiveProcess)(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
    );
typedef BOOL(WINAPI* WinStationTerminateProcess)(HANDLE hServer, DWORD ProcessId, DWORD ExitCode);
/* SystemParametersInfoA/W hook 已移除：仅保留注册表持久化壁纸修改拦截，
 * 不再拦截系统级 SPI_SETDESKWALLPAPER 调用（explorer 正常设置壁纸不再弹窗）。 */
/* SystemParametersInfo hook 已移除
typedef BOOL(WINAPI* SystemParametersInfoA_t)(
    UINT  uiAction,
    UINT  uiParam,
    PVOID pvParam,
    UINT  fWinIni);
typedef BOOL(WINAPI* SystemParametersInfoW_t)(
    UINT  uiAction,
    UINT  uiParam,
    PVOID pvParam,
    UINT  fWinIni);
*/
typedef NTSTATUS(calling* NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
    );
typedef HRESULT(WINAPI* DirectShowCreate)(const GUID*, void**, const GUID*);
typedef MMRESULT(WINAPI* WaveInOpen)(LPHWAVEIN, UINT, LPCWAVEFORMATEX, DWORD_PTR, DWORD_PTR, DWORD);
typedef HRESULT(WINAPI* MFCreateDeviceSource_type)(IMFAttributes*, IMFMediaSource**);
typedef NTSTATUS(WINAPI* NtSetSystemTime)(
    _In_opt_ PLARGE_INTEGER SystemTime,
    _Out_opt_ PLARGE_INTEGER PreviousTime
);
typedef NTSTATUS(calling* NtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );
NET_API_STATUS(NET_API_FUNCTION* OriginalNetUserAdd)(
    _In_opt_  LPCWSTR    servername OPTIONAL,
    _In_      DWORD      level,
    _When_(level == 1, _In_reads_bytes_(sizeof(USER_INFO_1)))
    _When_(level == 2, _In_reads_bytes_(sizeof(USER_INFO_2)))
    _When_(level == 3, _In_reads_bytes_(sizeof(USER_INFO_3)))
    _When_(level == 4, _In_reads_bytes_(sizeof(USER_INFO_4)))
    LPBYTE     buf,
    _Out_opt_ LPDWORD    parm_err OPTIONAL
    ) = NetUserAdd;

NET_API_STATUS(NET_API_FUNCTION* OriginalNetUserSetInfo)(
    _In_opt_  LPCWSTR    servername OPTIONAL,
    _In_      LPCWSTR    username,
    _In_      DWORD     level,
    _In_reads_(_Inexpressible_("varies")) LPBYTE buf,
    _Out_opt_ LPDWORD   parm_err OPTIONAL
    ) = NetUserSetInfo;

NET_API_STATUS(NET_API_FUNCTION* OriginalNetUserDel)(
    _In_opt_  LPCWSTR    servername OPTIONAL,
    _In_      LPCWSTR    username
    ) = NetUserDel;
typedef NTSTATUS(calling* NtQueryDirectoryFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
    );
typedef NTSTATUS(calling* NtDeleteFile)(
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );
typedef NTSTATUS(calling* NtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass);
BOOL(WINAPI* OriginalSetCursorPos)(
    _In_ int X,
    _In_ int Y) = SetCursorPos;

BOOL(WINAPI* OriginalSetPhysicalCursorPos)(
    _In_ int X,
    _In_ int Y) = SetPhysicalCursorPos;
typedef NTSTATUS(calling* NtDeleteKey)(
    _In_ HANDLE KeyHandle
    );
typedef NTSTATUS(calling* NtDeleteValueKey)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName
    );
typedef NTSTATUS(calling* NtOpenFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
    );
typedef HRESULT(WINAPI* CoCreateInstance_type)(
    REFCLSID rclsid,
    LPUNKNOWN pUnkOuter,
    DWORD dwClsContext,
    REFIID riid,
    LPVOID* ppv);
typedef HRESULT(STDMETHODCALLTYPE* RegisterTaskDefinition_type)(
    ITaskFolder*,
    BSTR, ITaskDefinition*, long, VARIANT, VARIANT, TASK_LOGON_TYPE, VARIANT, IRegisteredTask**);
typedef ULONG(STDMETHODCALLTYPE* Release_type)(IUnknown*);
typedef NTSTATUS(NTAPI* RtlSetProcessIsCritical)(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag
);
typedef NTSTATUS (calling* NtSetInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
);
typedef NTSTATUS(calling* NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );
typedef NTSTATUS(calling* NtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(calling* NtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
typedef NTSTATUS(calling* NtQueueApcThreadEx)(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE UserApcReserveHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
typedef NTSTATUS(calling* NtQueueApcThreadEx2)(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE UserApcReserveHandle,
    _In_ ULONG_PTR ApcContext,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
    );
typedef BOOL(calling* StartServiceW_type)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCWSTR* lpServiceArgVectors);
typedef BOOL(calling* StartServiceA_type)(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR* lpServiceArgVectors);
typedef NTSTATUS(calling* ZwLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(calling* ZwSetSystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength
    );
typedef NTSTATUS(calling* NtProtectVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
    );
typedef NTSTATUS(calling* NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

// Define Original Function
NtCreateUserProcess OriginalNtCreateUserProcess;
NtResumeThread OriginalNtResumeThread;
NtResumeProcess OriginalNtResumeProcess;
NtCreateProcessEx OriginalNtCreateProcessEx;
NtSetValueKey OriginalNtSetValueKey;
NtWriteFile OriginalNtWriteFile;
NtRaiseHardError OriginalNtRaiseHardError;
WinStationTerminateProcess OriginalWinStationTerminateProcess;
NtDebugActiveProcess OriginalNtDebugActiveProcess;
PspTerminateThreadByPointer OriginalPspTerminateThreadByPointer;
PspTerminateProcess OriginalPspTerminateProcess;
NtTerminateProcess OriginalNtTerminateProcess;
NtOpenProcess OriginalNtOpenProcess;
DirectShowCreate OriginalDirectShowCreate;
WaveInOpen OriginalWaveInOpen;
MFCreateDeviceSource_type OriginalMFCreateDeviceSource;
NtSetSystemTime OriginalNtSetSystemTime;
NtCreateFile OriginalNtCreateFile;
NtQueryDirectoryFile OriginalNtQueryDirectoryFile;
NtDeleteFile OriginalNtDeleteFile;
NtSetInformationFile OriginalNtSetInformationFile;
NtDeleteKey OriginalNtDeleteKey;
NtDeleteValueKey OriginalNtDeleteValueKey;
NtOpenFile OriginalNtOpenFile;
RtlSetProcessIsCritical OriginalRtlSetProcessIsCritical;
NtSetInformationProcess OriginalNtSetInformationProcess;
NtCreateThreadEx OriginalNtCreateThreadEx;
NtMapViewOfSection OriginalNtMapViewOfSection;
NtQueueApcThread OriginalNtQueueApcThread;
NtQueueApcThreadEx OriginalNtQueueApcThreadEx;
NtQueueApcThreadEx2 OriginalNtQueueApcThreadEx2;
StartServiceW_type OriginalStartServiceW;
StartServiceA_type OriginalStartServiceA;
ZwLoadDriver OriginalZwLoadDriver;
ZwSetSystemInformation OriginalZwSetSystemInformation;
NtProtectVirtualMemory OriginalNtProtectVirtualMemory;
NtWriteVirtualMemory OriginalNtWriteVirtualMemory;
NtQueryInformationProcess OriginalNtQueryInformationProcess;
NtQueryVirtualMemory_t OriginalNtQueryVirtualMemory;
/* SystemParametersInfo hook 已移除：仅保留注册表持久化壁纸修改拦截，
 * 不再拦截系统级 SPI_SETDESKWALLPAPER 调用（explorer 正常设置壁纸不再弹窗）。 */
//SystemParametersInfoA_t OriginalSystemParametersInfoA = NULL;
//SystemParametersInfoW_t OriginalSystemParametersInfoW = NULL;

// DLL 侧载防护函数指针
typedef NTSTATUS(calling* LdrLoadDll_t)(
    PWCHAR PathToFile,
    PULONG DllCharacteristics,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
    );
LdrLoadDll_t OriginalLdrLoadDll = NULL;

// Define Nt Function(Not Hooked)


// 全局变量

// 勒索软件防护
std::vector<std::pair<std::chrono::steady_clock::time_point, std::wstring>> g_fileOperations;
std::shared_mutex g_opsMutex;
const size_t WINDOW_SIZE = 10;                // 滑动窗口大小
const std::chrono::seconds WINDOW_DURATION(1); // 滑动窗口时间范围
const double RATE_THRESHOLD = 10.0;           // 每秒10个文件操作视为可疑
chrono::steady_clock::time_point ProcStartTime;

BOOL isCurrentConsoleProcess = FALSE;

// 可疑文件扩展名
const std::vector<std::wstring> RANSOMWARE_EXTENSIONS =
{
    L".encrypted", L".crypted", L".locked", L".crypto",
    L".ransom", L".blackmail", L".aes", L".rsa",
    L".pzdc", L".crypt", L".xtbl", L".zepto", L".enc",
    L".lswj", L".died", L".murdered", L".locked"
};

// 可疑路径关键词
const std::vector<std::wstring> SUSPICIOUS_PATHS =
{
    L"\\appdata\\"
    L"\\desktop\\", L"\\documents\\", L"\\downloads\\",
    L"\\pictures\\", L"\\videos\\", L"\\music\\", L"\\data\\",
};

const vector<string> SUSPICIOUS_EXTFILE =
{
    ".xls", ".xlsx", ".ppt", ".pptx", ".doc", ".docx", ".txt", ".html", ".htm", ".hta",
    ".jpg", ".jpeg", ".png", ".gif", ".pdf", ".db", ".mp4", ".mp3", ".mindx", "flv"
};

const vector<string> WHITE_EXTFILE =
{
    ".exe", ".dll", ".sys", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".reg"
};


// 操作类型枚举
enum class FileOpType
{
    F_CREATE,
    F_DELETE
};

// 文件操作记录结构
struct DeFileOperation
{
    chrono::steady_clock::time_point time;
    wstring filename;
    FileOpType type;
};

SOCKET Tran_Server;
HMODULE hDll;
int MainProcessPid = -1;
int InjectorPid = -1;

HANDLE CreateResponseEvent = NULL;
short CreateOperationResult = FALSE;
short ProtectionReadyCount = 0;
CRITICAL_SECTION CreateCsSync;           // 临界区（确保线程安全）

HANDLE HandleOperationResponseEvent = NULL;
BOOL HandleOperationResult = FALSE;
CRITICAL_SECTION HandleCsSync;           // 临界区（确保线程安全）

BOOL isExplorer = FALSE;
BOOL isWindowsFile = FALSE;
BOOL isScriptScan = FALSE; // 本进程是否为脚本宿主
BOOL isProtectionFileReady = FALSE;

// DLL 侧载防护：当前进程 Authenticode 签名状态（在 InitT 中预计算，避免在 LdrLoadDll 钩子中做重签名验证导致死锁）
// -1 未初始化, 0 未签名/签名无效, 1 已签名
volatile LONG g_CurrentProcessSigned = -1;
volatile LONG g_DllSideLoadBlockedCount = 0; // 统计被拦截的 DLL 侧载次数

wchar_t wcSystemRootPath[32767 + 10] = { 0 };
wchar_t wcWindowsRootPath[32767 + 10] = { 0 };
wchar_t wcSysWow64Path[32767 + 10] = { 0 };
string DesktopPath;

char szStartupPath[MAX_PATH + 4];
char szStartupPathAllUsers[MAX_PATH + 4];

int Suspiciousness = 0;

vector<int> ThisProtectionTid_NtCreateFile;
vector<int> ThisProtectionTid_NtOpenFile;

string ProtectFile[100];
int ProcFileCount = 0;

string thisScriptPath;

int HideFileCount = 999;

static ULONGLONG SuspLastDecayTime = 0;
static bool SuspTimerStarted = false;

BOOL isEnableSyscallMonitor = FALSE;

// 全局函数

void EnterHandleEvent()
{
    // 进入临界区（防止多线程竞争）
    EnterCriticalSection(&HandleCsSync);
}

void ExitHandleEvent()
{
    LeaveCriticalSection(&HandleCsSync);
}

BOOL WaitForResult()
{
    ResetEvent(HandleOperationResponseEvent);  // 重置事件状态
    HandleOperationResult = FALSE;   // 重置结果

    // 等待接收线程响应
    DWORD dwWaitResult = WaitForSingleObject(HandleOperationResponseEvent, INFINITE);

    BOOL bResult = (dwWaitResult == WAIT_OBJECT_0) ? HandleOperationResult : FALSE;

    return bResult;
}

void SetHandleResult(BOOL Relsult)
{
    HandleOperationResult = Relsult;

    SetEvent(HandleOperationResponseEvent);     // 通知等待线程
}

bool CheckSuspiciousness()
{
    // 获取当前时间（毫秒）
    ULONGLONG dwCurrentTime = GetTickCount64();

    // 第一次调用时初始化计时器
    if (!SuspTimerStarted)
    {
        SuspLastDecayTime = dwCurrentTime;
        SuspTimerStarted = true;
    }

    // 计算已经过去的时间（秒）
    ULONGLONG dwElapsedSeconds = (dwCurrentTime - SuspLastDecayTime) / 1000;

    // 如果过去时间 >= 60秒，执行衰减
    if (dwElapsedSeconds >= 60)
    {
        // 计算需要执行的衰减次数
        int nDecayCount = (int)(dwElapsedSeconds / 60);

        // 执行多次衰减（每次减少50%）
        for (int i = 0; i < nDecayCount; i++)
        {
            Suspiciousness = Suspiciousness / 2;
        }

        // 更新最后一次衰减时间
        SuspLastDecayTime += (nDecayCount * 1000);
    }

    // 检查逻辑
    if (Suspiciousness >= 130)
    {
        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)"", PTVirusOperationConfirm,
            (char*)"Behavior/Malware.Generic",
            GetCurrentProcessId(),
            (char*)"BehaviorDetection",
            WDT_Normal, true) > 0)
        {
            ExitHandleEvent();
            return true;
        }
        else
        {
            ExitProcess(-1);
            return true;
        }
    }

    return false;
}

BOOL isFileUnderProtection(string sPath)
{
    // 临时方案：降低轮询频率以减少上下文切换（建议后续改为事件通知）
    while (!isProtectionFileReady) Sleep(100);

    /* ProtectFile[] 存储的是 DOS 路径（如 C:\Users\xxx\.hidden\file.docx），无前缀。
     * 调用方传入的路径可能带以下前缀之一，也可能无前缀（DOS 路径）：
     *   "\\??\\"   — NT 路径（NtCreateFile hook 传入）
     *   "\\\\?\\"  — Win32 扩展路径
     *   无前缀     — DOS 路径（NtQueryDirectoryFile hook 经 File_GetFilePathFromHFILE
     *               VOLUME_NAME_DOS 获取，用于目录枚举隐藏）
     * 统一剥离前缀后与 ProtectFile[] 直接比较，避免前缀不匹配导致漏判。 */
    string sPathNoPrefix = sPath;
    if (sPathNoPrefix.find("\\??\\") == 0 ||
        sPathNoPrefix.find("\\\\?\\") == 0)
    {
        sPathNoPrefix = sPathNoPrefix.substr(4);
    }

    for (int i = 0; i < ProcFileCount; ++i)
    {
        if (Str_CompareWithoutCap(ProtectFile[i], sPathNoPrefix))
        {
            return TRUE;
        }
    }
    return FALSE;
}
BOOL isFileUnderWindowsDirectory(string sPath)
{
    // 转换为宽字符串并统一为小写
    string sWindowsRoot = Str_ConvertLPWSTRToLPSTR((LPWSTR)wcWindowsRootPath);

    string sPathWithoutPrefix = sPath;

    // 处理常见的路径前缀
    if (sPathWithoutPrefix.find("\\??\\") == 0 ||
        sPathWithoutPrefix.find("\\\\?\\") == 0)
    {
        sPathWithoutPrefix = sPathWithoutPrefix.substr(4);
    }

    if (sWindowsRoot.back() != '\\')
    {
        sWindowsRoot += '\\';
    }

    // 检查是否以Windows目录开头
    if (Str_StartsWithWithoutCap(sPathWithoutPrefix, sWindowsRoot))
    {
        // 排除 Windows 临时目录：系统程序（如 MpCmdRun、TrustedInstaller 等）
        // 经常在 C:\Windows\TEMP\ 下创建临时文件，不应被误判为删除系统文件
        string sTempDir = sWindowsRoot + "TEMP\\";
        if (Str_StartsWithWithoutCap(sPathWithoutPrefix, sTempDir))
        {
            return FALSE;
        }
        return TRUE; // 是Windows目录或其子目录
    }

    // 检查是否是Windows目录本身（不带结尾的反斜杠）
    string sWindowsRootNoSlash = sWindowsRoot;
    if (sWindowsRootNoSlash.back() == '\\')
    {
        sWindowsRootNoSlash.pop_back();
    }

    if (sPathWithoutPrefix == sWindowsRootNoSlash)
    {
        return TRUE; // 路径就是Windows目录本身
    }

    return FALSE;
}

bool IsSystemAbusedProgram(const wstring& procPath, const wstring& exeName, const wstring& systemRootPath, const wstring& sysWow64Path)
{
    wstring systemPath = systemRootPath + L"\\" + exeName;
    wstring wow64Path = sysWow64Path + L"\\" + exeName;

    string procPathA = Str_ConvertLPWSTRToLPSTR((LPWSTR)procPath.c_str());
    return Str_CompareWithoutCap(procPathA, Str_ConvertLPWSTRToLPSTR((LPWSTR)systemPath.c_str())) ||
           Str_CompareWithoutCap(procPathA, Str_ConvertLPWSTRToLPSTR((LPWSTR)wow64Path.c_str()));
}

// 直接系统调用防护 ==========================================================

extern "C" void InstrumentationCallback(
#ifdef _WIN64
    PCONTEXT ctx,
#endif
    uintptr_t ReturnAddress,
    uintptr_t ReturnVal
);

// -------------------------------------------------------------------
// 常量与类型定义
// -------------------------------------------------------------------
#define NtCurrentProcess() ((HANDLE)-1)
#define ProcessInstrumentationCallback ((PROCESS_INFORMATION_CLASS)0x28)
#define IP_SANITY_CHECK(ip, Base, Size) \
    ((ip) > (Base) && (ip) < ((Base) + (Size)))

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef void (*CallbackFn)();

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    CallbackFn Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
    );

// -------------------------------------------------------------------
// 汇编代理声明
// -------------------------------------------------------------------
#ifdef _M_IX86
__declspec(naked) void InstrumentationCallbackProxy()
{
    __asm
    {
        push esp
        push ecx
        push eax
        mov eax, 1
        cmp fs : [1B8h] , eax; recursion flag
        je resume
        pop eax
        pop ecx
        pop esp
        mov fs : [1B0h] , ecx; InstrumentationCallbackPreviousPc
        mov fs : [1B4h] , esp; InstrumentationCallbackPreviousSp
        pushad
        pushfd
        cld
        push eax; ReturnValue
        push ecx; ReturnAddress
        call InstrumentationCallback
        add esp, 08h
        popfd
        popad
        mov esp, fs: [1B4h]
        mov ecx, fs : [1B0h]
        jmp ecx

        resume :
        pop eax
            pop ecx
            pop esp
            jmp ecx
    }
}
#else
extern "C" void InstrumentationCallbackProxy();
#endif

// -------------------------------------------------------------------
// DirectSyscallDetection 类
// -------------------------------------------------------------------
class DirectSyscallDetection
{
public:
    DirectSyscallDetection();
    ~DirectSyscallDetection();

    BOOL Initialize();
    BOOL Uninitialize();

    static void InstrumentationCallback(
#ifdef _WIN64
        PCONTEXT ctx,
#endif
        uintptr_t ReturnAddress,
        uintptr_t ReturnVal
    );

private:
    static DWORD_PTR m_NtdllBase;
    static DWORD_PTR m_W32UBase;
    static DWORD m_NtdllSize;
    static DWORD m_W32USize;

    PVOID m_pDisableStub;
    SIZE_T m_StubSize;
    BOOL m_bInitialized;

    static void GetBaseAddresses();
    NTSTATUS SetInstrumentationCallbackHook(HANDLE ProcessHandle, BOOL Enable);
};

// 静态成员初始化
DWORD_PTR DirectSyscallDetection::m_NtdllBase = 0;
DWORD_PTR DirectSyscallDetection::m_W32UBase = 0;
DWORD DirectSyscallDetection::m_NtdllSize = 0;
DWORD DirectSyscallDetection::m_W32USize = 0;

// -------------------------------------------------------------------
// 构造函数 / 析构函数
// -------------------------------------------------------------------
DirectSyscallDetection::DirectSyscallDetection()
    : m_pDisableStub(nullptr)
    , m_StubSize(0)
    , m_bInitialized(FALSE)
{
}

DirectSyscallDetection::~DirectSyscallDetection()
{
    if (m_bInitialized)
        Uninitialize();
}

// -------------------------------------------------------------------
// 获取 ntdll / win32u 基址与大小
// -------------------------------------------------------------------
void DirectSyscallDetection::GetBaseAddresses()
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;

    m_NtdllBase = (DWORD_PTR)GetModuleHandleW(L"ntdll.dll");
    if (m_NtdllBase)
    {
        pDos = (PIMAGE_DOS_HEADER)m_NtdllBase;
        pNt = (PIMAGE_NT_HEADERS)(m_NtdllBase + pDos->e_lfanew);
        m_NtdllSize = pNt->OptionalHeader.SizeOfImage;
    }

    m_W32UBase = (DWORD_PTR)GetModuleHandleW(L"win32u.dll");
    if (m_W32UBase)
    {
        pDos = (PIMAGE_DOS_HEADER)m_W32UBase;
        pNt = (PIMAGE_NT_HEADERS)(m_W32UBase + pDos->e_lfanew);
        m_W32USize = pNt->OptionalHeader.SizeOfImage;
    }
}

// -------------------------------------------------------------------
// 设置/移除 InstrumentationCallback 钩子
// -------------------------------------------------------------------
NTSTATUS DirectSyscallDetection::SetInstrumentationCallbackHook(
    HANDLE ProcessHandle,
    BOOL Enable)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    pNtSetInformationProcess NtSetInformationProcess =
        (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!NtSetInformationProcess) return STATUS_ENTRYPOINT_NOT_FOUND;

    CallbackFn Callback = Enable ? InstrumentationCallbackProxy : (CallbackFn)m_pDisableStub;
    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION info = { 0 };

#ifdef _WIN64
    info.Version = 0;
#else
    // x86 WOW64 要求 Version 字段等于回调地址本身
    BOOL isWow64 = FALSE;
    if (!IsWow64Process(ProcessHandle, &isWow64) || isWow64)
        return 0xC00000BBL;
    info.Version = (ULONG)Callback;
#endif

    info.Reserved = 0;
    info.Callback = Callback;

    return NtSetInformationProcess(
        ProcessHandle,
        ProcessInstrumentationCallback,
        &info,
        sizeof(info)
    );
}

// -------------------------------------------------------------------
// 核心检测回调（无调试输出）
// -------------------------------------------------------------------
void DirectSyscallDetection::InstrumentationCallback(
#ifdef _WIN64
    PCONTEXT ctx,
#endif
    uintptr_t ReturnAddress,
    uintptr_t ReturnVal)
{
    BOOLEAN okNt, okWu;
    DWORD_PTR ntBase, wuBase;
    DWORD ntSize, wuSize;
    int disableOffset, prevSpOffset, prevPcOffset;
    uintptr_t pTEB = (uintptr_t)NtCurrentTeb();

#ifdef _WIN64
    disableOffset = 0x02EC;     // TEB->InstrumentationCallbackDisabled
    prevPcOffset = 0x02D8;     // TEB->InstrumentationCallbackPreviousPc
    prevSpOffset = 0x02E0;     // TEB->InstrumentationCallbackPreviousSp

    ctx->Rip = *((uintptr_t*)(pTEB + prevPcOffset));
    ctx->Rsp = *((uintptr_t*)(pTEB + prevSpOffset));
    ctx->Rcx = ctx->R10;
    ctx->R10 = ctx->Rip;
#else
    disableOffset = 0x01B8;
    prevPcOffset = 0x01B0;
    prevSpOffset = 0x01B4;
#endif

    // 递归保护
    if (!*((uintptr_t*)(pTEB + disableOffset)))
    {
        *((uintptr_t*)(pTEB + disableOffset)) = 1;

        // 获取模块信息（线程安全）
        ntBase = (DWORD_PTR)InterlockedCompareExchangePointer((PVOID*)&m_NtdllBase, NULL, NULL);
        wuBase = (DWORD_PTR)InterlockedCompareExchangePointer((PVOID*)&m_W32UBase, NULL, NULL);
        ntSize = InterlockedCompareExchange((LONG*)&m_NtdllSize, 0, 0);
        wuSize = InterlockedCompareExchange((LONG*)&m_W32USize, 0, 0);

        // 检查返回地址是否位于合法模块内
#ifdef _WIN64
        okNt = IP_SANITY_CHECK(ctx->Rip, ntBase, ntSize);
        okWu = IP_SANITY_CHECK(ctx->Rip, wuBase, wuSize);
#else
        okNt = IP_SANITY_CHECK(ReturnAddress, ntBase, ntSize);
        okWu = IP_SANITY_CHECK(ReturnAddress, wuBase, wuSize);
#endif

        if (!(okNt || okWu))
        {
            __try {
                Tran_OrgSendPacket(Tran_Server, (char*)"", PTVirusOperationConfirm,
                    (char*)"Behavior/DirectSyscall.a",
                    GetCurrentProcessId(),
                    (char*)"BehaviorDetection",
                    WDT_Normal, true);
            }
            __finally {
                ExitProcess(-1);
            }
        }

        // 重新启用回调
        *((uintptr_t*)(pTEB + disableOffset)) = 0;
    }

#ifdef _WIN64
    RtlRestoreContext(ctx, NULL);
#endif
}

// -------------------------------------------------------------------
// 公共接口：初始化 / 反初始化
// -------------------------------------------------------------------
BOOL DirectSyscallDetection::Initialize()
{
    if (m_bInitialized)
        return TRUE;

    // 获取必要模块信息
    GetBaseAddresses();
    if (!m_NtdllBase)
        return FALSE;


    // 安装检测钩子
    if (!NT_SUCCESS(SetInstrumentationCallbackHook(NtCurrentProcess(), TRUE)))
    {
        VirtualFree(m_pDisableStub, 0, MEM_RELEASE);
        m_pDisableStub = nullptr;
        return FALSE;
    }

    m_bInitialized = TRUE;
    return TRUE;
}

BOOL DirectSyscallDetection::Uninitialize()
{
#ifdef _WIN64
    const unsigned char g_SSavetub[] = {
        0x50,0x51,0x53,0x55,0x57,0x56,0x54,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,
        0x48,0x83,0xEC,0x20,
        0x48,0x83,0xC4,0x20,
        0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x5C,0x5E,0x5F,0x5D,0x5B,0x59,0x58,
        0x49,0xFF,0xE2
    };
#else
    const unsigned char g_SSavetub[] = {
        0x60,0x9C,0x83,0xEC,0x20,0x83,0xC4,0x20,0x9D,0x61,0xFF,0xE1
    };
#endif

    SIZE_T size = sizeof(g_SSavetub);
    PVOID p = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!p) return FALSE;

    memcpy(p, g_SSavetub, size);
    FlushInstructionCache(GetCurrentProcess(), p, size);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return STATUS_DLL_NOT_FOUND;

    pNtSetInformationProcess NtSetInformationProcess =
        (pNtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (!NtSetInformationProcess) return STATUS_ENTRYPOINT_NOT_FOUND;

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo = { 0 };
    CallbackInfo.Callback = (CallbackFn)p;

    NTSTATUS status = NtSetInformationProcess(
        GetCurrentProcess(),
        ProcessInstrumentationCallback,
        &CallbackInfo,
        sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION)
    );

    if (status != 0) { VirtualFree(p, 0, MEM_RELEASE); return FALSE; }

    return TRUE;
}

DirectSyscallDetection detector;


extern "C" void InstrumentationCallback(
#ifdef _WIN64
    PCONTEXT ctx,
#endif
    uintptr_t ReturnAddress,
    uintptr_t ReturnVal
)
{
#ifdef _WIN64
    detector.InstrumentationCallback(ctx, ReturnAddress, ReturnVal);
#else
	detector.InstrumentationCallback(ReturnAddress, ReturnVal);
#endif
}

// ===========================================================================

// 进程防护区域 ==============================================================

// 子进程防护 =========================================

NTSTATUS calling NewNtCreateUserProcess(
    PHANDLE ProcessHandle,
    PHANDLE ThreadHandle,
    ACCESS_MASK ProcessDesiredAccess,
    ACCESS_MASK ThreadDesiredAccess,
    PCOBJECT_ATTRIBUTES ProcessObjectAttributes,
    PCOBJECT_ATTRIBUTES ThreadObjectAttributes,
    ULONG ProcessFlags,
    ULONG ThreadFlags,
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
    PVOID CreateInfo,
    PPS_ATTRIBUTE_LIST AttributeList
)
{
    if (ProcessParameters && ProcessParameters->ImagePathName.Buffer)
    {
        wstring wsPath(ProcessParameters->ImagePathName.Buffer, ProcessParameters->ImagePathName.MaximumLength);

        // 进入临界区（防止多线程竞争）
        EnterCriticalSection(&CreateCsSync);

        ResetEvent(CreateResponseEvent);  // 重置事件状态
        CreateOperationResult = FALSE;   // 重置结果

        Tran_SendPacket(Tran_Server, (char*)Str_ConvertLPWSTRToLPSTR((LPWSTR)wsPath.c_str()), PTCreateProcessRoutine, (char*)"NtCreateUserProcess", -1);

        // 等待接收线程响应
        DWORD dwWaitResult = WaitForSingleObject(CreateResponseEvent, INFINITE);

        BOOL bResult = (dwWaitResult == WAIT_OBJECT_0) ? CreateOperationResult : FALSE;

        LeaveCriticalSection(&CreateCsSync);

        if (!bResult) return ACCESS_IS_DENIED;
    }

    return OriginalNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes,
        ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
}

NTSTATUS calling NewNtCreateProcessEx(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ParentProcess,
    _In_ ULONG Flags, // PROCESS_CREATE_FLAGS_*
    _In_opt_ HANDLE SectionHandle,
    _In_opt_ HANDLE DebugPort,
    _In_opt_ HANDLE TokenHandle,
    _Reserved_ ULONG Reserved // JobMemberLevel
)
{
    return OriginalNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, TokenHandle, Reserved);
}

// 判断 targetPid 是否是由 parentPid 创建的子进程
static BOOL IsChildProcessOf(DWORD targetPid, DWORD parentPid)
{
    if (targetPid == 0 || parentPid == 0 || !OriginalNtQueryInformationProcess)
        return FALSE;

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
    if (!hProc)
        return FALSE;

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = OriginalNtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    CloseHandle(hProc);

    return NT_SUCCESS(status) && (DWORD)(ULONG_PTR)pbi.InheritedFromUniqueProcessId == parentPid;
}

// 前向声明：DLL 防护模块的路径匹配函数（定义在后方）
static BOOL DllProtPathContainsI(const WCHAR* str, SIZE_T len, const WCHAR* sub);

// 判断目标地址是否位于进程初始化区域（PEB / RTL_USER_PROCESS_PARAMETERS），
// 这些写操作属于 CreateProcess 时的正常初始化，不是注入。
static BOOL IsTargetAddressInProcessInitRegion(DWORD targetPid, PVOID targetAddr)
{
    if (!OriginalNtQueryInformationProcess || !OriginalNtQueryVirtualMemory || targetPid == 0 || !targetAddr)
        return FALSE;

    HANDLE hQuery = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
    if (!hQuery)
        return FALSE;

    BOOL bInit = FALSE;
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG retLen = 0;
    NTSTATUS status = OriginalNtQueryInformationProcess(hQuery, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    if (NT_SUCCESS(status) && pbi.PebBaseAddress)
    {
        MEMORY_BASIC_INFORMATION mbi = {};
        SIZE_T returnLength = 0;
        NTSTATUS queryStatus = OriginalNtQueryVirtualMemory(hQuery, pbi.PebBaseAddress,
            MemoryBasicInformationValue, &mbi, sizeof(mbi), &returnLength);
        if (NT_SUCCESS(queryStatus) && returnLength == sizeof(mbi))
        {
            ULONG_PTR base = (ULONG_PTR)mbi.BaseAddress;
            ULONG_PTR addr = (ULONG_PTR)targetAddr;
            if (addr >= base && addr < base + mbi.RegionSize)
                bInit = TRUE;
        }

        if (!bInit)
        {
#ifdef _WIN64
            const SIZE_T pebOffset = 0x20;
#else
            const SIZE_T pebOffset = 0x10;
#endif
            PVOID processParams = NULL;
            SIZE_T readBytes = 0;
            if (ReadProcessMemory(hQuery, (BYTE*)pbi.PebBaseAddress + pebOffset,
                &processParams, sizeof(processParams), &readBytes) &&
                readBytes == sizeof(processParams) && processParams)
            {
                MEMORY_BASIC_INFORMATION mbiParams = {};
                SIZE_T returnLengthParams = 0;
                NTSTATUS queryStatusParams = OriginalNtQueryVirtualMemory(hQuery, processParams,
                    MemoryBasicInformationValue, &mbiParams, sizeof(mbiParams), &returnLengthParams);
                if (NT_SUCCESS(queryStatusParams) && returnLengthParams == sizeof(mbiParams))
                {
                    ULONG_PTR base = (ULONG_PTR)mbiParams.BaseAddress;
                    ULONG_PTR addr = (ULONG_PTR)targetAddr;
                    if (addr >= base && addr < base + mbiParams.RegionSize)
                        bInit = TRUE;
                }
            }
        }
    }

    CloseHandle(hQuery);
    return bInit;
}

// 判断目标地址所在区域是否已经是可执行内存。
// 注入通常会先写入可读写的私有内存，再改成可执行；
// 而直接写入已有可执行区域的往往是合法补丁/初始化，误报率较高。
static BOOL IsMemoryRegionExecutable(HANDLE hProcess, DWORD targetPid, PVOID addr)
{
    if (!OriginalNtQueryVirtualMemory || !hProcess || !addr || targetPid == 0)
        return FALSE;

    auto DoQuery = [&](HANDLE hProc, MEMORY_BASIC_INFORMATION& mbi) -> BOOL {
        SIZE_T returnLength = 0;
        NTSTATUS status = OriginalNtQueryVirtualMemory(hProc, addr, MemoryBasicInformationValue,
            &mbi, sizeof(mbi), &returnLength);
        return NT_SUCCESS(status) && returnLength == sizeof(mbi);
    };

    MEMORY_BASIC_INFORMATION mbi = {};
    if (!DoQuery(hProcess, mbi))
    {
        HANDLE hQuery = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
        if (!hQuery)
            return FALSE;
        BOOL ok = DoQuery(hQuery, mbi);
        CloseHandle(hQuery);
        if (!ok)
            return FALSE;
    }

    if (mbi.State != MEM_COMMIT)
        return FALSE;

    return (mbi.Protect == PAGE_EXECUTE ||
            mbi.Protect == PAGE_EXECUTE_READ ||
            mbi.Protect == PAGE_EXECUTE_READWRITE ||
            mbi.Protect == PAGE_EXECUTE_WRITECOPY);
}

std::wstring GetProcessPath(HANDLE hProcess)
{
    if (!hProcess) return L"";

    DWORD dwSize = MAX_PATH;
    std::vector<WCHAR> buffer(dwSize);

    while (!QueryFullProcessImageNameW(hProcess, 0, buffer.data(), &dwSize))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return L"";

        // 缓冲区不足，扩大后重试
        buffer.resize(dwSize);
    }

    return std::wstring(buffer.data());
}

NTSTATUS calling NewNtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount)
{
    if (ThreadHandle != NULL)
    {
        // 获取线程所属进程的 ID
        DWORD dwProcessId;
        dwProcessId = GetProcessIdOfThread(ThreadHandle);

        if (dwProcessId != GetCurrentProcessId() && dwProcessId != 0)
        {
            Tran_SendPacket(Tran_Server, (char*)"", PTCreateProcessRoutine, (char*)"", dwProcessId);

            // 进入临界区（防止多线程竞争）
            EnterCriticalSection(&CreateCsSync);

            ResetEvent(CreateResponseEvent);  // 重置事件状态
            CreateOperationResult = FALSE;   // 重置结果

            // 等待接收线程响应
            DWORD dwWaitResult = WaitForSingleObject(CreateResponseEvent, INFINITE);

            BOOL bResult = (dwWaitResult == WAIT_OBJECT_0) ? CreateOperationResult : FALSE;

            LeaveCriticalSection(&CreateCsSync);

            if (bResult == FALSE)
            {
                Suspiciousness += 20;

                if (ThreadHandle) TerminateThread(ThreadHandle, ACCESS_IS_DENIED);

                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

				wstring procPath = GetProcessPath(hProcess);

                if (hProcess)
                {
                    TerminateProcess(hProcess, ACCESS_IS_DENIED);

                    CloseHandle(hProcess);
                }

                if (!isCurrentConsoleProcess)
                {
                    MessageBox(NULL, L"Windows 无法访问指定设备、路径或文件。你可能没有适当权限访问该项目。", procPath.c_str(), MB_TOPMOST | MB_ICONERROR);
                }
                else
                {
                    cout << "拒绝访问。" << endl;
                }

                return ACCESS_IS_DENIED;
            }
            else if (bResult == -1)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

                wstring procPath = GetProcessPath(hProcess);

                if (MessageBox(NULL, L"天宏安全防御对该进程无法兼容。\n单击“确定”以关闭该进程。\n单击“取消”以继续运行不受限制的该进程（不建议）。", procPath.c_str(), MB_TOPMOST | MB_ICONWARNING | MB_YESNO) == IDYES)
                {
                    if (hProcess)
                    {
                        TerminateProcess(hProcess, ACCESS_IS_DENIED);

                        CloseHandle(hProcess);
                    }

                    return ACCESS_IS_DENIED;
                }

                if (hProcess) CloseHandle(hProcess);
            }
        }
    }
    return OriginalNtResumeThread(ThreadHandle, PreviousSuspendCount);
}

NTSTATUS calling NewNtResumeProcess(IN HANDLE ProcessHandle)
{
    return OriginalNtResumeProcess(ProcessHandle);
}

// ====================================================

// 蓝屏防护区域 =======================================


NTSTATUS calling NewNtRaiseHardError(
    _In_ NTSTATUS ErrorStatus,
    _In_ ULONG NumberOfParameters,
    _In_ ULONG UnicodeStringParameterMask,
    _In_reads_(NumberOfParameters) PULONG_PTR Parameters,
    _In_ ULONG ValidResponseOptions,
    _Out_ PULONG Response
)
{
    /* NtRaiseHardError 主要用于显示错误消息框（如 WerFault.exe 错误报告），
     * 仅极少数 ErrorStatus 值可触发蓝屏：
     *   STATUS_FLOAT_MULTIPLE_FAULTS  (0xC00002B5)
     *   STATUS_FLOAT_MULTIPLE_TRAPS   (0xC00002B6)
     * 其他状态码均为正常错误报告，直接放行，避免误报。 */
    if (ErrorStatus != 0xC00002B5 && ErrorStatus != 0xC00002B6) {
        return OriginalNtRaiseHardError(ErrorStatus, NumberOfParameters,
            UnicodeStringParameterMask, Parameters, ValidResponseOptions, Response);
    }

    string sendOut;

    sendOut += "[ADV·恶意拦截] 发现r3层进程试图调用蓝屏！可能会影响用户的运行体验，并且正常r3进程不会调用蓝屏，极有可能是病毒，为了电脑安全，拦截时将直接终止进程！";

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程试图调用蓝屏", GetCurrentProcessId(), (char*)"可疑行为", WDT_Normal, true) <= 0)
    {
        ExitHandleEvent();
        SetLastError(5);
        return ERROR_ACCESS_DENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalNtRaiseHardError(ErrorStatus, NumberOfParameters, UnicodeStringParameterMask, Parameters, ValidResponseOptions, Response);
        }
        else
        {
            ExitHandleEvent();
            SetLastError(5);
            return ERROR_ACCESS_DENIED;
        }
    }
}

NTSTATUS calling NewRtlSetProcessIsCritical(
    _In_ BOOLEAN NewValue,
    _Out_opt_ PBOOLEAN OldValue,
    _In_ BOOLEAN CheckFlag
)
{
    string sendOut;

    sendOut += "[ADV·恶意拦截] 发现r3层进程试图设置关键进程！可能会影响用户的运行体验（该进程关闭后会蓝屏），并且正常r3进程不会设置关键进程，极有可能是病毒，为了电脑安全，拦截时将直接终止进程！";

    Suspiciousness += 100;

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程试图设置关键进程", GetCurrentProcessId(), (char*)"可疑行为", WDT_Normal, true) <= 0)
    {
        ExitHandleEvent();
        SetLastError(5);
        return ERROR_ACCESS_DENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalRtlSetProcessIsCritical(NewValue, OldValue, CheckFlag);
        }
        else
        {
            ExitHandleEvent();
            SetLastError(5);
            return ERROR_ACCESS_DENIED;
        }
    }
}

NTSTATUS calling NewNtSetInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_reads_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength
)
{
    if (ProcessInformationClass == ProcessBreakOnTermination && ProcessInformation)
    {
        if (*(PULONG)ProcessInformation)
        {
            Suspiciousness += 100;
            
            string sendOut;

            sendOut += "[ADV·恶意拦截] 发现r3层进程试图设置关键进程！可能会影响用户的运行体验（该进程关闭后会蓝屏），并且正常r3进程不会设置关键进程，极有可能是病毒，为了电脑安全，拦截时将直接终止进程！";

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程试图设置关键进程", GetCurrentProcessId(), (char*)"可疑行为", WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                SetLastError(5);
                return ERROR_ACCESS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
                }
                else
                {
                    ExitHandleEvent();
                    SetLastError(5);
                    return ERROR_ACCESS_DENIED;
                }
            }
        }
    }
    return OriginalNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
}

// ====================================================

// 驱动加载保护 =======================================

string PrintServiceDetails(SC_HANDLE hService)
{
    string OutPut;
    DWORD bytesNeeded = 0;
    LPQUERY_SERVICE_CONFIGA pServiceConfig = NULL;

    // 首先获取所需缓冲区大小
    QueryServiceConfigA(hService, NULL, 0, &bytesNeeded);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        pServiceConfig = (LPQUERY_SERVICE_CONFIGA)malloc(bytesNeeded);
        if (pServiceConfig && QueryServiceConfigA(hService, pServiceConfig, bytesNeeded, &bytesNeeded))
        {
            // 获取服务状态信息以确定是否是驱动
            SERVICE_STATUS_PROCESS ssp = { 0 };
            DWORD tmpBytesNeeded = 0;

            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &tmpBytesNeeded))
            {
                if (ssp.dwServiceType == SERVICE_KERNEL_DRIVER || ssp.dwServiceType == SERVICE_FILE_SYSTEM_DRIVER)
                {
                    // 输出驱动服务信息
                    OutPut += "服务名: " + (string)pServiceConfig->lpDisplayName;
                    OutPut += "\r\n驱动路径: " + ((string)pServiceConfig->lpBinaryPathName).substr(4);
                    OutPut += "\r\n驱动类型: " + (string)((ssp.dwServiceType == SERVICE_KERNEL_DRIVER) ? "Kernel Driver 内核驱动" : "File System Driver 文件系统驱动");
                    OutPut += "\r\n启动类型: " + (string)(
                        pServiceConfig->dwStartType == SERVICE_BOOT_START ? "Boot Start 引导启动" :
                        pServiceConfig->dwStartType == SERVICE_SYSTEM_START ? "System Start 系统启动" :
                        pServiceConfig->dwStartType == SERVICE_AUTO_START ? "Auto Start 自动启动" :
                        pServiceConfig->dwStartType == SERVICE_DEMAND_START ? "Demand Start 按需启动" : "Disabled 已禁用");

                    return OutPut;
                }
            }
        }
        free(pServiceConfig);
    }

    return "";
}

BOOL NewStartServiceW(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCWSTR* lpServiceArgVectors)
{
    BOOL bIsDriver = FALSE;
    WCHAR szServiceName[256] = L"";
    LPQUERY_SERVICE_CONFIGW lpConfig = NULL;
    DWORD dwBytesNeeded = 0;

    // 直接从服务配置获取服务名称和服务类型
    QueryServiceConfigW(hService, NULL, 0, &dwBytesNeeded);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        lpConfig = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            dwBytesNeeded);
        if (lpConfig)
        {
            if (QueryServiceConfigW(hService, lpConfig, dwBytesNeeded, &dwBytesNeeded))
            {
                // 服务名称
                if (lpConfig->lpDisplayName)
                    wcscpy_s(szServiceName, _countof(szServiceName), lpConfig->lpDisplayName);

                // 判断是否是驱动
                bIsDriver = (lpConfig->dwServiceType == SERVICE_KERNEL_DRIVER ||
                    lpConfig->dwServiceType == SERVICE_FILE_SYSTEM_DRIVER);
            }
            HeapFree(GetProcessHeap(), 0, lpConfig);
        }
    }

    // 如果是驱动加载，进行安全检测
    if (bIsDriver)
    {
        // 构造详细信息
        std::wstring details = L"[驱动防护·加载] 进程正在尝试加载驱动程序\r\n";
        details += L"服务名称: " + std::wstring(szServiceName) + L"\r\n";

        // 获取驱动文件路径（需要额外查询）
        LPQUERY_SERVICE_CONFIGW lpFullConfig = NULL;
        if (QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytesNeeded) ||
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            lpFullConfig = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                dwBytesNeeded);
            if (lpFullConfig)
            {
                if (QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION,
                    (LPBYTE)lpFullConfig, dwBytesNeeded, &dwBytesNeeded))
                {
                    details += L"驱动路径: " + std::wstring(lpFullConfig->lpBinaryPathName) + L"\r\n";
                }
                HeapFree(GetProcessHeap(), 0, lpFullConfig);
            }
        }

        // 发送安全检测请求
        EnterHandleEvent();

        int nRet = Tran_OrgSendPacket(Tran_Server,
            (char*)details.c_str(),
            PTVirusOperationConfirm,
            (char*)"发现进程试图加载驱动程序，建议拦截",
            GetCurrentProcessId(),
            (char*)"驱动保护");

        if (nRet <= 0 || !WaitForResult())
        {
            // 用户选择拦截或通讯失败
            ExitHandleEvent();
            SetLastError(ERROR_ACCESS_DENIED);  // 5
            return FALSE;
        }

        ExitHandleEvent();
        // 用户允许，继续执行
    }

    return OriginalStartServiceW(hService, dwNumServiceArgs, lpServiceArgVectors);
}

BOOL NewStartServiceA(
    SC_HANDLE hService,
    DWORD dwNumServiceArgs,
    LPCSTR* lpServiceArgVectors)
{
    BOOL bIsDriver = FALSE;
    WCHAR szServiceName[256] = L"";
    LPQUERY_SERVICE_CONFIGW lpConfig = NULL;
    DWORD dwBytesNeeded = 0;

    // 直接从服务配置获取服务名称和服务类型
    QueryServiceConfigW(hService, NULL, 0, &dwBytesNeeded);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        lpConfig = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),
            HEAP_ZERO_MEMORY,
            dwBytesNeeded);
        if (lpConfig)
        {
            if (QueryServiceConfigW(hService, lpConfig, dwBytesNeeded, &dwBytesNeeded))
            {
                // 服务名称
                if (lpConfig->lpDisplayName)
                    wcscpy_s(szServiceName, _countof(szServiceName), lpConfig->lpDisplayName);

                // 判断是否是驱动
                bIsDriver = (lpConfig->dwServiceType == SERVICE_KERNEL_DRIVER ||
                    lpConfig->dwServiceType == SERVICE_FILE_SYSTEM_DRIVER);
            }
            HeapFree(GetProcessHeap(), 0, lpConfig);
        }
    }

    // 如果是驱动加载，进行安全检测
    if (bIsDriver)
    {
        // 构造详细信息
        std::wstring details = L"[驱动防护·加载] 进程正在尝试加载驱动程序\r\n";
        details += L"服务名称: " + std::wstring(szServiceName) + L"\r\n";

        // 获取驱动文件路径（需要额外查询）
        LPQUERY_SERVICE_CONFIGW lpFullConfig = NULL;
        if (QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &dwBytesNeeded) ||
            GetLastError() == ERROR_INSUFFICIENT_BUFFER)
        {
            lpFullConfig = (LPQUERY_SERVICE_CONFIGW)HeapAlloc(GetProcessHeap(),
                HEAP_ZERO_MEMORY,
                dwBytesNeeded);
            if (lpFullConfig)
            {
                if (QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION,
                    (LPBYTE)lpFullConfig, dwBytesNeeded, &dwBytesNeeded))
                {
                    details += L"驱动路径: " + std::wstring(lpFullConfig->lpBinaryPathName) + L"\r\n";
                }
                HeapFree(GetProcessHeap(), 0, lpFullConfig);
            }
        }

        // 发送安全检测请求
        EnterHandleEvent();

        int nRet = Tran_OrgSendPacket(Tran_Server,
            (char*)details.c_str(),
            PTVirusOperationConfirm,
            (char*)"发现进程试图加载驱动程序，建议拦截",
            GetCurrentProcessId(),
            (char*)"驱动保护");

        if (nRet <= 0 || !WaitForResult())
        {
            // 用户选择拦截或通讯失败
            ExitHandleEvent();
            SetLastError(ERROR_ACCESS_DENIED);  // 5
            return FALSE;
        }

        ExitHandleEvent();
        // 用户允许，继续执行
    }

    return OriginalStartServiceA(hService, dwNumServiceArgs, lpServiceArgVectors);
}

NTSTATUS calling NewZwLoadDriver(PUNICODE_STRING DriverServicePath)
{
    string sendOut;
    char DriverPath[512] = { 0 };
    char DriverName[256] = { 0 };
    WCHAR ImagePath[512] = { 0 };

    // 获取驱动服务名称
    if (DriverServicePath && DriverServicePath->Buffer)
    {
        wstring RegPath = Str_PUNICODE_STRINGToWString(DriverServicePath);

        // 转换为注册表路径格式
        if (wcsncmp(RegPath.c_str(), L"\\Registry\\Machine\\", 18) == 0)
        {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, RegPath.substr(18).c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD Size = sizeof(ImagePath);
                DWORD Type;
                if (RegQueryValueExW(hKey, L"ImagePath", NULL, &Type, (LPBYTE)ImagePath, &Size) == ERROR_SUCCESS)
                {
                    // 构建警告信息
                    sendOut += "[驱动防护·加载] 发现进程试图加载驱动程序！";
                    sendOut += "\r\n试图加载驱动路径：";
                    sendOut += Str_ConvertLPWSTRToLPSTR(ImagePath);
                }
                else
                {
                    sendOut += "[驱动防护·加载] 发现进程试图加载驱动程序！\r\n无法读取驱动路径";
                }
                RegCloseKey(hKey);

                Suspiciousness += 60;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(),
                    PTVirusOperationConfirm,
                    (char*)"发现可疑进程试图加载驱动程序",
                    GetCurrentProcessId(),
                    (char*)"驱动防护",
                    WDT_Normal, true) <= 0)
                {
                    ExitHandleEvent();
                    SetLastError(5);
                    return ERROR_ACCESS_DENIED;
                }
                else
                {
                    if (WaitForResult())
                    {
                        ExitHandleEvent();
                    }
                    else
                    {
                        ExitHandleEvent();
                        return ERROR_ACCESS_DENIED;
                    }
                }
            }
        }
    }

    return OriginalZwLoadDriver(DriverServicePath);
}

NTSTATUS calling NewZwSetSystemInformation(ULONG InfoClass, PVOID Info, ULONG Length)
{
    // 只监控驱动加载请求
    if (InfoClass == 38 && Info != NULL) // SystemExtendServiceTableInformation,                    // s: (requires SeLoadDriverPrivilege) // loads win32k only
    {
        PSYSTEM_LOAD_AND_CALL_IMAGE pLoadImage = (PSYSTEM_LOAD_AND_CALL_IMAGE)Info;

        // 获取驱动路径
        if (pLoadImage->ModuleName.Buffer)
        {
            string sendOut;
            wstring DriverPath(pLoadImage->ModuleName.Buffer, pLoadImage->ModuleName.Length / sizeof(wchar_t));

            // 构建警告信息（带具体路径）
            sendOut += "[驱动防护·加载] 发现进程试图通过SystemInformation加载驱动！\r\n";
            sendOut += "试图加载的驱动路径: ";
            sendOut += Str_ConvertLPWSTRToLPSTR((LPWSTR)DriverPath.c_str());

            Suspiciousness += 75;

            EnterHandleEvent();

            // 发送给服务器确认
            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(),
                PTVirusOperationConfirm,
                (char*)"发现可疑进程试图加载驱动",
                GetCurrentProcessId(),
                (char*)"驱动防护",
                WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                SetLastError(5);
                return ERROR_ACCESS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                }
                else
                {
                    ExitHandleEvent();
                    return ERROR_ACCESS_DENIED;
                }
            }
        }
    }

    // 如果不是驱动加载请求，直接放行
    return OriginalZwSetSystemInformation(InfoClass, Info, Length);
}


// ====================================================

// 自我保护 ===========================================

void WaitForPidProtection()
{
    // 临时方案：降低轮询频率以减少上下文切换（建议后续改为事件通知）
    while (ProtectionReadyCount < 2) Sleep(100);
}

BOOL IsProtectProcess(int pid)
{
    if (MainProcessPid == pid) return TRUE;
    if (InjectorPid == pid) return TRUE;

    return FALSE;
}

NTSTATUS calling NewPspTerminateThreadByPointer(HANDLE Thread, NTSTATUS ExitStatus, BOOLEAN DirectTerminate)
{
    WaitForPidProtection();

    if (!IsProtectProcess(GetProcessIdOfThread(Thread)))
    {
        return OriginalPspTerminateThreadByPointer(Thread, ExitStatus, DirectTerminate);
    }
    else
    {
        return ACCESS_IS_DENIED;
    }
}

NTSTATUS calling NewPspTerminateProcess(HANDLE Process, NTSTATUS ExitStatus)
{
    WaitForPidProtection();

    if (!IsProtectProcess(GetProcessId(Process)))
    {
        return OriginalPspTerminateProcess(Process, ExitStatus);
    }
    else
    {
        return ACCESS_IS_DENIED;
    }
}

NTSTATUS calling NewNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
    if (ProcessHandle != NULL)
    {
        WaitForPidProtection();

        if (IsProtectProcess(GetProcessId(ProcessHandle)))
        {
            return ACCESS_IS_DENIED;
        }
    }

    return OriginalNtTerminateProcess(ProcessHandle, ExitStatus);
}

NTSTATUS calling NewNtDebugActiveProcess(
    HANDLE ProcessHandle,
    HANDLE DebugObjectHandle
)
{
    WaitForPidProtection();

    if (!IsProtectProcess(GetProcessId(ProcessHandle)))
    {
        return OriginalNtDebugActiveProcess(ProcessHandle, DebugObjectHandle);
    }
    else
    {
        return ACCESS_IS_DENIED;
    }
}

BOOL NewWinStationTerminateProcess(HANDLE hServer, DWORD ProcessId, DWORD ExitCode)
{
    WaitForPidProtection();

    if (!IsProtectProcess(ProcessId))
    {
        return OriginalWinStationTerminateProcess(hServer, ProcessId, ExitCode);
    }
    else
    {
        SetLastError(5);
        return FALSE;
    }
}

NTSTATUS calling NewNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
)
{
    WaitForPidProtection();

    if (IsProtectProcess((DWORD)(ULONG_PTR)ClientId->UniqueProcess))
    {
        ProcessHandle = NULL;
        return ACCESS_IS_DENIED;
    }
    else
    {
        return OriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
}

// ====================================================

// 远程注入防护区域 ===================================

// 拦截远程线程注入
NTSTATUS calling NewNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
)
{
    // 获取当前进程ID
    DWORD currentPid = GetCurrentProcessId();

    // 获取目标进程ID
    DWORD targetPid = GetProcessId(ProcessHandle);

    // 如果尝试在其他进程创建线程，则阻止
    if (currentPid != targetPid && targetPid != 0 && ProcessHandle)
    {
        Suspiciousness += 100;

        string sendOut;

        sendOut += "[ADV·恶意拦截] 发现进程试图远程线程注入！可能会绕过防护，拦截时将直接终止进程！";

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程试图远程线程注入", GetCurrentProcessId(), (char*)"内存防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    // 正常调用原始函数
    return OriginalNtCreateThreadEx(
        ThreadHandle,
        DesiredAccess,
        ObjectAttributes,
        ProcessHandle,
        StartRoutine,
        Argument,
        CreateFlags,
        ZeroBits,
        StackSize,
        MaximumStackSize,
        AttributeList
    );
}

// 拦截内存映射注入
NTSTATUS calling NewNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Win32Protect)
{
    DWORD currentPid = GetCurrentProcessId();
    DWORD targetPid = GetProcessId(ProcessHandle);

    if (currentPid != targetPid && targetPid != 0 && ProcessHandle)
    {
        Suspiciousness += 100;

        string sendOut;

        sendOut += "[ADV·恶意拦截] 发现进程试图远程线程注入（通过跨进程内存映射）！可能会绕过防护，拦截时将直接终止进程！";

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程试图远程线程注入", GetCurrentProcessId(), (char*)"内存防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    return OriginalNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Win32Protect);
}

static BOOL DllProtVerifyAuthenticode(const WCHAR* filePath);

// 拦截远程内存保护属性修改为可执行（Process Hollowing / shellcode 典型行为）
NTSTATUS calling NewNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
)
{
    DWORD currentPid = GetCurrentProcessId();
    DWORD targetPid = GetProcessId(ProcessHandle);

    if (currentPid != 0 && targetPid != 0 && currentPid != targetPid && ProcessHandle != NULL)
    {
        if (!OriginalNtQueryVirtualMemory)
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        MEMORY_BASIC_INFORMATION mbi;
        NTSTATUS queryStatus = OriginalNtQueryVirtualMemory(
            ProcessHandle,
            *BaseAddress,
            MemoryBasicInformationValue,
            &mbi,
            sizeof(mbi),
            NULL
        );

        if (!NT_SUCCESS(queryStatus))
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        if (IsTargetAddressInProcessInitRegion(targetPid, *BaseAddress))
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        BOOL wasExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        BOOL isNowExecutable = (NewProtect == PAGE_EXECUTE ||
            NewProtect == PAGE_EXECUTE_READ ||
            NewProtect == PAGE_EXECUTE_READWRITE ||
            NewProtect == PAGE_EXECUTE_WRITECOPY);

        if (!wasExecutable && isNowExecutable)
        {
            Suspiciousness += 80;

            char msg[256];
            sprintf_s(msg, sizeof(msg),
                "[ADV·内存防护] 检测到试图注入远程进程 PID=%lu ！",
                targetPid);

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, msg, PTVirusOperationConfirm,
                (char*)"检测到注入远程进程", GetCurrentProcessId(), (char*)"内存防护", WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
                }
                else
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
            }
        }
    }

    /* 自身内存保护改为可执行（shellcode 执行/载荷解密）
     * 检测策略（参考内核 BehaviorAnalysis.c + 精确条件）：
     *   1) 排除 PE 镜像段（MEM_IMAGE）
     *   2) 仅关注堆/栈私有内存（MEM_PRIVATE + MEM_COMMIT）
     *   3) 精确匹配 RW→X 特征：旧权限可写、旧不可执行、新可执行、新不可写
     */
    if (currentPid != 0 && targetPid != 0 && currentPid == targetPid && ProcessHandle != NULL)
    {
        if (!OriginalNtQueryVirtualMemory)
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        MEMORY_BASIC_INFORMATION mbi;
        NTSTATUS queryStatus = OriginalNtQueryVirtualMemory(
            ProcessHandle,
            *BaseAddress,
            MemoryBasicInformationValue,
            &mbi,
            sizeof(mbi),
            NULL
        );

        if (!NT_SUCCESS(queryStatus))
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        /* 排除 PE 镜像段（.text 段由加载器设为 RX） */
        if (mbi.Type == MEM_IMAGE)
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        /* 仅关注本进程动态内存（私有、已提交） */
        if (!(mbi.Type == MEM_PRIVATE && mbi.State == MEM_COMMIT))
        {
            return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
        }

        DWORD oldProtect = mbi.Protect;
        bool oldWritable  = (oldProtect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        bool oldExecutable = (oldProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        bool newExecutable = (NewProtect == PAGE_EXECUTE || NewProtect == PAGE_EXECUTE_READ ||
                              NewProtect == PAGE_EXECUTE_READWRITE || NewProtect == PAGE_EXECUTE_WRITECOPY);
        bool newWritable   = (NewProtect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

        /* 精确匹配 RW → X 特征：原可写、原不可执行、新可执行、新不可写 */
        if (oldWritable && !oldExecutable && newExecutable && !newWritable)
        {
            Suspiciousness += 50;

            /* === 1. 仅检测未签名进程，降低误报（提前短路，避免无意义的调用栈回溯开销） === */
            if (g_CurrentProcessSigned == 1)
            {
                return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
            }

            /* === 2. 调用栈回溯：定位触发源 caller === */
            char callerModule[260] = "(no caller)";
            {
                void* stack[16];
                USHORT frames = CaptureStackBackTrace(2, 16, stack, NULL);
                if (frames > 0)
                {
                    static HMODULE hDbgHelp = NULL;
                    static BOOL (WINAPI *pfnSymInitialize)(HANDLE, PCSTR, BOOL) = NULL;
                    static BOOL (WINAPI *pfnSymFromAddr)(HANDLE, DWORD64, PULONG64, PSYMBOL_INFO) = NULL;
                    if (!hDbgHelp)
                    {
                        hDbgHelp = LoadLibraryA("dbghelp.dll");
                        if (hDbgHelp)
                        {
                            pfnSymInitialize = (BOOL (WINAPI *)(HANDLE, PCSTR, BOOL))GetProcAddress(hDbgHelp, "SymInitializeA");
                            pfnSymFromAddr   = (BOOL (WINAPI *)(HANDLE, DWORD64, PULONG64, PSYMBOL_INFO))GetProcAddress(hDbgHelp, "SymFromAddrA");
                        }
                    }
                    if (pfnSymInitialize && pfnSymFromAddr)
                    {
                        pfnSymInitialize(GetCurrentProcess(), NULL, TRUE);
                        SYMBOL_INFO* pSym = (SYMBOL_INFO*)calloc(1, sizeof(SYMBOL_INFO) + 256);
                        if (pSym)
                        {
                            pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
                            pSym->MaxNameLen   = 255;
                            DWORD64 displacement = 0;
                            if (pfnSymFromAddr(GetCurrentProcess(), (DWORD64)stack[0], &displacement, pSym))
                            {
                                snprintf(callerModule, sizeof(callerModule), "%s!+0x%llx", pSym->Name, (unsigned long long)displacement);
                            }
                            else
                            {
                                snprintf(callerModule, sizeof(callerModule), "addr=0x%p", stack[0]);
                            }
                            free(pSym);
                        }
                        pfnSymInitialize(GetCurrentProcess(), NULL, FALSE);
                    }
                }
            }

            /* === 3. 查询所在模块名 === */
            char moduleName[260] = "(无)";
            {
                static BOOL (WINAPI *pfnEnumModules)(HANDLE, HMODULE*, DWORD, LPDWORD) = NULL;
                static BOOL initDone = FALSE;
                if (!initDone)
                {
                    HMODULE hPsapi = GetModuleHandleW(L"psapi.dll");
                    if (hPsapi)
                        pfnEnumModules = (BOOL (WINAPI *)(HANDLE, HMODULE*, DWORD, LPDWORD))GetProcAddress(hPsapi, "EnumProcessModules");
                    initDone = TRUE;
                }
                if (pfnEnumModules)
                {
                    HMODULE hMods[1024];
                    DWORD cbNeeded = 0;
                    if (pfnEnumModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
                    {
                        DWORD moduleCount = cbNeeded / sizeof(HMODULE);
                        ULONG_PTR addr = (ULONG_PTR)*BaseAddress;
                        for (DWORD i = 0; i < moduleCount; i++)
                        {
                            MODULEINFO mi = {0};
                            if (GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi)))
                            {
                                ULONG_PTR base = (ULONG_PTR)mi.lpBaseOfDll;
                                ULONG_PTR end  = base + mi.SizeOfImage;
                                if (addr >= base && addr < end)
                                {
                                    GetModuleBaseNameA(GetCurrentProcess(), hMods[i], moduleName, sizeof(moduleName));
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            char msg[900];
            sprintf_s(msg, sizeof(msg),
                "[ADV·内存防护] PID=%lu Caller=%s | 堆/栈→RX | Addr=0x%p Size=%llu | Old=0x%X(%s) New=0x%X(%s) | Type=0x%X(%s) State=0x%X(%s) | AllocBase=0x%p AllocProtect=0x%X(%s) | Module=%s | Susp=%d",
                currentPid, callerModule, *BaseAddress, (unsigned long long)mbi.RegionSize,
                oldProtect,
                (oldProtect == PAGE_READWRITE ? "RW" :
                 oldProtect == PAGE_EXECUTE_READWRITE ? "RWX" :
                 oldProtect == PAGE_EXECUTE_READ ? "RX" :
                 oldProtect == PAGE_READONLY ? "R" :
                 oldProtect == PAGE_NOACCESS ? "NOACC" : "OTHER"),
                NewProtect,
                (NewProtect == PAGE_EXECUTE_READ ? "RX" :
                 NewProtect == PAGE_EXECUTE_READWRITE ? "RWX" :
                 NewProtect == PAGE_EXECUTE ? "X" :
                 NewProtect == PAGE_READONLY ? "R" :
                 NewProtect == PAGE_NOACCESS ? "NOACC" : "OTHER"),
                mbi.Type,
                (mbi.Type == MEM_PRIVATE ? "PRIVATE" :
                 mbi.Type == MEM_MAPPED ? "MAPPED" :
                 mbi.Type == MEM_IMAGE ? "IMAGE" : "UNKNOWN"),
                mbi.State,
                (mbi.State == MEM_COMMIT ? "COMMIT" :
                 mbi.State == MEM_RESERVE ? "RESERVE" : "FREE"),
                mbi.AllocationBase,
                mbi.AllocationProtect,
                (mbi.AllocationProtect == PAGE_READWRITE ? "RW" :
                 mbi.AllocationProtect == PAGE_EXECUTE_READWRITE ? "RWX" :
                 mbi.AllocationProtect == PAGE_EXECUTE_READ ? "RX" : "OTHER"),
                moduleName,
                Suspiciousness);

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, msg, PTVirusOperationConfirm,
                (char*)"检测到自身内存改为可执行", GetCurrentProcessId(), (char*)"内存防护", WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
                }
                else
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
            }
        }
    }

    return OriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

// 拦截远程进程内存写入（跨进程 WriteProcessMemory / NtWriteVirtualMemory）
NTSTATUS calling NewNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T BufferSize,
    PSIZE_T NumberOfBytesWritten
)
{
    DWORD currentPid = GetCurrentProcessId();
    DWORD targetPid = GetProcessId(ProcessHandle);

    if (currentPid != 0 && targetPid != 0 && currentPid != targetPid && ProcessHandle != NULL && BufferSize > 0)
    {
        // 获取目标内存保护属性
        MEMORY_BASIC_INFORMATION mbi = { 0 };
        if (OriginalNtQueryVirtualMemory)
        {
            NTSTATUS status = OriginalNtQueryVirtualMemory(
                ProcessHandle,
                BaseAddress,
                MemoryBasicInformationValue,
                &mbi,
                sizeof(mbi),
                NULL
            );
            if (!NT_SUCCESS(status))
            {
                return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
            }
        }
        else
        {
            return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }

        // 只在写入目标是 PAGE_EXECUTE_READWRITE 时才拦截（最典型的恶意可执行内存）
        if (mbi.Protect != PAGE_EXECUTE_READWRITE)
        {
            return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }

        // 跳过进程初始化阶段对 PEB / ProcessParameters 的正常写入
        if (IsTargetAddressInProcessInitRegion(targetPid, BaseAddress))
        {
            return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }

        Suspiciousness += 60;

        // 获取注入进程（当前进程）路径
        char currentPath[MAX_PATH] = { 0 };
        HANDLE hCurrent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, currentPid);
        if (hCurrent)
        {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameA(hCurrent, 0, currentPath, &size);
            CloseHandle(hCurrent);
        }

        // 获取被注入进程（目标进程）路径
        char targetPath[MAX_PATH] = { 0 };
        HANDLE hTarget = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetPid);
        if (hTarget)
        {
            DWORD size = MAX_PATH;
            QueryFullProcessImageNameA(hTarget, 0, targetPath, &size);
            CloseHandle(hTarget);
        }

        // 同镜像进程间内存写入放行（如 msedge.exe -> msedge.exe 多进程架构内部通信）
        if (currentPath[0] != '\0' && targetPath[0] != '\0' &&
            _stricmp(currentPath, targetPath) == 0)
        {
            return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }

        char msg[512];
        sprintf_s(msg, sizeof(msg),
            "[ADV·内存防护] 进程 %s (PID=%lu) 向远程进程 %s (PID=%lu) 的 EXECUTE_READWRITE 内存 (0x%p, 大小=%zu) 写入数据，疑似 shellcode 注入！",
            currentPath[0] ? currentPath : "Unknown",
            currentPid,
            targetPath[0] ? targetPath : "Unknown",
            targetPid,
            BaseAddress,
            BufferSize);

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, msg, PTVirusOperationConfirm,
            (char*)"检测到远程进程内存写入到可执行内存", GetCurrentProcessId(), (char*)"内存防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    return OriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

// ====================================================

// DLL 侧载防护区域 ===================================
// 目标：高置信度场景下拦截“已签名进程加载无签名/无效签名 DLL”的 DLL 侧载攻击。
// 设计原则：
//   1. 当前进程签名状态在 InitT 中预计算并缓存，避免重复做 WinVerifyTrust。
//   2. DLL 签名状态先通过轻量级 PE 证书目录预筛，再用 WinVerifyTrust 验证有效性；带缓存减少开销。
//   3. 使用基于线程 ID 的重入保护，防止 WinVerifyTrust 递归加载 DLL 时造成无限递归或死锁。
//   4. 仅对高风险路径（临时目录、下载、桌面、当前进程同目录）做检查，系统目录快速放行。

// DLL 签名验证缓存（固定大小、无锁、避免堆分配）
#define DLL_SIG_CACHE_SIZE 64
struct DLL_SIG_CACHE_ENTRY
{
    WCHAR Path[260];
    LONG Signed; // 0 无签名, 1 有签名
    ULONG Hash;
    BOOL Valid;
};
static DLL_SIG_CACHE_ENTRY g_DllSigCache[DLL_SIG_CACHE_SIZE] = { 0 };

// LdrLoadDll 钩子重入保护：记录当前已进入钩子的线程 ID，遇到递归时直接放行
#define DLL_LOAD_HOOK_MAX_THREADS 16
static volatile DWORD g_DllLoadHookActiveThreads[DLL_LOAD_HOOK_MAX_THREADS] = { 0 };

static BOOL DllProtEnterHook()
{
    DWORD tid = GetCurrentThreadId();
    for (int i = 0; i < DLL_LOAD_HOOK_MAX_THREADS; i++)
    {
        if (InterlockedCompareExchange((LONG*)&g_DllLoadHookActiveThreads[i], (LONG)tid, 0) == 0)
            return TRUE;
    }
    // 槽位已满，保守放行，避免阻塞加载
    return FALSE;
}

static void DllProtLeaveHook()
{
    DWORD tid = GetCurrentThreadId();
    for (int i = 0; i < DLL_LOAD_HOOK_MAX_THREADS; i++)
    {
        if (g_DllLoadHookActiveThreads[i] == tid)
        {
            InterlockedExchange((LONG*)&g_DllLoadHookActiveThreads[i], 0);
            return;
        }
    }
}

static BOOL DllProtIsRecursiveHook()
{
    DWORD tid = GetCurrentThreadId();
    for (int i = 0; i < DLL_LOAD_HOOK_MAX_THREADS; i++)
    {
        if (g_DllLoadHookActiveThreads[i] == tid)
            return TRUE;
    }
    return FALSE;
}

// 宽字符小写（仅 ASCII 范围，路径判断足够）
static WCHAR DllProtLowerW(WCHAR c)
{
    if (c >= L'A' && c <= L'Z') return c + (L'a' - L'A');
    return c;
}

// 不依赖 CRT/堆的宽字符串后缀匹配
static BOOL DllProtEndWithI(const WCHAR* str, SIZE_T len, const WCHAR* suffix)
{
    SIZE_T suffixLen = 0;
    while (suffix[suffixLen]) suffixLen++;
    if (len < suffixLen) return FALSE;
    for (SIZE_T i = 0; i < suffixLen; i++)
    {
        if (DllProtLowerW(str[len - suffixLen + i]) != DllProtLowerW(suffix[i]))
            return FALSE;
    }
    return TRUE;
}

// 路径包含子串（大小写不敏感）
static BOOL DllProtPathContainsI(const WCHAR* str, SIZE_T len, const WCHAR* sub)
{
    SIZE_T subLen = 0;
    while (sub[subLen]) subLen++;
    if (subLen == 0 || len < subLen) return FALSE;
    for (SIZE_T i = 0; i <= len - subLen; i++)
    {
        BOOL match = TRUE;
        for (SIZE_T j = 0; j < subLen; j++)
        {
            if (DllProtLowerW(str[i + j]) != DllProtLowerW(sub[j]))
            {
                match = FALSE;
                break;
            }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// 计算宽字符串哈希（djb2，小写）
static ULONG DllProtHashW(const WCHAR* s, SIZE_T len)
{
    ULONG h = 5381;
    for (SIZE_T i = 0; i < len; i++)
        h = ((h << 5) + h) + (ULONG)DllProtLowerW(s[i]);
    return h;
}

// 使用 WinVerifyTrust 验证文件 Authenticode 签名（仅在非 loader lock 线程中调用）
static BOOL DllProtVerifyAuthenticode(const WCHAR* filePath)
{
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(trustData);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_SAFER_FLAG;
    trustData.dwUIContext = 0;

    LONG status = WinVerifyTrust(NULL, &actionGuid, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &trustData);

    return status == ERROR_SUCCESS;
}

// 轻量级 PE 证书目录检查：判断文件是否包含签名数据（不验证有效性，但可快速识别无签名 DLL）
static BOOL DllProtHasPeCertificate(const WCHAR* filePath)
{
    // 在文件保护列表就绪前跳过，避免经过 NtCreateFile 钩子产生自旋/死锁
    if (!isProtectionFileReady) return TRUE;

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return TRUE; // 无法确认时保守放行

    BOOL hasCert = FALSE;
    BYTE dosHdr[64] = { 0 };
    DWORD read = 0;
    if (ReadFile(hFile, dosHdr, sizeof(dosHdr), &read, NULL) && read >= sizeof(IMAGE_DOS_HEADER))
    {
        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)dosHdr;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            BYTE ntHdr[512] = { 0 };
            SetFilePointer(hFile, pDos->e_lfanew, NULL, FILE_BEGIN);
            if (ReadFile(hFile, ntHdr, sizeof(ntHdr), &read, NULL))
            {
                PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)ntHdr;
                if (pNt->Signature == IMAGE_NT_SIGNATURE &&
                    pNt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
                {
                    DWORD certVa = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
                    DWORD certSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
                    hasCert = (certVa != 0 && certSize != 0);
                }
            }
        }
    }
    CloseHandle(hFile);
    return hasCert;
}

// 从缓存或重新检测 DLL 是否经过有效签名
static BOOL DllProtIsDllSignedFast(const WCHAR* path, SIZE_T len)
{
    ULONG hash = DllProtHashW(path, len);
    SIZE_T idx = hash % DLL_SIG_CACHE_SIZE;

    // 检查缓存命中（允许偶发 race，不影响稳定性）
    DLL_SIG_CACHE_ENTRY* entry = &g_DllSigCache[idx];
    if (entry->Valid && entry->Hash == hash)
    {
        BOOL match = TRUE;
        for (SIZE_T i = 0; i < len && i < 259; i++)
        {
            if (DllProtLowerW(entry->Path[i]) != DllProtLowerW(path[i]))
            {
                match = FALSE;
                break;
            }
        }
        if (match) return entry->Signed == 1;
    }

    // 先通过 PE 证书目录快速排除无签名文件，避免不必要地调用 WinVerifyTrust
    BOOL isSigned = FALSE;
    if (DllProtHasPeCertificate(path))
    {
        // 有证书数据时，进一步验证签名的有效性
        isSigned = DllProtVerifyAuthenticode(path);
    }

    // 更新缓存
    entry->Hash = hash;
    for (SIZE_T i = 0; i < len && i < 259; i++) entry->Path[i] = path[i];
    entry->Path[len < 259 ? len : 259] = L'\0';
    entry->Signed = isSigned ? 1 : 0;
    entry->Valid = TRUE;

    return isSigned;
}

// 判断 DLL 路径是否属于低风险/可信目录
static BOOL DllProtIsTrustedLocation(const WCHAR* path, SIZE_T len)
{
    if (DllProtEndWithI(path, len, L"\\system32\\") ||
        DllProtEndWithI(path, len, L"\\syswow64\\") ||
        DllProtEndWithI(path, len, L"\\winsxs\\") ||
        DllProtPathContainsI(path, len, L"\\microsoft\\windows\\") ||
        DllProtPathContainsI(path, len, L"\\microsoft shared\\"))
        return TRUE;
    return FALSE;
}

// 判断是否为高风险的侧载路径
static BOOL DllProtIsHighRiskSideLoadPath(const WCHAR* path, SIZE_T len)
{
    if (DllProtPathContainsI(path, len, L"\\temp\\") ||
        DllProtPathContainsI(path, len, L"\\tmp\\") ||
        DllProtPathContainsI(path, len, L"\\downloads\\") ||
        DllProtPathContainsI(path, len, L"\\desktop\\") ||
        DllProtPathContainsI(path, len, L"\\appdata\\local\\temp\\"))
        return TRUE;
    return FALSE;
}

// 判断 DLL 是否与当前进程在同一目录（常见 DLL 侧载场景）
static BOOL DllProtIsSameDirAsExe(const WCHAR* dllPath, SIZE_T dllLen)
{
    WCHAR exePath[MAX_PATH] = { 0 };
    DWORD exeLen = GetModuleFileNameW(NULL, exePath, MAX_PATH);
    if (exeLen == 0 || exeLen >= MAX_PATH) return FALSE;

    // 找到 exe 目录末尾（包含反斜杠）
    SIZE_T exeDirLen = 0;
    for (SIZE_T i = 0; i < exeLen; i++)
    {
        if (exePath[i] == L'\\' || exePath[i] == L'/')
            exeDirLen = i + 1;
    }
    if (exeDirLen == 0) return FALSE;
    if (dllLen < exeDirLen) return FALSE;

    for (SIZE_T i = 0; i < exeDirLen; i++)
    {
        if (DllProtLowerW(dllPath[i]) != DllProtLowerW(exePath[i]))
            return FALSE;
    }
    return TRUE;
}

// 判断某个 DLL 文件名是否在 system32 中存在同名系统 DLL（典型 DLL 侧载/劫持指标）
static BOOL DllProtSystem32HasSameName(const WCHAR* dllPath, SIZE_T len)
{
    // 找到文件名起始位置
    SIZE_T nameStart = len;
    for (SIZE_T i = len; i > 0; i--)
    {
        if (dllPath[i - 1] == L'\\' || dllPath[i - 1] == L'/')
        {
            nameStart = i;
            break;
        }
    }
    if (nameStart >= len) return FALSE;

    SIZE_T nameLen = len - nameStart;
    if (nameLen == 0) return FALSE;

    WCHAR sysPath[MAX_PATH] = { 0 };
    UINT sysLen = GetSystemDirectoryW(sysPath, MAX_PATH);
    if (sysLen == 0 || sysLen + 1 + nameLen >= MAX_PATH) return FALSE;

    sysPath[sysLen] = L'\\';
    for (SIZE_T i = 0; i < nameLen; i++)
        sysPath[sysLen + 1 + i] = dllPath[nameStart + i];
    sysPath[sysLen + 1 + nameLen] = L'\0';

    DWORD attrs = GetFileAttributesW(sysPath);
    return (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0);
}

// LdrLoadDll 钩子：DLL 侧载防护
NTSTATUS calling NewLdrLoadDll(
    PWCHAR PathToFile,
    PULONG DllCharacteristics,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
)
{
    // 递归保护：WinVerifyTrust 可能触发 DLL 加载，避免无限递归
    if (DllProtIsRecursiveHook())
    {
        return OriginalLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle);
    }

    BOOL entered = DllProtEnterHook();
    NTSTATUS status = STATUS_SUCCESS;

    do
    {
        // 仅在当前进程已签名时启用侧载防护；未初始化或当前进程未签名时直接放行
        if (g_CurrentProcessSigned != 1)
        {
            status = OriginalLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle);
            break;
        }

        if (!ModuleFileName || !ModuleFileName->Buffer || ModuleFileName->Length == 0)
        {
            status = OriginalLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle);
            break;
        }

        const WCHAR* pPath = ModuleFileName->Buffer;
        SIZE_T pathLen = ModuleFileName->Length / sizeof(WCHAR);

        // 只处理完整路径；相对名/搜索路径加载无法快速判断，交由原始函数
        if (pathLen < 4 ||
            !(pPath[1] == L':' ||
              (pPath[0] == L'\\' && pPath[1] == L'\\') ||
              (pPath[0] == L'%')))
        {
            status = OriginalLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle);
            break;
        }

        // 系统目录等可信位置快速放行
        if (DllProtIsTrustedLocation(pPath, pathLen))
        {
            status = OriginalLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle);
            break;
        }

        // 仅对高风险路径或当前进程同目录且与 system32 同名的 DLL 做签名检查
        BOOL highRisk = DllProtIsHighRiskSideLoadPath(pPath, pathLen);
        BOOL sameDir = DllProtIsSameDirAsExe(pPath, pathLen);

        BOOL shouldCheckSig = highRisk;
        if (!shouldCheckSig && sameDir)
        {
            // 同目录场景下，进一步判断是否为 system32 已知 DLL 的同名劫持
            shouldCheckSig = DllProtSystem32HasSameName(pPath, pathLen);
        }

        if (shouldCheckSig)
        {
            if (!DllProtIsDllSignedFast(pPath, pathLen))
            {
                // 已签名进程加载无签名 DLL，疑似 DLL 侧载，直接拒绝
                InterlockedIncrement(&g_DllSideLoadBlockedCount);
                status = ACCESS_IS_DENIED;
                break;
            }
        }

        status = OriginalLdrLoadDll(PathToFile, DllCharacteristics, ModuleFileName, ModuleHandle);
    } while (0);

    if (entered) DllProtLeaveHook();
    return status;
}

void GetProcessNameByPid(DWORD pid, char* processName, size_t bufferSize)
{
    if (bufferSize == 0) return;

    processName[0] = '\0';

    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL)
    {
        // 如果无法打开，尝试使用更低的权限
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess == NULL)
        {
            strcpy_s(processName, bufferSize, "Unknown");
            return;
        }
    }

    // 获取进程可执行文件路径
    char fullPath[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;

    if (QueryFullProcessImageNameA(hProcess, 0, fullPath, &size))
    {
        // 从完整路径中提取文件名
        char* fileName = strrchr(fullPath, '\\');
        if (fileName != NULL)
        {
            strcpy_s(processName, bufferSize, fileName + 1);
        }
        else
        {
            strcpy_s(processName, bufferSize, fullPath);
        }
    }
    else
    {
        strcpy_s(processName, bufferSize, "Unknown");
    }

    CloseHandle(hProcess);
}

NTSTATUS calling NewNtQueueApcThread(
    _In_ HANDLE ThreadHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
)
{
    // 获取当前进程ID
    DWORD currentPid = GetCurrentProcessId();

    // 获取目标线程所属进程ID
    DWORD targetPid = GetProcessIdOfThread(ThreadHandle);

    // 如果尝试向其他进程的线程插入APC，则阻止
    if (currentPid != targetPid && (!isWindowsFile || isScriptScan) && ThreadHandle && targetPid != 0)
    {
        Suspiciousness += 100;

        // 获取目标进程名
        char targetProcessName[MAX_PATH] = { 0 };
        GetProcessNameByPid(targetPid, targetProcessName, MAX_PATH);

        string sendOut;
        sendOut += "[ADV·恶意拦截] 发现进程试图远程线程注入（通过跨进程APC）！可能会绕过防护，拦截时将直接终止进程！\r\n\r\n";
        sendOut += "目标进程：";
        sendOut += targetProcessName;
        sendOut += "(PID: ";
        sendOut += std::to_string(targetPid);
        sendOut += ")";

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm,
            (char*)"发现可疑进程试图远程线程注入", GetCurrentProcessId(),
            (char*)"内存防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    return OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

NTSTATUS calling NewNtQueueApcThreadEx(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE UserApcReserveHandle,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
)
{
    // 获取当前进程ID
    DWORD currentPid = GetCurrentProcessId();

    // 获取目标线程所属进程ID
    DWORD targetPid = GetProcessIdOfThread(ThreadHandle);

    // 如果尝试向其他进程的线程插入APC，则阻止
    if (currentPid != targetPid && (!isWindowsFile || isScriptScan) && ThreadHandle && targetPid != 0)
    {
        Suspiciousness += 100;

        // 获取目标进程名
        char targetProcessName[MAX_PATH] = { 0 };
        GetProcessNameByPid(targetPid, targetProcessName, MAX_PATH);

        string sendOut;
        sendOut += "[ADV·恶意拦截] 发现进程试图远程线程注入（通过跨进程APC）！可能会绕过防护，拦截时将直接终止进程！\r\n\r\n";
        sendOut += "目标进程：";
        sendOut += targetProcessName;
        sendOut += "(PID: ";
        sendOut += std::to_string(targetPid);
        sendOut += ")";

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm,
            (char*)"发现可疑进程试图远程线程注入", GetCurrentProcessId(),
            (char*)"内存防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    return OriginalNtQueueApcThreadEx(ThreadHandle, UserApcReserveHandle, ApcRoutine,
        ApcArgument1, ApcArgument2, ApcArgument3);
}

NTSTATUS calling NewNtQueueApcThreadEx2(
    _In_ HANDLE ThreadHandle,
    _In_opt_ HANDLE UserApcReserveHandle,
    _In_ ULONG_PTR ApcContext,
    _In_ PPS_APC_ROUTINE ApcRoutine,
    _In_opt_ PVOID ApcArgument1,
    _In_opt_ PVOID ApcArgument2,
    _In_opt_ PVOID ApcArgument3
)
{
    // 获取当前进程ID
    DWORD currentPid = GetCurrentProcessId();

    // 获取目标线程所属进程ID
    DWORD targetPid = GetProcessIdOfThread(ThreadHandle);

    // 如果尝试向其他进程的线程插入APC，则阻止
    if (currentPid != targetPid && (!isWindowsFile || isScriptScan) && ThreadHandle && targetPid != 0)
    {
        Suspiciousness += 100;

        // 获取目标进程名
        char targetProcessName[MAX_PATH] = { 0 };
        GetProcessNameByPid(targetPid, targetProcessName, MAX_PATH);

        string sendOut;
        sendOut += "[ADV·恶意拦截] 发现进程试图远程线程注入（通过跨进程APC）！可能会绕过防护，拦截时将直接终止进程！\r\n\r\n";
        sendOut += "目标进程：";
        sendOut += targetProcessName;
        sendOut += "(PID: ";
        sendOut += std::to_string(targetPid);
        sendOut += ")";

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm,
            (char*)"发现可疑进程试图远程线程注入", GetCurrentProcessId(),
            (char*)"内存防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    return OriginalNtQueueApcThreadEx2(ThreadHandle, UserApcReserveHandle, ApcContext,
        ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}

// ====================================================

// ===========================================================================



// 注册表防护区域 ============================================================

// 注册表修改拦截区域 =================================

// 辅助函数：提取命令行
string ExtractCommandLine(const string& data) {
    size_t start = data.find("CommandLineTemplate=\"");
    if (start != string::npos) {
        start += 20;
        size_t end = data.find("\"", start);
        if (end != string::npos) {
            return data.substr(start, end - start);
        }
    }

    start = data.find("ExecutablePath=\"");
    if (start != string::npos) {
        start += 15;
        size_t end = data.find("\"", start);
        if (end != string::npos) {
            return data.substr(start, end - start);
        }
    }

    return "提取失败";
}

// 辅助函数：提取脚本内容
string ExtractScriptText(const string& data) {
    size_t start = data.find("ScriptText=\"");
    if (start != string::npos) {
        start += 11;
        size_t end = data.find("\"", start);
        if (end != string::npos) {
            string script = data.substr(start, end - start);
            if (script.length() > 15) {
                script = script.substr(0, 15) + "...[内容过长已截断]";
            }
            return script;
        }
    }
    return "提取失败";
}

NTSTATUS calling NewNtSetValueKey(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    ULONG TitleIndex,
    ULONG Type,
    PVOID Data,
    ULONG DataSize
)
{
    string sPath = Str_ConvertLPWSTRToLPSTR((LPWSTR)Reg_GetKeyPathFromKKEY((HKEY)KeyHandle).c_str());
    string sName = Str_ConvertLPWSTRToLPSTR((LPWSTR)Str_PUNICODE_STRINGToWString(ValueName).c_str());
    string sHandled = Str_ExtractContentBetweenThirdAndForthSlashes(sPath);

    ULONG dwType = Type;
    PVOID lpData = Data;
    int INTValue = 0;
    wstring wsdata = L"";
    BOOL isSendSuccess = TRUE;

    if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY)
        INTValue = (int)*(int*)lpData;
    else if (Data != nullptr)
    {
        wsdata.append(reinterpret_cast<const wchar_t*>(Data), DataSize);
        INTValue = atoi(Str_ConvertLPWSTRToLPSTR((LPWSTR)wsdata.c_str()));
    }

    bool isWait = false;
    string sRoot = Str_ExtractContentBetweenSecondAndThirdSlashes(sPath);
    string sDataContent = (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) ?
        to_string(INTValue) : Str_ConvertLPWSTRToLPSTR((LPWSTR)wsdata.c_str());

    // 规则定义结构体
    struct RegRule
    {
        function<bool()> condition;
        function<void()> action;
        string alertTitle;
        string alertMsg;
        int suspiciousDelta;
    };

    // 规则列表
    vector<RegRule> rules = {
        // 规则1: 添加开机启动项
        {
            [&]() -> bool {
            // 基本启动路径
            return Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") ||

                // Winlogon相关
                (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") &&
                 (Str_CompareWithoutCap(sName, "Shell") ||
                  Str_CompareWithoutCap(sName, "UserInit"))) ||  // Userinit

                // 32位兼容路径 (WOW6432Node)
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") ||

                // Winlogon 32位兼容路径
                (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") &&
                 (Str_CompareWithoutCap(sName, "Shell") ||
                  Str_CompareWithoutCap(sName, "UserInit"))) ||

                // 系统设置相关
                (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SYSTEM\\Setup") &&
                 (Str_CompareWithoutCap(sName, "CmdLine") ||
                  Str_CompareWithoutCap(sName, "OsLoaderPath"))) ||

                // 服务账户启动路径
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-19\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-19\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-19\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-19\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-19\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") ||

                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-20\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-20\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-20\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-20\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\S-1-5-20\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") ||

                // 当前处理用户
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") ||

                // Explorer Shell Folders Startup
                (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders") &&
                 Str_CompareWithoutCap(sName, "Startup")) ||

                // 32位用户路径 (WOW6432Node)
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce") ||
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run") ||

                // Explorer Shell Folders Startup (32位用户路径)
                (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders") &&
                 Str_CompareWithoutCap(sName, "Startup"));
            },
            [&]() {
                string ssendOut = "[注册表防护·添加] 允许进程加入开机启动项，会减慢开机速度，并可能导致系统运行异常。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath) +
                            "\r\n\r\n项: " + sName +
                            "\r\n内容: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在添加开机启动项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "添加开机启动项",
            "检测到有进程正在添加开机启动项，建议阻止",
            10
        },

        // 规则2: 修改Windows Nt Load项
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows")) &&
                         Str_CompareWithoutCap(sName, "Load"));
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 程序正在修改 Windows Nt Load 项，可能导致病毒自启动。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath) +
                            "\r\n\r\n项: " + sName +
                            "\r\n内容: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm, (char*)"有进程正在修改注册表关键项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改Windows Nt Load项",
            "有进程正在修改注册表关键项，建议阻止",
            30
        },

        // 规则3: 修改TelemetryController Command
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath.substr(0, sPath.find_last_of("\\")),
                       "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController") ||
                    Str_CompareWithoutCap(sPath.substr(0, sPath.find_last_of("\\")),
                           "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController")) &&
                       Str_CompareWithoutCap(sName, "Command");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 程序正在修改 TelemetryController Command 项，可能导致病毒自启动。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\" + Str_ExtractContentAfterNSlash(sPath) +
                            "\r\n\r\n项: " + sName +
                            "\r\n内容: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm, (char*)"有进程正在修改注册表关键项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改TelemetryController",
            "有进程正在修改注册表关键项，建议阻止",
            30
        },

        // 规则4: 修改Windows Logon Script项
        {
            [&]() -> bool {
                return Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Environment") &&
                       Str_CompareWithoutCap(sName, "UserInitMprLogonScript");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 程序正在修改 Windows Logon Script 项，可能导致病毒自启动。\r\n\r\n";
                ssendOut += "HKEY_USERS\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"有进程修改注册表关键项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改Logon Script项",
            "有进程修改注册表关键项，建议阻止",
            30
        },

        // 规则5: 修改SilentProcessExit项
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath.substr(0, sPath.find_last_of("\\")),
                       "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit") ||
                    Str_CompareWithoutCap(sPath.substr(0, sPath.find_last_of("\\")),
                           "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit")) &&
                       Str_CompareWithoutCap(sName, "MonitorProcess");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 程序正在修改 SilentProcessExit 项，可能导致病毒自启动。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"有进程正在修改注册表关键项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改SilentProcessExit",
            "有进程正在修改注册表关键项，建议阻止",
            30
        },

        // 规则6: 禁用CMD
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Policies\\Microsoft\\Windows\\System") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\System")) &&
                       Str_CompareWithoutCap(sName, "DisableCMD") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用CMD，将无法使用CMD。\r\n\r\n";
                ssendOut += "HKEY_USERS\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用CMD，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用CMD",
            "检测到有进程正在禁用CMD，建议阻止",
            10
        },

            // 规则7: 禁用任务管理器
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\system")) &&
                       Str_CompareWithoutCap(sName, "DisableTaskmgr") &&
                       ((dwType == REG_DWORD && (int)*(int*)lpData != 0) || (dwType != REG_DWORD));
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用任务管理器，将无法使用任务管理器。\r\n\r\n";
                ssendOut += "HKEY_USERS\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用任务管理器，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用任务管理器",
            "检测到有进程正在禁用任务管理器，建议阻止",
            10
        },

            // 规则8: 禁用电源选项
        {
            [&]() -> bool {
                return (((Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) && (int)*(int*)lpData == 1 && (Str_CompareWithoutCap(sName, "HidePowerOptions") || Str_CompareWithoutCap(sName, "NoClose"))) ||
                       ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Start\\HideShutdown") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\PolicyManager\\default\\Start\\HideShutdown") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Start\\HideRestart") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\PolicyManager\\default\\Start\\HideRestart") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Start\\HideSleep") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\PolicyManager\\default\\Start\\HideSleep") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Start\\HideSignOut") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\PolicyManager\\default\\Start\\HideSignOut")) &&
                        Str_CompareWithoutCap(sName, "value") && (int)*(int*)lpData != 0)) ||
                       ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) &&
                        (Str_CompareWithoutCap(sName, "NoClose") || Str_CompareWithoutCap(sName, "NoLogOff")) &&
                        (int)*(int*)lpData == 1) &&
                       dwType == REG_DWORD;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用电源选项，将无法进行一些电源操作。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用电源选项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用电源选项",
            "检测到有进程正在禁用电源选项，建议阻止",
            10
        },

            // 规则9: 禁用运行功能(NoRun)
        {
             [&]() -> bool {
                 return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                        (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                        Str_CompareWithoutCap(sName, "NoRun") &&
                        dwType == REG_DWORD &&
                        (int)*(int*)lpData == 1;
             },
             [&]() {
                     string ssendOut = "[注册表防护·禁用] 允许进程禁用运行，将无法使用'Win+R'运行。\r\n\r\n";
                 if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                 else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                 else ssendOut += "~";
                 ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                            "\r\n\r\n项: " + sName +
                            "\r\n内容: " + to_string(INTValue);
                 EnterHandleEvent();
                 if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                      (char*)"检测到有进程正在禁用'Win+R'，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                     isSendSuccess = FALSE;
                     ExitHandleEvent();
                 }
             },
             "禁用运行功能",
             "检测到有进程正在禁用'Win+R'，建议阻止",
             10
        },

            // 规则10: 禁用文件资源管理器(NoSetFolders)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoSetFolders") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData == 1;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用SetFolders，将无法使用'Win+E'。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用'Win+E'，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用文件资源管理器",
            "检测到有进程正在禁用'Win+E'，建议阻止",
            10
        },

            // 规则11: 隐藏桌面(NoDesktop)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoDesktop") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·隐藏] 进程正在隐藏桌面。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在隐藏桌面，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "隐藏桌面",
            "检测到有进程正在隐藏桌面，建议阻止",
            10
        },

            // 规则12: 隐藏右键菜单(NoViewContextMenu)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoViewContextMenu") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·隐藏] 进程正在隐藏右键菜单。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在隐藏右键菜单，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "隐藏右键菜单",
            "检测到有进程正在隐藏右键菜单，建议阻止",
            10
        },

            // 规则13: 隐藏任务栏右键菜单(NoTrayContextMenu)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoTrayContextMenu") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·隐藏] 进程正在隐藏任务栏右键菜单。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在隐藏任务栏右键菜单，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "隐藏任务栏右键菜单",
            "检测到有进程正在隐藏任务栏右键菜单，建议阻止",
            10
        },

            // 规则14: 禁用控制面板(NoControlPanel)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoControlPanel") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData == 1;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用控制面板，将无法使用控制面板。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用控制面板，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用控制面板",
            "检测到有进程正在禁用控制面板，建议阻止",
            10
        },

            // 规则15: 禁用程序运行(RestrictRun/DisallowRun)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       (Str_CompareWithoutCap(sName, "RestrictRun") || Str_CompareWithoutCap(sName, "DisallowRun")) &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 进程正在禁用常规程序启动，建议阻止。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用常规程序启动，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用程序运行",
            "检测到有进程正在禁用常规程序启动，建议阻止",
            10
        },

            // 规则16: 隐藏驱动器(NoDrives)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoDrives") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData != 0;
                },
                [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用显示分区，分区将隐藏。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                    "\r\n\r\n项: " + sName +
                    "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                    (char*)"检测到有进程正在禁用显示分区，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
                },
                "隐藏驱动器",
                "检测到有进程正在禁用显示分区，建议阻止",
                10
        },

            // 规则17: 禁用查看驱动器内容(NoViewOnDrive)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoViewOnDrive") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用列出分区文件，explorer将无法展示分区。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用列出分区文件，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用查看驱动器内容",
            "检测到有进程正在禁用列出分区文件，建议阻止",
            10
        },

            // 规则18: 禁用任务栏设置(NoSetTaskBar)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoSetTaskBar") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 进程正在禁用任务栏。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用任务栏，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用任务栏设置",
            "检测到有进程正在禁用任务栏，建议阻止",
            10
        },

            // 规则19: 禁用文件菜单(NoFileMenu)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoFileMenu") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 进程正在禁用文件菜单。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用文件菜单，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用文件菜单",
            "检测到有进程正在禁用文件菜单，建议阻止",
            10
        },

            // 规则20: 禁用文件夹选项(NoFolderOptions)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoFolderOptions") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·更改] 进程正在更改文件夹和搜索选项。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在更改文件夹和搜索选项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用文件夹选项",
            "检测到有进程正在更改文件夹和搜索选项，建议阻止",
            10
        },

            // 规则21: 禁用Win热键(NoWinKeys)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "NoWinKeys") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 进程正在禁用Win热键。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用Win热键，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用Win热键",
            "检测到有进程正在禁用Win热键，建议阻止",
            10
        },

            // 规则22: 隐藏注销按钮(StartMenuLogOff)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer")) ||
                       (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"))) &&
                       Str_CompareWithoutCap(sName, "StartMenuLogOff") &&
                       INTValue != 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 进程正在隐藏注销按钮。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在隐藏注销按钮，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "隐藏注销按钮",
            "检测到有进程正在隐藏注销按钮，建议阻止",
            10
        },

            // 规则23: 禁用注册表工具(DisableRegistryTools)
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\system")) &&
                       Str_CompareWithoutCap(sName, "DisableRegistryTools") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData == 1;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用注册表，将无法使用注册表。\r\n\r\n";
                ssendOut += "HKEY_USERS\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在禁用注册表，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用注册表工具",
            "检测到有进程正在禁用注册表，建议阻止",
            10
        },

            // 规则24: 映像劫持(Debugger)
        {
            [&]() -> bool {
                return Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" +
                       sPath.substr(sPath.find_last_of('\\') + 1)) &&
                       Str_CompareWithoutCap(sName, "debugger");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 允许进程映像劫持，可能导致某些程序运行异常。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\" +
                           sPath.substr(sPath.find_last_of('\\') + 1) + "\\" + sName +
                           "\r\n\r\n映像劫持的受影响程序: " + sPath.substr(sPath.find_last_of('\\') + 1) +
                           "\r\n映像劫持的目标: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在映像劫持，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "映像劫持",
            "检测到有进程正在映像劫持，建议阻止",
            10
        },

            // 规则25: 修改IE主页(Start Page)
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\Internet Explorer\\Main") ||
                       Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\Internet Explorer\\Main") ||
                       Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Internet Explorer\\Main") ||
                       Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Internet Explorer\\Main")) &&
                       Str_CompareWithoutCap(sName, "Start Page");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 允许进程修改IE主页，可能会导致打开IE时访问陌生网站。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\nIE起始页项: " + sName +
                           "\r\n指向网页: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在修改IE起始页，建议阻止", GetCurrentProcessId(), (char*)"计算机设置") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改IE主页",
            "检测到有进程正在修改IE起始页，建议阻止",
            10
        },

            // 规则26: 禁用U盘访问(Deny_All)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\RemovableStorageDevices")) ||
                    (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices") ||
                     Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Policies\\Microsoft\\Windows\\RemovableStorageDevices"))) &&
                    Str_CompareWithoutCap(sName, "Deny_All") &&
                    dwType == REG_DWORD &&
                    (int)*(int*)lpData == 1;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 允许进程禁用U盘，将无法访问U盘。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                    "\r\n\r\n项: " + sName +
                    "\r\n内容: 1";
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                    (char*)"检测到有进程正在禁用U盘，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用U盘访问",
            "检测到有进程正在禁用U盘，建议阻止",
            10
        },

            // 规则27: 修改文件关联
        {
            [&]() -> bool {
                return (((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\" + sPath.substr(sPath.find_last_of('\\') + 1)) &&
                        Str_EndsWith(sHandled, "_Classes")) ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes\\" + sPath.substr(sPath.find_last_of('\\') + 1)) ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Classes\\" + sPath.substr(sPath.find_last_of('\\') + 1))) &&
                        (sPath.substr(sPath.find_last_of('\\') + 1).find('.') == 0) &&
                        Str_CompareWithoutCap(sName, "") &&
                        !isExplorer);
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 允许进程修改后缀名关联项，可能导致系统运行出错。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += "\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n后缀名: " +
                           sPath.substr(sPath.find_last_of('\\') + 1) +
                           "\r\n修改后内容: " +
                           sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在修改后缀名关联项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改文件关联",
            "检测到有进程正在修改后缀名关联项，建议阻止",
            10
        },

            // 规则28: UAC绕过(ms-settings)
        {
            [&]() -> bool {
                return Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\ms-settings\\shell\\open\\command") &&
                       Str_CompareWithoutCap(sName, "") &&
                       Str_EndsWith(sHandled, "_Classes");
            },
            [&]() {
                string ssendOut = "[注册表防护·UAC绕过] 该进程正在修改系统默认程序，正常程序不会修改此项，建议阻止。\r\n\r\n";
                ssendOut += "HKEY_USERS\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: (默认)" +
                           "\r\n内容: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在尝试绕过UAC，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "UAC绕过",
            "检测到有进程正在尝试绕过UAC，建议阻止",
            50
        },

            // 规则29: 禁用UAC(EnableLUA)
        {
            [&]() -> bool {
                return Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System") &&
                       Str_CompareWithoutCap(sName, "EnableLUA") &&
                       dwType == REG_DWORD &&
                       (int)*(int*)lpData == 0;
            },
            [&]() {
                string ssendOut = "[注册表防护·禁用] 进程正在禁用UAC，建议阻止。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" +
                           (string)"\r\n\r\n项: " + sName +
                           "\r\n内容: " + to_string(INTValue);
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在尝试绕过UAC，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用UAC",
            "检测到有进程正在尝试绕过UAC，建议阻止",
            50
        },

            // 规则30: 修改桌面壁纸(WallPaper)
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Control Panel\\Desktop") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies") ||
                        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies")) &&
                       Str_CompareWithoutCap(sName, "WallPaper"));
            },
            [&]() {
                // explorer.exe 修改壁纸注册表直接放行
                if (isExplorer) {
                    return;
                }
                string ssendOut = "[注册表防护·修改] 进程正在修改桌面壁纸。\r\n\r\n";
                ssendOut += "HKEY_USERS\\" + Str_ExtractContentAfterNSlash(sPath) +
                           "\r\n\r\n项: " + sName +
                           "\r\n修改后指向的图像文件: " + sDataContent;
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到有进程正在修改桌面壁纸，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改桌面壁纸",
            "检测到有进程正在修改桌面壁纸，建议阻止",
            10
        },

            // 规则31: 修改服务配置(ControlSet001)
        {
            [&]() -> bool {
                return (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\" + Str_ExtractContentAfterNSlash(sPath, 5)));
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改服务配置项，建议阻止。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\" +
                           Str_ExtractContentAfterNSlash(sPath, 5) +
                           "\r\n\r\n项: " + sName;
                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);
                }
                else if (Data != nullptr) {
                    ssendOut += "\r\n内容: " + sDataContent;
                }
                EnterHandleEvent();
            if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                 (char*)"检测到有进程正在修改服务配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                isSendSuccess = FALSE;
                ExitHandleEvent();
            }
            },
            "修改服务配置",
            "检测到有进程正在修改服务配置项，建议阻止",
            50
        },

            // 规则32: 修改启动配置(BCD)
        {
            [&]() -> bool {
                int nFindPos = sPath.find('\\', 29);
                if (nFindPos != string::npos) {
                    return Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\BCD00000000" + sPath.substr(nFindPos));
                }
                return Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\BCD00000000");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改启动配置项，可能是非法自启动绕过行为，建议阻止。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\" +
                           Str_ExtractContentAfterNSlash(sPath, 3) +
                           "\r\n\r\n项: " + sName;
                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);
                }
                else if (Data != nullptr) {
                    ssendOut += "\r\n内容: " + sDataContent;
                }
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                 (char*)"检测到有进程正在修改启动配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改启动配置",
            "检测到有进程正在修改启动配置项，建议阻止",
            50
        },

            // 规则33: 修改AppInit实现Dll注入
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows") && (Str_CompareWithoutCap(sName, "AppInit_DLLs") || Str_CompareWithoutCap(sName, "LoadAppInit_DLLs")))
                    || (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows") && (Str_CompareWithoutCap(sName, "AppInit_DLLs") || Str_CompareWithoutCap(sName, "LoadAppInit_DLLs"))));
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改全局dll加载项，可能是非法自启动绕过行为或绕过保护行为，阻止后会直接终止进程。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\" +
                    Str_ExtractContentAfterNSlash(sPath, 3) +
                    "\r\n\r\n项: " + sName;
                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY)
                {
                    ssendOut += "\r\n内容: " + to_string(INTValue);
                }
                else if (Data != nullptr)
                {
                    ssendOut += "\r\n内容: " + sDataContent;
                }
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                    (char*)"检测到有进程正在修改全局Dll加载项", GetCurrentProcessId(), (char*)"注册表防护", WDT_Normal, true) <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "修改全局Dll加载项",
            "检测到有进程正在修改全局Dll加载项，建议阻止",
            150
        },

            // 规则34: 调整UAC设置
        {
            [&]() -> bool {
                return Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system") &&
                    Str_CompareWithoutCap(sName, "PromptOnSecureDesktop");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改UAC设置项。\r\n\r\n";
                ssendOut += "HKEY_LOCAL_MACHINE\\" +
                           Str_ExtractContentAfterNSlash(sPath, 3) +
                           "\r\n\r\n项: " + sName;
                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);
                }
                else if (Data != nullptr) {
                    ssendOut += "\r\n内容: " + sDataContent;
                }
                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                 (char*)"检测到有进程正在修改UAC配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "UAC配置项",
            "检测到有进程正在修改UAC配置项，建议阻止",
            10
        },

            // 规则35: 修改CLSID配置（用户和系统级）
        {
            [&]() -> bool {
                // 检查用户级CLSID
                bool isUserClsid = Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Classes\\CLSID");
                // 检查系统级CLSID（64位和32位）
                bool isSystemClsid = Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Classes\\CLSID") ||
                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Classes\\CLSID");

                return isUserClsid || isSystemClsid;
                },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改CLSID配置，可能用于注册恶意COM对象或劫持合法对象。\r\n\r\n";

                // 构建注册表路径显示
                if (sPath.find("\\REGISTRY\\USER\\") != string::npos) {
                    ssendOut += "HKEY_USERS\\" + sHandled + "\\Software\\Classes\\CLSID\\";
                }
                else if (sPath.find("\\REGISTRY\\MACHINE\\") != string::npos) {
                    if (sPath.find("Wow6432Node") != string::npos) {
                        ssendOut += "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Classes\\CLSID\\";
                    }
                    else {
                        ssendOut += "HKEY_LOCAL_MACHINE\\Software\\Classes\\CLSID\\";
                    }
                }

                string clsidPath = Str_ExtractContentAfterNSlash(sPath, sPath.find("\\REGISTRY\\USER\\") != string::npos ? 5 : 4);
                ssendOut += clsidPath + "\r\n\r\n项: " + sName;

                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);
                }
                else if (Data != nullptr) {
                    ssendOut += "\r\n内容: " + sDataContent;
                }

                // 检查高危操作
                string riskType = "";

                if (sPath.find("InprocServer32") != string::npos && (sName.empty() || Str_CompareWithoutCap(sName, "ThreadingModel"))) {
                    ssendOut += "\r\n检测到InprocServer32修改，可能是DLL劫持。";
                }
                else if (sPath.find("LocalServer32") != string::npos && sName.empty()) {
                    ssendOut += "\r\n检测到LocalServer32修改，可能是EXE劫持。";
                }
                else if ((sPath.find("TreatAs") != string::npos || sPath.find("AutoTreatAs") != string::npos) && sName.empty()) {
                    ssendOut += "\r\n检测到TreatAs/AutoTreatAs修改，可能是COM对象劫持。";
                }

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                    (char*)"检测到有进程正在修改CLSID配置，建议拦截", GetCurrentProcessId(), (char*)"注册表防护",
                    WDT_Normal, false) <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "CLSID配置修改",
            "检测到有进程正在修改CLSID配置",
            60
        },

            // 规则36: 禁用系统还原
        {
            [&]() -> bool {
                // 检查系统策略中的系统还原禁用设置
                bool isSystemRestorePath = Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore") ||
                                           Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\SystemRestore");

                return isSystemRestorePath && (Str_CompareWithoutCap(sName, "DisableSR") || Str_CompareWithoutCap(sName, "DisableConfig"));
            },
            [&]() {
                string ssendOut = "[注册表防护·高危] 进程正在尝试禁用系统还原功能！\r\n\r\n";

                // 构建注册表路径显示
                if (sPath.find("Policies") != string::npos) {
                    ssendOut += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore";
                }
                else {
                    ssendOut += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\SystemRestore";
                }

                ssendOut += "\r\n\r\n项: " + sName;

                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);

                    // 检查是否为禁用值
                    if (INTValue == 1) {
                        ssendOut += " (禁用系统还原)";
                    }
                }
                else if (Data != nullptr) {
                    ssendOut += "\r\n内容: " + sDataContent;
                }

                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                    (char*)"检测到高危系统还原禁用操作，建议拦截", GetCurrentProcessId(), (char*)"注册表防护", WDT_Normal, false) <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "禁用系统还原",
            "检测到高危系统还原禁用操作",
            200
        },

            // 规则37: 配置系统还原设置
        {
            [&]() -> bool {
                bool isSystemRestorePath = Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore") ||
                                           Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\SystemRestore");

                if (!isSystemRestorePath) return false;

                // 检查关键配置项
                vector<string> criticalItems = {
                    "DisableSR",
                    "DisableConfig",
                    "RPSessionInterval",
                    "RPLifeInterval",
                    "RPSessionLimit",
                    "RPLifeInterval",
                    "DSMax",
                    "DSMin"
                };

                for (const auto& item : criticalItems) {
                    if (Str_CompareWithoutCap(sName, item)) {
                        return true;
                    }
                }
                return false;
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改系统还原配置。\r\n\r\n";

                if (sPath.find("Policies") != string::npos) {
                    ssendOut += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\SystemRestore";
                }
                else {
                    ssendOut += "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\SystemRestore";
                }

                ssendOut += "\r\n\r\n项: " + sName;

                if (Type == REG_DWORD || Type == REG_QWORD || Type == REG_BINARY) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);

                    // 根据项名解释含义
                    if (Str_CompareWithoutCap(sName, "DisableSR") && INTValue == 1) {
                        ssendOut += " (完全禁用系统还原)";
                    }
                    else if (Str_CompareWithoutCap(sName, "DisableConfig") && INTValue == 1) {
                        ssendOut += " (禁用系统还原配置界面)";
                    }
                    else if (Str_CompareWithoutCap(sName, "RPSessionInterval")) {
                        ssendOut += " (还原点创建间隔分钟数)";
                    }
                    else if (Str_CompareWithoutCap(sName, "RPLifeInterval")) {
                        ssendOut += " (还原点保留天数)";
                    }
                }
                else if (Data != nullptr) {
                    ssendOut += "\r\n内容: " + sDataContent;
                }

                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到系统还原配置修改", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "系统还原配置修改",
            "检测到系统还原配置修改",
            80
        },

            // 规则38: 修改系统服务支持程序
        {
            [&]() -> bool {
                return Str_StartsWithWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\PEERDIST\\SERVICE");
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改系统服务支持程序。\r\n\r\n路径：";
                ssendOut += sPath;

                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到系统服务支持程序修改", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "系统服务支持程序修改",
            "检测到系统服务支持程序修改",
            50
        },

            // 规则39: 拦截Svchost配置修改
        {
            [&]() -> bool {
                // 检查是否为目标Svchost路径
                bool isSvchostPath = Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost") ||
                                    Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Svchost");

                if (!isSvchostPath) {
                    // 检查是否为Svchost的子项（以路径开头匹配）
                    return Str_StartsWithWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\\") ||
                           Str_StartsWithWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Svchost\\");
                }

                return true;
            },
            [&]() {
                string ssendOut = "[注册表防护·修改] 进程正在修改Svchost服务配置。\r\n\r\n";

                // 显示完整路径
                ssendOut += "路径: " + sPath;

                if (!sName.empty()) {
                    ssendOut += "\r\n项: " + sName;
                }

                // 根据数据类型显示内容
                if (Type == REG_DWORD || Type == REG_QWORD) {
                    ssendOut += "\r\n内容: " + to_string(INTValue);

                    // 常见Svchost配置项解释
                    if (Str_CompareWithoutCap(sName, "CoInitializeSecurityParam")) {
                        ssendOut += " (COM安全初始化参数)";
                    }
                    else if (Str_CompareWithoutCap(sName, "AuthenticationCapabilities")) {
                        ssendOut += " (身份验证能力)";
                    }
                    else if (Str_CompareWithoutCap(sName, "LocalService")) {
                        ssendOut += " (本地服务配置)";
                    }
                }
                else if (Type == REG_MULTI_SZ || Type == REG_EXPAND_SZ || Type == REG_SZ) {
                    if (Data != nullptr) {
                        ssendOut += "\r\n内容: " + sDataContent;

                        // 如果是服务分组配置，特别标注
                        if (sDataContent.find(',') != string::npos ||
                            sDataContent.find(' ') != string::npos) {
                            ssendOut += " (服务分组配置)";
                        }
                    }
                }
                else if (Type == REG_BINARY) {
                    ssendOut += "\r\n内容: [二进制数据]";
                    if (Data != nullptr && DataSize > 0) {
                        ssendOut += " 大小: " + to_string(DataSize) + " 字节";
                    }
                }

                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                                     (char*)"检测到服务配置修改", GetCurrentProcessId(), (char*)"注册表防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "服务配置修改",
            "检测到服务配置修改",
            85
        },

        // 规则40: 拦截WMI永久事件订阅创建
        {
            [&]() -> bool {
                return ((Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\CIMOM") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\ESS") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\WBEM\\Scripting") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\WBEM\\CIMOM") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\WBEM\\ESS") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\WBEM\\Scripting") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Microsoft\\WBEM\\CIMOM") ||
                         Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\SOFTWARE\\Wow6432Node\\Microsoft\\WBEM\\CIMOM") ||
                         sPath.find("\\Microsoft\\WBEM\\") != string::npos) &&
                         (Str_CompareWithoutCap(sName, "__EventFilter") ||
                          Str_CompareWithoutCap(sName, "__EventConsumer") ||
                          Str_CompareWithoutCap(sName, "FilterToConsumerBinding") ||
                          Str_CompareWithoutCap(sName, "CommandLineEventConsumer") ||
                          Str_CompareWithoutCap(sName, "ActiveScriptEventConsumer") ||
                          sName.find("__Permanent") != string::npos ||
                          sDataContent.find("CommandLineTemplate") != string::npos ||
                          sDataContent.find("ScriptText") != string::npos));
            },
            [&]() {
                string ssendOut = "[WMI防护·永久事件订阅] 程序正在创建WMI永久事件订阅，可能导致恶意代码持久化运行。\r\n\r\n";
                if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
                else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
                else ssendOut += "~";
                ssendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath) +
                            "\r\n\r\n项: " + sName;

                // 提取命令执行内容
                if (sDataContent.find("CommandLineTemplate") != string::npos) {
                    ssendOut += "\r\n执行命令: " + ExtractCommandLine(sDataContent);
                }

                // 提取脚本内容
                if (sDataContent.find("ScriptText") != string::npos) {
                    ssendOut += "\r\n脚本内容: " + ExtractScriptText(sDataContent);
                }

                ssendOut += "\r\n完整内容: " + sDataContent;

                EnterHandleEvent();
                if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                    (char*)"有进程正在创建WMI永久事件订阅，建议阻止", GetCurrentProcessId(), (char*)"WMI防护") <= 0) {
                    isSendSuccess = FALSE;
                    ExitHandleEvent();
                }
            },
            "拦截WMI永久事件订阅",
            "有进程正在创建WMI永久事件订阅，建议阻止",
            30
        },

        // 规则41: 修改ETW配置
        {
            [&]() -> bool {
               return (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\WMI\\") ||
                       Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\"));
            },
            [&]() {
                string ssendOut = "[注册表防护·ETW] 进程正在修改ETW事件追踪配置，这并不是正常软件做的事情，建议阻止。\r\n\r\n";
                ssendOut += "路径: " + sPath + "\r\n";
                ssendOut += "项名: " + sName;
                EnterHandleEvent();
                Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                         (char*)"检测到ETW配置修改，可能导致安全监控失效",
                         GetCurrentProcessId(), (char*)"注册表防护");
            },
            "修改ETW配置",
            "检测到进程正在修改ETW事件追踪配置，建议阻止",
            80
        }
    };

    // 执行规则检查
    for (auto& rule : rules)
    {
        if (rule.condition())
        {
            Suspiciousness += rule.suspiciousDelta;
            if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

            rule.action();

            // 处理发送结果
            if (!isSendSuccess)
            {
                return ACCESS_IS_DENIED;
            }
            isWait = true;
            break;
        }
    }

    // 等待用户响应
    if (isWait)
    {
        if (!WaitForResult())
        {
            return ACCESS_IS_DENIED;
        }
    }

    return OriginalNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
}

// ====================================================

// 壁纸修改拦截 =====================================
/* SystemParametersInfo hook 已移除：仅保留注册表持久化壁纸修改拦截，
 * 不再拦截系统级 SPI_SETDESKWALLPAPER 调用（explorer 正常设置壁纸不再弹窗）。 */
/*
#define TH_SPI_SETDESKWALLPAPER 0x0014

static BOOL CheckWallpaperChange(const void* pvParam, BOOL isWide)
{
    char pathBuf[MAX_PATH] = { 0 };
    if (pvParam != NULL)
    {
        if (isWide)
        {
            const wchar_t* wp = (const wchar_t*)pvParam;
            int i = 0;
            for (; i < MAX_PATH - 1 && wp[i] != L'\0'; i++)
            {
                wchar_t c = wp[i];
                pathBuf[i] = (c < 128) ? (char)c : '?';
            }
            pathBuf[i] = '\0';
        }
        else
        {
            const char* cp = (const char*)pvParam;
            int i = 0;
            for (; i < MAX_PATH - 1 && cp[i] != '\0'; i++)
                pathBuf[i] = cp[i];
            pathBuf[i] = '\0';
        }
    }

    string ssendOut = "[注册表防护·修改] 进程正在修改桌面壁纸。\r\n\r\n";
    ssendOut += "通过 SystemParametersInfo(SPI_SETDESKWALLPAPER) 调用。\r\n\r\n";
    if (pathBuf[0] != '\0')
        ssendOut += string("目标壁纸路径：") + pathBuf;
    else
        ssendOut += "目标壁纸路径：(空)";

    EnterHandleEvent();
    if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm,
                           (char*)"检测到有进程正在修改桌面壁纸，建议阻止",
                           GetCurrentProcessId(), (char*)"注册表防护") <= 0)
    {
        ExitHandleEvent();
        return FALSE;
    }

    if (!WaitForResult())
    {
        return FALSE;
    }
    return TRUE;
}

BOOL WINAPI NewSystemParametersInfoW(
    UINT  uiAction,
    UINT  uiParam,
    PVOID pvParam,
    UINT  fWinIni)
{
    if (uiAction == TH_SPI_SETDESKWALLPAPER)
    {
        if (CheckSuspiciousness()) return FALSE;

        if (!CheckWallpaperChange(pvParam, TRUE))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    return OriginalSystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
}

BOOL WINAPI NewSystemParametersInfoA(
    UINT  uiAction,
    UINT  uiParam,
    PVOID pvParam,
    UINT  fWinIni)
{
    if (uiAction == TH_SPI_SETDESKWALLPAPER)
    {
        if (CheckSuspiciousness()) return FALSE;

        if (!CheckWallpaperChange(pvParam, FALSE))
        {
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    return OriginalSystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
}
*/

// 注册表删除防护区域 =================================


NTSTATUS calling NewNtDeleteKey(
    _In_ HANDLE KeyHandle
)
{
    string sPath = Str_ConvertLPWSTRToLPSTR((LPWSTR)Reg_GetKeyPathFromKKEY((HKEY)KeyHandle).c_str());
    string sHandled = Str_ExtractContentBetweenThirdAndForthSlashes(sPath);

    if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Microsoft\\SystemCertificates\\" + Str_ExtractContentAfterNSlash(sPath, 7)) ||
        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\" + Str_ExtractContentAfterNSlash(sPath, 6)) ||
        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Microsoft\\SystemCertificates") ||
        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates"))
    {
        string ssendOut;
        string sRoot = Str_ExtractContentBetweenSecondAndThirdSlashes(sPath);

        ssendOut += "[注册表防护·删除] 允许进程删除受信任证书，可能导致系统运行异常。\r\n\r\n";

        Suspiciousness += 20;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
        else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
        else ssendOut += "~";

        ssendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath);

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除受信任证书，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtDeleteKey(KeyHandle);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    else if (
        (
            (
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\" + Str_ExtractContentAfterNSlash(sPath, 4))
                && (Str_EndsWith(Str_ExtractContentBetweenThirdAndForthSlashes(sPath), "_Classes"))
                && !Str_StartsWithWithoutCap(Str_ExtractContentAfterNSlash(sPath, 4), "Local Settings")
                )
            || (
                Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Classes\\" + Str_ExtractContentAfterNSlash(sPath, 5))
                && !Str_StartsWithWithoutCap(Str_ExtractContentAfterNSlash(sPath, 5), "Local Settings")
                )
            ) && !isExplorer)
    {
        string sendOut;

        sendOut += "[注册表防护·删除] 允许进程删除后缀名关联项，可能导致系统运行出错。\r\n\r\n";

        Suspiciousness += 10;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        string Root = Str_ExtractContentBetweenSecondAndThirdSlashes(sPath);
        if (Str_CompareWithoutCap(Root, "MACHINE")) sendOut += "HKEY_LOCAL_MACHINE";
        else if (Str_CompareWithoutCap(Root, "USER")) sendOut += "HKEY_USERS";
        else sendOut += "~";

        sendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath);

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除后缀名关联项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtDeleteKey(KeyHandle);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    else if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\" + Str_ExtractContentAfterNSlash(sPath, 5)))
    {
        string sendOut;

        sendOut += "[注册表防护·删除] 进程正在删除服务配置项，建议阻止。\r\n\r\n";

        Suspiciousness += 50;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        sendOut += "HKEY_LOCAL_MACHINE";
        sendOut += (string)"\\SYSTEM\\ControlSet001";
        sendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath, 5);

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除服务配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtDeleteKey(KeyHandle);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    else if (sPath.length() >= 29)
    {
        int nFindPos = 0;
        BOOL isBcdChange = FALSE;

        if ((nFindPos = sPath.find('\\', 29)) != string::npos)
        {
            if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\BCD00000000" + sPath.substr(nFindPos)))
            {
                isBcdChange = TRUE;
            }
        }
        else
        {
            if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\BCD00000000"))
            {
                isBcdChange = TRUE;
            }
        }

        if (isBcdChange)
        {
            string sendOut;

            sendOut += "[注册表防护·删除] 进程正在删除启动配置项，可能导致无法正常启动，建议阻止。\r\n\r\n";

            Suspiciousness += 50;

            if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

            sendOut += "HKEY_LOCAL_MACHINE";
            sendOut += (string)"\\";
            sendOut += (string)Str_ExtractContentAfterNSlash(sPath, 3);

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除启动配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalNtDeleteKey(KeyHandle);
                }
                else
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
            }
        }
    }

    return OriginalNtDeleteKey(KeyHandle);
}


NTSTATUS calling NewNtDeleteValueKey(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName
)
{
    string sPath = Str_ConvertLPWSTRToLPSTR((LPWSTR)Reg_GetKeyPathFromKKEY((HKEY)KeyHandle).c_str());
    string sName = Str_ConvertLPWSTRToLPSTR((LPWSTR)Str_PUNICODE_STRINGToWString(ValueName).c_str());
    string sHandled = Str_ExtractContentBetweenThirdAndForthSlashes(sPath);

    if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Microsoft\\SystemCertificates\\" + Str_ExtractContentAfterNSlash(sPath, 7)) ||
        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates\\" + Str_ExtractContentAfterNSlash(sPath, 6)) ||
        Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\Software\\Microsoft\\SystemCertificates") ||
        Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Microsoft\\SystemCertificates"))
    {
        string ssendOut;
        string sRoot = Str_ExtractContentBetweenSecondAndThirdSlashes(sPath);

        ssendOut += "[注册表防护·删除] 允许进程删除受信任证书，可能导致系统运行异常。\r\n\r\n";

        Suspiciousness += 10;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        if (Str_CompareWithoutCap(sRoot, "MACHINE")) ssendOut += "HKEY_LOCAL_MACHINE";
        else if (Str_CompareWithoutCap(sRoot, "USER")) ssendOut += "HKEY_USERS";
        else ssendOut += "~";

        ssendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath);
        ssendOut += "\r\n键名称： ";
        ssendOut += sName;

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)ssendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除受信任证书，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtDeleteValueKey(KeyHandle, ValueName);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    else if (
        (
            (
            Str_CompareWithoutCap(sPath, "\\REGISTRY\\USER\\" + sHandled + "\\" + Str_ExtractContentAfterNSlash(sPath, 4))
            && (Str_EndsWith(Str_ExtractContentBetweenThirdAndForthSlashes(sPath), "_Classes"))
            && !Str_StartsWithWithoutCap(Str_ExtractContentAfterNSlash(sPath, 4), "Local Settings")
            )
        || (
            Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\Software\\Classes\\" + Str_ExtractContentAfterNSlash(sPath, 5))
            && !Str_StartsWithWithoutCap(Str_ExtractContentAfterNSlash(sPath, 5), "Local Settings")
            )
        ) && !isExplorer)
    {
        string sendOut;

        sendOut += "[注册表防护·删除] 允许进程删除后缀名关联项，可能导致系统运行出错。\r\n\r\n";

        Suspiciousness += 10;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        string Root = Str_ExtractContentBetweenSecondAndThirdSlashes(sPath);
        if (Str_CompareWithoutCap(Root, "MACHINE")) sendOut += "HKEY_LOCAL_MACHINE";
        else if (Str_CompareWithoutCap(Root, "USER")) sendOut += "HKEY_USERS";
        else sendOut += "~";

        sendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath);
        sendOut += "\r\n键名称： ";
        sendOut += sName;

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除后缀名关联项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtDeleteValueKey(KeyHandle, ValueName);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    else if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\" + Str_ExtractContentAfterNSlash(sPath, 5)))
    {
        string sendOut;

        sendOut += "[注册表防护·删除] 进程正在删除服务配置项，建议阻止。\r\n\r\n";

        Suspiciousness += 50;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        sendOut += "HKEY_LOCAL_MACHINE";
        sendOut += (string)"\\SYSTEM\\ControlSet001";
        sendOut += (string)"\\" + Str_ExtractContentAfterNSlash(sPath, 5);
        sendOut += "\r\n键名称： ";
        sendOut += sName;

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除服务配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtDeleteValueKey(KeyHandle, ValueName);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    else if (sPath.length() >= 29)
    {
        int nFindPos = 0;
        BOOL isBcdChange = FALSE;

        if ((nFindPos = sPath.find('\\', 29)) != string::npos)
        {
            if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\BCD00000000" + sPath.substr(nFindPos)))
            {
                isBcdChange = TRUE;
            }
        }
        else
        {
            if (Str_CompareWithoutCap(sPath, "\\REGISTRY\\MACHINE\\BCD00000000"))
            {
                isBcdChange = TRUE;
            }
        }

        if (isBcdChange)
        {
            string sendOut;

            sendOut += "[注册表防护·删除] 进程正在删除启动配置项，可能导致无法正常启动，建议阻止。\r\n\r\n";

            Suspiciousness += 50;

            if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

            sendOut += "HKEY_LOCAL_MACHINE";
            sendOut += (string)"\\";
            sendOut += (string)Str_ExtractContentAfterNSlash(sPath, 3);
            sendOut += "\r\n键名称： ";
            sendOut += sName;

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在删除启动配置项，建议阻止", GetCurrentProcessId(), (char*)"注册表防护") <= 0)
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalNtDeleteValueKey(KeyHandle, ValueName);
                }
                else
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
            }
        }
    }

    return OriginalNtDeleteValueKey(KeyHandle, ValueName);
}

// ====================================================

// ===========================================================================

// 文件防护区域 ==============================================================

// 文件操作拦截区域 ===================================

string GetDevicePath(HANDLE hDevice)
{
    STORAGE_DEVICE_NUMBER deviceNumber;
    DWORD returnedLength;

    // 获取设备号码
    if (DeviceIoControl(hDevice,
        IOCTL_STORAGE_GET_DEVICE_NUMBER,
        NULL,
        0,
        &deviceNumber,
        sizeof(deviceNumber),
        &returnedLength,
        NULL))
    {

        // 构造设备路径
        char devicePath[64];
        sprintf_s(devicePath, "\\\\.\\PhysicalDrive%d", deviceNumber.DeviceNumber);

        return devicePath;
    }
    else
    {
        return "";
    }
}

struct WRITEFILE_CACHE_ENTRY
{
    HANDLE Handle;
    BOOL   Allow;
};

thread_local std::vector<WRITEFILE_CACHE_ENTRY> g_WriteCache;

NTSTATUS calling NewNtWriteFile(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID            Buffer,
    ULONG            Length,
    PLARGE_INTEGER   ByteOffset,
    PULONG           Key
)
{
    for (auto it = g_WriteCache.begin(); it != g_WriteCache.end();)
    {
        BOOL validHandle = FALSE;

        if (it->Handle && it->Handle != INVALID_HANDLE_VALUE)
        {
            DWORD flags = 0;

            validHandle = GetHandleInformation(
                it->Handle,
                &flags
            );
        }

        if (!validHandle)
        {
            it = g_WriteCache.erase(it);
            continue;
        }

        if (it->Handle == FileHandle)
        {
            if (it->Allow)
            {
                return OriginalNtWriteFile(
                    FileHandle,
                    Event,
                    ApcRoutine,
                    ApcContext,
                    IoStatusBlock,
                    Buffer,
                    Length,
                    ByteOffset,
                    Key
                );
            }

            return ACCESS_IS_DENIED;
        }

        ++it;
    }

    bool allowWrite = true;

    string filePath =
        Str_ConvertLPWSTRToLPSTR(
            LPWSTR(
                File_GetFilePathFromHFILE(
                    FileHandle,
                    VOLUME_NAME_DOS
                ).c_str()
            )
        );

    if (filePath.empty())
    {
        return OriginalNtWriteFile(
            FileHandle,
            Event,
            ApcRoutine,
            ApcContext,
            IoStatusBlock,
            Buffer,
            Length,
            ByteOffset,
            Key
        );
    }

    // 勒索诱捕文件写入拦截
    if (isFileUnderProtection(filePath))
    {
        string sendOut;
        sendOut += "[ADV·勒索拦截] 发现可疑进程正在写入诱捕文件！可能是勒索病毒。\r\n\r\n";
        sendOut += "文件路径: ";
        sendOut += filePath;

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            g_WriteCache.push_back({FileHandle, false});
            return ACCESS_IS_DENIED;
        }
        else
        {
            WaitForResult();
            ExitHandleEvent();
            g_WriteCache.push_back({FileHandle, false});
            return ACCESS_IS_DENIED;
        }
    }

    const size_t pathLen = filePath.length();

    size_t slashPos = filePath.find_last_of('\\');

    const string filename =
        (slashPos != string::npos)
        ? filePath.substr(slashPos + 1)
        : filePath;

    if (Str_CompareWithoutCap(GetDevicePath(FileHandle), "\\\\.\\PhysicalDrive0"))
    {
        Suspiciousness += 100;

        if (CheckSuspiciousness())
        {
            allowWrite = false;
        }
        else
        {
            string sendOut =
                "[低层磁盘访问·修改] 允许进程更改系统低层磁盘，可能导致MBR被修改，系统无法进入。";

            EnterHandleEvent();

            if (Tran_OrgSendPacket(
                Tran_Server,
                (char*)sendOut.c_str(),
                PTVirusOperationConfirm,
                (char*)"有进程正在访问低层磁盘，建议立即阻止",
                GetCurrentProcessId(),
                (char*)"文件防护"
            ) > 0)
            {
                allowWrite = WaitForResult();
            }
            else
            {
                allowWrite = false;
            }

            ExitHandleEvent();
        }
    }
    else if (pathLen > 4)
    {
        size_t dotPos = filePath.find_last_of('.');

        string ext;

        if (dotPos != string::npos)
        {
            ext = filePath.substr(dotPos + 1);
        }

        const bool isLnkOrUrl =
            Str_CompareWithoutCap(ext, "lnk") ||
            Str_CompareWithoutCap(ext, "url");

        if (
            !isExplorer &&
            isLnkOrUrl &&
            Str_CompareWithoutCap(
                "\\\\?\\" + DesktopPath + "\\" + filename,
                filePath
            )
            )
        {
            Suspiciousness += 10;

            if (CheckSuspiciousness())
            {
                allowWrite = false;
            }
            else
            {
                string sendOut;

                sendOut.reserve(512);

                sendOut += "[快捷方式防护·修改] 允许进程修改桌面快捷方式，可能导致桌面混乱。\r\n\r\n";
                sendOut += "修改路径: ";
                sendOut += DesktopPath;
                sendOut += "\\";
                sendOut += filename;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(
                    Tran_Server,
                    (char*)sendOut.c_str(),
                    PTVirusOperationConfirm,
                    (char*)"检测到有进程正在修改桌面快捷方式",
                    GetCurrentProcessId(),
                    (char*)"文件防护"
                ) > 0)
                {
                    allowWrite = WaitForResult();
                }
                else
                {
                    allowWrite = false;
                }

                ExitHandleEvent();
            }
        }
        else if (
            (
                Str_CompareWithoutCap(
                    "\\\\?\\" + (string)szStartupPath + "\\" + filename,
                    filePath
                ) ||
                Str_CompareWithoutCap(
                    "\\\\?\\" + (string)szStartupPathAllUsers + "\\" + filename,
                    filePath
                )
                ) &&
            !Str_CompareWithoutCap(filename, "desktop.ini")
            )
        {
            Suspiciousness += 10;

            if (CheckSuspiciousness())
            {
                allowWrite = false;
            }
            else
            {
                string sendOut;

                sendOut.reserve(512);

                sendOut += "[文件防护·修改] 允许进程修改开机启动项，可能会减慢开机速度，并可能导致系统运行异常。\r\n\r\n";
                sendOut += "启动文件夹路径: ";
                sendOut += (string)szStartupPath;
                sendOut += "\\";
                sendOut += filename;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(
                    Tran_Server,
                    (char*)sendOut.c_str(),
                    PTVirusOperationConfirm,
                    (char*)"检测到有进程正在添加开机启动项，建议阻止",
                    GetCurrentProcessId(),
                    (char*)"文件防护"
                ) > 0)
                {
                    allowWrite = WaitForResult();
                }
                else
                {
                    allowWrite = false;
                }

                ExitHandleEvent();
            }
        }
    }

    g_WriteCache.push_back(
        {
            FileHandle,
            allowWrite
        });

    if (!allowWrite)
    {
        return ACCESS_IS_DENIED;
    }

    return OriginalNtWriteFile(
        FileHandle,
        Event,
        ApcRoutine,
        ApcContext,
        IoStatusBlock,
        Buffer,
        Length,
        ByteOffset,
        Key
    );
}

/*
// 权重配置
struct DetectionWeights
{
    double extensionWeight = 0.4;    // 可疑扩展名权重
    double rateWeight = 0.3;         // 操作速率权重
    double pathWeight = 0.2;         // 可疑路径权重
    double sequenceWeight = 0.1;     // 操作序列权重
    double supActionWeight = 0.6;    // 可疑操作权重
} g_weights;

// 检测可疑文件扩展名
double CheckSuspiciousExtension(const std::wstring& filename)
{
    std::wstring lowerFilename = filename;
    std::transform(lowerFilename.begin(), lowerFilename.end(), lowerFilename.begin(), ::towlower);

    for (const auto& ext : SUSPICIOUS_EXTFILE)
    {
        if (lowerFilename.size() >= ext.size() &&
            std::equal(ext.rbegin(), ext.rend(), lowerFilename.rbegin()))
        {
            return 1.0; // 完全匹配可疑扩展名
        }
    }
    return 0.0;
}

// 检测可疑路径
double CheckSuspiciousPath(const std::wstring& filepath)
{
    std::wstring lowerPath = filepath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    for (const auto& path : SUSPICIOUS_PATHS)
    {
        if (lowerPath.find(path) != std::wstring::npos)
        {
            for (const auto& ext : WHITE_EXTFILE)
            {
                if (lowerPath.size() >= ext.size() &&
                    std::equal(ext.rbegin(), ext.rend(), lowerPath.rbegin()))
                {
                    return 0.0;
                }
                else return 1.0;
            }
        }
    }
    return 0.0;
}

// 计算操作速率得分
double CalculateRateScore()
{
    std::shared_lock<std::shared_mutex> lock(g_opsMutex); // 共享锁，允许并发读
    auto windowStart = std::chrono::steady_clock::now() - WINDOW_DURATION;
    size_t count = 0;
    for (auto it = g_fileOperations.rbegin(); it != g_fileOperations.rend(); ++it) {
        if (it->first < windowStart) break;
        ++count;
    }
    double rate = static_cast<double>(count) / WINDOW_DURATION.count();
    return min(rate / RATE_THRESHOLD, 1.0);
}

// 检测操作序列模式 (检查是否有系统性的重命名模式)
double CheckOperationPattern()
{
    std::shared_lock<std::shared_mutex> lock(g_opsMutex);

    if (g_fileOperations.size() < 5) return 0.0;

    // 模式检测 - 检查是否有大量相同扩展名变为另一扩展名
    std::map<std::wstring, int> extChanges;

    for (size_t i = 1; i < g_fileOperations.size(); ++i)
    {
        std::wstring prevExt = PathFindExtension(g_fileOperations[i - 1].second.c_str());
        std::wstring currExt = PathFindExtension(g_fileOperations[i].second.c_str());

        if (!prevExt.empty() && !currExt.empty() && prevExt != currExt)
        {
            std::wstring change = prevExt + L"->" + currExt;
            extChanges[change]++;
        }
    }

    // 如果有超过3次相同的扩展名变化模式，认为可疑
    for (const auto& change : extChanges)
    {
        if (change.second >= 3)
        {
            return 1.0;
        }
    }

    return 0.0;
}

// 综合评分函数
double CalculateThreatScore(const std::wstring& filename)
{
    double score = 0.0;

    // 1. 检查文件扩展名
    double extScore = CheckSuspiciousExtension(filename);
    score += extScore * g_weights.extensionWeight;

    // 2. 检查路径
    double pathScore = CheckSuspiciousPath(filename);
    score += pathScore * g_weights.pathWeight;

    // 3. 计算操作速率
    double rateScore = CalculateRateScore();
    score += rateScore * g_weights.rateWeight;

    // 4. 检查操作序列模式
    double seqScore = CheckOperationPattern();
    score += seqScore * g_weights.sequenceWeight;

    // 5. Check Time
    auto NowTime = chrono::steady_clock::now();

    std::chrono::duration<double> elapsed_time = NowTime - ProcStartTime;

    // 转换为秒
    double elapsed_milliseconds = elapsed_time.count();

    score += (1 / (elapsed_milliseconds + 6.0)) + 0.1;

    // 6. Check tmp
    if (Str_EndsWith(Str_ConvertLPWSTRToLPSTR((LPWSTR)filename.c_str()), ".tmp")) score -= 1.0;

    return score;
}

*/

NTSTATUS calling NewNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
    string Path = Str_ConvertLPWSTRToLPSTR((LPWSTR)Str_PUNICODE_STRINGToWString(ObjectAttributes->ObjectName).c_str()); // 删除文件路径
    string orgPath;

    if (Path.length() > 5)
    {
        orgPath = Path.substr(4, Path.length() - 4);
    }
    else orgPath = Path;

    // MessageBoxA(NULL, Path.c_str(), "Delete", MB_TOPMOST);

    if (isFileUnderProtection(Path))
    {
        return ACCESS_IS_DENIED;
    }

    // 计算威胁分数
    // double threatScore = CalculateThreatScore(Str_ConvertLPSTRToLPWSTR((LPSTR)orgPath.c_str()));

    // string sPathLower(Path);
    // transform(sPathLower.begin(), sPathLower.end(), sPathLower.begin(), ::tolower);

   //  if (sPathLower.find("temp") && sPathLower.find("PSScriptPolicyTest")) threatScore -= 0.1;

    if (File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR((LPSTR)orgPath.c_str())))
    {
        Suspiciousness += 20;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        string sendOut;

        sendOut += "[系统保护] 发现进程正在删除系统文件！\r\n\r\n";
        sendOut += "目标路径: ";
        sendOut += Path.substr(4);

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"进程极有可能删除系统文件！", GetCurrentProcessId(), (char*)"文件防护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }
    /*else if (threatScore >= 0.7)
    {
        Suspiciousness += 40;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        string sendOut;

        sendOut += "[ADV·勒索拦截] 发现可疑进程，可能是勒索病毒。\r\n\r\n当前目标: ";
        sendOut += Str_ConvertLPWSTRToLPSTR(Str_ConvertLPSTRToLPWSTR((LPSTR)orgPath.c_str()));

        if (isScriptScan && thisScriptPath.length() >= 2)
        {
            sendOut += "\r\n脚本病毒文件路径: ";
            sendOut += thisScriptPath;
        }

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"文件防护", WDT_Normal, true) <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }*/

    return OriginalNtDeleteFile(ObjectAttributes);
}

NTSTATUS calling NewNtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
)
{
    for (auto tid : ThisProtectionTid_NtCreateFile) // 防死锁
    {
        if (tid == GetCurrentThreadId())
        {
            return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
        }
    }

    if (ObjectAttributes && !isExplorer && ObjectAttributes->ObjectName)
    {
        string Path = Str_ConvertLPWSTRToLPSTR((LPWSTR)Str_PUNICODE_STRINGToWString(ObjectAttributes->ObjectName).c_str());

        string::size_type iPos;
        string filename, orgPath;
        if (Path.length() > 5)
        {
            iPos = Path.find_last_of('\\') + 1;
            filename = Path.substr(iPos, Path.length() - iPos);
            orgPath = Path.substr(4, Path.length() - 4);
        }
        else orgPath = Path;

        // MessageBoxA(NULL, Path.substr(0, Path.find_last_of('.')).c_str(), "CreateFile", MB_TOPMOST | MB_ICONERROR);

        if ((isScriptScan || !isWindowsFile) && Str_CompareWithoutCap(orgPath, Str_ConvertLPWSTRToLPSTR((LPWSTR)((wstring)wcSystemRootPath + L"\\config\\OSDATA").c_str())))
        {
            Suspiciousness += 100;

            if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

            string sendOut;

            sendOut += "[漏洞·利用拦截] 发现进程正在创建OSDATA文件，可能导致系统反复蓝屏。鉴于其行为，拦截时将直接终止进程。";
            sendOut += Path.substr(4);

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"漏洞利用拦截", GetCurrentProcessId(), (char*)"漏洞利用", WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                }
                else
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
            }
        }

        // 做hook规避
        ULONG hTid = GetCurrentThreadId();
        ThisProtectionTid_NtCreateFile.push_back(hTid);
        BOOL hSFC = File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR((LPSTR)orgPath.c_str()));
        ThisProtectionTid_NtCreateFile.erase(remove(ThisProtectionTid_NtCreateFile.begin(), ThisProtectionTid_NtCreateFile.end(), hTid), ThisProtectionTid_NtCreateFile.end());

        if (!isWindowsFile || isScriptScan)
        {
            if ((hSFC || isFileUnderWindowsDirectory(Path)) && ((CreateOptions & FILE_DELETE_ON_CLOSE) != 0))
            {
                Suspiciousness += 20;

                if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                string sendOut;

                sendOut += "[系统保护] 发现进程极有可能删除系统文件！\r\n\r\n";
                sendOut += "目标路径: ";
                sendOut += orgPath;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"进程极有可能删除系统文件！", GetCurrentProcessId(), (char*)"系统保护") <= 0)
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
                else
                {
                    if (WaitForResult())
                    {
                        ExitHandleEvent();
                        
                        return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
                    }
                    else
                    {
                        ExitHandleEvent();
                        return ACCESS_IS_DENIED;
                    }
                }
            }
        }
        else if ((!isWindowsFile || isScriptScan) && (isFileUnderProtection(Path.substr(0, Path.find_last_of('.'))) || isFileUnderProtection(Path))
            && ((CreateOptions & FILE_DELETE_ON_CLOSE) != 0)) // 拦截删除
        {
            Suspiciousness += 20;
            if (Path.substr(Path.find_last_of('.')).length() >= 6) Suspiciousness += 40;

            if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

            string sendOut;

            sendOut += "[ADV·勒索拦截] 发现可疑进程！可能是勒索病毒。";

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
                else
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
            }
        }

        if (isScriptScan && !hSFC)
        {
            if (Str_EndsWith(orgPath, ".ps1") || Str_EndsWith(orgPath, ".vbs") || Str_EndsWith(orgPath, ".js") || Str_EndsWith(orgPath, ".cmd") || Str_EndsWith(orgPath, ".bat"))
            {
                thisScriptPath = orgPath;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)orgPath.c_str(), PTVirusOperationConfirm, (char*)"AskForScanScript", GetCurrentProcessId(), (char*)"脚本病毒", WDT_Normal, true) <= 0)
                {
                    ExitHandleEvent();
                    return VIRUS_FOUND;
                }
                else
                {
                    if (WaitForResult())
                    {
                        ExitHandleEvent();
                        return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
                    }
                    else
                    {
                        ExitHandleEvent();
                        return VIRUS_FOUND;
                    }
                }
            }
        }
    }

    return OriginalNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS calling NewNtOpenFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess,
    ULONG OpenOptions
)
{
    for (auto tid : ThisProtectionTid_NtOpenFile)
    {
        if (tid == GetCurrentThreadId())
        {
            return OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
        }
    }

    if (ObjectAttributes && !isExplorer && ObjectAttributes->ObjectName)
    {
        string Path = Str_ConvertLPWSTRToLPSTR((LPWSTR)Str_PUNICODE_STRINGToWString(ObjectAttributes->ObjectName).c_str());

        string::size_type iPos;
        string filename, orgPath;
        if (Path.length() > 5)
        {
            iPos = Path.find_last_of('\\') + 1;
            filename = Path.substr(iPos, Path.length() - iPos);
            orgPath = Path.substr(4, Path.length() - 4);
        }
        else orgPath = Path;

        // 做hook规避
        ULONG hTid = GetCurrentThreadId();
        ThisProtectionTid_NtOpenFile.push_back(hTid);
        BOOL hSFC = File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR((LPSTR)orgPath.c_str()));
        ThisProtectionTid_NtOpenFile.erase(remove(ThisProtectionTid_NtOpenFile.begin(), ThisProtectionTid_NtOpenFile.end(), hTid), ThisProtectionTid_NtOpenFile.end());

        if (isScriptScan && !hSFC)
        {
            if (Str_EndsWith(orgPath, ".ps1") || Str_EndsWith(orgPath, ".vbs") || Str_EndsWith(orgPath, ".js") || Str_EndsWith(orgPath, ".cmd") || Str_EndsWith(orgPath, ".bat"))
            {
                thisScriptPath = orgPath;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)orgPath.c_str(), PTVirusOperationConfirm, (char*)"AskForScanScript", GetCurrentProcessId(), (char*)"脚本病毒", WDT_Normal, true) <= 0)
                {
                    ExitHandleEvent();
                    return VIRUS_FOUND;
                }
                else
                {
                    if (WaitForResult())
                    {
                        ExitHandleEvent();
                        return OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
                    }
                    else
                    {
                        ExitHandleEvent();
                        return VIRUS_FOUND;
                    }
                }
            }
        }

        if (!isWindowsFile || isScriptScan)
        {
            if (isFileUnderProtection(Path) && ((OpenOptions & FILE_DELETE_ON_CLOSE) != 0))
            {
                return ACCESS_IS_DENIED;
            }

            if ((hSFC || isFileUnderWindowsDirectory(Path)) && ((OpenOptions & FILE_DELETE_ON_CLOSE) != 0))
            {
                Suspiciousness += 20;

                if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                string sendOut;

                sendOut += "[系统保护] 发现进程极有可能删除系统文件！\r\n\r\n";
                sendOut += "目标路径: ";
                sendOut += orgPath;

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"进程极有可能删除系统文件！", GetCurrentProcessId(), (char*)"系统保护") <= 0)
                {
                    ExitHandleEvent();
                    return ACCESS_IS_DENIED;
                }
                else
                {
                    if (WaitForResult())
                    {
                        ExitHandleEvent();
                        return OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
                    }
                    else
                    {
                        ExitHandleEvent();
                        return ACCESS_IS_DENIED;
                    }
                }
            }
        }
    }

    return OriginalNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
}

NTSTATUS calling NewNtQueryDirectoryFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    BOOLEAN ReturnSingleEntry,
    PUNICODE_STRING FileName,
    BOOLEAN RestartScan
)
{
    NTSTATUS status = OriginalNtQueryDirectoryFile(
        FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        FileInformation, Length, FileInformationClass, ReturnSingleEntry,
        FileName, RestartScan
    );

    if (isExplorer) // explorer 用户隐藏
    {
        string filePath = Str_ConvertLPWSTRToLPSTR(LPWSTR(File_GetFilePathFromHFILE(FileHandle, VOLUME_NAME_DOS).c_str()));
        if (status == STATUS_SUCCESS)
        {
            /* 支持所有常见目录信息类，避免 explorer 使用非 FileIdBothDirectoryInformation
             * 查询时诱捕文件未被隐藏。
             *
             * 所有信息类的字段布局：
             *   NextEntryOffset  — ULONG @ 偏移 0（所有信息类固定）
             *   FileNameLength   — ULONG @ 偏移 60（前 7 个字段固定 60 字节：
             *                       NextEntryOffset(4) + FileIndex(4) + 6×LARGE_INTEGER(48) +
             *                       FileAttributes(4) = 60）
             *                     — 例外：FileNamesInformation 的 FileNameLength @ 偏移 8
             *   FileName         — WCHAR[] @ 偏移按信息类不同（含对齐）
             *
             * FileName 偏移（基于 WDK 公开结构体定义）：
             *   FileDirectoryInformation(1)        = 64
             *   FileFullDirectoryInformation(2)    = 68  (+EaSize)
             *   FileBothDirectoryInformation(3)    = 94  (+EaSize+ShortName[12])
             *   FileIdBothDirectoryInformation(37) = 104 (+pad+FileId)
             *   FileIdFullDirectoryInformation(38) = 80  (+pad+FileId)
             *   FileNamesInformation(12)           = 12  (仅 NextEntryOffset+FileIndex+FileNameLength)
             * 使用常量偏移避免引入 winternl.h（与 define.h 自定义 NT 结构体冲突）。 */
            ULONG fileNameOffset = 0;
            ULONG fileNameLenOffset = 60;  /* FileNameLength 在大多数信息类中固定 @60 */
            bool supported = true;

            switch (FileInformationClass)
            {
                case FileDirectoryInformation:       /* 1  -> FileName@64, FileNameLength@60 */
                    fileNameOffset = 64;
                    break;
                case FileFullDirectoryInformation:   /* 2  -> FileName@68, FileNameLength@60 */
                    fileNameOffset = 68;
                    break;
                case FileBothDirectoryInformation:    /* 3  -> FileName@94, FileNameLength@60 */
                    fileNameOffset = 94;
                    break;
                case FileIdBothDirectoryInformation:  /* 37 -> FileName@104, FileNameLength@60 */
                    fileNameOffset = 104;
                    break;
                case FileIdFullDirectoryInformation:  /* 38 -> FileName@80, FileNameLength@60 */
                    fileNameOffset = 80;
                    break;
                case FileNamesInformation:           /* 12 -> FileName@12, FileNameLength@8 */
                    fileNameOffset = 12;
                    fileNameLenOffset = 8;
                    break;
                default:
                    supported = false;
                    break;
            }

            if (supported)
            {
                PBYTE pBase = (PBYTE)FileInformation;
                ULONG bufferLen = (ULONG)IoStatusBlock->Information;
                PBYTE pEnd = pBase + bufferLen;
                PBYTE pCur = pBase;
                PBYTE pPrev = nullptr;

                /* 遍历目录条目链表，隐藏匹配诱捕文件的条目。
                 * 每个条目以 NextEntryOffset(ULONG@0) 链接，0 表示最后一条。
                 * FileNameLength(ULONG@fileNameLenOffset) 指定 FileName 字段长度。 */
                while (pCur + fileNameOffset + sizeof(ULONG) <= pEnd)
                {
                    ULONG nextOff = *(PULONG)pCur;
                    ULONG nameLen = *(PULONG)(pCur + fileNameLenOffset);

                    /* 文件名长度越界保护，防止构造 wstring 时读越界崩溃 */
                    if (nameLen > (ULONG)(pEnd - (pCur + fileNameOffset)))
                        break;

                    wstring currentFileName;
                    if (nameLen > 0 && (nameLen % sizeof(WCHAR)) == 0)
                    {
                        currentFileName.assign((PWCH)(pCur + fileNameOffset),
                                               nameLen / sizeof(WCHAR));
                    }

                    BOOL shouldHide = isFileUnderProtection(
                        filePath + "\\" + Str_ConvertLPWSTRToLPSTR((LPWSTR)currentFileName.c_str()));

                    if (shouldHide)
                    {
                        if (pPrev)
                        {
                            /* 非首条目：调整前一条目的 NextEntryOffset 跳过本条目 */
                            if (nextOff == 0)
                                *(PULONG)pPrev = 0;
                            else
                                *(PULONG)pPrev = (ULONG)(pCur - pPrev) + nextOff;
                        }
                        else
                        {
                            /* 首条目需隐藏：不能仅改局部指针（调用方仍看到原缓冲区），
                             * 必须将后续条目前移覆盖首条目 */
                            if (nextOff == 0)
                            {
                                /* 首条目即唯一条目：返回无更多文件 */
                                IoStatusBlock->Information = 0;
                                return 0x8000001a; // STATUS_NO_MORE_FILES
                            }
                            /* 将 nextOff 之后的所有数据前移到缓冲区起始 */
                            ULONG remainingBytes = (ULONG)(pEnd - (pCur + nextOff));
                            if (remainingBytes > 0)
                                memmove(pBase, pCur + nextOff, remainingBytes);
                            bufferLen -= nextOff;
                            pEnd = pBase + bufferLen;
                            IoStatusBlock->Information = bufferLen;
                            /* 从头重新扫描新缓冲区（pPrev 保持 nullptr） */
                            pCur = pBase;
                            continue;
                        }
                    }
                    else
                    {
                        pPrev = pCur;
                    }

                    if (nextOff == 0) break;
                    pCur += nextOff;
                }
            }
        }
    }

    return status;
}


typedef struct _FILE_DISPOSITION_INFORMATION
{
    BOOLEAN IsDeleteFile;
} FILE_DISPOSITION_INFORMATION, * PFILE_DISPOSITION_INFORMATION;

typedef struct _FILE_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} FILE_DISPOSITION_INFORMATION_EX, * PFILE_DISPOSITION_INFORMATION_EX;


// 拦截重命名

NTSTATUS calling NewNtSetInformationFile(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass)
{
    if (FileHandle)
    {
        // 检查是否是重命名操作
        if (FileInformationClass == FileRenameInformation)
        {
            wstring NorPath = File_GetFilePathFromHFILE(FileHandle, FILE_NAME_NORMALIZED).c_str();

            NorPath[1] = '?';

            if (isFileUnderProtection(Str_ConvertLPWSTRToLPSTR(LPWSTR(File_GetFilePathFromHFILE(FileHandle, VOLUME_NAME_DOS).c_str()))))
            {
                Suspiciousness += 20;

                if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                string sendOut;

                sendOut += "[勒索拦截] 发现可疑进程正在重命名勒索诱捕文件！可能是勒索病毒。";

                EnterHandleEvent();

                if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) > 0)
                {
                    WaitForResult();
                }

                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }

            if (!isWindowsFile || isScriptScan)
            {
                /*
                auto renameInfo = reinterpret_cast<PFILE_RENAME_INFORMATION>(FileInformation);
                if (renameInfo && renameInfo->FileNameLength > 0)
                {
                    wstring newFilename(renameInfo->FileName, renameInfo->FileNameLength / sizeof(WCHAR));

                    // 获取原始文件名
                    wchar_t originalName[MAX_PATH] = { 0 };
                    if (GetFinalPathNameByHandleW(FileHandle, originalName, MAX_PATH, FILE_NAME_NORMALIZED))
                    {
                        auto now = chrono::steady_clock::now();

                        {
                            std::unique_lock<std::shared_mutex> lock(g_opsMutex);
                            g_fileOperations.emplace_back(now, NorPath);

                            // 保持窗口大小
                            if (g_fileOperations.size() > WINDOW_SIZE * 2)
                            {
                                g_fileOperations.erase(g_fileOperations.begin(),
                                    g_fileOperations.begin() + (g_fileOperations.size() - WINDOW_SIZE));
                            }
                        }

                        // 计算威胁分数
                        double threatScore = CalculateThreatScore(NorPath);

                        string hanedstr = (string(Str_ConvertLPWSTRToLPSTR(originalName))).substr(4);

                        for (const auto& ext : SUSPICIOUS_EXTFILE)
                        {
                            if (Str_EndsWith(hanedstr, ext))
                            {
                                threatScore += 0.1;
                                break;
                            }
                        }

                        // 威胁分数超过阈值
                        if (threatScore >= 0.7)
                        {
                            Suspiciousness += 40;

                            if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                            string sendOut;

                            sendOut += "[ADV·勒索拦截] 发现可疑进程，可能是勒索病毒。\r\n\r\n当前目标: ";
                            sendOut += hanedstr;

                            if (isScriptScan && thisScriptPath.length() >= 2)
                            {
                                sendOut += "\r\n脚本病毒文件路径: ";
                                sendOut += thisScriptPath;
                            }

                            EnterHandleEvent();

                            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                            else
                            {
                                if (WaitForResult())
                                {
                                    ExitHandleEvent();
                                    return OriginalNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
                                }
                                else
                                {
                                    ExitHandleEvent();
                                    return ACCESS_IS_DENIED;
                                }
                            }
                        }
                    }
                }
                */
            }
        }
        else if (!isWindowsFile || isScriptScan)
        {
            string NorPath = Str_ConvertLPWSTRToLPSTR((LPWSTR)File_GetFilePathFromHFILE(FileHandle, FILE_NAME_NORMALIZED).c_str());

            NorPath[1] = '?';

            if (FileInformationClass == FileDispositionInformation)
            {
                FILE_DISPOSITION_INFORMATION* dispInfo = (FILE_DISPOSITION_INFORMATION*)FileInformation;

                if (dispInfo->IsDeleteFile)
                {
                    if (isFileUnderProtection(NorPath))
                    {
                        Suspiciousness += 40;

                        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                        string sendOut;

                        sendOut += "[ADV·勒索拦截] 发现可疑进程！可能是勒索病毒。";

                        EnterHandleEvent();

                        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
                        {
                            ExitHandleEvent();
                            return ACCESS_IS_DENIED;
                        }
                        else
                        {
                            if (WaitForResult())
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                            else
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                        }
                    }
                    /*

                    auto now = chrono::steady_clock::now();

                    {
                        std::unique_lock<std::shared_mutex> lock(g_opsMutex);
                        g_fileOperations.emplace_back(now, Str_ConvertLPSTRToLPWSTR((char*)NorPath.substr(4).c_str()));

                        // 保持窗口大小
                        if (g_fileOperations.size() > WINDOW_SIZE * 2)
                        {
                            g_fileOperations.erase(g_fileOperations.begin(),
                                g_fileOperations.begin() + (g_fileOperations.size() - WINDOW_SIZE));
                        }
                    }

                    // 计算威胁分数
                    double threatScore = CalculateThreatScore(Str_ConvertLPSTRToLPWSTR((char*)NorPath.substr(4).c_str()));

                    // 威胁分数超过阈值
                    if (threatScore >= 0.7)
                    {
                        Suspiciousness += 40;

                        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                        string sendOut;

                        sendOut += "[ADV·勒索拦截] 发现可疑进程，可能是勒索病毒。\r\n\r\n当前目标: ";
                        sendOut += NorPath.substr(4);

                        if (isScriptScan && thisScriptPath.length() >= 2)
                        {
                            sendOut += "\r\n脚本病毒文件路径: ";
                            sendOut += thisScriptPath;
                        }

                        EnterHandleEvent();

                        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
                        {
                            ExitHandleEvent();
                            return ACCESS_IS_DENIED;
                        }
                        else
                        {
                            if (WaitForResult())
                            {
                                ExitHandleEvent();
                                return OriginalNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
                            }
                            else
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                        }
                    }
                    */

                    // MessageBoxA(NULL, (char*)NorPath.c_str(), "Rename - 2", MB_TOPMOST);

                    if (File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR((char*)NorPath.c_str())))
                    {
                        Suspiciousness += 20;

                        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                        string sendOut;

                        sendOut += "[系统保护] 发现进程正在删除系统文件！\r\n\r\n";
                        sendOut += "目标路径: ";
                        sendOut += NorPath.substr(4);

                        EnterHandleEvent();

                        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"进程正在删除系统文件！", GetCurrentProcessId(), (char*)"系统保护") <= 0)
                        {
                            ExitHandleEvent();
                            return ACCESS_IS_DENIED;
                        }
                        else
                        {
                            if (WaitForResult())
                            {
                                ExitHandleEvent();
                                return OriginalNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
                            }
                            else
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                        }
                    }
                }
            }
            else if (FileInformationClass == FileDispositionInformationEx)
            {
                FILE_DISPOSITION_INFORMATION_EX* dispInfo = (FILE_DISPOSITION_INFORMATION_EX*)FileInformation;

                if ((dispInfo->Flags & FILE_DISPOSITION_DELETE) != 0)
                {
                    if (isFileUnderProtection(NorPath))
                    {
                        Suspiciousness += 40;

                        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                        string sendOut;

                        sendOut += "[ADV·勒索拦截] 发现可疑进程！可能是勒索病毒。";

                        EnterHandleEvent();

                        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
                        {
                            ExitHandleEvent();
                            return ACCESS_IS_DENIED;
                        }
                        else
                        {
                            if (WaitForResult())
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                            else
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                        }
                    }

                    /*

                    auto now = chrono::steady_clock::now();

                    {
                        std::unique_lock<std::shared_mutex> lock(g_opsMutex);
                        g_fileOperations.emplace_back(now, Str_ConvertLPSTRToLPWSTR((char*)NorPath.substr(4).c_str()));

                        // 保持窗口大小
                        if (g_fileOperations.size() > WINDOW_SIZE * 2)
                        {
                            g_fileOperations.erase(g_fileOperations.begin(),
                                g_fileOperations.begin() + (g_fileOperations.size() - WINDOW_SIZE));
                        }
                    }

                    // 计算威胁分数
                    double threatScore = CalculateThreatScore(Str_ConvertLPSTRToLPWSTR((char*)NorPath.substr(4).c_str()));

                    // 威胁分数超过阈值
                    if (threatScore >= 0.7)
                    {
                        Suspiciousness += 40;

                        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                        string sendOut;

                        sendOut += "[ADV·勒索拦截] 发现可疑进程，可能是勒索病毒。\r\n\r\n当前目标: ";
                        sendOut += NorPath.substr(4);

                        if (isScriptScan && thisScriptPath.length() >= 2)
                        {
                            sendOut += "\r\n脚本病毒文件路径: ";
                            sendOut += thisScriptPath;
                        }

                        EnterHandleEvent();

                        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"勒索病毒拦截", GetCurrentProcessId(), (char*)"勒索病毒", WDT_Normal, true) <= 0)
                        {
                            ExitHandleEvent();
                            return ACCESS_IS_DENIED;
                        }
                        else
                        {
                            if (WaitForResult())
                            {
                                ExitHandleEvent();
                                return OriginalNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
                            }
                            else
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                        }
                    }
                    */

                    if (File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR((char*)NorPath.c_str())))
                    {
                        Suspiciousness += 20;

                        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

                        string sendOut;

                        sendOut += "[系统保护] 发现进程正在删除系统文件！\r\n\r\n";
                        sendOut += "目标路径: ";
                        sendOut += NorPath.substr(4);

                        EnterHandleEvent();

                        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"进程正在删除系统文件！", GetCurrentProcessId(), (char*)"系统保护") <= 0)
                        {
                            ExitHandleEvent();
                            return ACCESS_IS_DENIED;
                        }
                        else
                        {
                            if (WaitForResult())
                            {
                                ExitHandleEvent();
                                return OriginalNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
                            }
                            else
                            {
                                ExitHandleEvent();
                                return ACCESS_IS_DENIED;
                            }
                        }
                    }
                }
            }
        }
    }

    return OriginalNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
}

// ====================================================

// ===========================================================================

// 隐私保护区域 ==============================================================

HRESULT WINAPI NewMFCreateDeviceSource(IMFAttributes* pAttributes, IMFMediaSource** ppSource)
{
    string sendOut;

    sendOut += "[隐私防护·启动] 进程正在试图访问 Media Foundation，可能侵犯隐私。";

    Suspiciousness += 30;

    if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在使用摄像头，建议阻止", GetCurrentProcessId(), (char*)"开机启动项") <= 0)
    {
        ExitHandleEvent();
        return ACCESS_IS_DENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalMFCreateDeviceSource(pAttributes, ppSource);
        }
        else
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
    }
}

// 用户区域 ===========================================

NET_API_STATUS NewNetUserAdd(
    _In_opt_  LPCWSTR    servername OPTIONAL,
    _In_      DWORD      level,
    _When_(level == 1, _In_reads_bytes_(sizeof(USER_INFO_1)))
    _When_(level == 2, _In_reads_bytes_(sizeof(USER_INFO_2)))
    _When_(level == 3, _In_reads_bytes_(sizeof(USER_INFO_3)))
    _When_(level == 4, _In_reads_bytes_(sizeof(USER_INFO_4)))
    LPBYTE     buf,
    _Out_opt_ LPDWORD    parm_err OPTIONAL
)
{
    wstring Name, Password;
    DWORD Pri = 0;
    if (level == 1)
    {
        USER_INFO_1 UI = *((USER_INFO_1*)buf);
        Name = UI.usri1_name;
        Password = UI.usri1_password;
        Pri = UI.usri1_priv;
    }
    else if (level == 2)
    {
        USER_INFO_2 UI = *((USER_INFO_2*)buf);
        Name = UI.usri2_name;
        Password = UI.usri2_password;
        Pri = UI.usri2_priv;
    }
    else if (level == 3)
    {
        USER_INFO_3 UI = *((USER_INFO_3*)buf);
        Name = UI.usri3_name;
        Password = UI.usri3_password;
        Pri = UI.usri3_priv;
    }
    else if (level == 4)
    {
        USER_INFO_4 UI = *((USER_INFO_4*)buf);
        Name = UI.usri4_name;
        Password = UI.usri4_password;
        Pri = UI.usri4_priv;
    }

    string priv;

    switch (Pri)
    {
    case USER_PRIV_GUEST:
        priv = "客人(GUEST)";
        break;
    case USER_PRIV_USER:
        priv = "用户(USER)";
        break;
    case USER_PRIV_ADMIN:
        priv = "管理员(ADMIN)";
        break;
    default:
        priv = "未知级别(UNKNOWN)";
        break;
    }

    string sendOut;

    sendOut += "[账户防护·创建] 允许进程新建用户，可能不安全。\r\n\r\n";

    Suspiciousness += 10;

    if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

    sendOut += "用户名: ";
    sendOut += Str_ConvertLPWSTRToLPSTR((LPWSTR)Name.c_str());
    sendOut += " (";
    sendOut += priv;
    sendOut += ")";
    sendOut += "\r\n密码：";
    sendOut += Str_ConvertLPWSTRToLPSTR((LPWSTR)Password.c_str());

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"有进程正在新建用户，建议阻止", GetCurrentProcessId(), (char*)"系统保护") <= 0)
    {
        ExitHandleEvent();
        SetLastError(5);
        return ERROR_ACCESS_DENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalNetUserAdd(servername, level, buf, parm_err);
        }
        else
        {
            ExitHandleEvent();
            SetLastError(5);
            return ERROR_ACCESS_DENIED;
        }
    }
}

NET_API_STATUS NewNetUserSetInfo(
    _In_opt_  LPCWSTR    servername OPTIONAL,
    _In_      LPCWSTR    username,
    _In_      DWORD     level,
    _In_reads_(_Inexpressible_("varies")) LPBYTE buf,
    _Out_opt_ LPDWORD   parm_err OPTIONAL
)
{
    wstring Password;

    if (level == 1)
    {
        USER_INFO_1 UI = *((USER_INFO_1*)buf);
        Password = UI.usri1_password;
    }
    else if (level == 2)
    {
        USER_INFO_2 UI = *((USER_INFO_2*)buf);
        Password = UI.usri2_password;
    }
    else if (level == 3)
    {
        USER_INFO_3 UI = *((USER_INFO_3*)buf);
        Password = UI.usri3_password;
    }
    else if (level == 4)
    {
        USER_INFO_4 UI = *((USER_INFO_4*)buf);
        Password = UI.usri4_password;
    }
    else if (level == 1003)
    {
        USER_INFO_1003 UI = *((USER_INFO_1003*)buf);
        Password = UI.usri1003_password;
    }

    string sendOut;

    sendOut += "[账户防护·修改] 允许进程修改用户密码，可能不安全。\r\n\r\n";

    Suspiciousness += 10;

    if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

    sendOut += "用户名: ";
    sendOut += Str_ConvertLPWSTRToLPSTR((LPWSTR)username);
    sendOut += "\r\n密码：";
    sendOut += Str_ConvertLPWSTRToLPSTR((LPWSTR)Password.c_str());

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"有进程正在修改用户密码，建议阻止", GetCurrentProcessId(), (char*)"系统保护") <= 0)
    {
        ExitHandleEvent();
        SetLastError(5);
        return ERROR_ACCESS_DENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalNetUserSetInfo(servername, username, level, buf, parm_err);
        }
        else
        {
            ExitHandleEvent();
            SetLastError(5);
            return ERROR_ACCESS_DENIED;
        }
    }
}

NET_API_STATUS NewNetUserDel(
    _In_opt_  LPCWSTR    servername OPTIONAL,
    _In_      LPCWSTR    username
)
{
    string sendOut;

    sendOut += "[账户防护·删除] 允许进程删除用户，可能不安全。\r\n\r\n";

    Suspiciousness += 10;

    if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

    sendOut += "用户名: ";
    sendOut += Str_ConvertLPWSTRToLPSTR((LPWSTR)username);

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"有进程正在删除用户，建议阻止", GetCurrentProcessId(), (char*)"系统保护") <= 0)
    {
        ExitHandleEvent();
        SetLastError(5);
        return ERROR_ACCESS_DENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalNetUserDel(servername, username);
        }
        else
        {
            ExitHandleEvent();
            SetLastError(5);
            return ERROR_ACCESS_DENIED;
        }
    }
}

// ====================================================

// 鼠标防护区域 =======================================
int AntiPosCounter = 0;
ULONGLONG AntiPosStart = 0;

BOOL NewSetCursorPos(int X, int Y)
{
    if (AntiPosCounter == 0)
    {
        AntiPosStart = GetTickCount64();

        AntiPosCounter++;

        return OriginalSetCursorPos(X, Y);
    }
    else
    {
        AntiPosCounter++;

        if (AntiPosCounter >= 10 && GetTickCount64() - AntiPosStart <= 2000)
        {
            Suspiciousness += 40;

            string sendOut;

            sendOut += "[ADV·恶意拦截] 发现可疑进程频繁操控鼠标，可能影响用户使用体验，还可能是远控、勒索，建议拦截以终止进程。\r\n\r\n";

            EnterHandleEvent();

            if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程频繁操控鼠标", GetCurrentProcessId(), (char*)"系统保护", WDT_Normal, true) <= 0)
            {
                ExitHandleEvent();
                SetLastError(5);
                return ERROR_ACCESS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalSetCursorPos(X, Y);
                }
                else
                {
                    ExitHandleEvent();
                    SetLastError(5);
                    return ERROR_ACCESS_DENIED;
                }
            }
        }
        else if (AntiPosCounter > 10)
        {
            AntiPosCounter = 0;
            AntiPosStart = GetTickCount64();

            return OriginalSetCursorPos(X, Y);
        }
        else return OriginalSetCursorPos(X, Y);
    }
}

BOOL NewSetPhysicalCursorPos(int X, int Y)
{
    if (AntiPosCounter == 0)
    {
        AntiPosStart = GetTickCount64();

        AntiPosCounter++;

        return OriginalSetPhysicalCursorPos(X, Y);
    }
    else
    {
        AntiPosCounter++;

        if (AntiPosCounter >= 10 && GetTickCount64() - AntiPosStart <= 2000)
        {
            Suspiciousness += 40;

            string sendOut;

            sendOut += "[ADV·恶意拦截] 发现可疑进程频繁操控鼠标，可能影响用户使用体验，还可能是远控、勒索，建议拦截以终止进程。\r\n\r\n";

            EnterHandleEvent();

            if ((Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"发现可疑进程频繁操控鼠标", GetCurrentProcessId(), (char*)"系统保护", WDT_Normal, true)) <= 0)
            {
                ExitHandleEvent();
                SetLastError(5);
                return ERROR_ACCESS_DENIED;
            }
            else
            {
                if (WaitForResult())
                {
                    ExitHandleEvent();
                    return OriginalSetPhysicalCursorPos(X, Y);
                }
                else
                {
                    ExitHandleEvent();
                    SetLastError(5);
                    return ERROR_ACCESS_DENIED;
                }
            }
        }
        else if (AntiPosCounter > 10)
        {
            AntiPosCounter = 0;
            AntiPosStart = GetTickCount64();

            return OriginalSetPhysicalCursorPos(X, Y);
        }
        else return OriginalSetPhysicalCursorPos(X, Y);
    }
}


// ====================================================

// 系统时间设置区域 ===================================

NTSTATUS calling NewNtSetSystemTime(
    _In_opt_ PLARGE_INTEGER SystemTime,
    _Out_opt_ PLARGE_INTEGER PreviousTime
)
{
    if (!isWindowsFile || isScriptScan)
    {
        string sendOut;

        sendOut += "[隐私防护·设置] 进程正在试图设置系统时间，此操作并不常见，可能是木马程序。";

        Suspiciousness += 30;

        if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

        EnterHandleEvent();

        if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在使用摄像头，建议阻止", GetCurrentProcessId(), (char*)"系统保护") <= 0)
        {
            ExitHandleEvent();
            return ACCESS_IS_DENIED;
        }
        else
        {
            if (WaitForResult())
            {
                ExitHandleEvent();
                return OriginalNtSetSystemTime(SystemTime, PreviousTime);
            }
            else
            {
                ExitHandleEvent();
                return ACCESS_IS_DENIED;
            }
        }
    }

    return OriginalNtSetSystemTime(SystemTime, PreviousTime);
}


// ====================================================

// 摄像头防护区域 =====================================

HRESULT WINAPI NewDirectShowCreate(const GUID* clsid, void** ppv, const GUID* iid)
{
    string sendOut;

    sendOut += "[隐私防护·启动] 进程正在试图使用摄像头，可能侵犯隐私。";

    Suspiciousness += 30;

    if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在使用摄像头，建议阻止", GetCurrentProcessId(), (char*)"系统保护") <= 0)
    {
        ExitHandleEvent();
        return E_ACCESSDENIED;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalDirectShowCreate(clsid, ppv, iid);
        }
        else
        {
            ExitHandleEvent();
            return E_ACCESSDENIED;
        }
    }
}

// ====================================================

// 麦克风防护区域 =====================================

MMRESULT WINAPI NewWaveInOpen(LPHWAVEIN phwi, UINT uDeviceID, LPCWAVEFORMATEX pwfx,
    DWORD_PTR dwCallback, DWORD_PTR dwInstance, DWORD fdwOpen)
{
    string sendOut;

    sendOut += "[隐私防护·启动] 进程正在试图使用麦克风，可能侵犯隐私。";

    Suspiciousness += 30;

    if (CheckSuspiciousness()) return ACCESS_IS_DENIED;

    EnterHandleEvent();

    if (Tran_OrgSendPacket(Tran_Server, (char*)sendOut.c_str(), PTVirusOperationConfirm, (char*)"检测到有进程正在使用麦克风，建议阻止", GetCurrentProcessId(), (char*)"系统保护") <= 0)
    {
        ExitHandleEvent();
        return MMSYSERR_ERROR;
    }
    else
    {
        if (WaitForResult())
        {
            ExitHandleEvent();
            return OriginalWaveInOpen(phwi, uDeviceID, pwfx, dwCallback, dwInstance, fdwOpen);
        }
        else
        {
            ExitHandleEvent();
            return MMSYSERR_ERROR;
        }
    }
}

// ====================================================

// ===========================================================================

void StartHook()
{
    // 初始化
    HMODULE hNt = LoadLibraryW(L"ntdll.dll");

    if (!hNt)
    {
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    OriginalNtResumeThread = (NtResumeThread)GetProcAddress(hNt, "NtResumeThread");
    OriginalNtResumeProcess = (NtResumeProcess)GetProcAddress(hNt, "NtResumeProcess");
    OriginalNtCreateUserProcess = (NtCreateUserProcess)GetProcAddress(hNt, "NtCreateUserProcess");
    OriginalNtSetValueKey = (NtSetValueKey)GetProcAddress(hNt, "NtSetValueKey");
    OriginalNtWriteFile = (NtWriteFile)GetProcAddress(hNt, "NtWriteFile");
    OriginalNtRaiseHardError = (NtRaiseHardError)GetProcAddress(hNt, "NtRaiseHardError");
    OriginalPspTerminateThreadByPointer = (PspTerminateThreadByPointer)GetProcAddress(hNt, "PspTerminateThreadByPointer");
    OriginalPspTerminateProcess = (PspTerminateProcess)GetProcAddress(hNt, "PspTerminateProcess");
    OriginalNtTerminateProcess = (NtTerminateProcess)GetProcAddress(hNt, "NtTerminateProcess");
    OriginalNtDebugActiveProcess = (NtDebugActiveProcess)GetProcAddress(hNt, "NtDebugActiveProcess");
    OriginalWinStationTerminateProcess = (WinStationTerminateProcess)GetProcAddress(GetModuleHandleW(L"winsta.dll"), "WinStationTerminateProcess");
    OriginalNtOpenProcess = (NtOpenProcess)GetProcAddress(hNt, "NtOpenProcess");
    OriginalNtSetSystemTime = (NtSetSystemTime)GetProcAddress(hNt, "NtSetSystemTime");
    OriginalNtQueryDirectoryFile = (NtQueryDirectoryFile)GetProcAddress(hNt, "NtQueryDirectoryFile");
    OriginalNtSetInformationFile = (NtSetInformationFile)GetProcAddress(hNt, "NtSetInformationFile");
    OriginalNtDeleteKey = (NtDeleteKey)GetProcAddress(hNt, "NtDeleteKey");
    OriginalNtDeleteValueKey = (NtDeleteValueKey)GetProcAddress(hNt, "NtDeleteValueKey");
    OriginalNtDeleteFile = (NtDeleteFile)GetProcAddress(hNt, "NtDeleteFile");
    OriginalNtCreateFile = (NtCreateFile)GetProcAddress(hNt, "NtCreateFile");
    OriginalNtOpenFile = (NtOpenFile)GetProcAddress(hNt, "NtOpenFile");
    OriginalRtlSetProcessIsCritical = (RtlSetProcessIsCritical)GetProcAddress(hNt, "RtlSetProcessIsCritical");
    OriginalNtSetInformationProcess = (NtSetInformationProcess)GetProcAddress(hNt, "NtSetInformationProcess");
    OriginalNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(hNt, "NtCreateThreadEx");
    OriginalNtMapViewOfSection = (NtMapViewOfSection)GetProcAddress(hNt, "NtMapViewOfSection");
    OriginalNtQueueApcThread = (NtQueueApcThread)GetProcAddress(hNt, "NtQueueApcThread");
    OriginalNtQueueApcThreadEx = (NtQueueApcThreadEx)GetProcAddress(hNt, "NtQueueApcThreadEx");
    OriginalNtQueueApcThreadEx2 = (NtQueueApcThreadEx2)GetProcAddress(hNt, "NtQueueApcThreadEx2");
    HMODULE hAdvapi = GetModuleHandleW(L"advapi32.dll");
    OriginalStartServiceW = (StartServiceW_type)GetProcAddress(hAdvapi, "StartServiceW");
    OriginalStartServiceA = (StartServiceA_type)GetProcAddress(hAdvapi, "StartServiceA");
    OriginalZwLoadDriver = (ZwLoadDriver)GetProcAddress(hNt, "ZwLoadDriver");
    OriginalZwSetSystemInformation = (ZwSetSystemInformation)GetProcAddress(hNt, "ZwSetSystemInformation");
    OriginalNtProtectVirtualMemory = (NtProtectVirtualMemory)GetProcAddress(hNt, "NtProtectVirtualMemory");
    OriginalNtWriteVirtualMemory = (NtWriteVirtualMemory)GetProcAddress(hNt, "NtWriteVirtualMemory");
    OriginalNtQueryInformationProcess = (NtQueryInformationProcess)GetProcAddress(hNt, "NtQueryInformationProcess");
    OriginalNtQueryVirtualMemory = (NtQueryVirtualMemory_t)GetProcAddress(hNt, "NtQueryVirtualMemory");
    OriginalLdrLoadDll = (LdrLoadDll_t)GetProcAddress(hNt, "LdrLoadDll");

    /* SystemParametersInfo hook 已移除：不再拦截 SPI_SETDESKWALLPAPER */
    /*
    HMODULE hUser32 = LoadLibraryW(L"user32.dll");
    if (hUser32)
    {
        OriginalSystemParametersInfoW = (SystemParametersInfoW_t)GetProcAddress(hUser32, "SystemParametersInfoW");
        OriginalSystemParametersInfoA = (SystemParametersInfoA_t)GetProcAddress(hUser32, "SystemParametersInfoA");
    }
    */

    if (OriginalNtResumeThread)                        DetourAttach(&(PVOID&)OriginalNtResumeThread, NewNtResumeThread);
    if (OriginalNtResumeProcess)                       DetourAttach(&(PVOID&)OriginalNtResumeProcess, NewNtResumeProcess);
    if (OriginalNtCreateUserProcess)                   DetourAttach(&(PVOID&)OriginalNtCreateUserProcess, NewNtCreateUserProcess);
    if (OriginalNtSetValueKey)                         DetourAttach(&(PVOID&)OriginalNtSetValueKey, NewNtSetValueKey);
    if (OriginalNtWriteFile)                           DetourAttach(&(PVOID&)OriginalNtWriteFile, NewNtWriteFile);
    if (OriginalNtRaiseHardError)                      DetourAttach(&(PVOID&)OriginalNtRaiseHardError, NewNtRaiseHardError);
    if (OriginalPspTerminateThreadByPointer)           DetourAttach(&(PVOID&)OriginalPspTerminateThreadByPointer, NewPspTerminateThreadByPointer);
    if (OriginalPspTerminateProcess)                   DetourAttach(&(PVOID&)OriginalPspTerminateProcess, NewPspTerminateProcess);
    if (OriginalNtTerminateProcess)                    DetourAttach(&(PVOID&)OriginalNtTerminateProcess, NewNtTerminateProcess);
    if (OriginalNtDebugActiveProcess)                  DetourAttach(&(PVOID&)OriginalNtDebugActiveProcess, NewNtDebugActiveProcess);
    if (OriginalWinStationTerminateProcess)            DetourAttach(&(PVOID&)OriginalWinStationTerminateProcess, NewWinStationTerminateProcess);
    if (OriginalNtOpenProcess)                         DetourAttach(&(PVOID&)OriginalNtOpenProcess, NewNtOpenProcess);
    if (OriginalMFCreateDeviceSource)                  DetourAttach(&(PVOID&)OriginalMFCreateDeviceSource, NewMFCreateDeviceSource);
    if (OriginalDirectShowCreate)                      DetourAttach(&(PVOID&)OriginalDirectShowCreate, NewDirectShowCreate);
    if (OriginalWaveInOpen)                            DetourAttach(&(PVOID&)OriginalWaveInOpen, NewWaveInOpen);
    if (OriginalNtSetSystemTime)                       DetourAttach(&(PVOID&)OriginalNtSetSystemTime, NewNtSetSystemTime);
    if (OriginalNetUserAdd)                            DetourAttach(&(PVOID&)OriginalNetUserAdd, NewNetUserAdd);
    if (OriginalNetUserSetInfo)                        DetourAttach(&(PVOID&)OriginalNetUserSetInfo, NewNetUserSetInfo);
    if (OriginalNetUserDel)                            DetourAttach(&(PVOID&)OriginalNetUserDel, NewNetUserDel);
    if (OriginalNtQueryDirectoryFile)                  DetourAttach(&(PVOID&)OriginalNtQueryDirectoryFile, NewNtQueryDirectoryFile);
    if (OriginalNtSetInformationFile)                  DetourAttach(&(PVOID&)OriginalNtSetInformationFile, NewNtSetInformationFile);
    if (OriginalSetCursorPos)                          DetourAttach(&(PVOID&)OriginalSetCursorPos, NewSetCursorPos);
    if (OriginalSetPhysicalCursorPos)                  DetourAttach(&(PVOID&)OriginalSetPhysicalCursorPos, NewSetPhysicalCursorPos);
    if (OriginalNtDeleteKey)                           DetourAttach(&(PVOID&)OriginalNtDeleteKey, NewNtDeleteKey);
    if (OriginalNtDeleteValueKey)                      DetourAttach(&(PVOID&)OriginalNtDeleteValueKey, NewNtDeleteValueKey);
    if (OriginalNtDeleteFile)                          DetourAttach(&(PVOID&)OriginalNtDeleteFile, NewNtDeleteFile);
    if (OriginalNtCreateFile)                          DetourAttach(&(PVOID&)OriginalNtCreateFile, NewNtCreateFile);
    if (OriginalNtOpenFile)                            DetourAttach(&(PVOID&)OriginalNtOpenFile, NewNtOpenFile);
    if (OriginalRtlSetProcessIsCritical)               DetourAttach(&(PVOID&)OriginalRtlSetProcessIsCritical, NewRtlSetProcessIsCritical);
    if (OriginalNtSetInformationProcess)               DetourAttach(&(PVOID&)OriginalNtSetInformationProcess, NewNtSetInformationProcess);
    if (OriginalNtCreateThreadEx)                      DetourAttach(&(PVOID&)OriginalNtCreateThreadEx, NewNtCreateThreadEx);
    if (OriginalNtMapViewOfSection)                    DetourAttach(&(PVOID&)OriginalNtMapViewOfSection, NewNtMapViewOfSection);
    if (OriginalNtQueueApcThread)                      DetourAttach(&(PVOID&)OriginalNtQueueApcThread, NewNtQueueApcThread);
    if (OriginalNtQueueApcThreadEx)                    DetourAttach(&(PVOID&)OriginalNtQueueApcThreadEx, NewNtQueueApcThreadEx);
    if (OriginalNtQueueApcThreadEx2)                   DetourAttach(&(PVOID&)OriginalNtQueueApcThreadEx2, NewNtQueueApcThreadEx2);
    if (OriginalNtProtectVirtualMemory)                DetourAttach(&(PVOID&)OriginalNtProtectVirtualMemory, NewNtProtectVirtualMemory);
    if (OriginalNtWriteVirtualMemory)                  DetourAttach(&(PVOID&)OriginalNtWriteVirtualMemory, NewNtWriteVirtualMemory);
    if (OriginalLdrLoadDll)                            DetourAttach(&(PVOID&)OriginalLdrLoadDll, NewLdrLoadDll);
    if (OriginalStartServiceW)                         DetourAttach(&(PVOID&)OriginalStartServiceW, NewStartServiceW);
    if (OriginalStartServiceA)                         DetourAttach(&(PVOID&)OriginalStartServiceA, NewStartServiceA);
    if (OriginalZwLoadDriver)                          DetourAttach(&(PVOID&)OriginalZwLoadDriver, NewZwLoadDriver);
    if (OriginalZwSetSystemInformation)                DetourAttach(&(PVOID&)OriginalZwSetSystemInformation, NewZwSetSystemInformation);
    // SystemParametersInfo hook 已移除
    //if (OriginalSystemParametersInfoW)                DetourAttach(&(PVOID&)OriginalSystemParametersInfoW, NewSystemParametersInfoW);
    //if (OriginalSystemParametersInfoA)                DetourAttach(&(PVOID&)OriginalSystemParametersInfoA, NewSystemParametersInfoA);

    DetourTransactionCommit();

    FreeLibrary(hNt);

    Tran_SendPacket(Tran_Server, (char*)"", PTCreateProcessRoutine, (char*)"CallResumeEvent", GetCurrentProcessId());
}

void StopHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (OriginalNtResumeThread)                        DetourDetach(&(PVOID&)OriginalNtResumeThread, NewNtResumeThread);
    if (OriginalNtResumeProcess)                       DetourDetach(&(PVOID&)OriginalNtResumeProcess, NewNtResumeProcess);
    if (OriginalNtCreateUserProcess)                   DetourDetach(&(PVOID&)OriginalNtCreateUserProcess, NewNtCreateUserProcess);
    if (OriginalNtSetValueKey)                         DetourDetach(&(PVOID&)OriginalNtSetValueKey, NewNtSetValueKey);
    if (OriginalNtWriteFile)                           DetourDetach(&(PVOID&)OriginalNtWriteFile, NewNtWriteFile);
    if (OriginalNtRaiseHardError)                      DetourDetach(&(PVOID&)OriginalNtRaiseHardError, NewNtRaiseHardError);
    if (OriginalPspTerminateThreadByPointer)           DetourDetach(&(PVOID&)OriginalPspTerminateThreadByPointer, NewPspTerminateThreadByPointer);
    if (OriginalPspTerminateProcess)                   DetourDetach(&(PVOID&)OriginalPspTerminateProcess, NewPspTerminateProcess);
    if (OriginalNtTerminateProcess)                    DetourDetach(&(PVOID&)OriginalNtTerminateProcess, NewNtTerminateProcess);
    if (OriginalNtDebugActiveProcess)                  DetourDetach(&(PVOID&)OriginalNtDebugActiveProcess, NewNtDebugActiveProcess);
    if (OriginalWinStationTerminateProcess)            DetourDetach(&(PVOID&)OriginalWinStationTerminateProcess, NewWinStationTerminateProcess);
    if (OriginalNtOpenProcess)                         DetourDetach(&(PVOID&)OriginalNtOpenProcess, NewNtOpenProcess);
    if (OriginalNtSetSystemTime)                       DetourDetach(&(PVOID&)OriginalNtSetSystemTime, NewNtSetSystemTime);
    if (OriginalNetUserAdd)                            DetourDetach(&(PVOID&)OriginalNetUserAdd, NewNetUserAdd);
    if (OriginalNetUserSetInfo)                        DetourDetach(&(PVOID&)OriginalNetUserSetInfo, NewNetUserSetInfo);
    if (OriginalNetUserDel)                            DetourDetach(&(PVOID&)OriginalNetUserDel, NewNetUserDel);
    if (OriginalNtQueryDirectoryFile)                  DetourDetach(&(PVOID&)OriginalNtQueryDirectoryFile, NewNtQueryDirectoryFile);
    if (OriginalNtSetInformationFile)                  DetourDetach(&(PVOID&)OriginalNtSetInformationFile, NewNtSetInformationFile);
    if (OriginalSetCursorPos)                          DetourDetach(&(PVOID&)OriginalSetCursorPos, NewSetCursorPos);
    if (OriginalSetPhysicalCursorPos)                  DetourDetach(&(PVOID&)OriginalSetPhysicalCursorPos, NewSetPhysicalCursorPos);
    if (OriginalNtDeleteKey)                           DetourDetach(&(PVOID&)OriginalNtDeleteKey, NewNtDeleteKey);
    if (OriginalNtDeleteValueKey)                      DetourDetach(&(PVOID&)OriginalNtDeleteValueKey, NewNtDeleteValueKey);
    if (OriginalNtDeleteFile)                          DetourDetach(&(PVOID&)OriginalNtDeleteFile, NewNtDeleteFile);
    if (OriginalNtCreateFile)                          DetourDetach(&(PVOID&)OriginalNtCreateFile, NewNtCreateFile);
    if (OriginalNtOpenFile)                            DetourDetach(&(PVOID&)OriginalNtOpenFile, NewNtOpenFile);
    if (OriginalRtlSetProcessIsCritical)               DetourDetach(&(PVOID&)OriginalRtlSetProcessIsCritical, NewRtlSetProcessIsCritical);
    if (OriginalNtSetInformationProcess)               DetourDetach(&(PVOID&)OriginalNtSetInformationProcess, NewNtSetInformationProcess);
    if (OriginalNtCreateThreadEx)                      DetourDetach(&(PVOID&)OriginalNtCreateThreadEx, NewNtCreateThreadEx);
    if (OriginalNtMapViewOfSection)                    DetourDetach(&(PVOID&)OriginalNtMapViewOfSection, NewNtMapViewOfSection);
    if (OriginalNtQueueApcThread)                      DetourDetach(&(PVOID&)OriginalNtQueueApcThread, NewNtQueueApcThread);
    if (OriginalNtQueueApcThreadEx)                    DetourDetach(&(PVOID&)OriginalNtQueueApcThreadEx, NewNtQueueApcThreadEx);
    if (OriginalNtQueueApcThreadEx2)                   DetourDetach(&(PVOID&)OriginalNtQueueApcThreadEx2, NewNtQueueApcThreadEx2);
    if (OriginalNtProtectVirtualMemory)                DetourDetach(&(PVOID&)OriginalNtProtectVirtualMemory, NewNtProtectVirtualMemory);
    if (OriginalNtWriteVirtualMemory)                  DetourDetach(&(PVOID&)OriginalNtWriteVirtualMemory, NewNtWriteVirtualMemory);
    if (OriginalLdrLoadDll)                            DetourDetach(&(PVOID&)OriginalLdrLoadDll, NewLdrLoadDll);
    if (OriginalStartServiceW)                         DetourDetach(&(PVOID&)OriginalStartServiceW, NewStartServiceW);
    if (OriginalStartServiceA)                         DetourDetach(&(PVOID&)OriginalStartServiceA, NewStartServiceA);
    if (OriginalZwLoadDriver)                          DetourDetach(&(PVOID&)OriginalZwLoadDriver, NewZwLoadDriver);
    if (OriginalZwSetSystemInformation)                DetourDetach(&(PVOID&)OriginalZwSetSystemInformation, NewZwSetSystemInformation);
    // SystemParametersInfo hook 已移除
    //if (OriginalSystemParametersInfoW)                DetourDetach(&(PVOID&)OriginalSystemParametersInfoW, NewSystemParametersInfoW);
    //if (OriginalSystemParametersInfoA)                DetourDetach(&(PVOID&)OriginalSystemParametersInfoA, NewSystemParametersInfoA);

    DetourTransactionCommit();

    if (isEnableSyscallMonitor) detector.Uninitialize();
}

static DWORD calling RecvT(LPVOID lpParam)
{
    while (true)
    {
        Packet PacketRecv;

        if (Tran_IsSocketClosed(Tran_Server)) break;
        else if (Tran_RecvPacket(Tran_Server, PacketRecv) > 0)
        {

            switch (PacketRecv.PacketTyped)
            {
            case PTConnection:
            {
                if (strcmp(PacketRecv.WarnTitle, "MainProcess") == 0)
                {
                    MainProcessPid = PacketRecv.Pid;
                    ProtectionReadyCount++;
                }
                else if (strcmp(PacketRecv.WarnTitle, "Injector") == 0)
                {
                    InjectorPid = PacketRecv.Pid;
                    ProtectionReadyCount++;

                    Tran_SendPacket(Tran_Server, (char*)"", PTConnection, (char*)"", GetCurrentProcessId());
                }
                else if (strcmp(PacketRecv.WarnTitle, "IsSyscallDetectionEnable") == 0)
                {
                    if (PacketRecv.Pid)
                    {
                        if (detector.Initialize())
                        {
                            isEnableSyscallMonitor = TRUE;
                        }
                    }
				}
                break;
            }

            case PTCreateProcessRoutine:
            {
                if (PacketRecv.Pid == 1)
                    CreateOperationResult = TRUE;
                else if (PacketRecv.Pid == -1)
                    CreateOperationResult = -1;
                else
                    CreateOperationResult = FALSE;

                SetEvent(CreateResponseEvent);
                break;
            }

            case PTVirusOperationConfirm:
            {
                if (strcmp(PacketRecv.WarnTitle, "OperationConfirm") == 0)
                {
                    SetHandleResult(PacketRecv.Pid);
                }
                else if (strcmp(PacketRecv.WarnTitle, "NeedScriptPath") == 0)
                {
                    if (Tran_OrgSendPacket(Tran_Server, (char*)thisScriptPath.c_str(),
                        PTVirusOperationConfirm, (char*)"ReturnScriptPath",
                        GetCurrentProcessId(), (char*)"脚本病毒") <= 0)
                    {
                        ExitProcess(-1);
                    }
                }
                break;
            }

            case PTHideFile:
            {
                if (strcmp(PacketRecv.WarnTitle, "HideFileCount") == 0)
                {
                    HideFileCount = PacketRecv.Pid;

                    if (PacketRecv.Pid == 0) isProtectionFileReady = TRUE;
                    break;
                }

                ProtectFile[ProcFileCount] = PacketRecv.Message;

                ProcFileCount++;

                if (ProcFileCount >= HideFileCount) isProtectionFileReady = TRUE;

                break;
            }

            case PTThreatScore:
            {
                if (isExplorer)
                    break;

                Suspiciousness += 25;

                if (CheckSuspiciousness())
                {
                    return ACCESS_IS_DENIED;
                }
                break;
            }

            default:
                break;
            }
        }
        Sleep(10);
    }

    SetHandleResult(FALSE);

    StopHook();

    if (Tran_Server != NULL)
    {
        closesocket(Tran_Server);
        Tran_Server = NULL;
    }

    /*

    // 等待 Main 程序重新上线并重新启动接收任务
    while (true)
    {
        // 尝试重新连接主程序
        WSADATA wsaData;
        struct sockaddr_in serverAddr;

        SOCKET newSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (newSocket == INVALID_SOCKET)
        {
            Sleep(5000);
            continue;
        }

        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        serverAddr.sin_port = htons(12345);

        if (connect(newSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
        {
            closesocket(newSocket);
            Sleep(5000);
            continue;
        }

        u_long mode = 0;

        if (ioctlsocket(newSocket, FIONBIO, &mode) != 0)
        {
            // MessageBox(L"[-] 设置sock阻塞模式失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
            return 1;
        }

        // 连接成功，更新全局 socket
        Tran_Server = newSocket;

		MessageBox(NULL, L"主程序已重新上线，防护模块继续运行", L"提示", MB_TOPMOST | MB_ICONINFORMATION);

        StartHook();

        isDllExited = FALSE;

        // 重新启动接收任务
        CreateThread(NULL, 0, RecvT, NULL, 0, NULL);
        return 0; // 当前线程结束，新线程继续接收
    }

    */

    FreeLibraryAndExitThread(hDll, 0);
    return 0;
}

DWORD calling InitT(LPVOID lpParam)
{
    // 组网初始化
    WSADATA wsaData;
    struct sockaddr_in serverAddr;

    // 初始化 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        // MessageBox(NULL, L"[-] WSAStartup失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
        return 1;
    }

    // 创建 socket
    if ((Tran_Server = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        // MessageBox(NULL, L"[-] 创建socket失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
        return 1;
    }

    // 设置服务器地址和端口
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // 服务器 IP 地址
    serverAddr.sin_port = htons(12345); // 服务器端口

    // 连接到服务器
    if (connect(Tran_Server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
    {
        // MessageBox(NULL, L"[-] 连接失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
        return 1;
    }

    u_long mode = 0;

    if (ioctlsocket(Tran_Server, FIONBIO, &mode) != 0)
    {
        // MessageBox(L"[-] 设置sock阻塞模式失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
        return 1;
    }

    CreateThread(0, 0, RecvT, 0, 0, 0);

    InitializeCriticalSection(&CreateCsSync);
    InitializeCriticalSection(&HandleCsSync);
    HandleOperationResponseEvent = CreateEvent(NULL, TRUE, FALSE, NULL);  // 手动重置事件
    CreateResponseEvent = CreateEvent(NULL, TRUE, FALSE, NULL);  // 手动重置事件

    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    if (hStdOut)
    {
        DWORD mode = 0;
        isCurrentConsoleProcess = (GetConsoleMode(hStdOut, &mode) != 0);
    }

    HANDLE hProcess = GetCurrentProcess();
    char processPath[MAX_PATH + 4];
    ZeroMemory(processPath, MAX_PATH + 4);
    if (hProcess)
    {
        DWORD pathSize = sizeof(processPath) / sizeof(char);
        QueryFullProcessImageNameA(hProcess, 0, processPath, &pathSize);
        CloseHandle(hProcess);
    }

    GetSystemDirectoryW(wcSystemRootPath, 32767);
    GetWindowsDirectoryW(wcWindowsRootPath, 32767);
    GetWindowsDirectoryW(wcSysWow64Path, 32767);

    SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, szStartupPath);
    SHGetFolderPathA(NULL, CSIDL_COMMON_STARTUP, NULL, 0, szStartupPathAllUsers);

    wchar_t desktopPath[MAX_PATH];
    SHGetFolderPath(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    DesktopPath = Str_ConvertLPWSTRToLPSTR(desktopPath);

    if (IsSystemAbusedProgram(Str_ConvertLPSTRToLPWSTR(processPath), L"WScript.exe", wcSystemRootPath, wcSysWow64Path)
        || IsSystemAbusedProgram(Str_ConvertLPSTRToLPWSTR(processPath), L"cmd.exe", wcSystemRootPath, wcSysWow64Path)
        || IsSystemAbusedProgram(Str_ConvertLPSTRToLPWSTR(processPath), L"WindowsPowerShell\\v1.0\\PowerShell.exe", wcSystemRootPath, wcSysWow64Path)
        || IsSystemAbusedProgram(Str_ConvertLPSTRToLPWSTR(processPath), L"CScript.exe", wcSystemRootPath, wcSysWow64Path))
    {
        Suspiciousness += 60;
        isScriptScan = true;
    }

    if (Str_CompareWithoutCap(processPath, Str_ConvertLPWSTRToLPSTR(wcWindowsRootPath) + (string)"\\explorer.exe"))
    {
        if (File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR(processPath)))
        {
            Suspiciousness -= 30;
            isExplorer = TRUE;
        }
    }

    // 预计算当前进程 Authenticode 签名状态，供 DLL 侧载防护使用
    // 在 InitT（非 loader lock）中完成，避免在 LdrLoadDll 钩子中调用 WinVerifyTrust 导致死锁
    {
        wchar_t* pwcProcessPath = Str_ConvertLPSTRToLPWSTR(processPath);
        if (pwcProcessPath && pwcProcessPath[0] != L'\0')
        {
            g_CurrentProcessSigned = DllProtVerifyAuthenticode(pwcProcessPath) ? 1 : 0;
        }
    }

    StartHook();

    if (File_VerifySystemFile(Str_ConvertLPSTRToLPWSTR(processPath)))
    {
        Suspiciousness -= 50;
        isWindowsFile = TRUE;
    }

    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        hDll = hModule;

        CreateThread(0, 0, InitT, 0, 0, 0);

        return TRUE;
    }
    case DLL_THREAD_ATTACH:
    {
        break;
    }
    case DLL_THREAD_DETACH:
    {
        break;
    }
    case DLL_PROCESS_DETACH:
    {
        StopHook();
        if (CreateResponseEvent) CloseHandle(CreateResponseEvent);
        DeleteCriticalSection(&CreateCsSync);
        break;
    }
    }
    return TRUE;
}

