#pragma once
#include "PublicIncluding.h"

#define INJECT TRUE
#define IS_RANSOM_DETECT_OPEN TRUE
#define IS_LOAD_YARAC TRUE
#define ENCRPT_XOR_PASSWORD "*M3jui2dE?"
#define MAX_CLIENT_COUNT 2048

// -- Shared service / device names (user-mode) --
#define THSD_SERVICE_NAME_W       L"TianHongHips"
#define THSD_USER_DEVICE_PATH_W   L"\\\\.\\TianHongHips"
#define THSD_DISK_SERVICE_NAME_W      L"TianHongHips.Disk"
#define THSD_NETWORK_SERVICE_NAME_W   L"TianHongHips.Network"

#define GAA_FLAG_INCLUDE_DNS_SERVERS 0x00000040
#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

const uint32_t K[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

enum RelScanVirus
{
	UnDefined,           // 初始值
	ByScanedWhiteList,   // 无毒（通过whitelist，不需加入whitelist)
	ByScanedBlackList,   // 有毒（通过blacklist，不需加入blacklist)
	ByCommonScaned,      // 有毒（通过commonscaned，需加入blacklist)
	IsntVirus            // 无毒（通过commonscaned，需加入whitelist)
};

enum PacketType
{
	PTConnection,
	PTVirusOperationConfirm,
	PTProtectFile,
	PTHideFile,
	PTCreateProcessRoutine,
	PTThreatScore,
	PTClientMessage       // Client (KernelProtectionClient) 通信
};

enum WarnDlgType
{
	WDT_Normal,
	WDT_Setting,
	WDT_Wifi
};

struct Packet
{
	PacketType PacketTyped;    // 类型
	char Message[4096];        // 信息（ enlarged to fit longer alert messages）
	int Pid;                   // 进程pid
	char WarnTitle[128];       // 作为WarnDlg标题
	char InfoTitle[32];        // 作为Info类型标题
	bool NeedTerminate = false;// 拦截直接Terminate进程
	WarnDlgType WarnType;      // WarnDlg图标风格
};

enum RelActWarnType
{
	AW_Terminate,
	AW_Prevent,
	AW_Allow,
	AW_AutoPrevent,
	AW_AutoAllow
};

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

struct ScanPrcMemStruct
{
	int pid;
	int ClientCount;
};

typedef NTSTATUS(NTAPI* typeNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI* typeNtSetInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength
	);
typedef NTSTATUS(NTAPI* typeZwTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitCode);
typedef NTSTATUS(NTAPI* typeNtSuspendProcess)(IN HANDLE ProcessHandle);
typedef NTSTATUS(NTAPI* typeNtResumeProcess)(IN HANDLE ProcessHandle);

class MainWindow : public ElaWindow
{
public:
	void InitWindow();
	void CloseWindow();

	ElaContentDialog* _closeDialog;
	QDialog* _exitLoadingDialog;
	QWidget* _exitOverlay;
};

enum ScanState {
	ssPrepared,
	ssRunning,
	ssStoppingPreparing,
	ssStopping,
	ssEnding,
	ssScanResult
};

static std::string HeurExceptYaraRuleName[] =
{
	"Yara/Suspicious_RegeditVirus",
	"Yara/DodgyStrings",
	"Yara/Suspicious_Packed_By_PYInstaller",
	"Yara/Suspicious_PackerSections"
};