#pragma once
#include <ntifs.h>
#include <ntddk.h>

#ifdef __cplusplus
extern "C" {
#endif

#if DBG
#  define DriverDllInjectDbgPrint(Format, ...)  \
    DriverDbgPrint(Format, __VA_ARGS__)
#else
#  define DriverDllInjectDbgPrint(Format, ...)  \
    DriverDbgPrint(Format, __VA_ARGS__)
#endif

/* ── 架构枚举 ── */
typedef enum _DRIVER_DLL_INJECT_ARCHITECTURE
{
    DriverDllInjectArchX86,
    DriverDllInjectArchX64,
    DriverDllInjectArchARM32,
    DriverDllInjectArchARM64,
    DriverDllInjectArchMax,
#if defined(_M_IX86)
    DriverDllInjectArchNative = DriverDllInjectArchX86
#elif defined(_M_AMD64)
    DriverDllInjectArchNative = DriverDllInjectArchX64
#elif defined(_M_ARM64)
    DriverDllInjectArchNative = DriverDllInjectArchARM64
#endif
} DRIVER_DLL_INJECT_ARCHITECTURE;

/* ── 注入方法枚举 ── */
typedef enum _DRIVER_DLL_INJECT_METHOD
{
    /* 通过 thunk shellcode 调用 LdrLoadDll，注入与进程同架构的 DLL */
    DriverDllInjectMethodThunk,
    /* 直接设置 LdrLoadDll 为 user APC 例程，仅支持 x64（thunkless 模式） */
    DriverDllInjectMethodThunkless,
    /* Wow64 log reparse 方式，仅 ARM64 */
    DriverDllInjectMethodWow64LogReparse,
} DRIVER_DLL_INJECT_METHOD;

/* ── 系统 DLL 加载标志 ── */
typedef enum _DRIVER_DLL_INJECT_SYSTEM_DLL
{
    DriverDllInjectNothingLoaded            = 0x0000,
    DriverDllInjectSysArm32NtdllLoaded      = 0x0001,
    DriverDllInjectSyChpe32NtdllLoaded      = 0x0002,
    DriverDllInjectSysWow64NtdllLoaded      = 0x0004,
    DriverDllInjectSystem32NtdllLoaded      = 0x0008,
    DriverDllInjectSystem32Wow64Loaded      = 0x0010,
    DriverDllInjectSystem32Wow64WinLoaded   = 0x0020,
    DriverDllInjectSystem32Wow64CpuLoaded   = 0x0040,
    DriverDllInjectSystem32WowArmHwLoaded   = 0x0080,
    DriverDllInjectSystem32XtajitLoaded     = 0x0100,
} DRIVER_DLL_INJECT_SYSTEM_DLL;

/* ── 注入配置 ── */
typedef struct _DRIVER_DLL_INJECT_SETTINGS
{
    UNICODE_STRING  DllPath[DriverDllInjectArchMax];
    DRIVER_DLL_INJECT_METHOD Method;
} DRIVER_DLL_INJECT_SETTINGS, *PDRIVER_DLL_INJECT_SETTINGS;

/* ── 进程注入状态 ── */
typedef struct _DRIVER_DLL_INJECT_INFO
{
    LIST_ENTRY  ListEntry;
    HANDLE      ProcessId;
    ULONG       LoadedDlls;           /* DRIVER_DLL_INJECT_SYSTEM_DLL 标志组合 */
    BOOLEAN     IsInjected;
    BOOLEAN     ForceUserApc;         /* 是否强制投递 user APC */
    PVOID       LdrLoadDllRoutineAddress;
    DRIVER_DLL_INJECT_METHOD Method;
} DRIVER_DLL_INJECT_INFO, *PDRIVER_DLL_INJECT_INFO;

/* ── 公共 API ── */
NTSTATUS
NTAPI
DriverDllInjectInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PDRIVER_DLL_INJECT_SETTINGS Settings
);

VOID
NTAPI
DriverDllInjectDestroy(
    VOID
);

NTSTATUS
NTAPI
DriverDllInjectCreateInjectionInfo(
    _In_opt_ PDRIVER_DLL_INJECT_INFO* InjectionInfo,
    _In_ HANDLE ProcessId
);

VOID
NTAPI
DriverDllInjectRemoveInjectionInfo(
    _In_ PDRIVER_DLL_INJECT_INFO InjectionInfo,
    _In_ BOOLEAN FreeMemory
);

VOID
NTAPI
DriverDllInjectRemoveInjectionInfoByProcessId(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN FreeMemory
);

PDRIVER_DLL_INJECT_INFO
NTAPI
DriverDllInjectFindInjectionInfo(
    _In_ HANDLE ProcessId
);

BOOLEAN
NTAPI
DriverDllInjectCanInject(
    _In_ PDRIVER_DLL_INJECT_INFO InjectionInfo
);

NTSTATUS
NTAPI
DriverDllInject(
    _In_ PDRIVER_DLL_INJECT_INFO InjectionInfo
);

/* ── 镜像加载回调（由 LoadImageNotifyRoutine 调用）── */
VOID
NTAPI
DriverDllInjectLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
);

#ifdef __cplusplus
}
#endif
