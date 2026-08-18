#include "DriverDllInject.h"
#include <ntimage.h>
#include "../shared/Common.h"
#include "Main.h"

#if defined(_M_AMD64) || defined(_M_ARM64)
#define DRIVER_DLL_INJECT_CONFIG_SUPPORTS_WOW64
#endif

/* 手动声明 WDK 版本可能未导出的类型和函数 */
#ifndef KAPC_ENVIRONMENT_DEFINED
typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;
#define KAPC_ENVIRONMENT_DEFINED
#endif

#ifndef PKNORMAL_ROUTINE_DEFINED
typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2);
#define PKNORMAL_ROUTINE_DEFINED
#endif

#ifndef PKKERNEL_ROUTINE_DEFINED
typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2);
#define PKKERNEL_ROUTINE_DEFINED
#endif

#ifndef PKRUNDOWN_ROUTINE_DEFINED
typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(
    _In_ PKAPC Apc);
#define PKRUNDOWN_ROUTINE_DEFINED
#endif

// 声明未导出的内核 API
NTKERNELAPI PVOID NTAPI PsGetProcessWow64Process(_In_ PEPROCESS Process);
NTKERNELAPI BOOLEAN NTAPI PsIsProtectedProcess(_In_ PEPROCESS Process);
NTKERNELAPI VOID NTAPI KeTestAlertThread(_In_ KPROCESSOR_MODE AlertMode);
NTKERNELAPI VOID NTAPI KeInitializeApc(
    _Out_ PRKAPC Apc,
    _In_ PKTHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_opt_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext);
NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment);
NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(
    _In_ PVOID BaseOfImage,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size);

//////////////////////////////////////////////////////////////////////////
// 常量
//////////////////////////////////////////////////////////////////////////

#define DRIVER_DLL_INJECT_MEMORY_TAG 'jnID'

//////////////////////////////////////////////////////////////////////////
// 系统 DLL 描述符（用于判断何时可以安全注入）
//////////////////////////////////////////////////////////////////////////

static const struct
{
    UNICODE_STRING  DllPathSuffix;
    DRIVER_DLL_INJECT_SYSTEM_DLL Flag;
} g_DriverDllInjectSystemDlls[] = {
    { RTL_CONSTANT_STRING(L"\\SysArm32\\ntdll.dll"),    DriverDllInjectSysArm32NtdllLoaded   },
    { RTL_CONSTANT_STRING(L"\\SyChpe32\\ntdll.dll"),    DriverDllInjectSyChpe32NtdllLoaded   },
    { RTL_CONSTANT_STRING(L"\\SysWow64\\ntdll.dll"),    DriverDllInjectSysWow64NtdllLoaded   },
    { RTL_CONSTANT_STRING(L"\\System32\\ntdll.dll"),    DriverDllInjectSystem32NtdllLoaded   },
    { RTL_CONSTANT_STRING(L"\\System32\\wow64.dll"),    DriverDllInjectSystem32Wow64Loaded   },
    { RTL_CONSTANT_STRING(L"\\System32\\wow64win.dll"), DriverDllInjectSystem32Wow64WinLoaded},
    { RTL_CONSTANT_STRING(L"\\System32\\wow64cpu.dll"), DriverDllInjectSystem32Wow64CpuLoaded},
    { RTL_CONSTANT_STRING(L"\\System32\\wowarmhw.dll"), DriverDllInjectSystem32WowArmHwLoaded},
    { RTL_CONSTANT_STRING(L"\\System32\\xtajit.dll"),   DriverDllInjectSystem32XtajitLoaded  },
};

//////////////////////////////////////////////////////////////////////////
// Thunk shellcode（供 thunk 模式注入使用）
//////////////////////////////////////////////////////////////////////////

static const UCHAR g_DriverDllInjectThunkX86[] = {
    0x83, 0xec, 0x08,                   // sub    esp,0x8
    0x0f, 0xb7, 0x44, 0x24, 0x14,       // movzx  eax,[esp + 0x14]
    0x66, 0x89, 0x04, 0x24,             // mov    [esp],ax
    0x66, 0x89, 0x44, 0x24, 0x02,       // mov    [esp + 0x2],ax
    0x8b, 0x44, 0x24, 0x10,             // mov    eax,[esp + 0x10]
    0x89, 0x44, 0x24, 0x04,             // mov    [esp + 0x4],eax
    0x8d, 0x44, 0x24, 0x14,             // lea    eax,[esp + 0x14]
    0x50,                               // push   eax
    0x8d, 0x44, 0x24, 0x04,             // lea    eax,[esp + 0x4]
    0x50,                               // push   eax
    0x6a, 0x00,                         // push   0x0
    0x6a, 0x00,                         // push   0x0
    0xff, 0x54, 0x24, 0x1c,             // call   [esp + 0x1c]
    0x83, 0xc4, 0x08,                   // add    esp,0x8
    0xc2, 0x0c, 0x00,                   // ret    0xc
};

static const UCHAR g_DriverDllInjectThunkX64[] = {
    0x48, 0x83, 0xec, 0x38,             // sub    rsp,0x38
    0x48, 0x89, 0xc8,                   // mov    rax,rcx
    0x66, 0x44, 0x89, 0x44, 0x24, 0x20, // mov    [rsp+0x20],r8w
    0x66, 0x44, 0x89, 0x44, 0x24, 0x22, // mov    [rsp+0x22],r8w
    0x4c, 0x8d, 0x4c, 0x24, 0x40,       // lea    r9,[rsp+0x40]
    0x48, 0x89, 0x54, 0x24, 0x28,       // mov    [rsp+0x28],rdx
    0x4c, 0x8d, 0x44, 0x24, 0x20,       // lea    r8,[rsp+0x20]
    0x31, 0xd2,                         // xor    edx,edx
    0x31, 0xc9,                         // xor    ecx,ecx
    0xff, 0xd0,                         // call   rax
    0x48, 0x83, 0xc4, 0x38,             // add    rsp,0x38
    0xc2, 0x00, 0x00,                   // ret    0x0
};

static const UCHAR g_DriverDllInjectThunkARM32[] = {
    0x1f, 0xb5,                         // push   {r0-r4,lr}
    0xad, 0xf8, 0x08, 0x20,             // strh   r2,[sp,#8]
    0xad, 0xf8, 0x0a, 0x20,             // strh   r2,[sp,#0xA]
    0x03, 0x91,                         // str    r1,[sp,#0xC]
    0x02, 0xaa,                         // add    r2,sp,#8
    0x00, 0x21,                         // movs   r1,#0
    0x04, 0x46,                         // mov    r4,r0
    0x6b, 0x46,                         // mov    r3,sp
    0x00, 0x20,                         // movs   r0,#0
    0xa0, 0x47,                         // blx    r4
    0x1f, 0xbd,                         // pop    {r0-r4,pc}
};

static const UCHAR g_DriverDllInjectThunkARM64[] = {
    0xfe, 0x0f, 0x1f, 0xf8,             // str    lr,[sp,#-0x10]!
    0xff, 0x83, 0x00, 0xd1,             // sub    sp,sp,#0x20
    0xe9, 0x03, 0x00, 0xaa,             // mov    x9,x0
    0xe2, 0x13, 0x00, 0x79,             // strh   w2,[sp,#8]
    0x00, 0x00, 0x80, 0xd2,             // mov    x0,#0
    0xe2, 0x17, 0x00, 0x79,             // strh   w2,[sp,#0xA]
    0xe2, 0x23, 0x00, 0x91,             // add    x2,sp,#8
    0xe1, 0x0b, 0x00, 0xf9,             // str    x1,[sp,#0x10]
    0x01, 0x00, 0x80, 0xd2,             // mov    x1,#0
    0xe3, 0x03, 0x00, 0x91,             // mov    x3,sp
    0x20, 0x01, 0x3f, 0xd6,             // blr    x9
    0xff, 0x83, 0x00, 0x91,             // add    sp,sp,#0x20
    0xfe, 0x07, 0x41, 0xf8,             // ldr    lr,[sp],#0x10
    0xc0, 0x03, 0x5f, 0xd6,             // ret
};

/* thunk 表 */
static const struct _THUNK_DESC {
    const UCHAR* Buffer;
    USHORT Length;
} g_DriverDllInjectThunk[] = {
    { g_DriverDllInjectThunkX86,   sizeof(g_DriverDllInjectThunkX86)   },
    { g_DriverDllInjectThunkX64,   sizeof(g_DriverDllInjectThunkX64)   },
    { g_DriverDllInjectThunkARM32, sizeof(g_DriverDllInjectThunkARM32) },
    { g_DriverDllInjectThunkARM64, sizeof(g_DriverDllInjectThunkARM64) },
};

//////////////////////////////////////////////////////////////////////////
// 全局变量
//////////////////////////////////////////////////////////////////////////

static LIST_ENTRY         g_DriverDllInjectInfoListHead;
static DRIVER_DLL_INJECT_METHOD g_DriverDllInjectMethod;
static BOOLEAN            g_DriverDllInjectIsWindows7;

/* 全局 DLL 注入路径和开关（由 IOCTL 设置） */
extern WCHAR   g_DllInjectPath[260];
extern BOOLEAN g_bDllInjectPathSet;
extern BOOLEAN g_bR3ProtectionEnabled;

//////////////////////////////////////////////////////////////////////////
// 辅助函数
//////////////////////////////////////////////////////////////////////////

/* 在 PE 镜像的导出表中按名称查找函数地址（二分搜索） */
static PVOID
NTAPI
DriverDllInjectFindExportedRoutineByName(
    _In_ PVOID DllBase,
    _In_ PANSI_STRING ExportName
)
{
    PULONG NameTable;
    PUSHORT OrdinalTable;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    LONG Low = 0, Mid = 0, High;
    USHORT Ordinal;
    PVOID Function;
    ULONG ExportSize;
    PULONG ExportTable;

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(
        DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &ExportSize);
    if (!ExportDirectory)
        return NULL;

    NameTable    = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
    OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

    High = (LONG)ExportDirectory->NumberOfNames - 1;
    while (High >= Low)
    {
        Mid = (Low + High) >> 1;
        int Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);
        if (Ret < 0)
            High = Mid - 1;
        else if (Ret > 0)
            Low = Mid + 1;
        else
            break;
    }

    if (High < Low)
        return NULL;

    Ordinal = OrdinalTable[Mid];
    if (Ordinal >= ExportDirectory->NumberOfFunctions)
        return NULL;

    ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
    Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);
    return Function;
}

/* 检查 FullImageName 尾部是否匹配某个系统 DLL 路径后缀 */
static DRIVER_DLL_INJECT_SYSTEM_DLL
NTAPI
DriverDllInjectGetSystemDllFlag(
    _In_ PUNICODE_STRING FullImageName
)
{
    for (ULONG i = 0; i < RTL_NUMBER_OF(g_DriverDllInjectSystemDlls); i++)
    {
        const UNICODE_STRING* suffix = &g_DriverDllInjectSystemDlls[i].DllPathSuffix;
        if (FullImageName->Length >= suffix->Length)
        {
            UNICODE_STRING tail;
            tail.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer +
                                   FullImageName->Length - suffix->Length);
            tail.Length = suffix->Length;
            tail.MaximumLength = suffix->Length;
            if (RtlEqualUnicodeString(suffix, &tail, TRUE))
                return g_DriverDllInjectSystemDlls[i].Flag;
        }
    }
    return DriverDllInjectNothingLoaded;
}

//////////////////////////////////////////////////////////////////////////
// APC 队列与注入回调
//////////////////////////////////////////////////////////////////////////

/* kernel APC 清理例程：释放 KAPC 结构 */
static
VOID
NTAPI
DriverDllInjectApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    ExFreePoolWithTag(Apc, DRIVER_DLL_INJECT_MEMORY_TAG);
}

/* user APC 正常例程：调用 LdrLoadDll 加载防御 DLL */
static
VOID
NTAPI
DriverDllInjectApcNormalRoutine(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    PDRIVER_DLL_INJECT_INFO info = (PDRIVER_DLL_INJECT_INFO)NormalContext;
    DriverDllInjectDbgPrint("[DLL-INJECT] APC FIRED! PID=%lld Info=%p\n",
        (INT64)(ULONG_PTR)info->ProcessId, info);
    DriverDllInject(info);
}

/* 将 kernel APC 入队到当前线程 */
static NTSTATUS
NTAPI
DriverDllInjectQueueApc(
    _In_ KPROCESSOR_MODE ApcMode,
    _In_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
)
{
    PKAPC apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), DRIVER_DLL_INJECT_MEMORY_TAG);
    if (!apc)
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] ExAllocatePool2(KAPC) failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(apc,
                    PsGetCurrentThread(),
                    OriginalApcEnvironment,
                    DriverDllInjectApcKernelRoutine,
                    NULL,
                    NormalRoutine,
                    ApcMode,
                    NormalContext);

    if (!KeInsertQueueApc(apc, SystemArgument1, SystemArgument2, 0))
    {
        ExFreePoolWithTag(apc, DRIVER_DLL_INJECT_MEMORY_TAG);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

//////////////////////////////////////////////////////////////////////////
// 核心注入函数（参考 injdrv: https://github.com/wbenny/injdrv）
//////////////////////////////////////////////////////////////////////////

/* thunk 模式：通过 shellcode 调用 LdrLoadDll */
static NTSTATUS
NTAPI
DriverDllInjectThunk(
    _In_ PDRIVER_DLL_INJECT_INFO Info,
    _In_ DRIVER_DLL_INJECT_ARCHITECTURE Arch,
    _In_ HANDLE SectionHandle,
    _In_ SIZE_T SectionSize
)
{
    NTSTATUS Status;
    DriverDllInjectDbgPrint("[DLL-INJECT] Thunk mode, Arch=%d\n", Arch);

    /* 创建可读写的 section */
    PVOID SecMem = NULL;
    Status = ZwMapViewOfSection(SectionHandle, ZwCurrentProcess(),
                                &SecMem, 0, SectionSize,
                                NULL, &SectionSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] ZwMapViewOfSection(RW) failed: 0x%X\n", Status);
        return Status;
    }

    /* 写入 thunk shellcode */
    PVOID ApcRoutineAddr = SecMem;
    RtlCopyMemory(ApcRoutineAddr,
                  g_DriverDllInjectThunk[Arch].Buffer,
                  g_DriverDllInjectThunk[Arch].Length);

    /* 写入 DLL 路径（全局 g_DllInjectPath + 架构后缀） */
    PWCHAR DllPath = (PWCHAR)((PUCHAR)SecMem + g_DriverDllInjectThunk[Arch].Length);
    ULONG_PTR dst = (ULONG_PTR)DllPath;
    for (ULONG i = 0; g_DllInjectPath[i] != L'\0'; i++)
        *(PWCHAR)dst = g_DllInjectPath[i], dst += sizeof(WCHAR);
    *(PWCHAR)dst = L'\0';
    dst += sizeof(WCHAR);
    if (Arch == DriverDllInjectArchX64)
    { *(PWCHAR)dst = L'6'; dst += sizeof(WCHAR); *(PWCHAR)dst = L'4'; dst += sizeof(WCHAR); }
    else
    { *(PWCHAR)dst = L'3'; dst += sizeof(WCHAR); *(PWCHAR)dst = L'2'; dst += sizeof(WCHAR); }
    *(PWCHAR)dst = L'.'; dst += sizeof(WCHAR);
    *(PWCHAR)dst = L'd'; dst += sizeof(WCHAR);
    *(PWCHAR)dst = L'l'; dst += sizeof(WCHAR);
    *(PWCHAR)dst = L'l'; dst += sizeof(WCHAR);
    *(PWCHAR)dst = L'\0';

    /* 解除映射并以 PAGE_EXECUTE_READ 重新映射 */
    ZwUnmapViewOfSection(ZwCurrentProcess(), SecMem);
    SecMem = NULL;
    SectionSize = PAGE_SIZE;
    Status = ZwMapViewOfSection(SectionHandle, ZwCurrentProcess(),
                                &SecMem, 0, SectionSize,
                                NULL, &SectionSize, ViewUnmap, 0, PAGE_EXECUTE_READ);
    if (!NT_SUCCESS(Status))
        return Status;

    ApcRoutineAddr = SecMem;
    DllPath = (PWCHAR)((PUCHAR)SecMem + g_DriverDllInjectThunk[Arch].Length);

    PVOID ApcContext   = Info->LdrLoadDllRoutineAddress;
    PVOID ApcArg1      = (PVOID)DllPath;
    PVOID ApcArg2      = NULL;
    /* ApcArg2 = DLL 路径字节长度 */
    {
        ULONG len = 0;
        PWCHAR p = (PWCHAR)ApcArg1;
        while (*p++) len++;
        ApcArg2 = (PVOID)(len * sizeof(WCHAR));
    }

#ifdef DRIVER_DLL_INJECT_CONFIG_SUPPORTS_WOW64
    if (PsGetProcessWow64Process(PsGetCurrentProcess()))
    {
        if (Arch == DriverDllInjectArchARM32)
            ApcRoutineAddr = (PVOID)((ULONG_PTR)ApcRoutineAddr | 1);
        PsWrapApcWow64Thread(&ApcContext, &ApcRoutineAddr);
    }
#endif

    PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)ApcRoutineAddr;

    Status = DriverDllInjectQueueApc(UserMode, ApcRoutine, ApcContext, ApcArg1, ApcArg2);
    if (!NT_SUCCESS(Status))
        ZwUnmapViewOfSection(ZwCurrentProcess(), SecMem);

    return Status;
}

/* thunkless 模式（仅 x64）：直接将 LdrLoadDll 设为 user APC 例程 */
static NTSTATUS
NTAPI
DriverDllInjectThunkless(
    _In_ PDRIVER_DLL_INJECT_INFO Info,
    _In_ HANDLE SectionHandle,
    _In_ SIZE_T SectionSize
)
{
    NT_ASSERT(Info->LdrLoadDllRoutineAddress);

    NTSTATUS Status;
    PVOID SecMem = NULL;
    Status = ZwMapViewOfSection(SectionHandle, ZwCurrentProcess(),
                                &SecMem, 0, SectionSize,
                                NULL, &SectionSize, ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
        return Status;

    /* LdrLoadDll 的 DllName 参数是 PUNICODE_STRING，而非裸 WCHAR 缓冲区。
     * 若直接传 WCHAR 数组，LdrLoadDll 会把路径前 8 字节当作 Length/MaximumLength/Buffer，
     * 导致读取非法指针而崩溃、注入失败。
     * 因此在 section 内存中构造 UNICODE_STRING 结构体，随后紧跟 DLL 路径文本。 */
    PUNICODE_STRING DllName = (PUNICODE_STRING)SecMem;
    PWCHAR DllPathBuf = (PWCHAR)((PUCHAR)SecMem + sizeof(UNICODE_STRING));

    /* 写入 DLL 路径（全局 g_DllInjectPath + 架构后缀 64.dll） */
    ULONG pathLen = 0;
    ULONG_PTR dst = (ULONG_PTR)DllPathBuf;
    for (ULONG i = 0; g_DllInjectPath[i] != L'\0'; i++)
    {
        *(PWCHAR)dst = g_DllInjectPath[i]; dst += sizeof(WCHAR); pathLen++;
    }
    *(PWCHAR)dst = L'6'; dst += sizeof(WCHAR); pathLen++;
    *(PWCHAR)dst = L'4'; dst += sizeof(WCHAR); pathLen++;
    *(PWCHAR)dst = L'.'; dst += sizeof(WCHAR); pathLen++;
    *(PWCHAR)dst = L'd'; dst += sizeof(WCHAR); pathLen++;
    *(PWCHAR)dst = L'l'; dst += sizeof(WCHAR); pathLen++;
    *(PWCHAR)dst = L'l'; dst += sizeof(WCHAR); pathLen++;
    *(PWCHAR)dst = L'\0';

    DllName->Length        = (USHORT)(pathLen * sizeof(WCHAR));
    DllName->MaximumLength = DllName->Length + sizeof(WCHAR);
    DllName->Buffer        = DllPathBuf;

    PKNORMAL_ROUTINE ApcRoutine = (PKNORMAL_ROUTINE)(ULONG_PTR)Info->LdrLoadDllRoutineAddress;

    /* thunkless: NormalContext→SearchPath(NULL), SystemArgument1→DllCharacteristics(NULL),
     * SystemArgument2→DllName(指向 UNICODE_STRING 结构体)
     * 第4个参数 BaseAddress 由 KiUserApcDispatcher 从 CONTEXT.P4Home 隐式获取 */
    Status = DriverDllInjectQueueApc(UserMode, ApcRoutine,
                                       NULL,      /* SearchPath */
                                       NULL,      /* DllCharacteristics */
                                       DllName);  /* DllName (PUNICODE_STRING) */
    if (!NT_SUCCESS(Status))
        ZwUnmapViewOfSection(ZwCurrentProcess(), SecMem);

    return Status;
}

//////////////////////////////////////////////////////////////////////////
// 公共函数
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
DriverDllInject(
    _In_ PDRIVER_DLL_INJECT_INFO Info
)
{
    if (!Info || !Info->LdrLoadDllRoutineAddress)
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] DriverDllInject: INVALID_PARAMETER (Info=%p LdrLoadDll=%p)\n",
            Info, Info ? Info->LdrLoadDllRoutineAddress : NULL);
        return STATUS_INVALID_PARAMETER;
    }

    DriverDllInjectDbgPrint("[DLL-INJECT] DriverDllInject: LdrLoadDll=%p method=%d\n",
        Info->LdrLoadDllRoutineAddress, Info->Method);

    OBJECT_ATTRIBUTES oa = RTL_CONSTANT_OBJECT_ATTRIBUTES(NULL, OBJ_KERNEL_HANDLE);
    HANDLE SectionHandle;
    SIZE_T SectionSize = PAGE_SIZE;
    LARGE_INTEGER MaxSize = { .QuadPart = SectionSize };

    NTSTATUS Status = ZwCreateSection(&SectionHandle,
                                      GENERIC_READ | GENERIC_WRITE,
                                      &oa, &MaxSize,
                                      PAGE_EXECUTE_READWRITE,
                                      SEC_COMMIT, NULL);
    if (!NT_SUCCESS(Status))
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] ZwCreateSection failed: 0x%X\n", Status);
        return Status;
    }

    DRIVER_DLL_INJECT_ARCHITECTURE Arch = (DRIVER_DLL_INJECT_ARCHITECTURE)DriverDllInjectArchMax;

#if defined(_M_AMD64)
    Arch = PsGetProcessWow64Process(PsGetCurrentProcess())
        ? DriverDllInjectArchX86 : DriverDllInjectArchX64;
#elif defined(_M_IX86)
    Arch = DriverDllInjectArchX86;
#elif defined(_M_ARM64)
    switch (PsWow64GetProcessMachine(PsGetCurrentProcess()))
    {
        case IMAGE_FILE_MACHINE_I386:  Arch = DriverDllInjectArchX86;  break;
        case IMAGE_FILE_MACHINE_ARMNT: Arch = DriverDllInjectArchARM32; break;
        case IMAGE_FILE_MACHINE_ARM64: Arch = DriverDllInjectArchARM64; break;
    }
#endif

    NT_ASSERT(Arch != (DRIVER_DLL_INJECT_ARCHITECTURE)DriverDllInjectArchMax);

    if (Info->Method == DriverDllInjectMethodThunk ||
        Info->Method == DriverDllInjectMethodWow64LogReparse)
    {
        Status = DriverDllInjectThunk(Info, Arch, SectionHandle, SectionSize);
    }
#if defined(_M_AMD64)
    else if (Info->Method == DriverDllInjectMethodThunkless && Arch == DriverDllInjectArchX64)
    {
        /* 与 injdrv 参考实现一致：thunkless 仅用于原生 x64 进程，
         * 直接以 LdrLoadDll 作为 user APC 例程注入 64.dll。
         * 注：thunkless 只缓存 System32\ntdll.dll 的 x64 LdrLoadDll 地址，
         * 若在 32 位进程中以 thunk 执行会崩溃，因此仅当 Arch==X64 时才走 thunkless。 */
        Status = DriverDllInjectThunkless(Info, SectionHandle, SectionSize);
    }
    else if (Info->Method == DriverDllInjectMethodThunkless && Arch == DriverDllInjectArchX86)
    {
        /* WoW64（32 位）进程：x64 的 thunkless 无法注入，必须回退到 thunk 模式。
         * thunk 模式会写入 x86 shellcode，经 PsWrapApcWow64Thread 转换后
         * 以 32 位 LdrLoadDll 注入 32.dll。Arch 已由 PsGetProcessWow64Process 判定为 X86。 */
        DriverDllInjectDbgPrint("[DLL-INJECT] WoW64 process, falling back to Thunk mode\n");
        Status = DriverDllInjectThunk(Info, Arch, SectionHandle, SectionSize);
    }
#endif

    ZwClose(SectionHandle);

    if (NT_SUCCESS(Status) && Info->ForceUserApc)
        KeTestAlertThread(UserMode);

    return Status;
}

BOOLEAN
NTAPI
DriverDllInjectCanInject(
    _In_ PDRIVER_DLL_INJECT_INFO Info
)
{
    ULONG RequiredDlls = DriverDllInjectSystem32NtdllLoaded;

#ifdef DRIVER_DLL_INJECT_CONFIG_SUPPORTS_WOW64
    if (PsGetProcessWow64Process(PsGetCurrentProcess()))
    {
        RequiredDlls |= DriverDllInjectSystem32Wow64Loaded;
        RequiredDlls |= DriverDllInjectSystem32Wow64WinLoaded;
#ifdef _M_AMD64
        RequiredDlls |= DriverDllInjectSystem32Wow64CpuLoaded;
        RequiredDlls |= DriverDllInjectSysWow64NtdllLoaded;
#endif
    }
#endif

    return (Info->LoadedDlls & RequiredDlls) == RequiredDlls;
}

NTSTATUS
NTAPI
DriverDllInjectCreateInjectionInfo(
    _In_opt_ PDRIVER_DLL_INJECT_INFO* InjectionInfo,
    _In_ HANDLE ProcessId
)
{
    PDRIVER_DLL_INJECT_INFO info;

    if (InjectionInfo && *InjectionInfo)
    {
        info = *InjectionInfo;
    }
    else
    {
        info = (PDRIVER_DLL_INJECT_INFO)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, sizeof(DRIVER_DLL_INJECT_INFO), DRIVER_DLL_INJECT_MEMORY_TAG);
        if (!info)
            return STATUS_INSUFFICIENT_RESOURCES;
        if (InjectionInfo)
            *InjectionInfo = info;
    }

    RtlZeroMemory(info, sizeof(DRIVER_DLL_INJECT_INFO));
    info->ProcessId = ProcessId;
    info->ForceUserApc = TRUE;
    info->Method = g_DriverDllInjectMethod;

    InsertTailList(&g_DriverDllInjectInfoListHead, &info->ListEntry);
    return STATUS_SUCCESS;
}

VOID
NTAPI
DriverDllInjectRemoveInjectionInfo(
    _In_ PDRIVER_DLL_INJECT_INFO Info,
    _In_ BOOLEAN FreeMemory
)
{
    RemoveEntryList(&Info->ListEntry);
    if (FreeMemory)
        ExFreePoolWithTag(Info, DRIVER_DLL_INJECT_MEMORY_TAG);
}

VOID
NTAPI
DriverDllInjectRemoveInjectionInfoByProcessId(
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN FreeMemory
)
{
    PLIST_ENTRY entry = g_DriverDllInjectInfoListHead.Flink;
    while (entry != &g_DriverDllInjectInfoListHead)
    {
        PDRIVER_DLL_INJECT_INFO info = CONTAINING_RECORD(entry, DRIVER_DLL_INJECT_INFO, ListEntry);
        if (info->ProcessId == ProcessId)
        {
            RemoveEntryList(&info->ListEntry);
            if (FreeMemory)
                ExFreePoolWithTag(info, DRIVER_DLL_INJECT_MEMORY_TAG);
            return;
        }
        entry = entry->Flink;
    }
}

PDRIVER_DLL_INJECT_INFO
NTAPI
DriverDllInjectFindInjectionInfo(
    _In_ HANDLE ProcessId
)
{
    PLIST_ENTRY entry = g_DriverDllInjectInfoListHead.Flink;
    while (entry != &g_DriverDllInjectInfoListHead)
    {
        PDRIVER_DLL_INJECT_INFO info = CONTAINING_RECORD(entry, DRIVER_DLL_INJECT_INFO, ListEntry);
        if (info->ProcessId == ProcessId)
            return info;
        entry = entry->Flink;
    }
    return NULL;
}

//////////////////////////////////////////////////////////////////////////
// DriverDllInjectLoadImageNotifyRoutine — 注入触发点
//
// 设计说明（参考 injdrv: https://github.com/wbenny/injdrv）：
//   - 通过 PsSetLoadImageNotifyRoutine 监听镜像加载事件
//   - 等待 ntdll.dll 加载完成后缓存 LdrLoadDll 地址
//   - 所有系统 DLL 加载完毕后才触发注入，确保 LdrLoadDll 可用
//   - 使用 kernel APC 间接调用注入，避免在 NtMapViewOfSection 调用栈中死锁
//////////////////////////////////////////////////////////////////////////

VOID
NTAPI
DriverDllInjectLoadImageNotifyRoutine(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
)
{
    /* 防护未启用时跳过 */
    if (!g_bR3ProtectionEnabled || !g_bDllInjectPathSet)
        return;

    if (!FullImageName || !FullImageName->Buffer || ProcessId <= (HANDLE)4)
        return;

    if (ImageInfo->ImagePartialMap)
        return;

    PDRIVER_DLL_INJECT_INFO info = DriverDllInjectFindInjectionInfo(ProcessId);
    if (!info)
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] No injection info for PID=%lld (not registered)\n", (INT64)(ULONG_PTR)ProcessId);
        return;
    }
    if (info->IsInjected)
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] Already injected PID=%lld, skipping\n", (INT64)(ULONG_PTR)ProcessId);
        return;
    }

    /* 跳过受保护进程 */
    PEPROCESS curProc = PsGetCurrentProcess();
    if (curProc && PsIsProtectedProcess(curProc))
    {
        DriverDllInjectDbgPrint("[DLL-INJECT] Skipping protected process PID=%lld\n", (INT64)(ULONG_PTR)ProcessId);
        DriverDllInjectRemoveInjectionInfoByProcessId(ProcessId, TRUE);
        return;
    }

    if (!DriverDllInjectCanInject(info))
    {
        /* 检测系统 DLL 加载，标记状态 */
        DRIVER_DLL_INJECT_SYSTEM_DLL flag = DriverDllInjectGetSystemDllFlag(FullImageName);
        if (flag != DriverDllInjectNothingLoaded)
        {
            info->LoadedDlls |= flag;
            DriverDllInjectDbgPrint("[DLL-INJECT] PID=%lld loaded DLL flag=0x%X total=0x%X\n",
                (INT64)(ULONG_PTR)ProcessId, flag, info->LoadedDlls);

            /* 缓存 ntdll!LdrLoadDll 地址（完全对齐参考实现 injlib:1376-1404）
             * - thunk 模式：System32\ntdll 或 SysWow64\ntdll 均可提供 LdrLoadDll
             * - thunkless 模式：仅使用 System32\ntdll（x64 原生） */
            if (ImageInfo->ImageBase &&
                (flag == DriverDllInjectSystem32NtdllLoaded ||
                 flag == DriverDllInjectSysWow64NtdllLoaded ||
                 flag == DriverDllInjectSysArm32NtdllLoaded ||
                 flag == DriverDllInjectSyChpe32NtdllLoaded))
            {
                ANSI_STRING ldrName = RTL_CONSTANT_STRING("LdrLoadDll");
                PVOID addr = DriverDllInjectFindExportedRoutineByName(
                    ImageInfo->ImageBase, &ldrName);
                if (addr)
                {
                    /* 与参考实现 InjpLoadImageNotifyRoutine switch-case 逻辑对齐 */
                    if (flag == DriverDllInjectSystem32NtdllLoaded)
                    {
                        /* System32\ntdll: thunkless 和 thunk 均使用（参考实现无条件设置） */
                        info->LdrLoadDllRoutineAddress = addr;
                        DriverDllInjectDbgPrint("[DLL-INJECT] PID=%lld LdrLoadDll cached: %p (System32 ntdll)\n",
                            (INT64)(ULONG_PTR)ProcessId, addr);
                    }
                    else
                    {
                        /* SysWow64/SysArm32/SyChpe32\ntdll: 无条件缓存（WoW64 32 位 ntdll 最后加载，
                         * 覆盖 System32\ntdll 缓存的 64 位地址；否则 Thunkless+WoW64 回退 thunk 时
                         * 会用 64 位 LdrLoadDll，32 位 thunk 调用它会导致主线程崩溃）。
                         * 原生 x64 进程不会加载这些 ntdll，不受影响。 */
                        info->LdrLoadDllRoutineAddress = addr;
                        DriverDllInjectDbgPrint("[DLL-INJECT] PID=%lld LdrLoadDll cached: %p (%wZ)\n",
                            (INT64)(ULONG_PTR)ProcessId, addr, FullImageName);
                    }
                }
                else
                {
                    DriverDllInjectDbgPrint("[DLL-INJECT] PID=%lld LdrLoadDll NOT found in %wZ\n",
                        (INT64)(ULONG_PTR)ProcessId, FullImageName);
                }
            }
        }
        DriverDllInjectDbgPrint("[DLL-INJECT] PID=%lld CanInject=NO loaded=0x%X required=0x%X method=%d ldr=%p\n",
            (INT64)(ULONG_PTR)ProcessId, info->LoadedDlls,
            DriverDllInjectSystem32NtdllLoaded,
            info->Method, info->LdrLoadDllRoutineAddress);
        return;
    }

    DriverDllInjectDbgPrint("[DLL-INJECT] PID=%lld CanInject=YES injecting!\n", (INT64)(ULONG_PTR)ProcessId);

    /* Windows 7 Wow64 额外延迟（等待 kernel32/user32 加载完成） */
#ifdef DRIVER_DLL_INJECT_CONFIG_SUPPORTS_WOW64
    {
        PEPROCESS targetProc = NULL;
        NTSTATUS wow64Status = PsLookupProcessByProcessId(ProcessId, &targetProc);
        if (NT_SUCCESS(wow64Status) && targetProc &&
            g_DriverDllInjectIsWindows7 &&
            info->Method == DriverDllInjectMethodThunk &&
            PsGetProcessWow64Process(targetProc))
        {
            static const struct { UNICODE_STRING Suffix; } waitDlls[] = {
                { RTL_CONSTANT_STRING(L"\\System32\\kernel32.dll") },
                { RTL_CONSTANT_STRING(L"\\SysWOW64\\kernel32.dll") },
                { RTL_CONSTANT_STRING(L"\\System32\\user32.dll")   },
                { RTL_CONSTANT_STRING(L"\\SysWOW64\\user32.dll")   },
            };
            for (ULONG i = 0; i < RTL_NUMBER_OF(waitDlls); i++)
            {
                if (FullImageName->Length >= waitDlls[i].Suffix.Length)
                {
                    UNICODE_STRING tail;
                    tail.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer +
                                           FullImageName->Length - waitDlls[i].Suffix.Length);
                    tail.Length = waitDlls[i].Suffix.Length;
                    tail.MaximumLength = waitDlls[i].Suffix.Length;
                    if (RtlEqualUnicodeString(&waitDlls[i].Suffix, &tail, TRUE))
                    {
                        DriverDllInjectDbgPrint("[DLL-INJECT] Postponing injection (%wZ)\n", FullImageName);
                        ObDereferenceObject(targetProc);
                        return;
                    }
                }
            }
        }
        if (targetProc)
            ObDereferenceObject(targetProc);
    }
#endif

    DriverDllInjectDbgPrint("[DLL-INJECT] Injecting PID=%lld\n", (INT64)(ULONG_PTR)ProcessId);

    /* 通过 kernel APC 排队注入（避免在 MapViewOfSection 调用栈中死锁） */
    NTSTATUS injectStatus = DriverDllInjectQueueApc(KernelMode,
                                                    DriverDllInjectApcNormalRoutine,
                                                    info, NULL, NULL);
    if (NT_SUCCESS(injectStatus))
        info->IsInjected = TRUE;
    else
        DriverDllInjectDbgPrint("[DLL-INJECT] Failed to queue APC PID=%lld: 0x%X\n",
                               (INT64)(ULONG_PTR)ProcessId, injectStatus);
}

//////////////////////////////////////////////////////////////////////////
// 初始化与销毁
//////////////////////////////////////////////////////////////////////////

NTSTATUS
NTAPI
DriverDllInjectInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath,
    _In_ PDRIVER_DLL_INJECT_SETTINGS Settings
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    if (!Settings)
        return STATUS_INVALID_PARAMETER;

    InitializeListHead(&g_DriverDllInjectInfoListHead);

    /* 检测 Windows 7 */
    RTL_OSVERSIONINFOW ver = { 0 };
    ver.dwOSVersionInfoSize = sizeof(ver);
    RtlGetVersion(&ver);
    if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 1)
    {
        g_DriverDllInjectIsWindows7 = TRUE;
        DriverDllInjectDbgPrint("[DLL-INJECT] Windows 7 detected\n");
    }

    /* 设置注入方法 */
#if defined(_M_AMD64)
    g_DriverDllInjectMethod = Settings->Method;
    /* thunkless 仅 x64 原生支持 */
    if (g_DriverDllInjectMethod != DriverDllInjectMethodThunk &&
        g_DriverDllInjectMethod != DriverDllInjectMethodThunkless)
        g_DriverDllInjectMethod = DriverDllInjectMethodThunk;
#elif defined(_M_IX86)
    g_DriverDllInjectMethod = DriverDllInjectMethodThunk;
#elif defined(_M_ARM64)
    g_DriverDllInjectMethod = DriverDllInjectMethodWow64LogReparse;
#else
    g_DriverDllInjectMethod = DriverDllInjectMethodThunk;
#endif

    DriverDllInjectDbgPrint("[DLL-INJECT] Method: %s\n",
        g_DriverDllInjectMethod == DriverDllInjectMethodThunk           ? "Thunk"           :
        g_DriverDllInjectMethod == DriverDllInjectMethodThunkless       ? "Thunkless"       :
        g_DriverDllInjectMethod == DriverDllInjectMethodWow64LogReparse ? "Wow64LogReparse" : "Unknown");

    return STATUS_SUCCESS;
}

VOID
NTAPI
DriverDllInjectDestroy(
    VOID
)
{
    PLIST_ENTRY entry = g_DriverDllInjectInfoListHead.Flink;
    while (entry != &g_DriverDllInjectInfoListHead)
    {
        PLIST_ENTRY next = entry->Flink;
        PDRIVER_DLL_INJECT_INFO info = CONTAINING_RECORD(entry, DRIVER_DLL_INJECT_INFO, ListEntry);
        ExFreePoolWithTag(info, DRIVER_DLL_INJECT_MEMORY_TAG);
        entry = next;
    }
    InitializeListHead(&g_DriverDllInjectInfoListHead);
    DriverDllInjectDbgPrint("[DLL-INJECT] Destroyed\n");
}
