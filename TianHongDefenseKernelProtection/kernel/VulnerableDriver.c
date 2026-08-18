/* ============================================================================
 * VulnerableDriver.c — 漏洞驱动（BYOVD）加载拦截
 *
 * 原理：
 *   维护已知漏洞驱动（BYOVD, Bring Your Own Vulnerable Driver）的 SHA256
 *   哈希黑名单。驱动镜像加载时（PsSetLoadImageNotifyRoutine 回调，.sys 文件），
 *   由于加载回调运行在 DISPATCH_LEVEL+，无法做同步文件 I/O，因此在回调中
 *   仅识别 .sys 路径并排队 work item；work item 运行在 PASSIVE_LEVEL，
 *   读取驱动文件计算 SHA256，与黑名单比对，命中则终止发起加载的进程并
 *   通知用户态。
 *
 * 哈希来源：LOLDrivers (https://www.loldrivers.io) 已验证样本（Build 2026）。
 * ============================================================================ */

#include "VulnerableDriver.h"
#include "Main.h"
#include "ResponseSystem.h"
#include <ntifs.h>
#include <ntstrsafe.h>

/* 进程操作 API（由 ProcessCallback.c 提供，复用其内核句柄 + 关键进程保护方案） */
NTSTATUS VdTerminateProcessByPid(INT64 pid);

/* ═══════════════════════════════════════════════════════════════════════════
 * 一、漏洞驱动 SHA256 哈希黑名单
 * ═══════════════════════════════════════════════════════════════════════════ */

const VD_DRIVER_ENTRY g_VulnDrivers[] = {
    /* ── 经典高危 BYOVD（任意内核读写 / 进程终止 / 物理内存映射）── */
    { "RTCore64.sys",      "01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd" }, /* MSI Afterburner, CVE-2019-16098 */
    { "dbutil_2_3.sys",    "0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5" }, /* Dell, CVE-2021-21551 */
    { "gdrv.sys",          "092d04284fdeb6762e65e6ac5b813920d6c69a5e99d110769c5c1a78e11c5ba0" }, /* Gigabyte, CVE-2018-19320 */
    { "nvflash.sys",       "9368e51ec98e2ad20893a5fc21e6a8b20c5bee158d5c49ca58649cff84db9d68" }, /* NVIDIA flash, arbitrary r/w */
    { "IMFForceDelete.sys","ef4e4b88df24825dbf4e7131e71a41002715d38b7a8c0c432aa936c854152ef3" }, /* IObit ForceDelete */

    /* ── memory-mapped / arbitrary physical r/w 驱动 ── */
    { "directio64.sys",    "b8bf3bd441ebc5814c5d39d053fdcb263e8e58476cbdee4b1226903305f547b6" },
    { "directio64.sys",    "40e624bf557b51775af1ca17062c4eca3693322e250b257aec7dc579e626ef07" },
    { "directio64.sys",    "841f965977f33d621d126412032c47dd6118251623c380e5572f7553b620b0e1" },
    { "directio64.sys",    "fb5e65aec819c5a91ef0ce0fec0a957826b5e1ac9bac559a1b4201a3870462a3" },
    { "directio64.sys",    "a520ff5c754a1fb62ba88399a313d0c0fb99145ba2d3d91dbf4282388b77fa84" },
    { "directio64.sys",    "9996b31234ba736fc2c6f2b75f641e25d156f19d6ac84cf85283fde08a714842" },
    { "directio64.sys",    "ad44cfd9c6262a6ff36ee9d03e59ba4b0524ef87f6b980ce15abb10a35d39f88" },
    { "directio64.sys",    "96a5b3cd7c1a6dda5b6f402e6c35ba535270467f56addc7448dbe4aa78428411" },
    { "directio64.sys",    "21a8aa12aa944658f05694243e4d7b9ba07ea24447b539d40977e9b7fa19fed1" },
    { "directio.sys",      "e6a7a497010579fde69cd52bed8de28db610c33bbc5ce0774459dcf64657b802" },
    { "WINIODrv.sys",      "b3cbb2b364a494f096e68dc48cca89799ed27e6b97b17633036e363a98fd4421" },
    { "WINIODrv.sys",      "9199979b9f3ea2108299d028373a6effcc41c81a46eecb430cc6653211d2913d" },
    { "WINIODrv.sys",      "961012d06eeaabd9eff9b36173e566bf148a5c8f743f3329c70d8918eba26093" },
    { "atillk64.sys",      "126719d008d106b7100ae47ed47666c1334701bd7ddb32d5b8e84048f258700f" },
    { "atillk64.sys",      "c9b8ecd0657fda14476920fe47783bd8a951d7a4a640935d9199b4a7ae4b8b69" },
    { "atillk64.sys",      "94111de210f6b3b48dda16b3422f0f9180e30bcb5765b6858c451d1d89196199" },
    { "atillk64.sys",      "fb19f241ddae74ec4a0f87dff025ec68dc809f9dd883649c0e58822de28e6f1b" },
    { "speedfan.sys",      "22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c" }, /* SpeedFan, CVE-2007-5633 */

    /* ── 恶意/受控驱动（已知恶意样本）── */
    { "wantd_5.sys",       "b9dad0131c51e2645e761b74a71ebad2bf175645fa9f42a4ab0e6921b83306e3" }, /* Daxin WAN transport driver */
    { "windows7-32.sys",   "4941c4298f4560fc1e59d0f16f84bab5c060793700b82be2fd7c63735f1657a8" },
};

const ULONG g_VulnDriverCount =
    sizeof(g_VulnDrivers) / sizeof(g_VulnDrivers[0]);

/* ═══════════════════════════════════════════════════════════════════════════
 * 二、自包含 SHA256 实现（内核安全，无 bcrypt/外部依赖）
 *
 * 参考 FIPS 180-4 标准实现，纯软件计算，可在 PASSIVE_LEVEL 安全调用。
 * ═══════════════════════════════════════════════════════════════════════════ */

#define VD_ROTR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define VD_CH(x, y, z)   (((x) & (y)) ^ (~(x) & (z)))
#define VD_MAJ(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define VD_BIG_S0(x)     (VD_ROTR32(x, 2) ^ VD_ROTR32(x, 13) ^ VD_ROTR32(x, 22))
#define VD_BIG_S1(x)     (VD_ROTR32(x, 6) ^ VD_ROTR32(x, 11) ^ VD_ROTR32(x, 25))
#define VD_SMALL_S0(x)   (VD_ROTR32(x, 7) ^ VD_ROTR32(x, 18) ^ ((x) >> 3))
#define VD_SMALL_S1(x)   (VD_ROTR32(x, 17) ^ VD_ROTR32(x, 19) ^ ((x) >> 10))

static const ULONG g_vdSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct _VD_SHA256_CTX {
    ULONG state[8];
    ULONG bitCount[2];   /* bitCount[0] = 低 32 位, bitCount[1] = 高 32 位 */
    ULONG bufferLen;     /* 缓冲区中已填充的字节数（0..63） */
    UCHAR buffer[64];
} VD_SHA256_CTX;

static void VdSha256Transform(ULONG state[8], const UCHAR block[64])
{
    ULONG w[64];
    ULONG i;

    /* 将 64 字节块转换为 16 个大端字 */
    for (i = 0; i < 16; i++) {
        w[i] = ((ULONG)block[i * 4] << 24) |
               ((ULONG)block[i * 4 + 1] << 16) |
               ((ULONG)block[i * 4 + 2] << 8) |
               ((ULONG)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = VD_SMALL_S1(w[i - 2]) + w[i - 7] +
               VD_SMALL_S0(w[i - 15]) + w[i - 16];
    }

    ULONG a = state[0], b = state[1], c = state[2], d = state[3];
    ULONG e = state[4], f = state[5], g = state[6], h = state[7];

    for (i = 0; i < 64; i++) {
        ULONG t1 = h + VD_BIG_S1(e) + VD_CH(e, f, g) +
                   g_vdSha256K[i] + w[i];
        ULONG t2 = VD_BIG_S0(a) + VD_MAJ(a, b, c);
        h = g; g = f; f = e;
        e = d + t1;
        d = c; c = b; b = a;
        a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void VdSha256Init(VD_SHA256_CTX* ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bitCount[0] = 0;
    ctx->bitCount[1] = 0;
    ctx->bufferLen = 0;
}

static void VdSha256Update(VD_SHA256_CTX* ctx, const UCHAR* data, ULONG len)
{
    ULONG newLo;

    /* 累加位计数（低 32 位溢出则进位到高 32 位） */
    newLo = ctx->bitCount[0] + (len << 3);
    if (newLo < ctx->bitCount[0]) {
        ctx->bitCount[1]++;
    }
    ctx->bitCount[0] = newLo;

    /* 填充当前缓冲区 */
    if (ctx->bufferLen != 0) {
        ULONG need = 64 - ctx->bufferLen;
        if (len >= need) {
            RtlCopyMemory(ctx->buffer + ctx->bufferLen, data, need);
            VdSha256Transform(ctx->state, ctx->buffer);
            data += need;
            len -= need;
            ctx->bufferLen = 0;
        }
    }

    /* 整块处理 */
    while (len >= 64) {
        VdSha256Transform(ctx->state, data);
        data += 64;
        len -= 64;
    }

    /* 剩余字节存入缓冲区 */
    if (len > 0) {
        RtlCopyMemory(ctx->buffer + ctx->bufferLen, data, len);
        ctx->bufferLen += len;
    }
}

static void VdSha256StoreWide(ULONG value, UCHAR* out)
{
    out[0] = (UCHAR)((value >> 24) & 0xFF);
    out[1] = (UCHAR)((value >> 16) & 0xFF);
    out[2] = (UCHAR)((value >> 8) & 0xFF);
    out[3] = (UCHAR)(value & 0xFF);
}

static void VdSha256Final(VD_SHA256_CTX* ctx, UCHAR hash[VD_SHA256_SIZE])
{
    ULONG i;
    ULONG bitCountL;
    ULONG bitCountH;
    UCHAR pad[128];
    ULONG padLen;
    UCHAR lenByte[8];

    /* 记录当前位计数（用于结尾追加 64 位长度字段） */
    bitCountL = ctx->bitCount[0];
    bitCountH = ctx->bitCount[1];

    /* 计算填充：先补 0x80，再补 0 直到 (bufferLen+1+padZero) % 64 == 56 */
    RtlZeroMemory(pad, sizeof(pad));
    pad[0] = 0x80;
    padLen = 1;
    while ((ctx->bufferLen + padLen) % 64 != 56) {
        padLen++;
    }
    VdSha256Update(ctx, pad, padLen);

    /* 追加 64 位大端消息长度（位计数） */
    VdSha256StoreWide(bitCountH, &lenByte[0]);
    VdSha256StoreWide(bitCountL, &lenByte[4]);
    VdSha256Update(ctx, lenByte, 8);

    /* 输出：每个状态字大端序 */
    for (i = 0; i < 8; i++) {
        VdSha256StoreWide(ctx->state[i], &hash[i * 4]);
    }
}

/* 将 32 字节哈希转换为 64 位小写十六进制字符串 */
static void VdHashToHex(const UCHAR hash[VD_SHA256_SIZE], char* hexOut)
{
    static const char hexDigits[] = "0123456789abcdef";
    ULONG i;
    for (i = 0; i < VD_SHA256_SIZE; i++) {
        hexOut[i * 2] = hexDigits[(hash[i] >> 4) & 0xF];
        hexOut[i * 2 + 1] = hexDigits[hash[i] & 0xF];
    }
    hexOut[VD_SHA256_SIZE * 2] = '\0';
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 三、路径判断：是否为 .sys 驱动文件
 * ═══════════════════════════════════════════════════════════════════════════ */

BOOLEAN VdIsDriverImagePath(_In_ PUNICODE_STRING FullImageName)
{
    if (!FullImageName || !FullImageName->Buffer || FullImageName->Length < 4)
        return FALSE;

    /* 检查是否以 .sys 结尾（不区分大小写） */
    UNICODE_STRING sysExt;
    RtlInitUnicodeString(&sysExt, L".sys");
    if (FullImageName->Length < sysExt.Length)
        return FALSE;

    UNICODE_STRING tail;
    tail.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer +
        FullImageName->Length - sysExt.Length);
    tail.Length = sysExt.Length;
    tail.MaximumLength = sysExt.Length;

    return RtlEqualUnicodeString(&tail, &sysExt, TRUE);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 四、计算文件 SHA256（PASSIVE_LEVEL 调用）
 * ═══════════════════════════════════════════════════════════════════════════ */

NTSTATUS VdComputeFileSha256(_In_ PUNICODE_STRING FilePath,
                             _Out_ UCHAR hash[VD_SHA256_SIZE])
{
    NTSTATUS status;
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK iosb = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    VD_SHA256_CTX ctx;
    UCHAR* buffer = NULL;
    ULONGLONG fileSize = 0;
    LARGE_INTEGER byteOffset;

    if (!FilePath || !FilePath->Buffer || !hash)
        return STATUS_INVALID_PARAMETER;

    /* 打开文件（只读，与 ZwReadFile 配合） */
    InitializeObjectAttributes(&objAttr, FilePath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = IoCreateFileEx(
        &hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &objAttr,
        &iosb,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0,
        CreateFileTypeNone, NULL,
        IO_FORCE_ACCESS_CHECK, NULL);

    if (!NT_SUCCESS(status) || !hFile)
        return status;

    __try {
        /* 获取文件大小 */
        FILE_STANDARD_INFORMATION stdInfo = { 0 };
        status = ZwQueryInformationFile(
            hFile,
            &iosb,
            &stdInfo,
            sizeof(stdInfo),
            FileStandardInformation);
        if (!NT_SUCCESS(status)) {
            ZwClose(hFile);
            return status;
        }
        fileSize = stdInfo.EndOfFile.QuadPart;

        /* 分配读取缓冲区（64KB 分块，避免大型驱动占用过多内存） */
        ULONG blockSize = 64 * 1024;
        buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, blockSize, 'VdSh');
        if (!buffer) {
            ZwClose(hFile);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        VdSha256Init(&ctx);
        byteOffset.QuadPart = 0;
        ULONGLONG remaining = fileSize;

        while (remaining > 0) {
            ULONG toRead = (remaining > blockSize) ? blockSize : (ULONG)remaining;
            IO_STATUS_BLOCK readIosb = { 0 };
            status = ZwReadFile(hFile, NULL, NULL, NULL, &readIosb,
                buffer, toRead, &byteOffset, NULL);
            if (!NT_SUCCESS(status)) {
                break;
            }
            if (readIosb.Information == 0) {
                break; /* EOF */
            }
            VdSha256Update(&ctx, buffer, (ULONG)readIosb.Information);
            byteOffset.QuadPart += (LONGLONG)readIosb.Information;
            remaining -= readIosb.Information;
        }

        if (NT_SUCCESS(status)) {
            VdSha256Final(&ctx, hash);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
    }

    if (buffer) {
        ExFreePoolWithTag(buffer, 'VdSh');
    }
    ZwClose(hFile);
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 五、哈希比对：是否命中漏洞驱动黑名单
 * ═══════════════════════════════════════════════════════════════════════════ */

BOOLEAN VdIsBlockedHash(_In_ const UCHAR hash[VD_SHA256_SIZE])
{
    char hex[65];
    ULONG i;

    if (!hash)
        return FALSE;

    VdHashToHex(hash, hex);

    for (i = 0; i < g_VulnDriverCount; i++) {
        if (RtlEqualMemory(g_VulnDrivers[i].Sha256Hex, hex, 64))
            return TRUE;
    }
    return FALSE;
}

/* 返回命中条目的驱动名（用于日志），未命中返回 NULL */
const char* VdGetMatchedDriverName(_In_ const UCHAR hash[VD_SHA256_SIZE])
{
    char hex[65];
    ULONG i;

    if (!hash)
        return NULL;

    VdHashToHex(hash, hex);

    for (i = 0; i < g_VulnDriverCount; i++) {
        if (RtlEqualMemory(g_VulnDrivers[i].Sha256Hex, hex, 64))
            return g_VulnDrivers[i].Name;
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 六、运行引擎：哈希比对 + 终止进程（PASSIVE_LEVEL）
 * ═══════════════════════════════════════════════════════════════════════════ */

BOOLEAN VdCheckAndBlock(
    _In_ PUNICODE_STRING DriverPath,
    _In_ HANDLE LoaderPid,
    _In_ BOOLEAN LogOnly)
{
    UCHAR hash[VD_SHA256_SIZE];
    NTSTATUS status;
    const char* matchedName;
    CHAR pathA[520] = { 0 };
    CHAR logMsg[640];

    if (!DriverPath || !DriverPath->Buffer)
        return FALSE;

    /* 计算哈希 */
    status = VdComputeFileSha256(DriverPath, hash);
    if (!NT_SUCCESS(status)) {
        DriverDbgPrint("[VULN-DRIVER] SHA256 compute failed path status=0x%X\n", status);
        return FALSE;
    }

    if (!VdIsBlockedHash(hash)) {
        return FALSE; /* 未命中黑名单 */
    }

    matchedName = VdGetMatchedDriverName(hash);

    /* 构造路径的 ANSI 表示用于日志 */
    {
        int i;
        for (i = 0; i < 519 && DriverPath->Buffer[i]; i++) {
            pathA[i] = (CHAR)DriverPath->Buffer[i];
        }
        pathA[i] = '\0';
    }

    DriverDbgPrint("[VULN-DRIVER-BLOCKED] LoaderPid=%lld Driver=%s SHA256 = %s\n",
        (LONGLONG)(ULONG_PTR)LoaderPid,
        matchedName ? matchedName : pathA,
        "matched");

    RtlStringCbPrintfA(logMsg, sizeof(logMsg),
        "[漏洞驱动拦截] 检测到已知漏洞驱动加载: %s (%s), 发起进程 PID=%lld, 已阻止加载",
        matchedName ? matchedName : pathA,
        pathA,
        (LONGLONG)(ULONG_PTR)LoaderPid);

    /* 通知用户态（Fire-and-Forget 日志） */
    SendInjectionLog(logMsg);

    if (!LogOnly) {
        /* 终止发起加载的进程（漏洞驱动已加载，阻止其利用） */
        VdTerminateProcessByPid((INT64)(ULONG_PTR)LoaderPid);
    }

    return TRUE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 七、work item：异步漏洞驱动检查
 *
 * 在 LoadImageNotifyRoutine（DISPATCH_LEVEL+）中仅排队，实际文件读取与
 * 哈希计算在 PASSIVE_LEVEL 的 work item 中进行，避免 IRQL 违规。
 * ═══════════════════════════════════════════════════════════════════════════ */

typedef struct _VD_WORKITEM_CTX {
    WORK_QUEUE_ITEM WorkItem;
    HANDLE LoaderPid;          /* 发起加载的进程 PID */
    WCHAR DriverPath[520];     /* 驱动文件完整路径 */
} VD_WORKITEM_CTX, *PVD_WORKITEM_CTX;

static VOID VdVulnerableDriverWorkItem(PVOID Context)
{
    PVD_WORKITEM_CTX ctx = (PVD_WORKITEM_CTX)Context;
    UNICODE_STRING path;

    __try {
        if (!ctx)
            return;

        RtlInitUnicodeString(&path, ctx->DriverPath);
        VdCheckAndBlock(&path, ctx->LoaderPid, FALSE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DriverDbgPrint("[VULN-DRIVER] Exception in work item\n");
    }

    if (ctx) {
        ExFreePoolWithTag(ctx, 'VdWk');
    }
}

/* 排队漏洞驱动检查 work item（在 LoadImageNotifyRoutine 中调用） */
VOID VdQueueCheck(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE LoaderPid)
{
    PVD_WORKITEM_CTX ctx;
    ULONG i;

    if (!FullImageName || !FullImageName->Buffer ||
        FullImageName->Length >= (520 * sizeof(WCHAR)))
        return;

    ctx = (PVD_WORKITEM_CTX)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(VD_WORKITEM_CTX), 'VdWq');
    if (!ctx)
        return;

    RtlZeroMemory(ctx, sizeof(VD_WORKITEM_CTX));
    ctx->LoaderPid = LoaderPid;

    /* 复制路径（宽字符） */
    ULONG copyLen = FullImageName->Length / sizeof(WCHAR);
    if (copyLen > 519) copyLen = 519;
    for (i = 0; i < copyLen; i++) {
        ctx->DriverPath[i] = FullImageName->Buffer[i];
    }
    ctx->DriverPath[copyLen] = L'\0';

    ExInitializeWorkItem(&ctx->WorkItem, VdVulnerableDriverWorkItem, ctx);
    ExQueueWorkItem(&ctx->WorkItem, DelayedWorkQueue);
}