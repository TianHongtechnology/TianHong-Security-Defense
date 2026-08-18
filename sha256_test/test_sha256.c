#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- Copy of the SHA256 implementation from VulnerableDriver.c ---- */
typedef unsigned char UCHAR;
typedef unsigned long ULONG;
#define RtlCopyMemory memcpy
#define RtlZeroMemory(z, n) memset(z, 0, n)

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
    ULONG bitCount[2];
    ULONG bufferLen;
    UCHAR buffer[64];
} VD_SHA256_CTX;

static void VdSha256Transform(ULONG state[8], const UCHAR block[64])
{
    ULONG w[64];
    ULONG i;
    for (i = 0; i < 16; i++) {
        w[i] = ((ULONG)block[i * 4] << 24) | ((ULONG)block[i * 4 + 1] << 16) |
               ((ULONG)block[i * 4 + 2] << 8) | ((ULONG)block[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        w[i] = VD_SMALL_S1(w[i - 2]) + w[i - 7] + VD_SMALL_S0(w[i - 15]) + w[i - 16];
    }
    ULONG a = state[0], b = state[1], c = state[2], d = state[3];
    ULONG e = state[4], f = state[5], g = state[6], h = state[7];
    for (i = 0; i < 64; i++) {
        ULONG t1 = h + VD_BIG_S1(e) + VD_CH(e, f, g) + g_vdSha256K[i] + w[i];
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
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitCount[0] = 0; ctx->bitCount[1] = 0; ctx->bufferLen = 0;
}

static void VdSha256Update(VD_SHA256_CTX* ctx, const UCHAR* data, ULONG len)
{
    ULONG newLo;
    newLo = ctx->bitCount[0] + (len << 3);
    if (newLo < ctx->bitCount[0]) ctx->bitCount[1]++;
    ctx->bitCount[0] = newLo;
    if (ctx->bufferLen != 0) {
        ULONG need = 64 - ctx->bufferLen;
        if (len >= need) {
            RtlCopyMemory(ctx->buffer + ctx->bufferLen, data, need);
            VdSha256Transform(ctx->state, ctx->buffer);
            data += need; len -= need; ctx->bufferLen = 0;
        }
    }
    while (len >= 64) { VdSha256Transform(ctx->state, data); data += 64; len -= 64; }
    if (len > 0) { RtlCopyMemory(ctx->buffer + ctx->bufferLen, data, len); ctx->bufferLen += len; }
}

static void VdSha256StoreWide(ULONG value, UCHAR* out)
{
    out[0] = (UCHAR)((value >> 24) & 0xFF); out[1] = (UCHAR)((value >> 16) & 0xFF);
    out[2] = (UCHAR)((value >> 8) & 0xFF);  out[3] = (UCHAR)(value & 0xFF);
}

static void VdSha256Final(VD_SHA256_CTX* ctx, UCHAR hash[32])
{
    ULONG i, bitCountL, bitCountH;
    UCHAR pad[128]; ULONG padLen; UCHAR lenByte[8];
    bitCountL = ctx->bitCount[0]; bitCountH = ctx->bitCount[1];
    RtlZeroMemory(pad, sizeof(pad)); pad[0] = 0x80; padLen = 1;
    while ((ctx->bufferLen + padLen) % 64 != 56) padLen++;
    VdSha256Update(ctx, pad, padLen);
    VdSha256StoreWide(bitCountH, &lenByte[0]);
    VdSha256StoreWide(bitCountL, &lenByte[4]);
    VdSha256Update(ctx, lenByte, 8);
    for (i = 0; i < 8; i++) VdSha256StoreWide(ctx->state[i], &hash[i * 4]);
}

static void hexdump(const unsigned char* h, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", h[i]);
    printf("\n");
}

static int check(const char* name, const unsigned char* got, const char* expect) {
    /* Compare 32-byte binary hash against 64-char lowercase hex string */
    static const char hexDigits[] = "0123456789abcdef";
    int ok = 1;
    size_t k;
    for (k = 0; k < 32; k++) {
        unsigned char hi = hexDigits[(got[k] >> 4) & 0xF];
        unsigned char lo = hexDigits[got[k] & 0xF];
        if ((unsigned char)expect[k*2] != hi || (unsigned char)expect[k*2+1] != lo) {
            ok = 0; break;
        }
    }
    printf("%s: %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) { printf("  got:      "); hexdump(got, 32); printf("  expected: %s\n", expect); }
    return ok ? 0 : 1;
}

int main(void) {
    int fails = 0;
    {
        VD_SHA256_CTX ctx; unsigned char h[32];
        VdSha256Init(&ctx); VdSha256Final(&ctx, h);
        fails += check("SHA256(\"\")", h, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
    {
        VD_SHA256_CTX ctx; unsigned char h[32];
        VdSha256Init(&ctx); VdSha256Update(&ctx, (const UCHAR*)"abc", 3); VdSha256Final(&ctx, h);
        fails += check("SHA256(\"abc\") single-update", h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    {
        VD_SHA256_CTX ctx; unsigned char h[32];
        VdSha256Init(&ctx);
        VdSha256Update(&ctx, (const UCHAR*)"a", 1);
        VdSha256Update(&ctx, (const UCHAR*)"b", 1);
        VdSha256Update(&ctx, (const UCHAR*)"c", 1);
        VdSha256Final(&ctx, h);
        fails += check("SHA256(a,b,c) streamed", h, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
    {
        VD_SHA256_CTX ctx; unsigned char h[32];
        VdSha256Init(&ctx); VdSha256Update(&ctx, (const UCHAR*)"a", 1); VdSha256Final(&ctx, h);
        fails += check("SHA256(\"a\")", h, "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    }
    {
        /* Multi-block: 55 bytes, padding + 8-byte length fit in same block */
        VD_SHA256_CTX ctx; unsigned char h[32]; char msg[55];
        memset(msg, 'a', 55);
        VdSha256Init(&ctx); VdSha256Update(&ctx, (const UCHAR*)msg, 55); VdSha256Final(&ctx, h);
        fails += check("SHA256(55*a)", h, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    }
    {
        /* Multi-block: 64 bytes fills exactly one block, padding goes to second block */
        VD_SHA256_CTX ctx; unsigned char h[32]; char msg[64];
        memset(msg, 'a', 64);
        VdSha256Init(&ctx); VdSha256Update(&ctx, (const UCHAR*)msg, 64); VdSha256Final(&ctx, h);
        fails += check("SHA256(64*a)", h, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    }
    {
        VD_SHA256_CTX ctx; unsigned char h[32]; char msg[65];
        memset(msg, 'a', 65);
        VdSha256Init(&ctx); VdSha256Update(&ctx, (const UCHAR*)msg, 65); VdSha256Final(&ctx, h);
        fails += check("SHA256(65*a)", h, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");
    }
    printf("\nTotal failures: %d\n", fails);
    return fails;
}