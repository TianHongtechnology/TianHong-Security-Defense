#define _CRT_SECURE_NO_WARNINGS
#define IS_MODE_FLASH FALSE

#include "PEScan.h"
#include <atlstr.h>
#include <algorithm>
#include <comutil.h>
#include <vector>
#include <sfc.h>
#include <WinTrust.h>
#include <SoftPub.h>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <yara.h>

#pragma comment(lib, "libyara64.lib")

#pragma comment(lib, "comsuppw.lib") // 链接库
#pragma comment(lib, "sfc.lib")
#pragma comment(lib, "wintrust.lib")

BOOL PE_IsReady = FALSE;

YR_RULES* Yara_Rules; // YARA 规则

LightGBMClassifier mPEModel;

std::unordered_map<std::string, std::string> Sha256List;
std::unordered_set<std::string> WhiteSha256List;

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

string ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)
{
    wstring ws = lpwszStrIn;
    _bstr_t t = ws.c_str();
    char* pt = _strdup(t);
    string s = pt;
    free(pt);   // _strdup 使用 malloc 分配，必须用 free 释放
    return s;
}

bool CompareWithoutCap(const string& str1, const string& str2)
{
    if (str1.size() != str2.size())
        return false;

    for (size_t i = 0; i < str1.size(); ++i)
    {
        if (::tolower(static_cast<unsigned char>(str1[i])) !=
            ::tolower(static_cast<unsigned char>(str2[i])))
            return false;
    }
    return true;
}

// 计算文件熵值
double File_CalculateEntropy(const string& filePath) {
    // 打开文件
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        // std::cerr << "无法打开文件: " << filePath << std::endl;
        return -1.0;
    }

    // 获取文件大小
    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0) {
        // std::cerr << "文件为空或无法获取大小" << std::endl;
        return 0.0;
    }

    // 回到文件开头
    file.seekg(0, std::ios::beg);

    // 统计每个字节的出现次数
    unsigned int byteCount[256] = { 0 };
    unsigned char buffer[4096];

    while (file) {
        file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        std::streamsize bytesRead = file.gcount();

        for (std::streamsize i = 0; i < bytesRead; ++i) {
            byteCount[buffer[i]]++;
        }
    }

    // 计算熵值
    double entropy = 0.0;
    double totalBytes = static_cast<double>(fileSize);

    for (int i = 0; i < 256; ++i) {
        if (byteCount[i] > 0) {
            double probability = static_cast<double>(byteCount[i]) / totalBytes;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

string File_GetShortFileName(string longFileName)
{
    char shortPath[MAX_PATH];
    DWORD result = GetShortPathNameA(longFileName.c_str(), shortPath, MAX_PATH);
    if (result == 0)
    {
        return longFileName;
    }
    else
    {
        return longFileName.substr(0, longFileName.find_last_of('\\')) + ((string)shortPath).substr(((string)shortPath).find_last_of('\\'));
    }
}

bool File_IsModifiedOverOneDay(wchar_t* filePath)
{
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
    {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    // 转换为系统时间
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ftWrite, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    // 转换为time_t
    struct tm tm;
    tm.tm_year = stLocal.wYear - 1900;
    tm.tm_mon = stLocal.wMonth - 1;
    tm.tm_mday = stLocal.wDay;
    tm.tm_hour = stLocal.wHour;
    tm.tm_min = stLocal.wMinute;
    tm.tm_sec = stLocal.wSecond;
    tm.tm_isdst = -1;
    time_t fileTime = mktime(&tm);

    // 当前时间
    time_t now = time(NULL);

    // 计算时间差（秒）
    double diff = difftime(now, fileTime);

    return diff > 24 * 3600; // 超过1天
}

// 检查文件是否为PE格式（EXE/DLL）
bool File_IsPEFile(char* filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file)
    {
        return false;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    file.seekg(dosHeader.e_lfanew, ios::beg);
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    if (peSignature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    return true;
}

// 检查PE文件是否包含图标资源
bool File_HasIconResource(wchar_t* filePath)
{
    HMODULE hModule = LoadLibraryEx(filePath, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hModule == NULL)
    {
        return false;
    }

    HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(1), RT_GROUP_ICON);
    if (hResource == NULL)
    {
        hResource = FindResource(hModule, MAKEINTRESOURCE(1), RT_ICON);
    }

    FreeLibrary(hModule);
    return hResource != NULL;
}

// 检查文件大小是否正常（大于20KB）
bool File_IsFileSizeNormal(wchar_t* filePath)
{
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return fileSize.QuadPart > 20 * 1024; // 大于20KB
}

// 检查是否为系统文件
bool File_VerifySystemFile(wstring filePath)
{
    BOOL isProtected = SfcIsFileProtected(NULL, filePath.c_str());

    return isProtected;
}

bool File_CheckFileSignature(const wstring& filePath, const wstring& certName)
{
    bool isValid = false;
    wstring signerCertName = L"";

    // 初始化文件信息
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // 初始化信任数据
    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

    // 验证签名
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // 检查签名有效性
    if (result == ERROR_SUCCESS)
    {
        isValid = true;
    }

    // 清理WinVerifyTrust资源
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return isValid;
}

uint32_t Encrypt_RightRotate(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

void Encrypt_ProcessBlock(const unsigned char* block, uint32_t* h)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
    {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = Encrypt_RightRotate(w[i - 15], 7) ^ Encrypt_RightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Encrypt_RightRotate(w[i - 2], 17) ^ Encrypt_RightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t S1 = Encrypt_RightRotate(e, 6) ^ Encrypt_RightRotate(e, 11) ^ Encrypt_RightRotate(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h_val + S1 + ch + K[i] + w[i];
        uint32_t S0 = Encrypt_RightRotate(a, 2) ^ Encrypt_RightRotate(a, 13) ^ Encrypt_RightRotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h_val = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
}

string Encrypt_CalculateFileSHA256(string filePath)
{
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    FILE* file = fopen(filePath.c_str(), "rb");
    if (!file) return "";

    unsigned char buffer[64];
    size_t bytesRead;
    uint64_t totalBytes = 0;

    while ((bytesRead = fread(buffer, 1, 64, file)) == 64)
    {
        Encrypt_ProcessBlock(buffer, h);
        totalBytes += 64;
    }
    totalBytes += bytesRead;

    unsigned char lastBlock[128] = { 0 };
    if (bytesRead > 0) memcpy(lastBlock, buffer, bytesRead);

    uint64_t bitLength = totalBytes * 8;
    size_t rem = bytesRead;

    if (rem < 56)
    {
        lastBlock[rem] = 0x80;
        memset(lastBlock + rem + 1, 0, 55 - rem);
        for (int i = 0; i < 8; i++)
            lastBlock[56 + i] = (bitLength >> (56 - i * 8)) & 0xFF;
        Encrypt_ProcessBlock(lastBlock, h);
    }
    else
    {
        lastBlock[rem] = 0x80;
        memset(lastBlock + rem + 1, 0, 63 - rem);
        Encrypt_ProcessBlock(lastBlock, h);
        memset(lastBlock, 0, 56);
        for (int i = 0; i < 8; i++)
            lastBlock[56 + i] = (bitLength >> (56 - i * 8)) & 0xFF;
        Encrypt_ProcessBlock(lastBlock, h);
    }

    fclose(file);

    stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint32_t val : h) ss << std::setw(8) << val;
    return ss.str();
}

// 压缩文件格式魔数定义
namespace ArchiveSignatures {
    // ZIP 及相关格式
    const std::vector<uint8_t> ZIP_LOCAL = { 0x50, 0x4B, 0x03, 0x04 };     // ZIP 本地文件头
    const std::vector<uint8_t> ZIP_EMPTY = { 0x50, 0x4B, 0x05, 0x05 };     // ZIP 空归档
    const std::vector<uint8_t> ZIP_SPANNED = { 0x50, 0x4B, 0x07, 0x08 };    // ZIP 分卷
    const std::vector<uint8_t> ZIP_CENTRAL = { 0x50, 0x4B, 0x01, 0x02 };    // ZIP 中央目录
    const std::vector<uint8_t> ZIP_EOCD = { 0x50, 0x4B, 0x05, 0x06 };       // ZIP 结束记录
    const std::vector<uint8_t> ZIP_7Z = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }; // 7z 格式

    // RAR 格式
    const std::vector<uint8_t> RAR_1_5 = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }; // RAR 1.5
    const std::vector<uint8_t> RAR_5_0 = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 }; // RAR 5.0

    // GZIP
    const std::vector<uint8_t> GZIP = { 0x1F, 0x8B };

    // TAR
    const std::vector<uint8_t> TAR_USTAR = { 0x75, 0x73, 0x74, 0x61, 0x72 }; // ustar 偏移257

    // CAB
    const std::vector<uint8_t> CAB = { 0x4D, 0x53, 0x43, 0x46 }; // MSCF

    // BZIP2
    const std::vector<uint8_t> BZIP2 = { 0x42, 0x5A, 0x68 };

    // XZ
    const std::vector<uint8_t> XZ = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };

    // ISO
    const std::vector<uint8_t> ISO_9660 = { 0x43, 0x44, 0x30, 0x30, 0x31 }; // CD001 偏移32769

    // ARJ
    const std::vector<uint8_t> ARJ = { 0x60, 0xEA };

    // LZH/LHA
    const std::vector<uint8_t> LZH = { 0x2D, 0x6C, 0x68, 0x2D }; // -lh-
}

// 检查文件头是否匹配魔数
bool CheckSignature(const uint8_t* data, size_t data_len, const std::vector<uint8_t>& sig, size_t offset = 0) {
    if (data_len < offset + sig.size()) {
        return false;
    }
    return memcmp(data + offset, sig.data(), sig.size()) == 0;
}

// 通过扩展名判断
bool IsArchiveByExtension(const std::string& path) {
    std::string ext;
    size_t pos = path.find_last_of(".");
    if (pos != std::string::npos) {
        ext = path.substr(pos + 1);
        // 转换为小写
        for (char& c : ext) c = tolower(c);

        // 常见压缩文件扩展名
        std::vector<std::string> archive_exts = {
            "zip", "rar", "7z", "gz", "gzip", "tar", "tgz", "bz2", "bz",
            "xz", "z", "lz", "lzma", "lzo", "arj", "cab", "iso", "img",
            "dmg", "pkg", "deb", "rpm", "zst", "tzst", "tbz2", "tlz",
            "tz", "taz", "tz2", "t7z", "apk", "jar", "war", "ear", "xpi",
            "cbz", "cbr", "epub", "dmg", "vhd", "vmdk", "ova", "msi"
        };

        for (const auto& archive_ext : archive_exts) {
            if (ext == archive_ext) {
                return true;
            }
        }
    }
    return false;
}

bool File_IsArchive(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // 读取文件头（前512字节足够检测大部分格式）
    const size_t HEADER_SIZE = 512;
    std::vector<uint8_t> header(HEADER_SIZE);
    file.read(reinterpret_cast<char*>(header.data()), HEADER_SIZE);
    size_t read_size = file.gcount();

    if (read_size < 4) { // 至少需要4字节
        return false;
    }

    // 1. 检查文件头魔数
    using namespace ArchiveSignatures;

    // ZIP 格式检测
    if (CheckSignature(header.data(), read_size, ZIP_LOCAL) ||
        CheckSignature(header.data(), read_size, ZIP_EMPTY) ||
        CheckSignature(header.data(), read_size, ZIP_SPANNED) ||
        CheckSignature(header.data(), read_size, ZIP_CENTRAL) ||
        CheckSignature(header.data(), read_size, ZIP_EOCD)) {
        return true;
    }

    // 7z 格式检测
    if (CheckSignature(header.data(), read_size, ZIP_7Z)) {
        return true;
    }

    // RAR 格式检测
    if (CheckSignature(header.data(), read_size, RAR_1_5) ||
        CheckSignature(header.data(), read_size, RAR_5_0)) {
        return true;
    }

    // GZIP 格式检测
    if (CheckSignature(header.data(), read_size, GZIP)) {
        return true;
    }

    // CAB 格式检测
    if (CheckSignature(header.data(), read_size, CAB)) {
        return true;
    }

    // BZIP2 格式检测
    if (CheckSignature(header.data(), read_size, BZIP2)) {
        return true;
    }

    // XZ 格式检测
    if (CheckSignature(header.data(), read_size, XZ)) {
        return true;
    }

    // ARJ 格式检测
    if (CheckSignature(header.data(), read_size, ARJ)) {
        return true;
    }

    // LZH/LHA 格式检测
    if (CheckSignature(header.data(), read_size, LZH)) {
        return true;
    }

    // TAR 格式检测（ustar 签名在偏移257处）
    if (read_size > 257 + 5) {
        if (CheckSignature(header.data(), read_size, TAR_USTAR, 257)) {
            return true;
        }
    }

    // ISO 格式检测（CD001 签名在偏移32769处，但这里只读512字节，所以作为备选）
    if (read_size > 32769 + 5) {
        // 需要读取更多数据
        file.clear();
        file.seekg(32769, std::ios::beg);
        std::vector<uint8_t> iso_sig(5);
        file.read(reinterpret_cast<char*>(iso_sig.data()), 5);
        if (file.gcount() == 5 && memcmp(iso_sig.data(), ISO_9660.data(), 5) == 0) {
            return true;
        }
    }

    return false;
}

// ===================================================================
// 简单 JSON 解析器（仅支持本规范所需结构）
// ===================================================================
class SimpleJson {
public:
    enum Type { NUL, BOOL, INT, STRING, OBJECT };

    Type type = NUL;
    bool bool_val = false;
    int64_t int_val = 0;
    std::string str_val;
    std::map<std::string, SimpleJson> children;

    SimpleJson() : type(NUL) {}
    explicit SimpleJson(Type t) : type(t) {}

    bool has(const std::string& key) const {
        return type == OBJECT && children.count(key);
    }

    const SimpleJson& operator[](const std::string& key) const {
        static SimpleJson empty;
        if (type == OBJECT) {
            auto it = children.find(key);
            if (it != children.end()) return it->second;
        }
        return empty;
    }

    std::string getString(const std::string& key = "") const {
        if (!key.empty()) return (*this)[key].str_val;
        return str_val;
    }

    int64_t getInt(const std::string& key = "") const {
        if (!key.empty()) return (*this)[key].int_val;
        return int_val;
    }

    bool getBool(const std::string& key = "") const {
        if (!key.empty()) return (*this)[key].bool_val;
        return bool_val;
    }
};

class JsonParser {
public:
    static SimpleJson parse(const std::string& json_str) {
        size_t idx = 0;
        skipWhitespace(json_str, idx);
        return parseValue(json_str, idx);
    }

private:
    static void skipWhitespace(const std::string& s, size_t& idx) {
        while (idx < s.size() && (s[idx] == ' ' || s[idx] == '\t' || s[idx] == '\n' || s[idx] == '\r'))
            ++idx;
    }

    static SimpleJson parseValue(const std::string& s, size_t& idx) {
        skipWhitespace(s, idx);
        if (idx >= s.size()) return SimpleJson();
        char c = s[idx];
        if (c == '{') return parseObject(s, idx);
        if (c == '"') return parseString(s, idx);
        if (c == 't' || c == 'f') return parseBool(s, idx);
        if (c == 'n') { idx += 4; return SimpleJson(); }
        return parseNumber(s, idx);
    }

    static SimpleJson parseObject(const std::string& s, size_t& idx) {
        SimpleJson obj(SimpleJson::OBJECT);
        ++idx; // skip '{'
        skipWhitespace(s, idx);
        if (idx < s.size() && s[idx] == '}') { ++idx; return obj; }
        while (true) {
            skipWhitespace(s, idx);
            std::string key = parseKey(s, idx);
            skipWhitespace(s, idx);
            ++idx; // skip ':'
            SimpleJson val = parseValue(s, idx);
            obj.children[key] = val;
            skipWhitespace(s, idx);
            if (idx < s.size() && s[idx] == ',') { ++idx; continue; }
            if (idx < s.size() && s[idx] == '}') { ++idx; break; }
            break;
        }
        return obj;
    }

    static SimpleJson parseString(const std::string& s, size_t& idx) {
        SimpleJson res(SimpleJson::STRING);
        ++idx; // skip opening "
        std::string out;
        while (idx < s.size()) {
            if (s[idx] == '\\') {
                ++idx;
                if (idx < s.size()) {
                    switch (s[idx]) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'n': out += '\n'; break;
                    case 't': out += '\t'; break;
                    default: out += '\\'; out += s[idx]; break;
                    }
                    ++idx;
                }
            }
            else if (s[idx] == '"') {
                ++idx; break;
            }
            else {
                out += s[idx++];
            }
        }
        res.str_val = out;
        return res;
    }

    static std::string parseKey(const std::string& s, size_t& idx) {
        return parseString(s, idx).str_val;
    }

    static SimpleJson parseBool(const std::string& s, size_t& idx) {
        SimpleJson res(SimpleJson::BOOL);
        if (s.compare(idx, 4, "true") == 0) { res.bool_val = true; idx += 4; }
        else if (s.compare(idx, 5, "false") == 0) { res.bool_val = false; idx += 5; }
        return res;
    }

    static SimpleJson parseNumber(const std::string& s, size_t& idx) {
        SimpleJson res(SimpleJson::INT);
        size_t start = idx;
        if (s[idx] == '-') ++idx;
        while (idx < s.size() && isdigit(s[idx])) ++idx;
        res.int_val = std::stoll(s.substr(start, idx - start));
        return res;
    }
};

// ===================================================================
// JSON 输出辅助（手动拼接，无外部库）
// ===================================================================
std::string escapeJson(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out += c;
        }
    }
    return out;
}

std::string normalizePath(const std::string& path) {
    std::string p = path;
    std::replace(p.begin(), p.end(), '\\', '/');
    return p;
}

// ===================================================================
// 原有枚举与全局变量
// ===================================================================
enum Yara_FileType {
    YAFILE_TYPE_UNKNOWN = 0,
    YAFILE_TYPE_PE,
    YAFILE_TYPE_ARCHIVE
};

// 引擎元数据
const std::string ENGINE_NAME = "ThSecPEEngine";
const std::string ENGINE_VERSION = "3.0.0.2";
std::string SIGNATURE_VERSION = "2026";

// 日志文件
std::ofstream g_LogFile;

void Log(const std::string& msg) {
    if (g_LogFile.is_open())
        g_LogFile << msg << std::endl;
}

// ===================================================================
// YARA 回调与扫描（保留原有逻辑，修正 bug）
// ===================================================================
int Yara_ScanFileCallBack(YR_SCAN_CONTEXT* context, int message, void* data, void* user) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* result = (std::string*)user;
        YR_RULE* rule = (YR_RULE*)data;

        if (!result->empty()) return CALLBACK_CONTINUE;

        int file_type = (int)(uintptr_t)user & 0xFF;

        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_STRING &&
                strcmp(meta->identifier, "description") == 0 &&
                meta->string) {
                std::string desc = meta->string;

                if (file_type == YAFILE_TYPE_PE &&
                    desc.find("SIGNATURE_TYPE_PEHSTR_EXT") != std::string::npos) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
                if (file_type == YAFILE_TYPE_ARCHIVE &&
                    desc.find("SIGNATURE_TYPE_ARHSTR_EXT") != std::string::npos) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
                if (desc.find("SIGNATURE_TYPE_") == std::string::npos) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
                break;
            }
            else if (meta->type == META_TYPE_STRING &&
                strcmp(meta->identifier, "filetype") == 0 &&
                meta->string) {
                if (strcmp(meta->string, "memory") != 0) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
            }
            else if (meta->type == META_TYPE_STRING &&
                strcmp(meta->identifier, "rule_usage") == 0 &&
                meta->string) {
                if (strcmp(meta->string, "memory scan") != 0) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
            }
        }
    }
    return CALLBACK_CONTINUE;
}

bool Yara_ScanFile(const std::string& path, std::string& virus_name) {
    int file_type = YAFILE_TYPE_UNKNOWN;
    if (File_IsPEFile((char*)path.c_str()))
        file_type = YAFILE_TYPE_PE;
    else if (File_IsArchive(path))
        file_type = YAFILE_TYPE_ARCHIVE;

    void* user_data = (void*)(uintptr_t)file_type;
    std::string result;

    int ret = yr_rules_scan_file(Yara_Rules, path.c_str(),
        SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING,
        Yara_ScanFileCallBack, &result, 2000);

    if (ret == ERROR_SUCCESS && !result.empty()) {
        virus_name = result;
        return true;
    }
    virus_name = "Empty";
    return false;
}

// 修正原数组遍历 bug
static std::vector<std::string> HeurExceptYaraRuleName = {
    "Yara/Suspicious_RegeditVirus",
    "Yara/DodgyStrings",
    "Yara/Suspicious_Packed_By_PYInstaller",
    "Yara/Suspicious_PackerSections"
};

bool IsExceptYaraRule(const std::string& name) {
    return std::find(HeurExceptYaraRuleName.begin(), HeurExceptYaraRuleName.end(), name)
        != HeurExceptYaraRuleName.end();
}

// ===================================================================
// 扫描结果结构体
// ===================================================================
struct ScanOutcome {
    enum class Verdict { BENIGN, UNDETECTED, SUSPICIOUS, MALWARE };
    Verdict verdict = Verdict::UNDETECTED;
    std::string threat_name;
    double confidence = 0.0;
    std::vector<std::string> matched_rules;
    std::string message;
};

// ===================================================================
// 核心扫描函数（整合原 Scan_GeneralScan）
// ===================================================================
ScanOutcome ScanFileBySpec(const std::string& filePath,
    const std::string& sha256,
    int timeoutMs,
    bool enableHeuristics) {
    ScanOutcome outcome;

    if (!std::filesystem::exists(filePath)) {
        outcome.verdict = ScanOutcome::Verdict::UNDETECTED;
        outcome.message = "File not found";
        return outcome;
    }

    // 白名单快速通道
    if (!sha256.empty() && WhiteSha256List.find(sha256) != WhiteSha256List.end()) {
        outcome.verdict = ScanOutcome::Verdict::BENIGN;
        outcome.message = "White listed";
        return outcome;
    }

    // 黑名单快速通道
    auto it = Sha256List.find(sha256);
    if (it != Sha256List.end()) {
        outcome.verdict = ScanOutcome::Verdict::MALWARE;
        outcome.threat_name = it->second;
        outcome.confidence = 100.0;
        outcome.message = "Blacklist hit";
        return outcome;
    }

    // 系统文件免杀
    if (File_VerifySystemFile(std::wstring(filePath.begin(), filePath.end()))) {
        outcome.verdict = ScanOutcome::Verdict::BENIGN;
        outcome.message = "System file";
        return outcome;
    }

    // 仅支持 PE 文件后续扫描（压缩包等暂不处理）
    if (!File_IsPEFile((char*)filePath.c_str())) {
        outcome.verdict = ScanOutcome::Verdict::UNDETECTED;
        outcome.message = "Not a PE file, scan skipped";
        return outcome;
    }

    bool yaraHit = false;
    bool suspiciousHeurNeeded = false;
    std::string yaraResult;

    // ---------- YARA 扫描 ----------
    if (!IS_MODE_FLASH && Yara_Rules) {
        std::string yaraVirus;
        if (Yara_ScanFile(filePath, yaraVirus)) {
            if (IsExceptYaraRule(yaraVirus)) {
                suspiciousHeurNeeded = true;
            }
            else if (yaraVirus != "Empty") {
                yaraHit = true;
                outcome.matched_rules.push_back(yaraVirus);
                outcome.threat_name = yaraVirus;
            }
        }
    }

    if (yaraHit) {
        outcome.verdict = ScanOutcome::Verdict::MALWARE;
        outcome.confidence = 100.0;
        outcome.message = "YARA match";
        return outcome;
    }

    // ---------- PE 启发式扫描 ----------
    if (enableHeuristics && PE_IsReady) {
        PEFileAnalyzer analyzer32(filePath);
        if (analyzer32.isValid()) {
            RawSample sample;
            sample.base_features = analyzer32.extractFeatures();
            sample.imports = analyzer32.getImportedFunctions();

            double confid = 0.0;
            if (mPEModel.Predict(sample, confid)) {
                confid = confid * 2.0 - 1.0;
                confid *= 100.0;

                if (File_CheckFileSignature(std::wstring(filePath.begin(), filePath.end()), L""))
                    confid -= 20.0;
                else
                    confid += 7.69;

                bool sizeNormal = File_IsFileSizeNormal((wchar_t*)std::wstring(filePath.begin(), filePath.end()).c_str());
                bool hasIcon = File_HasIconResource((wchar_t*)std::wstring(filePath.begin(), filePath.end()).c_str());
                if (!sizeNormal) confid += 0.8;
                if (!hasIcon) confid += 2.0;
                if (suspiciousHeurNeeded) confid += 5.0;

                if (confid > 100.0) confid = 100.0;
                else if (confid < -100.0) confid = -100.0;

                if (confid > 67.0) {
                    outcome.verdict = ScanOutcome::Verdict::MALWARE;
                    outcome.threat_name = "Heur/PEEngine.Malware.Generic!" + std::to_string((int)confid);
                    outcome.confidence = confid;
                    outcome.message = "Heuristic malware detection";
                }
                else if (confid > 50.0) {
                    outcome.verdict = ScanOutcome::Verdict::SUSPICIOUS;
                    outcome.threat_name = "Heur/PEEngine.Suspicious.Generic!" + std::to_string((int)confid);
                    outcome.confidence = confid;
                    outcome.message = "Heuristic suspicious detection";
                }
                else {
                    outcome.verdict = ScanOutcome::Verdict::UNDETECTED;
                    outcome.message = "Below threshold";
                }
                return outcome;
            }
        }
    }

    outcome.verdict = ScanOutcome::Verdict::UNDETECTED;
    outcome.message = "No threats found";
    return outcome;
}

// ===================================================================
// 构建符合规范的 JSON 响应（手动拼接）
// ===================================================================
std::string BuildResponse(const std::string& taskId,
    const std::string& filePath,
    const std::string& fileName,
    const std::string& sha256,
    const ScanOutcome& outcome,
    const std::string& engineStatus,
    int subCode,
    const std::string& statusMsg,
    long scanTimeMs) {
    std::ostringstream json;
    json << "{";

    // target_info
    json << "\"target_info\":{";
    json << "\"task_id\":\"" << escapeJson(taskId) << "\",";
    json << "\"file_path\":\"" << escapeJson(normalizePath(filePath)) << "\"";
    if (!fileName.empty()) json << ",\"file_name\":\"" << escapeJson(fileName) << "\"";
    if (!sha256.empty()) json << ",\"sha256\":\"" << escapeJson(sha256) << "\"";
    json << "},";

    // engine_status
    json << "\"engine_status\":{";
    json << "\"code\":\"" << engineStatus << "\"";
    if (subCode != 0) json << ",\"sub_code\":" << subCode;
    json << ",\"message\":\"" << escapeJson(statusMsg) << "\"";
    json << "},";

    // scan_result (仅成功/部分成功时携带)
    if (engineStatus == "SUCCESS" || engineStatus == "ERR_PARTIAL") {
        json << "\"scan_result\":{";
        std::string verdictStr;
        switch (outcome.verdict) {
        case ScanOutcome::Verdict::BENIGN: verdictStr = "Benign"; break;
        case ScanOutcome::Verdict::UNDETECTED: verdictStr = "Undetected"; break;
        case ScanOutcome::Verdict::SUSPICIOUS: verdictStr = "Suspicious"; break;
        case ScanOutcome::Verdict::MALWARE: verdictStr = "Malware"; break;
        }
        json << "\"verdict\":\"" << verdictStr << "\"";
        if (outcome.verdict == ScanOutcome::Verdict::MALWARE ||
            outcome.verdict == ScanOutcome::Verdict::SUSPICIOUS) {
            json << ",\"threat_name\":\"" << escapeJson(outcome.threat_name) << "\"";
            json << ",\"confidence\":" << outcome.confidence;
        }
        else {
            json << ",\"threat_name\":null";
            json << ",\"confidence\":0.0";
        }
        if (!outcome.matched_rules.empty()) {
            json << ",\"matched_rules\":[";
            for (size_t i = 0; i < outcome.matched_rules.size(); ++i) {
                if (i) json << ",";
                json << "\"" << escapeJson(outcome.matched_rules[i]) << "\"";
            }
            json << "]";
        }
        json << "},";
    }

    // engine_metadata
    json << "\"engine_metadata\":{";
    json << "\"engine_name\":\"" << ENGINE_NAME << "\",";
    json << "\"engine_version\":\"" << ENGINE_VERSION << "\",";
    json << "\"signature_version\":\"" << SIGNATURE_VERSION << "\",";
    json << "\"scan_time_ms\":" << scanTimeMs;
    // 扫描时间戳省略（可选）
    json << "}";

    json << "}";
    return json.str();
}

// ===================================================================
// 处理单次请求
// ===================================================================
std::string ProcessRequest(const std::string& requestLine) {
    auto start = std::chrono::steady_clock::now();

    SimpleJson req;
    try {
        req = JsonParser::parse(requestLine);
    }
    catch (...) {
        // 畸形 JSON
        std::string errResp = "{"
            "\"target_info\":{\"task_id\":null,\"file_path\":null},"
            "\"engine_status\":{\"code\":\"ERR_INTERNAL\",\"message\":\"Malformed JSON request\"}"
            "}";
        return errResp;
    }

    // 检查必要字段
    if (!req.has("task_info") || !req["task_info"].has("task_id") ||
        !req.has("target") || !req["target"].has("file_path")) {
        std::string taskId = "null";
        std::string filePath = "null";
        if (req.has("task_info") && req["task_info"].has("task_id"))
            taskId = "\"" + escapeJson(req["task_info"].getString("task_id")) + "\"";
        else taskId = "null";
        if (req.has("target") && req["target"].has("file_path"))
            filePath = "\"" + escapeJson(req["target"].getString("file_path")) + "\"";
        else filePath = "null";

        std::ostringstream err;
        err << "{"
            << "\"target_info\":{\"task_id\":" << taskId << ",\"file_path\":" << filePath << "},"
            << "\"engine_status\":{\"code\":\"ERR_INTERNAL\",\"message\":\"Missing required fields\"}"
            << "}";
        return err.str();
    }

    std::string taskId = req["task_info"].getString("task_id");
    std::string filePath = req["target"].getString("file_path");
    std::string fileName = req["target"].has("file_name") ? req["target"].getString("file_name") : "";
    std::string sha256 = req["target"].has("sha256") ? req["target"].getString("sha256") : "";
    int timeoutMs = req["task_info"].has("timeout_ms") ? (int)req["task_info"].getInt("timeout_ms") : 30000;
    bool enableHeuristics = true;
    if (req.has("scan_options") && req["scan_options"].has("enable_heuristics"))
        enableHeuristics = req["scan_options"].getBool("enable_heuristics");

    // 文件存在性检查
    if (!std::filesystem::exists(filePath)) {
        ScanOutcome dummy;
        auto end = std::chrono::steady_clock::now();
        long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return BuildResponse(taskId, filePath, fileName, sha256, dummy,
            "ERR_FILE_ACCESS", 0, "File does not exist", elapsed);
    }

    // 可选 SHA256 校验
    if (!sha256.empty()) {
        std::string actualHash = Encrypt_CalculateFileSHA256(filePath);
        if (actualHash != sha256) {
            ScanOutcome dummy;
            auto end = std::chrono::steady_clock::now();
            long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
            return BuildResponse(taskId, filePath, fileName, sha256, dummy,
                "ERR_FILE_ACCESS", 0, "SHA256 mismatch", elapsed);
        }
    }

    // 执行扫描
    ScanOutcome outcome = ScanFileBySpec(filePath, sha256, timeoutMs, enableHeuristics);
    auto end = std::chrono::steady_clock::now();
    long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::string engineStatus = "SUCCESS";
    std::string statusMsg = outcome.message;

    if (outcome.message == "File not found" ||
        outcome.message == "Not a PE file, scan skipped") {
        engineStatus = "ERR_FILE_ACCESS";
    }

    return BuildResponse(taskId, filePath, fileName, sha256, outcome,
        engineStatus, 0, statusMsg, elapsed);
}

// ===================================================================
// 获取当前进程目录
// ===================================================================
std::wstring Process_GetCurrentProcessPath() {
    TCHAR szDir[MAX_PATH];
    HMODULE hModule;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCTSTR)Process_GetCurrentProcessPath, &hModule);
    if (hModule) {
        GetModuleFileName(hModule, szDir, MAX_PATH);
        PathRemoveFileSpec(szDir);
    }
    return szDir;
}

// ===================================================================
// 主函数 —— 常驻进程模式
// ===================================================================
int main(int argc, char* argv[]) {
    // 打开日志文件
    g_LogFile.open("engine.log", std::ios::out | std::ios::app);
    Log("[*] Engine starting...");

    // 加载模型和白名单
    std::wstring currentDir = Process_GetCurrentProcessPath();
    std::string heurPath = (std::string)(CW2A)(currentDir + L"\\Heur.data").c_str();
    Log("[*] Loading heuristic model: " + heurPath);

    if (mPEModel.LoadModel(heurPath)) {
        PE_IsReady = TRUE;
        Log("[+] Heuristic model loaded.");
        // 加载黑名单
        std::ifstream virusFile((std::string)(CW2A)(currentDir + L"\\malware.data").c_str());
        if (virusFile.is_open()) {
            std::string name, hash;
            while (virusFile >> name >> hash) {
                Sha256List[hash] = name;
            }
            Log("[+] Malware list loaded.");
        }
        else {
            Log("[-] Failed to load malware.data");
        }
        // 加载白名单
        std::ifstream whiteFile((std::string)(CW2A)(currentDir + L"\\White.data").c_str());
        if (whiteFile.is_open()) {
            std::string hash;
            while (whiteFile >> hash) {
                WhiteSha256List.insert(hash);
            }
            Log("[+] White list loaded.");
        }
        else {
            Log("[-] Failed to load White.data");
        }
    }
    else {
        Log("[-] Heuristic model load failed.");
    }

    // YARA 初始化
    if (!IS_MODE_FLASH) {
        if (yr_initialize() != ERROR_SUCCESS) {
            Log("[-] YARA init failed.");
            std::cout << "{\"engine_status\":{\"code\":\"ERR_INITIALIZATION\",\"message\":\"YARA init failed\"}}" << std::endl;
            return 1;
        }
        std::wstring rulesPath = currentDir + L"\\Malware.yarac";
        std::string rulesPathA = (std::string)(CW2A)(rulesPath.c_str());
        int ret = yr_rules_load(rulesPathA.c_str(), &Yara_Rules);
        if (ret != ERROR_SUCCESS) {
            Log("[-] YARA rules load failed.");
            std::cout << "{\"engine_status\":{\"code\":\"ERR_INITIALIZATION\",\"message\":\"YARA rules load failed\"}}" << std::endl;
            yr_finalize();
            return 1;
        }
        Log("[+] YARA engine ready.");
    }

    // 启动握手
    std::cout << "{\"engine_status\":{\"code\":\"SUCCESS\",\"message\":\"Engine initialized and ready.\"}}" << std::endl;
    Log("[*] Ready handshake sent.");

    // 工作循环
    std::string line;
    while (true) {
        if (!std::getline(std::cin, line)) {
            Log("[*] stdin closed, exiting.");
            break;
        }
        if (line.empty()) continue;

        // 显式退出命令
        if (line.find("\"command\":\"EXIT\"") != std::string::npos) {
            Log("[*] Received EXIT command.");
            std::cout << "{\"engine_status\":{\"code\":\"SUCCESS\",\"message\":\"Engine is shutting down.\"}}" << std::endl;
            break;
        }

        std::string response = ProcessRequest(line);
        std::cout << response << std::endl;
    }

    // 清理
    if (Yara_Rules) yr_rules_destroy(Yara_Rules);
    yr_finalize();
    Log("[*] Engine terminated gracefully.");
    return 0;
}