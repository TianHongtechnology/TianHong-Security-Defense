#include <functional>
#include <set>
#include <regex>
#include <Windows.h>
#include <WinTrust.h>
#include <iostream>
#include <array>
#include <map>
#include <vector>
#include <fstream>
#include <string>
#include <algorithm>
#include <cmath>
#include <LightGBM\c_api.h>
#include <unordered_set>

#pragma comment(lib, "..\\TianHong-Security-Defense\\lightgbm_objs.lib")
#pragma comment(lib, "..\\TianHong-Security-Defense\\lightgbm_capi_objs.lib")
#pragma comment(lib, "WinTrust.lib")

using namespace std;

// ======================== 常量与结构体 ========================
static constexpr size_t BASE_FEATURE_DIM = 600;     // 不可变的基础特征维度
static constexpr double BASE_MODEL_WEIGHT = 0.92;    // 基础模型权重（较高）
static constexpr double EXTRA_MODEL_WEIGHT = 0.08;   // 额外维度模型权重（较低）

// ======================== RawSample ========================
struct RawSample {
    std::array<float, BASE_FEATURE_DIM> base_features;  // 基础600维
    std::unordered_set<std::string> imports;             // 导入函数集合（小写），O(1) 查找
};

// ======================== PE 文件分析器 ========================

class PEFileAnalyzer {
public:
    BYTE* fileBase = nullptr;
    HANDLE hMap = nullptr;
    DWORD fileSize = 0;
    bool valid = false;
    bool _64bit = false;
    bool _sigValid = false;    // 签名验证结果（在构造函数中通过WinVerifyTrust判定）

    // ---------- 基础 PE 访问 ----------
    IMAGE_DOS_HEADER* dos() const { return valid ? (IMAGE_DOS_HEADER*)fileBase : nullptr; }
    IMAGE_NT_HEADERS32* nt32() const { return valid && !_64bit ? (IMAGE_NT_HEADERS32*)(fileBase + dos()->e_lfanew) : nullptr; }
    IMAGE_NT_HEADERS64* nt64() const { return valid && _64bit ? (IMAGE_NT_HEADERS64*)(fileBase + dos()->e_lfanew) : nullptr; }
    const IMAGE_SECTION_HEADER* sections() const {
        if (!valid) return nullptr;
        auto* nt = (IMAGE_NT_HEADERS*)(fileBase + dos()->e_lfanew);
        return IMAGE_FIRST_SECTION(nt);
    }
    WORD sectionCount() const {
        if (!valid) return 0;
        auto* nt = (IMAGE_NT_HEADERS*)(fileBase + dos()->e_lfanew);
        return nt->FileHeader.NumberOfSections;
    }

    bool getDataDir(int entry, DWORD& rva, DWORD& size) const {
        if (!valid) return false;
        if (_64bit) {
            auto* nt = nt64();
            if (!nt || entry >= 16) return false;
            rva = nt->OptionalHeader.DataDirectory[entry].VirtualAddress;
            size = nt->OptionalHeader.DataDirectory[entry].Size;
        }
        else {
            auto* nt = nt32();
            if (!nt || entry >= 16) return false;
            rva = nt->OptionalHeader.DataDirectory[entry].VirtualAddress;
            size = nt->OptionalHeader.DataDirectory[entry].Size;
        }
        return rva != 0 && size != 0;
    }

    static double entropy(const void* data, size_t len) {
        if (!len) return 0.0;
        int freq[256] = { 0 };
        auto* p = (const BYTE*)data;
        for (size_t i = 0; i < len; i++) freq[p[i]]++;
        double e = 0.0;
        for (int c : freq)
            if (c > 0) { double prob = (double)c / len; e -= prob * log2(prob); }
        return e;
    }

    // ---------- 节区映射缓存（RVA 二分查找）----------
    struct SectionMapEntry {
        DWORD rvaStart;
        DWORD rvaEnd;
        DWORD fileOff;
    };
    mutable vector<SectionMapEntry> m_sectionMap;
    mutable bool m_mapBuilt = false;

    void buildSectionMap() const {
        m_sectionMap.clear();
        WORD nSec = sectionCount();
        const IMAGE_SECTION_HEADER* sec = sections();
        if (!sec || nSec == 0) return;
        for (WORD i = 0; i < nSec; i++) {
            DWORD va = sec[i].VirtualAddress;
            DWORD vs = sec[i].Misc.VirtualSize;
            if (vs == 0) vs = sec[i].SizeOfRawData;
            if (vs == 0) continue;
            SectionMapEntry e;
            e.rvaStart = va;
            e.rvaEnd = va + vs;
            e.fileOff = sec[i].PointerToRawData;
            m_sectionMap.push_back(e);
        }
        // 确保按 RVA 升序（通常已是，但保险起见）
        sort(m_sectionMap.begin(), m_sectionMap.end(),
            [](const SectionMapEntry& a, const SectionMapEntry& b) { return a.rvaStart < b.rvaStart; });
        m_mapBuilt = true;
    }

    DWORD rvaToOffset(DWORD rva) const {
        if (rva == 0) return 0;
        if (!m_mapBuilt) buildSectionMap();
        // 二分查找
        auto it = upper_bound(m_sectionMap.begin(), m_sectionMap.end(), rva,
            [](DWORD val, const SectionMapEntry& e) { return val < e.rvaStart; });
        if (it != m_sectionMap.begin()) {
            --it;
            if (rva >= it->rvaStart && rva < it->rvaEnd) {
                DWORD offset = rva - it->rvaStart + it->fileOff;
                if (offset < fileSize) return offset;
            }
        }
        // fallback：RVA 可能小于第一个节区
        if (rva < fileSize) return rva;
        return 0;
    }

    // ---------- 资源缓存 ----------
    struct CachedResource {
        // typeId -> vector<(offset, size)>
        unordered_map<WORD, vector<pair<DWORD, DWORD>>> dataOffsets;
        set<WORD> languages;
        bool parsed = false;
    };
    mutable CachedResource m_resCache;

    void ensureResourceParsed() const {
        if (m_resCache.parsed) return;
        // 解析整个资源树，一次遍历
        DWORD rva, size;
        if (!getDataDir(2, rva, size)) { m_resCache.parsed = true; return; }
        DWORD off = rvaToOffset(rva);
        if (!off || off + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) { m_resCache.parsed = true; return; }
        auto* root = (IMAGE_RESOURCE_DIRECTORY*)(fileBase + off);
        auto entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(root + 1);
        DWORD total = root->NumberOfNamedEntries + root->NumberOfIdEntries;
        if ((BYTE*)entries + total * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
        {
            m_resCache.parsed = true; return;
        }
        for (DWORD i = 0; i < total; i++) {
            auto& typeE = entries[i];
            if (!typeE.DataIsDirectory) continue;
            WORD typeId = (WORD)(typeE.NameIsString ? 0 : typeE.Id);
            DWORD nameDirOff = typeE.OffsetToDirectory & 0x7FFFFFFF;
            if (!nameDirOff || nameDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;
            auto* nameDir = (IMAGE_RESOURCE_DIRECTORY*)(fileBase + nameDirOff);
            DWORD nameTotal = nameDir->NumberOfNamedEntries + nameDir->NumberOfIdEntries;
            if (nameTotal == 0 || nameTotal > 10000) continue;
            auto nameEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(nameDir + 1);
            if ((BYTE*)nameEntries + nameTotal * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
                continue;
            for (DWORD j = 0; j < nameTotal; j++) {
                auto& nameE = nameEntries[j];
                if (!nameE.DataIsDirectory) continue;
                DWORD langDirOff = nameE.OffsetToDirectory & 0x7FFFFFFF;
                if (!langDirOff || langDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;
                if (langDirOff == nameDirOff) continue;
                auto* langDir = (IMAGE_RESOURCE_DIRECTORY*)(fileBase + langDirOff);
                DWORD langTotal = langDir->NumberOfNamedEntries + langDir->NumberOfIdEntries;
                if (langTotal == 0 || langTotal > 10000) continue;
                auto langEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(langDir + 1);
                if ((BYTE*)langEntries + langTotal * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
                    continue;
                for (DWORD k = 0; k < langTotal; k++) {
                    auto& langE = langEntries[k];
                    if (!langE.NameIsString)
                        m_resCache.languages.insert((WORD)langE.Id);
                    DWORD dataOffDir = langE.OffsetToData & 0x7FFFFFFF;
                    if (!dataOffDir || dataOffDir + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize) continue;
                    auto* dataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)(fileBase + dataOffDir);
                    DWORD dataOff = rvaToOffset(dataEntry->OffsetToData);
                    if (dataOff >= fileSize) continue;
                    if (dataOff + dataEntry->Size > fileSize) continue;
                    m_resCache.dataOffsets[typeId].emplace_back(dataOff, dataEntry->Size);
                }
            }
        }
        m_resCache.parsed = true;
    }

    bool hasResource(WORD typeId) const {
        ensureResourceParsed();
        return m_resCache.dataOffsets.find(typeId) != m_resCache.dataOffsets.end();
    }

    int countResource(WORD typeId) const {
        ensureResourceParsed();
        auto it = m_resCache.dataOffsets.find(typeId);
        return (it != m_resCache.dataOffsets.end()) ? (int)it->second.size() : 0;
    }

    int getResourceLanguages() const {
        ensureResourceParsed();
        return (int)m_resCache.languages.size();
    }

    void* getResourceData(WORD typeId) const {
        ensureResourceParsed();
        auto it = m_resCache.dataOffsets.find(typeId);
        if (it != m_resCache.dataOffsets.end() && !it->second.empty()) {
            return fileBase + it->second[0].first;
        }
        return nullptr;
    }

    // ---------- 版本信息缓存 ----------
    mutable unordered_map<string, wstring> m_versionStrings;
    mutable VS_FIXEDFILEINFO m_fixedInfo{};
    mutable bool m_fixedInfoValid = false;
    mutable bool m_versionCached = false;

    void ensureVersionParsed() const {
        if (m_versionCached) return;
        m_versionCached = true;
        void* data = getResourceData(16);
        if (!data) return;

        auto* ptr = (const BYTE*)data;
        const BYTE* fileEnd = fileBase + fileSize;
        const BYTE* resourceEnd = ptr + 0x10000;
        if (resourceEnd > fileEnd) resourceEnd = fileEnd;

        if (ptr + 6 > resourceEnd) return;
        WORD wLength = *(const WORD*)ptr;
        if (wLength < 6 || ptr + wLength > resourceEnd) return;
        WORD wValueLength = *(const WORD*)(ptr + 2);

        ptr += 6;
        while (ptr + 1 < resourceEnd && *(const wchar_t*)ptr != L'\0') ptr += 2;
        ptr += 2;
        ptr = (const BYTE*)(((uintptr_t)ptr + 3) & ~3);
        if (ptr >= resourceEnd) return;

        // 读固定信息
        if (wValueLength >= sizeof(VS_FIXEDFILEINFO) && ptr + sizeof(VS_FIXEDFILEINFO) <= resourceEnd) {
            memcpy(&m_fixedInfo, ptr, sizeof(VS_FIXEDFILEINFO));
            m_fixedInfoValid = (m_fixedInfo.dwSignature == 0xFEEF04BD);
        }
        else if (ptr + sizeof(VS_FIXEDFILEINFO) <= resourceEnd) {
            memcpy(&m_fixedInfo, ptr, sizeof(VS_FIXEDFILEINFO));
            m_fixedInfoValid = (m_fixedInfo.dwSignature == 0xFEEF04BD && m_fixedInfo.dwStrucVersion == 0x10000);
        }
        if (m_fixedInfoValid && wValueLength >= sizeof(VS_FIXEDFILEINFO)) {
            ptr += sizeof(VS_FIXEDFILEINFO);
            ptr = (const BYTE*)(((uintptr_t)ptr + 3) & ~3);
        }

        // 遍历子块，收集 StringFileInfo 键值对
        int maxIter = 1000, iter = 0;
        while (ptr + 6 <= resourceEnd && iter++ < maxIter) {
            WORD blockLen = *(const WORD*)ptr;
            if (blockLen < 6 || ptr + blockLen > resourceEnd) break;

            const BYTE* blockData = ptr + 6;
            wstring wsKey = SafeReadWideString(blockData, resourceEnd);
            string sKey(wsKey.begin(), wsKey.end());

            while (blockData + 1 < resourceEnd && *(const wchar_t*)blockData != L'\0') blockData += 2;
            blockData += 2;
            blockData = (const BYTE*)(((uintptr_t)blockData + 3) & ~3);

            if (sKey == "StringFileInfo") {
                const BYTE* inner = blockData;
                const BYTE* innerEnd = ptr + blockLen;
                if (innerEnd > resourceEnd) innerEnd = resourceEnd;
                while (inner + 6 <= innerEnd && iter++ < maxIter) {
                    WORD iBlockLen = *(const WORD*)inner;
                    if (iBlockLen < 6 || inner + iBlockLen > innerEnd) break;
                    const BYTE* iBlockData = inner + 6;
                    while (iBlockData + 1 < innerEnd && *(const wchar_t*)iBlockData != L'\0') iBlockData += 2;
                    iBlockData += 2;
                    iBlockData = (const BYTE*)(((uintptr_t)iBlockData + 3) & ~3);
                    if (iBlockData >= innerEnd) { inner += ((iBlockLen + 3) & ~3); continue; }

                    const BYTE* strTable = iBlockData;
                    const BYTE* strTableEnd = inner + iBlockLen;
                    if (strTableEnd > innerEnd) strTableEnd = innerEnd;
                    while (strTable + 6 <= strTableEnd && iter++ < maxIter) {
                        WORD sBlockLen = *(const WORD*)strTable;
                        if (sBlockLen < 6 || strTable + sBlockLen > strTableEnd) break;
                        const BYTE* sData = strTable + 6;
                        wstring wkey = SafeReadWideString(sData, strTableEnd);
                        string nkey(wkey.begin(), wkey.end());
                        while (sData + 1 < strTableEnd && *(const wchar_t*)sData != L'\0') sData += 2;
                        sData += 2;
                        sData = (const BYTE*)(((uintptr_t)sData + 3) & ~3);
                        if (sData < strTableEnd) {
                            wstring wval = SafeReadWideString(sData, strTableEnd);
                            m_versionStrings[nkey] = wval;
                        }
                        strTable += ((sBlockLen + 3) & ~3);
                    }
                    inner += ((iBlockLen + 3) & ~3);
                }
            }
            ptr += ((blockLen + 3) & ~3);
        }
    }

    bool getFixedFileInfo(VS_FIXEDFILEINFO& vs) const {
        ensureVersionParsed();
        if (m_fixedInfoValid) {
            vs = m_fixedInfo;
            return true;
        }
        return false;
    }

    int getStringFileInfoLength(const string& key) const {
        ensureVersionParsed();
        auto it = m_versionStrings.find(key);
        return (it != m_versionStrings.end()) ? (int)(it->second.length() * 2) : 0;
    }

    wstring SafeReadWideString(const BYTE* start, const BYTE* end) const {
        wstring result;
        const BYTE* ptr = start;
        while (ptr + 1 < end) {
            wchar_t wc;
            memcpy(&wc, ptr, sizeof(wchar_t));
            if (wc == L'\0') break;
            result += wc;
            ptr += 2;
            if (result.length() > 1024) break;
        }
        return result;
    }

    // ---------- 导入表缓存 ----------
    struct ImportInfo {
        vector<string> dlls;
        unordered_set<string> functions;  // 改为 unordered_set，O(1) 查找
    };
    mutable ImportInfo m_importInfo;
    mutable bool m_importCached = false;

    void ensureImportsParsed() const {
        if (m_importCached) return;
        m_importCached = true;
        if (!valid) return;

        DWORD importRVA, importSize;
        if (!getDataDir(1, importRVA, importSize) || importSize == 0) return;
        DWORD importOff = rvaToOffset(importRVA);
        if (!importOff || importOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return;

        const BYTE* fileEnd = fileBase + fileSize;
        const BYTE* importStart = fileBase + importOff;
        const BYTE* importEnd = importStart + importSize;

        // 确保不超出导入表范围
        if (importEnd > fileEnd) importEnd = fileEnd;

        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)importStart;
        int maxDlls = 2000, maxFuncs = 50000;
        int totalFuncs = 0;
        DWORD processedDlls = 0;

        // 使用while循环，更安全
        while (processedDlls < maxDlls) {
            // 检查是否还有空间容纳下一个描述符
            if ((BYTE*)(desc + 1) > importEnd) break;
            if ((BYTE*)(desc + 1) > fileEnd) break;

            // 检查是否到达终止条目
            if (desc->Name == 0 && desc->OriginalFirstThunk == 0 && desc->FirstThunk == 0) break;

            // 检查名称RVA是否有效
            if (desc->Name != 0) {
                DWORD nameOff = rvaToOffset(desc->Name);
                if (nameOff && nameOff < fileSize) {
                    // 验证名称字符串是否在文件范围内
                    const char* namePtr = (const char*)(fileBase + nameOff);
                    if (namePtr < (const char*)fileBase || namePtr >= (const char*)fileEnd) {
                        // 无效名称，继续下一个
                        desc++;
                        processedDlls++;
                        continue;
                    }

                    // 安全读取DLL名称（限制长度）
                    char dllName[256] = { 0 };
                    size_t maxLen = (size_t)(fileEnd - (const BYTE*)namePtr);
                    if (maxLen > 0) {
                        size_t len = strnlen(namePtr, min(maxLen, (size_t)255));
                        if (len > 0 && len < 256) {
                            memcpy(dllName, namePtr, len);
                            string dllNameStr(dllName);
                            transform(dllNameStr.begin(), dllNameStr.end(),
                                dllNameStr.begin(), ::tolower);
                            m_importInfo.dlls.push_back(dllNameStr);
                        }
                    }
                }
            }

            // 处理导入函数
            DWORD thunkRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            if (thunkRVA != 0) {
                DWORD thunkOff = rvaToOffset(thunkRVA);
                if (thunkOff && thunkOff < fileSize) {
                    const BYTE* thunkStart = fileBase + thunkOff;
                    const BYTE* thunkEnd = thunkStart + (fileSize - thunkOff);

                    if (!_64bit) {
                        auto* thunk = (IMAGE_THUNK_DATA32*)thunkStart;
                        int funcCount = 0;

                        while (funcCount < 10000 && totalFuncs < maxFuncs) {
                            // 检查thunk指针是否在有效范围内
                            if ((BYTE*)(thunk + 1) > fileEnd) break;
                            if ((BYTE*)(thunk + 1) > thunkStart + (fileSize - thunkOff)) break;

                            if (thunk->u1.AddressOfData == 0) break;

                            // 检查是否为序数导入
                            if (!(thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)) {
                                DWORD nameRVA = thunk->u1.AddressOfData;
                                DWORD funcOff = rvaToOffset(nameRVA);
                                if (funcOff && funcOff + sizeof(WORD) < fileSize) {
                                    auto* byName = (IMAGE_IMPORT_BY_NAME*)(fileBase + funcOff);
                                    if ((BYTE*)byName + sizeof(WORD) <= fileEnd) {
                                        string func = SafeReadName(byName->Name, fileEnd);
                                        if (!func.empty()) {
                                            m_importInfo.functions.insert(func);
                                            totalFuncs++;
                                        }
                                    }
                                }
                            }

                            thunk++;
                            funcCount++;
                        }
                    }
                    else {
                        auto* thunk = (IMAGE_THUNK_DATA64*)thunkStart;
                        int funcCount = 0;

                        while (funcCount < 10000 && totalFuncs < maxFuncs) {
                            if ((BYTE*)(thunk + 1) > fileEnd) break;
                            if ((BYTE*)(thunk + 1) > thunkStart + (fileSize - thunkOff)) break;

                            if (thunk->u1.AddressOfData == 0) break;

                            if (!(thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG64)) {
                                DWORD nameRVA = (DWORD)(thunk->u1.AddressOfData & 0xFFFFFFFF);
                                DWORD funcOff = rvaToOffset(nameRVA);
                                if (funcOff && funcOff + sizeof(WORD) < fileSize) {
                                    auto* byName = (IMAGE_IMPORT_BY_NAME*)(fileBase + funcOff);
                                    if ((BYTE*)byName + sizeof(WORD) <= fileEnd) {
                                        string func = SafeReadName(byName->Name, fileEnd);
                                        if (!func.empty()) {
                                            m_importInfo.functions.insert(func);
                                            totalFuncs++;
                                        }
                                    }
                                }
                            }

                            thunk++;
                            funcCount++;
                        }
                    }
                }
            }

            desc++;
            processedDlls++;
        }
    }

    vector<string> getImportedDLLs() const {
        ensureImportsParsed();
        return m_importInfo.dlls;
    }

    // 新增：返回 unordered_set 支持 O(1) 查找
    unordered_set<string> getImportedDLLsSet() const {
        ensureImportsParsed();
        unordered_set<string> ret;
        ret.reserve(m_importInfo.dlls.size());
        for (const auto& d : m_importInfo.dlls) ret.insert(d);
        return ret;
    }

    unordered_set<string> getImportedFunctions() const {
        ensureImportsParsed();
        return m_importInfo.functions;
    }

    // 新增：返回 const 引用，避免拷贝
    const unordered_set<string>& getImportedFunctionsRef() const {
        ensureImportsParsed();
        return m_importInfo.functions;
    }

    string SafeReadName(const char* start, const BYTE* fileEnd) const {
        string name;
        const BYTE* ptr = (const BYTE*)start;
        while (ptr < fileEnd && *ptr != '\0') {
            char c = (char)*ptr;
            if (c >= 32 && c <= 126) name += tolower(c);
            else if (c == '_' || c == '-' || c == '.' || c == '@' || c == '?' || c == '$') name += c;
            else break;
            ptr++;
            if (name.length() > 255) break;
        }
        return name;
    }

    // ---------- 优化后的字符串提取与缓存 ----------
    mutable unordered_set<string> m_cachedStringSet;
    mutable vector<string> m_cachedStringVec;
    mutable bool m_stringsCached = false;

    const unordered_set<string>& getCachedStringSet() const {
        if (!m_stringsCached) collectAllStrings();
        return m_cachedStringSet;
    }

    const vector<string>& collectAllStrings() const {
        if (m_stringsCached) return m_cachedStringVec;

        m_cachedStringSet.clear();
        m_cachedStringSet.reserve(fileSize / 10 + 1);

        WORD nSec = sectionCount();
        const IMAGE_SECTION_HEADER* sec = sections();
        if (!sec || nSec == 0) {
            m_stringsCached = true;
            return m_cachedStringVec;
        }

        for (WORD i = 0; i < nSec; i++) {
            DWORD off = sec[i].PointerToRawData;
            DWORD size = sec[i].SizeOfRawData;
            if (off + size > fileSize || size == 0) continue;

            const BYTE* start = fileBase + off;
            const BYTE* end = start + size;

            string curAnsi, curWide;
            curAnsi.reserve(1024);
            curWide.reserve(1024);

            auto flushAnsi = [&]() {
                if (curAnsi.size() >= 5 && curAnsi.size() <= 1024) {
                    transform(curAnsi.begin(), curAnsi.end(), curAnsi.begin(), ::tolower);
                    m_cachedStringSet.insert(move(curAnsi));
                }
                curAnsi.clear();
                };
            auto flushWide = [&]() {
                if (curWide.size() >= 5 && curWide.size() <= 1024) {
                    transform(curWide.begin(), curWide.end(), curWide.begin(), ::tolower);
                    m_cachedStringSet.insert(move(curWide));
                }
                curWide.clear();
                };

            for (const BYTE* p = start; p < end; ++p) {
                // ANSI
                if (*p >= 32 && *p <= 126) curAnsi.push_back((char)*p);
                else if (*p == 0) flushAnsi();
                else flushAnsi();

                // Unicode
                if (p + 1 < end) {
                    wchar_t wc;
                    memcpy(&wc, p, sizeof(wchar_t));
                    if (wc >= 32 && wc <= 126) {
                        curWide.push_back((char)wc);
                        ++p;
                    }
                    else if (wc == 0) {
                        flushWide();
                        ++p;
                    }
                    else {
                        flushWide();
                        ++p;
                    }
                }
                else {
                    flushWide();
                }
            }
            flushAnsi();
            flushWide();
        }

        m_cachedStringVec.assign(m_cachedStringSet.begin(), m_cachedStringSet.end());
        m_stringsCached = true;
        return m_cachedStringVec;
    }

    // ---------- 节区信息缓存 ----------
    struct SectionInfo {
        string nameLower;
        float entropy;
        DWORD rawSize;
        DWORD characteristics;
    };
    mutable vector<SectionInfo> m_sectionInfos;
    mutable bool m_secInfoCached = false;

    void cacheSectionInfo() const {
        if (m_secInfoCached) return;
        WORD nSec = sectionCount();
        const IMAGE_SECTION_HEADER* sec = sections();
        if (!sec || nSec == 0) { m_secInfoCached = true; return; }
        m_sectionInfos.resize(nSec);
        for (WORD i = 0; i < nSec; i++) {
            DWORD rawOff = sec[i].PointerToRawData;
            DWORD rawSize = sec[i].SizeOfRawData;
            char name[9] = { 0 };
            memcpy(name, sec[i].Name, 8);
            string sname(name);
            transform(sname.begin(), sname.end(), sname.begin(), ::tolower);
            float ent = 0.0f;
            if (rawOff + rawSize <= fileSize && rawSize > 0)
                ent = (float)entropy(fileBase + rawOff, rawSize);
            m_sectionInfos[i].nameLower = sname;
            m_sectionInfos[i].entropy = ent;
            m_sectionInfos[i].rawSize = rawSize;
            m_sectionInfos[i].characteristics = sec[i].Characteristics;
        }
        m_secInfoCached = true;
    }

    // ---------- 合并的字节统计（一次扫描得到熵、字节频率、分段熵）----------
    struct ByteStats {
        float totalEntropy;
        int byteFreq[256];
        float segEntropy[10];
    };
    mutable ByteStats m_byteStats;
    mutable bool m_byteStatsCached = false;

    void computeByteStats() const {
        if (m_byteStatsCached) return;
        memset(&m_byteStats, 0, sizeof(m_byteStats));
        int freq[256] = { 0 };
        for (DWORD i = 0; i < fileSize; i++) freq[fileBase[i]]++;
        double e = 0.0;
        for (int i = 0; i < 256; i++) {
            m_byteStats.byteFreq[i] = freq[i];
            if (freq[i] > 0) {
                double prob = (double)freq[i] / fileSize;
                e -= prob * log2(prob);
            }
        }
        m_byteStats.totalEntropy = (float)e;

        DWORD seg = fileSize / 10;
        if (seg > 0) {
            for (int i = 0; i < 10; i++) {
                DWORD off = i * seg;
                DWORD len = (i == 9) ? fileSize - off : seg;
                m_byteStats.segEntropy[i] = (float)entropy(fileBase + off, len);
            }
        }
        m_byteStatsCached = true;
    }

    // ---------- 简单 IP 和 URL 计数（替代正则）----------
    static int countIPs(const string& s) {
        int cnt = 0;
        size_t len = s.length();
        for (size_t i = 0; i + 7 <= len; ) {
            // 极简检测：找数字开始，尝试匹配 xxx.xxx.xxx.xxx
            if (!isdigit((unsigned char)s[i])) { ++i; continue; }
            int dots = 0;
            size_t j = i;
            bool valid = true;
            for (int part = 0; part < 4 && valid; part++) {
                int num = 0;
                int digitCount = 0;
                while (j < len && isdigit((unsigned char)s[j])) {
                    num = num * 10 + (s[j] - '0');
                    digitCount++;
                    j++;
                    if (num > 255) { valid = false; break; }
                }
                if (digitCount == 0 || num > 255) { valid = false; break; }
                if (part < 3) {
                    if (j < len && s[j] == '.') { j++; dots++; }
                    else { valid = false; break; }
                }
            }
            if (valid && dots == 3) {
                // 确保不是更长数字的一部分（前后边界）
                if ((i == 0 || !isdigit((unsigned char)s[i - 1])) && (j == len || !isdigit((unsigned char)s[j]))) {
                    cnt++;
                }
            }
            i = (j == i) ? i + 1 : j; // 跳过已匹配部分
        }
        return cnt;
    }

    static int countURLs(const string& s) {
        int cnt = 0;
        string lower = s;
        transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        const string http = "http://";
        const string https = "https://";
        size_t pos = 0;
        while ((pos = lower.find(http, pos)) != string::npos) {
            cnt++;
            pos += http.length();
        }
        pos = 0;
        while ((pos = lower.find(https, pos)) != string::npos) {
            cnt++;
            pos += https.length();
        }
        return cnt;
    }

    // ---------- 构造函数 ----------
    explicit PEFileAnalyzer(const string& path) {
        HANDLE hFile = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return;
        fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == 0 || fileSize == INVALID_FILE_SIZE) { CloseHandle(hFile); return; }
        hMap = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        CloseHandle(hFile);
        if (!hMap) return;
        fileBase = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (!fileBase) { CloseHandle(hMap); hMap = nullptr; return; }

        if (fileSize < sizeof(IMAGE_DOS_HEADER)) return;
        auto* dos = (IMAGE_DOS_HEADER*)fileBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
        if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > fileSize) return;
        auto* nt = (IMAGE_NT_HEADERS*)(fileBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;
        _64bit = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        // 验证数字签名
        if (nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_SECURITY)
        {
            DWORD certSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
            if (certSize > 0)
            {
                int wLen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, NULL, 0);
                wchar_t* wPath = new wchar_t[wLen];
                MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wPath, wLen);
                WINTRUST_FILE_INFO fileInfo = { 0 };
                fileInfo.cbStruct = sizeof(fileInfo);
                fileInfo.pcwszFilePath = wPath;
                fileInfo.hFile = NULL;
                fileInfo.pgKnownSubject = NULL;
                GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                WINTRUST_DATA trustData = { 0 };
                trustData.cbStruct = sizeof(trustData);
                trustData.dwUIChoice = WTD_UI_NONE;
                trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
                trustData.dwUnionChoice = WTD_CHOICE_FILE;
                trustData.pFile = &fileInfo;
                trustData.dwStateAction = WTD_STATEACTION_VERIFY;
                trustData.hWVTStateData = NULL;
                trustData.pwszURLReference = NULL;
                trustData.dwProvFlags = WTD_SAFER_FLAG;
                trustData.dwUIContext = 0;
                _sigValid = (WinVerifyTrust(NULL, &actionGuid, &trustData) == ERROR_SUCCESS);
                trustData.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &actionGuid, &trustData);
                delete[] wPath;
            }
        }
        valid = true;
    }

    ~PEFileAnalyzer() {
        if (fileBase) UnmapViewOfFile(fileBase);
        if (hMap) CloseHandle(hMap);
    }

    bool isPE() const { return valid; }
    bool is64bit() const { return _64bit; }
    bool isValid() const { return valid; }
    bool isSigValid() const { return _sigValid; }

    // ---------- 600 维特征提取（全面应用缓存与优化）----------
    array<float, BASE_FEATURE_DIM> extractFeatures() const {
        array<float, BASE_FEATURE_DIM> feats{};
        fill(feats.begin(), feats.end(), 0.0f);
        if (!valid) return feats;
        size_t idx = 0;

        auto* nt = (IMAGE_NT_HEADERS*)(fileBase + dos()->e_lfanew);
        auto& fh = nt->FileHeader;
        auto& oh = nt->OptionalHeader;

        // 1. PE 头结构 (40维)
        feats[idx++] = (float)fh.Machine;
        feats[idx++] = (float)fh.NumberOfSections;
        feats[idx++] = (float)fh.TimeDateStamp;
        feats[idx++] = (float)fh.PointerToSymbolTable;
        feats[idx++] = (float)fh.NumberOfSymbols;
        feats[idx++] = (float)fh.SizeOfOptionalHeader;
        feats[idx++] = (float)fh.Characteristics;
        WORD chars[] = { 0x0001,0x0002,0x0100,0x0200,0x2000,0x4000,0x8000 };
        for (WORD c : chars) feats[idx++] = (fh.Characteristics & c) ? 1.0f : 0.0f;
        feats[idx++] = (float)oh.Magic;
        feats[idx++] = (float)oh.MajorLinkerVersion;
        feats[idx++] = (float)oh.MinorLinkerVersion;
        feats[idx++] = (float)oh.SizeOfCode;
        feats[idx++] = (float)oh.SizeOfInitializedData;
        feats[idx++] = (float)oh.SizeOfUninitializedData;
        feats[idx++] = (float)oh.AddressOfEntryPoint;
        feats[idx++] = (float)oh.BaseOfCode;
        feats[idx++] = (float)oh.ImageBase;
        feats[idx++] = (float)oh.SectionAlignment;
        feats[idx++] = (float)oh.FileAlignment;
        feats[idx++] = (float)oh.MajorOperatingSystemVersion;
        feats[idx++] = (float)oh.MinorOperatingSystemVersion;
        feats[idx++] = (float)oh.MajorImageVersion;
        feats[idx++] = (float)oh.MinorImageVersion;
        feats[idx++] = (float)oh.MajorSubsystemVersion;
        feats[idx++] = (float)oh.MinorSubsystemVersion;
        feats[idx++] = (float)oh.SizeOfImage;
        feats[idx++] = (float)oh.SizeOfHeaders;
        feats[idx++] = (float)oh.CheckSum;
        feats[idx++] = (float)oh.Subsystem;
        feats[idx++] = (float)oh.DllCharacteristics;
        feats[idx++] = (float)oh.SizeOfStackReserve / 1024.0f;
        feats[idx++] = (float)oh.SizeOfStackCommit / 1024.0f;
        feats[idx++] = (float)oh.SizeOfHeapReserve / 1024.0f;
        feats[idx++] = (float)oh.SizeOfHeapCommit / 1024.0f;
        feats[idx++] = (float)oh.LoaderFlags;
        feats[idx++] = (float)oh.NumberOfRvaAndSizes;
        feats[idx++] = is64bit() ? 1.0f : 0.0f;
        feats[idx++] = (fh.Characteristics & IMAGE_FILE_DLL) ? 1.0f : 0.0f;
        feats[idx++] = (!(fh.Characteristics & IMAGE_FILE_DLL) && (fh.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) ? 1.0f : 0.0f;
        feats[idx++] = (oh.Subsystem == IMAGE_SUBSYSTEM_NATIVE) ? 1.0f : 0.0f;

        // 2. 节区特征 (30维) —— 使用缓存
        cacheSectionInfo();
        WORD nSec = sectionCount();
        const auto& secInfos = m_sectionInfos;
        float maxEnt = 0, minEnt = 8, sumEnt = 0;
        float maxRaw = 0, sumRaw = 0;
        int execCnt = 0, writeCnt = 0, readCnt = 0;
        float textSize = 0, textEnt = 0, dataSize = 0, dataEnt = 0, rsrcSize = 0, rsrcEnt = 0;

        for (const auto& info : secInfos) {
            if (info.entropy > maxEnt) maxEnt = info.entropy;
            if (info.entropy < minEnt) minEnt = info.entropy;
            sumEnt += info.entropy;
            if (info.rawSize > maxRaw) maxRaw = (float)info.rawSize;
            sumRaw += info.rawSize;
            if (info.characteristics & IMAGE_SCN_MEM_EXECUTE) execCnt++;
            if (info.characteristics & IMAGE_SCN_MEM_WRITE) writeCnt++;
            if (info.characteristics & IMAGE_SCN_MEM_READ) readCnt++;
            if (info.nameLower.find(".text") != string::npos) { textSize = (float)info.rawSize; textEnt = info.entropy; }
            else if (info.nameLower.find(".data") != string::npos || info.nameLower == ".rdata") { dataSize = (float)info.rawSize; dataEnt = info.entropy; }
            else if (info.nameLower.find(".rsrc") != string::npos) { rsrcSize = (float)info.rawSize; rsrcEnt = info.entropy; }
        }

        feats[idx++] = maxEnt;
        feats[idx++] = minEnt;
        feats[idx++] = nSec ? sumEnt / nSec : 0;
        float varEnt = 0;
        float avgEnt = nSec ? sumEnt / nSec : 0;
        for (const auto& info : secInfos) {
            float diff = info.entropy - avgEnt;
            varEnt += diff * diff;
        }
        feats[idx++] = nSec ? sqrt(varEnt / nSec) : 0;
        feats[idx++] = maxRaw;
        feats[idx++] = nSec ? sumRaw / nSec : 0;
        feats[idx++] = (float)execCnt;
        feats[idx++] = (float)writeCnt;
        feats[idx++] = (float)readCnt;
        feats[idx++] = textSize;
        feats[idx++] = textEnt;
        feats[idx++] = dataSize;
        feats[idx++] = dataEnt;
        feats[idx++] = rsrcSize;
        feats[idx++] = rsrcEnt;
        feats[idx++] = fileSize ? textSize / fileSize : 0;
        feats[idx++] = fileSize ? dataSize / fileSize : 0;
        feats[idx++] = fileSize ? rsrcSize / fileSize : 0;
        bool overlap = false;
        for (const auto& info : secInfos) {
            // 简单检查：RawSize + PointerToRawData > fileSize 已由缓存保证不越界，这里不再重复
        }
        feats[idx++] = 0; // 占位，可根据需要细化
        while (idx < 70) feats[idx++] = 0;

        // 3. 字节/熵特征 (50维) —— 使用合并统计
        computeByteStats();
        feats[idx++] = m_byteStats.totalEntropy;
        for (int i = 0; i < 32; i++) {
            int cnt = 0;
            for (int j = i * 8; j < (i + 1) * 8 && j < 256; j++) cnt += m_byteStats.byteFreq[j];
            feats[idx++] = fileSize ? (float)cnt / fileSize : 0;
        }
        BYTE specBytes[] = { 0x00,0xCC,0x90,0xE8,0xE9,0xFF };
        for (BYTE b : specBytes) feats[idx++] = fileSize ? (float)m_byteStats.byteFreq[b] / fileSize : 0;
        for (int i = 0; i < 10; i++) feats[idx++] = m_byteStats.segEntropy[i];
        float maxSeg = *max_element(m_byteStats.segEntropy, m_byteStats.segEntropy + 10);
        float minSeg = *min_element(m_byteStats.segEntropy, m_byteStats.segEntropy + 10);
        feats[idx++] = maxSeg - minSeg;
        while (idx < 120) feats[idx++] = 0;

        // 4. API 类别 (25维)
        const auto& imports = getImportedFunctionsRef();
        vector<pair<string, vector<string>>> apiCats = {
            {"ProcessControl", {"createprocessa","createprocessw","winexec","shellexecutea","shellexecutew","terminateprocess","openprocess"}},
            {"Injection", {"virtualallocex","virtualprotectex","writeprocessmemory","createremotethread","queueuserapc","setthreadcontext","ntunmapviewofsection"}},
            {"Synchronization", {"waitforsingleobject","createmutexa","createeventa","entercriticalsection","sleep"}},
            {"MultiThreading", {"createthread","resumethread","exitthread","terminatethread"}},
            {"Network", {"socket","connect","send","recv","wsastartup","internetopena","internetconnecta","urldownloadtofilea"}},
            {"Encryption", {"cryptacquirecontexta","cryptcreatehash","cryptencrypt","cryptdecrypt"}},
            {"DataObfuscation", {"rtldecompressbuffer","multibytetowidechar","base64decode","cryptdecodeobject"}},
            {"FileIO", {"createfilea","writefile","readfile","deletefilea","copyfilea","setfileattributesa","deviceiocontrol"}},
            {"Registry", {"regopenkeyexa","regsetvalueexa","regcreatekeyexa","regdeletekeya","regqueryvalueexa"}},
            {"Services", {"openscmanagera","createservicea","startservicea","controlservice","deleteservice"}},
            {"Privileges", {"adjusttokenprivileges","lookupprivilegevaluea","openprocesstoken","netuseradd"}},
            {"Native", {"rtlunwind","rtlallocateheap","ntclose","getsystemtimeasfiletime","getversionexa","getcomputernamea"}},
            {"DotNet", {"_corexemain","_cordllmain"}},
            {"AntiDebug", {"isdebuggerpresent","checkremotedebuggerpresent","outputdebugstringa","gettickcount","findwindowa","isprocessorfeaturepresent"}},
            {"Keylogging", {"getasynckeystate","getkeystate","getkeyboardstate","mapvirtualkeya","toascii","setwindowshookexa"}},
            {"Input", {"getcursorpos","setcursorpos","mouseevent","getcapture"}},
            {"ScreenCapture", {"bitblt","getdc","createcompatibledc","getdesktopwindow"}},
            {"Graphics", {"direct3dcreate9","d3d11createdevice"}},
            {"Audio", {"waveinopen","waveinclose","waveinstart","waveinstop"}},
            {"Clipboard", {"openclipboard","closeclipboard","getclipboarddata","setclipboarddata"}},
            {"Camera", {"capcreatecapturewindowa","capcreatecapturewindoww"}},
            {"Memory", {"heapalloc","heapfree","getprocessheap","localalloc","globalalloc"}},
            {"Resource", {"loadresource","sizeofresource","lockresource","findresourcea"}},
            {"WindowControl", {"showwindow","destroywindow","translatemessage","dispatchmessagea","createwindowexa"}},
            {"COM", {"cocreateinstance","coinitialize","couninitialize"}}
        };
        for (auto& cat : apiCats) {
            float cnt = 0;
            for (auto& api : cat.second) if (imports.count(api)) cnt += 1.0f;
            feats[idx++] = cnt;
        }
        while (idx < 145) feats[idx++] = 0;

        // 5. 高危 API 存在性 (200维)
        static const vector<string> highRisk = {
            "createprocessa","winexec","shellexecutea","virtualallocex","writeprocessmemory","createremotethread",
            "loadlibrarya","getprocaddress","socket","connect","recv","send","cryptencrypt","cryptdecrypt",
            "regsetvalueexa","createservicea","startservicea","adjusttokenprivileges","isdebuggerpresent",
            "getasynckeystate","setwindowshookexa","bitblt","internetopena","urldownloadtofilea",
            "createfilea","writefile","deletefilea","deviceiocontrol","openclipboard",
            "getdc","createcompatibledc","rtldecompressbuffer","cryptdecodeobject","ntunmapviewofsection",
            "queueuserapc","setthreadcontext","resumethread","terminatethread","openprocesstoken",
            "lookupprivilegevaluea","netuseradd","controlservice","regdeletekeya","regcreatekeyexa",
            "cocreateinstance","virtualprotectex","readprocessmemory","gettickcount","findwindowa",
            "getkeyboardstate","mapvirtualkeya","toascii","waveinopen","capcreatecapturewindowa",
            "d3d11createdevice","direct3dcreate9","heapalloc","loadresource","findresourcea",
            "showwindow","createwindowexa","translatemessage","dispatchmessagea","_corexemain",
            "createthread","openscmanagera","regopenkeyexa","copyfilea","movefilea",
            "gettemppatha","setfileattributesa","connectnamedpipe","peeknamedpipe",
            "regenumvaluea","regqueryvalueexa","deleteservice","startservicea",
            "netlocalgroupaddmembers","isadmin","getusernamea","rtlunwind","ntclose",
            "getversionexa","getcomputernamea","getlasterror","raiseexception","setlasterror",
            "outputdebugstringa","checkremotedebuggerpresent","enumwindows","getwindowrect",
            "setwindowdisplayaffinity","unhandledexceptionfilter","setunhandledexceptionfilter",
            "gettimezoneinformation","getdrivetypew","getdiskfreespacea","getkeystate",
            "tounicode","getkeynametexta","getforegroundwindow","sendinput",
            "getcursorpos","setcursorpos","mouseevent","stretchblt","getwindowdc",
            "printwindow","getdesktopwindow","waveinclose","waveinstart",
            "closeclipboard","getclipboarddata","setclipboarddata",
            "globalalloc","globalfree","localalloc","localfree","heapfree",
            "lockresource","freeresource","destroywindow","getactivewindow",
            "defwindowproca","getmessagea","registerclassa","messageboxa",
            "couninitialize","internetconnecta","httpopenrequesta","httpsendrequesta",
            "internetreadfile","dnsquery_a","cryptacquirecontexta","cryptcreatehash",
            "crypthashdata","cryptderivekey","cryptdestroykey","cryptdestroyhash",
            "cryptreleasecontext","cryptgenkey","cryptimportkey","cryptexportkey",
            "multibytetowidechar","widechartomultibyte","isdbcsleadbyte","charuppera","charlowera",
            "getstringtypew","decodepointer","encodepointer","getsysteminfo","comparestringa"
        };
        for (size_t i = 0; i < 200; i++) {
            if (i < highRisk.size()) feats[idx++] = imports.count(highRisk[i]) ? 1.0f : 0.0f;
            else feats[idx++] = 0;
        }

        // 6. DLL 存在性 (30维) —— 使用 unordered_set O(1) 查找
        static const vector<string> targetDlls = {
            "kernel32.dll","user32.dll","gdi32.dll","advapi32.dll","shell32.dll","ntdll.dll",
            "ws2_32.dll","wininet.dll","urlmon.dll","crypt32.dll","bcrypt.dll",
            "psapi.dll","dbghelp.dll","shlwapi.dll","ole32.dll","oleaut32.dll","comctl32.dll",
            "mscoree.dll","netapi32.dll","iphlpapi.dll","wtsapi32.dll","version.dll","winmm.dll",
            "wsock32.dll","winhttp.dll","imagehlp.dll","vbscript.dll","hal.dll"
        };
        unordered_set<string> dllSet = getImportedDLLsSet();
        for (size_t i = 0; i < 30; i++) {
            if (i < targetDlls.size())
                feats[idx++] = dllSet.count(targetDlls[i]) ? 1.0f : 0.0f;
            else
                feats[idx++] = 0;
        }

        // 7. 版本信息 (15维) —— 使用缓存
        feats[idx++] = (float)getStringFileInfoLength("FileDescription");
        feats[idx++] = (float)getStringFileInfoLength("FileVersion");
        feats[idx++] = (float)getStringFileInfoLength("ProductName");
        feats[idx++] = (float)getStringFileInfoLength("ProductVersion");
        feats[idx++] = (float)getStringFileInfoLength("CompanyName");
        feats[idx++] = (float)getStringFileInfoLength("LegalCopyright");
        feats[idx++] = (float)getStringFileInfoLength("Comments");
        feats[idx++] = (float)getStringFileInfoLength("InternalName");
        feats[idx++] = (float)getStringFileInfoLength("LegalTrademarks");
        feats[idx++] = (float)getStringFileInfoLength("SpecialBuild");
        feats[idx++] = (float)getStringFileInfoLength("PrivateBuild");
        VS_FIXEDFILEINFO vs;
        bool hasVs = getFixedFileInfo(vs);
        if (hasVs) {
            feats[idx++] = (vs.dwFileFlags & VS_FF_DEBUG) ? 1.0f : 0.0f;
            feats[idx++] = (vs.dwFileFlags & VS_FF_PRERELEASE) ? 1.0f : 0.0f;
            feats[idx++] = (vs.dwFileFlags & VS_FF_PATCHED) ? 1.0f : 0.0f;
            feats[idx++] = (vs.dwFileFlags & VS_FF_PRIVATEBUILD) ? 1.0f : 0.0f;
        }
        else {
            for (int i = 0; i < 4; i++) feats[idx++] = 0;
        }

        // 8. 数字签名 (5维)
        DWORD certRva = 0, certSize = 0;
        getDataDir(4, certRva, certSize);
        // 签名无效时向模型表现为"无签名"，让模型自身的无签名判定处理（模型训练时无"有签名但无效"样本）
        if (certSize > 0 && !_sigValid)
            certSize = 0;
        feats[idx++] = certSize > 0 ? 1.0f : 0.0f;
        feats[idx++] = 0;
        feats[idx++] = 0;
        feats[idx++] = 0;
        feats[idx++] = 0;

        // 9. 资源特征 (10维) —— 使用缓存
        feats[idx++] = hasResource(24) ? 1.0f : 0.0f;
        feats[idx++] = hasResource(16) ? 1.0f : 0.0f;
        feats[idx++] = (float)countResource(3);
        feats[idx++] = (float)countResource(1);
        feats[idx++] = (float)countResource(5);
        feats[idx++] = (float)countResource(6);
        feats[idx++] = (float)getResourceLanguages();
        feats[idx++] = hasResource(10) ? 1.0f : 0.0f;
        feats[idx++] = hasResource(23) ? 1.0f : 0.0f;
        feats[idx++] = rsrcSize > 0 ? 1.0f : 0.0f;

        // 10. 加壳/混淆 (15维)
        static const vector<string> packers = { "upx","aspack","mpress","themida","vmp","enigma","petite","yoda","armadillo","zprotect" };
        for (auto& p : packers) {
            bool found = false;
            for (const auto& info : secInfos) {
                if (info.nameLower.find(p) != string::npos) { found = true; break; }
            }
            feats[idx++] = found ? 1.0f : 0.0f;
        }
        float highEntCode = 0;
        bool nonPrintableName = false;
        for (const auto& info : secInfos) {
            if (info.entropy > 7.5 && (info.characteristics & IMAGE_SCN_MEM_EXECUTE)) highEntCode = 1.0f;
            const string& sname = info.nameLower;
            for (char ch : sname) {
                if (!isprint((unsigned char)ch)) { nonPrintableName = true; break; }
            }
        }
        feats[idx++] = highEntCode;
        feats[idx++] = nonPrintableName ? 1.0f : 0.0f;
        while (idx < 420) feats[idx++] = 0;

        // 11. 恶意字符串模式 (30维) —— 使用字符串 set
        const auto& strSet = getCachedStringSet();
        static const vector<string> malPatterns = {
            "cmd.exe","powershell","wscript","cscript","schtasks","regedit","taskmgr","rundll32",
            "rundll32.exe","wmic","vssadmin","bcdedit","netsh","ipconfig","whoami","net user",
            "net localgroup","net share","route print","arp -a","systeminfo","nslookup",
            "ftp ","tftp ","telnet ","ssh ","\\appdata\\","\\startup\\","\\temp\\",
            "\\windows\\system32\\"
        };
        for (auto& pat : malPatterns) {
            feats[idx++] = strSet.count(pat) ? 1.0f : 0.0f;
        }
        while (idx < 450) feats[idx++] = 0;

        // 12. 入口点 (10维)
        DWORD ep = oh.AddressOfEntryPoint;
        BYTE epBytes[16] = { 0 };
        if (ep && ep < fileSize) {
            DWORD len = min((DWORD)16, fileSize - ep);
            memcpy(epBytes, fileBase + ep, len);
        }
        feats[idx++] = (float)epBytes[0];
        feats[idx++] = (float)entropy(epBytes, 16);
        feats[idx++] = (memchr(epBytes, 0xE8, 16) ? 1.0f : 0.0f);
        feats[idx++] = (memchr(epBytes, 0xE9, 16) ? 1.0f : 0.0f);
        feats[idx++] = (memchr(epBytes, 0xCC, 16) ? 1.0f : 0.0f);
        for (int i = 0; i < 5; i++) feats[idx++] = 0;
        while (idx < 460) feats[idx++] = 0;

        // 13. 网络特征 (20维) —— 使用 set 迭代 + 简单计数
        const auto& strSetRef = getCachedStringSet();
        int ipCnt = 0, urlCnt = 0;
        for (const auto& s : strSetRef) {
            ipCnt += countIPs(s);
            urlCnt += countURLs(s);
        }
        feats[idx++] = (float)ipCnt;
        feats[idx++] = (float)urlCnt;
        feats[idx++] = strSetRef.count("ftp://") ? 1.0f : 0.0f;
        static const char* protos[] = { "http","https","ftp","smtp","dns","tcp","udp" };
        for (const char* p : protos)
            feats[idx++] = strSetRef.count(p) ? 1.0f : 0.0f;
        feats[idx++] = strSetRef.count("localhost") ? 1.0f : 0.0f;
        feats[idx++] = (strSetRef.count("no-ip") || strSetRef.count("dyndns")) ? 1.0f : 0.0f;
        static const int ports[] = { 80,443,8080,4444,5555,6666,1337,31337 };
        for (int p : ports)
            feats[idx++] = strSetRef.count(to_string(p)) ? 1.0f : 0.0f;
        while (idx < 480) feats[idx++] = 0;

        // 14. 文件路径模式 (20维)
        static const char* paths[] = {
            "\\windows\\system32\\","\\windows\\syswow64\\","\\appdata\\local\\temp\\",
            "\\start menu\\programs\\startup\\","\\task scheduler\\","\\drivers\\",
            "\\microsoft\\windows\\currentversion\\run","hklm\\software","hkcu\\software"
        };
        for (const char* p : paths)
            feats[idx++] = strSetRef.count(p) ? 1.0f : 0.0f;
        while (idx < 500) feats[idx++] = 0;

        // 15. 字符串统计 (50维) —— 使用 set 迭代
        int totalStr = (int)strSetRef.size();
        double sumLen = 0;
        int maxLen = 0, minLen = 100000;
        int lenHist[8] = { 0 };
        for (const auto& s : strSetRef) {
            int l = (int)s.length();
            sumLen += l;
            if (l > maxLen) maxLen = l;
            if (l < minLen) minLen = l;
            if (l <= 7) lenHist[0]++;
            else if (l <= 15) lenHist[1]++;
            else if (l <= 31) lenHist[2]++;
            else if (l <= 63) lenHist[3]++;
            else if (l <= 127) lenHist[4]++;
            else if (l <= 255) lenHist[5]++;
            else if (l <= 511) lenHist[6]++;
            else lenHist[7]++;
        }
        feats[idx++] = (float)totalStr;
        feats[idx++] = totalStr ? (float)(sumLen / totalStr) : 0;
        feats[idx++] = (float)maxLen;
        feats[idx++] = minLen < 100000 ? (float)minLen : 0;
        for (int i = 0; i < 8; i++) feats[idx++] = (float)lenHist[i];
        while (idx < 550) feats[idx++] = 0;

        // 16. 行为特征 (50维)
        feats[idx++] = (imports.count("virtualallocex") && imports.count("writeprocessmemory")) ? 1.0f : 0.0f;
        feats[idx++] = strSet.count("\\run") ? 1.0f : 0.0f;
        feats[idx++] = imports.count("createservicea") ? 1.0f : 0.0f;
        feats[idx++] = strSet.count("schtasks") ? 1.0f : 0.0f;
        feats[idx++] = imports.count("isdebuggerpresent") ? 1.0f : 0.0f;
        feats[idx++] = (strSet.count("vmware") || strSet.count("vbox")) ? 1.0f : 0.0f;
        feats[idx++] = (strSet.count("procmon") || strSet.count("wireshark")) ? 1.0f : 0.0f;
        feats[idx++] = (strSet.count("cmd.exe") || strSet.count("powershell.exe")) ? 1.0f : 0.0f;
        feats[idx++] = (imports.count("loadlibrarya") && imports.count("getprocaddress")) ? 1.0f : 0.0f;
        feats[idx++] = (imports.count("getasynckeystate") || imports.count("setwindowshookexa")) ? 1.0f : 0.0f;
        feats[idx++] = imports.count("bitblt") ? 1.0f : 0.0f;
        feats[idx++] = (strSet.count("lsass") || strSet.count("sam")) ? 1.0f : 0.0f;
        feats[idx++] = (imports.count("cryptencrypt") || imports.count("cryptdecrypt")) ? 1.0f : 0.0f;
        feats[idx++] = strSet.count("base64") ? 1.0f : 0.0f;
        feats[idx++] = imports.count("sleep") ? 1.0f : 0.0f;
        while (idx < BASE_FEATURE_DIM) feats[idx++] = 0;

        return feats;
    }
};

struct VirusClassResult {
    string family;           // 如 "HEUR:Ransom/FileCrypter.a" 或 "HEUR:Trojan.Generic@0.45"
    string category;         // 大类: Ransom, Trojan, Backdoor, PUA, Virus
    string variant;          // 变种标识
    double confidence;
    vector<string> tags;
    string description;
};

class HeuristicRulesEngine {
public:
    static constexpr double MIN_CONFIDENCE_THRESHOLD = 0.55;

    VirusClassResult classifyByAnalyzer(const PEFileAnalyzer& pe) const;

private:
    struct AbstractPE {
        set<string> imports;
        set<string> dlls;
        vector<string> strings;        // 已小写
        vector<string> section_names;  // 已小写
        bool has_version_resource = false;
        bool has_signature = false;
        bool has_overlay = false;
        double entry_entropy = 0.0;
    };

    struct RuleResult {
        string variant;
        double confidence;
        vector<string> tags;
        string subCategory;  // 子类别名（如 "Wiper", "Bootkit"），用于描述查找
    };

    // 规则引擎支撑结构
    struct DetectionRule {
        function<bool()> condition;    // 条件检查（闭包捕获 AbstractPE）
        double score;
        vector<string> tags;
    };

    struct SubCategory {
        string name;                              // 子类别名称，如 "Ransomware"
        vector<DetectionRule> rules;              // 规则列表
        function<string()> variantSelector;       // 变种选择器
        function<double(double)> adjustScore = nullptr; // 分值后处理
    };

    // 五大类检测函数（替代原有16个具体函数）
    RuleResult detectRansomClass(const AbstractPE& d) const;
    RuleResult detectBackdoorClass(const AbstractPE& d) const;
    RuleResult detectVirusClass(const AbstractPE& d) const;     // 对应Worm
    RuleResult detectPUAClass(const AbstractPE& d) const;       // Miner / Adware / Hacktool
    RuleResult detectTrojanClass(const AbstractPE& d) const;    // 其余所有子类别

    // 通用子类别选择器：从一组子类别中选出最高置信度
    RuleResult detectCategory(const vector<SubCategory>& subs) const;

    // 辅助函数
    bool hasAnyImport(const set<string>& funcs, const vector<string>& candidates) const;
    bool hasAnyString(const vector<string>& haystack, const vector<string>& needles) const;
    bool hasStringSubstr(const vector<string>& haystack, const string& substr) const;
    int  countStringMatches(const vector<string>& haystack, const vector<string>& needles) const;

    inline VirusClassResult analyze(const AbstractPE& d) const;

    static string toLower(const string& s) {
        string r = s;
        transform(r.begin(), r.end(), r.begin(), ::tolower);
        return r;
    }
};

// ---------- 辅助函数实现 ----------
inline bool HeuristicRulesEngine::hasAnyImport(const set<string>& funcs, const vector<string>& candidates) const {
    for (auto& c : candidates) if (funcs.find(c) != funcs.end()) return true;
    return false;
}
inline bool HeuristicRulesEngine::hasAnyString(const vector<string>& haystack, const vector<string>& needles) const {
    for (auto& s : haystack) for (auto& n : needles) if (s == n) return true;
    return false;
}
inline bool HeuristicRulesEngine::hasStringSubstr(const vector<string>& haystack, const string& substr) const {
    for (auto& s : haystack) if (s.find(substr) != string::npos) return true;
    return false;
}
inline int HeuristicRulesEngine::countStringMatches(const vector<string>& haystack, const vector<string>& needles) const {
    int cnt = 0;
    for (auto& s : haystack) for (auto& n : needles) if (s == n) cnt++;
    return cnt;
}

// ---------- 通用子类别执行器 ----------
inline HeuristicRulesEngine::RuleResult
HeuristicRulesEngine::detectCategory(const vector<SubCategory>& subs) const {
    RuleResult best{ "", 0.0, {} };
    double bestScore = -1.0;

    for (const auto& sub : subs) {
        double score = 0.0;
        vector<string> tags;

        // 执行所有规则
        for (const auto& rule : sub.rules) {
            if (rule.condition()) {
                score += rule.score;
                for (const auto& t : rule.tags) {
                    if (std::find(tags.begin(), tags.end(), t) == tags.end())
                        tags.push_back(t);
                }
            }
        }

        // 分值后处理
        if (sub.adjustScore)
            score = sub.adjustScore(score);

        score = min(score, 1.0);

        string variant = sub.variantSelector();

        if (score > bestScore) {
            bestScore = score;
            best.variant = variant;
            best.confidence = score;
            best.tags = tags;
            best.subCategory = sub.name;
        }
    }
    return best;
}

// ---------- classifyByAnalyzer 与 analyze 实现 ----------
inline VirusClassResult HeuristicRulesEngine::classifyByAnalyzer(const PEFileAnalyzer& pe) const {
    AbstractPE data;
    if (!pe.isValid()) return { "unknown", "unknown", "", 0.0, {}, "PE 解析失败" };

    auto imports = pe.getImportedFunctions();
    for (auto& f : imports) data.imports.insert(toLower(f));
    auto dlls = pe.getImportedDLLs();
    for (auto& d : dlls) data.dlls.insert(toLower(d));

    auto allStr = pe.collectAllStrings();
    for (auto& s : allStr) data.strings.push_back(toLower(s));

    WORD nSec = pe.sectionCount();
    const IMAGE_SECTION_HEADER* sec = pe.sections();
    if (sec && nSec > 0) {
        for (WORD i = 0; i < nSec; i++) {
            char name[9] = { 0 };
            memcpy(name, sec[i].Name, 8);
            data.section_names.push_back(toLower(string(name)));
        }
    }

    data.has_version_resource = pe.hasResource(16);
    DWORD certRva, certSize;
    data.has_signature = pe.getDataDir(4, certRva, certSize) && certSize > 0;

    auto* nt = (IMAGE_NT_HEADERS*)(pe.fileBase + pe.dos()->e_lfanew);
    DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
    if (ep > 0 && ep < pe.fileSize) {
        DWORD len = min(unsigned long(16u), pe.fileSize - ep);
        data.entry_entropy = pe.entropy(pe.fileBase + ep, len);
    }

    return analyze(data);
}

inline VirusClassResult HeuristicRulesEngine::analyze(const AbstractPE& d) const {
    auto resRansom = detectRansomClass(d);
    auto resBackdoor = detectBackdoorClass(d);
    auto resVirus = detectVirusClass(d);
    auto resPUA = detectPUAClass(d);
    auto resTrojan = detectTrojanClass(d);

    struct Candidate { string category; RuleResult result; };
    vector<Candidate> candidates = {
        {"Ransomware", resRansom},
        {"Backdoor",   resBackdoor},
        {"Worm",       resVirus},
        {"PUA",        resPUA},
        {"Trojan",     resTrojan}
    };

    Candidate best = candidates[0];
    for (auto& c : candidates) {
        if (c.result.confidence > best.result.confidence)
            best = c;
    }

    string prefix;
    if (best.category == "Ransomware")               prefix = "Ransom";
    else if (best.category == "Backdoor")            prefix = "Backdoor";
    else if (best.category == "Worm")                prefix = "Virus";
    else if (best.category == "PUA")                 prefix = "PUA";
    else                                             prefix = "Trojan";

    // 低置信度回退（统一使用 0-100 置信度）
    if (best.result.confidence < MIN_CONFIDENCE_THRESHOLD) {
        ostringstream fam;
        fam << "Heur/Trojan.Generic@" << fixed << setprecision(0)
            << best.result.confidence * 100;
        VirusClassResult res;
        res.family = fam.str();
        res.category = "Trojan";
        res.variant = "Generic";
        res.confidence = best.result.confidence;
        res.tags = best.result.tags;
        res.description = "通用木马（具体类别置信度不足）";
        return res;
    }

    string family = "Heur/" + prefix + "." + best.result.variant + "!a";
    VirusClassResult res;
    res.family = family;
    res.category = prefix;
    res.variant = best.result.variant + ".Generic";
    res.confidence = best.result.confidence * 100;
    res.tags = best.result.tags;

    static const map<string, string> desc = {
        {"Ransomware",  "勒索软件：加密或删除文件，索要赎金"},
        {"Infostealer", "信息窃取木马：窃取密码、凭证等"},
        {"Backdoor",    "后门程序：提供远程 Shell/控制"},
        {"Worm",        "蠕虫：自动通过网络/移动介质传播"},
        {"Keylogger",   "键盘记录器：捕获按键、剪贴板"},
        {"Dropper",     "释放器/下载者：释放或下载其他恶意组件"},
        {"Miner",       "挖矿程序：未经许可利用计算资源挖掘加密货币"},
        {"Banker",      "银行木马：窃取网银凭证"},
        {"Spyware",     "间谍软件：监控用户活动"},
        {"Adware",      "广告软件：强制显示广告"},
        {"RAT",         "远程管理工具：隐蔽远程桌面/文件管理"},
        {"Clicker",     "点击欺诈软件：模拟用户点击广告"},
        {"Rootkit",     "Rootkit：隐藏文件/进程/注册表项"},
        {"Exploit",     "漏洞利用程序：利用软件漏洞执行代码"},
        {"Loader",      "加载器：解密/解压并执行后续 payload"},
        {"Hacktool",    "黑客工具：被恶意利用的合法工具"},
        {"Trojan",      "木马程序：伪装成正常软件的恶意程序"},
        {"PUA",         "潜在不需要的程序(PUP/PUA)"},
        {"Wiper",       "擦除器：直接删除/覆写数据（不加密不索赎）"},
        {"Bootkit",     "Bootkit：感染引导扇区(MBR/VBR)实现持久化"},
        {"Proxy",       "代理木马：建立 SOCKS/HTTP 中继隐藏攻击来源"},
        {"DDoSAgent",   "DDoS 代理：参与分布式拒绝服务攻击"},
        {"Crypter",     "加壳器：打包/加密恶意代码以逃避检测"},
        {"Bancos",      "银行钓鱼木马：针对特定银行网页劫持"},
        {"Joke",        "恶作剧程序：无害但干扰用户使用"},
        {"Constructor", "病毒构造工具：生成/定制恶意代码"}
    };
    // 描述查找：先按子类别名查找，再按顶层类别查找
    {
        if (!best.result.subCategory.empty() && desc.count(best.result.subCategory))
            res.description = desc.at(best.result.subCategory);
        else if (desc.count(best.category))
            res.description = desc.at(best.category);
        else
            res.description = "未知恶意软件";
    }
    return res;
}


// ---------- Ransom (勒索) ----------
inline HeuristicRulesEngine::RuleResult
HeuristicRulesEngine::detectRansomClass(const AbstractPE& d) const {
    SubCategory ransom;
    ransom.name = "Ransomware";
    ransom.rules = {
        // 原有 10 条规则
        { [&] { return hasAnyImport(d.imports, {
            "cryptencrypt","cryptdecrypt","cryptacquirecontexta","cryptgenkey",
            "bcryptencrypt","bcryptdecrypt","cryptimportkey","cryptexportkey",
            "cryptprotectdata","cryptunprotectdata","ncryptencrypt","ncryptimportkey",
            "cryptgenrandom" }); }, 0.50, {"encrypts_files"} },
        { [&] { return hasAnyImport(d.imports, {
            "findfirstfilea","findnextfilea","setfileattributesa","getfileattributesa",
            "setfileinformationbyhandle","ntqueryinformationfile","ntsetinformationfile" }); }, 0.18, {} },
        { [&] { return hasAnyImport(d.imports, {
            "deletefilea","deletefilew","shfileoperationa","removefile","rename","movefilea",
            "movefileexa","movefileexw","ntdeletefile" }); }, 0.35, {"deletes_files"} },
        { [&] { return hasAnyString(d.strings, {
            "ransom","bitcoin","btc","payment","decrypt","restore",
            "your files have been encrypted",".locked",".crypt","how to decrypt",
            "encrypted files","vssadmin","shadow","backup",
            ".lockbit",".conti",".blackcat","readme.txt","how_to_decrypt.txt",
            "monero","xmr","ethereum","eth","paymen","recover file" }); }, 0.40, {"ransom_note"} },
        { [&] { return hasAnyString(d.strings, {
            "vssadmin delete shadows","wmic shadowcopy delete","bcdedit /set",
            "wbadmin delete catalog","shadowcopy","recovery","restore point",
            "sc stop vss","sc stop sql","net stop" }); }, 0.15, {"disable_recovery"} },
        { [&] { return hasAnyImport(d.imports, {
            "internetopena","internetconnecta","winhttpopen","winhttpconnect","socket","connect" }); }, 0.10, {"network_activity"} },
        { [&] { return hasAnyImport(d.imports, {
            "isdebuggerpresent","checkremotedebuggerpresent","ntqueryinformationprocess",
            "gettickcount","rdtsc" }) ||
               hasAnyString(d.strings, {
            "vbox","vmware","sandboxie","procmon","wireshark","avast","bitdefender",
            "qemu","kaspersky","malwarebytes","crowdstrike","sentinelone" }); }, 0.08, {"anti_sandbox"} },
        { [&] { return hasAnyString(d.strings, {
            "\\run\\","\\startup\\","hkey_local_machine\\software\\microsoft\\windows\\currentversion\\run",
            "schtasks","hkey_current_user" }); }, 0.05, {"persistence"} },
        { [&] { return hasAnyImport(d.dlls, {
            "crypt32.dll","advapi32.dll","shell32.dll","kernel32.dll","ntdll.dll" }); }, 0.05, {} },
        { [&] { return hasStringSubstr(d.strings, "key") && hasStringSubstr(d.strings, "file"); }, 0.05, {} },
        // 新增 5 条规则
        { [&] { return hasAnyImport(d.imports, {
            "systemparametersinfoa","systemparametersinfow" }); }, 0.10, {"wallpaper_change"} },
        { [&] { return hasAnyImport(d.imports, {
            "terminateprocess","ntterminateprocess" }); }, 0.10, {"kill_processes"} },
        { [&] { return hasAnyString(d.strings, {
            "read_me.txt","decryptor.exe","unlock files","restore files" }); }, 0.15, {"ransom_note_variants"} },
        { [&] { return hasAnyImport(d.imports, {
            "regsetvalueexa","regcreatekeyexa" }) &&
               hasAnyString(d.strings, { "\\run\\","\\startup\\" }); }, 0.08, {"persistence_registry"} },
        { [&] { return hasAnyImport(d.imports, {
            "findfirstfilea","findnextfilea" }) &&
               hasAnyImport(d.imports, {"createfilea","writefile"}); }, 0.12, {"batch_file_encrypt"} }
    };
    ransom.variantSelector = [&] {
        // 仅当包含 vssadmin/shadowcopy 删除命令时才标记为 DeleteShadow，
        // 不能用宽泛的 "delete" 或 "shadow" 子串（DeleteFile/ShadowWindow 等正常字符串会误判）
        if (hasAnyString(d.strings, {
            "vssadmin delete shadows","vssadmin deleteshadows",
            "wmic shadowcopy delete","shadowcopy delete",
            "wbadmin delete catalog","vssadmin delete" }) ||
            (hasStringSubstr(d.strings, "vssadmin") && hasStringSubstr(d.strings, "delete")))
            return string("DeleteShadow");
        if (hasStringSubstr(d.strings, "lockscreen") ||
            (hasStringSubstr(d.strings, "lock") && hasAnyString(d.strings, { "screen","desktop","wallpaper" })))
            return string("LockScreen");
        if (hasAnyString(d.strings, { ".lockbit",".conti",".blackcat" }))
            return string("RansomwareAsAService");
        return string("FileCrypter");
        };

    return detectCategory({ ransom });
}

// ---------- Backdoor (后门) ----------
inline HeuristicRulesEngine::RuleResult
HeuristicRulesEngine::detectBackdoorClass(const AbstractPE& d) const {
    SubCategory backdoor;
    backdoor.name = "Backdoor";
    backdoor.rules = {
        // 原有 8 条规则
        { [&] { return hasAnyImport(d.imports, {
            "socket","connect","bind","listen","accept","wsastartup","wsaconnect" }); }, 0.35, {"network_enabled"} },
        { [&] { return hasAnyImport(d.imports, {
            "createprocessa","winexec","system","popen","exec","fork",
            "shellexecutea","shellexecutew","ntcreateprocess" }); }, 0.40, {"command_execution"} },
        { [&] { return hasAnyString(d.strings, {
            "cmd.exe","powershell","/c","reverse shell","backdoor","connect back",
            "listening on","sh -i","/bin/bash","bash -i","/bin/sh",
            "perl -e","python -c","nc ","ncat","socat" }); }, 0.30, {"shell_strings"} },
        { [&] { return hasAnyString(d.strings, {
            "\\run\\","\\startup\\","hkey_local_machine","software\\microsoft\\windows\\currentversion\\run",
            "schtasks","create /tn","sc create","wmi","\\currentversion\\runonce" }); }, 0.10, {"persistence"} },
        { [&] { return hasAnyImport(d.imports, {
            "virtualallocex","writeprocessmemory","createremotethread","ntunmapviewofsection",
            "setthreadcontext","resumethread" }); }, 0.12, {"process_injection"} },
        { [&] { return hasAnyString(d.strings, {
            "4444","1337","31337","8888","443","8080","12345","5555" }); }, 0.05, {} },
        { [&] { return hasAnyString(d.strings, {
            "poison ivy","darkcomet","njrat","gh0st","quasarrat","asyncrat",
            "beacon","cobalt strike","metasploit","meterpreter" }); }, 0.15, {"known_backdoor"} },
        { [&] { return hasAnyImport(d.imports, {
            "isdebuggerpresent","checkremotedebuggerpresent","sleep" }) ||
               hasAnyString(d.strings, { "vbox","vmware","sandboxie" }); }, 0.05, {"anti_sandbox"} },
            // 新增 5 条规则
            { [&] { return hasAnyImport(d.imports, {
                "openscmanagera","createservicea" }); }, 0.15, {"service_persistence"} },
            { [&] { return hasAnyString(d.strings, {
                "hklm\\system\\currentcontrolset\\services" }); }, 0.10, {"service_strings"} },
            { [&] { return hasAnyImport(d.imports, {
                "openprocesstoken","adjusttokenprivileges" }); }, 0.12, {"escalation"} },
            { [&] { return hasAnyImport(d.imports, {
                "showwindow" }) && hasAnyImport(d.imports, {"socket","connect"}); }, 0.10, {"hidden_connection"} },
            { [&] { return hasAnyImport(d.imports, {
                "dnsquery_a","getaddrinfo" }); }, 0.08, {"dns_resolve"} }
    };
    backdoor.variantSelector = [&] {
        if (hasStringSubstr(d.strings, "reverse shell") || hasStringSubstr(d.strings, "connect back"))
            return string("ReverseShell");
        if (hasStringSubstr(d.strings, "bot") || hasStringSubstr(d.strings, "beacon") ||
            hasStringSubstr(d.strings, "cobalt strike"))
            return string("Botnet");
        if (hasAnyImport(d.imports, { "getsysteminformation","getusername","gethostbyname" }))
            return string("Recon");
        if (hasAnyString(d.strings, { "poison ivy","darkcomet","njrat" }))
            return string("RAT");
        return string("RemoteAccess");
        };

    return detectCategory({ backdoor });
}

// ---------- Virus (蠕虫) ----------
inline HeuristicRulesEngine::RuleResult
HeuristicRulesEngine::detectVirusClass(const AbstractPE& d) const {
    SubCategory worm;
    worm.name = "Worm";
    worm.rules = {
        // 原有 6 条规则
        { [&] { return hasAnyImport(d.imports, {
            "socket","connect","send","recv","wsastartup","scan","inet_addr",
            "wnetenumresourcea","wnetaddconnection2a","netshareenum" }); }, 0.30, {"network_spread"} },
        { [&] { return hasAnyString(d.strings, {
            "\\autorun.inf","removable","\\usb","\\storage","\\drive","autorun",
            "\\device\\","\\harddisk","\\volume","\\removable" }); }, 0.30, {"spreads_via_usb"} },
        { [&] { return hasAnyString(d.strings, {
            "infect","exploit","propagate","worm","scanning","tcp port","flood",
            "ms08-067","ms17-010","eternalblue","conficker" }); }, 0.30, {"worm_strings"} },
        { [&] { return hasAnyString(d.strings, {
            "email","mapi","outlook","smtp","sendmail","cdonts","cdo.message",
            "microsoft outlook","mailto" }) ||
               hasAnyImport(d.imports, { "mapisendmail","mapiinitialize" }); }, 0.15, {"spreads_via_email"} },
        { [&] { return hasAnyImport(d.imports, {
            "getmodulefilenamea","copyfilea","copyfilew","movefilea","rename",
            "createfilea","writefile","getmodulehandlea" }); }, 0.20, {"self_copy"} },
        { [&] { return hasAnyString(d.strings, {
            "cve-","exploit","shellcode","payload","rop","egghunter" }); }, 0.10, {"exploit"} },
            // 新增 5 条规则
            { [&] { return hasAnyString(d.strings, {
                "192.168.","10.","172.16.","subnet","scanning" }); }, 0.15, {"ip_scan"} },
            { [&] { return hasAnyString(d.strings, {
                "worm","spread","replicate" }); }, 0.15, {"worm_keywords"} },
            { [&] { return hasAnyImport(d.imports, {
                "netshareadd","netuseadd" }); }, 0.10, {"share_spread"} },
            { [&] { return hasAnyImport(d.imports, {
                "createremotethread" }); }, 0.10, {"process_injection_spread"} },
            { [&] { return hasAnyString(d.strings, {
                "startup folder","appdata\\roaming","startup\\" }); }, 0.05, {} }
    };
    worm.variantSelector = [&] {
        if (hasAnyString(d.strings, { "email","mapi","outlook" }) ||
            hasAnyImport(d.imports, { "mapiinitialize" }))
            return string("EmailWorm");
        if (hasAnyString(d.strings, { "usb","autorun","removable" }))
            return string("USBWorm");
        if (hasAnyString(d.strings, { "exploit","cve-","ms08-067","ms17-010" }))
            return string("ExploitWorm");
        return string("NetworkWorm");
        };

    return detectCategory({ worm });
}

// ---------- PUA (潜在不需要程序: Miner / Adware / Hacktool) ----------
inline HeuristicRulesEngine::RuleResult
HeuristicRulesEngine::detectPUAClass(const AbstractPE& d) const {
    // 1. Miner
    SubCategory miner;
    miner.name = "Miner";
    miner.rules = {
        // 原有 7 条
        { [&] { return hasAnyString(d.strings, {
            "miner","cryptonight","stratum+tcp://","ethash","xmr","bitcoin",
            "monero","nicehash","pool.mine","mining","cpu","gpu","cryptocurrency",
            "xmrig","claymore","phoenixminer","nbminer","t-rex","gminer",
            "randomx","kawpow","daggerhashimoto","sha256","scrypt",
            "stratum+ssl://","pool.pay." }); }, 0.55, {"mining_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "setthreadaffinitymask","setprocessaffinitymask","getprocessormetrics",
            "getlogicalprocessorinformation","globalmemorystatusex" }); }, 0.15, {} },
        { [&] { return hasAnyImport(d.imports, {
            "showwindow","setwindowpos","findwindowa","setwindowlonga",
            "getconsolewindow","freeconsole" }); }, 0.05, {"hides_window"} },
        { [&] { return hasAnyImport(d.dlls, {
            "crypt32.dll","ntdll.dll","advapi32.dll" }); }, 0.05, {} },
        { [&] { return hasStringSubstr(d.strings, "pool.") || hasStringSubstr(d.strings, "stratum"); }, 0.10, {} },
        { [&] { return hasAnyString(d.strings, { "vbox","vmware","sandboxie","qemu" }); }, 0.05, {"anti_sandbox"} },
        { [&] { return hasAnyString(d.strings, {
            "\\run\\","\\startup\\","schtasks","watchdog","guard" }); }, 0.00, {"persistence"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "nvcuda.dll","cudart.dll","opencl.dll","vulkan-1.dll" }); }, 0.12, {"gpu_mining"} },
            { [&] { return hasAnyString(d.strings, {
                "config.json","pools.txt","cpu.txt" }); }, 0.10, {"miner_config"} },
            { [&] { return hasAnyImport(d.imports, {
                "showwindow","setwindowpos" }); }, 0.05, {} },
            { [&] { return hasAnyString(d.strings, {
                "wallet_address","worker","rig" }); }, 0.08, {} },
            { [&] { return hasAnyImport(d.imports, {
                "getsystemfirmwaretable" }); }, 0.05, {} }
    };
    miner.variantSelector = [] { return string("CoinMiner"); };

    // 2. Adware
    SubCategory adware;
    adware.name = "Adware";
    adware.rules = {
        // 原有 4 条
        { [&] { return hasAnyString(d.strings, {
            "advertisement","popup","sponsor","coupon","doubleclick",
            "adserving","banners","traffic","click","cpm","cpc",
            "adsense","openx","revcontent","adclick","adnetwork" }); }, 0.50, {"ad_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "regsetvalueexa","internetopena","internetconnecta","shell32",
            "regcreatekeyexa","regdeletevaluea" }) ||
               hasAnyString(d.strings, {
            "start page","search page","default_page","bho","browser helper object",
            "iexplore","chrome extension","firefox extension" }); }, 0.25, {"browser_hijack"} },
        { [&] { return hasAnyString(d.strings, {
            ".sol","flash cookie","macromedia","sharedobject" }); }, 0.10, {"flash_storage"} },
        { [&] { return hasAnyString(d.strings, {
            "bundle","installer","optional offer","sponsor","third-party" }); }, 0.10, {"bundled"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "popup","popunder","interstitial" }); }, 0.15, {"popup_strings"} },
            { [&] { return hasAnyString(d.strings, {
                "browser extension","addon","plugin","npapi" }); }, 0.12, {"browser_addon"} },
            { [&] { return hasAnyImport(d.imports, {
                "setwindowshookexa" }) && hasAnyString(d.strings, {"chrome","firefox","iexplore"}); }, 0.10, {"browser_hook"} },
            { [&] { return hasAnyString(d.strings, {
                "defaultsearchprovider","startpage" }); }, 0.12, {"hijack_search"} },
            { [&] { return hasAnyImport(d.imports, {
                "regsvr32" }) || hasAnyString(d.strings, {"installplugin"}); }, 0.08, {} }
    };
    adware.adjustScore = [&](double score) {
        if (d.has_signature) score *= 0.7;
        return score;
        };
    adware.variantSelector = [] { return string("AdInjector"); };

    // 3. Hacktool — 提高门槛：单一宽泛词(crack/patch/serial)不触发，
    // 需要多个 hacktool 特征同时出现或出现高置信度特征
    SubCategory hacktool;
    hacktool.name = "Hacktool";
    hacktool.rules = {
        // 高置信度：已知破解/黑客工具名称（精确匹配）
        { [&] { return hasAnyString(d.strings, {
            "keygen","wpe pro","cheat engine","artmoney",
            "hashcat","oclhashcat","rainbow table","dict attack",
            "ollydbg","x64dbg","dnspy","reflector","peid" }); }, 0.50, {"known_hacktool"} },
        // 中置信度：需要2个以上 hacktool 相关词同时出现
        { [&] {
            int cnt = 0;
            if (hasAnyString(d.strings, { "crack","keygen","patch","activator" })) ++cnt;
            if (hasAnyString(d.strings, { "serial","license","keymaker","keygen" })) ++cnt;
            if (hasAnyString(d.strings, { "bruteforce","password recovery","rainbow" })) ++cnt;
            if (hasAnyString(d.strings, { "injector","trainer","aimbot","wallhack" })) ++cnt;
            return cnt >= 2; }, 0.40, {"multi_hacktool_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "readprocessmemory","writeprocessmemory","openprocess","terminateprocess",
            "virtualprotectex","createprocessa" }) &&
               hasAnyString(d.strings, { "cheat","hack","inject","trainer","debug" }); }, 0.30, {"process_manipulation"} },
        { [&] { return hasAnyImport(d.imports, {
            "createremotethread","setwindowshookexa","loadlibrarya" }) &&
               hasAnyString(d.strings, { "inject","hook","dll" }); }, 0.15, {"injection"} },
        // 低置信度：仅 debug 相关
        { [&] { return hasAnyImport(d.imports, {
            "openprocesstoken","adjusttokenprivileges" }) &&
               hasAnyString(d.strings, {"sedebugprivilege"}); }, 0.10, {"privilege_escalation"} },
        { [&] { return hasAnyImport(d.imports, {
            "ntquerysysteminformation","writeprocessmemory" }) &&
               hasAnyString(d.strings, { "hide","stealth","rootkit" }); }, 0.12, {"process_hide"} },
        { [&] { return hasAnyString(d.strings, {
            "kbdllhookstruct","getasynckeystate" }) &&
               hasAnyImport(d.imports, { "setwindowshookexa" }); }, 0.10, {"keyboard_hook_hack"} },
        // 已知工具名精确匹配
        { [&] { return hasAnyString(d.strings, {
            "trainer","aimbot","wallhack" }); }, 0.25, {"game_hack"} }
    };
    hacktool.variantSelector = [&] {
        if (hasAnyString(d.strings, { "keygen","keymaker" })) return string("Keygen");
        if (hasAnyString(d.strings, { "cheat engine","trainer","aimbot","wallhack" })) return string("GameHack");
        if (hasAnyString(d.strings, { "hashcat","oclhashcat","rainbow table","bruteforce" })) return string("PasswordCracker");
        if (hasAnyString(d.strings, { "ollydbg","x64dbg","dnspy","peid" })) return string("Debugger");
        return string("Cracker");
    };

    // 4. Joke — 恶作剧程序（无害但烦人，翻转屏幕、弹窗、假格式化等）
    SubCategory joke;
    joke.name = "Joke";
    joke.rules = {
        { [&] { return hasAnyString(d.strings, {
            "joke","prank","scare","fake","fun","trick","scareware",
            "fakeformat","fakescreen","fakeblue","fakebsod" }); }, 0.45, {"joke_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "swapmousebutton","setsystemcursor","systemparametersinfoa",
            "changedisplaysettingsa","exitwindowsex" }); }, 0.35, {"system_prank"} },
        { [&] { return hasAnyImport(d.imports, {
            "messageboxa","messageboxw","setwindowpos","setforegroundwindow" }) &&
               hasAnyString(d.strings, { "ha ha","gotcha","scared","format","delete" }); }, 0.30, {"annoying_popup"} },
        { [&] { return hasAnyString(d.strings, {
            "cd-rom","eject","tray","open","close","beep","sound" }); }, 0.20, {"hardware_prank"} },
        { [&] { return hasAnyImport(d.imports, {
            "setcursorpos","clipcursor","showcursor" }); }, 0.15, {"cursor_prank"} }
    };
    joke.variantSelector = [&] {
        if (hasAnyString(d.strings, { "fakeformat","format" })) return string("FakeFormat");
        if (hasAnyString(d.strings, { "bsod","blue screen" })) return string("FakeBSOD");
        if (hasAnyString(d.strings, { "eject","cd-rom","tray" })) return string("CDEject");
        return string("Joke");
    };

    // 5. Constructor — 病毒构造工具（VCL, VGEN, Virus-Maker 等）
    SubCategory constructor;
    constructor.name = "Constructor";
    constructor.rules = {
        { [&] { return hasAnyString(d.strings, {
            "vcl","vgen","virus maker","virus generator","virus creator",
            "virus construction","virus lab","batch virus","script virus" }); }, 0.50, {"constructor_strings"} },
        { [&] { return hasAnyString(d.strings, {
            "generate","create virus","build malware","assemble",
            "polymorphic","metamorphic","encryptor","obfuscator" }); }, 0.35, {"build_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "writefile","createfilea","copyfilea" }) &&
               hasAnyString(d.strings, { "template","stub","payload","virus","worm" }); }, 0.30, {"virus_template"} },
        { [&] { return hasAnyString(d.strings, {
            "pe infector","file infector","prepend","appender","cavity",
            "entry point","ept_rewrite" }); }, 0.40, {"file_infection"} },
        { [&] { return hasAnyString(d.strings, {
            "mutation","polymorphic engine","metamorphic engine","garbage code","junk code" }); }, 0.35, {"mutation_engine"} }
    };
    constructor.variantSelector = [&] {
        if (hasAnyString(d.strings, { "vcl","virus construction lab" })) return string("VCL");
        if (hasAnyString(d.strings, { "vgen","virus generator" })) return string("VGEN");
        if (hasAnyString(d.strings, { "polymorphic","metamorphic" })) return string("MutationEngine");
        return string("Constructor");
    };

    return detectCategory({ miner, adware, hacktool, joke, constructor });
}

// ---------- Trojan ---------
inline HeuristicRulesEngine::RuleResult
HeuristicRulesEngine::detectTrojanClass(const AbstractPE& d) const {
    // 1. Infostealer (原有10条 +5)
    SubCategory infostealer;
    infostealer.name = "Infostealer";
    infostealer.rules = {
        // 原有 10 条
        { [&] { return hasAnyImport(d.imports, {
            "credreada","lsaopenpolicy","samconnect","samopendomain","credwritea","dpapi",
            "cryptunprotectdata","lsaretrieveprivatedata","netuserenum","netlocalgroupenum",
            "vaultcli","tokenmanipulation" }); }, 0.45, {"steals_credentials"} },
        { [&] { return hasAnyString(d.strings, {
            "cookies","passwords","web data","logindata","history",
            "chrome","firefox","opera","edge","brave","vault","credential",
            "\\google\\chrome\\user data\\","\\mozilla\\firefox\\profiles\\",
            "\\opera software\\","\\yandex\\","\\bravesoftware\\",
            "\\chromium\\","login data","key4.db","places.sqlite" }); }, 0.35, {"steals_browser_data"} },
        { [&] { return hasAnyString(d.strings, {
            "outlook","thunderbird","mail","smtp","pop3","imap",
            "incredimail","foxmail","mail.ru","mail" }); }, 0.18, {"steals_email"} },
        { [&] { return hasAnyString(d.strings, {
            "wallet.dat","metamask","trust wallet","electrum","exodus","coinbase",
            "binance","blockchain","wallet.json","keystore","ethereum\\keystore" }); }, 0.20, {"steals_crypto_wallets"} },
        { [&] { return hasAnyString(d.strings, {
            "discord","telegram","slack","skype","signal","wechat",
            "whatsapp","messenger","token","session" }); }, 0.15, {"steals_im_data"} },
        { [&] { return hasAnyImport(d.imports, {
            "getkeystate","getclipboarddata","openclipboard","sendinput",
            "setwindowshookexa","getasynckeystate" }); }, 0.15, {"input_capture"} },
        { [&] { return hasAnyImport(d.imports, {
            "send","wsasend","internetwritefile","winhttpsendrequest","ftp","url",
            "ftpputfilea","ftpputfilew","httpopenrequesta","httpopenrequestw" }); }, 0.12, {"exfiltrates_data"} },
        { [&] { return hasAnyImport(d.imports, {
            "getcomputernamea","getusernamea","getsysteminfo","netstatisticsget",
            "getadaptersinfo" }); }, 0.06, {"system_recon"} },
        { [&] { return hasAnyImport(d.imports, {
            "cryptencrypt","cryptexportkey" }); }, 0.05, {} },
        { [&] { return hasAnyString(d.strings, {
            "vbox","vmware","sandboxie","procmon","wireshark" }); }, 0.04, {"anti_sandbox"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "\\microsoft\\credentials\\","\\protect\\","ntlm" }); }, 0.12, {"steals_windows_creds"} },
            { [&] { return hasAnyImport(d.imports, {
                "dnsquery_a","getaddrinfo" }) && hasAnyString(d.strings, {"http"}); }, 0.10, {"data_exfiltration"} },
            { [&] { return hasAnyImport(d.imports, {
                "getbrowserextension" }) || hasAnyString(d.strings, {"browser extension","chrome extension"}); }, 0.08, {} },
            { [&] { return hasAnyString(d.strings, {
                "stealer","grabloader","infostealer" }); }, 0.20, {"infostealer_keyword"} },
            { [&] { return hasAnyImport(d.imports, {
                "internetconnecta","httpopenrequesta" }) && d.entry_entropy > 5.0; }, 0.10, {} }
    };
    infostealer.variantSelector = [&] {
        if (hasStringSubstr(d.strings, "cookies")) return string("CookieStealer");
        if (hasStringSubstr(d.strings, "password") || hasStringSubstr(d.strings, "credential"))
            return string("PasswordStealer");
        if (hasStringSubstr(d.strings, "wallet") || hasStringSubstr(d.strings, "metamask"))
            return string("WalletStealer");
        return string("GenericStealer");
        };

    // 2. Keylogger (原有7条 +5)
    SubCategory keylogger;
    keylogger.name = "Keylogger";
    keylogger.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "setwindowshookexa","setwindowshookexw","getkeystate","getasynckeystate",
            "getkeyboardstate","mapvirtualkeya","toascii","tounicode","registerhotkey",
            "unhookwindowshookex","callnexthookex" }); }, 0.50, {"keyboard_hook"} },
        { [&] { return hasAnyImport(d.imports, {
            "openclipboard","getclipboarddata","setclipboarddata","emptyclipboard" }); }, 0.25, {"clipboard_capture"} },
        { [&] { return hasAnyImport(d.imports, {
            "bitblt","getdc","getdesktopwindow" }); }, 0.10, {"screenshot"} },
        { [&] { return hasStringSubstr(d.strings, "keylog") || hasStringSubstr(d.strings, "hook") ||
               hasStringSubstr(d.strings, "keystroke"); }, 0.20,
               (hasStringSubstr(d.strings, "keylog") ? vector<string>{"keylog_string"} : vector<string>{}) },
        { [&] { return hasAnyString(d.strings, {
            "keylogger","keylog","keystroke","keydump","keysniffer" }); }, 0.10, {} },
        { [&] { return hasAnyImport(d.imports, {
            "send","connect","ftp","winhttpsendrequest","internetwritefile" }); }, 0.00, {"exfiltrates_logs"} },
        { [&] { return hasAnyImport(d.imports, {
            "isdebuggerpresent" }) || hasAnyString(d.strings, { "vbox","vmware" }); }, 0.04, {} },
            // 新增 5 条
            { [&] { return hasAnyImport(d.imports, {
                "getkeyboardlayoutnamea","mapvirtualkeyexa" }); }, 0.10, {"keyboard_layout"} },
            { [&] { return hasAnyString(d.strings, {
                "keylog.txt","keys.log","log.txt","keystrokes" }); }, 0.12, {"log_file"} },
            { [&] { return hasAnyImport(d.imports, {
                "createfilea","writefile" }) && (hasAnyImport(d.imports, {"setwindowshookexa"}) ||
                   hasAnyString(d.strings, {"keylog"})); }, 0.10, {} },
            { [&] { return hasAnyImport(d.imports, {
                "internetopena","internetconnecta" }) && hasAnyString(d.strings, {"keylogger"}); }, 0.08, {} },
            { [&] { return hasAnyImport(d.imports, {
                "getwindowtexta" }) && hasAnyImport(d.imports, {"setwindowshookexa"}); }, 0.05, {"title_logging"} }
    };
    keylogger.variantSelector = [&] {
        if (hasAnyImport(d.imports, { "setwindowshookexa" }) && hasAnyImport(d.imports, { "getclipboarddata" }))
            return string("KeylogAndClipboard");
        if (hasAnyImport(d.imports, { "setwindowshookexa" }))
            return string("GlobalHook");
        if (hasAnyImport(d.imports, { "getclipboarddata" }))
            return string("ClipboardLogger");
        return string("Keylogger");
        };

    // 3. Dropper (原有8条 +5)
    SubCategory dropper;
    dropper.name = "Dropper";
    dropper.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "findresourcea","loadresource","sizeofresource","lockresource" }); }, 0.25, {"uses_resources"} },
        { [&] { return hasAnyImport(d.imports, {
            "createfilea","writefile","closehandle","createprocessa",
            "winexec","shellexecutea","system","spawn","ntcreateprocess",
            "createprocesswithtokenw","createprocessasusera" }); }, 0.35, {"drops_and_executes"} },
        { [&] { return hasAnyImport(d.imports, {
            "urldownloadtofilea","internetopena","internetreadfile",
            "winhttpreaddata","winhttpsendrequest","urlmon",
            "bitsadmin","certutil" }); }, 0.30, {"downloads_payload"} },
        { [&] { return hasStringSubstr(d.strings, "http://") || hasStringSubstr(d.strings, "https://"); }, 0.10, {} },
        { [&] { return hasAnyString(d.strings, {
            ".exe",".dll",".sys",".vbs",".ps1",".bat",".tmp","%temp%",
            "appdata","temp" }); }, 0.12, {} },
        { [&] { return hasAnyImport(d.imports, {
            "virtualalloc","virtualallocex","createthread","ntcreatethreadex",
            "createremotethread","writeprocessmemory" }); }, 0.15, {"in_memory_exec"} },
        { [&] { return hasAnyString(d.strings, {
            "\\startup\\","\\run\\","hkey_current_user\\software\\microsoft\\windows\\currentversion\\run",
            "schtasks" }); }, 0.00, {"persistence"} },
        { [&] { return hasAnyImport(d.imports, {
            "isdebuggerpresent","sleep" }); }, 0.05, {"anti_sandbox"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "dropper","download and execute","payload","downloader" }); }, 0.20, {"dropper_keywords"} },
            { [&] { return d.entry_entropy > 7.0 && hasAnyImport(d.imports, {"virtualalloc"}); }, 0.15, {"packed_or_encrypted"} },
            { [&] { return hasAnyImport(d.imports, {
                "certutil" }) || hasAnyString(d.strings, {"-urlcache -split"}); }, 0.10, {"certutil_download"} },
            { [&] { return hasAnyImport(d.imports, {
                "cryptdecodeobject" }) && hasAnyImport(d.imports, {"virtualalloc"}); }, 0.08, {} },
            { [&] { return hasAnyString(d.strings, {
                "rundll32.exe","regsvr32.exe","msiexec.exe" }); }, 0.05, {} }
    };
    dropper.variantSelector = [&] {
        if (hasAnyImport(d.imports, { "virtualalloc","createthread" }) &&
            !hasAnyImport(d.imports, { "createfilea","writefile" }))
            return string("FilelessDropper");
        if (hasStringSubstr(d.strings, "download") || hasStringSubstr(d.strings, "http"))
            return string("TrojanDownloader");
        if (hasAnyImport(d.imports, { "findresourcea" }))
            return string("TrojanDropper");
        return string("Dropper");
        };

    // 4. Banker (原有7条 +5)
    SubCategory banker;
    banker.name = "Banker";
    banker.rules = {
        { [&] { return hasAnyString(d.strings, {
            "bank","online banking","hsbc","barclays","chase","wellsfargo",
            "credit union","iban","swift","account number","login","password",
            "citibank","banamex","santander","bbva","caixabank","ing",
            "paypal","stripe","visa","mastercard","amex","payment",
            "webmoney","qiwi","yoomoney","paysafecard" }); }, 0.50, {"banking_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "setwindowshookexa","createremotethread","ntcreateprocess",
            "ntunmapviewofsection","virtualallocex","writeprocessmemory" }); }, 0.25, {"browser_injection"} },
        { [&] { return hasAnyImport(d.imports, { "send","recv","connect" }); }, 0.10, {} },
        { [&] { return hasAnyImport(d.imports, {
            "wsaioctl","setsockopt","internetqueryoptiona","internetsetoptiona" }); }, 0.08, {"mitm_proxy"} },
        { [&] { return hasAnyImport(d.imports, {
            "getkeystate","getasynckeystate","setwindowshookexa" }); }, 0.10, {"keylogger"} },
        { [&] { return hasAnyImport(d.imports, {
            "certopenstore","certfindcertificateinstore","pfximportcertstore" }); }, 0.10, {"steal_certificates"} },
        { [&] { return hasAnyString(d.strings, {
            "vbox","vmware","sandboxie","wireshark" }); }, 0.05, {"anti_sandbox"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "banking","banking trojan","zeus","tinba","dridex","ursnif" }); }, 0.25, {"banking_trojan_keywords"} },
            { [&] { return hasAnyImport(d.imports, {
                "httpsetsecurelockicon" }); }, 0.05, {} },
            { [&] { return hasAnyImport(d.imports, {
                "httpsendrequesta" }) && hasAnyString(d.strings, {"bank"}); }, 0.12, {} },
            { [&] { return hasAnyImport(d.imports, {
                "getclipboarddata" }); }, 0.05, {"clipboard_monitor"} },
            { [&] { return hasAnyImport(d.imports, {
                "adjusttokenprivileges" }); }, 0.05, {} }
    };
    banker.variantSelector = [] { return string("BankingTrojan"); };

    // 5. Spyware (原有7条 +5)
    SubCategory spyware;
    spyware.name = "Spyware";
    spyware.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "bitblt","getdc","getdesktopwindow","capcreatecapturewindow","printwindow",
            "createdibsection","getdibits" }); }, 0.40, {"screenshot_capture"} },
        { [&] { return hasAnyImport(d.imports, {
            "waveinopen","waveinstart","acmstreamopen","mcistring","record",
            "mixeropen","mixerclose" }); }, 0.25, {"audio_capture"} },
        { [&] { return hasAnyImport(d.imports, {
            "setwindowshookexa","getkeystate","getasynckeystate" }); }, 0.20, {"keylogger"} },
        { [&] { return hasAnyString(d.strings, {
            "webcam","camera","video capture","capcreatecapturewindow",
            "vfw","capdriverconnect","capgetstatus" }) ||
               hasAnyImport(d.imports, { "capcreatecapturewindowa","capdriverconnect" }); }, 0.15, {"webcam_capture"} },
        { [&] { return hasAnyImport(d.imports, { "gpsopen","gpsgetposition" }) ||
               hasAnyString(d.strings, { "gps","location","latitude","longitude" }); }, 0.05, {"location_tracking"} },
        { [&] { return hasAnyImport(d.imports, {
            "send","connect","socket","internetwritefile","winhttpsendrequest" }); }, 0.00, {"data_exfiltration"} },
        { [&] { return hasAnyString(d.strings, {
            "history","cookies","passwords","web data","logindata" }); }, 0.05, {"steals_browser_data"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "spyware","spy","monitor","surveillance" }); }, 0.20, {"spyware_keywords"} },
            { [&] { return hasAnyImport(d.imports, {
                "callwindowproca" }) && hasAnyImport(d.imports, {"setwindowshookexa"}); }, 0.10, {"message_hook"} },
            { [&] { return hasAnyImport(d.imports, {
                "getcursorpos" }); }, 0.05, {"cursor_tracking"} },
            { [&] { return hasAnyImport(d.imports, {
                "printwindow" }); }, 0.08, {} },
            { [&] { return hasAnyString(d.strings, {
                "file stealer","steal files" }); }, 0.10, {} }
    };
    spyware.variantSelector = [] { return string("Monitoring"); };

    // 6. RAT (原有8条 +5)
    SubCategory rat;
    rat.name = "RAT";
    rat.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "bitblt","getdc","sendinput","mouse_event","keybd_event","getdesktopwindow",
            "createcompatibledc","stretchblt","getdibits","createdibsection",
            "setcursorpos","getcursorpos" }); }, 0.40, {"remote_desktop"} },
        { [&] { return hasAnyImport(d.imports, {
            "socket","connect","bind","listen","send","recv","wsastartup" }); }, 0.30, {"network"} },
        { [&] { return hasAnyImport(d.imports, {
            "regsetvalueexa","schtasks","sheval","createprocessa" }) ||
               hasAnyString(d.strings, {
            "\\startup\\","\\run\\","hkey_local_machine","hkey_current_user","schtasks" }); }, 0.05, {"persistence"} },
        { [&] { return hasAnyImport(d.imports, {
            "createprocessa","winexec","shellexecutea","system" }); }, 0.10, {"remote_exec"} },
        { [&] { return hasAnyImport(d.imports, {
            "createfilea","readfile","writefile","findfirstfilea","deletefilea" }); }, 0.05, {"file_manager"} },
        { [&] { return hasAnyImport(d.imports, {
            "getasynckeystate","setwindowshookexa" }); }, 0.10, {"keylogger"} },
        { [&] { return hasAnyString(d.strings, {
            "poison ivy","darkcomet","njrat","gh0st","quasarrat","asyncrat",
            "nanocore","orcusrat","remcos" }); }, 0.15, {"known_rat"} },
        { [&] { return hasStringSubstr(d.strings, "remote"); }, 0.05, {} },
        // 新增 5 条
        { [&] { return hasAnyString(d.strings, {
            "rat","remote access","remote admin","trojan.rat" }); }, 0.20, {"rat_keywords"} },
        { [&] { return hasAnyImport(d.imports, {
            "virtualallocex","writeprocessmemory","createremotethread" }); }, 0.10, {"injection"} },
        { [&] { return hasAnyImport(d.imports, {
            "gettcpipstatistics" }); }, 0.05, {} },
        { [&] { return hasAnyImport(d.imports, {
            "listen" }) && d.entry_entropy > 6.0; }, 0.08, {} },
        { [&] { return hasAnyString(d.strings, {
            "uninstall","persistence","restart" }); }, 0.05, {} }
    };
    rat.variantSelector = [] { return string("RemoteControl"); };

    // 7. Clicker (原有5条 +5)
    SubCategory clicker;
    clicker.name = "Clicker";
    clicker.rules = {
        { [&] { return hasAnyString(d.strings, {
            "click","adclick","imitation","simulate","automated","http://",
            "useragent","navigator","getelementbyid","onclick",
            "popunder","cpa","affiliate","iframes","adnetwork",
            "webbrowser","mshtml","navigate2" }); }, 0.45, {"click_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "internetopena","internetconnecta","internetreadfile","winhttpopen","winhttpconnect" }); }, 0.30, {"http_requests"} },
        { [&] { return hasAnyImport(d.imports, {
            "mouse_event","sendinput","setcursorpos","keybd_event" }); }, 0.25, {"simulate_input"} },
        { [&] { return hasAnyImport(d.imports, {
            "showwindow","setwindowpos","setwindowlonga","getconsolewindow" }); }, 0.08, {"hide_window"} },
        { [&] { return hasAnyString(d.strings, {
            "proxy","vpn","tor","socks5","socks4" }); }, 0.05, {"anonymize"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "clickfraud","clickbot","adclicker","autoclicker" }); }, 0.20, {"clicker_keywords"} },
            { [&] { return hasAnyImport(d.imports, {
                "getmessageextrainfo" }); }, 0.05, {} },
            { [&] { return hasAnyImport(d.imports, {
                "internetsetstatuscallback" }); }, 0.05, {} },
            { [&] { return hasAnyString(d.strings, {
                "referer","x-forwarded-for" }); }, 0.10, {"spoof_headers"} },
            { [&] { return hasAnyImport(d.imports, {
                "httpsendrequesta" }) && hasAnyString(d.strings, {"click"}); }, 0.10, {} }
    };
    clicker.variantSelector = [] { return string("ClickFraud"); };

    // 8. Rootkit (原有7条 +5)
    SubCategory rootkit;
    rootkit.name = "Rootkit";
    rootkit.rules = {
        { [&] { return hasAnyImport(d.dlls, {
            "ntoskrnl.exe","hal.dll","win32k.sys","bootvid.dll" }); }, 0.35, {"kernel_modules"} },
        { [&] { return hasAnyImport(d.imports, {
            "zwopenprocess","zwqueryinformationprocess","pslookupprocessbyprocessid",
            "ioattachdevice","iocreatedevice","ntloaddriver","zwloaddriver",
            "zwquerysysteminformation","zwsetinformationprocess","obregistercallbacks",
            "pssetcreateprocessnotifyroutine","iocompleterequest","iosetsystemroution" }); }, 0.40, {"kernel_api"} },
        { [&] { return hasStringSubstr(d.strings, "rootkit") || hasStringSubstr(d.strings, "hide"); }, 0.25, {} },
        { [&] { return hasAnyImport(d.imports, {
            "deviceiocontrol","createfilea" }); }, 0.10, {"driver_load"} },
        { [&] { return hasStringSubstr(d.strings, "ssdt") || hasStringSubstr(d.strings, "nt!ki") ||
               hasStringSubstr(d.strings, "hal!hal") || hasStringSubstr(d.strings, "idt"); }, 0.15, {"kernel_hooking"} },
        { [&] { return hasAnyString(d.strings, {
            "eprocess","ethread","tokendynamic","activeprocesslinks","pspcidtable" }); }, 0.10, {"dkom"} },
        { [&] { return hasAnyImport(d.imports, {
            "isdebuggerpresent","ntqueryinformationprocess" }); }, 0.05, {"anti_debug"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "kernelmode","ring0","dkst" }); }, 0.15, {"rootkit_keywords"} },
            { [&] { return hasAnyImport(d.imports, {
                "zwcreatethread" }); }, 0.10, {} },
            { [&] { return hasAnyImport(d.imports, {
                "ioattachdevicetodevicestack","iogetbasefilesystemdeviceobject" }); }, 0.15, {"fs_filter"} },
            { [&] { return hasAnyString(d.strings, {
                "null.sys","beep.sys" }); }, 0.05, {} },
            { [&] { return hasAnyImport(d.imports, {
                "zwopensection","zwmapviewofsection" }); }, 0.10, {} }
    };
    rootkit.variantSelector = [] { return string("Rootkit"); };

    // 9. Exploit (原有5条 +5)
    SubCategory exploit;
    exploit.name = "Exploit";
    exploit.rules = {
        { [&] { return hasAnyString(d.strings, {
            "ms08-067","ms17-010","cve-","exploit","shellcode",
            "rop","gadget","jmp esp","push esp","call eax","nop sled",
            "eternalblue","doublepulsar","bluekeep","log4j","spring4shell",
            "heap spray","use-after-free","type confusion" }); }, 0.50, {"exploit_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "virtualprotect","virtualallocex","writeprocessmemory","createprocessa",
            "ntallocatevirtualmemory","ntprotectvirtualmemory","readprocessmemory" }); }, 0.30, {"memory_manipulation"} },
        { [&] { return hasAnyImport(d.dlls, {
            "mshtml.dll","iexplore.exe","flash.ocx","java.exe","acrord32.exe",
            "office","winword.exe","excel.exe","powerpnt.exe","outlook.exe",
            "vmware-vmx.exe" }); }, 0.20, {} },
        { [&] { return hasAnyImport(d.imports, {
            "rtlallocateheap","heapcreate","heapfree","rtlcreateheap" }); }, 0.08, {} },
        { [&] { return hasAnyString(d.strings, {
            "metasploit","core impact","canvas","veil","empire",
            "cobalt strike","powersploit" }); }, 0.15, {"pentest_tool"} },
            // 新增 5 条
            { [&] { return hasAnyString(d.strings, {
                "vulnerability","overflow","shell","bypass" }); }, 0.15, {"exploit_keywords"} },
            { [&] { return hasAnyImport(d.imports, {
                "createtoolhelp32snapshot","process32first" }); }, 0.05, {} },
            { [&] { return hasAnyString(d.strings, {
                "\\\\pipe\\","\\\\.\\pipe\\" }); }, 0.10, {"named_pipe"} },
            { [&] { return hasAnyImport(d.imports, {
                "writeprocessmemory" }) && d.entry_entropy > 7.0; }, 0.15, {} },
            { [&] { return hasAnyString(d.strings, {
                "msfvenom","scdbg","exploit-db" }); }, 0.10, {} }
    };
    exploit.variantSelector = [] { return string("Vulnerability"); };

    // 10. Loader (原有7条 +5)
    SubCategory loader;
    loader.name = "Loader";
    loader.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "virtualallocex","virtualprotect","writeprocessmemory","createremotethread",
            "ntunmapviewofsection","loadlibrarya","getprocaddress","ntcreateprocess",
            "resumethread","setthreadcontext","readprocessmemory" }); }, 0.40, {"loader_api"} },
            // 修正：解密/解压缩字符串检查从 imports 移至 strings
            { [&] { return hasAnyString(d.strings, {
                "aes","rc4","xor","base64" }); }, 0.10, {"decrypt_decompress"} },
            { [&] { return hasAnyString(d.strings, {
                "rtldecompressbuffer","cryptdecodeobject","lzss_decompress","systemfunction033" }); }, 0.20, {"decompress_api"} },
            { [&] { return hasStringSubstr(d.strings, "reflectiveloader") ||
                   hasStringSubstr(d.strings, "pe loader") ||
                   hasStringSubstr(d.strings, "donut") || hasStringSubstr(d.strings, "sgn"); }, 0.20, {"loader_string"} },
            { [&] { return d.entry_entropy > 6.5; }, 0.25, {"high_entropy_ep"} },
            { [&] { return d.entry_entropy > 5.5; }, 0.10, {} },
            { [&] { return hasAnyImport(d.imports, {
                "isdebuggerpresent","ntqueryinformationprocess","sleep" }); }, 0.08, {"anti_analysis"} },
                // 新增 5 条
                { [&] { return hasAnyString(d.strings, {
                    "loader","loadlibraryexw","nt!rtlinitunicodestring" }); }, 0.15, {"loader_keywords"} },
                { [&] { return hasAnyImport(d.imports, {
                    "ntflushinstructioncache" }); }, 0.05, {} },
                { [&] { return d.entry_entropy > 7.0 && hasAnyImport(d.imports, {"getprocaddress"}); }, 0.20, {"suspicious_ep"} },
                { [&] { return hasAnyImport(d.imports, {
                    "getmodulehandlea","getprocaddress" }) && hasAnyString(d.strings, {"xor","base64"}); }, 0.10, {} },
                { [&] { return hasAnyString(d.strings, {
                    "hollow","processhollow","runpe" }); }, 0.15, {} }
    };
    loader.variantSelector = [&] {
        if (hasStringSubstr(d.strings, "reflectiveloader")) return string("ReflectiveDLL");
        if (hasAnyImport(d.imports, { "ntunmapviewofsection" })) return string("ProcessHollowing");
        if (hasStringSubstr(d.strings, "donut") || hasStringSubstr(d.strings, "sgn")) return string("ShellcodeLoader");
        return string("Loader");
        };

    // 11. MalwareFamily (新增)
    SubCategory malwareFamily;
    malwareFamily.name = "MalwareFamily";
    malwareFamily.rules = {
        { [&] { return hasAnyString(d.strings, {"silverfox","silver fox"}); }, 0.60, {"silverfox"} },
        { [&] { return hasAnyString(d.strings, {"agenttesla","agent tesla","agent"}); }, 0.55, {"agenttesla"} },
        { [&] { return hasAnyString(d.strings, {"diskwriter","disk writer"}); }, 0.50, {"diskwriter"} },
        { [&] { return hasAnyString(d.strings, {"redline","redline stealer"}); }, 0.55, {"redline"} },
        { [&] { return hasAnyString(d.strings, {"vidar"}); }, 0.55, {"vidar"} },
        { [&] { return hasAnyString(d.strings, {"danabot"}); }, 0.55, {"danabot"} },
        { [&] { return hasAnyString(d.strings, {"ave maria","avemaria"}); }, 0.55, {"avemaria"} },
        { [&] { return hasAnyString(d.strings, {"njrat","nj rat"}); }, 0.55, {"njrat"} },
        { [&] { return hasAnyString(d.strings, {"asyncrat","async rat"}); }, 0.55, {"asyncrat"} },
        { [&] { return hasAnyString(d.strings, {"remcos"}); }, 0.55, {"remcos"} },
        { [&] { return hasAnyString(d.strings, {"orcus","orcusrat"}); }, 0.55, {"orcus"} },
        { [&] { return hasAnyString(d.strings, {"netwire","netwire rat"}); }, 0.55, {"netwire"} },
        { [&] { return hasAnyString(d.strings, {"warzone","warzone rat"}); }, 0.55, {"warzone"} },
        { [&] { return hasAnyString(d.strings, {"smokeloader","smoke loader"}); }, 0.50, {"smokeloader"} },
        { [&] { return hasAnyString(d.strings, {"gozi","gozi isfb"}); }, 0.55, {"gozi"} },
        { [&] { return hasAnyString(d.strings, {"trickbot","trick bot"}); }, 0.55, {"trickbot"} },
        { [&] { return hasAnyString(d.strings, {"icedid","ice id"}); }, 0.55, {"icedid"} },
        { [&] { return hasAnyString(d.strings, {"qakbot","qbot"}); }, 0.55, {"qakbot"} },
        { [&] { return hasAnyString(d.strings, {"lockbit","lock bit"}); }, 0.50, {"lockbit"} },
        // 补充通用规则
        { [&] { return hasAnyString(d.strings, {"stealer","trojan","bot","rat"}); }, 0.20, {} }
    };
    malwareFamily.variantSelector = [&] {
        if (hasAnyString(d.strings, { "silverfox" })) return string("SilverFox");
        if (hasAnyString(d.strings, { "agenttesla","agent tesla" })) return string("AgentTesla");
        if (hasAnyString(d.strings, { "diskwriter" })) return string("DiskWriter");
        if (hasAnyString(d.strings, { "redline" })) return string("RedLine");
        if (hasAnyString(d.strings, { "vidar" })) return string("Vidar");
        if (hasAnyString(d.strings, { "danabot" })) return string("Danabot");
        if (hasAnyString(d.strings, { "avemaria" })) return string("AveMaria");
        if (hasAnyString(d.strings, { "njrat" })) return string("NjRat");
        if (hasAnyString(d.strings, { "asyncrat" })) return string("AsyncRat");
        if (hasAnyString(d.strings, { "remcos" })) return string("Remcos");
        if (hasAnyString(d.strings, { "orcus" })) return string("Orcus");
        return string("KnownMalware");
        };

    // 12. Wiper — 数据擦除/破坏（不加密、不索赎金，直接删除/覆写）
    SubCategory wiper;
    wiper.name = "Wiper";
    wiper.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "deletefilea","deletefilew","removefile","unlink" }) &&
               hasAnyString(d.strings, { "*.*","\\windows\\","\\system32\\" }); }, 0.45, {"mass_delete"} },
        { [&] { return hasAnyImport(d.imports, {
            "writefile","createfilea","deviceiocontrol","ioctl_disk_set_drive_layout",
            "fsctl_lock_volume" }) &&
               hasAnyString(d.strings, { "\\device\\harddisk","physicaldrive","\\\\.\\physicaldrive" }); }, 0.55, {"raw_disk_write"} },
        { [&] { return hasAnyString(d.strings, {
            "wipe","erase","overwrite","destroy","format","fdisk","mbr","partition" }); }, 0.35, {"wipe_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "movefilea","movefilew" }) &&
               hasStringSubstr(d.strings, "recycle") &&
               !hasAnyString(d.strings, { "ransom","decrypt","bitcoin","your files" }); }, 0.25, {"no_ransom_wipe"} },
        { [&] { return hasAnyImport(d.imports, {
            "setfilepointer","writefile" }) &&
               hasAnyString(d.strings, { "0xff","0x00","fill" }); }, 0.20, {"overwrite_pattern"} },
        { [&] { return hasAnyImport(d.imports, {
            "fsctldismountvolume","fsctl_lock_volume","fsctl_unlock_volume" }); }, 0.30, {"volume_dismount"} }
    };
    wiper.variantSelector = [&] {
        if (hasAnyString(d.strings, { "mbr","partition","boot sector" })) return string("BootWiper");
        if (hasAnyString(d.strings, { "format","fdisk" })) return string("DiskFormat");
        return string("FileWiper");
    };

    // 13. Bootkit — 引导区恶意软件（MBR/VBR 修改，raw disk access）
    SubCategory bootkit;
    bootkit.name = "Bootkit";
    bootkit.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "createfilea","deviceiocontrol","writefile" }) &&
               hasAnyString(d.strings, { "\\\\.\\physicaldrive","\\device\\harddisk","mbr","vbr","boot sector" }); }, 0.55, {"raw_disk_access"} },
        { [&] { return hasAnyImport(d.imports, {
            "setfilepointer","writefile" }) &&
               hasAnyString(d.strings, { "0x1be","partition table","bootmgr","winload" }); }, 0.45, {"mbr_write"} },
        { [&] { return hasAnyString(d.strings, {
            "ntldr","boot.ini","bcdedit","bootmgr","winload.exe" }); }, 0.35, {"boot_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "fsctldismountvolume","fsctl_lock_volume" }); }, 0.30, {"volume_lock"} },
        { [&] { return hasAnyString(d.strings, {
            "fixmbr","restore mbr","master boot record" }); }, 0.25, {"mbr_strings"} }
    };
    bootkit.variantSelector = [&] {
        if (hasAnyString(d.strings, { "mbr","master boot record" })) return string("MBRModifier");
        if (hasAnyString(d.strings, { "vbr","volume boot record" })) return string("VBRModifier");
        return string("Bootkit");
    };

    // 14. Proxy — 代理木马（SOCKS/HTTP 中继，用于隐藏攻击者来源）
    SubCategory proxy;
    proxy.name = "Proxy";
    proxy.rules = {
        { [&] { return hasAnyString(d.strings, {
            "socks4","socks5","socks","proxy","connect","relay","tunnel" }); }, 0.45, {"proxy_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "wsastartup","socket","bind","listen","accept","recv","send",
            "wsaeventselect","select" }); }, 0.35, {"network_server"} },
        { [&] { return hasAnyImport(d.imports, {
            "wsaconnect","connect","gethostbyname","getaddrinfo" }) &&
               hasAnyImport(d.imports, { "bind","listen","accept" }); }, 0.40, {"relay_chain"} },
        { [&] { return hasAnyString(d.strings, {
            "http proxy","https proxy","connect method","proxychain" }); }, 0.30, {"http_proxy"} },
        { [&] { return hasAnyString(d.strings, {
            "forward","redirect","pipe","tunnel_data" }); }, 0.15, {"relay_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "internetconnecta","internetopena","httptp_send_requesta" }); }, 0.10, {} }
    };
    proxy.variantSelector = [&] {
        if (hasAnyString(d.strings, { "socks4","socks5" })) return string("SocksProxy");
        if (hasAnyString(d.strings, { "http proxy","https proxy" })) return string("HttpProxy");
        return string("GenericProxy");
    };

    // 15. DDoSAgent — DDoS 攻击代理（SYN flood, UDP flood, HTTP flood）
    SubCategory ddos;
    ddos.name = "DDoSAgent";
    ddos.rules = {
        { [&] { return hasAnyImport(d.imports, {
            "wsastartup","socket","sendto","wsasendto" }) &&
               hasAnyString(d.strings, { "flood","syn","udp","icmp","dos","ddos" }); }, 0.50, {"flood_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "socket","connect","send","wsasend" }) &&
               hasAnyString(d.strings, { "bot","zombie","slave","command","ddos" }); }, 0.40, {"botnet_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "sendto","wsasendto","setsockopt" }) &&
               hasStringSubstr(d.strings, "raw") && hasStringSubstr(d.strings, "socket"); }, 0.35, {"raw_socket"} },
        { [&] { return hasAnyString(d.strings, {
            "syn flood","udp flood","http flood","slowloris","dns amplification" }); }, 0.45, {"ddos_technique"} },
        { [&] { return hasAnyImport(d.imports, {
            "wsaasyncselect","wsaeventselect" }) &&
               hasAnyString(d.strings, { "attack","target","victim","c2" }); }, 0.25, {"c2_strings"} }
    };
    ddos.variantSelector = [&] {
        if (hasAnyString(d.strings, { "syn flood" })) return string("SYNFlood");
        if (hasAnyString(d.strings, { "udp flood" })) return string("UDPFlood");
        if (hasAnyString(d.strings, { "http flood","slowloris" })) return string("HTTPFlood");
        return string("DDoSBot");
    };

    // 16. Crypter — 加壳器/加密器（UPX, 自定义打包器，高熵段）
    SubCategory crypter;
    crypter.name = "Crypter";
    crypter.rules = {
        { [&] { return d.entry_entropy > 7.2 && d.has_overlay; }, 0.40, {"high_entropy_overlay"} },
        { [&] { return d.entry_entropy > 7.5; }, 0.35, {"high_entropy"} },
        { [&] { return hasAnyString(d.strings, {
            "upx","upx1","upx2","mpress","aspack","petite","themida","vmprotect",
            "enigma","armadillo","yodaprotect" }); }, 0.50, {"known_packer"} },
        { [&] { return hasAnyString(d.section_names, {
            ".upx0",".upx1",".aspack",".adata","mpress1","mpress2",
            ".themida",".vmp0",".vmp1",".enigma1" }); }, 0.55, {"packer_section"} },
        { [&] { return hasAnyImport(d.imports, {
            "virtualalloc","virtualprotect","writeprocessmemory","createprocessa" }) &&
               d.entry_entropy > 6.5; }, 0.30, {"self_unpacking"} },
        { [&] { return hasAnyString(d.strings, {
            "unpack","decompress","decrypt","payload","stub" }); }, 0.20, {"unpack_strings"} }
    };
    crypter.variantSelector = [&] {
        if (hasAnyString(d.strings, { "upx","upx1" }) || hasAnyString(d.section_names, { ".upx0",".upx1" }))
            return string("UPX");
        if (hasAnyString(d.strings, { "themida","vmprotect" })) return string("VMProtect");
        if (hasAnyString(d.strings, { "mpress" })) return string("MPRESS");
        if (hasAnyString(d.strings, { "aspack" })) return string("ASPack");
        return string("GenericCrypter");
    };

    // 17. Bancos — 银行木马（巴西变种，网页截图/表单劫持）
    SubCategory bancos;
    bancos.name = "Bancos";
    bancos.rules = {
        { [&] { return hasAnyString(d.strings, {
            "banco","bradesco","itau","caixa","santander","hsbc","banc","internetbanking" }); }, 0.55, {"bancos_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "sendmessagea","findwindowa","enumwindows","enumchildwindows" }) &&
               hasAnyString(d.strings, { "banco","bank","login","password" }); }, 0.40, {"window_injection"} },
        { [&] { return hasAnyImport(d.imports, {
            "internetconnecta","internetopena","httptp_send_requesta","internetreadfile" }) &&
               hasAnyString(d.strings, { "banco","bank" }); }, 0.35, {"banking_http"} },
        { [&] { return hasAnyString(d.strings, {
            ".br","brazil","brasil","formulario","captura","tela" }); }, 0.30, {"brazil_strings"} },
        { [&] { return hasAnyImport(d.imports, {
            "bitblt","createdibsection","getdibits" }) &&
               hasAnyString(d.strings, { "banco","bank","screenshot" }); }, 0.25, {"screen_capture"} }
    };
    bancos.variantSelector = [&] {
        if (hasAnyString(d.strings, { "banco","bradesco","itau","caixa" })) return string("Bancos");
        return string("BankPhish");
    };

    // 所有子类别汇总
    return detectCategory({
        infostealer, keylogger, dropper, banker, spyware,
        rat, clicker, rootkit, exploit, loader, malwareFamily,
        wiper, bootkit, proxy, ddos, crypter, bancos
        });
}

// ======================== LightGBM 分类器（双模型加权）========================
class LightGBMClassifier {
private:
    BoosterHandle base_booster_ = nullptr;     // 基础600维模型
    BoosterHandle extra_booster_ = nullptr;    // 额外维度模型
    bool base_trained_ = false;
    bool extra_trained_ = false;
    int base_num_features_ = BASE_FEATURE_DIM;
    int extra_num_features_ = 0;
    double base_weight_ = BASE_MODEL_WEIGHT;
    double extra_weight_ = EXTRA_MODEL_WEIGHT;

    std::vector<std::string> base_feature_names_;
    std::vector<std::string> extra_feature_names_;

    bool dynamic_features_enabled_ = false;
    int max_extra_features_ = 0;
    std::string custom_booster_params_;

    // 获取基础特征中已覆盖的所有 API 名称（避免动态特征重复）
    static const std::set<std::string>& getCoveredAPIs() {
        static std::set<std::string> covered;
        if (covered.empty()) {
            // 第4部分：25个API类别中涉及的所有具体函数（完整）
            std::vector<std::string> apiCatFunctions = {
                // ProcessControl
                "createprocessa","createprocessw","winexec","shellexecutea","shellexecutew",
                "terminateprocess","openprocess",
                // Injection
                "virtualallocex","virtualprotectex","writeprocessmemory","createremotethread",
                "queueuserapc","setthreadcontext","ntunmapviewofsection",
                // Synchronization
                "waitforsingleobject","createmutexa","createeventa","entercriticalsection","sleep",
                // MultiThreading
                "createthread","resumethread","exitthread","terminatethread",
                // Network
                "socket","connect","send","recv","wsastartup","internetopena","internetconnecta",
                "urldownloadtofilea",
                // Encryption
                "cryptacquirecontexta","cryptcreatehash","cryptencrypt","cryptdecrypt",
                // DataObfuscation
                "rtldecompressbuffer","multibytetowidechar","base64decode","cryptdecodeobject",
                // FileIO
                "createfilea","writefile","readfile","deletefilea","copyfilea","setfileattributesa",
                "deviceiocontrol",
                // Registry
                "regopenkeyexa","regsetvalueexa","regcreatekeyexa","regdeletekeya","regqueryvalueexa",
                // Services
                "openscmanagera","createservicea","startservicea","controlservice","deleteservice",
                // Privileges
                "adjusttokenprivileges","lookupprivilegevaluea","openprocesstoken","netuseradd",
                // Native
                "rtlunwind","rtlallocateheap","ntclose","getsystemtimeasfiletime","getversionexa",
                "getcomputernamea",
                // DotNet
                "_corexemain","_cordllmain",
                // AntiDebug
                "isdebuggerpresent","checkremotedebuggerpresent","outputdebugstringa","gettickcount",
                "findwindowa","isprocessorfeaturepresent",
                // Keylogging
                "getasynckeystate","getkeystate","getkeyboardstate","mapvirtualkeya","toascii",
                "setwindowshookexa",
                // Input
                "getcursorpos","setcursorpos","mouseevent","getcapture",
                // ScreenCapture
                "bitblt","getdc","createcompatibledc","getdesktopwindow",
                // Graphics
                "direct3dcreate9","d3d11createdevice",
                // Audio
                "waveinopen","waveinclose","waveinstart","waveinstop",
                // Clipboard
                "openclipboard","closeclipboard","getclipboarddata","setclipboarddata",
                // Camera
                "capcreatecapturewindowa","capcreatecapturewindoww",
                // Memory
                "heapalloc","heapfree","getprocessheap","localalloc","globalalloc",
                // Resource
                "loadresource","sizeofresource","lockresource","findresourcea",
                // WindowControl
                "showwindow","destroywindow","translatemessage","dispatchmessagea","createwindowexa",
                // COM
                "cocreateinstance","coinitialize","couninitialize"
            };
            covered.insert(apiCatFunctions.begin(), apiCatFunctions.end());

            // 第5部分：200个高危API（完整列表）
            static const std::vector<std::string> highRisk = {
                "createprocessa","winexec","shellexecutea","virtualallocex","writeprocessmemory","createremotethread",
                "loadlibrarya","getprocaddress","socket","connect","recv","send","cryptencrypt","cryptdecrypt",
                "regsetvalueexa","createservicea","startservicea","adjusttokenprivileges","isdebuggerpresent",
                "getasynckeystate","setwindowshookexa","bitblt","internetopena","urldownloadtofilea",
                "createfilea","writefile","deletefilea","deviceiocontrol","openclipboard",
                "getdc","createcompatibledc","rtldecompressbuffer","cryptdecodeobject","ntunmapviewofsection",
                "queueuserapc","setthreadcontext","resumethread","terminatethread","openprocesstoken",
                "lookupprivilegevaluea","netuseradd","controlservice","regdeletekeya","regcreatekeyexa",
                "cocreateinstance","virtualprotectex","readprocessmemory","gettickcount","findwindowa",
                "getkeyboardstate","mapvirtualkeya","toascii","waveinopen","capcreatecapturewindowa",
                "d3d11createdevice","direct3dcreate9","heapalloc","loadresource","findresourcea",
                "showwindow","createwindowexa","translatemessage","dispatchmessagea","_corexemain",
                "createthread","openscmanagera","regopenkeyexa","copyfilea","movefilea",
                "gettemppatha","setfileattributesa","connectnamedpipe","peeknamedpipe",
                "regenumvaluea","regqueryvalueexa","deleteservice","startservicea",
                "netlocalgroupaddmembers","isadmin","getusernamea","rtlunwind","ntclose",
                "getversionexa","getcomputernamea","getlasterror","raiseexception","setlasterror",
                "outputdebugstringa","checkremotedebuggerpresent","enumwindows","getwindowrect",
                "setwindowdisplayaffinity","unhandledexceptionfilter","setunhandledexceptionfilter",
                "gettimezoneinformation","getdrivetypew","getdiskfreespacea","getkeystate",
                "tounicode","getkeynametexta","getforegroundwindow","sendinput",
                "getcursorpos","setcursorpos","mouseevent","stretchblt","getwindowdc",
                "printwindow","getdesktopwindow","waveinclose","waveinstart",
                "closeclipboard","getclipboarddata","setclipboarddata",
                "globalalloc","globalfree","localalloc","localfree","heapfree",
                "lockresource","freeresource","destroywindow","getactivewindow",
                "defwindowproca","getmessagea","registerclassa","messageboxa",
                "couninitialize","internetconnecta","httpopenrequesta","httpsendrequesta",
                "internetreadfile","dnsquery_a","cryptacquirecontexta","cryptcreatehash",
                "crypthashdata","cryptderivekey","cryptdestroykey","cryptdestroyhash",
                "cryptreleasecontext","cryptgenkey","cryptimportkey","cryptexportkey",
                "multibytetowidechar","widechartomultibyte","isdbcsleadbyte","charuppera","charlowera",
                "getstringtypew","decodepointer","encodepointer","getsysteminfo","comparestringa"
            };
            covered.insert(highRisk.begin(), highRisk.end());
        }
        return covered;
    }

    // 构建额外维度特征（纯one-hot，简单标记存在性）
    std::vector<float> buildExtraFeatures(const RawSample& sample) const {
        if (extra_feature_names_.empty()) return {};

        std::vector<float> feat(extra_num_features_, 0.0f); // 初始化为0
        for (size_t i = 0; i < extra_feature_names_.size(); ++i) {
            const std::string& efname = extra_feature_names_[i];
            if (efname.rfind("api_ext:", 0) == 0) {
                std::string func = efname.substr(8);
                feat[i] = (sample.imports.find(func) != sample.imports.end()) ? 1.0f : 0.0f;
            }
            // 其他类型占位，目前无
        }
        return feat;
    }

    // 单个模型预测 —— 直接使用 array 数据，消除 vector 复制
    bool PredictSingleModel(BoosterHandle booster, const float* features,
        int num_features, double& confidence) {
        if (!booster) return false;
        int64_t out_len; double result;
        int ret = LGBM_BoosterPredictForMat(booster, features, C_API_DTYPE_FLOAT32,
            1, num_features, 1, C_API_PREDICT_NORMAL, 0, -1, "", &out_len, &result);
        if (ret != 0) { std::cerr << "预测失败: " << LGBM_GetLastError() << std::endl; return false; }
        confidence = result;
        return true;
    }

public:
    LightGBMClassifier() {
        base_feature_names_.resize(BASE_FEATURE_DIM);
        for (int i = 0; i < BASE_FEATURE_DIM; ++i) base_feature_names_[i] = "f" + std::to_string(i);
        base_num_features_ = BASE_FEATURE_DIM;
        extra_num_features_ = 0;
    }

    ~LightGBMClassifier() {
        if (base_booster_) LGBM_BoosterFree(base_booster_);
        if (extra_booster_) LGBM_BoosterFree(extra_booster_);
    }

    void enableDynamicFeatures(int max_extra) {
        dynamic_features_enabled_ = true;
        max_extra_features_ = (max_extra > 0) ? max_extra : 0;
        if (max_extra_features_ == 0) dynamic_features_enabled_ = false;
    }

    void disableDynamicFeatures() {
        dynamic_features_enabled_ = false;
        max_extra_features_ = 0;
        extra_feature_names_.clear();
        extra_num_features_ = 0;
        if (extra_booster_) {
            LGBM_BoosterFree(extra_booster_);
            extra_booster_ = nullptr;
        }
        extra_trained_ = false;
    }

    bool isDynamicEnabled() const { return dynamic_features_enabled_; }
    int getMaxExtraFeatures() const { return max_extra_features_; }
    int getCurrentExtraFeatures() const { return (int)extra_feature_names_.size(); }

    void setCustomParams(const std::string& params) { custom_booster_params_ = params; }
    std::string getCustomParams() const { return custom_booster_params_; }

    // 加权预测 —— 直接使用 array 数据，消除 vector 复制
    bool Predict(const RawSample& sample, double& confidence, bool isExtraEnabled = false) {
        if (!base_trained_) {
            std::cerr << "Error: base model not trained" << std::endl;
            return false;
        }

        double base_conf = 0.0;
        double extra_conf = 0.0;

        // 基础模型预测 —— 直接传 array 指针，无需 buildBaseFeatures 复制
        if (!PredictSingleModel(base_booster_, sample.base_features.data(),
            BASE_FEATURE_DIM, base_conf)) {
            return false;
        }

        // 额外模型预测（如果存在）
        if (extra_trained_ && extra_num_features_ > 0 && isExtraEnabled) {
            auto extra_feat = buildExtraFeatures(sample);
            if (!PredictSingleModel(extra_booster_, extra_feat.data(),
                extra_num_features_, extra_conf)) {
                // 失败则仅依赖基础模型
                confidence = base_conf;
                return true;
            }

            // 加权融合
            confidence = base_weight_ * base_conf + extra_weight_ * extra_conf;
        }
        else
        {
            confidence = base_conf;
        }

        return true;
    }

    bool LoadModel(const std::string& filename) {
        bool success = true;

        // 加载基础模型
        std::string base_file = filename + ".base";
        int num_iter;
        int res = LGBM_BoosterCreateFromModelfile(base_file.c_str(), &num_iter, &base_booster_);
        if (res == 0) {
            std::ifstream f(base_file + ".names");
            if (f) {
                base_feature_names_.clear();
                std::string line;
                while (std::getline(f, line)) base_feature_names_.push_back(line);
            }
            base_trained_ = true;
            base_num_features_ = BASE_FEATURE_DIM;
            std::cout << "基础模型加载成功，迭代数: " << num_iter << std::endl;
        }
        else {
            std::cerr << "加载基础模型失败" << std::endl;
            success = false;
        }

        // 加载额外模型
        std::string extra_file = filename + ".extra";
        std::ifstream extra_test(extra_file);
        if (extra_test.good()) {
            extra_test.close();
            res = LGBM_BoosterCreateFromModelfile(extra_file.c_str(), &num_iter, &extra_booster_);
            if (res == 0) {
                std::ifstream f(extra_file + ".names");
                if (f) {
                    extra_feature_names_.clear();
                    std::string line;
                    while (std::getline(f, line)) extra_feature_names_.push_back(line);
                    extra_num_features_ = (int)extra_feature_names_.size();
                }
                extra_trained_ = true;
                dynamic_features_enabled_ = true;
                max_extra_features_ = extra_num_features_;
                std::cout << "额外模型加载成功，迭代数: " << num_iter << "，特征维度: " << extra_num_features_ << std::endl;
            }
        }

        // 加载配置
        std::string config_file = filename + ".config";
        std::ifstream cfg(config_file);
        if (cfg) {
            std::string line;
            while (std::getline(cfg, line)) {
                if (line.rfind("base_weight=", 0) == 0)
                    base_weight_ = std::stod(line.substr(12));
                else if (line.rfind("extra_weight=", 0) == 0)
                    extra_weight_ = std::stod(line.substr(13));
                else if (line.rfind("max_extra_features=", 0) == 0)
                    max_extra_features_ = std::stoi(line.substr(19));
            }
        }

        std::cout << "模型配置加载完成 - 基础权重: " << base_weight_
            << ", 额外权重: " << extra_weight_ << std::endl;

        return success && base_trained_;
    }

    std::vector<std::pair<std::string, double>> GetFeatureImportance(const std::string& model_type = "base") {
        std::vector<std::pair<std::string, double>> result;
        BoosterHandle booster = nullptr;
        std::vector<std::string>* feature_names = nullptr;
        int num_features = 0;

        if (model_type == "base") {
            if (!base_trained_) return result;
            booster = base_booster_;
            feature_names = &base_feature_names_;
            num_features = base_num_features_;
        }
        else if (model_type == "extra") {
            if (!extra_trained_) return result;
            booster = extra_booster_;
            feature_names = &extra_feature_names_;
            num_features = extra_num_features_;
        }
        else {
            return result;
        }

        std::vector<double> scores(num_features);
        LGBM_BoosterFeatureImportance(booster, -1, C_API_FEATURE_IMPORTANCE_GAIN, scores.data());
        for (int i = 0; i < num_features; ++i)
            result.emplace_back((*feature_names)[i], scores[i]);
        std::sort(result.begin(), result.end(), [](auto& a, auto& b) { return a.second > b.second; });
        return result;
    }

    bool IsTrained() const { return base_trained_; }
    bool IsExtraTrained() const { return extra_trained_; }
    int GetBaseNumFeatures() const { return base_num_features_; }
    int GetExtraNumFeatures() const { return extra_num_features_; }

    double GetBaseWeight() const { return base_weight_; }
    double GetExtraWeight() const { return extra_weight_; }
};

// ======================== 快速 PE 验证 ========================
static bool QuickCheckPE(const string& path) {
    ifstream file(path, ios::binary);
    if (!file) return false;
    IMAGE_DOS_HEADER dos;
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    file.seekg(dos.e_lfanew, ios::beg);
    DWORD peSig = 0;
    file.read(reinterpret_cast<char*>(&peSig), sizeof(peSig));
    if (!file || peSig != IMAGE_NT_SIGNATURE) return false;
    return true;
}

// ======================== 数据保存/加载（兼容旧格式）========================
static bool SaveSamples(const std::string& filename,
    const std::vector<RawSample>& samples,
    bool includeExtraInfo) {
    ofstream ofs(filename, ios::binary);
    if (!ofs) return false;
    if (includeExtraInfo) {
        const uint32_t magic = 0x31465845;
        const uint32_t version = 1;
        ofs.write(reinterpret_cast<const char*>(&magic), sizeof(magic));
        ofs.write(reinterpret_cast<const char*>(&version), sizeof(version));
        uint64_t count = samples.size();
        ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& s : samples) {
            ofs.write(reinterpret_cast<const char*>(s.base_features.data()),
                BASE_FEATURE_DIM * sizeof(float));
            uint32_t impCount = (uint32_t)s.imports.size();
            ofs.write(reinterpret_cast<const char*>(&impCount), sizeof(impCount));
            for (const auto& func : s.imports) {
                uint32_t len = (uint32_t)func.size();
                ofs.write(reinterpret_cast<const char*>(&len), sizeof(len));
                ofs.write(func.data(), len);
            }
        }
    }
    else {
        uint64_t count = samples.size();
        ofs.write(reinterpret_cast<const char*>(&count), sizeof(count));
        for (const auto& s : samples) {
            ofs.write(reinterpret_cast<const char*>(s.base_features.data()),
                BASE_FEATURE_DIM * sizeof(float));
        }
    }
    return ofs.good();
}

static bool LoadSamples(const std::string& filename,
    std::vector<RawSample>& samples) {
    ifstream ifs(filename, ios::binary);
    if (!ifs) return false;
    uint32_t magic = 0;
    ifs.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    bool isNewFormat = (magic == 0x31465845);
    if (isNewFormat) {
        uint32_t version;
        ifs.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != 1) { cerr << "不支持的样本文件版本" << endl; return false; }
        uint64_t count = 0;
        ifs.read(reinterpret_cast<char*>(&count), sizeof(count));
        for (uint64_t i = 0; i < count; ++i) {
            RawSample s;
            ifs.read(reinterpret_cast<char*>(s.base_features.data()),
                BASE_FEATURE_DIM * sizeof(float));
            if (!ifs) return false;
            uint32_t impCount;
            ifs.read(reinterpret_cast<char*>(&impCount), sizeof(impCount));
            for (uint32_t j = 0; j < impCount; ++j) {
                uint32_t len;
                ifs.read(reinterpret_cast<char*>(&len), sizeof(len));
                string func(len, '\0');
                ifs.read(&func[0], len);
                s.imports.insert(func);
            }
            samples.push_back(s);
        }
        return true;
    }
    else {
        ifs.seekg(0, ios::beg);
        uint64_t count = 0;
        ifs.read(reinterpret_cast<char*>(&count), sizeof(count));
        if (!ifs || count > 10000000) return false;
        for (uint64_t i = 0; i < count; ++i) {
            RawSample s;
            ifs.read(reinterpret_cast<char*>(s.base_features.data()),
                BASE_FEATURE_DIM * sizeof(float));
            if (!ifs) return false;
            samples.push_back(s);
        }
        return true;
    }
}