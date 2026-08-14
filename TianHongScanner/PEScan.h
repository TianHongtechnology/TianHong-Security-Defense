#include <functional>
#include <set>
#include <Windows.h>
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

using namespace std;

// ======================== 手写 IP 检测（替代 regex，性能提升 10x+）========================
static int countIPsFast(const string& s) {
    int cnt = 0, i = 0, len = (int)s.size();
    while (i < len) {
        // 跳过非数字
        if (s[i] < '0' || s[i] > '9') { i++; continue; }
        int dots = 0, digits = 0, j = i;
        while (j < len) {
            if (s[j] >= '0' && s[j] <= '9') {
                digits++;
                while (j < len && s[j] >= '0' && s[j] <= '9') j++;
                if (j < len && s[j] == '.' && dots < 3) { dots++; j++; }
                else break;
            }
            else break;
        }
        if (dots == 3 && digits >= 4) cnt++;
        i = (j > i) ? j : i + 1;
    }
    return cnt;
}

// ======================== 常量与结构体 ========================
static constexpr size_t BASE_FEATURE_DIM = 600;     // 不可变的基础特征维度
static constexpr double BASE_MODEL_WEIGHT = 0.92;    // 基础模型权重（较高）
static constexpr double EXTRA_MODEL_WEIGHT = 0.08;   // 额外维度模型权重（较低）

// ======================== RawSample ========================
struct RawSample {
    std::array<float, BASE_FEATURE_DIM> base_features;  // 基础600维
    std::unordered_set<std::string> imports;             // 导入函数集合（小写），查找平均 O(1)
};

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

    // 构建基础600维特征
    std::vector<float> buildBaseFeatures(const RawSample& sample) const {
        std::vector<float> feat(BASE_FEATURE_DIM);
        std::copy(sample.base_features.begin(), sample.base_features.end(), feat.begin());
        return feat;
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

    // 单个模型预测
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

    // 加权预测 - useExtra 控制是否使用额外模型
    bool Predict(const RawSample& sample, double& confidence, bool useExtra = true) {
        if (!base_trained_) {
            std::cerr << "Error: base model not trained" << std::endl;
            return false;
        }

        double base_conf = 0.0;
        double extra_conf = 0.0;

        // 基础模型预测 - 直接使用 array 数据，消除 vector 复制
        if (!PredictSingleModel(base_booster_, sample.base_features.data(),
            BASE_FEATURE_DIM, base_conf)) {
            return false;
        }

        // 额外模型预测（如果存在且启用）
        if (useExtra && extra_trained_ && extra_num_features_ > 0) {
            auto extra_feat = buildExtraFeatures(sample);
            if (!PredictSingleModel(extra_booster_, extra_feat.data(),
                extra_num_features_, extra_conf)) {
                // 失败则仅依赖基础模型
                confidence = base_conf;
                return base_conf > 0.5;
            }

            // 加权融合
            confidence = base_weight_ * base_conf + extra_weight_ * extra_conf;
        }
        else {
            confidence = base_conf;
        }

        return confidence > 0.5;
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

// ======================== PE 文件分析器（完整实现）========================
class PEFileAnalyzer {
private:
    BYTE* fileBase = nullptr;            // 内存映射基址
    HANDLE hMap = nullptr;
    DWORD fileSize = 0;
    bool valid = false;
    bool _64bit = false;

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

    // ---------- 安全的 RVA 转文件偏移 ----------
    DWORD rvaToOffset(DWORD rva) const {
        if (rva == 0) return 0;
        WORD nSec = sectionCount();
        if (nSec == 0) return rva < fileSize ? rva : 0;
        const IMAGE_SECTION_HEADER* sec = sections();
        if (!sec) return 0;
        if (rva < sec[0].VirtualAddress) {
            return rva < fileSize ? rva : 0;
        }
        for (WORD i = 0; i < nSec; i++) {
            DWORD secVA = sec[i].VirtualAddress;
            DWORD secSize = sec[i].Misc.VirtualSize;
            if (secSize == 0) secSize = sec[i].SizeOfRawData;
            if (secSize == 0) continue;
            if (rva >= secVA && rva < secVA + secSize) {
                DWORD offset = rva - secVA + sec[i].PointerToRawData;
                if (offset < fileSize) return offset;
            }
        }
        return 0;
    }

    // ---------- 资源遍历 (防死循环增强版) ----------
    IMAGE_RESOURCE_DIRECTORY* resRoot() const {
        DWORD rva, size;
        if (!getDataDir(2, rva, size)) return nullptr;
        DWORD off = rvaToOffset(rva);
        if (off == 0 || off + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) return nullptr;
        return (IMAGE_RESOURCE_DIRECTORY*)(fileBase + off);
    }

    int enumResources(WORD typeId,
        function<bool(IMAGE_RESOURCE_DIRECTORY_ENTRY*, IMAGE_RESOURCE_DIRECTORY_ENTRY*,
            IMAGE_RESOURCE_DIRECTORY_ENTRY*, void*, DWORD)> callback) const {
        auto* root = resRoot();
        if (!root) return 0;
        int count = 0;
        auto entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(root + 1);
        DWORD totalEntries = root->NumberOfNamedEntries + root->NumberOfIdEntries;

        if ((BYTE*)entries + totalEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
            return 0;

        for (DWORD i = 0; i < totalEntries; i++) {
            auto& typeE = entries[i];
            if (typeE.NameIsString || typeE.Id != typeId) continue;
            if (!typeE.DataIsDirectory) continue;

            DWORD nameDirOff = typeE.OffsetToDirectory & 0x7FFFFFFF;
            if (nameDirOff == 0 || nameDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;

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
                if (langDirOff == 0 || langDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;
                if (langDirOff == nameDirOff) continue; // 防止自己指向自己

                auto* langDir = (IMAGE_RESOURCE_DIRECTORY*)(fileBase + langDirOff);
                DWORD langTotal = langDir->NumberOfNamedEntries + langDir->NumberOfIdEntries;
                if (langTotal == 0 || langTotal > 10000) continue;

                auto langEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(langDir + 1);
                if ((BYTE*)langEntries + langTotal * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
                    continue;

                for (DWORD k = 0; k < langTotal; k++) {
                    auto& langE = langEntries[k];
                    DWORD dataOffDir = langE.OffsetToData & 0x7FFFFFFF;
                    if (dataOffDir == 0 || dataOffDir + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize) continue;

                    auto* dataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)(fileBase + dataOffDir);
                    DWORD dataOff = rvaToOffset(dataEntry->OffsetToData);
                    if (dataOff >= fileSize) continue;

                    if (dataOff + dataEntry->Size > fileSize) continue;

                    void* data = fileBase + dataOff;
                    if (callback(&typeE, &nameE, &langE, data, dataEntry->Size))
                        count++;
                }
            }
        }
        return count;
    }

    bool hasResource(WORD typeId) const {
        return enumResources(typeId, [](auto*, auto*, auto*, void*, DWORD) { return true; }) > 0;
    }

    int countResource(WORD typeId) const {
        return enumResources(typeId, [](auto*, auto*, auto*, void*, DWORD) { return true; });
    }

    int getResourceLanguages() const {
        set<WORD> langs;
        auto* root = resRoot();
        if (!root) return 0;
        auto entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(root + 1);
        DWORD totalEntries = root->NumberOfNamedEntries + root->NumberOfIdEntries;

        if ((BYTE*)entries + totalEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
            return 0;

        for (DWORD i = 0; i < totalEntries; i++) {
            auto& typeE = entries[i];
            if (!typeE.DataIsDirectory) continue;

            DWORD nameDirOff = typeE.OffsetToDirectory & 0x7FFFFFFF;
            if (nameDirOff == 0 || nameDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;

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
                if (langDirOff == 0 || langDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;

                auto* langDir = (IMAGE_RESOURCE_DIRECTORY*)(fileBase + langDirOff);
                DWORD langTotal = langDir->NumberOfNamedEntries + langDir->NumberOfIdEntries;
                if (langTotal == 0 || langTotal > 10000) continue;

                auto langEntries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(langDir + 1);
                if ((BYTE*)langEntries + langTotal * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
                    continue;

                for (DWORD k = 0; k < langTotal; k++) {
                    if (!langEntries[k].NameIsString)
                        langs.insert((WORD)langEntries[k].Id);
                }
            }
        }
        return (int)langs.size();
    }

    // 新增：单次遍历收集所有资源统计信息，替代 9 次独立遍历
    struct ResourceStats {
        bool has24 = false, has16 = false, has10 = false, has23 = false;
        int count3 = 0, count1 = 0, count5 = 0, count6 = 0;
        unordered_set<WORD> langs;
    };

    ResourceStats collectResourceStats() const {
        ResourceStats stats;
        auto* root = resRoot();
        if (!root) return stats;
        auto entries = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(root + 1);
        DWORD totalEntries = root->NumberOfNamedEntries + root->NumberOfIdEntries;
        if ((BYTE*)entries + totalEntries * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY) > fileBase + fileSize)
            return stats;

        for (DWORD i = 0; i < totalEntries; i++) {
            auto& typeE = entries[i];
            if (!typeE.DataIsDirectory) continue;
            WORD tid = (WORD)typeE.Id;
            if (typeE.NameIsString) continue;

            DWORD nameDirOff = typeE.OffsetToDirectory & 0x7FFFFFFF;
            if (nameDirOff == 0 || nameDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;

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
                if (langDirOff == 0 || langDirOff + sizeof(IMAGE_RESOURCE_DIRECTORY) > fileSize) continue;
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
                        stats.langs.insert((WORD)langE.Id);

                    DWORD dataOffDir = langE.OffsetToData & 0x7FFFFFFF;
                    if (dataOffDir == 0 || dataOffDir + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > fileSize) continue;
                    auto* dataEntry = (IMAGE_RESOURCE_DATA_ENTRY*)(fileBase + dataOffDir);
                    DWORD dataOff = rvaToOffset(dataEntry->OffsetToData);
                    if (dataOff >= fileSize) continue;
                    if (dataOff + dataEntry->Size > fileSize) continue;

                    // 累计计数
                    switch (tid) {
                    case 24: stats.has24 = true; break;
                    case 16: stats.has16 = true; break;
                    case 10: stats.has10 = true; break;
                    case 23: stats.has23 = true; break;
                    case 3:  stats.count3++;  break;
                    case 1:  stats.count1++;  break;
                    case 5:  stats.count5++;  break;
                    case 6:  stats.count6++;  break;
                    }
                }
            }
        }
        return stats;
    }

    void* getResourceData(WORD typeId) const {
        void* found = nullptr;
        enumResources(typeId, [&](auto*, auto*, auto*, void* data, DWORD) {
            found = data;
            return true;
            });
        return found;
    }

    // ---------- 辅助函数：安全读取宽字符串 ----------
    wstring SafeReadWideString(const BYTE* start, const BYTE* end) const {
        wstring result;
        const BYTE* ptr = start;
        while (ptr + 1 < end) {
            wchar_t wc = *(const wchar_t*)ptr;
            if (wc == L'\0') break;
            result += wc;
            ptr += 2;
            if (result.length() > 1024) break;
        }
        return result;
    }

    // ---------- 获取版本固定文件信息 ----------
    bool getFixedFileInfo(VS_FIXEDFILEINFO& vs) const {
        return getFixedFileInfoFromData(getResourceData(16), vs);
    }

    // 新增：使用预加载的资源数据
    bool getFixedFileInfoFromData(void* raw, VS_FIXEDFILEINFO& vs) const {
        void* data = raw;
        if (!data) return false;

        auto* ptr = (const BYTE*)data;
        const BYTE* resourceEnd = (const BYTE*)data + 0x10000;
        const BYTE* fileEnd = fileBase + fileSize;

        if (resourceEnd > fileEnd) resourceEnd = fileEnd;
        if (ptr + 6 > resourceEnd) return false;

        WORD wLength = *(const WORD*)(ptr);
        WORD wValueLength = *(const WORD*)(ptr + 2);

        if (wLength < 6 || ptr + wLength > resourceEnd) return false;

        ptr += 6;
        while (ptr + 1 < resourceEnd && *(const wchar_t*)ptr != L'\0') ptr += 2;
        ptr += 2;
        ptr = (const BYTE*)(((uintptr_t)ptr + 3) & ~3);

        if (ptr >= resourceEnd) return false;

        if (wValueLength >= sizeof(VS_FIXEDFILEINFO) && ptr + sizeof(VS_FIXEDFILEINFO) <= resourceEnd) {
            memcpy(&vs, ptr, sizeof(VS_FIXEDFILEINFO));
            return (vs.dwSignature == 0xFEEF04BD);
        }

        if (ptr + sizeof(VS_FIXEDFILEINFO) <= resourceEnd) {
            memcpy(&vs, ptr, sizeof(VS_FIXEDFILEINFO));
            if (vs.dwSignature == 0xFEEF04BD && vs.dwStrucVersion == 0x10000)
                return true;
        }
        return false;
    }

    // ---------- 获取 StringFileInfo 中指定键的值长度 (增强防死循环) ----------
    int getStringFileInfoLength(const string& key) const {
        return getStringFileInfoLengthFromData(key, getResourceData(16));
    }

    // 新增：使用预加载的资源数据，避免重复遍历资源树
    int getStringFileInfoLengthFromData(const string& key, void* raw) const {
        void* data = raw;
        if (!data) return 0;

        auto* ptr = (const BYTE*)data;
        const BYTE* fileEnd = fileBase + fileSize;

        if (ptr + 6 > fileEnd) return 0;

        WORD wLength = *(const WORD*)ptr;
        if (wLength < 6 || wLength > 0x10000) return 0;

        const BYTE* resourceEnd = ptr + wLength;
        if (resourceEnd > fileEnd) resourceEnd = fileEnd;
        if (ptr >= resourceEnd) return 0;

        WORD wValueLength = *(const WORD*)(ptr + 2);

        const BYTE* cur = ptr + 6;
        while (cur + 1 < resourceEnd && *(const wchar_t*)cur != L'\0') cur += 2;
        cur += 2;
        cur = (const BYTE*)(((uintptr_t)cur + 3) & ~3);
        if (cur >= resourceEnd) return 0;

        if (wValueLength >= sizeof(VS_FIXEDFILEINFO) && cur + sizeof(VS_FIXEDFILEINFO) <= resourceEnd) {
            cur += sizeof(VS_FIXEDFILEINFO);
            cur = (const BYTE*)(((uintptr_t)cur + 3) & ~3);
        }

        int maxIterations = 1000;
        int iterCount = 0;

        while (cur + 6 <= resourceEnd && iterCount++ < maxIterations) {
            if (cur + 2 > resourceEnd) break;
            WORD blockLen = *(const WORD*)cur;
            if (blockLen < 6 || blockLen == 0 || cur + blockLen > resourceEnd || blockLen < 6) {
                cur = (const BYTE*)(((uintptr_t)cur + 3) & ~3);
                continue;
            }
            if (cur + 4 > resourceEnd) break;
            WORD blockValLen = *(const WORD*)(cur + 2);

            const BYTE* blockDataStart = cur + 6;
            if (blockDataStart > resourceEnd) break;

            wstring wsKey = SafeReadWideString(blockDataStart, resourceEnd);
            string sKey(wsKey.begin(), wsKey.end());

            const BYTE* blockData = blockDataStart;
            while (blockData + 1 < resourceEnd && *(const wchar_t*)blockData != L'\0') blockData += 2;
            blockData += 2;
            blockData = (const BYTE*)(((uintptr_t)blockData + 3) & ~3);

            if (sKey == "StringFileInfo") {
                const BYTE* inner = blockData;
                const BYTE* innerEnd = cur + blockLen;
                if (innerEnd > resourceEnd) innerEnd = resourceEnd;

                while (inner + 6 <= innerEnd && iterCount++ < maxIterations) {
                    if (inner + 2 > innerEnd) break;
                    WORD iBlockLen = *(const WORD*)inner;
                    if (iBlockLen < 6 || iBlockLen == 0 || inner + iBlockLen > innerEnd) {
                        inner = (const BYTE*)(((uintptr_t)inner + 3) & ~3);
                        if (inner >= innerEnd) break;
                        continue;
                    }

                    const BYTE* iBlockData = inner + 6;
                    while (iBlockData + 1 < innerEnd && *(const wchar_t*)iBlockData != L'\0') iBlockData += 2;
                    iBlockData += 2;
                    iBlockData = (const BYTE*)(((uintptr_t)iBlockData + 3) & ~3);
                    if (iBlockData >= innerEnd) {
                        inner += ((iBlockLen + 3) & ~3);
                        continue;
                    }

                    const BYTE* strTable = iBlockData;
                    const BYTE* strTableEnd = inner + iBlockLen;
                    if (strTableEnd > innerEnd) strTableEnd = innerEnd;

                    while (strTable + 6 <= strTableEnd && iterCount++ < maxIterations) {
                        if (strTable + 2 > strTableEnd) break;
                        WORD sBlockLen = *(const WORD*)strTable;
                        if (sBlockLen < 6 || sBlockLen == 0 || strTable + sBlockLen > strTableEnd) {
                            strTable = (const BYTE*)(((uintptr_t)strTable + 3) & ~3);
                            if (strTable >= strTableEnd) break;
                            continue;
                        }

                        const BYTE* sBlockData = strTable + 6;
                        wstring wkey = SafeReadWideString(sBlockData, strTableEnd);
                        string narrowKey(wkey.begin(), wkey.end());

                        while (sBlockData + 1 < strTableEnd && *(const wchar_t*)sBlockData != L'\0') sBlockData += 2;
                        sBlockData += 2;
                        sBlockData = (const BYTE*)(((uintptr_t)sBlockData + 3) & ~3);

                        if (narrowKey == key) {
                            if (sBlockData < strTableEnd) {
                                wstring wvalue = SafeReadWideString(sBlockData, strTableEnd);
                                return (int)(wvalue.length() * 2);
                            }
                            return 0;
                        }
                        strTable += ((sBlockLen + 3) & ~3);
                    }
                    inner += ((iBlockLen + 3) & ~3);
                }
            }
            cur += ((blockLen + 3) & ~3);
        }
        return 0;
    }

    // ---------- 安全读取窄字符串 ----------
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

    // ---------- 字符串提取 ----------
    void extractStrings(const BYTE* start, size_t len, bool unicode, vector<string>& out) const {
        if (!start || len < 2) return;
        const BYTE* end = start + len;
        string cur;
        auto flush = [&]() {
            if (cur.length() >= 5 && cur.length() <= 1024) out.push_back(cur);
            cur.clear();
            };
        if (!unicode) {
            for (const BYTE* p = start; p < end; ++p) {
                if (*p >= 32 && *p <= 126) cur += (char)*p;
                else if (*p == 0) flush();
                else flush();
            }
        }
        else {
            for (const BYTE* p = start; p < end - 1; p += 2) {
                uint16_t wc = *(uint16_t*)p;
                if (wc >= 32 && wc <= 126) cur += (char)wc;
                else if (wc == 0) flush();
                else flush();
            }
        }
        flush();
    }

    vector<string> getImportedDLLs() const {
        vector<string> dlls;
        DWORD importRVA, importSize;
        if (!getDataDir(1, importRVA, importSize) || importSize == 0) return dlls;
        DWORD importOff = rvaToOffset(importRVA);
        if (importOff == 0 || importOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return dlls;
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(fileBase + importOff);
        const BYTE* const fileEnd = fileBase + fileSize;
        for (int i = 0; i < 2000 && (BYTE*)(desc + 1) <= fileEnd && desc->Name != 0; i++, desc++) {
            DWORD nameOff = rvaToOffset(desc->Name);
            if (nameOff && nameOff < fileSize) {
                string dll = (char*)(fileBase + nameOff);
                transform(dll.begin(), dll.end(), dll.begin(), ::tolower);
                dlls.push_back(dll);
            }
        }
        return dlls;
    }

    // 新增：返回 unordered_set 以支持 O(1) 查找
    unordered_set<string> getImportedDLLsSet() const {
        unordered_set<string> dlls;
        DWORD importRVA, importSize;
        if (!getDataDir(1, importRVA, importSize) || importSize == 0) return dlls;
        DWORD importOff = rvaToOffset(importRVA);
        if (importOff == 0 || importOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return dlls;
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(fileBase + importOff);
        const BYTE* const fileEnd = fileBase + fileSize;
        for (int i = 0; i < 2000 && (BYTE*)(desc + 1) <= fileEnd && desc->Name != 0; i++, desc++) {
            DWORD nameOff = rvaToOffset(desc->Name);
            if (nameOff && nameOff < fileSize) {
                string dll = (char*)(fileBase + nameOff);
                transform(dll.begin(), dll.end(), dll.begin(), ::tolower);
                dlls.insert(dll);
            }
        }
        return dlls;
    }

public:
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
        valid = true;
    }

    ~PEFileAnalyzer() {
        if (fileBase) UnmapViewOfFile(fileBase);
        if (hMap) CloseHandle(hMap);
    }

    bool isPE() const { return valid; }
    bool is64bit() const { return _64bit; }
    bool isValid() const { return valid; }

    // 返回 unordered_set 以支持 O(1) 查找；同时保留小写化去重
    unordered_set<string> collectAllStrings() const {
        unordered_set<string> unique;
        unique.reserve(4096);
        WORD nSec = sectionCount();
        const IMAGE_SECTION_HEADER* sec = sections();
        if (!sec) return unique;
        string cur;
        cur.reserve(1024);
        for (WORD i = 0; i < nSec; i++) {
            DWORD off = sec[i].PointerToRawData;
            DWORD size = sec[i].SizeOfRawData;
            if (off + size <= fileSize && size > 0) {
                // 直接小写化并插入 set，避免中间 vector
                extractStringsLower(fileBase + off, size, false, unique, cur);
                extractStringsLower(fileBase + off, size, true, unique, cur);
            }
        }
        return unique;
    }

private:
    // 内联小写化字符串提取，直接写入 unordered_set，消除中间 vector 和二次遍历
    void extractStringsLower(const BYTE* start, size_t len, bool unicode,
        unordered_set<string>& out, string& cur) const {
        if (!start || len < 2) return;
        const BYTE* end = start + len;
        cur.clear();
        auto flush = [&]() {
            if (cur.length() >= 5 && cur.length() <= 1024) out.insert(cur);
            cur.clear();
        };
        if (!unicode) {
            for (const BYTE* p = start; p < end; ++p) {
                BYTE c = *p;
                if (c >= 32 && c <= 126) cur += (char)::tolower(c);
                else flush();
            }
        }
        else {
            for (const BYTE* p = start; p < end - 1; p += 2) {
                uint16_t wc = *(uint16_t*)p;
                if (wc >= 32 && wc <= 126) cur += (char)::tolower((BYTE)wc);
                else flush();
            }
        }
        flush();
    }

public:

    // ---------- 导入函数 (防死循环增强，同时作为公共接口) ----------
    std::unordered_set<string> getImportedFunctions() const {
        std::unordered_set<string> funcs;
        if (!valid) return funcs;

        DWORD importRVA = 0, importSize = 0;
        if (!getDataDir(1, importRVA, importSize) || importSize == 0) return funcs;

        DWORD importOff = rvaToOffset(importRVA);
        if (importOff == 0 || importOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > fileSize) return funcs;

        const BYTE* const fileEnd = fileBase + fileSize;
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(fileBase + importOff);

        int maxDlls = 2000;
        int maxFuncs = 50000;
        int totalFuncs = 0;

        for (int descIdx = 0; descIdx < maxDlls && desc->Name != 0 && totalFuncs < maxFuncs; descIdx++, desc++) {
            if ((BYTE*)(desc + 1) > fileEnd) break;

            DWORD thunkRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            if (thunkRVA == 0) continue;

            DWORD thunkOff = rvaToOffset(thunkRVA);
            if (thunkOff == 0 || thunkOff >= fileSize) continue;

            if (!_64bit) {
                auto* thunk = (IMAGE_THUNK_DATA32*)(fileBase + thunkOff);
                if ((BYTE*)(thunk + 1) > fileEnd) continue;

                for (int thunkIdx = 0; thunkIdx < 10000 && thunk->u1.AddressOfData != 0 && totalFuncs < maxFuncs; thunkIdx++, thunk++) {
                    if ((BYTE*)(thunk + 1) > fileEnd) break;
                    if (thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG32) continue;

                    DWORD nameRVA = thunk->u1.AddressOfData;
                    DWORD nameOff = rvaToOffset(nameRVA);
                    if (nameOff == 0 || nameOff + sizeof(WORD) >= fileSize) continue;

                    auto* byName = (IMAGE_IMPORT_BY_NAME*)(fileBase + nameOff);
                    if ((BYTE*)byName + sizeof(WORD) > fileEnd) continue;

                    string name = SafeReadName(byName->Name, fileEnd);
                    if (!name.empty()) {
                        funcs.insert(name);
                        totalFuncs++;
                    }
                }
            }
            else {
                auto* thunk = (IMAGE_THUNK_DATA64*)(fileBase + thunkOff);
                if ((BYTE*)(thunk + 1) > fileEnd) continue;

                for (int thunkIdx = 0; thunkIdx < 10000 && thunk->u1.AddressOfData != 0 && totalFuncs < maxFuncs; thunkIdx++, thunk++) {
                    if ((BYTE*)(thunk + 1) > fileEnd) break;
                    if (thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG64) continue;

                    DWORD nameRVA = (DWORD)(thunk->u1.AddressOfData & 0xFFFFFFFF);
                    DWORD nameOff = rvaToOffset(nameRVA);
                    if (nameOff == 0 || nameOff + sizeof(WORD) >= fileSize) continue;

                    auto* byName = (IMAGE_IMPORT_BY_NAME*)(fileBase + nameOff);
                    if ((BYTE*)byName + sizeof(WORD) > fileEnd) continue;

                    string name = SafeReadName(byName->Name, fileEnd);
                    if (!name.empty()) {
                        funcs.insert(name);
                        totalFuncs++;
                    }
                }
            }
        }
        return funcs;
    }

    // ---------- 600 维特征提取（完整实现）----------
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

        // 2. 节区特征 (30维)
        WORD nSec = sectionCount();
        const IMAGE_SECTION_HEADER* sec = sections();
        float secEnt[96] = { 0 }, secRaw[96] = { 0 };
        int execCnt = 0, writeCnt = 0, readCnt = 0;
        float textSize = 0, textEnt = 0, dataSize = 0, dataEnt = 0, rsrcSize = 0, rsrcEnt = 0;

        if (sec && nSec > 0) {
            for (WORD i = 0; i < nSec && i < 96; i++) {
                DWORD rawOff = sec[i].PointerToRawData;
                DWORD rawSize = sec[i].SizeOfRawData;
                if (rawOff + rawSize <= fileSize && rawSize > 0)
                    secEnt[i] = (float)entropy(fileBase + rawOff, rawSize);
                secRaw[i] = (float)rawSize;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) execCnt++;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_WRITE) writeCnt++;
                if (sec[i].Characteristics & IMAGE_SCN_MEM_READ) readCnt++;
                char name[9] = { 0 }; memcpy(name, sec[i].Name, 8);
                string sname(name);
                if (sname.find(".text") != string::npos) { textSize = (float)rawSize; textEnt = secEnt[i]; }
                else if (sname.find(".data") != string::npos || sname == ".rdata") { dataSize = (float)rawSize; dataEnt = secEnt[i]; }
                else if (sname.find(".rsrc") != string::npos) { rsrcSize = (float)rawSize; rsrcEnt = secEnt[i]; }
            }
        }

        float maxEnt = 0, minEnt = 8, sumEnt = 0;
        for (WORD i = 0; i < nSec && i < 96; i++) {
            if (secEnt[i] > maxEnt) maxEnt = secEnt[i];
            if (secEnt[i] < minEnt) minEnt = secEnt[i];
            sumEnt += secEnt[i];
        }
        feats[idx++] = maxEnt;
        feats[idx++] = minEnt;
        feats[idx++] = nSec ? sumEnt / nSec : 0;
        float varEnt = 0;
        for (WORD i = 0; i < nSec && i < 96; i++) {
            float diff = secEnt[i] - (nSec ? sumEnt / nSec : 0);
            varEnt += diff * diff;
        }
        feats[idx++] = nSec ? sqrt(varEnt / nSec) : 0;
        float maxRaw = 0, sumRaw = 0;
        for (WORD i = 0; i < nSec && i < 96; i++) {
            if (secRaw[i] > maxRaw) maxRaw = secRaw[i];
            sumRaw += secRaw[i];
        }
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
        if (sec) {
            for (WORD i = 0; i < nSec; i++) {
                if (sec[i].PointerToRawData + sec[i].SizeOfRawData > fileSize) { overlap = true; break; }
            }
        }
        feats[idx++] = overlap ? 1.0f : 0.0f;
        while (idx < 70) feats[idx++] = 0;

        // 3. 字节/熵特征 (50维)
        feats[idx++] = (float)entropy(fileBase, fileSize);
        int byteFreq[256] = { 0 };
        for (DWORD i = 0; i < fileSize; i++) byteFreq[fileBase[i]]++;
        for (int i = 0; i < 32; i++) {
            int cnt = 0;
            for (int j = i * 8; j < (i + 1) * 8 && j < 256; j++) cnt += byteFreq[j];
            feats[idx++] = fileSize ? (float)cnt / fileSize : 0;
        }
        BYTE specBytes[] = { 0x00,0xCC,0x90,0xE8,0xE9,0xFF };
        for (BYTE b : specBytes) feats[idx++] = fileSize ? (float)byteFreq[b] / fileSize : 0;
        DWORD seg = fileSize / 10;
        float segEnt[10] = { 0 };
        if (seg > 0) {
            for (int i = 0; i < 10; i++) {
                DWORD off = i * seg;
                DWORD len = (i == 9) ? fileSize - off : seg;
                segEnt[i] = (float)entropy(fileBase + off, len);
            }
        }
        for (int i = 0; i < 10; i++) feats[idx++] = segEnt[i];
        feats[idx++] = *max_element(segEnt, segEnt + 10) - *min_element(segEnt, segEnt + 10);
        while (idx < 120) feats[idx++] = 0;

        // 4. API 类别 (25维)
        std::unordered_set<string> imports = getImportedFunctions();
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

        // 6. DLL 存在性 (30维) - 使用 unordered_set O(1) 查找
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

        // 7. 版本信息 (15维) - 预加载资源数据，避免 10+1 次资源树遍历
        void* vsResourceData = getResourceData(16); // 单次获取
        VS_FIXEDFILEINFO vs;
        bool hasVs = getFixedFileInfoFromData(vsResourceData, vs);
        feats[idx++] = (float)getStringFileInfoLengthFromData("FileDescription", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("FileVersion", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("ProductName", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("ProductVersion", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("CompanyName", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("LegalCopyright", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("Comments", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("InternalName", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("LegalTrademarks", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("SpecialBuild", vsResourceData);
        feats[idx++] = (float)getStringFileInfoLengthFromData("PrivateBuild", vsResourceData);
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
        feats[idx++] = certSize > 0 ? 1.0f : 0.0f;
        feats[idx++] = 0;
        feats[idx++] = 0;
        feats[idx++] = 0;
        feats[idx++] = 0;

        // 9. 资源特征 (10维) - 单次遍历替代 9 次独立遍历
        ResourceStats rs = collectResourceStats();
        feats[idx++] = rs.has24 ? 1.0f : 0.0f;
        feats[idx++] = rs.has16 ? 1.0f : 0.0f;
        feats[idx++] = (float)rs.count3;
        feats[idx++] = (float)rs.count1;
        feats[idx++] = (float)rs.count5;
        feats[idx++] = (float)rs.count6;
        feats[idx++] = (float)rs.langs.size();
        feats[idx++] = rs.has10 ? 1.0f : 0.0f;
        feats[idx++] = rs.has23 ? 1.0f : 0.0f;
        feats[idx++] = rsrcSize > 0 ? 1.0f : 0.0f;

        // 10. 加壳/混淆 (15维)
        static const vector<string> packers = { "upx","aspack","mpress","themida","vmp","enigma","petite","yoda","armadillo","zprotect" };
        for (auto& p : packers) {
            bool found = false;
            if (sec && nSec > 0) {
                for (WORD i = 0; i < nSec; i++) {
                    char name[9] = { 0 }; memcpy(name, sec[i].Name, 8);
                    string sname(name);
                    transform(sname.begin(), sname.end(), sname.begin(), ::tolower);
                    if (sname.find(p) != string::npos) { found = true; break; }
                }
            }
            feats[idx++] = found ? 1.0f : 0.0f;
        }
        float highEntCode = 0;
        bool nonPrintableName = false;
        if (sec && nSec > 0) {
            for (WORD i = 0; i < nSec; i++) {
                if (secEnt[i] > 7.5 && (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) highEntCode = 1.0f;
                char name[9] = { 0 }; memcpy(name, sec[i].Name, 8);
                for (int j = 0; j < 8 && name[j]; j++)
                    if (!isprint((BYTE)name[j])) { nonPrintableName = true; break; }
            }
        }
        feats[idx++] = highEntCode;
        feats[idx++] = nonPrintableName ? 1.0f : 0.0f;
        while (idx < 420) feats[idx++] = 0;

        // 11. 恶意字符串模式 (30维)
        static const vector<string> malPatterns = {
            "cmd.exe","powershell","wscript","cscript","schtasks","regedit","taskmgr","rundll32",
            "rundll32.exe","wmic","vssadmin","bcdedit","netsh","ipconfig","whoami","net user",
            "net localgroup","net share","route print","arp -a","systeminfo","nslookup",
            "ftp ","tftp ","telnet ","ssh ","\\appdata\\","\\startup\\","\\temp\\",
            "\\windows\\system32\\"
        };
        unordered_set<string> cachedStr = collectAllStrings();
        for (auto& pat : malPatterns) {
            feats[idx++] = cachedStr.count(pat) ? 1.0f : 0.0f;
        }
        while (idx < 450) feats[idx++] = 0;

        // 12. 入口点 (10维)
        DWORD ep = oh.AddressOfEntryPoint;
        BYTE epBytes[16] = { 0 };
        if (ep && ep < fileSize) {
            DWORD len = min((DWORD)16, fileSize - ep);
            memcpy(epBytes, fileBase + ep, len);
        }
        feats[idx++] = epBytes[0];
        feats[idx++] = (float)entropy(epBytes, 16);
        feats[idx++] = (memchr(epBytes, 0xE8, 16) ? 1.0f : 0.0f);
        feats[idx++] = (memchr(epBytes, 0xE9, 16) ? 1.0f : 0.0f);
        feats[idx++] = (memchr(epBytes, 0xCC, 16) ? 1.0f : 0.0f);
        for (int i = 0; i < 5; i++) feats[idx++] = 0;
        while (idx < 460) feats[idx++] = 0;

        // 13. 网络特征 (20维) - 手写 IP/URL 检测替代 regex
        int ipCnt = 0, urlCnt = 0;
        for (auto& s : cachedStr) {
            ipCnt += countIPsFast(s);
            if (s.find("http://") != string::npos || s.find("https://") != string::npos)
                urlCnt++;
        }
        feats[idx++] = (float)ipCnt;
        feats[idx++] = (float)urlCnt;
        feats[idx++] = cachedStr.count("ftp://") ? 1.0f : 0.0f;
        static const char* protos[] = { "http","https","ftp","smtp","dns","tcp","udp" };
        for (const char* p : protos)
            feats[idx++] = cachedStr.count(p) ? 1.0f : 0.0f;
        feats[idx++] = cachedStr.count("localhost") ? 1.0f : 0.0f;
        feats[idx++] = (cachedStr.count("no-ip") || cachedStr.count("dyndns")) ? 1.0f : 0.0f;
        static const int ports[] = { 80,443,8080,4444,5555,6666,1337,31337 };
        for (int p : ports)
            feats[idx++] = cachedStr.count(to_string(p)) ? 1.0f : 0.0f;
        while (idx < 480) feats[idx++] = 0;

        // 14. 文件路径模式 (20维)
        static const char* paths[] = {
            "\\windows\\system32\\","\\windows\\syswow64\\","\\appdata\\local\\temp\\",
            "\\start menu\\programs\\startup\\","\\task scheduler\\","\\drivers\\",
            "\\microsoft\\windows\\currentversion\\run","hklm\\software","hkcu\\software"
        };
        for (const char* p : paths)
            feats[idx++] = cachedStr.count(p) ? 1.0f : 0.0f;
        while (idx < 500) feats[idx++] = 0;

        // 15. 字符串统计 (50维)
        int totalStr = (int)cachedStr.size();
        double sumLen = 0;
        int maxLen = 0, minLen = 100000;
        int lenHist[8] = { 0 };
        for (auto& s : cachedStr) {
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
        feats[idx++] = cachedStr.count("\\run") ? 1.0f : 0.0f;
        feats[idx++] = imports.count("createservicea") ? 1.0f : 0.0f;
        feats[idx++] = cachedStr.count("schtasks") ? 1.0f : 0.0f;
        feats[idx++] = imports.count("isdebuggerpresent") ? 1.0f : 0.0f;
        feats[idx++] = (cachedStr.count("vmware") || cachedStr.count("vbox")) ? 1.0f : 0.0f;
        feats[idx++] = (cachedStr.count("procmon") || cachedStr.count("wireshark")) ? 1.0f : 0.0f;
        feats[idx++] = (cachedStr.count("cmd.exe") || cachedStr.count("powershell.exe")) ? 1.0f : 0.0f;
        feats[idx++] = (imports.count("loadlibrarya") && imports.count("getprocaddress")) ? 1.0f : 0.0f;
        feats[idx++] = (imports.count("getasynckeystate") || imports.count("setwindowshookexa")) ? 1.0f : 0.0f;
        feats[idx++] = imports.count("bitblt") ? 1.0f : 0.0f;
        feats[idx++] = (cachedStr.count("lsass") || cachedStr.count("sam")) ? 1.0f : 0.0f;
        feats[idx++] = (imports.count("cryptencrypt") || imports.count("cryptdecrypt")) ? 1.0f : 0.0f;
        feats[idx++] = cachedStr.count("base64") ? 1.0f : 0.0f;
        feats[idx++] = imports.count("sleep") ? 1.0f : 0.0f;
        while (idx < BASE_FEATURE_DIM) feats[idx++] = 0;

        return feats;
    }
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