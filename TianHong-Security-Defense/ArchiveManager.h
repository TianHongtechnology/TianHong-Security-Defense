#pragma once

#include <archive.h>
#include <archive_entry.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "libarchive.lib")

namespace fs = std::filesystem;

struct TraverseOptions {
    bool recursive_archive = false;     // 是否递归扫描压缩包内的压缩包
    int max_archive_depth = 3;          // 压缩包递归最大深度
    bool recursive_directory = true;    // 是否递归扫描文件夹
    bool stop_on_first = false;

    TraverseOptions() = default;
};

struct VirusFileInfo {
    std::string archive_path;     // 压缩包路径（普通文件则为自身路径）
    std::string inner_path;       // 压缩包内路径（普通文件为空）
    std::string file_path;        // 实际可扫描的文件路径（已提取的临时路径）

    bool is_from_archive() const { return !inner_path.empty(); }

    std::string display_path() const {
        if (is_from_archive()) {
            return archive_path + " >> " + inner_path;
        }
        return file_path;
    }
};

class ArchiveTraverser {
public:
    std::string m_lastPassword;

    using FileCallback = std::function<bool(const VirusFileInfo&)>;
    using PasswordCallback = std::function<std::string()>;

    ArchiveTraverser() = default;
    ~ArchiveTraverser() = default;

    void setOptions(const TraverseOptions& options) { m_options = options; }

    // 设置密码回调（必须在 traverse 前调用）
    void setPasswordCallback(PasswordCallback cb) { m_passwordCallback = std::move(cb); }

    static const char* passphraseCallback(struct archive* a, void* client_data);

    void stop() { m_stop_requested = true; }
    void reset() { m_stop_requested = false; }

    bool traverse(const std::string& path, FileCallback callback);

private:
    bool traverseDirectory(const std::string& dir_path, FileCallback& callback);
    bool traverseFile(const std::string& file_path, int depth,
        const std::string& parent_archive, FileCallback& callback);
    bool traverseArchive(const std::string& archive_path, int depth,
        const std::string& parent_archive, FileCallback& callback);

    std::string extractToTemp(struct archive* a, struct archive_entry* entry);
    bool isArchiveFile(const std::string& path);

    TraverseOptions m_options;
    std::atomic<bool> m_stop_requested{ false };
    std::atomic<int> m_temp_counter{ 0 };
    PasswordCallback m_passwordCallback;
};