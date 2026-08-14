#include "ArchiveManager.h"

bool ArchiveTraverser::traverse(const std::string& path, FileCallback callback) {
    reset();
    fs::path p(path);
    if (!fs::exists(p)) return false;
    if (fs::is_directory(p))
        return traverseDirectory(p.string(), callback);
    else
        return traverseFile(p.string(), 0, "", callback);
}

bool ArchiveTraverser::traverseDirectory(const std::string& dir_path, FileCallback& callback) {
    if (!m_options.recursive_directory) {
        for (const auto& entry : fs::directory_iterator(dir_path)) {
            if (m_stop_requested) return false;
            if (entry.is_regular_file())
                if (!traverseFile(entry.path().string(), 0, "", callback))
                    return false;
        }
    }
    else {
        for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
            if (m_stop_requested) return false;
            if (entry.is_regular_file())
                if (!traverseFile(entry.path().string(), 0, "", callback))
                    return false;
        }
    }
    return !m_stop_requested;
}

bool ArchiveTraverser::traverseFile(const std::string& file_path, int depth,
    const std::string& parent_archive,
    FileCallback& callback) {
    if (m_stop_requested) return false;
    if (isArchiveFile(file_path))
        return traverseArchive(file_path, depth, parent_archive, callback);
    else {
        VirusFileInfo info;
        info.file_path = file_path;
        info.archive_path = parent_archive.empty() ? file_path : parent_archive;
        info.inner_path = "";
        return callback(info);
    }
}

const char* ArchiveTraverser::passphraseCallback(struct archive* a, void* client_data) {
    ArchiveTraverser* self = static_cast<ArchiveTraverser*>(client_data);
    if (!self || !self->m_passwordCallback) return nullptr;

    // 调用用户设置的密码回调（可能弹出UI）
    std::string pwd = self->m_passwordCallback();
    if (pwd.empty()) return nullptr;   // 用户跳过，返回空表示无密码

    self->m_lastPassword = pwd;
    return self->m_lastPassword.c_str();
}

bool ArchiveTraverser::traverseArchive(const std::string& archive_path, int depth,
    const std::string& parent_archive,
    FileCallback& callback)
{
    if (m_stop_requested) return false;

    struct archive* a = archive_read_new();
    if (!a) return true;
    archive_read_support_format_all(a);
    archive_read_support_filter_all(a);

    // 设置密码回调（无论何时需要密码，libarchive 都会调用）
    archive_read_set_passphrase_callback(a, this, passphraseCallback);

    // 尝试打开压缩包
    int r = archive_read_open_filename(a, archive_path.c_str(), 10240);
    if (r != ARCHIVE_OK) {
        // 打开失败（可能是损坏或不支持），直接跳过
        archive_read_free(a);
        return true;
    }

    struct archive_entry* entry;
    std::string current_archive_path = parent_archive.empty()
        ? archive_path
        : parent_archive + " >> " + fs::path(archive_path).filename().string();

    // 遍历所有条目
    while ((r = archive_read_next_header(a, &entry)) == ARCHIVE_OK) {
        if (m_stop_requested) break;

        const char* entry_name = archive_entry_pathname(entry);
        if (!entry_name) continue;   // 防止空指针崩溃

        if (archive_entry_filetype(entry) == AE_IFDIR) continue;

        std::string entry_name_str(entry_name);
        bool is_nested = isArchiveFile(entry_name_str);

        // 对于需要回调的条目（普通文件/不可递归的嵌套压缩包），先提取到临时文件
        if (!is_nested || !m_options.recursive_archive || depth >= m_options.max_archive_depth) {
            std::string temp_path = extractToTemp(a, entry);
            if (temp_path.empty()) continue;

            VirusFileInfo info;
            info.file_path = temp_path;
            info.archive_path = current_archive_path;
            info.inner_path = entry_name;

            bool ret = callback(info);
            fs::remove(temp_path);

            if (!ret) break;
        }
        else {
            // 嵌套压缩包：提取后递归遍历
            std::string temp_path = extractToTemp(a, entry);
            if (!temp_path.empty()) {
                traverseFile(temp_path, depth + 1, current_archive_path, callback);
                fs::remove(temp_path);
            }
        }
    }

    // 检查遍历终止的原因
    if (r != ARCHIVE_OK && r != ARCHIVE_EOF) {
        // 读取头失败，可能是密码错误
        const char* err = archive_error_string(a);
    }

    archive_read_close(a);
    archive_read_free(a);
    return !m_stop_requested;
}

std::string ArchiveTraverser::extractToTemp(struct archive* a, struct archive_entry* entry) {
    std::string temp_path = fs::temp_directory_path().string()
        + "/arc_tmp_" + std::to_string(m_temp_counter++) + "_" + std::to_string(time(nullptr));
    std::ofstream out(temp_path, std::ios::binary);
    if (!out.is_open()) return "";

    const void* buffer;
    size_t buffer_size;
    la_int64_t offset;
    while (archive_read_data_block(a, &buffer, &buffer_size, &offset) == ARCHIVE_OK) {
        out.write(static_cast<const char*>(buffer), buffer_size);
    }
    out.close();
    return temp_path;
}

bool ArchiveTraverser::isArchiveFile(const std::string& path) {
    static const std::vector<std::string> exts = {
        ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz",
        ".tgz", ".tbz2", ".txz", ".zst", ".lz4"
    };
    fs::path p(path);
    std::string ext = p.extension().string();
    for (auto& c : ext) c = tolower(c);
    for (const auto& e : exts) if (ext == e) return true;
    std::string stem_ext = fs::path(p.stem()).extension().string();
    for (auto& c : stem_ext) c = tolower(c);
    return stem_ext == ".tar";
}