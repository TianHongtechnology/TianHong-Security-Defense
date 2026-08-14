#include "Sandbox.h"

#include <iostream>
#include <fstream>
#include <random>
#include <cmath>
#include <iterator>
#include <numeric>
#include <cstring>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace ScriptSandbox {

namespace {

/* ============================================================
 *  String utilities
 * ============================================================ */
static inline std::string Trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    size_t b = s.size();
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

static inline std::string ToLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

static inline bool StartsWith(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

static inline bool EndsWith(const std::string& s, const std::string& suffix) {
    return s.size() >= suffix.size() && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

static inline bool Contains(const std::string& s, const std::string& needle) {
    return s.find(needle) != std::string::npos;
}

static inline void ReplaceAll(std::string& s, const std::string& from, const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
}

static std::vector<std::string> Split(const std::string& s, char delim, bool keep_empty = false) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == delim) {
            if (keep_empty || !cur.empty()) out.push_back(cur);
            cur.clear();
        } else cur.push_back(c);
    }
    if (keep_empty || !cur.empty()) out.push_back(cur);
    return out;
}

static std::string Join(const std::vector<std::string>& parts, const std::string& delim) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += delim;
        out += parts[i];
    }
    return out;
}

static std::string RemoveQuotes(std::string s) {
    while (!s.empty() && (s.front() == '"' || s.front() == '\'')) s.erase(s.begin());
    while (!s.empty() && (s.back() == '"' || s.back() == '\'')) s.pop_back();
    return s;
}

static std::string NormalizeSlashes(std::string s) {
    for (char& c : s) if (c == '/') c = '\\';
    return s;
}

/* ============================================================
 *  Base64 decoder
 * ============================================================ */
static bool Base64Decode(const std::string& in, std::string& out) {
    static const std::string b64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; ++i) T[static_cast<unsigned char>(b64[i])] = i;
    out.clear();
    int val = 0, bits = -8;
    for (unsigned char c : in) {
        if (c == '=') break;
        if (T[c] == -1) continue;
        val = (val << 6) + T[c];
        bits += 6;
        if (bits >= 0) {
            out.push_back(char((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return !out.empty();
}

static bool LooksLikeBase64(const std::string& s) {
    if (s.empty() || s.size() % 4 != 0) return false;
    size_t valid = 0;
    for (char c : s) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '+' || c == '/' || c == '=')
            ++valid;
    }
    return valid == s.size();
}

/* ============================================================
 *  Deobfuscator
 * ============================================================ */
class Deobfuscator {
public:
    static std::string Deobfuscate(const std::string& raw, bool is_cmd = false) {
        // Guard: if the script is extremely long (single-line obfuscated),
        // skip regex-based deobfuscation to avoid stack overflow.
        // The interpreter will handle it via the expression evaluator.
        static constexpr size_t kMaxDeobfuscateSize = 65536;  // 64KB
        if (raw.size() > kMaxDeobfuscateSize) return raw;

        std::string prev;
        std::string cur = raw;
        int rounds = 0;
        try {
            do {
                prev = cur;
                cur = StripCarets(cur);
                if (is_cmd) {
                    cur = StripCallPrefixes(cur);
                } else {
                    try { cur = ExpandPsVariables(cur); } catch (...) {}
                    try { cur = ExpandPsStringConcat(cur); } catch (...) {}
                    try { cur = ExpandPsFormatString(cur); } catch (...) {}
                    try { cur = DecodeBase64Blocks(cur); } catch (...) {}
                    try { cur = ReplacePsAliases(cur); } catch (...) {}
                    try { cur = UnescapePsString(cur); } catch (...) {}
                    try { cur = DetectIex(cur); } catch (...) {}
                }
                cur = Trim(cur);
                if (++rounds > 20) break;
            } while (cur != prev);
        } catch (...) {}
        return cur;
    }

    // Public helpers for use by expression evaluator in interpreter.
    static std::string ExpandPsFormatString(const std::string& s) {
        return ExpandPsFormatStringImpl(s);
    }

private:
    static std::string StripCarets(std::string s) {
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '^' && i + 1 < s.size()) {
                out.push_back(s[i + 1]);
                ++i;
            } else out.push_back(s[i]);
        }
        return out;
    }

    // CMD substring expansion: %var:~n,m%
    static std::string ExpandCmdVariables(std::string s) {
        std::regex re(R"(%([a-zA-Z0-9_]+):~(-?\d+),(-?\d+)%)");
        std::smatch m;
        while (std::regex_search(s, m, re)) {
            // We do not have runtime variables here; just strip the marker.
            std::string repl = "%" + m[1].str() + "%";
            s.replace(m.position(), m.length(), repl);
        }
        return s;
    }

    static std::string ExpandCmdDelayed(std::string s) {
        std::regex re(R"(!([a-zA-Z0-9_]+)!)");
        std::smatch m;
        while (std::regex_search(s, m, re)) {
            s.replace(m.position(), m.length(), "%" + m[1].str() + "%");
        }
        return s;
    }

    static std::string UnquoteCmd(std::string s) {
        std::string out;
        bool in_quote = false;
        for (char c : s) {
            if (c == '"') in_quote = !in_quote;
            else out.push_back(c);
        }
        return out;
    }

    static std::string StripCallPrefixes(std::string s) {
        std::string t = ToLower(Trim(s));
        if (StartsWith(t, "call ")) s = Trim(s.substr(5));
        return s;
    }

    // PowerShell [char[]]@(97,98,99) -join '' patterns.
    static std::string ExpandPsCharArrays(std::string s) {
        std::regex re1(R"(\[char\]\s*\(?\s*(\d+)\s*\)?)");
        std::smatch m;
        while (std::regex_search(s, m, re1)) {
            char ch = static_cast<char>(std::stoi(m[1].str()) & 0xFF);
            s.replace(m.position(), m.length(), std::string(1, ch));
        }
        std::regex re2(R"(\[char\[\]\]\s*@?\s*\(([^)]+)\))");
        while (std::regex_search(s, m, re2)) {
            std::string nums = m[2].str();
            std::string out;
            for (const auto& tok : Split(nums, ',')) {
                std::string v = Trim(tok);
                if (!v.empty() && std::isdigit(v[0]))
                    out.push_back(static_cast<char>(std::stoi(v) & 0xFF));
            }
            s.replace(m.position(), m.length(), out);
        }
        return s;
    }

    // String concatenation: "a" + "b" or 'a'+'b'.
    static std::string ExpandPsStringConcat(std::string s) {
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '+' && i > 0 && i + 1 < s.size()) {
                if ((s[i - 1] == '\"' || s[i - 1] == '\'') &&
                    (s[i + 1] == '\"' || s[i + 1] == '\'')) {
                    continue;
                }
            }
            out.push_back(s[i]);
        }
        return out;
    }

    static std::vector<std::string> SplitFormatArgs(const std::string& args) {
        std::vector<std::string> parts;
        std::string cur;
        bool in_quote = false;
        char quote_c = 0;
        int depth = 0;
        for (size_t i = 0; i < args.size(); ++i) {
            char c = args[i];
            if (!in_quote && (c == '(' || c == '[')) { ++depth; cur.push_back(c); continue; }
            if (!in_quote && (c == ')' || c == ']')) { if (depth > 0) --depth; cur.push_back(c); continue; }
            if (in_quote) {
                cur.push_back(c);
                if (c == quote_c) in_quote = false;
                continue;
            }
            if (c == '\"' || c == '\'') { in_quote = true; quote_c = c; cur.push_back(c); continue; }
            if (c == ',' && depth == 0) { parts.push_back(cur); cur.clear(); continue; }
            cur.push_back(c);
        }
        if (!cur.empty() || !parts.empty()) parts.push_back(cur);
        return parts;
    }

    static std::string ResolveValue(const std::string& token, std::unordered_map<std::string, std::string>* known_vars) {
        std::string t = Trim(token);
        if (t.empty()) return "";
        if ((t.front() == '\"' && t.back() == '\"') || (t.front() == '\'' && t.back() == '\''))
            return t.substr(1, t.size() - 2);
        if (known_vars && t.size() > 1 && t[0] == '$') {
            std::string name = Trim(t.substr(1));
            auto it = known_vars->find(name);
            if (it != known_vars->end()) return it->second;
        }
        return t;
    }

    static std::string ExpandPsFormatStringImpl(std::string s) {
        try {
            bool changed = false;
            // Find "..." -f / "..." -F patterns and expand them.
            // Handles both ("...")-f args (closing paren before -f) and
            // ("..." -f args) (closing paren after args).
            std::regex re(R"regex("((?:[^"\\]|\\.)*)"\s*-\s*[fF]\s*)regex");
            std::smatch m;
            std::string::const_iterator search_start = s.cbegin();

            while (std::regex_search(search_start, s.cend(), m, re)) {
                size_t pos = m.position() + (search_start - s.cbegin());
                std::string fmt = m[1].str();  // format string content

                // Find where the argument list ends:
                //   - matching closing paren at depth 0
                //   - semicolon at depth 0
                //   - end of string
                size_t args_start = pos + m.length();
                size_t args_end = s.size();
                int depth = 0;
                char quote = 0;
                for (size_t i = args_start; i < s.size(); ++i) {
                    char c = s[i];
                    if (quote) {
                        if (c == '\\' && i + 1 < s.size()) { ++i; continue; }
                        if (c == quote) quote = 0;
                        continue;
                    }
                    if (c == '"' || c == '\'') { quote = c; continue; }
                    if (c == '(') { ++depth; continue; }
                    if (c == ')') {
                        if (depth == 0) { args_end = i; break; }
                        --depth;
                        continue;
                    }
                    if (c == ';' && depth == 0) { args_end = i; break; }
                }

                std::string args_str = Trim(s.substr(args_start, args_end - args_start));
                if (args_str.empty()) {
                    search_start = s.cbegin() + pos + m.length();
                    continue;
                }

                // Check if the whole expression is wrapped in outer parens:
                //   leading '(' before the format string
                //   trailing ')' after the args
                bool leading_paren = (pos > 0 && s[pos - 1] == '(');
                bool trailing_paren = (args_end < s.size() && s[args_end] == ')');
                bool has_outer_parens = leading_paren && trailing_paren;

                size_t replace_start = has_outer_parens ? pos - 1 : pos;
                size_t replace_end = has_outer_parens ? args_end + 1 : args_end;

                std::vector<std::string> args = SplitFormatArgs(args_str);
                std::string out;
                for (size_t i = 0; i < fmt.size(); ++i) {
                    if (fmt[i] == '{') {
                        size_t j = fmt.find('}', i);
                        if (j == std::string::npos) { out.push_back(fmt[i]); continue; }
                        std::string idx_str = Trim(fmt.substr(i + 1, j - i - 1));
                        int idx = -1;
                        try { idx = std::stoi(idx_str); } catch (...) {}
                        if (idx >= 0 && idx < (int)args.size()) {
                            std::string val = ResolveValue(args[idx], nullptr);
                            out += val;
                        } else {
                            out += fmt.substr(i, j - i + 1);
                        }
                        i = j;
                    } else {
                        out.push_back(fmt[i]);
                    }
                }

                s.replace(replace_start, replace_end - replace_start, out);
                changed = true;
                search_start = s.cbegin() + replace_start + out.size();
            }
            return changed ? s : s;
        } catch (...) {
            return s;
        }
    }

    static std::string ExpandPsVariables(std::string s) {
        try {
            std::regex re(R"((?i)\$\{?([a-zA-Z0-9_`]+)\}?)");
            std::string out;
            size_t last_end = 0;
            bool changed = false;
            for (std::sregex_iterator it(s.begin(), s.end(), re), end; it != end; ++it) {
                const std::smatch& m = *it;
                out.append(s.substr(last_end, m.position() - last_end));
                std::string name = m[1].str();
                std::string unescaped;
                for (char c : name) {
                    if (c != '`') unescaped.push_back(c);
                }
                out += "$" + unescaped;
                last_end = m.position() + m.length();
                changed = true;
            }
            out.append(s.substr(last_end));
            return changed ? out : s;
        } catch (...) { return s; }
    }

    static bool IsInsideDotNetStringMethod(const std::string& s, size_t start, size_t end) {
        if (start == 0) return false;
        size_t paren = s.rfind('(', start - 1);
        if (paren == std::string::npos) return false;
        std::string before = ToLower(s.substr(0, paren));
        bool isMethod = before.find("frombase64string") != std::string::npos ||
                        before.find("getstring") != std::string::npos;
        if (!isMethod) return false;
        return s.find(')', end) != std::string::npos;
    }

    static std::string DecodeBase64Blocks(std::string s) {
        try {
            std::regex re(R"((?:[A-Za-z0-9+/]{4,}={0,2}))");
            std::map<size_t, std::pair<size_t, std::string>, std::greater<size_t>> repls;
            for (std::sregex_iterator it(s.begin(), s.end(), re), end; it != end; ++it) {
                std::string candidate = it->str();
                size_t pos = it->position();
                // Avoid decoding short literal words (e.g. "encoding") that happen
                // to be valid base64; only decode reasonably long blocks that are
                // likely real payloads.
                if (candidate.size() >= 20 && LooksLikeBase64(candidate)) {
                    if (IsInsideDotNetStringMethod(s, pos, pos + candidate.size())) continue;
                    std::string decoded;
                    if (Base64Decode(candidate, decoded) && !decoded.empty()) {
                        int printable = 0;
                        for (unsigned char c : decoded) {
                            if (std::isprint(c) || std::isspace(c)) ++printable;
                        }
                        if (printable * 100 / static_cast<int>(decoded.size()) > 85) {
                            repls[pos] = {candidate.size(), decoded};
                        }
                    }
                }
            }
            for (const auto& kv : repls) {
                s.replace(kv.first, kv.second.first, kv.second.second);
            }
            return s;
        } catch (...) { return s; }
    }

    static std::string ReverseLiteralBlocks(std::string s) {
        std::regex re(R"(-join\s*\(?\s*'([^']+)'\s*\)?)");
        std::smatch m;
        while (std::regex_search(s, m, re)) {
            std::string rev = m[1].str();
            std::reverse(rev.begin(), rev.end());
            s.replace(m.position(), m.length(), "'" + rev + "'");
        }
        return s;
    }

    static std::string ReplacePsAliases(std::string s) {
        std::string t = ToLower(s);
        static const std::pair<const char*, const char*> aliases[] = {
            {"iex", "Invoke-Expression"}, {"gwmi", "Get-WmiObject"},
            {"saps", "Start-Process"}, {"start", "Start-Process"},
            {"ni", "New-Item"}, {"sp", "Set-ItemProperty"},
            {"gp", "Get-ItemProperty"}, {"sc", "Set-Content"},
            {"cat", "Get-Content"}, {"wr", "Write-Output"},
            {"sal", "Set-Alias"}, {"cls", "Clear-Host"},
            {"fl", "Format-List"}, {"ft", "Format-Table"},
            {"epal", "Export-Alias"}, {"ipal", "Import-Alias"}
        };
        for (const auto& p : aliases) {
            std::string pat = "\\b" + std::string(p.first) + "\\b";
            std::regex r(pat);
            s = std::regex_replace(s, r, p.second);
        }
        return s;
    }

    static std::string DetectIex(std::string s) {
        std::string low = ToLower(s);
        size_t pos = 0;
        while ((pos = low.find("invoke-expression", pos)) != std::string::npos) {
            size_t start = pos;
            size_t paren = low.find('(', start);
            if (paren != std::string::npos) {
                size_t end = std::string::npos;
                int depth = 0;
                for (size_t i = paren; i < low.size(); ++i) {
                    if (low[i] == '(') ++depth;
                    else if (low[i] == ')') {
                        if (--depth == 0) { end = i; break; }
                    }
                }
                if (end != std::string::npos) {
                    std::string payload = Trim(s.substr(paren + 1, end - paren - 1));
                    std::string pl = ToLower(payload);
                    if (pl.find("base64") != std::string::npos || pl.find("frombase64string") != std::string::npos ||
                        pl.find("getstring") != std::string::npos || pl.find("iex") != std::string::npos) {
                        s.replace(start, end - start + 1, "Invoke-Expression(OBFUSCATED_BASE64_PAYLOAD)");
                    }
                }
            }
            pos += std::string("invoke-expression").size();
        }
        return s;
    }

    static std::string UnescapePsString(std::string s) {
        std::string out;
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '`' && i + 1 < s.size()) {
                out.push_back(s[++i]);
            } else out.push_back(s[i]);
        }
        return out;
    }
};

/* ============================================================
 *  Tokenizer
 * ============================================================ */
static std::vector<std::string> Tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    char quote = 0;
    int paren = 0;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (quote) {
            cur.push_back(c);
            if (c == quote) quote = 0;
            continue;
        }
        if (c == '\"' || c == '\'') { quote = c; cur.push_back(c); continue; }
        if (c == '(') { ++paren; cur.push_back(c); continue; }
        if (c == ')') { --paren; cur.push_back(c); continue; }
        if (paren > 0) { cur.push_back(c); continue; }
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
        } else if (c == '|' || c == ';' || c == '&') {
            if (!cur.empty()) { out.push_back(cur); cur.clear(); }
            out.push_back(std::string(1, c));
        } else cur.push_back(c);
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

/* ============================================================
 *  Virtual environment
 * ============================================================ */
struct VirtualEnvironment {
    // Shared variables between PS and CMD.
    std::unordered_map<std::string, std::string> variables;
    // Simulated file system: path -> content type tag.
    std::unordered_map<std::string, std::string> files;
    // Simulated registry keys.
    std::unordered_map<std::string, std::string> registry;
    // Simulated network responses: host pattern -> body tag.
    std::unordered_map<std::string, std::string> net_responses;
    // Process table: pid -> {name, ppid, command}
    struct Proc { std::string name; int ppid; std::string cmd; };
    std::unordered_map<int, Proc> processes;
    int next_pid = 1000;
    int next_bid = 1;
    int next_timestamp = 1;

    // Execution limits to prevent infinite loops / fork bombs.
    static constexpr int kMaxExecutionSteps = 2000;
    static constexpr int kMaxProcesses = 500;
    static constexpr int kMaxRecursionDepth = 20;
    int execution_steps = 0;
    int process_count = 0;

    int NewPid() { return next_pid++; }
    int NewBid() { return next_bid++; }
    int Tick() { return next_timestamp++; }

    bool IncStep() {
        if (execution_steps >= kMaxExecutionSteps) return false;
        ++execution_steps;
        return true;
    }

    bool IncProcess() {
        if (process_count >= kMaxProcesses) return false;
        ++process_count;
        return true;
    }

    void DecProcess() { if (process_count > 0) --process_count; }

    VirtualEnvironment() {
        // Seed common system directories as existing.
        files["C:\\Windows\\System32\\cmd.exe"] = "pe";
        files["C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"] = "pe";
        files["C:\\Windows\\System32\\rundll32.exe"] = "pe";
        files["C:\\Windows\\System32\\regsvr32.exe"] = "pe";
        files["C:\\Windows\\System32\\mshta.exe"] = "pe";
        files["C:\\Windows\\System32\\msbuild.exe"] = "pe";
        files["C:\\Windows\\System32\\schtasks.exe"] = "pe";
        files["C:\\Windows\\System32\\vssadmin.exe"] = "pe";
        files["C:\\Windows\\System32\\nltest.exe"] = "pe";
        files["C:\\Windows\\System32\\wmic.exe"] = "pe";
        files["C:\\Windows\\System32\\wscript.exe"] = "pe";
        files["C:\\Windows\\System32\\cscript.exe"] = "pe";
        files["C:\\Windows\\SysWOW64\\cmd.exe"] = "pe";
        files["C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"] = "pe";
        files["C:\\Windows\\System32\\reg.exe"] = "pe";

        // Common PowerShell environment variables used during deobfuscation.
        variables["TEMP"] = "C:\\Users\\User\\AppData\\Local\\Temp";
        variables["TMP"] = "C:\\Users\\User\\AppData\\Local\\Temp";
        variables["APPDATA"] = "C:\\Users\\User\\AppData\\Roaming";
        variables["LOCALAPPDATA"] = "C:\\Users\\User\\AppData\\Local";
        variables["PUBLIC"] = "C:\\Users\\Public";
        variables["PROGRAMDATA"] = "C:\\ProgramData";
        variables["USERPROFILE"] = "C:\\Users\\User";
        variables["WINDIR"] = "C:\\Windows";
        variables["SYSTEMROOT"] = "C:\\Windows";
        variables["COMSPEC"] = "C:\\Windows\\System32\\cmd.exe";
        variables["PSMODULEPATH"] = "C:\\Users\\User\\Documents\\WindowsPowerShell\\Modules";

        // Browser / credential paths.
        files["C:\\Users\\User\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"] = "credentials";
        files["C:\\Users\\User\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\xxx.default\\logins.json"] = "credentials";
        files["C:\\Users\\User\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"] = "credentials";
        files["C:\\Users\\User\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"] = "history";

        // Network response defaults.
        net_responses["*"] = "binary_payload";
        net_responses["invoice"] = "dll_payload";
        net_responses["doc"] = "dll_payload";
        net_responses["discord"] = "autoit_payload";
        net_responses["smtp.mail.com"] = "smtp_ok";
        net_responses["api/send"] = "exfil_ok";
    }
};

/* ============================================================
 *  Behavior recorder
 * ============================================================ */
class BehaviorRecorder {
public:
    explicit BehaviorRecorder(VirtualEnvironment& env) : env_(env) {}

    BehaviorRecord Record(const std::string& action, const std::string& target,
                          const std::string& details, int parent_id = -1,
                          const std::string& source = "sandbox", int pid = 0, int ppid = -1) {
        BehaviorRecord r;
        r.id = env_.NewBid();
        r.timestamp = env_.Tick();
        r.action = action;
        r.target = target;
        r.details = details;
        r.parent_id = parent_id;
        r.source = source;
        r.pid = pid;
        r.ppid = ppid;
        records_.push_back(r);
        last_by_action_[action] = r.id;
        return r;
    }

    int LastActionId(const std::string& action) const {
        auto it = last_by_action_.find(action);
        return it == last_by_action_.end() ? -1 : it->second;
    }

    const std::vector<BehaviorRecord>& Records() const { return records_; }

    // Build causal links: a FileWrite after a NetworkConnect to related URL becomes a child.
    void LinkRelated() {
        for (auto& r : records_) {
            if (r.action == "FileWrite") {
                std::string low = ToLower(r.target);
                for (const auto& p : records_) {
                    if (p.action == "NetworkConnect" && p.timestamp < r.timestamp &&
                        r.timestamp - p.timestamp < 20) {
                        std::string url = ToLower(p.target);
                        if ((Contains(url, "invoice") && Contains(low, ".dll")) ||
                            (Contains(url, "doc") && Contains(low, ".dll")) ||
                            (Contains(url, "discord") && Contains(low, ".au3")) ||
                            (Contains(url, "http") && Contains(low, "\\programdata\\")) ||
                            (Contains(url, ".dll") && EndsWith(low, ".dll"))) {
                            r.parent_id = p.id;
                            break;
                        }
                    }
                }
            }
            if (r.action == "NetworkConnect" && Contains(r.details, "exfil")) {
                for (const auto& p : records_) {
                    if ((p.action == "FileRead" || p.action == "RegRead") &&
                        p.timestamp < r.timestamp && r.timestamp - p.timestamp < 30) {
                        if (r.parent_id < 0) r.parent_id = p.id;
                    }
                }
            }
        }
    }

private:
    VirtualEnvironment& env_;
    std::vector<BehaviorRecord> records_;
    std::unordered_map<std::string, int> last_by_action_;
};

/* ============================================================
 *  Chain detector
 * ============================================================ */
struct ChainStep {
    std::string action;
    std::function<bool(const BehaviorRecord&)> matcher;
    int max_interval = 30;  // max simulated ticks after previous step.
};

struct FamilyChain {
    std::string family;
    std::vector<ChainStep> steps;
    int min_match = 3;
    int severity = 75;
};

class ChainDetector {
public:
    ChainDetector() { BuildRules(); }

    struct Match {
        std::string family;
        int matched_steps = 0;
        int total_steps = 0;
        int order_score = 0;
        std::vector<std::string> evidence;
    };

    std::vector<Match> Detect(const std::vector<BehaviorRecord>& records) const {
        std::vector<Match> matches;
        for (const auto& rule : rules_) {
            Match m = MatchRule(records, rule);
            if (m.matched_steps >= rule.min_match) {
                m.family = rule.family;
                matches.push_back(m);
            }
        }
        return matches;
    }

private:
    std::vector<FamilyChain> rules_;

    void BuildRules() {
        using BR = const BehaviorRecord&;
        auto net_invoice = [](BR r) { return r.action == "NetworkConnect" &&
                                             (Contains(ToLower(r.target), "invoice") ||
                                              Contains(ToLower(r.target), "doc")); };
        auto file_dll_programdata = [](BR r) {
            return r.action == "FileWrite" && Contains(ToLower(r.target), "programdata") &&
                   EndsWith(ToLower(r.target), ".dll");
        };
        auto proc_rundll = [](BR r) {
            return r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "rundll32");
        };
        auto schtasks = [](BR r) {
            return r.action == "SchtasksCreate" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "schtasks"));
        };
        auto regsave = [](BR r) {
            return r.action == "RegSave" || (r.action == "ProcessCreate" &&
                                             Contains(ToLower(r.target), "reg save"));
        };

        rules_.push_back({"BSD/Trojan-Downloader.Win32.Emotet",
                          {{"NetworkConnect", net_invoice},
                           {"FileWrite", file_dll_programdata},
                           {"ProcessCreate", proc_rundll},
                           {"SchtasksCreate", schtasks},
                           {"RegSave", regsave}},
                          3, 85});

        auto mem_key = [](BR r) {
            return r.action == "MemoryAlloc" &&
                   (Contains(ToLower(r.details), "getasynckeystate") ||
                    Contains(ToLower(r.details), "keylogger"));
        };
        auto read_browser = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "chrome") ||
                    Contains(ToLower(r.target), "firefox") ||
                    Contains(ToLower(r.target), "edge") ||
                    Contains(ToLower(r.target), "login data"));
        };
        auto smtp_exfil = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), "smtp") || Contains(ToLower(r.target), "ftp"));
        };
        rules_.push_back({"BSD/Trojan-Spy.Win32.AgentTesla",
                          {{"MemoryAlloc", mem_key},
                           {"FileRead", read_browser},
                           {"NetworkConnect", smtp_exfil}},
                          3, 90});

        auto refl = [](BR r) {
            return r.action == "ReflectionLoad" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "reflect"));
        };
        auto recon = [](BR r) {
            return r.action == "ProcessCreate" &&
                   (Contains(ToLower(r.target), "nltest") ||
                    Contains(ToLower(r.target), "net group") ||
                    Contains(ToLower(r.target), "domain admins"));
        };
        auto wmi_lat = [](BR r) {
            return r.action == "WMIRemoteExec" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "wmic") &&
                    Contains(ToLower(r.target), "/node"));
        };
        auto zip_browser = [](BR r) {
            return r.action == "FileWrite" && Contains(ToLower(r.target), "appdata") &&
                   EndsWith(ToLower(r.target), ".zip");
        };
        auto disdef = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.details), "defender") &&
                   Contains(ToLower(r.details), "disable");
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.TrickBot",
                          {{"ReflectionLoad", refl},
                           {"ProcessCreate", recon},
                           {"WMIRemoteExec", wmi_lat},
                           {"FileWrite", zip_browser},
                           {"RegSetValue", disdef}},
                          3, 88});

        auto cs_load = [](BR r) {
            return r.action == "ReflectionLoad" &&
                   Contains(ToLower(r.details), ".net assembly");
        };
        auto pipe = [](BR r) {
            return r.action == "NamedPipeConnect" || r.action == "NamedPipeRead" ||
                   r.action == "NamedPipeWrite";
        };
        auto msbuild = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "msbuild");
        };
        rules_.push_back({"BSD/Trojan-Dropper.Win32.CobaltStrike",
                          {{"ReflectionLoad", cs_load},
                           {"NamedPipeConnect", pipe},
                           {"ProcessCreate", msbuild}},
                          2, 85});

        auto read_many = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "wallet") ||
                    Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "login data"));
        };
        auto wmic_sys = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "wmic") &&
                   (Contains(ToLower(r.target), "cpu") || Contains(ToLower(r.target), "gpu"));
        };
        auto post_exfil = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), "/api/send") ||
                    Contains(ToLower(r.details), "post"));
        };
        rules_.push_back({"BSD/Trojan-Spy.Win32.RedLine",
                          {{"FileRead", read_many},
                           {"ProcessCreate", wmic_sys},
                           {"FileWrite", [](BR r) {
                                return r.action == "FileWrite" &&
                                       Contains(ToLower(r.target), "\\temp\\") &&
                                       EndsWith(ToLower(r.target), ".zip");
                            }},
                           {"NetworkConnect", post_exfil}},
                          3, 86});

        auto mass_enc = [](BR r) {
            return r.action == "FileWrite" &&
                   (Contains(ToLower(r.target), ".lockbit") ||
                    Contains(ToLower(r.target), ".abcd"));
        };
        auto vss = [](BR r) {
            return (r.action == "ProcessCreate" || r.action == "BackupDeletion") &&
                   Contains(ToLower(r.details), "vssadmin delete shadows");
        };
        auto stopsvc = [](BR r) {
            return r.action == "ServiceStop" ||
                   (r.action == "ProcessCreate" &&
                    Contains(ToLower(r.target), "net stop"));
        };
        auto ransom_note = [](BR r) {
            return r.action == "FileWrite" &&
                   (Contains(ToLower(r.target), "readme") ||
                    Contains(ToLower(r.target), "restore"));
        };
        rules_.push_back({"BSD/Trojan-Ransom.Win32.LockBit",
                          {{"FileWrite", mass_enc},
                           {"ProcessCreate", vss},
                           {"ServiceStop", stopsvc},
                           {"FileWrite", ransom_note}},
                          3, 95});

        // Wiper / destructive malware chain: disables security, deletes backups,
        // tampers boot config, and mass-deletes system files.
        auto wiper_reg = [](BR r) {
            std::string target = ToLower(r.target);
            std::string details = ToLower(r.details);

            return
                (
                    r.action == "RegSetValue" &&
                    (
                        Contains(details, "defender") ||
                        Contains(details, "disablesr")
                    )
                )
                ||
                (
                    r.action == "RegDelete" &&
                    (
                        StartsWith(target, "hku\\") ||
                        StartsWith(target, "hkcr\\") ||
                        StartsWith(target, "hklm\\") ||
                        StartsWith(target, "hkcu\\") ||
                        Contains(target, "sam") ||
                        Contains(target, "security") ||
                        Contains(target, "bcd")
                    )
                );
        };
        auto wiper_svc = [](BR r) {
            std::string target = ToLower(r.target);
            std::string details = ToLower(r.details);

            return
                (
                    r.action == "ServiceStop" &&
                    (
                        Contains(details, "windefend") ||
                        Contains(details, "defend")
                    )
                )
                ||
                (
                    r.action == "ProcessCreate" &&
                    (
                        Contains(target, "taskkill") ||
                        Contains(details, "taskkill")
                    )
                );
        };
        auto wiper_sys = [](BR r) {
            std::string target = ToLower(r.target);
            std::string details = ToLower(r.details);

            return r.action == "SystemConfig" &&
                   (
                       Contains(details, "recoveryenabled") ||
                       Contains(details, "bootstatuspolicy") ||
                       Contains(target, "mountvol") ||
                       Contains(details, "mountvol") ||
                       Contains(details, "\\efi")
                   );
        };
        auto wiper_bak = [](BR r) {
            return r.action == "BackupDeletion" &&
                   (Contains(ToLower(r.details), "vssadmin") ||
                    Contains(ToLower(r.details), "shadowcopy"));
        };
        auto wiper_del = [](BR r) {
            std::string target = ToLower(r.target);
            std::string details = ToLower(r.details);

            return r.action == "FileDelete" &&
                   (
                       Contains(details, "c:\\windows") ||
                       Contains(details, "*.exe") ||
                       Contains(details, "*.dll") ||
                       Contains(details, "*.*") ||
                       Contains(details, "\\efi") ||
                       Contains(details, "x:\\") ||
                       Contains(target, "mass_delete")
                   );
        };
        rules_.push_back({"BSD/Trojan-Dropper.Win32.WinKiller",
                          {{"RegSetValue", wiper_reg},
                           {"ServiceStop", wiper_svc},
                           {"SystemConfig", wiper_sys},
                           {"BackupDeletion", wiper_bak},
                           {"FileDelete", wiper_del}},
                          3, 95});

        auto destructive_delete = [](BR r) {
            if (r.action != "FileDelete") {
                return false;
            }

            std::string target = ToLower(r.target);
            std::string details = ToLower(r.details);

            return
                Contains(target, "mass_delete") ||
                Contains(details, "*.*") ||
                Contains(details, "\\efi") ||
                Contains(details, "x:\\") ||
                Contains(details, "del /") ||
                Contains(details, "erase ");
        };

        auto terminate_shell = [](BR r) {
            if (r.action != "ProcessCreate") {
                return false;
            }

            std::string target = ToLower(r.target);
            std::string details = ToLower(r.details);

            return
                Contains(target, "taskkill") ||
                Contains(details, "taskkill");
        };

        auto delete_registry = [](BR r) {
            if (r.action != "RegDelete") {
                return false;
            }

            std::string target = ToLower(r.target);

            return
                StartsWith(target, "hku\\") ||
                StartsWith(target, "hkcr\\") ||
                StartsWith(target, "hklm\\") ||
                StartsWith(target, "hkcu\\") ||
                Contains(target, "sam") ||
                Contains(target, "security") ||
                Contains(target, "bcd");
        };

        rules_.push_back({
            "BSD/Trojan-Dropper.Win32.WinKiller",
            {
                {"FileDelete", destructive_delete},
                {"ProcessCreate", terminate_shell},
                {"RegDelete", delete_registry}
            },
            3,
            98
        });

        /* ============================================================
         *  WinKiller 变形：MBR/DBR 直写检测
         *  覆盖 VBS / CMD / PS1 任意脚本尝试写入主引导记录/分区引导记录
         *  的行为。只要命中一次即判毒（min_match=1, severity=100）。
         *  样本：shell.Run "dd if=/dev/zero of=\\.\PhysicalDrive0 bs=512 count=1"
         * ============================================================ */
        auto mbr_dbr_write = [](BR r) {
            /* 仅关注可能携带写盘命令的行为类别 */
            if (r.action != "ProcessCreate" &&
                r.action != "FileWrite" &&
                r.action != "FileOpen" &&
                r.action != "RawDiskWrite") {
                return false;
            }

            std::string tgt = ToLower(r.target);
            std::string det = ToLower(r.details);

            /* 合并扫描便于匹配 */
            std::string blob = tgt + " " + det;

            /* Windows 物理磁盘直写路径（最关键信号）
             * 注意：JsUnescape 会把 \\ → \，所以同时匹配单/双反斜杠两种形态 */
            if (Contains(blob, "physicaldrive") &&
                (Contains(blob, "\\\\.\\") ||    /* 双反斜杠：\\.\PhysicalDrive0 */
                 Contains(blob, "\\.\\") ||      /* 单反斜杠：\.\PhysicalDrive0 (经unescape) */
                 Contains(blob, "\\\\.") ||
                 Contains(blob, "\\.\\"))) {
                return true;
            }
            /* 任意 physicaldrive + 写盘关键字（兜底，不依赖反斜杠形态） */
            if (Contains(blob, "physicaldrive") &&
                (Contains(blob, " of=") ||
                 Contains(blob, "out-file") ||
                 Contains(blob, "set-content") ||
                 Contains(blob, "add-content") ||
                 Contains(blob, "openwrite") ||
                 Contains(blob, "createfile") ||
                 Contains(blob, "deviceiocontrol") ||
                 Contains(blob, "format ") ||
                 Contains(blob, "fsutil") ||
                 Contains(blob, "diskpart"))) {
                return true;
            }

            if (Contains(blob, "\\\\.\\globalroot\\device\\harddisk")) return true;
            if (Contains(blob, "\\.\\globalroot\\device\\harddisk")) return true;
            if (Contains(blob, "device\\harddisk") &&
                (Contains(blob, " of=") || Contains(blob, "write"))) return true;

            /* dd 命令写盘：dd if=... of=\\.\PhysicalDriveN 或 of=/dev/sdX */
            if (Contains(blob, "dd ") && Contains(blob, " of=") &&
                (Contains(blob, "physicaldrive") ||
                 Contains(blob, "/dev/sd") ||
                 Contains(blob, "/dev/nvme") ||
                 Contains(blob, "/dev/rdisk"))) {
                return true;
            }

            /* PowerShell .NET 直写：[IO.File]::OpenWrite / Create 指向 PhysicalDrive */
            if (Contains(blob, "openwrite") && Contains(blob, "physicaldrive")) return true;
            if (Contains(blob, "[io.file]::create") && Contains(blob, "physicaldrive")) return true;
            if (Contains(blob, "[system.io.file]::") && Contains(blob, "physicaldrive")) return true;

            /* diskpart clean 指令（清空磁盘，可能破坏 MBR） */
            if (Contains(blob, "diskpart") && Contains(blob, "clean")) return true;

            /* 显式 MBR/DBR/BootSector 写入关键字 */
            if (Contains(blob, "mbr write") ||
                Contains(blob, "dbr write") ||
                Contains(blob, "boot sector write") ||
                Contains(blob, "write mbr") ||
                Contains(blob, "write dbr") ||
                Contains(blob, "overwrite mbr") ||
                Contains(blob, "overwrite boot")) {
                return true;
            }

            /* RawDiskWrite 行为（若有专门发射点） */
            if (r.action == "RawDiskWrite") return true;

            return false;
        };

        rules_.push_back({"BSD/Trojan-Dropper.Win32.MBRWriter",
                          {{"RawDiskWrite", mbr_dbr_write}},
                          1, 100});

        auto discord = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), "discord");
        };
        auto autoit = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".au3");
        };
        auto autoit_run = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "autoit");
        };
        auto hollow = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "hollow"));
        };
        rules_.push_back({"BSD/Trojan-Downloader.Win32.DarkGate",
                          {{"NetworkConnect", discord},
                           {"FileWrite", autoit},
                           {"ProcessCreate", autoit_run},
                           {"ProcessHollowing", hollow}},
                          3, 84});

        auto qak_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ".html") ||
                    Contains(ToLower(r.target), "office"));
        };
        auto qak_dll = [](BR r) {
            return r.action == "FileWrite" &&
                   (Contains(ToLower(r.target), "\\programdata\\") ||
                    Contains(ToLower(r.target), "\\public\\")) &&
                   EndsWith(ToLower(r.target), ".dll");
        };
        auto qak_regsvr = [](BR r) {
            return r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "regsvr32");
        };
        auto qak_sched = [](BR r) {
            return r.action == "SchtasksCreate" &&
                   Contains(ToLower(r.details), "regsvr32");
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.QakBot",
                          {{"NetworkConnect", qak_dl},
                           {"FileWrite", qak_dll},
                           {"ProcessCreate", qak_regsvr},
                           {"SchtasksCreate", qak_sched}},
                          3, 83});

        auto iced_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ".zip") ||
                    Contains(ToLower(r.target), ".cab"));
        };
        auto iced_dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll") &&
                   (Contains(ToLower(r.target), "\\programdata\\") ||
                    Contains(ToLower(r.target), "\\appdata\\"));
        };
        auto iced_rundll = [](BR r) {
            return r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "rundll32") &&
                   Contains(ToLower(r.target), "icedid");
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.IcedID",
                          {{"NetworkConnect", iced_dl},
                           {"FileWrite", iced_dll},
                           {"ProcessCreate", iced_rundll}},
                          3, 82});

        auto bumb_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), "iso") ||
                    Contains(ToLower(r.target), "img"));
        };
        auto bumb_lnk = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".lnk");
        };
        auto bumb_ps = [](BR r) {
            return r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "powershell");
        };
        rules_.push_back({"BSD/Trojan-Downloader.Win32.BumbleBee",
                          {{"NetworkConnect", bumb_dl},
                           {"FileWrite", bumb_lnk},
                           {"ProcessCreate", bumb_ps}},
                          3, 81});

        auto remc_drop = [](BR r) {
            return r.action == "FileWrite" &&
                   (Contains(ToLower(r.target), "\\remcos") ||
                    Contains(ToLower(r.target), "remcos"));
        };
        auto remc_reg = [](BR r) {
            return r.action == "RegSetValue" &&
                   Contains(ToLower(r.target), "\\run");
        };
        auto remc_inj = [](BR r) {
            return r.action == "ProcessHollowing" || r.action == "MemoryAlloc";
        };
        rules_.push_back({"BSD/Trojan-Spy.Win32.Remcos",
                          {{"FileWrite", remc_drop},
                           {"RegSetValue", remc_reg},
                           {"ProcessHollowing", remc_inj}},
                          3, 84});

        asyncrat_steps();
        dridex_steps();
        ursnif_steps();
        zeus_steps();
        iex_base64_steps();
        danabot_steps();
        conti_steps();
        revil_steps();
        blackcat_steps();
        hive_steps();
        darkside_steps();
        clop_steps();
        ryuk_steps();
        vidar_steps();
        raccoon_steps();
        mars_steps();
        azorult_steps();
        formbook_steps();
        njrat_steps();
        nanocore_steps();
        darkcomet_steps();
        quasarrat_steps();
        poisonivy_steps();
        smokeloader_steps();
        gootloader_steps();
        socgholish_steps();
        plugx_steps();
        shadowpad_steps();
        sliverfox_steps();
        snakekeylogger_steps();
        http_dropper_steps();
        additional_families_steps();
        more_families_steps();
    }

    void http_dropper_steps() {
        using BR = const BehaviorRecord&;
        auto http_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (StartsWith(ToLower(r.target), "http://") ||
                    StartsWith(ToLower(r.target), "https://")) &&
                   Contains(ToLower(r.target), ".exe");
        };
        auto exe_write = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".exe") &&
                   (Contains(ToLower(r.target), "\\temp\\") ||
                    Contains(ToLower(r.target), "\\appdata\\") ||
                    Contains(ToLower(r.target), "\\public\\") ||
                    Contains(ToLower(r.target), "\\programdata\\"));
        };
        auto exe_run = [](BR r) {
            return r.action == "ProcessCreate" && EndsWith(ToLower(r.target), ".exe") &&
                   (Contains(ToLower(r.target), "\\temp\\") ||
                    Contains(ToLower(r.target), "\\appdata\\") ||
                    Contains(ToLower(r.target), "\\public\\") ||
                    Contains(ToLower(r.target), "\\programdata\\"));
        };
        rules_.push_back({"BSD/Trojan-Downloader.Win32.HttpDropper",
                          {{"NetworkConnect", http_dl},
                           {"FileWrite", exe_write},
                           {"ProcessCreate", exe_run}},
                          3, 85});

        // Extra loose rule for obfuscated downloaders where the path is built from
        // $env:TEMP and may not contain the canonical directory names yet.
        auto any_exe_write = [](BR r) {
            if (r.action != "FileWrite") return false;
            std::string t = ToLower(r.target);
            return EndsWith(t, ".exe") &&
                   (Contains(t, "\\temp\\") || Contains(t, "\\appdata\\") ||
                    Contains(t, "\\public\\") || Contains(t, "\\programdata\\"));
        };
        auto any_exe_run = [](BR r) {
            if (r.action != "ProcessCreate") return false;
            std::string t = ToLower(r.target);
            return EndsWith(t, ".exe") &&
                   (Contains(t, "\\temp\\") || Contains(t, "\\appdata\\") ||
                    Contains(t, "\\public\\") || Contains(t, "\\programdata\\"));
        };
        rules_.push_back({"BSD/Trojan-Downloader.Win32.HttpDropper.Loose",
                          {{"NetworkConnect", http_dl},
                           {"FileWrite", any_exe_write},
                           {"ProcessCreate", any_exe_run}},
                          3, 82});

        // Obfuscated PowerShell that uses IEX/Invoke-Expression to run a payload
        // containing both an HTTP download and a subsequent process start.
        auto iex_obf = [](BR r) {
            return r.action == "IEXExecute" ||
                   (r.action == "Base64Decode" && Contains(ToLower(r.details), "invoke-expression"));
        };
        auto iex_http_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (StartsWith(ToLower(r.target), "http://") ||
                    StartsWith(ToLower(r.target), "https://"));
        };
        rules_.push_back({"BSD/Trojan-Downloader.Win32.ObfuscatedHttp",
                          {{"IEXExecute", iex_obf},
                           {"NetworkConnect", iex_http_dl},
                           {"FileWrite", any_exe_write},
                           {"ProcessCreate", any_exe_run}},
                          3, 84});
    }

    void additional_families_steps() {
        using BR = const BehaviorRecord&;

        // LummaStealer: browser credential theft + crypto wallet exfil
        auto lumma_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "web data") ||
                    Contains(ToLower(r.target), "wallet"));
        };
        auto lumma_zip = [](BR r) {
            return r.action == "FileWrite" &&
                   (EndsWith(ToLower(r.target), ".zip") || EndsWith(ToLower(r.target), ".7z"));
        };
        auto lumma_c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ".php") ||
                    Contains(ToLower(r.target), ".png") ||
                    Contains(ToLower(r.target), ".gif"));
        };
        rules_.push_back({"BSD/TrojanSpy.LummaStealer",
                          {{"FileRead", lumma_read},
                           {"FileWrite", lumma_zip},
                           {"NetworkConnect", lumma_c2}},
                          3, 86});

        // Stealc: browser/credential theft via SMTP/HTTP
        auto stealc_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "cookies.sqlite") ||
                    Contains(ToLower(r.target), "key4.db"));
        };
        auto stealc_mem = [](BR r) {
            return r.action == "MemoryAlloc" &&
                   Contains(ToLower(r.details), "stealc");
        };
        auto stealc_exfil = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ":443") ||
                    Contains(ToLower(r.target), ":80"));
        };
        rules_.push_back({"BSD/Trojan-PSW.Win32.Stealc",
                          {{"FileRead", stealc_read},
                           {"MemoryAlloc", stealc_mem},
                           {"NetworkConnect", stealc_exfil}},
                          3, 85});

        // RisePro: infostealer with Telegram/Discord exfil
        auto rise_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "logins.json") ||
                    Contains(ToLower(r.target), "login data"));
        };
        auto rise_tele = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "api.telegram.org");
        };
        rules_.push_back({"BSD/Trojan-PSW.Win32.RisePro",
                          {{"FileRead", rise_read},
                           {"FileWrite", [](BR r) { return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip"); }},
                           {"NetworkConnect", rise_tele}},
                          3, 85});

        // MysticStealer: browser/crypto wallet theft
        auto mystic_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "wallet.dat") ||
                    Contains(ToLower(r.target), "cookies"));
        };
        auto mystic_c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ".php") || Contains(ToLower(r.target), "panel"));
        };
        rules_.push_back({"BSD/Trojan-PSW.Win32.MysticStealer",
                          {{"FileRead", mystic_read},
                           {"MemoryAlloc", [](BR r) { return r.action == "MemoryAlloc" && Contains(ToLower(r.details), "mystic"); }},
                           {"NetworkConnect", mystic_c2}},
                          3, 84});

        // MeduzaStealer: browser session theft
        auto meduza_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "leveldb") ||
                    Contains(ToLower(r.target), "network"));
        };
        auto meduza_c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "/gate");
        };
        rules_.push_back({"BSD/Trojan-PSW.Win32.MeduzaStealer",
                          {{"FileRead", meduza_read},
                           {"FileWrite", [](BR r) { return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip"); }},
                           {"NetworkConnect", meduza_c2}},
                          3, 84});

        // WarzoneRAT: keylogging + screenshot + C2
        auto warz_key = [](BR r) {
            return r.action == "MemoryAlloc" &&
                   (Contains(ToLower(r.details), "keylog") || Contains(ToLower(r.details), "hook"));
        };
        auto warz_screen = [](BR r) {
            return r.action == "FileWrite" &&
                   (EndsWith(ToLower(r.target), ".png") || EndsWith(ToLower(r.target), ".jpg"));
        };
        auto warz_c2 = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), "warzone");
        };
        rules_.push_back({"BSD/Backdoor.Win32.WarzoneRAT",
                          {{"MemoryAlloc", warz_key},
                           {"FileWrite", warz_screen},
                           {"NetworkConnect", warz_c2}},
                          3, 84});

        // XWorm: USB spread + Telegram C2 + ransomware prep
        auto xworm_usb = [](BR r) {
            return r.action == "FileWrite" &&
                   Contains(ToLower(r.target), "\\$recycle.bin");
        };
        auto xworm_tele = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "api.telegram.org");
        };
        auto xworm_del = [](BR r) {
            return r.action == "FileDelete" || r.action == "BackupDeletion";
        };
        rules_.push_back({"BSD/Backdoor.Win32.XWorm",
                          {{"FileWrite", xworm_usb},
                           {"NetworkConnect", xworm_tele},
                           {"FileDelete", xworm_del}},
                          3, 84});

        // OrcusRAT: .NET RAT with plugin loading
        auto orcus_load = [](BR r) {
            return r.action == "ReflectionLoad" ||
                   (r.action == "FileRead" && EndsWith(ToLower(r.target), ".dll"));
        };
        auto orcus_proc = [](BR r) {
            return r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "regsvr32");
        };
        auto orcus_c2 = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), "orcus");
        };
        rules_.push_back({"BSD/Backdoor.Win32.OrcusRAT",
                          {{"ReflectionLoad", orcus_load},
                           {"ProcessCreate", orcus_proc},
                           {"NetworkConnect", orcus_c2}},
                          3, 83});

        // Njrat: USB spread + registry persistence + screenshot
        auto njrat_persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        auto njrat_screen = [](BR r) {
            return r.action == "FileWrite" &&
                   (EndsWith(ToLower(r.target), ".png") || EndsWith(ToLower(r.target), ".jpg"));
        };
        auto njrat_usb = [](BR r) {
            return r.action == "FileWrite" &&
                   Contains(ToLower(r.target), "\\$recycle.bin");
        };
        rules_.push_back({"BSD/Backdoor.Win32.NjRAT",
                          {{"RegSetValue", njrat_persist},
                           {"FileWrite", njrat_screen},
                           {"FileWrite", njrat_usb}},
                          3, 83});

        // Amadey: downloader + AV disable + payload fetch
        auto amadey_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ".exe") || Contains(ToLower(r.target), ".dll"));
        };
        auto amadey_av = [](BR r) {
            return r.action == "RegSetValue" &&
                   Contains(ToLower(r.details), "defender");
        };
        auto amadey_run = [](BR r) {
            return r.action == "ProcessCreate" &&
                   (Contains(ToLower(r.target), "regsvr32") ||
                    Contains(ToLower(r.target), "rundll32"));
        };
        rules_.push_back({"BSD/Trojan-Downloader.Win32.Amadey",
                          {{"NetworkConnect", amadey_dl},
                           {"RegSetValue", amadey_av},
                           {"ProcessCreate", amadey_run}},
                          3, 82});
    }

    void more_families_steps() {
        using BR = const BehaviorRecord&;

        // LokiBot: credential stealer that uses SMTP/HTTP exfil and writes a .bin staging file.
        auto loki_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "web data"));
        };
        auto loki_stage = [](BR r) {
            return r.action == "FileWrite" &&
                   (EndsWith(ToLower(r.target), ".bin") || EndsWith(ToLower(r.target), ".tmp"));
        };
        auto loki_exfil = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ":25") || Contains(ToLower(r.target), ":587"));
        };
        rules_.push_back({"BSD/Trojan-PSW.Win32.LokiBot",
                          {{"FileRead", loki_read},
                           {"FileWrite", loki_stage},
                           {"NetworkConnect", loki_exfil}},
                          3, 86});

        // HawkEye Keylogger: keylogging, clipboard capture and SMTP exfiltration.
        auto hawk_key = [](BR r) {
            return r.action == "MemoryAlloc" &&
                   (Contains(ToLower(r.details), "keylog") || Contains(ToLower(r.details), "clipboard"));
        };
        auto hawk_log = [](BR r) {
            return r.action == "FileWrite" &&
                   (EndsWith(ToLower(r.target), ".log") || EndsWith(ToLower(r.target), ".txt"));
        };
        auto hawk_smtp = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ":25") || Contains(ToLower(r.target), ":587"));
        };
        rules_.push_back({"BSD/TrojanSpy.HawkEye",
                          {{"MemoryAlloc", hawk_key},
                           {"FileWrite", hawk_log},
                           {"NetworkConnect", hawk_smtp}},
                          3, 85});

        // Pony Stealer: browser/credential theft and FTP exfiltration.
        auto pony_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "wallet") ||
                    Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "login data"));
        };
        auto pony_ftp = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (StartsWith(ToLower(r.target), "ftp://") || Contains(ToLower(r.target), ":21"));
        };
        rules_.push_back({"BSD/TrojanSpy.Pony",
                          {{"FileRead", pony_read},
                           {"FileWrite", [](BR r) { return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip"); }},
                           {"NetworkConnect", pony_ftp}},
                          3, 84});

        // FickerStealer: browser credential theft + crypto wallet + Telegram exfil.
        auto fick_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "wallet") ||
                    Contains(ToLower(r.target), "cookies"));
        };
        auto fick_tele = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), "api.telegram.org");
        };
        rules_.push_back({"BSD/TrojanSpy.FickerStealer",
                          {{"FileRead", fick_read},
                           {"FileWrite", [](BR r) { return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip"); }},
                           {"NetworkConnect", fick_tele}},
                          3, 84});

        // BlackMatter ransomware: encrypt + delete backups + stop services.
        auto black_enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".blackmatter");
        };
        auto black_bak = [](BR r) {
            return r.action == "BackupDeletion" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.details), "vssadmin"));
        };
        auto black_svc = [](BR r) {
            return r.action == "ServiceStop" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "net stop"));
        };
        rules_.push_back({"BSD/Ransomware.BlackMatter",
                          {{"FileWrite", black_enc},
                           {"BackupDeletion", black_bak},
                           {"ServiceStop", black_svc}},
                          3, 95});

        // Pysa (Mespinoza) ransomware: encrypt + delete shadows + steal data.
        auto pysa_enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".pysa");
        };
        auto pysa_bak = [](BR r) {
            return r.action == "BackupDeletion" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.details), "vssadmin"));
        };
        auto pysa_read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") || Contains(ToLower(r.target), "document"));
        };
        rules_.push_back({"BSD/Ransomware.Pysa",
                          {{"FileRead", pysa_read},
                           {"FileWrite", pysa_enc},
                           {"BackupDeletion", pysa_bak}},
                          3, 94});

        // Maze ransomware: file encryption, data leak site upload and backup deletion.
        auto maze_enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".maze");
        };
        auto maze_leak = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), "maze");
        };
        auto maze_bak = [](BR r) {
            return r.action == "BackupDeletion";
        };
        rules_.push_back({"BSD/Ransomware.Maze",
                          {{"FileWrite", maze_enc},
                           {"NetworkConnect", maze_leak},
                           {"BackupDeletion", maze_bak}},
                          3, 95});

        // Egregor ransomware: mass encryption + printing ransom note + backup deletion.
        auto egr_enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".egregor");
        };
        auto egr_note = [](BR r) {
            return r.action == "FileWrite" &&
                   Contains(ToLower(r.target), "recover-files");
        };
        auto egr_bak = [](BR r) {
            return r.action == "BackupDeletion" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.details), "vssadmin"));
        };
        rules_.push_back({"BSD/Ransomware.Egregor",
                          {{"FileWrite", egr_enc},
                           {"FileWrite", egr_note},
                           {"BackupDeletion", egr_bak}},
                          3, 94});

        // SunBurst: supply-chain backdoor with Orion context and dormant C2.
        auto sun_orion = [](BR r) {
            return r.action == "FileRead" && Contains(ToLower(r.target), "solarwinds");
        };
        auto sun_c2 = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), "avsvmcloud");
        };
        auto sun_inj = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "inject"));
        };
        rules_.push_back({"BSD/Backdoor.Win32.SunBurst",
                          {{"FileRead", sun_orion},
                           {"NetworkConnect", sun_c2},
                           {"ProcessHollowing", sun_inj}},
                          3, 90});

        // LemonDuck: cryptominer/worm that spreads via SMB and schedules tasks.
        auto lemon_smb = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ":445") || Contains(ToLower(r.target), ":135"));
        };
        auto lemon_sched = [](BR r) {
            return r.action == "SchtasksCreate" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "schtasks"));
        };
        auto lemon_miner = [](BR r) {
            return r.action == "ProcessCreate" &&
                   (Contains(ToLower(r.target), "xmrig") || Contains(ToLower(r.details), "miner"));
        };
        rules_.push_back({"BSD/Miner.LemonDuck",
                          {{"NetworkConnect", lemon_smb},
                           {"SchtasksCreate", lemon_sched},
                           {"ProcessCreate", lemon_miner}},
                          3, 85});
    }

    void asyncrat_steps() {
        using BR = const BehaviorRecord&;
        auto ar_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "pastebin");
        };
        auto ar_ps = [](BR r) {
            return r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "powershell");
        };
        auto ar_inj = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "inject"));
        };
        auto ar_persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        auto ar_c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ":") &&
                    !Contains(ToLower(r.target), "pastebin"));
        };
        rules_.push_back({"BSD/Trojan-Spy.Win32.AsyncRAT",
                          {{"NetworkConnect", ar_dl},
                           {"ProcessCreate", ar_ps},
                           {"ProcessHollowing", ar_inj},
                           {"RegSetValue", ar_persist},
                           {"NetworkConnect", ar_c2}},
                          3, 85});
    }

    void dridex_steps() {
        using BR = const BehaviorRecord&;
        auto dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), ".exe") ||
                    Contains(ToLower(r.target), ".dll") ||
                    Contains(ToLower(r.target), "payload"));
        };
        auto drop = [](BR r) {
            return r.action == "FileWrite" &&
                   (Contains(ToLower(r.target), "\\appdata\\") ||
                    Contains(ToLower(r.target), "\\temp\\")) &&
                   EndsWith(ToLower(r.target), ".dll");
        };
        auto inject = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "inject"));
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.Dridex",
                          {{"NetworkConnect", dl},
                           {"FileWrite", drop},
                           {"ProcessHollowing", inject},
                           {"RegSetValue", persist}},
                          3, 85});
    }

    void ursnif_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), ".php");
        };
        auto dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll") &&
                   Contains(ToLower(r.target), "\\appdata\\");
        };
        auto reg = [](BR r) {
            return r.action == "RegSetValue" &&
                   Contains(ToLower(r.target), "\\run") &&
                   Contains(ToLower(r.details), "ursnif");
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.Ursnif",
                          {{"NetworkConnect", c2},
                           {"FileWrite", dll},
                           {"RegSetValue", reg}},
                          3, 83});
    }

    void zeus_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "gate.php");
        };
        auto inject = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "zeus"));
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.ZeuS",
                          {{"NetworkConnect", c2},
                           {"ProcessHollowing", inject},
                           {"RegSetValue", persist}},
                          3, 84});
    }

    void danabot_steps() {
        using BR = const BehaviorRecord&;
        auto dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), ".exe");
        };
        auto drop = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".exe") &&
                   Contains(ToLower(r.target), "\\programdata\\");
        };
        auto sched = [](BR r) {
            return r.action == "SchtasksCreate" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "schtasks"));
        };
        rules_.push_back({"BSD/Trojan-Banker.Win32.DanaBot",
                          {{"NetworkConnect", dl},
                           {"FileWrite", drop},
                           {"SchtasksCreate", sched}},
                          3, 82});
    }

    void conti_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "tor2web");
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".conti");
        };
        auto vss = [](BR r) {
            return (r.action == "ProcessCreate" || r.action == "BackupDeletion") &&
                   Contains(ToLower(r.details), "vssadmin delete shadows");
        };
        auto stopsvc = [](BR r) {
            return r.action == "ServiceStop" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "net stop"));
        };
        rules_.push_back({"BSD/Ransomware.Conti",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"ProcessCreate", vss},
                           {"ServiceStop", stopsvc}},
                          3, 95});
    }

    void revil_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (Contains(ToLower(r.target), "splin") ||
                    Contains(ToLower(r.target), "revil"));
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" &&
                   (EndsWith(ToLower(r.target), ".revil") ||
                    EndsWith(ToLower(r.target), ".sodin"));
        };
        auto delbak = [](BR r) {
            return r.action == "BackupDeletion" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.details), "vssadmin"));
        };
        rules_.push_back({"BSD/Ransomware.REvil",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"BackupDeletion", delbak}},
                          3, 94});
    }

    void blackcat_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), ".onion");
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".blackcat");
        };
        auto delbak = [](BR r) {
            return r.action == "BackupDeletion";
        };
        rules_.push_back({"BSD/Ransomware.BlackCat",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"BackupDeletion", delbak}},
                          3, 94});
    }

    void hive_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "hive");
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".hive");
        };
        auto delbak = [](BR r) {
            return r.action == "BackupDeletion";
        };
        rules_.push_back({"BSD/Ransomware.Hive",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"BackupDeletion", delbak}},
                          3, 93});
    }

    void darkside_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "darkside");
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".darkside");
        };
        auto delbak = [](BR r) {
            return r.action == "BackupDeletion";
        };
        rules_.push_back({"BSD/Ransomware.DarkSide",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"BackupDeletion", delbak}},
                          3, 94});
    }

    void clop_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "clop");
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".clop");
        };
        auto stopsvc = [](BR r) {
            return r.action == "ServiceStop";
        };
        rules_.push_back({"BSD/Ransomware.Clop",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"ServiceStop", stopsvc}},
                          3, 93});
    }

    void ryuk_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "ryuk");
        };
        auto enc = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".ryuk");
        };
        auto delbak = [](BR r) {
            return r.action == "BackupDeletion";
        };
        auto boot = [](BR r) {
            return r.action == "SystemConfig" && Contains(ToLower(r.details), "recoveryenabled");
        };
        rules_.push_back({"BSD/Ransomware.Ryuk",
                          {{"NetworkConnect", c2},
                           {"FileWrite", enc},
                           {"BackupDeletion", delbak},
                           {"SystemConfig", boot}},
                          3, 95});
    }

    void vidar_steps() {
        using BR = const BehaviorRecord&;
        auto read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "wallet"));
        };
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), ".php");
        };
        auto zip = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip");
        };
        rules_.push_back({"BSD/TrojanSpy.Vidar",
                          {{"FileRead", read},
                           {"NetworkConnect", c2},
                           {"FileWrite", zip}},
                          3, 88});
    }

    void raccoon_steps() {
        using BR = const BehaviorRecord&;
        auto read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "login data") ||
                    Contains(ToLower(r.target), "wallet"));
        };
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "ftp");
        };
        auto ps = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "powershell");
        };
        rules_.push_back({"BSD/TrojanSpy.RaccoonStealer",
                          {{"FileRead", read},
                           {"NetworkConnect", c2},
                           {"ProcessCreate", ps}},
                          3, 87});
    }

    void mars_steps() {
        using BR = const BehaviorRecord&;
        auto read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "browser") ||
                    Contains(ToLower(r.target), "ftp") ||
                    Contains(ToLower(r.target), "mail"));
        };
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" && Contains(ToLower(r.target), ".php");
        };
        auto zip = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip");
        };
        rules_.push_back({"BSD/TrojanSpy.MarsStealer",
                          {{"FileRead", read},
                           {"NetworkConnect", c2},
                           {"FileWrite", zip}},
                          3, 88});
    }

    void azorult_steps() {
        using BR = const BehaviorRecord&;
        auto read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "wallet") ||
                    Contains(ToLower(r.target), "cookies") ||
                    Contains(ToLower(r.target), "autofill"));
        };
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), ".php");
        };
        auto cmd = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "cmd.exe");
        };
        rules_.push_back({"BSD/TrojanSpy.AZORult",
                          {{"FileRead", read},
                           {"NetworkConnect", c2},
                           {"ProcessCreate", cmd}},
                          3, 87});
    }

    void formbook_steps() {
        using BR = const BehaviorRecord&;
        auto mem = [](BR r) {
            return r.action == "MemoryAlloc" && Contains(ToLower(r.details), "keylog");
        };
        auto read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "chrome") ||
                    Contains(ToLower(r.target), "firefox"));
        };
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), ".php");
        };
        rules_.push_back({"BSD/TrojanSpy.FormBook",
                          {{"MemoryAlloc", mem},
                           {"FileRead", read},
                           {"NetworkConnect", c2}},
                          3, 86});
    }

    void njrat_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "njrat");
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        auto cmd = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "cmd.exe");
        };
        auto ps = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "powershell");
        };
        rules_.push_back({"BSD/Backdoor.Win32.NjRAT",
                          {{"NetworkConnect", c2},
                           {"RegSetValue", persist},
                           {"ProcessCreate", cmd},
                           {"ProcessCreate", ps}},
                          3, 85});
    }

    void nanocore_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "nanocore");
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        auto plugin = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll");
        };
        rules_.push_back({"BSD/Backdoor.Win32.NanoCore",
                          {{"NetworkConnect", c2},
                           {"RegSetValue", persist},
                           {"FileWrite", plugin}},
                          3, 84});
    }

    void darkcomet_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "darkcomet");
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        auto keylog = [](BR r) {
            return r.action == "MemoryAlloc" && Contains(ToLower(r.details), "keylog");
        };
        rules_.push_back({"BSD/Backdoor.Win32.DarkComet",
                          {{"NetworkConnect", c2},
                           {"RegSetValue", persist},
                           {"MemoryAlloc", keylog}},
                          3, 84});
    }

    void quasarrat_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "quasar");
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        auto cmd = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "cmd.exe");
        };
        rules_.push_back({"BSD/Backdoor.Win32.QuasarRAT",
                          {{"NetworkConnect", c2},
                           {"RegSetValue", persist},
                           {"ProcessCreate", cmd}},
                          3, 83});
    }

    void poisonivy_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "poisonivy");
        };
        auto inject = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "inject"));
        };
        auto dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll");
        };
        rules_.push_back({"BSD/Backdoor.Win32.PoisonIvy",
                          {{"NetworkConnect", c2},
                           {"ProcessHollowing", inject},
                           {"FileWrite", dll}},
                          3, 84});
    }

    void smokeloader_steps() {
        using BR = const BehaviorRecord&;
        auto dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "smokeloader");
        };
        auto dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll") &&
                   Contains(ToLower(r.target), "\\temp\\");
        };
        auto run = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "rundll32");
        };
        rules_.push_back({"BSD/TrojanDownloader.SmokeLoader",
                          {{"NetworkConnect", dl},
                           {"FileWrite", dll},
                           {"ProcessCreate", run}},
                          3, 83});
    }

    void gootloader_steps() {
        using BR = const BehaviorRecord&;
        auto dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "gootloader");
        };
        auto run = [](BR r) {
            return r.action == "ProcessCreate" &&
                   (Contains(ToLower(r.target), "mshta") ||
                    Contains(ToLower(r.target), "regsvr32"));
        };
        auto dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll");
        };
        rules_.push_back({"BSD/TrojanDownloader.GootLoader",
                          {{"NetworkConnect", dl},
                           {"ProcessCreate", run},
                           {"FileWrite", dll}},
                          3, 82});
    }

    void socgholish_steps() {
        using BR = const BehaviorRecord&;
        auto dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "socgholish");
        };
        auto js = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".js");
        };
        auto run = [](BR r) {
            return r.action == "ProcessCreate" &&
                   (Contains(ToLower(r.target), "mshta") ||
                    Contains(ToLower(r.target), "wscript"));
        };
        rules_.push_back({"BSD/TrojanDownloader.SocGholish",
                          {{"NetworkConnect", dl},
                           {"FileWrite", js},
                           {"ProcessCreate", run}},
                          3, 82});
    }

    void plugx_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "plugx");
        };
        auto dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll");
        };
        auto inject = [](BR r) {
            return r.action == "ProcessHollowing" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "plugx"));
        };
        rules_.push_back({"BSD/Backdoor.Win32.PlugX",
                          {{"NetworkConnect", c2},
                           {"FileWrite", dll},
                           {"ProcessHollowing", inject}},
                          3, 84});
    }

    void shadowpad_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "shadowpad");
        };
        auto dll = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".dll");
        };
        auto persist = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "\\run");
        };
        rules_.push_back({"BSD/Backdoor.Win32.ShadowPad",
                          {{"NetworkConnect", c2},
                           {"FileWrite", dll},
                           {"RegSetValue", persist}},
                          3, 84});
    }

    void sliverfox_steps() {
        using BR = const BehaviorRecord&;
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), "sliverfox");
        };
        auto read = [](BR r) {
            return r.action == "FileRead" &&
                   (Contains(ToLower(r.target), "browser") ||
                    Contains(ToLower(r.target), "wallet"));
        };
        auto zip = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".zip");
        };
        rules_.push_back({"BSD/Trojan-Spy.Win32.SliverFox",
                          {{"NetworkConnect", c2},
                           {"FileRead", read},
                           {"FileWrite", zip}},
                          3, 83});
    }

    void snakekeylogger_steps() {
        using BR = const BehaviorRecord&;
        auto mem = [](BR r) {
            return r.action == "MemoryAlloc" &&
                   (Contains(ToLower(r.details), "keylog") ||
                    Contains(ToLower(r.details), "hook"));
        };
        auto log = [](BR r) {
            return r.action == "FileWrite" && EndsWith(ToLower(r.target), ".log");
        };
        auto c2 = [](BR r) {
            return r.action == "NetworkConnect" &&
                   Contains(ToLower(r.target), ".php");
        };
        rules_.push_back({"BSD/TrojanSpy.SnakeKeylogger",
                          {{"MemoryAlloc", mem},
                           {"FileWrite", log},
                           {"NetworkConnect", c2}},
                          3, 86});
    }

    void iex_base64_steps() {
        using BR = const BehaviorRecord&;
        auto iex = [](BR r) {
            return r.action == "IEXExecute" ||
                   (r.action == "ProcessCreate" && Contains(ToLower(r.target), "invoke-expression"));
        };
        auto b64 = [](BR r) {
            return r.action == "Base64Decode" ||
                   (r.action == "MemoryAlloc" && Contains(ToLower(r.details), "base64"));
        };
        auto ps_exec = [](BR r) {
            return r.action == "ProcessCreate" && Contains(ToLower(r.target), "powershell");
        };
        rules_.push_back({"BSD/Generic.ObfuscatedPS",
                          {{"IEXExecute", iex},
                           {"Base64Decode", b64},
                           {"ProcessCreate", ps_exec}},
                          3, 82});

        using BR = const BehaviorRecord&;
        auto js_dl = [](BR r) {
            return r.action == "NetworkConnect" &&
                   (StartsWith(ToLower(r.target), "http://") ||
                    StartsWith(ToLower(r.target), "https://"));
        };
        auto js_iex = [](BR r) {
            return r.action == "IEXExecute" || r.action == "Base64Decode";
        };
        // Writing/opening an executable or script artifact, or writing into a
        // non-standard user-writable location (temp/appdata/programdata/public).
        auto js_file = [](BR r) {
            if (r.action != "FileWrite" && r.action != "FileOpen") return false;
            std::string t = ToLower(r.target);
            return EndsWith(t, ".js") || EndsWith(t, ".vbs") || EndsWith(t, ".ps1") ||
                   EndsWith(t, ".exe") || EndsWith(t, ".dll") || EndsWith(t, ".bat") ||
                   EndsWith(t, ".cmd") || EndsWith(t, ".scr") || EndsWith(t, ".tmp") ||
                   EndsWith(t, ".bin") || Contains(t, "\\temp\\") ||
                   Contains(t, "\\appdata\\") || Contains(t, "\\programdata\\") ||
                   Contains(t, "\\public\\") || Contains(t, "startup");
        };
        // Running a script interpreter or a payload from a user-writable location.
        auto js_run = [](BR r) {
            if (r.action != "ProcessCreate") return false;
            std::string t = ToLower(r.target);
            return Contains(t, "wscript") || Contains(t, "cscript") ||
                   Contains(t, "powershell") || Contains(t, "mshta") ||
                   Contains(t, "regsvr32") || Contains(t, "rundll32") ||
                   Contains(t, "cmd") || Contains(t, "\\temp\\") ||
                   Contains(t, "\\appdata\\") || Contains(t, "\\programdata\\");
        };
        auto js_av = [](BR r) {
            return r.action == "RegSetValue" && Contains(ToLower(r.target), "defender");
        };
        auto js_svc = [](BR r) {
            return r.action == "ServiceStop" || r.action == "ProcessCreate" &&
                   Contains(ToLower(r.target), "net stop");
        };
        auto js_del = [](BR r) {
            return r.action == "FileDelete";
        };
        auto js_bak = [](BR r) {
            return r.action == "BackupDeletion" || (r.action == "ProcessCreate" &&
                                                    Contains(ToLower(r.details), "vssadmin"));
        };
        // Reading browser credential/session files (info-stealer signal).
        auto js_cred_read = [](BR r) {
            if (r.action != "FileRead") return false;
            std::string t = ToLower(r.target);
            return Contains(t, "login data") || Contains(t, "cookies") ||
                   Contains(t, "web data") || Contains(t, "wallet") ||
                   Contains(t, "autofill") || Contains(t, "logins.json") ||
                   Contains(t, "key4.db") || Contains(t, "leveldb");
        };
        // Touching browser/credential-related registry keys.
        auto js_cred_reg = [](BR r) {
            if (r.action != "RegSetValue" && r.action != "RegRead" && r.action != "RegDelete")
                return false;
            std::string t = ToLower(r.target);
            return Contains(t, "\\software\\") &&
                   (Contains(t, "chrome") || Contains(t, "firefox") ||
                    Contains(t, "edge") || Contains(t, "password") ||
                    Contains(t, "credential"));
        };

        rules_.push_back({"BSD/TrojanDownloader.JSDropper",
                          {{"NetworkConnect", js_dl},
                           {"FileWrite", js_file},
                           {"ProcessCreate", js_run}},
                          3, 85});

        rules_.push_back({"BSD/TrojanSpy.JSInfoStealer",
                          {{"FileRead", js_cred_read},
                           {"NetworkConnect", js_dl},
                           {"RegSetValue", js_cred_reg}},
                          3, 82});

        rules_.push_back({"BSD/Ransomware.JSRansom",
                          {{"FileWrite", js_file},
                           {"FileDelete", js_del},
                           {"RegSetValue", js_av}},
                          3, 90});

        rules_.push_back({"BSD/Backdoor.Script.JS.Generic",
                          {{"NetworkConnect", js_dl},
                           {"ProcessCreate", js_run},
                           {"RegSetValue", [](BR r) {
                               return r.action == "RegSetValue" && Contains(ToLower(r.target), "run");
                           }}},
                          3, 82});

        rules_.push_back({"BSD/Trojan-Obfuscated.Script.JS.Generic",
                          {{"IEXExecute", js_iex},
                           {"Base64Decode", [](BR r) { return r.action == "Base64Decode"; }},
                           {"ProcessCreate", js_run}},
                          3, 78});
    }

    static Match MatchRule(const std::vector<BehaviorRecord>& records, const FamilyChain& rule) {
        Match m;
        m.total_steps = static_cast<int>(rule.steps.size());
        int last_ts = -1000;
        size_t idx = 0;
        int order = 0;
        for (const auto& r : records) {
            if (idx >= rule.steps.size()) break;
            const auto& step = rule.steps[idx];
            if (step.matcher(r) && r.timestamp >= last_ts &&
                (idx == 0 || r.timestamp - last_ts <= step.max_interval)) {
                ++m.matched_steps;
                last_ts = r.timestamp;
                m.order_score += (1 + static_cast<int>(idx));
                m.evidence.push_back(r.action + ":" + r.target);
                ++idx;
                ++order;
            }
        }
        return m;
    }
};

} // anonymous namespace

/* ============================================================
 *  Interpreter state
 * ============================================================ */
struct InterpreterState {
    VirtualEnvironment& env;
    BehaviorRecorder& recorder;
    std::vector<std::string>& log;
    int pid;
    int ppid;
    std::string source;  // "ps" or "cmd"
    std::unordered_map<std::string, std::string>& globals;
    int depth;

    InterpreterState(VirtualEnvironment& e, BehaviorRecorder& rec, std::vector<std::string>& l,
                     int p, int pp, const std::string& s,
                     std::unordered_map<std::string, std::string>& g, int d = 0)
        : env(e), recorder(rec), log(l), pid(p), ppid(pp), source(s), globals(g), depth(d) {}

    BehaviorRecord Emit(const std::string& action, const std::string& target,
                        const std::string& details, int parent = -1) {
        BehaviorRecord r = recorder.Record(action, target, details, parent, source, pid, ppid);
        log.push_back("EMIT: " + action + " target=" + target + " details=" + details);
        return r;
    }

    void Log(const std::string& msg) { log.push_back("[" + source + "] " + msg); }
};

class CmdInterpreter;
void ExecuteCmdChild(InterpreterState& st, const std::string& args, int cpid);
void ExecuteCmdPayload(InterpreterState& st, const std::string& code);

/* ============================================================
 *  PowerShell interpreter
 * ============================================================ */
class PowershellInterpreter {
public:
    static void Execute(InterpreterState& st, const std::string& code) {
        try {
            if (st.depth >= VirtualEnvironment::kMaxRecursionDepth) {
                st.Log("PS interpret aborted: recursion depth limit reached");
                return;
            }
            if (!st.env.IncStep()) {
                st.Log("PS interpret aborted: execution step limit reached");
                return;
            }
            // Guard: skip interpretation for extremely large inputs.
            static constexpr size_t kMaxPsCodeSize = 1048576;  // 1MB
            if (code.size() > kMaxPsCodeSize) {
                st.Log("PS interpret aborted: input too large");
                return;
            }
            st.Log("PS interpret start");
            std::string cleaned = Deobfuscator::Deobfuscate(code, false);
            if (cleaned != code) st.Log("Deobfuscated PS code");

            std::vector<std::string> lines = Split(cleaned, '\n');
            // Limit the number of lines interpreted to prevent excessive processing.
            static constexpr int kMaxPsLines = 5000;
            int line_count = 0;
            for (std::string line : lines) {
                if (++line_count > kMaxPsLines) {
                    st.Log("PS interpret aborted: line limit reached");
                    break;
                }
                line = Trim(line);
                if (line.empty() || StartsWith(line, "#")) continue;
                std::vector<std::string> stmts = SplitStatements(line);
                for (std::string& stmt : stmts) {
                    stmt = Trim(stmt);
                    if (stmt.empty() || StartsWith(stmt, "#")) continue;
                    ExecuteLine(st, stmt);
                }
            }
        } catch (...) {
            st.Log("PS interpret aborted: runtime exception");
        }
    }

private:
    static std::vector<std::string> SplitStatements(const std::string& line) {
        std::vector<std::string> out;
        std::string cur;
        bool in_sq = false, in_dq = false;
        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
            if (in_sq) {
                cur.push_back(c);
                if (c == '\'') in_sq = false;
                continue;
            }
            if (in_dq) {
                cur.push_back(c);
                if (c == '"') in_dq = false;
                continue;
            }
            if (c == '\'') { in_sq = true; cur.push_back(c); continue; }
            if (c == '"') { in_dq = true; cur.push_back(c); continue; }
            if (c == ';') {
                if (!cur.empty() || !out.empty()) out.push_back(cur);
                cur.clear();
                continue;
            }
            cur.push_back(c);
        }
        if (!cur.empty() || !out.empty()) out.push_back(cur);
        return out;
    }

    static bool LooksLikeBatch(const std::string& payload) {
        std::string low = ToLower(payload);
        auto lineHas = [&low](const std::string& prefix) {
            return StartsWith(low, prefix) || Contains(low, "\n" + prefix);
        };
        int batchMarkers = 0;
        if (lineHas("reg ")) ++batchMarkers;
        if (lineHas("net ")) ++batchMarkers;
        if (lineHas("sc ")) ++batchMarkers;
        if (Contains(low, "vssadmin")) ++batchMarkers;
        if (Contains(low, "bcdedit")) ++batchMarkers;
        if (lineHas("wmic ")) ++batchMarkers;
        if (Contains(low, "secedit")) ++batchMarkers;
        if (Contains(low, "del /f") || Contains(low, "del /q")) ++batchMarkers;
        if (lineHas("echo ")) ++batchMarkers;
        return batchMarkers >= 2;
    }

    static void ExecuteLine(InterpreterState& st, const std::string& line) {
        std::string l = Trim(line);
        // IEX / Invoke-Expression on following value.
        if (StartsWith(ToLower(l), "invoke-expression") || StartsWith(ToLower(l), "iex ") ||
            StartsWith(ToLower(l), "iex(")) {
            size_t pos = l.find_first_of(" \t(");
            std::string payload = pos == std::string::npos ? "" : Trim(l.substr(pos));
            payload = RemoveQuotes(EvaluateExpression(st, payload));
            if (!payload.empty()) {
                st.Log("IEX executing payload");
                std::string pl = ToLower(payload);
                if (pl.find("base64") != std::string::npos || pl.find("frombase64string") != std::string::npos ||
                    pl.find("getstring") != std::string::npos) {
                    st.Emit("Base64Decode", "IEX", "Invoke-Expression with Base64 payload", -1);
                }
                st.Emit("IEXExecute", "powershell", payload, -1);
                if (LooksLikeBatch(payload))
                    ExecuteCmdPayload(st, payload);
                else {
                    InterpreterState cst(st.env, st.recorder, st.log, st.env.NewPid(), st.pid,
                                         "child", st.globals, st.depth + 1);
                    PowershellInterpreter::Execute(cst, payload);
                }
            }
            return;
        }

        // Call operator & / .
        if (StartsWith(l, "&") || StartsWith(l, ".")) {
            std::string rest = Trim(l.substr(1));
            st.Log("Call operator rest=" + rest.substr(0, 80));
            if (!rest.empty() && rest.front() == '(') {
                // Find matching closing paren using depth tracking.
                size_t end_paren = std::string::npos;
                int pdepth = 1;
                bool in_sq = false, in_dq = false;
                for (size_t i = 1; i < rest.size(); ++i) {
                    char c = rest[i];
                    if (in_sq) { if (c == '\'') in_sq = false; continue; }
                    if (in_dq) { if (c == '"') in_dq = false; continue; }
                    if (c == '\'') { in_sq = true; continue; }
                    if (c == '"') { in_dq = true; continue; }
                    if (c == '(') { ++pdepth; continue; }
                    if (c == ')') {
                        if (--pdepth == 0) { end_paren = i; break; }
                    }
                }
                if (end_paren != std::string::npos) {
                    std::string cmd_expr = Trim(rest.substr(1, end_paren - 1));
                    std::string cmd = EvaluateExpression(st, cmd_expr);
                    std::string args = Trim(rest.substr(end_paren + 1));
                    st.Log("Call operator resolved cmd=[" + cmd + "] args=[" + args + "]");
                    std::string full = cmd;
                    if (!args.empty()) full += " " + args;
                    ExecuteLine(st, Trim(full));
                    return;
                } else {
                    st.Log("Call operator failed to find matching paren");
                }
            } else if (!rest.empty() && (rest.front() == '"' || rest.front() == '\'')) {
                // Bare quoted command: &"command" args or ."command" args
                char quote = rest.front();
                size_t quote_end = rest.find(quote, 1);
                if (quote_end != std::string::npos) {
                    std::string cmd = rest.substr(1, quote_end - 1);
                    std::string args = Trim(rest.substr(quote_end + 1));
                    std::string full = cmd;
                    if (!args.empty()) full += " " + args;
                    ExecuteLine(st, Trim(full));
                    return;
                }
            } else {
                // Bare command: &Set-Item args or .Get-Item args
                size_t cmd_end = 0;
                while (cmd_end < rest.size() &&
                       (std::isalnum(static_cast<unsigned char>(rest[cmd_end])) ||
                        rest[cmd_end] == '-' || rest[cmd_end] == '_' ||
                        rest[cmd_end] == ':' || rest[cmd_end] == '.')) {
                    ++cmd_end;
                }
                if (cmd_end > 0) {
                    std::string cmd = rest.substr(0, cmd_end);
                    std::string args = Trim(rest.substr(cmd_end));
                    std::string full = cmd;
                    if (!args.empty()) full += " " + args;
                    st.Log("Bare call operator cmd=[" + cmd + "] args=[" + args + "]");
                    ExecuteLine(st, Trim(full));
                    return;
                }
            }
        }

        // Variable assignment.
        if (l.size() > 1 && l[0] == '$') {
            size_t eq = l.find('=');
            if (eq != std::string::npos) {
                std::string name = Trim(l.substr(1, eq - 1));
                if (!name.empty() && name.front() == '{' && name.back() == '}') {
                    name = name.substr(1, name.size() - 2);
                }
                std::string unescaped;
                for (char c : name) {
                    if (c != '`') unescaped.push_back(c);
                }
                name = unescaped;
                std::string value = EvaluateExpression(st, Trim(l.substr(eq + 1)));
                st.globals[name] = value;
                st.globals["global:" + name] = value;
                st.Log("Set $" + name + " value_len=" + std::to_string(value.size()) + " value_preview=" + value.substr(0, 200));
                return;
            }
        }

        // Pipeline / cmdlet invocation.
        std::vector<std::string> toks = Tokenize(l);
        if (toks.empty()) return;

        std::string cmd = ToLower(toks[0]);

        if (cmd == "invoke-webrequest" || cmd == "wget" || cmd == "curl" ||
            Contains(l, "net.webclient")) {
            HandleDownload(st, l, toks);
        } else if (cmd == "start-process" || cmd == "start" || cmd == "saps") {
            HandleStartProcess(st, l, toks);
        } else if (cmd == "new-item" || cmd == "ni") {
            HandleNewItem(st, l, toks);
        } else if (cmd == "set-item" || cmd == "si") {
            HandleSetItem(st, l, toks);
        } else if (cmd == "get-variable" || cmd == "gv") {
            HandleGetVariable(st, l, toks);
        } else if (cmd == "set-itemproperty" || cmd == "sp") {
            HandleSetItemProperty(st, l, toks);
        } else if (cmd == "get-itemproperty" || cmd == "gp") {
            HandleGetItemProperty(st, l, toks);
        } else if (Contains(l, "[reflection.assembly]::load")) {
            HandleReflectionLoad(st, l);
        } else if (Contains(l, "[system.convert]::frombase64string") ||
                   Contains(l, "[system.text.encoding]::utf8.getstring") ||
                   Contains(l, "frombase64string") || Contains(l, "getstring")) {
            HandleDotNetDecode(st, l);
        } else if (Contains(l, "get-wmiobject") || Contains(l, "invoke-wmimethod")) {
            HandleWMI(st, l, toks);
        } else if (Contains(l, "reg.exe") || Contains(l, "reg save")) {
            HandleRegCmd(st, l, toks);
        } else if (Contains(l, "schtasks")) {
            HandleSchtasks(st, l, toks);
        } else if (cmd == "net") {
            HandleNetCmd(st, l, toks);
        } else if (Contains(l, "vssadmin")) {
            HandleVssadmin(st, l, toks);
        } else if (Contains(l, "get-content") || Contains(l, "[io.file]::readall")) {
            HandleFileRead(st, l, toks);
        } else if (Contains(l, "set-content") || Contains(l, "out-file") ||
                   Contains(l, "[io.file]::writeall")) {
            HandleFileWrite(st, l, toks);
        } else if (Contains(l, "add-type")) {
            HandleAddType(st, l);
        } else if (Contains(l, "[dllimport")) {
            st.Emit("MemoryAlloc", "", "DllImport GetAsyncKeyState", -1);
        }
    }

    // ============================================================
    //  PowerShell expression tokenizer & recursive-descent evaluator
    // ============================================================
    struct PsToken {
        enum Type { End, Ident, String, Number,
                    LBracket, RBracket, LParen, RParen,
                    Dot, ColonColon, Comma, Plus, Minus, Call, Other } type;
        std::string text;
    };

    class PsLexer {
    public:
        explicit PsLexer(const std::string& str) : s_(str), pos_(0) { SkipWs(); }

        PsToken Next() {
            // Loop instead of recursion to avoid stack overflow on many unknown chars.
            while (true) {
                SkipWs();
                if (pos_ >= s_.size()) return {PsToken::End, ""};
                char c = s_[pos_];
                if (c == '&') { ++pos_; return {PsToken::Call, "&"}; }
                if (c == '[') { ++pos_; return {PsToken::LBracket, "["}; }
                if (c == ']') { ++pos_; return {PsToken::RBracket, "]"}; }
                if (c == '(') { ++pos_; return {PsToken::LParen, "("}; }
                if (c == ')') { ++pos_; return {PsToken::RParen, ")"}; }
                if (c == '.') { ++pos_; return {PsToken::Dot, "."}; }
                if (c == ':' && pos_ + 1 < s_.size() && s_[pos_+1] == ':') {
                    pos_ += 2;
                    return {PsToken::ColonColon, "::"};
                }
                if (c == ',') { ++pos_; return {PsToken::Comma, ","}; }
                if (c == '+') { ++pos_; return {PsToken::Plus, "+"}; }
                if (c == '-') { ++pos_; return {PsToken::Minus, "-"}; }
                if (c == '"' || c == '\'') return ReadString(c);
                if (std::isdigit(static_cast<unsigned char>(c))) return ReadNumber();
                // PowerShell variables: $varName or ${varName}
                if (c == '$') return ReadVariable();
                if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') return ReadIdent();
                // Unknown single char, skip (loop continues).
                ++pos_;
            }
        }

    private:
        void SkipWs() {
            while (pos_ < s_.size() &&
                   std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }

        PsToken ReadString(char quote) {
            ++pos_;
            std::string out;
            while (pos_ < s_.size() && s_[pos_] != quote) {
                if (s_[pos_] == '`' && pos_ + 1 < s_.size()) {
                    char nxt = s_[pos_ + 1];
                    if (nxt == 'n') out.push_back('\n');
                    else if (nxt == 'r') out.push_back('\r');
                    else if (nxt == 't') out.push_back('\t');
                    else out.push_back(nxt);
                    pos_ += 2;
                } else {
                    out.push_back(s_[pos_]);
                    ++pos_;
                }
            }
            if (pos_ < s_.size()) ++pos_;
            return {PsToken::String, out};
        }

        PsToken ReadNumber() {
            size_t start = pos_;
            while (pos_ < s_.size() &&
                   (std::isdigit(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '.')) {
                ++pos_;
            }
            return {PsToken::Number, s_.substr(start, pos_ - start)};
        }

        PsToken ReadVariable() {
            ++pos_; // skip $
            if (pos_ < s_.size() && s_[pos_] == '{') {
                // ${varName} form
                ++pos_; // skip {
                size_t start = pos_;
                while (pos_ < s_.size() && s_[pos_] != '}') ++pos_;
                std::string name = s_.substr(start, pos_ - start);
                if (pos_ < s_.size()) ++pos_; // skip }
                return {PsToken::Ident, name};
            }
            // $varName form
            size_t start = pos_;
            while (pos_ < s_.size() &&
                   (std::isalnum(static_cast<unsigned char>(s_[pos_])) ||
                    s_[pos_] == '_' || s_[pos_] == '`')) {
                ++pos_;
            }
            std::string name = s_.substr(start, pos_ - start);
            return {PsToken::Ident, name};
        }

        PsToken ReadIdent() {
            size_t start = pos_;
            while (pos_ < s_.size() &&
                   (std::isalnum(static_cast<unsigned char>(s_[pos_])) ||
                    s_[pos_] == '_' || s_[pos_] == '.')) {
                ++pos_;
            }
            return {PsToken::Ident, s_.substr(start, pos_ - start)};
        }

        std::string s_;
        size_t pos_;
    };

    class PsExprParser {
    public:
        PsExprParser(const std::string& expr, InterpreterState& st)
            : lex_(expr), st_(st) { cur_ = lex_.Next(); }

        std::string Parse() {
            return ParseExpr();
        }

    private:
        void Eat(PsToken::Type t) {
            if (cur_.type == t) cur_ = lex_.Next();
        }

        std::string ParseExpr() {
            std::string left = ParseTerm();
            while (cur_.type == PsToken::Plus || cur_.type == PsToken::Minus) {
                PsToken::Type op = cur_.type;
                Eat(op);
                std::string right = ParseTerm();
                if (op == PsToken::Plus) left = left + right;
                // Minus not needed for current obfuscation patterns.
            }
            return left;
        }

        std::string ParseTerm() {
            return ParsePostfix();
        }

        std::string ParsePostfix() {
            std::string base = ParseAtom();
            while (true) {
                if (cur_.type == PsToken::ColonColon) {
                    Eat(PsToken::ColonColon);
                    if (cur_.type != PsToken::Ident) break;
                    std::string member = cur_.text;
                    Eat(PsToken::Ident);
                    base = base + "::" + member;
                    if (cur_.type == PsToken::LParen) {
                        std::vector<std::string> args = ParseArgList();
                        base = EvalMethod(base, args);
                    }
                } else if (cur_.type == PsToken::Dot) {
                    Eat(PsToken::Dot);
                    if (cur_.type != PsToken::Ident) break;
                    std::string member = cur_.text;
                    Eat(PsToken::Ident);
                    base = base + "." + member;
                    if (cur_.type == PsToken::LParen) {
                        std::vector<std::string> args = ParseArgList();
                        base = EvalMethod(base, args);
                    }
                } else if (cur_.type == PsToken::Call) {
                    Eat(PsToken::Call);
                    if (cur_.type == PsToken::LParen) {
                        Eat(PsToken::LParen);
                        std::string v = ParseExpr();
                        Eat(PsToken::RParen);
                        base = EvaluateExpression(st_, v);
                    }
                } else {
                    break;
                }
            }
            return base;
        }

        std::string ParseAtom() {
            if (cur_.type == PsToken::String) {
                std::string v = cur_.text;
                Eat(PsToken::String);
                return v;
            }
            if (cur_.type == PsToken::Number) {
                std::string v = cur_.text;
                Eat(PsToken::Number);
                return v;
            }
            if (cur_.type == PsToken::Ident) {
                std::string v = cur_.text;
                Eat(PsToken::Ident);
                return v;
            }
            if (cur_.type == PsToken::LBracket) {
                Eat(PsToken::LBracket);
                std::string type;
                while (cur_.type != PsToken::RBracket && cur_.type != PsToken::End) {
                    type += cur_.text;
                    cur_ = lex_.Next();
                }
                Eat(PsToken::RBracket);
                return "[" + type + "]";
            }
            if (cur_.type == PsToken::LParen) {
                Eat(PsToken::LParen);
                std::string v = ParseExpr();
                Eat(PsToken::RParen);
                return v;
            }
            std::string v = cur_.text;
            Eat(cur_.type);
            return v;
        }

        std::vector<std::string> ParseArgList() {
            std::vector<std::string> args;
            Eat(PsToken::LParen);
            if (cur_.type != PsToken::RParen) {
                args.push_back(ParseExpr());
                while (cur_.type == PsToken::Comma) {
                    Eat(PsToken::Comma);
                    args.push_back(ParseExpr());
                }
            }
            Eat(PsToken::RParen);
            return args;
        }

        std::string EvalMethod(const std::string& target,
                               const std::vector<std::string>& args) {
            std::string low = ToLower(target);
            if ((low == "[system.convert]::frombase64string" ||
                 EndsWith(low, "frombase64string")) && !args.empty()) {
                std::string decoded;
                Base64Decode(RemoveQuotes(args[0]), decoded);
                return decoded;
            }
            if ((low == "[system.text.encoding]::utf8.getstring" ||
                 EndsWith(low, "utf8.getstring") ||
                 EndsWith(low, "getstring")) && !args.empty()) {
                return RemoveQuotes(args[0]);
            }
            return target + "()";
        }

        PsLexer lex_;
        InterpreterState& st_;
        PsToken cur_;
    };

    // Find matching closing paren from start, accounting for quotes and nested parens.
    static size_t FindMatchingParen(const std::string& s, size_t start) {
        int depth = 1;
        bool in_sq = false, in_dq = false;
        for (size_t i = start; i < s.size(); ++i) {
            char c = s[i];
            if (in_sq) { if (c == '\'') in_sq = false; continue; }
            if (in_dq) { if (c == '"') in_dq = false; continue; }
            if (c == '\'') { in_sq = true; continue; }
            if (c == '"') { in_dq = true; continue; }
            if (c == '(') { ++depth; continue; }
            if (c == ')') { if (--depth == 0) return i; }
        }
        return std::string::npos;
    }

    // Evaluate &(...), .(...), ."cmd", .'cmd', &"cmd", &'cmd' call operator expressions.
    // Also supports bare call operators: .cmd args and &cmd args (common in obfuscated scripts).
    // e.g. &("Get-Item") ("Variable:8Kb1") -> value of Variable:8Kb1
    // e.g. ."Get-Item" ('Variable:8Kb1') -> value of Variable:8Kb1
    // e.g. .get-ITEM 'Variable:8Kb1' -> value of Variable:8Kb1
    static std::string EvaluatePsCallOp(InterpreterState& st, const std::string& expr) {
        auto isCommandChar = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == ':' || c == '.';
        };
        auto isKnownBareCommand = [](const std::string& cmd) {
            static const std::unordered_set<std::string> known = {
                "get-item", "gi", "get-variable", "gv", "set-item", "si",
                "set-variable", "sv", "get-content", "gc", "set-content", "sc"
            };
            return known.count(ToLower(cmd)) > 0;
        };
        auto readArgToken = [&](const std::string& s, size_t start, size_t& end) -> std::string {
            while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) ++start;
            if (start >= s.size()) { end = start; return ""; }
            if (s[start] == '(') {
                size_t paren_end = FindMatchingParen(s, start + 1);
                if (paren_end != std::string::npos) {
                    end = paren_end + 1;
                    return Trim(s.substr(start + 1, paren_end - start - 1));
                }
            } else if (s[start] == '"' || s[start] == '\'') {
                char q = s[start];
                size_t qend = s.find(q, start + 1);
                if (qend != std::string::npos) {
                    end = qend + 1;
                    return s.substr(start + 1, qend - start - 1);
                }
            }
            end = start;
            while (end < s.size() && !std::isspace(static_cast<unsigned char>(s[end])) &&
                   s[end] != ')' && s[end] != ';') ++end;
            return Trim(s.substr(start, end - start));
        };

        std::string result;
        for (size_t i = 0; i < expr.size(); ) {
            if ((expr[i] == '&' || expr[i] == '.') && i + 1 < expr.size()) {
                bool can_be_call_op = (i == 0 || expr[i-1] == '(' ||
                                       std::isspace(static_cast<unsigned char>(expr[i-1])));
                if (expr[i+1] == '(') {
                    // Handle &(...) and .(...) - command name as expression in parens
                    size_t paren_end = FindMatchingParen(expr, i + 2);
                    if (paren_end == std::string::npos) { result.push_back(expr[i]); ++i; continue; }
                    std::string cmd_expr = Trim(expr.substr(i + 2, paren_end - i - 2));
                    std::string cmd = EvaluateExpression(st, cmd_expr);
                    cmd = RemoveQuotes(cmd);
                    // Look for arguments after the closing paren.
                    size_t args_start = paren_end + 1;
                    while (args_start < expr.size() && std::isspace(static_cast<unsigned char>(expr[args_start]))) ++args_start;
                    std::string args;
                    if (args_start < expr.size() && expr[args_start] == '(') {
                        size_t args_paren_end = FindMatchingParen(expr, args_start + 1);
                        if (args_paren_end != std::string::npos) {
                            args = Trim(expr.substr(args_start + 1, args_paren_end - args_start - 1));
                            i = args_paren_end + 1;
                        } else {
                            i = paren_end + 1;
                        }
                    } else if (args_start < expr.size()) {
                        size_t arg_end = args_start;
                        while (arg_end < expr.size() && expr[arg_end] != ')' && expr[arg_end] != ';') ++arg_end;
                        args = Trim(expr.substr(args_start, arg_end - args_start));
                        i = arg_end;
                    } else {
                        i = paren_end + 1;
                    }
                    std::string val = EvaluatePsCommand(st, cmd, args);
                    result += val;
                    continue;
                } else if ((expr[i+1] == '"' || expr[i+1] == '\'') && can_be_call_op) {
                    // Handle ."command" / .'command' / &"command" / &'command'
                    char quote = expr[i+1];
                    size_t quote_end = expr.find(quote, i + 2);
                    if (quote_end == std::string::npos) { result.push_back(expr[i]); ++i; continue; }
                    std::string cmd = expr.substr(i + 2, quote_end - i - 2);
                    // Look for arguments after the quoted command.
                    size_t args_start = quote_end + 1;
                    while (args_start < expr.size() && std::isspace(static_cast<unsigned char>(expr[args_start]))) ++args_start;
                    std::string args;
                    if (args_start < expr.size() && expr[args_start] == '(') {
                        size_t args_paren_end = FindMatchingParen(expr, args_start + 1);
                        if (args_paren_end != std::string::npos) {
                            args = Trim(expr.substr(args_start + 1, args_paren_end - args_start - 1));
                            i = args_paren_end + 1;
                        } else {
                            i = quote_end + 1;
                        }
                    } else if (args_start < expr.size()) {
                        size_t arg_end = args_start;
                        while (arg_end < expr.size() && expr[arg_end] != ')' && expr[arg_end] != ';') ++arg_end;
                        args = Trim(expr.substr(args_start, arg_end - args_start));
                        i = arg_end;
                    } else {
                        i = quote_end + 1;
                    }
                    std::string val = EvaluatePsCommand(st, cmd, args);
                    result += val;
                    continue;
                } else if (can_be_call_op && std::isalpha(static_cast<unsigned char>(expr[i+1]))) {
                    // Handle bare .cmd args and &cmd args (e.g. .get-ITEM 'Variable:8Kb1').
                    size_t cmd_start = i + 1;
                    size_t cmd_end = cmd_start;
                    while (cmd_end < expr.size() && isCommandChar(expr[cmd_end])) ++cmd_end;
                    std::string cmd = expr.substr(cmd_start, cmd_end - cmd_start);
                    if (isKnownBareCommand(cmd)) {
                        size_t args_end = 0;
                        std::string args = readArgToken(expr, cmd_end, args_end);
                        i = args_end;
                        std::string val = EvaluatePsCommand(st, cmd, args);
                        result += val;
                        continue;
                    }
                }
            }
            result.push_back(expr[i]);
            ++i;
        }
        return result;
    }

    // Evaluate a known PowerShell command in the simulated environment.
    static std::string EvaluatePsCommand(InterpreterState& st, const std::string& cmd,
                                          const std::string& args) {
        std::string low_cmd = ToLower(cmd);
        // Evaluate the argument string (remove quotes, expand concatenation).
        std::string arg = RemoveQuotes(Trim(args));
        // Expand string concatenation in arg: 'a'+'b' -> 'ab'
        try {
            std::string concat;
            bool in_quote = false;
            char quote_c = 0;
            for (size_t i = 0; i < arg.size(); ++i) {
                char c = arg[i];
                if (!in_quote && (c == '\'' || c == '"')) { in_quote = true; quote_c = c; continue; }
                if (in_quote && c == quote_c) { in_quote = false; continue; }
                if (!in_quote && c == '+' && i > 0 && i + 1 < arg.size()) {
                    char prev = arg[i-1], next = arg[i+1];
                    if ((prev == '\'' || prev == '"') && (next == '\'' || next == '"')) continue;
                }
                concat.push_back(c);
            }
            arg = concat;
        } catch (...) {}
        arg = RemoveQuotes(arg);

        if (low_cmd == "get-item" || low_cmd == "gi" || low_cmd == "get-variable" || low_cmd == "gv") {
            // Handle Variable:NAME or Env:NAME
            std::string var_name = arg;
            if (StartsWith(ToLower(var_name), "variable:")) var_name = var_name.substr(9);
            else if (StartsWith(ToLower(var_name), "env:")) var_name = var_name.substr(4);
            // Remove backticks.
            std::string unescaped;
            for (char c : var_name) { if (c != '`') unescaped.push_back(c); }
            st.Log("GetItem/Var lookup arg=[" + arg + "] name=[" + unescaped + "]");
            std::string val = FindVarCaseInsensitive(st.globals, unescaped);
            st.Log("Lookup result val_len=" + std::to_string(val.size()) + " val=[" + val + "]");
            if (!val.empty()) return val;
            // Also check env.variables.
            auto it = st.env.variables.find(unescaped);
            if (it != st.env.variables.end()) return it->second;
            return arg; // Return as-is if not found.
        }
        if (low_cmd == "set-item" || low_cmd == "si") {
            // Handle Set-Item Variable:NAME value
            // The args format is typically 'Variable:NAME' or 'Env:NAME'
            std::string target = arg;
            if (StartsWith(ToLower(target), "variable:")) target = target.substr(9);
            else if (StartsWith(ToLower(target), "env:")) target = target.substr(4);
            return target; // Return the target name.
        }
        // For unknown commands, return the command name (simulating the command output).
        return cmd;
    }

    static std::string EvaluateExpression(InterpreterState& st, std::string expr) {
        expr = Trim(expr);
        if (expr.empty()) return "";

        bool debug = (expr.size() > 50 && (Contains(ToLower(expr), "getstring") || Contains(ToLower(expr), "frombase64string")));
        if (debug) st.Log("EvalExpr INPUT: " + expr.substr(0, 300));

        // Iteratively apply all transformations until the expression stabilizes.
        // This is needed because resolving one pattern (e.g. ::FromBase64String)
        // may reveal new patterns (e.g. ::GetString) that need further processing.
        int max_rounds = 100;
        while (max_rounds-- > 0) {
            std::string prev = expr;

            // Strip outer parens if the whole expression is wrapped in balanced parens.
            // Use explicit paren matching so the first '(' must be closed by the last ')'.
            try {
                while (!expr.empty() && expr.front() == '(' && expr.back() == ')') {
                    size_t close = FindMatchingParenDynamic(expr, 1);
                    if (close == expr.size() - 1) {
                        expr = Trim(expr.substr(1, expr.size() - 2));
                    } else {
                        break;
                    }
                }
            } catch (...) {}

            // Expand variables (case-insensitive, multi-pass).
            int varRounds = 0;
            while (varRounds++ < 50) {
                size_t before = expr.size();
                expr = ExpandVariablesOnce(st, expr);
                if (expr.size() == before) break;
            }

            // Expand -f / -F format strings.
            try {
                expr = Deobfuscator::ExpandPsFormatString(expr);
            } catch (...) {}

            // String concatenation: 'a'+'b' -> 'ab' + merge adjacent strings.
            try {
                std::string concat;
                bool in_quote = false;
                char quote_c = 0;
                for (size_t i = 0; i < expr.size(); ++i) {
                    char c = expr[i];
                    if (!in_quote && (c == '\'' || c == '"')) {
                        in_quote = true; quote_c = c; concat.push_back(c); continue;
                    }
                    if (in_quote && c == quote_c) {
                        in_quote = false; concat.push_back(c); continue;
                    }
                    if (!in_quote && c == '+' && i > 0 && i + 1 < expr.size()) {
                        char pv = expr[i-1], nx = expr[i+1];
                        if ((pv == '\'' || pv == '"') && (nx == '\'' || nx == '"')) continue;
                    }
                    concat.push_back(c);
                }
                // Merge adjacent quoted strings: 'a''b' -> 'ab'
                std::string merged;
                for (size_t i = 0; i < concat.size(); ) {
                    if ((concat[i] == '\'' || concat[i] == '"') && i + 1 < concat.size()) {
                        char q = concat[i];
                        size_t j = i + 1;
                        while (j < concat.size() && concat[j] != q) ++j;
                        if (j < concat.size()) {
                            merged.push_back(q);
                            merged.append(concat.substr(i + 1, j - i - 1));
                            i = j + 1;
                            while (i < concat.size() && concat[i] == q) {
                                size_t k = i + 1;
                                while (k < concat.size() && concat[k] != q) ++k;
                                if (k < concat.size()) {
                                    merged.append(concat.substr(i + 1, k - i - 1));
                                    i = k + 1;
                                } else {
                                    merged.push_back(concat[i]); ++i; break;
                                }
                            }
                            merged.push_back(q);
                            continue;
                        }
                    }
                    merged.push_back(concat[i]); ++i;
                }
                expr = merged;
            } catch (...) {}

            // Handle &(...) and .(...) call operators.
            if (expr.find("&(") != std::string::npos || expr.find(".(") != std::string::npos) {
                try { expr = EvaluatePsCallOp(st, expr); } catch (...) {}
            }

            // Strip leftover (prefix) patterns after call operator resolution.
            // e.g. (cmd) args -> args. Do NOT strip when the parens are part of a
            // member/property access such as (expr).Value::Method().
            try {
                while (!expr.empty() && expr[0] == '(') {
                    size_t close = FindMatchingParenDynamic(expr, 1);
                    if (close == std::string::npos) break;
                    std::string rest = Trim(expr.substr(close + 1));
                    if (!rest.empty() && rest[0] != '.' && rest[0] != ':' && rest[0] != '[') {
                        expr = rest;
                    } else break;
                }
            } catch (...) {}

            // Handle ::FromBase64String(...) and ::GetString(...) patterns.
            try {
                expr = ExpandPsDotNetMethods(st, expr);
            } catch (...) {}

            // Handle [Type]typeName - extract type name from type accelerator.
            if (!expr.empty() && expr[0] == '[') {
                size_t rb = expr.find(']');
                if (rb != std::string::npos) {
                    std::string bracketContent = expr.substr(1, rb - 1);
                    std::string lowBracket = ToLower(bracketContent);
                    if (lowBracket == "type") {
                        std::string typeName = Trim(expr.substr(rb + 1));
                        if (!typeName.empty() && typeName[0] == '.') typeName = typeName.substr(1);
                        if (!typeName.empty() && typeName.front() == '(' && typeName.back() == ')') {
                            typeName = Trim(typeName.substr(1, typeName.size() - 2));
                        }
                        typeName = RemoveQuotes(typeName);
                        if (!typeName.empty()) return typeName;
                    }
                }
            }

            // Handle [Type]::Method() via PsExprParser.
            if (expr.find('[') != std::string::npos || expr.find("::") != std::string::npos) {
                try {
                    PsExprParser parser(expr, st);
                    std::string parsed = parser.Parse();
                    if (!parsed.empty() && parsed != expr) { expr = parsed; continue; }
                } catch (...) {}
            }

            // If nothing changed, stop iterating.
            if (expr == prev) break;
            if (debug) st.Log("EvalExpr round: " + expr.substr(0, 300));
        }

        if (debug) st.Log("EvalExpr OUTPUT: " + expr.substr(0, 300));
        return RemoveQuotes(expr);
    }

    // Expand .NET method calls: ::FromBase64String(...) and ::GetString(...)
    // Uses manual parenthesis matching to handle complex nested arguments.
    static std::string ExpandPsDotNetMethods(InterpreterState& st, const std::string& expr) {
        std::string s = expr;

        // Step 0: Normalize quoted identifiers after :: and .
        try {
            std::regex quotedId(R"((::|\.)\s*\"((?:[^\"\\]|\\.)*)\")");
            std::smatch qm;
            while (std::regex_search(s, qm, quotedId)) {
                std::string prefix = qm[1].str();
                std::string unescaped;
                for (size_t i = 0; i < qm[2].str().size(); ++i) {
                    char c = qm[2].str()[i];
                    if (c == '`' && i + 1 < qm[2].str().size()) {
                        ++i;
                        unescaped.push_back(qm[2].str()[i]);
                    } else {
                        unescaped.push_back(c);
                    }
                }
                s.replace(qm.position(), qm.length(), prefix + unescaped);
            }
        } catch (...) {}

        // Step 0.5: Remove .Value before :: (PSVariable property access, case-insensitive).
        // If it follows a parenthesized expression, strip the wrapping parens too.
        try { s = RemoveValueBeforeColon(s); } catch (...) {}

        st.Log("DotNet normalized=" + s.substr(0, 250));

        // Step 1: Handle ::FromBase64String[.Invoke](complex_arg) with manual paren matching.
        // This handles both simple quoted-string args and complex nested expression args.
        try {
            std::string low = ToLower(s);
            size_t search_pos = 0;
            while (true) {
                size_t pos = low.find("::frombase64string", search_pos);
                if (pos == std::string::npos) break;
                // Find the opening paren after the method name (possibly with .Invoke).
                size_t after_method = pos + 18; // "::frombase64string".size()
                // Check for optional .Invoke
                if (after_method < s.size()) {
                    size_t invoke_pos = low.find(".invoke", after_method);
                    if (invoke_pos != std::string::npos && invoke_pos < after_method + 20) {
                        after_method = invoke_pos + 7; // ".invoke".size()
                    }
                }
                // Skip whitespace.
                while (after_method < s.size() && std::isspace(static_cast<unsigned char>(s[after_method])))
                    ++after_method;
                if (after_method >= s.size() || s[after_method] != '(') {
                    search_pos = pos + 1;
                    continue;
                }
                // Find matching closing paren.
                size_t open_paren = after_method;
                size_t close_paren = FindMatchingParenDynamic(s, open_paren + 1);
                if (close_paren == std::string::npos) {
                    search_pos = pos + 1;
                    continue;
                }
                std::string arg = Trim(s.substr(open_paren + 1, close_paren - open_paren - 1));
                st.Log("DotNet FromBase64 pos=" + std::to_string(pos) + " open=" + std::to_string(open_paren) + " close=" + std::to_string(close_paren) + " s_len=" + std::to_string(s.size()));
                st.Log("DotNet FromBase64 arg_len=" + std::to_string(arg.size()) + " arg=[" + arg.substr(0,100) + (arg.size()>100?"...":"") + "]");
                // Recursively evaluate the argument.
                std::string evaluated = EvaluateExpression(st, arg);
                evaluated = RemoveQuotes(evaluated);
                st.Log("DotNet FromBase64 evaluated_len=" + std::to_string(evaluated.size()) + " evaluated=[" + evaluated.substr(0,100) + (evaluated.size()>100?"...":"") + "]");
                // Try to base64-decode the evaluated argument.
                std::string decoded;
                if (Base64Decode(evaluated, decoded) && !decoded.empty()) {
                    st.Log("DotNet FromBase64 decoded_len=" + std::to_string(decoded.size()));
                    size_t prefix_start = FindDotNetPrefixStart(s, pos);
                    s.replace(prefix_start, close_paren - prefix_start + 1, "\"" + decoded + "\"");
                    low = ToLower(s);
                    search_pos = 0; // Restart search from beginning.
                } else {
                    st.Log("DotNet FromBase64 decode failed");
                    search_pos = pos + 1;
                }
            }
        } catch (...) {}

        // Step 2: Handle ::("FromBase64String").Invoke(complex_arg) - quoted method name.
        try {
            std::string low = ToLower(s);
            size_t search_pos = 0;
            while (true) {
                // Find ::"(\"...\")" pattern.
                size_t pos = low.find("::", search_pos);
                if (pos == std::string::npos) break;
                size_t after_cc = pos + 2;
                while (after_cc < s.size() && std::isspace(static_cast<unsigned char>(s[after_cc])))
                    ++after_cc;
                if (after_cc >= s.size() || s[after_cc] != '(') {
                    search_pos = pos + 1;
                    continue;
                }
                // Find the closing paren of the method name.
                size_t qm_open = after_cc;
                size_t qm_close = FindMatchingParenDynamic(s, qm_open + 1);
                if (qm_close == std::string::npos) {
                    search_pos = pos + 1;
                    continue;
                }
                std::string method_expr = Trim(s.substr(qm_open + 1, qm_close - qm_open - 1));
                std::string method_low = ToLower(method_expr);
                // Check if it's a base64 method name.
                bool is_b64_method = false;
                // Remove backticks and quotes.
                std::string clean_method;
                for (size_t i = 0; i < method_expr.size(); ++i) {
                    char c = method_expr[i];
                    if (c == '`' && i + 1 < method_expr.size()) { ++i; c = method_expr[i]; }
                    if (c != '"' && c != '\'') clean_method.push_back(c);
                }
                std::string clean_low = ToLower(clean_method);
                if (clean_low.find("frombase64string") != std::string::npos) is_b64_method = true;

                if (!is_b64_method) {
                    search_pos = pos + 1;
                    continue;
                }

                // Check for .Invoke after the method paren.
                size_t after_method_close = qm_close + 1;
                while (after_method_close < s.size() && std::isspace(static_cast<unsigned char>(s[after_method_close])))
                    ++after_method_close;
                if (after_method_close >= s.size() || ToLower(s.substr(after_method_close, 7)) != ".invoke") {
                    search_pos = pos + 1;
                    continue;
                }
                after_method_close += 7;
                while (after_method_close < s.size() && std::isspace(static_cast<unsigned char>(s[after_method_close])))
                    ++after_method_close;
                if (after_method_close >= s.size() || s[after_method_close] != '(') {
                    search_pos = pos + 1;
                    continue;
                }
                size_t invoke_close = FindMatchingParenDynamic(s, after_method_close + 1);
                if (invoke_close == std::string::npos) {
                    search_pos = pos + 1;
                    continue;
                }
                std::string arg = Trim(s.substr(after_method_close + 1, invoke_close - after_method_close - 1));
                std::string evaluated = EvaluateExpression(st, arg);
                evaluated = RemoveQuotes(evaluated);
                std::string decoded;
                if (Base64Decode(evaluated, decoded) && !decoded.empty()) {
                    s.replace(pos, invoke_close - pos + 1, "\"" + decoded + "\"");
                    low = ToLower(s);
                    search_pos = 0;
                } else {
                    search_pos = pos + 1;
                }
            }
        } catch (...) {}

        // Step 3: ::GetString(complex_arg) or ::UTF8.GetString(complex_arg)
        // Uses manual paren matching and recursive evaluation.
        try {
            std::string low = ToLower(s);
            size_t search_pos = 0;
            while (true) {
                // Find ::GetString or ::UTF8.GetString
                size_t gs_pos = std::string::npos;
                size_t pos1 = low.find("::getstring(", search_pos);
                size_t pos2 = low.find("::utf8.getstring(", search_pos);
                if (pos1 != std::string::npos && (pos2 == std::string::npos || pos1 < pos2))
                    gs_pos = pos1;
                else if (pos2 != std::string::npos)
                    gs_pos = pos2;
                if (gs_pos == std::string::npos) break;

                // Find the opening paren.
                size_t open_paren = low.find('(', gs_pos);
                if (open_paren == std::string::npos) { search_pos = gs_pos + 1; continue; }
                size_t close_paren = FindMatchingParenDynamic(s, open_paren + 1);
                if (close_paren == std::string::npos) { search_pos = gs_pos + 1; continue; }

                std::string arg = Trim(s.substr(open_paren + 1, close_paren - open_paren - 1));
                st.Log("DotNet GetString arg_len=" + std::to_string(arg.size()) + " arg=[" + arg.substr(0,100) + (arg.size()>100?"...":"") + "]");
                std::string evaluated = EvaluateExpression(st, arg);
                evaluated = RemoveQuotes(evaluated);
                st.Log("DotNet GetString evaluated_len=" + std::to_string(evaluated.size()) + " evaluated=[" + evaluated.substr(0,100) + (evaluated.size()>100?"...":"") + "]");
                size_t prefix_start = FindDotNetPrefixStart(s, gs_pos);
                s.replace(prefix_start, close_paren - prefix_start + 1, evaluated);
                low = ToLower(s);
                search_pos = 0;
            }
        } catch (...) {}

        return s;
    }

    // Find matching closing paren with quote tracking, starting from 'start' position.
    static size_t FindMatchingParenDynamic(const std::string& s, size_t start) {
        int depth = 1;
        bool in_sq = false, in_dq = false;
        for (size_t i = start; i < s.size(); ++i) {
            char c = s[i];
            if (in_sq) { if (c == '\'') in_sq = false; continue; }
            if (in_dq) { if (c == '"') in_dq = false; continue; }
            if (c == '\'') { in_sq = true; continue; }
            if (c == '"') { in_dq = true; continue; }
            if (c == '(') { ++depth; continue; }
            if (c == ')') { if (--depth == 0) return i; }
        }
        return std::string::npos;
    }

    // Find the matching opening '(' for a closing ')' with quote tracking.
    static size_t FindMatchingOpenParen(const std::string& s, size_t close_pos) {
        int depth = 1;
        bool in_sq = false, in_dq = false;
        for (size_t j = close_pos; j-- > 0; ) {
            char c = s[j];
            if (in_sq) { if (c == '\'') in_sq = false; continue; }
            if (in_dq) { if (c == '"') in_dq = false; continue; }
            if (c == '\'') { in_sq = true; continue; }
            if (c == '"') { in_dq = true; continue; }
            if (c == ')') { ++depth; continue; }
            if (c == '(') { if (--depth == 0) return j; }
        }
        return std::string::npos;
    }

    // Find the start position of the object/type expression before "::".
    // Handles identifiers with dots, parenthesized expressions, variables, and [Type].
    static size_t FindDotNetPrefixStart(const std::string& s, size_t colon_pos) {
        if (colon_pos == 0) return 0;
        size_t i = colon_pos;
        // Skip whitespace before ::
        while (i > 0 && std::isspace(static_cast<unsigned char>(s[i - 1]))) --i;
        if (i == 0) return 0;
        // If it ends with ']', find matching '['.
        if (s[i - 1] == ']') {
            int depth = 1;
            bool in_sq = false, in_dq = false;
            for (size_t j = i - 1; j-- > 0; ) {
                char c = s[j];
                if (in_sq) { if (c == '\'') in_sq = false; continue; }
                if (in_dq) { if (c == '"') in_dq = false; continue; }
                if (c == '\'') { in_sq = true; continue; }
                if (c == '"') { in_dq = true; continue; }
                if (c == ']') { ++depth; continue; }
                if (c == '[') { if (--depth == 0) return j; }
            }
            return i - 1;
        }
        // If it ends with ')', find matching '('.
        if (s[i - 1] == ')') {
            size_t open_paren = FindMatchingOpenParen(s, i - 1);
            if (open_paren != std::string::npos) return open_paren;
            return i - 1;
        }
        // Otherwise, scan backwards over identifier chars and dots.
        while (i > 0) {
            char c = s[i - 1];
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '$' || c == ':' || c == '-') {
                --i;
            } else {
                break;
            }
        }
        return i;
    }

    // Remove .Value (case-insensitive) before ::. If it follows a closing ')',
    // also strip the matching wrapping parentheses so (expr).Value:: becomes expr::.
    static std::string RemoveValueBeforeColon(const std::string& expr) {
        std::string s = expr;
        size_t i = 0;
        while (i < s.size()) {
            // Find next '.' followed by "value" (case-insensitive) followed by optional whitespace and "::".
            if (s[i] != '.') { ++i; continue; }
            if (i + 6 > s.size()) { ++i; continue; }
            if (ToLower(s.substr(i + 1, 5)) != "value") { ++i; continue; }
            size_t after_value = i + 6; // position after "value"
            // Skip optional whitespace, require '::'.
            size_t k = after_value;
            while (k < s.size() && std::isspace(static_cast<unsigned char>(s[k]))) ++k;
            if (k + 2 > s.size() || s[k] != ':' || s[k + 1] != ':') { ++i; continue; }
            // Check if there is a ')' immediately before optional whitespace before '.'.
            size_t before_dot = i;
            while (before_dot > 0 && std::isspace(static_cast<unsigned char>(s[before_dot - 1]))) --before_dot;
            if (before_dot > 0 && s[before_dot - 1] == ')') {
                size_t close_paren = before_dot - 1;
                size_t open_paren = FindMatchingOpenParen(s, close_paren);
                if (open_paren != std::string::npos) {
                    std::string inner = Trim(s.substr(open_paren + 1, close_paren - open_paren - 1));
                    s.replace(open_paren, k + 2 - open_paren, inner + "::");
                    i = open_paren;
                    continue;
                }
            }
            // Bare .Value: just remove it.
            s.replace(i, k - i, "");
            i = (i > 0) ? i - 1 : 0;
        }
        return s;
    }

    // Case-insensitive variable lookup helper.
    static std::string FindVarCaseInsensitive(
        const std::unordered_map<std::string, std::string>& globals,
        const std::string& name) {
        std::string lower = ToLower(name);
        for (const auto& kv : globals) {
            if (ToLower(kv.first) == lower) return kv.second;
        }
        return "";
    }

    static std::string ExpandVariablesOnce(InterpreterState& st, std::string expr) {
        std::regex varre(R"(\$\{?([a-zA-Z0-9_`]+)\}?)");
        std::string out;
        size_t last_end = 0;
        bool changed = false;
        for (std::sregex_iterator it(expr.begin(), expr.end(), varre), end; it != end; ++it) {
            const std::smatch& m = *it;
            out.append(expr.substr(last_end, m.position() - last_end));
            std::string name = m[1].str();
            std::string unescaped;
            for (char c : name) {
                if (c != '`') unescaped.push_back(c);
            }
            // Case-insensitive lookup (PowerShell is case-insensitive).
            std::string val = FindVarCaseInsensitive(st.globals, unescaped);
            if (val.empty()) {
                // Also resolve $env:NAME and $variable:NAME scopes.
                std::string scope_name = unescaped;
                if (StartsWith(ToLower(scope_name), "env:")) {
                    scope_name = scope_name.substr(4);
                } else if (StartsWith(ToLower(scope_name), "variable:")) {
                    scope_name = scope_name.substr(9);
                }
                auto it = st.env.variables.find(scope_name);
                if (it != st.env.variables.end()) val = it->second;
            }
            out += val;
            last_end = m.position() + m.length();
            changed = true;
        }
        out.append(expr.substr(last_end));
        return changed ? out : expr;
    }

    static void HandleDownload(InterpreterState& st, const std::string& l,
                               const std::vector<std::string>& toks) {
        std::string url;
        std::string outpath;
        for (size_t i = 0; i < toks.size(); ++i) {
            std::string t = ToLower(toks[i]);
            if ((t == "-uri" || t == "-url") && i + 1 < toks.size()) {
                url = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
            } else if ((t == "-outfile" || t == "-o") && i + 1 < toks.size()) {
                outpath = NormalizeSlashes(RemoveQuotes(EvaluateExpression(st, toks[i + 1])));
            }
        }
        // Try to infer URL if not explicit.
        if (url.empty()) {
            for (const auto& t : toks) {
                std::string e = EvaluateExpression(st, t);
                if (StartsWith(e, "http") || Contains(e, ".")) {
                    url = e;
                    break;
                }
            }
        }
        if (url.empty()) url = "http://unknown";
        auto rec = st.Emit("NetworkConnect", url, "download", -1);
        if (outpath.empty()) {
            size_t slash = url.find_last_of("/\\");
            outpath = "C:\\Users\\User\\AppData\\Local\\Temp\\" +
                      (slash == std::string::npos ? "downloaded" : url.substr(slash + 1));
        }
        std::string tag = "binary_payload";
        if (Contains(ToLower(url), ".dll")) tag = "dll_payload";
        if (Contains(ToLower(url), ".exe")) tag = "exe_payload";
        if (Contains(ToLower(url), "discord")) tag = "autoit_payload";
        st.env.files[outpath] = tag;
        st.Emit("FileWrite", outpath, tag, rec.id);
        st.Log("Download " + url + " -> " + outpath);
    }

    static void HandleStartProcess(InterpreterState& st, const std::string& l,
                                   const std::vector<std::string>& toks) {
        std::string path, args;
        for (size_t i = 0; i < toks.size(); ++i) {
            std::string t = ToLower(toks[i]);
            if ((t == "-filepath" || t == "-file") && i + 1 < toks.size())
                path = NormalizeSlashes(RemoveQuotes(EvaluateExpression(st, toks[i + 1])));
            else if ((t == "-argumentlist" || t == "-args") && i + 1 < toks.size())
                args = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
        }
        if (path.empty()) {
            for (const auto& t : toks) {
                std::string e = RemoveQuotes(EvaluateExpression(st, t));
                if (StartsWith(e, "C:\\") || StartsWith(e, "\"")) {
                    path = NormalizeSlashes(e);
                    break;
                }
            }
        }
        if (path.empty()) return;
        int cpid = st.env.NewPid();
        st.env.processes[cpid] = {path, st.pid, args};
        auto rec = st.Emit("ProcessCreate", path, args, -1);
        st.Log("Start-Process " + path + " " + args);

        // If spawned a known script host, recursively interpret the payload.
        std::string lp = ToLower(path);
        if (Contains(lp, "powershell") || Contains(lp, "cmd") || Contains(lp, "wscript") ||
            Contains(lp, "cscript") || Contains(lp, "mshta")) {
            if (Contains(lp, "powershell"))
            {
                InterpreterState cst(st.env, st.recorder, st.log, cpid, st.pid, "child", st.globals, 0);
                PowershellInterpreter::Execute(cst, args);
            }
            else
            {
                ExecuteCmdChild(st, args, cpid);
            }
        }
    }

    static void HandleSetItem(InterpreterState& st, const std::string& l,
                              const std::vector<std::string>& toks) {
        st.Log("HandleSetItem called with " + std::to_string(toks.size()) + " tokens, first=[" + (toks.empty() ? "" : toks[0]) + "]");
        std::string path;
        std::string value;
        bool has_path = false;
        for (size_t i = 1; i < toks.size(); ++i) {
            std::string t = ToLower(toks[i]);
            if ((t == "-path" || t == "-literalpath") && i + 1 < toks.size()) {
                path = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
                has_path = true;
                ++i;
            } else if (t == "-value" && i + 1 < toks.size()) {
                value = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
                ++i;
            } else if (!StartsWith(t, "-")) {
                std::string e = RemoveQuotes(EvaluateExpression(st, toks[i]));
                std::string e_lower = ToLower(e);
                if (StartsWith(e_lower, "env:") || StartsWith(e_lower, "variable:")) {
                    path = e;
                    has_path = true;
                } else if (path.empty()) {
                    path = e;
                    has_path = true;
                } else if (value.empty()) {
                    value = e;
                }
            }
        }
        if (!path.empty()) {
            st.Emit("EnvSet", path, value, -1);
            std::string path_lower = ToLower(path);
            st.Log("SetItem path=[" + path + "] value_len=" + std::to_string(value.size()) + " value=[" + value + "]");
            if (StartsWith(path_lower, "variable:")) {
                std::string name = path.substr(9);
                std::string unescaped;
                for (char c : name) {
                    if (c != '`') unescaped.push_back(c);
                }
                st.globals[unescaped] = value;
                st.globals["global:" + unescaped] = value;
                st.Log("Stored variable [" + unescaped + "]");
            } else if (StartsWith(path_lower, "env:")) {
                std::string name = path.substr(4);
                st.env.variables[name] = value;
            }
        }
    }

    static void HandleGetVariable(InterpreterState& st, const std::string& l,
                                  const std::vector<std::string>& toks) {
        std::string name;
        for (const auto& t : toks) {
            std::string e = RemoveQuotes(EvaluateExpression(st, t));
            if (StartsWith(e, "$")) {
                name = e.substr(1);
                break;
            }
            std::string e_lower = ToLower(e);
            if (StartsWith(e_lower, "env:")) {
                name = e.substr(4);
                auto it = st.env.variables.find(name);
                if (it != st.env.variables.end()) {
                    st.Emit("VarRead", e, it->second, -1);
                }
                return;
            }
            if (StartsWith(e_lower, "variable:")) {
                name = e.substr(9);
                break;
            }
        }
        if (!name.empty()) {
            std::string unescaped;
            for (char c : name) {
                if (c != '`') unescaped.push_back(c);
            }
            std::string val = FindVarCaseInsensitive(st.globals, unescaped);
            if (!val.empty()) {
                st.Emit("VarRead", "$" + name, val, -1);
            }
        }
    }

    static void HandleNewItem(InterpreterState& st, const std::string& l,
                              const std::vector<std::string>& toks) {
        std::string path;
        for (size_t i = 0; i < toks.size(); ++i) {
            if (ToLower(toks[i]) == "-path" && i + 1 < toks.size())
                path = NormalizeSlashes(RemoveQuotes(EvaluateExpression(st, toks[i + 1])));
        }
        if (path.empty()) {
            for (const auto& t : toks) {
                std::string e = RemoveQuotes(EvaluateExpression(st, t));
                if (StartsWith(e, "C:\\") || StartsWith(e, "HK")) {
                    path = NormalizeSlashes(e);
                    break;
                }
            }
        }
        if (path.empty()) return;
        if (StartsWith(path, "HK")) {
            st.env.registry[path] = "";
            st.Emit("RegSetValue", path, "create", -1);
        } else {
            st.env.files[path] = "";
            st.Emit("FileWrite", path, "create", -1);
        }
    }

    static void HandleSetItemProperty(InterpreterState& st, const std::string& l,
                                      const std::vector<std::string>& toks) {
        std::string path, name, value;
        for (size_t i = 0; i < toks.size(); ++i) {
            std::string t = ToLower(toks[i]);
            if (t == "-path" && i + 1 < toks.size())
                path = NormalizeSlashes(RemoveQuotes(EvaluateExpression(st, toks[i + 1])));
            else if (t == "-name" && i + 1 < toks.size())
                name = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
            else if (t == "-value" && i + 1 < toks.size())
                value = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
        }
        if (path.empty()) {
            // Positional fallback.
            for (const auto& t : toks) {
                std::string e = RemoveQuotes(EvaluateExpression(st, t));
                if (StartsWith(e, "HK")) path = NormalizeSlashes(e);
            }
        }
        if (!path.empty()) {
            st.env.registry[path + "\\" + name] = value;
            std::string details = name + "=" + value;
            st.Emit("RegSetValue", path, details, -1);
        }
    }

    static void HandleGetItemProperty(InterpreterState& st, const std::string& l,
                                      const std::vector<std::string>& toks) {
        std::string path;
        for (const auto& t : toks) {
            std::string e = RemoveQuotes(EvaluateExpression(st, t));
            if (StartsWith(e, "HK")) path = NormalizeSlashes(e);
        }
        if (!path.empty()) st.Emit("RegRead", path, "", -1);
    }

    static void HandleReflectionLoad(InterpreterState& st, const std::string& l) {
        std::string details = ".NET Assembly reflection load";
        if (Contains(l, "[byte[]]")) details += " from byte[]";
        st.Emit("ReflectionLoad", "", details, -1);
    }

    static void HandleDotNetDecode(InterpreterState& st, const std::string& l) {
        std::string low = ToLower(l);
        if (Contains(low, "frombase64string")) {
            st.Emit("Base64Decode", ".NET", "[Convert]::FromBase64String(...)", -1);
        }
        if (Contains(low, "getstring")) {
            st.Emit("Base64Decode", ".NET", "[Text.Encoding]::UTF8.GetString(...)", -1);
        }
    }

    static void HandleWMI(InterpreterState& st, const std::string& l,
                          const std::vector<std::string>& toks) {
        std::string target;
        for (const auto& t : toks) {
            std::string e = RemoveQuotes(EvaluateExpression(st, t));
            if (Contains(e, "\\\\") || Contains(e, "/node")) target = e;
        }
        if (Contains(ToLower(l), "win32_process") && Contains(ToLower(l), "create")) {
            st.Emit("WMIRemoteExec", target.empty() ? "remote" : target, "Create process", -1);
        } else if (Contains(ToLower(l), "cpu") || Contains(ToLower(l), "gpu")) {
            st.Emit("WMICQuery", "system", "CPU/GPU info", -1);
        } else {
            st.Emit("WMICQuery", target, "query", -1);
        }
    }

    static void HandleRegCmd(InterpreterState& st, const std::string& l,
                             const std::vector<std::string>& toks) {
        if (Contains(ToLower(l), "save"))
            st.Emit("RegSave", "SAM/SYSTEM", "reg save", -1);
        else if (Contains(ToLower(l), "add") || Contains(ToLower(l), "set"))
            st.Emit("RegSetValue", "HKCU", Join(toks, " "), -1);
    }

    static void HandleSchtasks(InterpreterState& st, const std::string& l,
                               const std::vector<std::string>& toks) {
        std::string details = Join(toks, " ");
        st.Emit("SchtasksCreate", "Task", details, -1);
    }

    static void HandleNetCmd(InterpreterState& st, const std::string& l,
                             const std::vector<std::string>& toks) {
        std::string details = Join(toks, " ");
        st.Emit("ProcessCreate", "net.exe", details, -1);
    }

    static void HandleVssadmin(InterpreterState& st, const std::string& l,
                               const std::vector<std::string>& toks) {
        st.Emit("ProcessCreate", "vssadmin.exe", Join(toks, " "), -1);
    }

    static void HandleFileRead(InterpreterState& st, const std::string& l,
                               const std::vector<std::string>& toks) {
        std::string path;
        for (const auto& t : toks) {
            std::string e = RemoveQuotes(EvaluateExpression(st, t));
            if (StartsWith(e, "C:\\")) path = NormalizeSlashes(e);
        }
        if (!path.empty()) st.Emit("FileRead", path, "", -1);
    }

    static void HandleFileWrite(InterpreterState& st, const std::string& l,
                                const std::vector<std::string>& toks) {
        std::string path, content;
        for (size_t i = 0; i < toks.size(); ++i) {
            std::string t = ToLower(toks[i]);
            if ((t == "-path" || t == "-filepath") && i + 1 < toks.size())
                path = NormalizeSlashes(RemoveQuotes(EvaluateExpression(st, toks[i + 1])));
            else if (t == "-value" && i + 1 < toks.size())
                content = RemoveQuotes(EvaluateExpression(st, toks[i + 1]));
        }
        if (path.empty()) {
            for (const auto& t : toks) {
                std::string e = RemoveQuotes(EvaluateExpression(st, t));
                if (StartsWith(e, "C:\\") || StartsWith(e, "%")) path = NormalizeSlashes(e);
            }
        }
        if (path.empty()) return;
        if (StartsWith(path, "%")) {
            // Expand simple env var.
            std::string key = path.substr(1);
            if (st.globals.count(key)) path = st.globals[key];
        }
        std::string tag = "data";
        if (Contains(ToLower(content), "<html") || Contains(ToLower(content), "hta")) tag = "hta";
        st.env.files[path] = tag;
        st.Emit("FileWrite", path, tag, -1);
    }

    static void HandleAddType(InterpreterState& st, const std::string& l) {
        st.Emit("MemoryAlloc", "", "Add-Type compile", -1);
    }
};

/* ============================================================
 *  CMD interpreter
 * ============================================================ */
class CmdInterpreter {
public:
    static void Execute(InterpreterState& st, const std::string& code) {
        try {
            if (!st.env.IncStep()) {
                st.Log("CMD interpret aborted: execution step limit reached");
                return;
            }

            st.Log("CMD interpret start");

            std::string cleaned =
                Deobfuscator::Deobfuscate(code, true);

            if (cleaned != code) {
                st.Log("Deobfuscated CMD code");
            }

            std::vector<std::string> lines =
                CollectCmdBlocks(Split(cleaned, '\n'));

            for (std::string line : lines) {
                line = Trim(line);

                if (line.empty()) {
                    continue;
                }

                ExecuteLine(st, line);
            }
        } catch (...) {
            st.Log("CMD interpret aborted: runtime exception");
        }
    }

private:
    static int ParenthesisDelta(const std::string& line) {
        bool in_quote = false;
        char quote_char = 0;
        int depth = 0;

        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];

            if (in_quote) {
                if (c == quote_char) {
                    in_quote = false;
                }

                // CMD ??????????????? ""
                if (c == '"' &&
                    i + 1 < line.size() &&
                    line[i + 1] == '"') {
                    ++i;
                }

                continue;
            }

            if (c == '"' || c == '\'') {
                in_quote = true;
                quote_char = c;
                continue;
            }

            if (c == '(') {
                ++depth;
            }
            else if (c == ')') {
                --depth;
            }
        }

        return depth;
    }

    static std::vector<std::string> CollectCmdBlocks(
        const std::vector<std::string>& input_lines) {
        std::vector<std::string> result;

        bool collecting = false;
        int depth = 0;
        std::string block;

        for (const std::string& raw_line : input_lines) {
            std::string line = Trim(raw_line);

            if (line.empty()) {
                continue;
            }

            if (!collecting) {
                int delta = ParenthesisDelta(line);

                if (delta > 0) {
                    collecting = true;
                    depth = delta;
                    block = line;
                }
                else {
                    result.push_back(line);
                }
            }
            else {
                if (!block.empty()) {
                    block += " ";
                }

                block += line;
                depth += ParenthesisDelta(line);

                if (depth <= 0) {
                    result.push_back(Trim(block));
                    block.clear();
                    depth = 0;
                    collecting = false;
                }
            }
        }

        if (collecting && !Trim(block).empty()) {
            result.push_back(Trim(block));
        }

        return result;
    }

    static bool HasCommandSeparator(const std::string& s) {
        bool in_quote = false;
        char quote_char = 0;
        int paren_depth = 0;
        for (size_t i = 0; i < s.size(); ++i) {
            char c = s[i];
            if (in_quote) {
                if (c == quote_char) in_quote = false;
            } else if (c == '"' || c == '\'') {
                in_quote = true;
                quote_char = c;
            } else if (c == '(') {
                ++paren_depth;
            } else if (c == ')') {
                if (paren_depth > 0) --paren_depth;
            } else if (paren_depth == 0 && c == '&') {
                return true;
            } else if (paren_depth == 0 && c == '|' && i + 1 < s.size() && s[i + 1] == '|') {
                return true;
            }
        }
        return false;
    }

    static std::vector<std::string> SplitCmdCommands(const std::string& line) {
        std::vector<std::string> out;
        std::string cur;
        bool in_quote = false;
        char quote_char = 0;
        int paren_depth = 0;
        for (size_t i = 0; i < line.size(); ++i) {
            char c = line[i];
            if (in_quote) {
                cur.push_back(c);
                if (c == quote_char) in_quote = false;
            } else if (c == '"' || c == '\'') {
                in_quote = true;
                quote_char = c;
                cur.push_back(c);
            } else if (c == '(') {
                ++paren_depth;
                cur.push_back(c);
            } else if (c == ')') {
                if (paren_depth > 0) --paren_depth;
                cur.push_back(c);
            } else if (paren_depth == 0 && c == '&') {
                if (!Trim(cur).empty()) {
                    out.push_back(Trim(cur));
                }
                cur.clear();
                if (i + 1 < line.size() && line[i + 1] == '&') {
                    ++i;
                }
            } else if (paren_depth == 0 && c == '|' && i + 1 < line.size() && line[i + 1] == '|') {
                if (!Trim(cur).empty()) {
                    out.push_back(Trim(cur));
                }
                cur.clear();
                ++i;
            } else {
                cur.push_back(c);
            }
        }
        if (!Trim(cur).empty()) out.push_back(Trim(cur));
        return out;
    }

    static void ExecuteLine(InterpreterState& st, std::string line) {
        line = Trim(line);

        if (line.empty()) {
            return;
        }

        std::string low = ToLower(line);

        /*
         * ???????��? FOR /L??
         *
         * FOR /L ????????????? &, ???��
         *
         *   for /l %%i in (1,1,38) do (
         *       start cmd /c !cmd%%i! & echo test
         *   )
         *
         * ???????? HasCommandSeparator()??
         * ????? FOR ????????
         */
        if (StartsWith(low, "for /l ")) {
            ExecuteForLoop(st, line);
            return;
        }

        /*
         * ??????????????????? &, &&
         */
        if (HasCommandSeparator(line)) {
            std::vector<std::string> parts =
                SplitCmdCommands(line);

            for (const std::string& part : parts) {
                std::string trimmed = Trim(part);

                if (!trimmed.empty()) {
                    ExecuteLine(st, trimmed);
                }
            }

            return;
        }

        // Variable assignment: set FOO=bar or set /a FOO=1+2
        if (StartsWith(low, "set ")) {
            std::string rest = Trim(line.substr(4));
            if (StartsWith(ToLower(rest), "/a ")) {
                std::string arith = Trim(rest.substr(3));
                size_t eq = arith.find('=');
                std::string name;
                std::string expr;
                if (eq != std::string::npos) {
                    name = Trim(arith.substr(0, eq));
                    expr = Trim(arith.substr(eq + 1));
                } else {
                    expr = arith;
                }
                std::string value = EvalSetA(st, expr);
                if (!name.empty()) {
                    st.globals[name] = value;
                    st.globals["env:" + name] = value;
                }
                st.Log("SET /A " + name + "=" + value);
            } else {
                size_t eq = rest.find('=');
                if (eq != std::string::npos) {
                    std::string name = RemoveQuotes(Trim(rest.substr(0, eq)));
                    std::string value = RemoveQuotes(ExpandVars(st, Trim(rest.substr(eq + 1))));
                    st.globals[name] = value;
                    st.globals["env:" + name] = value;
                    st.Log("SET " + name + "=" + value);
                }
            }
            return;
        }

        // Echo - just log.
        if (StartsWith(low, "echo ")) {
            st.Log("ECHO: " + line.substr(5));
            return;
        }

        // Call recursion.
        if (StartsWith(low, "call ")) {
            ExecuteLine(st, Trim(line.substr(5)));
            return;
        }

        // Start / cmd /c -> child process.
        if (StartsWith(low, "start ") || StartsWith(low, "cmd ") || StartsWith(low, "cmd.exe ")) {
            std::string args = line;
            if (StartsWith(low, "start ")) args = Trim(line.substr(6));
            if (StartsWith(ToLower(args), "\"\" ") || StartsWith(ToLower(args), "\"\""))
                args = Trim(args.substr(3));
            args = ExpandVars(st, args);
            Spawn(st, args);
            return;
        }

        // PowerShell -enc / -encodedcommand.
        if (Contains(low, "powershell") && (Contains(low, "-enc ") || Contains(low, "-encodedcommand "))) {
            std::string enc;
            std::vector<std::string> toks = Tokenize(line);
            for (size_t i = 0; i < toks.size(); ++i) {
                std::string t = ToLower(toks[i]);
                if ((t == "-enc" || t == "-encodedcommand") && i + 1 < toks.size()) {
                    enc = toks[i + 1];
                    break;
                }
            }
            if (!enc.empty()) {
                std::string decoded;
                if (Base64Decode(enc, decoded)) {
                    st.Log("CMD launched encoded PowerShell");
                    InterpreterState cst(st.env, st.recorder, st.log, st.env.NewPid(), st.pid,
                                         "ps", st.globals);
                    PowershellInterpreter::Execute(cst, decoded);
                }
            }
            return;
        }

        // Plain PowerShell call.
        if (StartsWith(low, "powershell")) {
            std::string args = ExpandVars(st, Trim(line.substr(10)));
            InterpreterState cst(st.env, st.recorder, st.log, st.env.NewPid(), st.pid, "ps",
                                 st.globals);
            PowershellInterpreter::Execute(cst, args);
            return;
        }

        // reg add / reg delete / reg save.
        if (StartsWith(low, "reg ")) {
            std::string reg_target = "HKLM/HKCU";
            std::string rest = Trim(line.substr(4));

            if (Contains(low, "save")) {
                reg_target = "SAM/SYSTEM";
            } else {
                std::vector<std::string> toks = Tokenize(rest);
                for (size_t i = 0; i < toks.size(); ++i) {
                    std::string t = ToLower(toks[i]);
                    if (t == "add" || t == "delete" || t == "save") {
                        if (i + 1 < toks.size()) {
                            reg_target = toks[i + 1];
                        }
                        break;
                    }
                }
            }

            if (Contains(low, "save"))
                st.Emit("RegSave", reg_target, line, -1);
            else if (Contains(low, "add"))
                st.Emit("RegSetValue", reg_target, line, -1);
            else if (Contains(low, "delete"))
                st.Emit("RegDelete", reg_target, line, -1);
            return;
        }

        // sc config / sc stop (service manipulation).
        if (StartsWith(low, "sc ")) {
            if (Contains(low, "config") || Contains(low, "stop") || Contains(low, "delete"))
                st.Emit("ServiceStop", "sc.exe", line, -1);
            else
                st.Emit("ProcessCreate", "sc.exe", line, -1);
            return;
        }

        // bcdedit (recovery/boot tampering).
        if (StartsWith(low, "bcdedit")) {
            st.Emit("SystemConfig", "bcdedit.exe", line, -1);
            return;
        }

        // schtasks.
        if (Contains(low, "schtasks")) {
            st.Emit("SchtasksCreate", "Task", line, -1);
            return;
        }

        // vssadmin / wmic shadowcopy delete (backup destruction).
        if (Contains(low, "vssadmin") || (StartsWith(low, "wmic") && Contains(low, "shadowcopy"))) {
            st.Emit("BackupDeletion", "vssadmin/wmic", line, -1);
            return;
        }

        // wmic.
        if (StartsWith(low, "wmic")) {
            if (Contains(low, "/node"))
                st.Emit("WMIRemoteExec", "remote", line, -1);
            else
                st.Emit("WMICQuery", "system", line, -1);
            return;
        }

        // net commands.
        if (StartsWith(low, "net ")) {
            if (Contains(low, "stop") || Contains(low, "delete"))
                st.Emit("ServiceStop", "net.exe", line, -1);
            else
                st.Emit("ProcessCreate", "net.exe", line, -1);
            return;
        }

        // taskkill /f /im xxx.exe
        if (StartsWith(low, "taskkill") ||
            StartsWith(low, "taskkill.exe")) {
            st.Emit(
                "ProcessCreate",
                "taskkill.exe",
                line,
                -1
            );
            return;
        }

        // mountvol X: /s ????? EFI ????????
        if (StartsWith(low, "mountvol") ||
            StartsWith(low, "mountvol.exe")) {
            st.Emit(
                "SystemConfig",
                "mountvol.exe",
                line,
                -1
            );
            return;
        }

        // del /erase /rd /rmdir ?????????
        if (StartsWith(low, "del ") ||
            StartsWith(low, "erase ") ||
            StartsWith(low, "rd ") ||
            StartsWith(low, "rmdir ") ||
            StartsWith(low, "rd.exe ") ||
            StartsWith(low, "rmdir.exe ")) {
            st.Emit(
                "FileDelete",
                "mass_delete",
                line,
                -1
            );
            return;
        }

        // rundll32 / regsvr32.
        if (StartsWith(low, "rundll32") || StartsWith(low, "regsvr32")) {
            st.Emit("ProcessCreate", line.substr(0, line.find(' ') == std::string::npos
                                                      ? line.size()
                                                      : line.find(' ')),
                    line, -1);
            return;
        }

        // wmic.
        if (StartsWith(low, "wmic")) {
            if (Contains(low, "/node"))
                st.Emit("WMIRemoteExec", "remote", line, -1);
            else
                st.Emit("WMICQuery", "system", line, -1);
            return;
        }

        // Direct file write via redirection (>).
        if (line.find('>') != std::string::npos) {
            size_t pos = line.find('>');
            std::string path = NormalizeSlashes(RemoveQuotes(ExpandVars(st, Trim(line.substr(pos + 1)))));
            if (!path.empty()) {
                st.env.files[path] = "data";
                st.Emit("FileWrite", path, "redirection", -1);
            }
            return;
        }

        // Type/read file.
        if (StartsWith(low, "type ")) {
            std::string path = NormalizeSlashes(ExpandVars(st, Trim(line.substr(5))));
            if (!path.empty()) st.Emit("FileRead", path, "", -1);
            return;
        }

        // Anything else that mentions a path - just log.
        st.Log("CMD unhandled: " + line);
    }

    static void ExecuteForLoop(InterpreterState& st, const std::string& line) {
        std::string low = ToLower(line);
        size_t in_pos = low.find(" in ");
        size_t do_pos = low.find(" do ");
        if (in_pos == std::string::npos || do_pos == std::string::npos || do_pos < in_pos) {
            st.Log("FOR /L parse failed: " + line);
            return;
        }

        std::string var_part = Trim(line.substr(6, in_pos - 6));
        std::string var_name = var_part;
        while (!var_name.empty() && var_name[0] == '%')
            var_name = var_name.substr(1);

        std::string range = Trim(line.substr(in_pos + 4, do_pos - (in_pos + 4)));
        if (range.size() < 3 || range.front() != '(' || range.back() != ')') {
            st.Log("FOR /L range parse failed: " + line);
            return;
        }
        std::string inner = Trim(range.substr(1, range.size() - 2));
        std::vector<std::string> parts = Split(inner, ',');
        if (parts.size() != 3) {
            st.Log("FOR /L bad range: " + line);
            return;
        }
        long long start = std::stoll(Trim(parts[0]));
        long long step = std::stoll(Trim(parts[1]));
        long long end = std::stoll(Trim(parts[2]));

        std::string body = Trim(line.substr(do_pos + 4));
        if (StartsWith(body, "(") && EndsWith(body, ")")) {
            body = body.substr(1, body.size() - 2);
        }

        long long iterations = 0;
        for (long long i = start; step > 0 ? i <= end : i >= end; i += step) {
            if (!st.env.IncStep()) {
                st.Log("FOR /L aborted: execution step limit reached");
                return;
            }
            if (++iterations > 10000) {
                st.Log("FOR /L aborted: iteration limit reached");
                return;
            }
            std::string val = std::to_string(i);
            st.globals[var_name] = val;
            st.globals["env:" + var_name] = val;
            std::string processed = body;
            std::string loop_marker = "%%" + var_name;
            std::string runtime_marker = "%" + var_name + "%";
            ReplaceAll(processed, loop_marker, runtime_marker);
            std::string expanded = ExpandVars(st, processed);

            st.Log(
                "FOR iteration " +
                std::to_string(i) +
                ": " +
                expanded
            );

            std::vector<std::string> commands =
                SplitCmdCommands(expanded);

            for (const std::string& command : commands) {
                std::string cmd_line = Trim(command);

                if (!cmd_line.empty()) {
                    ExecuteLine(st, cmd_line);
                }
            }
        }

        if (!st.log.empty()) {
            std::vector<std::string> chunks;
            std::string current;
            const size_t chunk_lines = 25;

            for (const auto& entry : st.log) {
                current += entry + "\n";

                size_t count = 0;
                for (char c : current) {
                    if (c == '\n') ++count;
                }

                if (count >= chunk_lines) {
                    chunks.push_back(current);
                    current.clear();
                }
            }

            if (!current.empty()) {
                chunks.push_back(current);
            }

            for (size_t i = 0; i < chunks.size(); ++i) {
                std::string title = "Sandbox Execution Log";
                if (chunks.size() > 1) {
                    title += " (" + std::to_string(i + 1) + "/" +
                             std::to_string(chunks.size()) + ")";
                }

                /*
                MessageBoxA(
                    nullptr,
                    chunks[i].c_str(),
                    title.c_str(),
                    MB_OK | MB_ICONINFORMATION
                );
                */
            }
        }
    }

    // ============================================================
    //  CMD expression evaluator (variable expansion + arithmetic)
    // ============================================================
    enum class CmdTok { End, Num, Ident, Plus, Minus, Star, Slash, Percent,
                        Amp, Pipe, Caret, LShift, RShift, LParen, RParen };

    struct CmdToken {
        CmdTok type;
        long long value;
        std::string text;
    };

    class CmdLexer {
    public:
        explicit CmdLexer(const std::string& s) : s_(s), pos_(0) { Next(); }

        CmdToken Peek() const { return cur_; }

        CmdToken Next() {
            SkipWs();
            if (pos_ >= s_.size()) return cur_ = {CmdTok::End, 0, ""};
            char c = s_[pos_];
            if (c == '+') { ++pos_; return cur_ = {CmdTok::Plus, 0, "+"}; }
            if (c == '-') { ++pos_; return cur_ = {CmdTok::Minus, 0, "-"}; }
            if (c == '*') { ++pos_; return cur_ = {CmdTok::Star, 0, "*"}; }
            if (c == '/') { ++pos_; return cur_ = {CmdTok::Slash, 0, "/"}; }
            if (c == '%') { ++pos_; return cur_ = {CmdTok::Percent, 0, "%"}; }
            if (c == '&') { ++pos_; return cur_ = {CmdTok::Amp, 0, "&"}; }
            if (c == '|') { ++pos_; return cur_ = {CmdTok::Pipe, 0, "|"}; }
            if (c == '^') { ++pos_; return cur_ = {CmdTok::Caret, 0, "^"}; }
            if (c == '(') { ++pos_; return cur_ = {CmdTok::LParen, 0, "("}; }
            if (c == ')') { ++pos_; return cur_ = {CmdTok::RParen, 0, ")"}; }
            if (c == '<' && pos_ + 1 < s_.size() && s_[pos_+1] == '<') {
                pos_ += 2; return cur_ = {CmdTok::LShift, 0, "<<"}; }
            if (c == '>' && pos_ + 1 < s_.size() && s_[pos_+1] == '>') {
                pos_ += 2; return cur_ = {CmdTok::RShift, 0, ">>"}; }
            if (std::isdigit(static_cast<unsigned char>(c))) {
                size_t start = pos_;
                long long val = 0;
                while (pos_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[pos_]))) {
                    val = val * 10 + (s_[pos_] - '0');
                    ++pos_;
                }
                return cur_ = {CmdTok::Num, val, s_.substr(start, pos_ - start)};
            }
            if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') {
                size_t start = pos_;
                while (pos_ < s_.size() &&
                       (std::isalnum(static_cast<unsigned char>(s_[pos_])) || s_[pos_] == '_')) {
                    ++pos_;
                }
                return cur_ = {CmdTok::Ident, 0, s_.substr(start, pos_ - start)};
            }
            // Skip unknown char.
            ++pos_;
            return Next();
        }

    private:
        void SkipWs() {
            while (pos_ < s_.size() && std::isspace(static_cast<unsigned char>(s_[pos_]))) ++pos_;
        }

        std::string s_;
        size_t pos_;
        CmdToken cur_;
    };

    static long long ParsePrimary(InterpreterState& st, CmdLexer& lex) {
        CmdToken t = lex.Peek();
        if (t.type == CmdTok::Num) {
            lex.Next();
            return t.value;
        }
        if (t.type == CmdTok::Ident) {
            lex.Next();
            std::string name = t.text;
            // Variable reference inside arithmetic expression.
            std::string val;
            auto it = st.globals.find(name);
            if (it != st.globals.end()) val = it->second;
            // Try parse as number.
            if (!val.empty()) {
                char* end = nullptr;
                long long n = std::strtoll(val.c_str(), &end, 0);
                if (end && *end == '\0') return n;
            }
            return 0;
        }
        if (t.type == CmdTok::LParen) {
            lex.Next();
            long long v = ParseArithExpr(st, lex);
            if (lex.Peek().type == CmdTok::RParen) lex.Next();
            return v;
        }
        // Unary minus.
        if (t.type == CmdTok::Minus) {
            lex.Next();
            return -ParsePrimary(st, lex);
        }
        // Unary plus.
        if (t.type == CmdTok::Plus) {
            lex.Next();
            return ParsePrimary(st, lex);
        }
        // Bitwise not ~
        if (t.type == CmdTok::Caret) {
            lex.Next();
            return ~ParsePrimary(st, lex);
        }
        lex.Next();
        return 0;
    }

    static long long ParseMulDiv(InterpreterState& st, CmdLexer& lex) {
        long long left = ParsePrimary(st, lex);
        while (true) {
            CmdToken t = lex.Peek();
            if (t.type == CmdTok::Star) {
                lex.Next();
                left = left * ParsePrimary(st, lex);
            } else if (t.type == CmdTok::Slash) {
                lex.Next();
                long long rhs = ParsePrimary(st, lex);
                left = rhs == 0 ? 0 : left / rhs;
            } else if (t.type == CmdTok::Percent) {
                lex.Next();
                long long rhs = ParsePrimary(st, lex);
                left = rhs == 0 ? 0 : left % rhs;
            } else break;
        }
        return left;
    }

    static long long ParseAddSub(InterpreterState& st, CmdLexer& lex) {
        long long left = ParseMulDiv(st, lex);
        while (true) {
            CmdToken t = lex.Peek();
            if (t.type == CmdTok::Plus) {
                lex.Next();
                left = left + ParseMulDiv(st, lex);
            } else if (t.type == CmdTok::Minus) {
                lex.Next();
                left = left - ParseMulDiv(st, lex);
            } else break;
        }
        return left;
    }

    static long long ParseShift(InterpreterState& st, CmdLexer& lex) {
        long long left = ParseAddSub(st, lex);
        while (true) {
            CmdToken t = lex.Peek();
            if (t.type == CmdTok::LShift) {
                lex.Next();
                left = left << ParseAddSub(st, lex);
            } else if (t.type == CmdTok::RShift) {
                lex.Next();
                left = left >> ParseAddSub(st, lex);
            } else break;
        }
        return left;
    }

    static long long ParseBitwise(InterpreterState& st, CmdLexer& lex) {
        long long left = ParseShift(st, lex);
        while (true) {
            CmdToken t = lex.Peek();
            if (t.type == CmdTok::Amp) {
                lex.Next();
                left = left & ParseShift(st, lex);
            } else if (t.type == CmdTok::Pipe) {
                lex.Next();
                left = left | ParseShift(st, lex);
            } else break;
        }
        return left;
    }

    static long long ParseArithExpr(InterpreterState& st, CmdLexer& lex) {
        return ParseBitwise(st, lex);
    }

    static std::string EvalArithExpr(InterpreterState& st, const std::string& expr) {
        std::string clean;
        for (char c : expr) {
            if (!std::isspace(static_cast<unsigned char>(c))) clean.push_back(c);
        }
        if (clean.empty()) return "0";
        CmdLexer lex(clean);
        long long v = ParseArithExpr(st, lex);
        return std::to_string(v);
    }

    static std::string ExpandVarRef(InterpreterState& st, const std::string& name, const std::string& spec) {
        auto it = st.globals.find(name);
        std::string val = (it != st.globals.end()) ? it->second : "";
        if (spec.empty()) return val;

        // Substring: ~n,m
        std::regex subre(R"(~(-?\d+)(?:,(-?\d+))?)");
        std::smatch m;
        if (std::regex_search(spec, m, subre)) {
            int start = std::stoi(m[1].str());
            int len = m[2].matched ? std::stoi(m[2].str()) : (int)val.size();
            if (start < 0) start = (int)val.size() + start;
            if (start < 0) start = 0;
            if (start > (int)val.size()) return "";
            if (len < 0) len = (int)val.size() - start;
            if (start + len > (int)val.size()) len = (int)val.size() - start;
            return val.substr(start, len);
        }

        // String replacement: =old=new
        size_t eq = spec.find('=');
        if (eq != std::string::npos) {
            std::string oldStr = spec.substr(1, eq - 1);
            std::string newStr = spec.substr(eq + 1);
            size_t pos = 0;
            while ((pos = val.find(oldStr, pos)) != std::string::npos) {
                val.replace(pos, oldStr.size(), newStr);
                pos += newStr.size();
            }
            return val;
        }

        return val;
    }

    static std::string ExpandVars(InterpreterState& st, std::string s) {
        auto expand_with_regex =
            [&st](const std::string& input,
                const std::regex& re,
                bool delayed) -> std::string {
                    std::string out;
                    size_t last = 0;
                    std::smatch m;

                    while (last < input.size()) {
                        const std::string tail = input.substr(last);

                        if (!std::regex_search(tail, m, re))
                            break;

                        const size_t pos =
                            last + static_cast<size_t>(m.position());
                        const size_t len =
                            static_cast<size_t>(m.length());

                        out.append(input, last, pos - last);

                        std::string name = m[1].str();
                        std::string spec =
                            m[2].matched ? m[2].str().substr(1) : "";

                        if (delayed) {
                            // ???? !cmd%%i! / !cmd%i! ?????
                            size_t percent = name.find('%');
                            if (percent != std::string::npos) {
                                std::string prefix = name.substr(0, percent);
                                std::string suffix = name.substr(percent);

                                while (!suffix.empty() && suffix.front() == '%')
                                    suffix.erase(suffix.begin());

                                auto it = st.globals.find(suffix);
                                std::string value =
                                    (it != st.globals.end()) ? it->second : "";

                                name = prefix + value;
                            }
                        }

                        out += ExpandVarRef(st, name, spec);
                        last = pos + len;
                    }

                    out.append(input, last, std::string::npos);
                    return out;
            };

        /*
         * ?????????%var%
         *
         * ???
         * ?????? %%i????? %%i ?? FOR ??????
         * ??????? ExecuteForLoop() ?��????�I??
         */
        {
            static const std::regex re(
                R"(%([a-zA-Z0-9_]+)(:[^%]*)?%)"
            );

            std::string out;
            size_t last = 0;
            std::smatch m;

            while (last < s.size()) {
                std::string tail = s.substr(last);

                if (!std::regex_search(tail, m, re))
                    break;

                size_t pos =
                    last + static_cast<size_t>(m.position());

                size_t len =
                    static_cast<size_t>(m.length());

                out.append(s, last, pos - last);

                std::string name = m[1].str();
                std::string spec =
                    m[2].matched ? m[2].str().substr(1) : "";

                out += ExpandVarRef(st, name, spec);
                last = pos + len;
            }

            out.append(s, last, std::string::npos);
            s = std::move(out);
        }

        /*
         * ????????!var!
         */
        {
            static const std::regex re(
                R"(!([a-zA-Z0-9_%]+)(:[^!]*)?!)"
            );

            std::string out;
            size_t last = 0;
            std::smatch m;

            while (last < s.size()) {
                std::string tail = s.substr(last);

                if (!std::regex_search(tail, m, re))
                    break;

                size_t pos =
                    last + static_cast<size_t>(m.position());

                size_t len =
                    static_cast<size_t>(m.length());

                out.append(s, last, pos - last);

                std::string name = m[1].str();
                std::string spec =
                    m[2].matched ? m[2].str().substr(1) : "";

                /*
                 * ???? !cmd%%i!
                 *
                 * ExecuteForLoop() ??? %%i ?�I?? %i??
                 * ????????????????? !cmd%i!??
                 */
                size_t percent = name.find('%');

                if (percent != std::string::npos) {
                    std::string prefix =
                        name.substr(0, percent);

                    std::string loop_var =
                        name.substr(percent);

                    while (!loop_var.empty() &&
                           loop_var.front() == '%') {
                        loop_var.erase(loop_var.begin());
                    }

                    auto it = st.globals.find(loop_var);
                    std::string loop_value =
                        (it != st.globals.end())
                            ? it->second
                            : "";

                    name = prefix + loop_value;
                }

                out += ExpandVarRef(st, name, spec);
                last = pos + len;
            }

            out.append(s, last, std::string::npos);
            s = std::move(out);
        }

        return s;
    }

    static std::string EvalSetA(InterpreterState& st, const std::string& expr) {
        std::string clean;
        for (char c : expr) {
            if (!std::isspace(static_cast<unsigned char>(c))) clean.push_back(c);
        }
        if (clean.empty()) return "0";
        CmdLexer lex(clean);
        long long v = ParseArithExpr(st, lex);
        return std::to_string(v);
    }

    static void Spawn(InterpreterState& st,
                      const std::string& args) {
        if (!st.env.IncProcess()) {
            st.Log("CMD spawn aborted: process limit reached");
            return;
        }

        std::string expanded_args = Trim(args);

        int cpid = st.env.NewPid();

        st.env.processes[cpid] = {
            "child_process",
            st.pid,
            expanded_args
        };

        /*
         * start cmd /c xxx
         *
         * ??????????????? cmd.exe?????????????????
         * ?????��? cmd ?????????��?
         */
        st.Emit(
            "ProcessCreate",
            "cmd.exe",
            expanded_args,
            -1
        );

        st.Log("CMD spawn: " + expanded_args);

        std::string low = ToLower(expanded_args);

        /*
         * ??? cmd.exe ????? /c ?? /k??
         *
         * ????
         *
         *   cmd /c command
         *   cmd.exe /c command
         *   CMD /K command
         */
        size_t cmd_pos = std::string::npos;

        if (StartsWith(low, "cmd.exe")) {
            cmd_pos = 7;       // strlen("cmd.exe")
        } else if (StartsWith(low, "cmd")) {
            cmd_pos = 3;       // strlen("cmd")
        }

        bool is_cmd_child = (cmd_pos != std::string::npos);

        if (is_cmd_child) {
            /*
             * ???? cmd.exe ???????
             */
            while (cmd_pos < expanded_args.size() &&
                   std::isspace(
                       static_cast<unsigned char>(
                           expanded_args[cmd_pos]))) {
                ++cmd_pos;
            }

            std::string after_cmd =
                expanded_args.substr(cmd_pos);

            std::string after_low =
                ToLower(after_cmd);

            size_t option_pos = std::string::npos;
            size_t option_len = 0;

            if (StartsWith(after_low, "/c")) {
                option_pos = 0;
                option_len = 2;
            } else if (StartsWith(after_low, "/k")) {
                option_pos = 0;
                option_len = 2;
            }

            if (option_pos != std::string::npos) {
                /*
                 * ???? /c ?? /k??
                 */
                size_t payload_pos = option_len;

                while (payload_pos < after_cmd.size() &&
                       std::isspace(
                           static_cast<unsigned char>(
                               after_cmd[payload_pos]))) {
                    ++payload_pos;
                }

                std::string cmd_payload =
                    after_cmd.substr(payload_pos);

                cmd_payload = Trim(cmd_payload);

                if (!cmd_payload.empty()) {
                    st.Log("CMD payload extracted: " + cmd_payload);

                    InterpreterState cst(
                        st.env,
                        st.recorder,
                        st.log,
                        cpid,
                        st.pid,
                        "cmd",
                        st.globals
                    );

                    CmdInterpreter::Execute(
                        cst,
                        cmd_payload
                    );
                }
            } else {
                /*
                 * ??? /c ?? /k ????????????????
                 * "cmd ..." ????????????�
                 */
                st.Log(
                    "CMD child has no /c or /k payload: " +
                    expanded_args
                );
            }
        }

        st.env.DecProcess();
    }
};

void ExecuteCmdChild(InterpreterState& st, const std::string& args, int cpid)
{
    InterpreterState cst(st.env, st.recorder, st.log, cpid, st.pid, "child", st.globals);
    CmdInterpreter::Execute(cst, args);
}

void ExecuteCmdPayload(InterpreterState& st, const std::string& code)
{
    CmdInterpreter::Execute(st, code);
}

/* ============================================================
 *  JS / WScript interpreter
 * ============================================================ */

struct JsEnvironment {
    std::unordered_map<std::string, std::string> variables;
    std::unordered_map<std::string, std::string> files;
    std::unordered_map<std::string, std::string> registry;
    std::unordered_map<std::string, std::string> net_responses;
    struct Proc { std::string name; int ppid; std::string cmd; };
    std::unordered_map<int, Proc> processes;
    int next_pid = 1000;
    int next_bid = 1;
    int next_timestamp = 1;

    int NewPid() { return next_pid++; }
    int NewBid() { return next_bid++; }
    int Tick() { return next_timestamp++; }

    bool IncStep(int& steps) {
        static constexpr int kMax = 2000;
        if (steps >= kMax) return false;
        ++steps;
        return true;
    }
};

struct JsRuntime {
    JsEnvironment& env;
    BehaviorRecorder& recorder;
    std::vector<std::string>& log;
    int& execution_steps;
    int pid;
    int ppid;
    std::string source;
    std::unordered_map<std::string, std::string> vars;
    std::unordered_map<std::string, std::string> objects;
    int depth = 0;

    JsRuntime(JsEnvironment& e, BehaviorRecorder& r, std::vector<std::string>& l,
              int& steps, int p, int pp, const std::string& s)
        : env(e), recorder(r), log(l), execution_steps(steps),
          pid(p), ppid(pp), source(s) {}

    BehaviorRecord Emit(const std::string& action, const std::string& target,
                        const std::string& details, int parent = -1) {
        BehaviorRecord rec;
        rec.id = env.NewBid();
        rec.timestamp = env.Tick();
        rec.action = action;
        rec.target = target;
        rec.details = details;
        rec.parent_id = parent;
        rec.source = source;
        rec.pid = pid;
        rec.ppid = ppid;
        recorder.Record(action, target, details, parent, source, pid, ppid);
        log.push_back("EMIT: " + action + " target=" + target + " details=" + details);
        return rec;
    }

    void Log(const std::string& msg) { log.push_back("[" + source + "] " + msg); }

    std::string Eval(const std::string& expr);
    std::string EvalStatement(const std::string& stmt);
    void Execute(const std::string& code);
};

class JsInterpreter {
public:
    static void Execute(InterpreterState& st, const std::string& code) {
        try {
            if (st.depth >= VirtualEnvironment::kMaxRecursionDepth) {
                st.Log("JS interpret aborted: recursion depth limit reached");
                return;
            }
            if (!st.env.IncStep()) {
                st.Log("JS interpret aborted: execution step limit reached");
                return;
            }

            st.Log("JS interpret start");

            JsEnvironment js_env;
            js_env.variables = st.env.variables;
            js_env.files = st.env.files;
            js_env.registry = st.env.registry;
            for (const auto& p : st.env.processes) {
                js_env.processes[p.first] = {p.second.name, p.second.ppid, p.second.cmd};
            }
            js_env.next_pid = st.env.next_pid;
            js_env.next_bid = st.env.next_bid;
            js_env.next_timestamp = st.env.next_timestamp;

            int js_steps = 0;
            JsRuntime runtime(js_env, st.recorder, st.log, js_steps,
                              st.pid, st.ppid, "js");

            runtime.depth = st.depth + 1;
            runtime.Execute(code);

            st.env.variables = js_env.variables;
            st.env.files = js_env.files;
            st.env.registry = js_env.registry;
            st.env.processes.clear();
            for (const auto& p : js_env.processes) {
                st.env.processes[p.first] = {p.second.name, p.second.ppid, p.second.cmd};
            }
            st.env.next_pid = js_env.next_pid;
            st.env.next_bid = js_env.next_bid;
            st.env.next_timestamp = js_env.next_timestamp;

            st.Log("JS interpret done");
        } catch (...) {
            st.Log("JS interpret aborted: runtime exception");
        }
    }
};

static std::string JsUnescape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 1 < s.size()) {
            char c = s[i + 1];
            if (c == 'n') { out.push_back('\n'); ++i; }
            else if (c == 't') { out.push_back('\t'); ++i; }
            else if (c == 'r') { out.push_back('\r'); ++i; }
            else if (c == '\\') { out.push_back('\\'); ++i; }
            else if (c == '\"') { out.push_back('\"'); ++i; }
            else if (c == '\'') { out.push_back('\''); ++i; }
            else { out.push_back(s[i]); }
        } else {
            out.push_back(s[i]);
        }
    }
    return out;
}

static std::string JsDecodeString(const std::string& s) {
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') ||
                          (s.front() == '\'' && s.back() == '\''))) {
        std::string inner = s.substr(1, s.size() - 2);
        return JsUnescape(inner);
    }
    return s;
}

static std::string JsBase64Decode(const std::string& s) {
    std::string decoded;
    if (Base64Decode(s, decoded)) return decoded;
    return s;
}

static std::string JsCharCodeDecode(const std::string& s) {
    std::string out;
    bool in_num = false;
    std::string num;
    for (char c : s) {
        if (std::isdigit(static_cast<unsigned char>(c))) {
            num.push_back(c);
            in_num = true;
        } else {
            if (in_num && !num.empty()) {
                int v = std::stoi(num);
                if (v >= 0 && v <= 255) out.push_back(static_cast<char>(v));
                num.clear();
            }
            in_num = false;
            out.push_back(c);
        }
    }
    if (in_num && !num.empty()) {
        int v = std::stoi(num);
        if (v >= 0 && v <= 255) out.push_back(static_cast<char>(v));
    }
    return out;
}

static bool IsJsKeyword(const std::string& w) {
    static const std::unordered_set<std::string> kw = {
        "var","let","const","function","return","if","else","for","while","do",
        "switch","case","break","continue","new","this","typeof","instanceof",
        "true","false","null","undefined","try","catch","finally","throw"
    };
    return kw.count(w);
}

static std::string JsEvalExpr(JsRuntime& rt, const std::string& expr, int depth = 0);

static std::string JsGetProperty(JsRuntime& rt, const std::string& obj_path, const std::string& prop) {
    std::string low = ToLower(obj_path);
    std::string low_prop = ToLower(prop);

    if (low.find("wscript.shell") != std::string::npos || low.find("wscript") != std::string::npos) {
        if (low_prop == "environment" || low_prop == "expandenvironmentstrings") {
            return "";
        }
        if (low_prop == "regread" || low_prop == "regwrite") {
            return "";
        }
    }

    if (low.find("filesystemobject") != std::string::npos || low.find("fso") != std::string::npos) {
        if (low_prop == "opentextfile" || low_prop == "createtextfile" ||
            low_prop == "fileexists" || low_prop == "folderexists" ||
            low_prop == "getfile" || low_prop == "getfoldername") {
            return "";
        }
    }

    if (low.find("adodb.stream") != std::string::npos) {
        if (low_prop == "type" || low_prop == "writetext" ||
            low_prop == "savetofile" || low_prop == "position") {
            return "";
        }
    }

    if (low.find("xmlhttp") != std::string::npos) {
        if (low_prop == "open" || low_prop == "send" || low_prop == "responsebody") {
            return "";
        }
    }

    return "";
}

static std::string JsCallMethod(JsRuntime& rt, const std::string& obj_path,
                                const std::string& method, const std::vector<std::string>& args) {
    std::string low = ToLower(obj_path);
    std::string low_method = ToLower(method);
    rt.Log("JS call: obj=" + obj_path + " method=" + method + " args=" + std::to_string(args.size()));

    if (low.find("wscript.shell") != std::string::npos || low.find("wscript") != std::string::npos) {
        if (low_method == "run" && !args.empty()) {
            std::string cmd = args[0];
            rt.Emit("ProcessCreate", cmd, "JS WScript.Shell.Run");
            return "";
        }
        if (low_method == "exec" && !args.empty()) {
            std::string cmd = args[0];
            rt.Emit("ProcessCreate", cmd, "JS WScript.Shell.Exec");
            return "";
        }
        if (low_method == "environment") {
            return "";
        }
        if (low_method == "expandenvironmentstrings" && !args.empty()) {
            std::string var = args[0];
            auto it = rt.env.variables.find(var);
            if (it != rt.env.variables.end()) return it->second;
            return "%" + var + "%";
        }
        if (low_method == "regread" && !args.empty()) {
            rt.Emit("RegRead", args[0], "JS WScript.Shell.RegRead");
            return "";
        }
        if (low_method == "regwrite" && args.size() >= 3) {
            rt.Emit("RegSetValue", args[0], "JS WScript.Shell.RegWrite value=" + args[2]);
            return "";
        }
        if (low_method == "regdelete") {
            rt.Emit("RegDelete", args[0], "JS WScript.Shell.RegDelete");
            return "";
        }
    }

    if (low.find("filesystemobject") != std::string::npos || low.find("fso") != std::string::npos) {
        if (low_method == "opentextfile" && !args.empty()) {
            std::string path = args[0];
            rt.Emit("FileOpen", path, "JS FSO.OpenTextFile mode=" + (args.size() > 1 ? args[1] : "1"));
            return "";
        }
        if (low_method == "createtextfile" && !args.empty()) {
            std::string path = args[0];
            rt.Emit("FileWrite", path, "JS FSO.CreateTextFile");
            return "";
        }
        if (low_method == "fileexists" || low_method == "folderexists") {
            return "false";
        }
        if (low_method == "deletefile" && !args.empty()) {
            rt.Emit("FileDelete", args[0], "JS FSO.DeleteFile");
            return "";
        }
        if (low_method == "deletefolder" && !args.empty()) {
            rt.Emit("FileDelete", args[0], "JS FSO.DeleteFolder");
            return "";
        }
    }

    if (low.find("adodb.stream") != std::string::npos) {
        if (low_method == "type") {
            return args.empty() ? "2" : args[0];
        }
        if (low_method == "writetext" && !args.empty()) {
            return "";
        }
        if (low_method == "savetofile" && !args.empty()) {
            std::string path = args[0];
            rt.Emit("FileWrite", path, "JS ADODB.Stream.SaveToFile");
            return "";
        }
        if (low_method == "position") {
            return args.empty() ? "0" : args[0];
        }
        if (low_method == "read" || low_method == "readtext") {
            return "";
        }
        if (low_method == "open") {
            return "";
        }
        if (low_method == "close") {
            return "";
        }
    }

    if (low.find("xmlhttp") != std::string::npos) {
        if (low_method == "open") {
            if (args.size() >= 2) {
                std::string url = args[1];
                if (Contains(ToLower(url), "http://") || Contains(ToLower(url), "https://")) {
                    rt.Emit("NetworkConnect", url, "JS XMLHTTP.Open");
                }
            }
            return "";
        }
        if (low_method == "send") {
            return "";
        }
        if (low_method == "responsebody") {
            return "";
        }
    }

    if (low_method == "getasynckeystate" || low_method == "getkeystate") {
        rt.Emit("MemoryAlloc", "", "JS GetAsyncKeyState keylogger");
        return "0";
    }

    return "";
}

static std::string JsEvalPrimary(JsRuntime& rt, const std::string& expr, int depth = 0) {
    std::string s = Trim(expr);
    if (s.empty()) return "";

    if ((s.front() == '"' && s.back() == '"') ||
        (s.front() == '\'' && s.back() == '\'')) {
        return JsDecodeString(s);
    }

    if (StartsWith(s, "0x") || StartsWith(s, "0X")) {
        try {
            return std::to_string(std::stoi(s.substr(2), nullptr, 16));
        } catch (...) {}
    }

    size_t base64_pos = s.find("base64,");
    if (base64_pos != std::string::npos) {
        std::string payload = s.substr(base64_pos + 7);
        size_t end_quote = payload.find('"');
        if (end_quote != std::string::npos) payload = payload.substr(0, end_quote);
        std::string decoded = JsBase64Decode(payload);
        if (decoded != payload) return decoded;
    }

    if (Contains(ToLower(s), "fromcharcode")) {
        size_t start = s.find('(');
        size_t end = s.rfind(')');
        if (start != std::string::npos && end != std::string::npos && end > start) {
            std::string inner = s.substr(start + 1, end - start - 1);
            std::string decoded = JsCharCodeDecode(inner);
            if (decoded != inner) return decoded;
        }
    }

    if (Contains(ToLower(s), "eval(")) {
        size_t start = s.find('(');
        size_t end = s.rfind(')');
        if (start != std::string::npos && end != std::string::npos && end > start) {
            std::string inner = s.substr(start + 1, end - start - 1);
            std::string unquoted = JsDecodeString(Trim(inner));
            if (unquoted != inner) {
                rt.Log("JS eval payload detected");
                rt.Emit("IEXExecute", unquoted, "JS eval payload");
                return JsEvalExpr(rt, unquoted, depth + 1);
            }
        }
    }

    if (Contains(ToLower(s), "new activexobject(")) {
        size_t start = s.find('(');
        size_t end = s.find(')', start);
        if (start != std::string::npos && end != std::string::npos) {
            std::string obj_name = s.substr(start + 1, end - start - 1);
            obj_name = JsDecodeString(Trim(obj_name));
            rt.objects[obj_name] = "";
            rt.Emit("ActiveXObject", obj_name, "JS ActiveXObject creation");
            return obj_name;
        }
    }

    if (StartsWith(ToLower(s), "new ")) {
        return "";
    }

    auto it = rt.vars.find(s);
    if (it != rt.vars.end()) return it->second;

    if (std::all_of(s.begin(), s.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c)) || c == '.' || c == '-';
    })) {
        return s;
    }

    return s;
}

static std::string JsEvalExpr(JsRuntime& rt, const std::string& expr, int depth) {
    // Guard against stack overflow from deeply nested expressions.
    // Depth > 64 is almost certainly malicious or malformed input.
    if (depth > 64) {
        rt.Log("JsEvalExpr recursion limit exceeded");
        return "";
    }
    std::string s = Trim(expr);
    if (s.empty()) return "";

    while (!s.empty() && (s.back() == ';' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();

    if (StartsWith(s, "var ") || StartsWith(s, "let ") || StartsWith(s, "const ")) {
        size_t eq = s.find('=');
        if (eq != std::string::npos) {
            std::string var_name = Trim(s.substr(4, eq - 4));
            std::string val_expr = s.substr(eq + 1);
            std::string val = JsEvalExpr(rt, val_expr, depth + 1);
            rt.vars[var_name] = val;
            return val;
        }
        return "";
    }

    size_t dot_pos = s.rfind('.');
    if (dot_pos != std::string::npos) {
        std::string left = Trim(s.substr(0, dot_pos));
        std::string right = Trim(s.substr(dot_pos + 1));

        if (right.find('(') != std::string::npos) {
            size_t paren = right.find('(');
            std::string method = Trim(right.substr(0, paren));
            std::string args_str = right.substr(paren + 1);
            size_t close = args_str.rfind(')');
            if (close != std::string::npos) args_str = args_str.substr(0, close);

            std::vector<std::string> args;
            size_t cur = 0, depth = 0, start = 0;
            for (size_t i = 0; i < args_str.size(); ++i) {
                if (args_str[i] == '(') ++depth;
                else if (args_str[i] == ')') --depth;
                else if (args_str[i] == ',' && depth == 0) {
                    args.push_back(Trim(args_str.substr(start, i - start)));
                    start = i + 1;
                }
            }
            args.push_back(Trim(args_str.substr(start)));

            std::string obj = JsEvalExpr(rt, left, depth + 1);
            for (std::string& a : args) a = JsEvalExpr(rt, a, depth + 1);
            return JsCallMethod(rt, obj, method, args);
        } else {
            std::string obj = JsEvalExpr(rt, left, depth + 1);
            return JsGetProperty(rt, obj, right);
        }
    }

    size_t paren = s.find('(');
    if (paren != std::string::npos) {
        std::string name = Trim(s.substr(0, paren));
        std::string args_str = s.substr(paren + 1);
        size_t close = args_str.rfind(')');
        if (close != std::string::npos) args_str = args_str.substr(0, close);

        if (ToLower(name) == "eval") {
            size_t end_quote = args_str.find('"');
            if (end_quote != std::string::npos) {
                std::string payload = JsDecodeString(Trim(args_str.substr(0, end_quote + 1)));
                rt.Log("JS eval detected");
                rt.Emit("IEXExecute", payload, "JS eval");
                return JsEvalExpr(rt, payload, depth + 1);
            }
            std::string payload = JsDecodeString(Trim(args_str));
            rt.Log("JS eval detected");
            rt.Emit("IEXExecute", payload, "JS eval");
            return JsEvalExpr(rt, payload, depth + 1);
        }

        if (ToLower(name) == "string.fromcharcode") {
            std::string decoded = JsCharCodeDecode(args_str);
            if (decoded != args_str) return decoded;
        }

        if (ToLower(name) == "atob") {
            std::string decoded = JsBase64Decode(JsDecodeString(Trim(args_str)));
            if (decoded != args_str) return decoded;
        }

        if (name == "unescape") {
            std::string inner = JsDecodeString(Trim(args_str));
            std::string out;
            for (size_t i = 0; i < inner.size(); ++i) {
                if (inner[i] == '%' && i + 2 < inner.size()) {
                    std::string hex = inner.substr(i + 1, 2);
                    char val = static_cast<char>(std::stoi(hex, nullptr, 16));
                    out.push_back(val);
                    i += 2;
                } else {
                    out.push_back(inner[i]);
                }
            }
            return out;
        }

        std::vector<std::string> args;
        size_t cur = 0, depth = 0, start = 0;
        for (size_t i = 0; i < args_str.size(); ++i) {
            if (args_str[i] == '(') ++depth;
            else if (args_str[i] == ')') --depth;
            else if (args_str[i] == ',' && depth == 0) {
                args.push_back(Trim(args_str.substr(start, i - start)));
                start = i + 1;
            }
        }
        args.push_back(Trim(args_str.substr(start)));

        if (StartsWith(ToLower(s), "new activexobject(")) {
            std::string obj_name = JsDecodeString(Trim(args_str));
            rt.objects[obj_name] = "";
            rt.Emit("ActiveXObject", obj_name, "JS ActiveXObject creation");
            return obj_name;
        }

        for (std::string& a : args) a = JsEvalExpr(rt, a, depth + 1);
        return JsCallMethod(rt, name, name, args);
    }

    if (StartsWith(s, "function ")) {
        return "";
    }

    if (StartsWith(s, "if ") || StartsWith(s, "if(")) {
        return "";
    }

    if (StartsWith(s, "while ") || StartsWith(s, "while(")) {
        return "";
    }

    if (StartsWith(s, "for ") || StartsWith(s, "for(")) {
        return "";
    }

    return JsEvalPrimary(rt, s, depth + 1);
}

static std::string JsEvalStatement(JsRuntime& rt, const std::string& stmt, int depth = 0) {
    std::string s = Trim(stmt);
    if (s.empty()) return "";

    if (StartsWith(s, "var ") || StartsWith(s, "let ") || StartsWith(s, "const ")) {
        return JsEvalExpr(rt, s, depth + 1);
    }

    if (StartsWith(s, "function ")) {
        return "";
    }

    if (StartsWith(s, "if ") || StartsWith(s, "if(")) {
        return "";
    }

    if (StartsWith(s, "while ") || StartsWith(s, "while(")) {
        return "";
    }

    if (StartsWith(s, "for ") || StartsWith(s, "for(")) {
        return "";
    }

    if (StartsWith(s, "return ")) {
        return JsEvalExpr(rt, s.substr(7), depth + 1);
    }

    if (Contains(s, std::string(1, '=')) && !StartsWith(s, "==") && !StartsWith(s, "===") &&
        !StartsWith(s, "!=") && !StartsWith(s, "!==")) {
        size_t eq = s.find('=');
        std::string left = Trim(s.substr(0, eq));
        std::string right = Trim(s.substr(eq + 1));
        if (!left.empty() && IsJsKeyword(left)) {
            return "";
        }
        std::string val = JsEvalExpr(rt, right, depth + 1);
        rt.vars[left] = val;
        return val;
    }

    return JsEvalExpr(rt, s, depth + 1);
}

void JsRuntime::Execute(const std::string& code) {
    if (!env.IncStep(execution_steps)) {
        Log("JS aborted: step limit");
        return;
    }

    std::string cleaned = code;
    ReplaceAll(cleaned, "\\r\\n", "\n");
    ReplaceAll(cleaned, "\\n", "\n");

    std::vector<std::string> lines = Split(cleaned, '\n');
    for (const std::string& line : lines) {
        std::string trimmed = Trim(line);
        if (trimmed.empty()) continue;
        Log("JS line: " + trimmed);
        JsEvalStatement(*this, trimmed);
    }
}

class Sandbox::Impl {
public:
    Impl() {}

    DetectionResult Analyze(const std::string& script_content) {
        DetectionResult res;
        try {
            VirtualEnvironment env;
            BehaviorRecorder recorder(env);
            std::unordered_map<std::string, std::string> globals;
            std::vector<std::string> log;

            int root_pid = env.NewPid();
            env.processes[root_pid] = {"root_script", -1, script_content};
            InterpreterState st(env, recorder, log, root_pid, -1, "root", globals);

            std::string cleaned = script_content;
            log.push_back("Deobfuscation rounds finished");

            // Dispatch based on dominant language.
            bool has_ps = Contains(ToLower(cleaned), "powershell") || Contains(cleaned, "$") ||
                          Contains(ToLower(cleaned), "invoke-") || Contains(ToLower(cleaned), "iex");
            bool has_cmd = Contains(ToLower(cleaned), "set ") || Contains(ToLower(cleaned), "cmd ") ||
                           Contains(ToLower(cleaned), "@echo") || Contains(ToLower(cleaned), "%");
            bool has_js = Contains(ToLower(cleaned), "wscript") || Contains(ToLower(cleaned), "wshell") ||
                          Contains(ToLower(cleaned), "activexobject") || Contains(ToLower(cleaned), "adodb") ||
                          Contains(ToLower(cleaned), "xmlhttp") || Contains(ToLower(cleaned), "scripting.filesystemobject") ||
                          Contains(ToLower(cleaned), "new activexobject") || Contains(ToLower(cleaned), "createobject") ||
                          Contains(cleaned, ".js") || Contains(ToLower(cleaned), "language=\"javascript\"") ||
                          Contains(ToLower(cleaned), "type=\"text/javascript\"");

            if (has_js && !has_ps && !has_cmd) {
                JsInterpreter::Execute(st, cleaned);
            } else if (has_cmd && !has_ps && !has_js) {
                CmdInterpreter::Execute(st, cleaned);
            } else if (has_ps && !has_cmd && !has_js) {
                PowershellInterpreter::Execute(st, cleaned);
            } else {
                // Mixed: prefer JS/PS unless there is a strong CMD marker at the start.
                std::string start = Trim(cleaned);
                if (StartsWith(ToLower(start), "@echo") ||
                    StartsWith(ToLower(start), "cmd ") ||
                    Contains(ToLower(start), "cmd /c"))
                    CmdInterpreter::Execute(st, cleaned);
                else if (has_js)
                    JsInterpreter::Execute(st, cleaned);
                else
                    PowershellInterpreter::Execute(st, cleaned);
            }

            recorder.LinkRelated();

            ChainDetector detector;
            auto matches = detector.Detect(recorder.Records());

            res.execution_log = std::move(log);
            for (const auto& r : recorder.Records()) {
                std::ostringstream oss;
                oss << "[" << r.timestamp << "] " << r.action << " target=" << r.target
                    << " details=" << r.details << " pid=" << r.pid;
                if (r.parent_id > 0) oss << " parent=" << r.parent_id;
                res.execution_log.push_back(oss.str());
            }

            if (matches.empty()) {
                // 行为链无匹配 → 判定为清洁。静态内容指纹检测已迁移至
                // BatchScan（ScriptDetectionEngine），此处不再重复。
                res.malicious = false;
                res.family = "BSD/Clean";
                res.severity_score = 0;
                return res;
            }

            // Pick best family by matched steps and order score.
            const auto* best = &matches[0];
            for (const auto& m : matches) {
                if (m.matched_steps > best->matched_steps ||
                    (m.matched_steps == best->matched_steps && m.order_score > best->order_score)) {
                    best = &m;
                }
            }

            res.malicious = true;
            res.family = best->family;
            res.severity_score = std::min(100, 50 + best->matched_steps * 10 + best->order_score);
            for (const auto& m : matches) {
                res.triggered_rules.push_back(m.family + " matched " +
                                              std::to_string(m.matched_steps) + "/" +
                                              std::to_string(m.total_steps) + " steps");
            }
        } catch (const std::exception& e) {
            res.execution_log.push_back(std::string("Sandbox exception: ") + e.what());
            res.malicious = false;
            res.family = "BSD/Error";
            res.severity_score = 0;
        } catch (...) {
            res.execution_log.push_back("Sandbox unknown exception");
            res.malicious = false;
            res.family = "BSD/Error";
            res.severity_score = 0;
        }
        return res;
    }
};

Sandbox::Sandbox() : d(std::make_unique<Impl>()) {}
Sandbox::~Sandbox() = default;

DetectionResult Sandbox::Analyze(const std::string& script_content) {
    return d->Analyze(script_content);
}

} // namespace ScriptSandbox

