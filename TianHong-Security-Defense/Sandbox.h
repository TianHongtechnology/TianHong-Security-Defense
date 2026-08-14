#pragma once
// Sandbox.h - C++ Script Behavior Analysis Sandbox
// Provides dynamic behavior-chain based detection for PowerShell/CMD mixed scripts.
// All operations are simulated; no real system state is touched.

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <set>
#include <deque>
#include <memory>
#include <functional>
#include <algorithm>
#include <cctype>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <regex>
#include <optional>
#include <variant>
#include <queue>
#include <stack>

namespace ScriptSandbox {

// A single simulated action observed during script execution.
struct BehaviorRecord {
    int id = 0;                 // Unique behavior identifier.
    int timestamp = 0;          // Monotonic step counter.
    std::string action;         // Action category: FileWrite, RegSetValue, etc.
    std::string target;         // Object of the action (path, URL, process name...)
    std::string details;        // Additional parameters / summary.
    int parent_id = -1;         // Parent behavior that caused this one, if known.
    std::string source;         // Source interpreter: "ps" / "cmd" / "child".
    int pid = 0;                // Simulated process id.
    int ppid = -1;              // Parent simulated process id.
};

// Final result produced by the sandbox.
struct DetectionResult {
    bool malicious = false;                       // Final verdict.
    std::string family = "Clean";                 // Malware family or "GenericMalware".
    int severity_score = 0;                       // 0-100 severity estimate.
    std::vector<std::string> triggered_rules;     // Human-readable matched chains.
    std::vector<std::string> execution_log;       // Execution / deobfuscation trace.
};

// Main sandbox entry point.
class Sandbox {
public:
    Sandbox();
    ~Sandbox();

    // Analyze a script (PowerShell, CMD, or mixed). Returns detection result.
    DetectionResult Analyze(const std::string& script_content);

private:
    class Impl;
    std::unique_ptr<Impl> d;
};

} // namespace ScriptSandbox
