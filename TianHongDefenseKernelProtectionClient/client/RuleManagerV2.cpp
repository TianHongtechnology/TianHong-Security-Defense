#include "RuleManagerV2.h"
#include "Comm.h"
#include "ConsoleOutput.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <direct.h>

// ── TomlRuleParser 实现 ──

std::string TomlRuleParser::Trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string TomlRuleParser::LowerCase(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), ::tolower);
    return out;
}

bool TomlRuleParser::ReadFile(const std::string& path, std::string& content) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f.is_open()) return false;
    std::stringstream buf;
    buf << f.rdbuf();
    content = buf.str();
    return true;
}

ULONG TomlRuleParser::ResolveIndicatorId(const std::string& name) {
    std::string n = LowerCase(name);
    // 去掉 "ba_ind_" 前缀后匹配，兼容大小写
    // 进程类 (0-4)
    if (n == "ba_ind_proc_from_temp_dir") return 0;
    if (n == "ba_ind_proc_from_downloads_dir") return 1;
    if (n == "ba_ind_proc_from_appdata_dir") return 2;
    if (n == "ba_ind_proc_unsigned") return 3;
    // 文件类 (4-18)
    if (n == "ba_ind_file_create_system_dir") return 4;
    if (n == "ba_ind_file_create_driver") return 5;
    if (n == "ba_ind_file_create_startup_exe") return 6;
    if (n == "ba_ind_file_drop_from_temp") return 7;
    if (n == "ba_ind_file_create_dll_hijack") return 8;
    if (n == "ba_ind_file_encrypted_extension") return 9;
    if (n == "ba_ind_file_ransom_note") return 10;
    if (n == "ba_ind_file_dll_side_load") return 11;
    if (n == "ba_ind_file_browser_cred_target") return 12;
    if (n == "ba_ind_file_self_delete") return 13;
    if (n == "ba_ind_file_network_share") return 14;
    if (n == "ba_ind_file_inf_autorun") return 15;
    if (n == "ba_ind_file_hosts_modify") return 16;
    if (n == "ba_ind_file_disk_raw_access") return 17;
    if (n == "ba_ind_file_byovd_driver_load") return 18;
    // 注册表类 (19-24)
    if (n == "ba_ind_reg_modify_run_key") return 19;
    if (n == "ba_ind_reg_modify_ifeo_debugger") return 20;
    if (n == "ba_ind_reg_modify_winlogon") return 21;
    if (n == "ba_ind_reg_create_service") return 22;
    if (n == "ba_ind_reg_modify_shell_open") return 23;
    if (n == "ba_ind_reg_scheduled_task_create") return 24;
    // 内存类 (25-27)
    if (n == "ba_ind_mem_open_system_process") return 25;
    if (n == "ba_ind_mem_open_remote_thread") return 26;
    if (n == "ba_ind_mem_read_lsass") return 27;
    // 进程行为类 (28-36)
    if (n == "ba_ind_proc_kill_security_process") return 28;
    if (n == "ba_ind_proc_vssadmin_shadow_delete") return 29;
    if (n == "ba_ind_proc_bcdedit_recovery_disable") return 30;
    if (n == "ba_ind_proc_fake_update_installer") return 31;
    if (n == "ba_ind_proc_keyboard_hook") return 32;
    if (n == "ba_ind_proc_hidden_window") return 33;
    if (n == "ba_ind_file_appdata_dll") return 34;
    if (n == "ba_ind_network_c2_connect") return 35;
    if (n == "ba_ind_file_boot_execute") return 36;
    // Winkiller (37-41)
    if (n == "ba_ind_file_mass_system_delete") return 37;
    if (n == "ba_ind_reg_mass_delete") return 38;
    if (n == "ba_ind_file_boot_sector") return 39;
    if (n == "ba_ind_disk_mbr_write") return 40;
    if (n == "ba_ind_proc_critical_process_kill") return 41;
    // 脚本/命令行 (42-51)
    if (n == "ba_ind_proc_script_interpreter") return 42;
    if (n == "ba_ind_office_spawn_cmd") return 43;
    if (n == "ba_ind_certutil_download") return 44;
    if (n == "ba_ind_bitsadmin_transfer") return 45;
    if (n == "ba_ind_net_user_modify") return 46;
    if (n == "ba_ind_svchost_anomaly") return 47;
    if (n == "ba_ind_icacls_modify") return 48;
    if (n == "ba_ind_taskkill_security") return 49;
    if (n == "ba_ind_msiexec_silent_install") return 50;
    if (n == "ba_ind_wmi_persistence") return 51;
    // 注入检测 (52-54)
    if (n == "ba_ind_mem_cross_process_write") return 52;
    if (n == "ba_ind_mem_injection_chain") return 53;
    if (n == "ba_ind_mem_process_hollowing") return 54;
    // 高危系统操作 (55-58)
    if (n == "ba_ind_proc_raise_hard_error") return 55;
    if (n == "ba_ind_proc_set_critical") return 56;
    if (n == "ba_ind_proc_apc_injection") return 57;
    if (n == "ba_ind_proc_map_section") return 58;
    // PoolParty/原子权限 (59-64)
    if (n == "ba_ind_mem_vm_write_vm_operate") return 59;
    if (n == "ba_ind_mem_vm_oper_create_thread") return 60;
    if (n == "ba_ind_mem_vm_oper_dup_handle") return 61;
    if (n == "ba_ind_mem_poolparty_handle_request") return 62;
    // ETW TI 注入指标 (65-72)
    if (n == "ba_ind_mem_etw_remote_alloc_executable") return 63;
    if (n == "ba_ind_mem_etw_remote_protect_executable") return 64;
    if (n == "ba_ind_mem_etw_remote_write_memory") return 65;
    if (n == "ba_ind_mem_etw_remote_queue_apc") return 66;
    if (n == "ba_ind_mem_etw_remote_set_thread_context") return 67;
    if (n == "ba_ind_mem_etw_remote_map_view_executable") return 68;
    if (n == "ba_ind_mem_etw_alloc_to_protect_chain") return 69;
    if (n == "ba_ind_mem_etw_write_to_protect_chain") return 70;
    // Syscall 绕过 (71-72)
    if (n == "ba_ind_mem_direct_syscall") return 71;
    if (n == "ba_ind_mem_indirect_syscall") return 72;
    // 自加载/DLL 规避 (73)
    if (n == "ba_ind_file_self_loading") return 73;
    // T1218 执行指标 (74-79)
    if (n == "ba_ind_mshta_execution") return 74;
    if (n == "ba_ind_regsvr32_execution") return 75;
    if (n == "ba_ind_control_panel_item") return 76;
    if (n == "ba_ind_mavinject_injection") return 77;
    if (n == "ba_ind_cmstp_execution") return 78;
    if (n == "ba_ind_msdt_execution") return 79;
    if (n == "ba_ind_signed_binary_proxy") return 80;
    if (n == "ba_ind_applocker_bypass") return 81;
    // 网络/C2 (82-86)
    if (n == "ba_ind_net_c2_connect") return 82;
    if (n == "ba_ind_net_unknown_port") return 83;
    if (n == "ba_ind_net_suspicious_dns") return 84;
    if (n == "ba_ind_net_process_network") return 85;
    if (n == "ba_ind_net_long_connection") return 86;
    // ntdll unhook (87-89)
    if (n == "ba_ind_ntdll_unhook") return 87;
    if (n == "ba_ind_ntdll_remap") return 88;
    if (n == "ba_ind_ntdll_path_anomaly") return 89;
    // 勒索/批量写入 (90)
    if (n == "ba_ind_file_bulk_write") return 90;
    // DCOM 横向移动 (91-97)
    if (n == "ba_ind_dcom_remote_activation") return 91;
    if (n == "ba_ind_dcom_mmc20_shellexec") return 92;
    if (n == "ba_ind_dcom_shellwindows") return 93;
    if (n == "ba_ind_dcom_excel_dde") return 94;
    if (n == "ba_ind_dcom_outlook_createobject") return 95;
    if (n == "ba_ind_dcom_child_process") return 96;
    if (n == "ba_ind_dcom_wmi_remote") return 97;
    // Syscall 分类 (98-110)
    if (n == "ba_ind_syscall_alloc_vm") return 98;
    if (n == "ba_ind_syscall_protect_vm") return 99;
    if (n == "ba_ind_syscall_write_vm") return 100;
    if (n == "ba_ind_syscall_create_thread") return 101;
    if (n == "ba_ind_syscall_queue_apc") return 102;
    if (n == "ba_ind_syscall_map_view") return 103;
    if (n == "ba_ind_syscall_open_process") return 104;
    if (n == "ba_ind_syscall_multi_type") return 105;
    if (n == "ba_ind_syscall_injection_chain") return 106;
    if (n == "ba_ind_syscall_read_vm") return 107;
    if (n == "ba_ind_syscall_set_context") return 108;
    if (n == "ba_ind_syscall_resume_thread") return 109;
    if (n == "ba_ind_syscall_token_manip") return 110;
    if (n == "ba_ind_syscall_handle_dup") return 111;
    if (n == "ba_ind_syscall_create_process") return 112;
    if (n == "ba_ind_syscall_query_sysinfo") return 113;
    if (n == "ba_ind_syscall_query_process") return 114;
    if (n == "ba_ind_syscall_create_section") return 115;
    if (n == "ba_ind_syscall_read_lsass_chain") return 116;
    if (n == "ba_ind_syscall_token_steal_chain") return 117;
    if (n == "ba_ind_syscall_process_hollow") return 118;
    if (n == "ba_ind_syscall_suspend_thread") return 119;
    if (n == "ba_ind_syscall_get_context") return 120;
    if (n == "ba_ind_syscall_terminate_process") return 121;
    if (n == "ba_ind_syscall_flush_inst_cache") return 122;
    if (n == "ba_ind_syscall_create_key") return 123;
    if (n == "ba_ind_syscall_set_value_key") return 124;
    if (n == "ba_ind_syscall_create_file") return 125;
    if (n == "ba_ind_syscall_delete_file") return 126;
    if (n == "ba_ind_syscall_load_driver") return 127;
    if (n == "ba_ind_syscall_worker_factory") return 128;
    if (n == "ba_ind_syscall_create_named_pipe") return 129;
    if (n == "ba_ind_syscall_set_info_process") return 130;
    if (n == "ba_ind_syscall_persistence_chain") return 131;
    // 扩展指标 (132-144)
    if (n == "ba_ind_mem_self_protect_executable") return 132;
    if (n == "ba_ind_file_create_fake_sys_dir") return 133;
    if (n == "ba_ind_proc_taskkill_security_tool") return 134;
    if (n == "ba_ind_reg_mass_modify") return 135;
    if (n == "ba_ind_reg_vm_tz_query") return 136;
    if (n == "ba_ind_reg_vm_bios_query") return 137;
    if (n == "ba_ind_reg_ts_key_read") return 138;
    if (n == "ba_ind_mem_process_enum_batch") return 139;
    if (n == "ba_ind_mem_self_vm_operation_open") return 140;
    if (n == "ba_ind_img_load_via_rop") return 141;
    // ATT&CK 补充 (142-160)
    if (n == "ba_ind_file_motw_zone_identifier") return 142;
    if (n == "ba_ind_file_dll_unsigned_chain") return 143;
    if (n == "ba_ind_reg_uac_bypass_classes") return 144;
    if (n == "ba_ind_mem_token_impersonalation") return 145;
    if (n == "ba_ind_proc_create_with_token") return 146;
    if (n == "ba_ind_file_sam_hive_read") return 147;
    if (n == "ba_ind_reg_ds_replication_query") return 148;
    if (n == "ba_ind_file_dpapi_master_key") return 149;
    if (n == "ba_ind_reg_lsa_secrets_query") return 150;
    if (n == "ba_ind_proc_account_discovery") return 151;
    if (n == "ba_ind_reg_system_info_discovery") return 152;
    if (n == "ba_ind_file_screen_capture") return 153;
    if (n == "ba_ind_file_data_staged") return 154;
    if (n == "ba_ind_proc_system_shutdown") return 155;
    if (n == "ba_ind_file_elevation_service_hijack") return 156;
    if (n == "ba_ind_reg_elevation_service_hijack") return 157;
    if (n == "ba_ind_file_fake_dir_drop") return 158;
    if (n == "ba_ind_file_temp_random_name_exe") return 159;
    // 注入防护强化 (160-163)
    if (n == "ba_ind_mem_thread_start_unbacked") return 160;
    if (n == "ba_ind_proc_high_risk_parent") return 161;
    if (n == "ba_ind_proc_edr_freeze") return 162;
    if (n == "ba_ind_mem_injection_rate_limit") return 163;
    // 提权检测 (164-165)
    if (n == "ba_ind_proc_dacl_modify") return 164;
    if (n == "ba_ind_proc_trustedinstaller_dup") return 165;
    return 0;
}

bool TomlRuleParser::ValidateRule(const BA_DYNAMIC_RULE& rule, std::string* errorOut) {
    std::string err;

    if (rule.RuleId == 0) {
        err = "RuleId is 0 (skipped)";
    } else if (rule.IndicatorCount == 0) {
        err = "No indicators defined";
    } else if (rule.Threshold < 0.0 || rule.Threshold > 200.0) {
        err = "Threshold out of range (0-200)";
    } else {
        // 检查每个指标
        bool hasRequired = false;
        for (int i = 0; i < rule.IndicatorCount; i++) {
            auto& ind = rule.Indicators[i];
            if (ind.IndicatorId == 0) {
                err = "Unknown indicator ID at index " + std::to_string(i);
                break;
            }
            if (ind.Weight < 0.0 || ind.Weight > 200.0) {
                err = "Indicator[" + std::to_string(i) + "] weight out of range";
                break;
            }
            if (ind.Required) hasRequired = true;
        }
        if (err.empty() && !hasRequired && rule.MinMatchCount > 1) {
            err = "MinMatchCount>1 but no required indicators (may never trigger)";
        }
    }

    if (!err.empty() && errorOut) *errorOut = err;
    return err.empty();
}

bool TomlRuleParser::ParseFile(const std::string& filePath, std::vector<BA_DYNAMIC_RULE>& outRules) {
    std::string content;
    if (!ReadFile(filePath, content)) {
        printf("[ERROR] RuleManager: Cannot read rule file: %s\n", filePath.c_str());
        return false;
    }

    std::istringstream stream(content);
    std::string line;
    BA_DYNAMIC_RULE currentRule = {0};
    bool inDetection = false;
    bool inIndicators = false;
    bool inExceptions = false;
    int indicatorIdx = -1;
    int exceptionIdx = -1;
    bool hasRule = false;
    std::vector<ULONG> seenRuleIds;

    while (std::getline(stream, line)) {
        line = Trim(line);
        if (line.empty() || line[0] == '#') continue;

        // Section detection
        if (line == "[rule]") {
            // 保存上一条规则
            if (hasRule) {
                std::string err;
                if (ValidateRule(currentRule, &err)) {
                    // 检查重复 RuleId
                    bool dup = false;
                    for (auto rid : seenRuleIds) {
                        if (rid == currentRule.RuleId) { dup = true; break; }
                    }
                    if (dup) {
                        printf("[WARN] RuleManager: Duplicate RuleId=%lu in %s, skipping\n",
                               currentRule.RuleId, filePath.c_str());
                    } else {
                        seenRuleIds.push_back(currentRule.RuleId);
                        outRules.push_back(currentRule);
                    }
                } else {
                    printf("[WARN] RuleManager: Invalid rule in %s: %s\n",
                           filePath.c_str(), err.c_str());
                }
            }
            // 重置
            RtlZeroMemory(&currentRule, sizeof(currentRule));
            inDetection = false; inIndicators = false; inExceptions = false;
            indicatorIdx = -1; exceptionIdx = -1;
            hasRule = false;
            continue;
        }
        if (line == "[rule.detection]") { inDetection = true; hasRule = true; continue; }
        if (line == "[[rule.detection.indicators]]") {
            inIndicators = true; inExceptions = false; inDetection = false;
            if (currentRule.IndicatorCount < BA_DYN_MAX_INDICATORS) {
                indicatorIdx = currentRule.IndicatorCount++;
                RtlZeroMemory(&currentRule.Indicators[indicatorIdx], sizeof(BA_DYN_INDICATOR_REF));
            }
            continue;
        }
        if (line == "[[rule.exceptions]]") {
            inExceptions = true; inIndicators = false; inDetection = false;
            if (currentRule.ExceptionCount < BA_DYN_MAX_EXCEPTIONS) {
                exceptionIdx = currentRule.ExceptionCount++;
                RtlZeroMemory(&currentRule.Exceptions[exceptionIdx], sizeof(BA_DYN_EXCEPTION));
            }
            continue;
        }
        if (line.find("[rule.") == 0) {
            inDetection = false; inIndicators = false; inExceptions = false;
            continue;
        }

        // Key = Value
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = Trim(line.substr(0, eq));
        std::string val = Trim(line.substr(eq + 1));

        // 移除引号
        if (val.size() >= 2 && val.front() == '"' && val.back() == '"')
            val = val.substr(1, val.size() - 2);

        if (inDetection) {
            if (key == "threshold") currentRule.Threshold = (DOUBLE)atof(val.c_str());
            else if (key == "min_match_count") currentRule.MinMatchCount = atoi(val.c_str());
            else if (key == "direct_malicious") currentRule.DirectMalicious = (val == "true" || val == "1");
            else if (key == "name") strncpy_s(currentRule.Name, sizeof(currentRule.Name), val.c_str(), _TRUNCATE);
            else if (key == "description") strncpy_s(currentRule.Description, sizeof(currentRule.Description), val.c_str(), _TRUNCATE);
            else if (key == "severity") {
                std::string sv = LowerCase(val);
                if (sv == "critical") currentRule.Severity = 5;
                else if (sv == "high") currentRule.Severity = 4;
                else if (sv == "medium") currentRule.Severity = 3;
                else if (sv == "low") currentRule.Severity = 2;
                else currentRule.Severity = 1;
            }
            else if (key == "risk_score") currentRule.RiskScore = (ULONG)atol(val.c_str());
            else if (key == "threat_class") strncpy_s(currentRule.ThreatClass, sizeof(currentRule.ThreatClass), val.c_str(), _TRUNCATE);
            else if (key == "rule_id") currentRule.RuleId = (ULONG)atol(val.c_str());
            else if (key == "version") currentRule.Version = (ULONG)atol(val.c_str());
        }
        else if (inIndicators && indicatorIdx >= 0) {
            if (key == "id") {
                currentRule.Indicators[indicatorIdx].IndicatorId = ResolveIndicatorId(val);
                if (currentRule.Indicators[indicatorIdx].IndicatorId == 0) {
                    printf("[WARN] RuleManager: Unknown indicator '%s' in %s, skipping\n",
                           val.c_str(), filePath.c_str());
                }
            }
            else if (key == "weight") {
                currentRule.Indicators[indicatorIdx].Weight = (DOUBLE)atof(val.c_str());
            }
            else if (key == "required") {
                currentRule.Indicators[indicatorIdx].Required = (val == "true" || val == "1");
            }
        }
        else if (inExceptions && exceptionIdx >= 0) {
            if (key == "image_path") {
                strncpy_s(currentRule.Exceptions[exceptionIdx].ImagePath,
                          sizeof(currentRule.Exceptions[exceptionIdx].ImagePath),
                          val.c_str(), _TRUNCATE);
                currentRule.Exceptions[exceptionIdx].Enabled = TRUE;
            }
            else if (key == "reason") {
                strncpy_s(currentRule.Exceptions[exceptionIdx].Reason,
                          sizeof(currentRule.Exceptions[exceptionIdx].Reason),
                          val.c_str(), _TRUNCATE);
            }
        }
    }

    // 处理最后一条规则
    if (hasRule) {
        std::string err;
        if (ValidateRule(currentRule, &err)) {
            bool dup = false;
            for (auto rid : seenRuleIds) {
                if (rid == currentRule.RuleId) { dup = true; break; }
            }
            if (!dup) {
                seenRuleIds.push_back(currentRule.RuleId);
                outRules.push_back(currentRule);
            } else {
                printf("[WARN] RuleManager: Duplicate RuleId=%lu in %s, skipping\n",
                       currentRule.RuleId, filePath.c_str());
            }
        } else {
            printf("[WARN] RuleManager: Invalid rule in %s: %s\n",
                   filePath.c_str(), err.c_str());
        }
    }

    return !outRules.empty();
}

// ── RuleManager 实现 ──

bool DynamicRuleManagerV2::Init(HANDLE hDevice, const std::string& rulesDir) {
    m_hDevice = hDevice;
    m_rulesDir = rulesDir;
    m_lastVersion = 0;
    m_watching = FALSE;
    return LoadRules(rulesDir);
}

bool DynamicRuleManagerV2::LoadRules(const std::string& rulesDir) {
    if (m_hDevice == INVALID_HANDLE_VALUE) {
        m_hDevice = CommOpenDevice();
        if (m_hDevice == INVALID_HANDLE_VALUE) {
            wprintf(L"[ERROR] RuleManager: Cannot open device\n");
            return false;
        }
    }

    if (rulesDir.empty()) {
        wprintf(L"[INFO] RuleManager: No rules directory specified, using built-in baseline\n");
        return true;
    }

    TomlRuleParser parser;
    std::vector<BA_DYNAMIC_RULE> rules;

    // 扫描目录
    WIN32_FIND_DATAA findData;
    std::string pattern = rulesDir + "\\*.toml";
    HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        printf("[WARN] RuleManager: No TOML files found in %s\n", rulesDir.c_str());
        return true;
    }

    do {
        std::string filePath = rulesDir + "\\" + findData.cFileName;
        std::vector<BA_DYNAMIC_RULE> fileRules;
        if (parser.ParseFile(filePath, fileRules)) {
            rules.insert(rules.end(), fileRules.begin(), fileRules.end());
            printf("[INFO] RuleManager: Parsed %d rules from %s\n",
                    (int)fileRules.size(), findData.cFileName);
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    // 清除旧规则并加载新规则
    CommClearDynamicRules(m_hDevice);

    for (size_t i = 0; i < rules.size(); i++) {
        BA_DYNAMIC_RULE_LOAD_REQ req = { rules[i] };
        if (!CommLoadDynamicRule(m_hDevice, &req)) {
            wprintf(L"[WARN] RuleManager: Failed to load rule: %S\n", rules[i].Name);
        }
    }

    {
        ULONG ver = 0;
        CommGetDynamicRuleVersion(m_hDevice, &ver);
        m_lastVersion = ver;
    }
    wprintf(L"[COMPLETE] RuleManager: Loaded %zu rules, version=%lu\n",
            rules.size(), m_lastVersion);
    return true;
}

bool DynamicRuleManagerV2::StartWatching() {
    if (m_watching) return true;

    HANDLE hThread = CreateThread(NULL, 0, WatchThreadFunc, this, 0, NULL);
    if (hThread == NULL) {
        wprintf(L"[ERROR] RuleManager: Failed to start watch thread\n");
        return false;
    }
    CloseHandle(hThread);
    m_watching = TRUE;
    wprintf(L"[INFO] RuleManager: File watching started for %S\n", m_rulesDir.c_str());
    return true;
}

void DynamicRuleManagerV2::StopWatching() {
    m_watching = FALSE;
    wprintf(L"[INFO] RuleManager: File watching stopped\n");
}

ULONG DynamicRuleManagerV2::GetVersion() {
    if (m_hDevice == INVALID_HANDLE_VALUE) return 0;
    ULONG ver = 0;
    CommGetDynamicRuleVersion(m_hDevice, &ver);
    return ver;
}

bool DynamicRuleManagerV2::GetStats(std::vector<BA_RULE_STATS>& outStats) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    return CommGetDynamicRuleStats(m_hDevice, outStats);
}

bool DynamicRuleManagerV2::GetList(std::vector<BA_DYNAMIC_RULE>& outRules) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    return CommGetDynamicRuleList(m_hDevice, outRules);
}

void DynamicRuleManagerV2::UnloadAll() {
    if (m_hDevice != INVALID_HANDLE_VALUE) {
        CommClearDynamicRules(m_hDevice);
    }
    m_lastVersion = 0;
    wprintf(L"[INFO] RuleManager: All rules unloaded\n");
}

bool DynamicRuleManagerV2::ReportFeedback(ULONG ruleId, INT64 pid, const char* imagePath,
                                  ULONG action, INT64 timestampMs) {
    if (m_hDevice == INVALID_HANDLE_VALUE) return false;
    return CommReportFeedback(m_hDevice, ruleId, pid, imagePath, action, timestampMs);
}

// ── 文件监控线程 ──
DWORD WINAPI DynamicRuleManagerV2::WatchThreadFunc(LPVOID param) {
    ((DynamicRuleManagerV2*)param)->WatchThreadFunc();
    return 0;
}

void DynamicRuleManagerV2::WatchThreadFunc() {
    if (m_rulesDir.empty() || m_hDevice == INVALID_HANDLE_VALUE) return;

    HANDLE hDir = CreateFileA(
        m_rulesDir.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        wprintf(L"[ERROR] RuleManager: Cannot open rules directory for watching\n");
        m_watching = FALSE;
        return;
    }

    BYTE buffer[4096];
    DWORD bytesReturned = 0;

    while (m_watching) {
        if (ReadDirectoryChangesW(hDir, buffer, sizeof(buffer),
                                   FALSE,
                                   FILE_NOTIFY_CHANGE_CREATION |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE |
                                   FILE_NOTIFY_CHANGE_SIZE,
                                   &bytesReturned, NULL, NULL)) {
            // 检测到变更，重新加载
            wprintf(L"[INFO] RuleManager: Rules directory changed, reloading...\n");
            LoadRules(m_rulesDir);
        } else {
            Sleep(1000);
        }
    }

    CloseHandle(hDir);
}

void DynamicRuleManagerV2::ProcessRuleFile(const std::string& filePath, bool isAdd) {
    // 简化实现：直接重新加载整个目录
    LoadRules(m_rulesDir);
}
