#pragma once
#include "../shared/Common.h"
#include <string>
#include <vector>

// 驱动通信接口
HANDLE CommOpenDevice();
VOID CommCloseDevice(HANDLE hDevice);
BOOL CommSendIoctl(HANDLE hDevice, DWORD ioctlCode, LPVOID inBuffer, DWORD inSize, LPVOID outBuffer, DWORD outSize, LPDWORD bytesReturned);
BOOL CommSendRule(HANDLE hDevice, RULE_DATA* rule);
BOOL CommProtectProcess(HANDLE hDevice, ULONG pid);
BOOL CommAddFileRule(HANDLE hDevice, RULE_FILE_DATA* rule);
BOOL CommRemoveFileRule(HANDLE hDevice, ULONG ruleId);
BOOL CommClearFileRules(HANDLE hDevice);
BOOL CommRemoveRule(HANDLE hDevice, ULONG ruleId);
BOOL CommClearRules(HANDLE hDevice);
BOOL CommGetFileRuleStats(HANDLE hDevice, FILE_RULE_STATS* stats);
BOOL CommPollDetectedEvent(HANDLE hDevice, COMM_RESPONSE_PACKET* response);
BOOL CommSendUserResponse(HANDLE hDevice, NTSTATUS result, const char* message);
BOOL CommSetResponseCache(HANDLE hDevice, ULONG cmd);  // 0=disable, 1=enable, 2=clear
BOOL CommSetFullScanMode(HANDLE hDevice, BOOL enable);
BOOL CommSetUnsignedDllScan(HANDLE hDevice, BOOL enable, BOOL blocking);
BOOL CommSetBehaviorDetection(HANDLE hDevice, BOOL enable);
BOOL CommSetR3Protection(HANDLE hDevice, BOOL enable);
BOOL CommSetDcomProtection(HANDLE hDevice, BOOL bEnable);
BOOL CommSetProcessProtection(HANDLE hDevice, BOOL enable);
BOOL CommClearProtectedPids(HANDLE hDevice);
BOOL CommBehaviorEvaluate(HANDLE hDevice, BA_THREAT_RESULT* results, INT maxResults, INT* outCount);
BOOL CommBehaviorGetStats(HANDLE hDevice, BA_STATS* stats);
BOOL CommBehaviorClear(HANDLE hDevice);

// ── 动态规则相关函数 ──
BOOL CommLoadDynamicRule(HANDLE hDevice, BA_DYNAMIC_RULE_LOAD_REQ* req);
BOOL CommRemoveDynamicRule(HANDLE hDevice, ULONG ruleId);
BOOL CommClearDynamicRules(HANDLE hDevice);
BOOL CommGetDynamicRuleVersion(HANDLE hDevice, ULONG* pVersion);
BOOL CommGetDynamicRuleStats(HANDLE hDevice, std::vector<BA_RULE_STATS>& outStats);
BOOL CommGetDynamicRuleList(HANDLE hDevice, std::vector<BA_DYNAMIC_RULE>& outRules);
BOOL CommReportFeedback(HANDLE hDevice, ULONG ruleId, INT64 pid, const char* imagePath, ULONG action, INT64 timestampMs);