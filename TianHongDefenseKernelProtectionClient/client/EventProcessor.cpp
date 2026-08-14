#include "EventProcessor.h"
#include "Comm.h"
#include "ConsoleOutput.h"
#include "../shared/Ioctl.h"
#include <windows.h>
#include <cstdio>

// 全局控制变量
static volatile BOOL g_bEventLoopRunning = FALSE;
static HANDLE g_hEventCommDevice = INVALID_HANDLE_VALUE;

// ============================================================================
// ProcessEvent - 处理单个事件，根据事件类型和严重级别打印不同颜色
// ============================================================================
void EventProcessor::ProcessEvent(const TH_EVENT_INFO& event)
{
    PrintSeparator();

    // 根据严重级别选择颜色
    switch (event.Severity)
    {
    case TH_SEVERITY_CRITICAL:
        SetConsoleColor(ConsoleColor::BrightRed);
        PrintFailure("事件严重级别: CRITICAL");
        break;
    case TH_SEVERITY_HIGH:
        SetConsoleColor(ConsoleColor::Red);
        PrintWarning("事件严重级别: HIGH");
        break;
    case TH_SEVERITY_MEDIUM:
        SetConsoleColor(ConsoleColor::Yellow);
        PrintInfo("事件严重级别: MEDIUM");
        break;
    case TH_SEVERITY_LOW:
    default:
        SetConsoleColor(ConsoleColor::Cyan);
        PrintInfo("事件严重级别: LOW");
        break;
    }
    ResetConsoleColor();

    // 输出事件来源
    const char* sourceStr = "未知";
    switch (event.Source)
    {
    case TH_EVENT_SOURCE_REGISTRY:   sourceStr = "注册表"; break;
    case TH_EVENT_SOURCE_FILE_SYSTEM: sourceStr = "文件系统"; break;
    case TH_EVENT_SOURCE_PROCESS:    sourceStr = "进程"; break;
    case TH_EVENT_SOURCE_MEMORY:     sourceStr = "内存"; break;
    }
    PrintInfo("事件来源: %s", sourceStr);

    // 输出事件动作
    const char* actionStr = "未知";
    switch (event.Action)
    {
    case TH_EVENT_ACTION_SET:    actionStr = "设置"; break;
    case TH_EVENT_ACTION_DELETE: actionStr = "删除"; break;
    case TH_EVENT_ACTION_RENAME: actionStr = "重命名"; break;
    case TH_EVENT_ACTION_READ:   actionStr = "读取"; break;
    case TH_EVENT_ACTION_WRITE:  actionStr = "写入"; break;
    case TH_EVENT_ACTION_CREATE: actionStr = "创建"; break;
    case TH_EVENT_ACTION_EXECUTE: actionStr = "执行"; break;
    }
    PrintInfo("事件动作: %s", actionStr);

    // 输出事件详情
    PrintInfo("进程PID: %d", event.ProcessPid);
    PrintInfo("进程名称: %s", event.ProcessName);
    PrintInfo("目标路径: %s", event.TargetPath);
    PrintInfo("目标名称: %s", event.TargetName);

    if (strlen(event.Detail) > 0)
    {
        PrintDebug("详细信息: %s", event.Detail);
    }

    PrintInfo("时间戳: %llu", event.Timestamp);

    PrintSeparator();
}

// ============================================================================
// StartEventLoop - 启动事件处理循环（轮询驱动检测事件）
// ============================================================================
void EventProcessor::StartEventLoop(HANDLE hCommDevice)
{
    if (g_bEventLoopRunning)
    {
        PrintWarning("EventProcessor: 事件循环已在运行中");
        return;
    }

    if (hCommDevice == NULL || hCommDevice == INVALID_HANDLE_VALUE)
    {
        PrintFailure("EventProcessor: 无效的驱动通信句柄");
        return;
    }

    g_hEventCommDevice = hCommDevice;
    g_bEventLoopRunning = TRUE;

    PrintInfo("EventProcessor: 事件处理循环已启动");

    COMM_RESPONSE_PACKET responsePacket;

    while (g_bEventLoopRunning)
    {
        ZeroMemory(&responsePacket, sizeof(responsePacket));

        BOOL hasEvent = CommPollDetectedEvent(g_hEventCommDevice, &responsePacket);

        if (!hasEvent)
        {
            Sleep(500);
            continue;
        }

        // 处理检测到的规则事件
        if (responsePacket.Type == RESPONSE_RULE_DETECTED)
        {
            COMM_RULE_DETECTED* ruleDetected = (COMM_RULE_DETECTED*)responsePacket.Data;

            PrintSeparator();
            SetConsoleColor(ConsoleColor::BrightYellow);
            PrintWarning("检测到规则触发事件");
            ResetConsoleColor();

            PrintInfo("规则ID: %d", ruleDetected->RuleId);
            PrintInfo("规则类型: %s", (ruleDetected->RuleType == 0) ? "注册表" : "文件");
            PrintInfo("进程PID: %d", ruleDetected->ProcessPid);

            // 根据规则类型解析不同的数据结构
            if (ruleDetected->RuleType == 0)
            {
                // 注册表规则检测
                RULE_REG_DETECTED_RESPONSE* regResponse = (RULE_REG_DETECTED_RESPONSE*)ruleDetected->Data;
                PrintInfo("路径: %s", regResponse->FullPath);

                if (regResponse->IsChangeValueEnabled)
                {
                    PrintDebug("修改的值: %s", regResponse->ChangeValue);
                }
                if (regResponse->IsChangeNameEnabled)
                {
                    PrintDebug("修改的名称: %s", regResponse->ChangeName);
                }
            }
            else if (ruleDetected->RuleType == 1)
            {
                // 文件规则检测
                RULE_FILE_DETECTED_RESPONSE* fileResponse = (RULE_FILE_DETECTED_RESPONSE*)ruleDetected->Data;
                PrintInfo("路径: %s", fileResponse->FullPath);
                PrintInfo("文件名: %s", fileResponse->FileName);
                PrintInfo("扩展名: %s", fileResponse->FileExt);

                if (fileResponse->IsChangePathEnabled)
                {
                    PrintDebug("修改的路径: %s", fileResponse->ChangePath);
                }
            }

            // 默认自动允许（后台模式）
            SetConsoleColor(ConsoleColor::Green);
            PrintComplete("EventProcessor: 自动允许操作");
            ResetConsoleColor();

            CommSendUserResponse(g_hEventCommDevice, STATUS_SUCCESS, "EventProcessor自动允许");
        }
        else
        {
            PrintDebug("EventProcessor: 收到未知响应类型 Type=%d", responsePacket.Type);
        }

        Sleep(100);
    }

    PrintInfo("EventProcessor: 事件处理循环已退出");
    g_hEventCommDevice = INVALID_HANDLE_VALUE;
}

// ============================================================================
// StopEventLoop - 停止事件处理循环
// ============================================================================
void EventProcessor::StopEventLoop()
{
    if (!g_bEventLoopRunning)
    {
        PrintWarning("EventProcessor: 事件循环未在运行");
        return;
    }

    PrintInfo("EventProcessor: 正在停止事件处理循环...");
    g_bEventLoopRunning = FALSE;
    PrintSuccess("EventProcessor: 事件处理循环已停止");
}