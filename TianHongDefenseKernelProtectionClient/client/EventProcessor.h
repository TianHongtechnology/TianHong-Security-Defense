#pragma once
#include "../shared/Event.h"

class EventProcessor {
public:
    static void ProcessEvent(const TH_EVENT_INFO& event);
    static void StartEventLoop(HANDLE hCommDevice);
    static void StopEventLoop();
};