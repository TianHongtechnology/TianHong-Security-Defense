/*++
Copyright (c) 2024  TianHong Security Defense

Module Name:
    WfpCallout.c

Abstract:
    WFP (Windows Filtering Platform) callout implementation for network
    traffic monitoring. Detects DoH (DNS over HTTPS) connections, C2
    port connections, and large HTTP POST exfiltration.

Environment:
    Kernel mode
--*/

/* WFP 头文件必须按 ntddk.h → ndis.h → fwpsk.h 顺序包含。
 * ndis.h 要求：
 *   1. NDIS_WDM：声明是 WDM 驱动（非 miniport）
 *   2. NDIS680：指定 NDIS 版本（Win10），否则 NET_BUFFER_LIST 等类型不会被定义
 * 不能包含 fltKernel.h（Common.h 引入），否则 NDIS 类型冲突。
 * 网络驱动是纯 WDM，不需要 minifilter，所以不需要 fltKernel.h。 */
#include <ntddk.h>
#include <ntstrsafe.h>

#ifndef NDIS_WDM
#define NDIS_WDM 1
#endif
#ifndef NDIS680
#define NDIS680
#endif
#pragma warning(push)
#pragma warning(disable:4201)
#include <ndis.h>
#pragma warning(pop)

#include <fwpsk.h>

/* INITGUID 必须在 fwpmk.h 之前定义，使 DEFINE_GUID 宏生成实际定义
 * (FWPM_LAYER_ALE_AUTH_CONNECT_V4 等 GUID 常量)，而非仅 extern 声明。 */
#ifndef INITGUID
#define INITGUID
#endif
#include <guiddef.h>
#include <fwpmk.h>

#include "WfpCallout.h"

/* RPC_C_AUTHN_DEFAULT 不在内核头文件中定义，需手动声明（用于 FwpmEngineOpen0） */
#ifndef RPC_C_AUTHN_DEFAULT
#define RPC_C_AUTHN_DEFAULT ((UINT32)0xFFFFFFFF)
#endif

/* ── 全局变量 ── */
BOOLEAN g_bNetworkProtectionEnabled = FALSE;
HANDLE g_WfpEngineHandle = NULL;
UINT32 g_WfpCalloutIdV4 = 0;
UINT32 g_WfpCalloutIdV6 = 0;
UINT32 g_WfpCalloutIdStreamV4 = 0;
KSPIN_LOCK g_DohServerLock;
DOH_SERVER_RECORD g_DohServers[MAX_DOH_SERVERS] = { 0 };
NETWORK_EVENT_RING g_NetEventRing = { 0 };

/* ── 默认 DoH 服务器域名 ── */
const char* g_defaultDohDomains[] = {
    "dns.alidns.com",
    "dns.google",
    "cloudflare-dns.com",
    "doh.pub",
    "dns.adguard.com",
    "dns.quad9.net",
    "doh.opendns.com",
    "dns.smith.ai",
    "doh.powerdns.org",
    "dns.controld.com",
    "doh.mullvad.net",
    "dns.nextdns.io"
};
const ULONG g_defaultDohDomainCount = sizeof(g_defaultDohDomains) / sizeof(g_defaultDohDomains[0]);

/* ── 已知 C2 端口 ── */
const USHORT g_c2Ports[C2_PORT_COUNT] = {
    4444, 8888, 1337, 9001, 1234, 4443,
    8443, 9999, 31337, 6667, 6668, 6669
};

/* ── 内部函数声明 ── */
/* FWPS_CALLOUT_CLASSIFY_FN2 签名要求返回 void 并包含 classifyContext 参数 */
static void NTAPI WfpAleConnectCalloutV4(
    IN FWPS_INCOMING_VALUES0* inFixedValues,
    IN FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN void* layerData,
    IN const void* classifyContext,
    IN const FWPS_FILTER2* filter,
    IN UINT64 flowContext,
    IN OUT FWPS_CLASSIFY_OUT0* classifyOut);

static void NTAPI WfpAleConnectCalloutV6(
    IN FWPS_INCOMING_VALUES0* inFixedValues,
    IN FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN void* layerData,
    IN const void* classifyContext,
    IN const FWPS_FILTER2* filter,
    IN UINT64 flowContext,
    IN OUT FWPS_CLASSIFY_OUT0* classifyOut);

static void NTAPI WfpStreamCalloutV4(
    IN FWPS_INCOMING_VALUES0* inFixedValues,
    IN FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN void* layerData,
    IN const void* classifyContext,
    IN const FWPS_FILTER2* filter,
    IN UINT64 flowContext,
    IN OUT FWPS_CLASSIFY_OUT0* classifyOut);

/* ═══════════════════════════════════════════════════════════════════════════
 * 事件环形缓冲区
 * ═══════════════════════════════════════════════════════════════════════════ */
VOID WfpAddEventToRing(PNETWORK_EVENT_DATA pEvent)
{
    KIRQL oldIrql;
    LONG head;

    if (pEvent == NULL) return;

    KeAcquireSpinLock(&g_NetEventRing.Lock, &oldIrql);
    head = g_NetEventRing.Head;
    RtlCopyMemory(&g_NetEventRing.Events[head], pEvent, sizeof(NETWORK_EVENT_DATA));
    head = (head + 1) % MAX_NETWORK_EVENTS;
    if (head == g_NetEventRing.Tail) {
        /* 缓冲区满，丢弃最旧的事件 */
        g_NetEventRing.Tail = (g_NetEventRing.Tail + 1) % MAX_NETWORK_EVENTS;
    }
    g_NetEventRing.Head = head;
    KeReleaseSpinLock(&g_NetEventRing.Lock, oldIrql);
}

BOOLEAN WfpPollEvent(PNETWORK_EVENT_DATA pOutEvent)
{
    KIRQL oldIrql;
    BOOLEAN hasEvent = FALSE;

    if (pOutEvent == NULL) return FALSE;

    KeAcquireSpinLock(&g_NetEventRing.Lock, &oldIrql);
    if (g_NetEventRing.Tail != g_NetEventRing.Head) {
        RtlCopyMemory(pOutEvent, &g_NetEventRing.Events[g_NetEventRing.Tail],
            sizeof(NETWORK_EVENT_DATA));
        g_NetEventRing.Tail = (g_NetEventRing.Tail + 1) % MAX_NETWORK_EVENTS;
        hasEvent = TRUE;
    }
    KeReleaseSpinLock(&g_NetEventRing.Lock, oldIrql);
    return hasEvent;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * DoH 服务器管理
 * ═══════════════════════════════════════════════════════════════════════════ */
NTSTATUS WfpAddDohServer(PDOH_SERVER_ENTRY pEntry)
{
    KIRQL oldIrql;
    ULONG i;

    if (pEntry == NULL) return STATUS_INVALID_PARAMETER;

    KeAcquireSpinLock(&g_DohServerLock, &oldIrql);
    /* 查找空槽或重复项 */
    for (i = 0; i < MAX_DOH_SERVERS; i++) {
        if (g_DohServers[i].Active &&
            g_DohServers[i].AddressType == pEntry->AddressType &&
            g_DohServers[i].Port == pEntry->Port &&
            RtlCompareMemory(g_DohServers[i].Address, pEntry->Address, 64) == 64)
        {
            KeReleaseSpinLock(&g_DohServerLock, oldIrql);
            return STATUS_SUCCESS; /* 已存在 */
        }
    }
    /* 查找空槽 */
    for (i = 0; i < MAX_DOH_SERVERS; i++) {
        if (!g_DohServers[i].Active) {
            g_DohServers[i].AddressType = pEntry->AddressType;
            RtlCopyMemory(g_DohServers[i].Address, pEntry->Address, 64);
            g_DohServers[i].Port = pEntry->Port;
            g_DohServers[i].Active = TRUE;
            KeReleaseSpinLock(&g_DohServerLock, oldIrql);
            return STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&g_DohServerLock, oldIrql);
    return STATUS_INSUFFICIENT_RESOURCES;
}

VOID WfpClearDohServers(VOID)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DohServerLock, &oldIrql);
    RtlZeroMemory(g_DohServers, sizeof(g_DohServers));
    KeReleaseSpinLock(&g_DohServerLock, oldIrql);
}

BOOLEAN WfpIsDohServer(const UCHAR* ip, ULONG ipType, USHORT port)
{
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_DohServerLock, &oldIrql);
    for (i = 0; i < MAX_DOH_SERVERS; i++) {
        if (!g_DohServers[i].Active) continue;
        if (g_DohServers[i].AddressType != ipType) continue;
        if (g_DohServers[i].Port != 0 && g_DohServers[i].Port != port) continue;
        if (RtlCompareMemory(g_DohServers[i].Address, ip,
            (ipType == 0) ? 4 : 16) == ((ipType == 0) ? 4 : 16)) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_DohServerLock, oldIrql);
    return found;
}

BOOLEAN WfpIsDohDomain(const char* domain)
{
    ULONG i;
    if (domain == NULL || domain[0] == '\0') return FALSE;
    for (i = 0; i < g_defaultDohDomainCount; i++) {
        /* 简单子串匹配：域名包含 DoH 服务器域名 */
        const char* p = domain;
        const char* needle = g_defaultDohDomains[i];
        int nlen = 0;
        while (needle[nlen]) nlen++;
        while (*p) {
            int j;
            for (j = 0; j < nlen && p[j] && (CHAR)(p[j] | 0x20) == (CHAR)(needle[j] | 0x20); j++);
            if (j == nlen) return TRUE;
            p++;
        }
    }
    return FALSE;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * 辅助函数：生成并发送网络事件
 * ═══════════════════════════════════════════════════════════════════════════ */
static VOID WfpSendEvent(
    INT64 pid,
    ULONG eventType,
    ULONG protocol,
    ULONG localPort,
    ULONG remotePort,
    const UCHAR* remoteAddr,
    ULONG addrType,
    BOOLEAN isOutbound,
    const CHAR* processName,
    const CHAR* extraContext)
{
    NETWORK_EVENT_DATA evt;
    ULONG nameLen = 0;
    ULONG ctxLen = 0;
    ULONG offset = 0;

    RtlZeroMemory(&evt, sizeof(evt));
    evt.CallerPid = pid;
    evt.EventType = eventType;
    evt.Protocol = protocol;
    evt.LocalPort = localPort;
    evt.RemotePort = remotePort;
    evt.RemoteAddressType = addrType;
    evt.IsOutbound = isOutbound ? 1 : 0;

    if (remoteAddr && addrType == 0) {
        RtlCopyMemory(evt.RemoteAddress, remoteAddr, 4);
    } else if (remoteAddr && addrType == 1) {
        RtlCopyMemory(evt.RemoteAddress, remoteAddr, 16);
    }

    /* 进程名放入 Payload 开头 */
    if (processName) {
        while (processName[nameLen] && nameLen < 62) {
            evt.Payload[nameLen] = processName[nameLen];
            nameLen++;
        }
        evt.Payload[nameLen] = '\0';
        nameLen++;
    }
    evt.ProcessNameOffset = 0;
    offset = nameLen;

    /* 额外上下文（URL/域名）跟在进程名后 */
    if (extraContext && offset < 256) {
        while (extraContext[ctxLen] && (offset + ctxLen) < 255) {
            evt.Payload[offset + ctxLen] = extraContext[ctxLen];
            ctxLen++;
        }
        evt.Payload[offset + ctxLen] = '\0';
        ctxLen++;
    }
    evt.PayloadSize = offset + ctxLen;

    WfpAddEventToRing(&evt);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ALE Auth Connect V4 Callout — 出站 IPv4 TCP/UDP 连接监控
 * ═══════════════════════════════════════════════════════════════════════════ */
static void NTAPI WfpAleConnectCalloutV4(
    IN FWPS_INCOMING_VALUES0* inFixedValues,
    IN FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN void* layerData,
    IN const void* classifyContext,
    IN const FWPS_FILTER2* filter,
    IN UINT64 flowContext,
    IN OUT FWPS_CLASSIFY_OUT0* classifyOut)
{
    UINT32 pid = 0;
    UINT8 protocol = 0;
    UINT16 localPort = 0, remotePort = 0;
    UINT8 remoteIp[4] = { 0 };
    BOOLEAN isOutbound = FALSE;
    BOOLEAN isDoh = FALSE;
    BOOLEAN isC2Port = FALSE;
    CHAR procName[64] = { 0 };
    UINT32 i;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (!g_bNetworkProtectionEnabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    __try {
        /* 获取 PID */
        if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
            pid = (UINT32)inMetaValues->processId;
        }
        if (pid == 0 || pid == 4) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }

        /* ALE_AUTH_CONNECT_V4 层仅对出站连接触发，isOutbound 恒为 TRUE */
        isOutbound = TRUE;

        /* 提取连接参数（按字段索引访问 inFixedValues） */
        if (inFixedValues->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
            for (i = 0; i < inFixedValues->valueCount; i++) {
                FWPS_INCOMING_VALUE0* val = &inFixedValues->incomingValue[i];
                switch (val->value.type) {
                    case FWP_UINT8:
                        /* FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL (index 5) */
                        if (i == 5)
                            protocol = val->value.uint8;
                        break;
                    case FWP_UINT16:
                        /* FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT (index 4) */
                        if (i == 4) localPort = val->value.uint16;
                        /* FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT (index 7) */
                        else if (i == 7) remotePort = val->value.uint16;
                        break;
                    case FWP_UINT32:
                        /* FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS (index 6) */
                        if (i == 6) {
                            UINT32 ip = val->value.uint32;
                            remoteIp[0] = (UINT8)(ip & 0xFF);
                            remoteIp[1] = (UINT8)((ip >> 8) & 0xFF);
                            remoteIp[2] = (UINT8)((ip >> 16) & 0xFF);
                            remoteIp[3] = (UINT8)((ip >> 24) & 0xFF);
                        }
                        break;
                }
            }
        }

        if (!isOutbound) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }

        /* 获取进程路径：FWPS_METADATA_FIELD_PROCESS_PATH → processPath (FWP_BYTE_BLOB*) */
        if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) {
            FWP_BYTE_BLOB* pathBlob = inMetaValues->processPath;
            if (pathBlob && pathBlob->data && pathBlob->size > 0) {
                ULONG copyChars = pathBlob->size / sizeof(WCHAR);
                if (copyChars > 62) copyChars = 62;
                for (i = 0; i < copyChars; i++) {
                    procName[i] = (CHAR)((WCHAR*)pathBlob->data)[i];
                }
                procName[copyChars] = '\0';
            }
        }

        /* 检测 DoH 连接：连接到已知 DoH 服务器的 443 端口 */
        if (protocol == 6 && remotePort == 443) { /* TCP 443 */
            isDoh = WfpIsDohServer(remoteIp, 0, 443);
        }

        /* 检测 C2 端口 */
        for (i = 0; i < C2_PORT_COUNT; i++) {
            if (remotePort == g_c2Ports[i]) {
                isC2Port = TRUE;
                break;
            }
        }

        /* 发送事件 */
        if (isDoh) {
            CHAR ctx[80];
            RtlStringCbPrintfA(ctx, sizeof(ctx), "DoH server %u.%u.%u.%u:%u",
                remoteIp[0], remoteIp[1], remoteIp[2], remoteIp[3], remotePort);
            WfpSendEvent((INT64)pid, NET_EVENT_DOH_CONNECT, protocol,
                localPort, remotePort, remoteIp, 0, TRUE, procName, ctx);
        }
        else if (isC2Port) {
            CHAR ctx[80];
            RtlStringCbPrintfA(ctx, sizeof(ctx), "C2 port %u.%u.%u.%u:%u",
                remoteIp[0], remoteIp[1], remoteIp[2], remoteIp[3], remotePort);
            WfpSendEvent((INT64)pid, NET_EVENT_C2_PORT, protocol,
                localPort, remotePort, remoteIp, 0, TRUE, procName, ctx);
        }
        else if (protocol == 6 && remotePort != 80 && remotePort != 443 &&
                 remotePort > 1024 && remotePort != 0) {
            /* 非 HTTP/HTTPS 的出站 TCP 连接 */
            WfpSendEvent((INT64)pid, NET_EVENT_TCP_CONNECT, protocol,
                localPort, remotePort, remoteIp, 0, TRUE, procName, NULL);
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* 异常时放行 */
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;
    return;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ALE Auth Connect V6 Callout — IPv6 版本（简化实现）
 * ═══════════════════════════════════════════════════════════════════════════ */
static void NTAPI WfpAleConnectCalloutV6(
    IN FWPS_INCOMING_VALUES0* inFixedValues,
    IN FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN void* layerData,
    IN const void* classifyContext,
    IN const FWPS_FILTER2* filter,
    IN UINT64 flowContext,
    IN OUT FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    return;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Stream V4 Callout — HTTP 内容检测
 * ═══════════════════════════════════════════════════════════════════════════ */
static void NTAPI WfpStreamCalloutV4(
    IN FWPS_INCOMING_VALUES0* inFixedValues,
    IN FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    IN void* layerData,
    IN const void* classifyContext,
    IN const FWPS_FILTER2* filter,
    IN UINT64 flowContext,
    IN OUT FWPS_CLASSIFY_OUT0* classifyOut)
{
    UINT32 pid = 0;
    UINT16 remotePort = 0;
    CHAR procName[64] = { 0 };
    NET_BUFFER_LIST* nbl = NULL;
    NET_BUFFER* nb = NULL;
    UCHAR httpData[512] = { 0 };
    ULONG dataLen = 0;
    UINT32 i;

    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);
    UNREFERENCED_PARAMETER(remotePort);

    if (!g_bNetworkProtectionEnabled) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    __try {
        if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) {
            pid = (UINT32)inMetaValues->processId;
        }
        if (pid == 0 || pid == 4) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }

        /* 获取进程路径：FWPS_METADATA_FIELD_PROCESS_PATH → processPath (FWP_BYTE_BLOB*) */
        if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_PATH) {
            FWP_BYTE_BLOB* pathBlob = inMetaValues->processPath;
            if (pathBlob && pathBlob->data && pathBlob->size > 0) {
                ULONG copyChars = pathBlob->size / sizeof(WCHAR);
                if (copyChars > 62) copyChars = 62;
                for (i = 0; i < copyChars; i++) {
                    procName[i] = (CHAR)((WCHAR*)pathBlob->data)[i];
                }
                procName[copyChars] = '\0';
            }
        }

        /* 检查 stream 数据（仅出站 HTTP） */
        nbl = (NET_BUFFER_LIST*)layerData;
        if (nbl == NULL) {
            classifyOut->actionType = FWP_ACTION_PERMIT;
            return;
        }

        nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        while (nb != NULL && dataLen < sizeof(httpData) - 1) {
            ULONG bufLen = NET_BUFFER_DATA_LENGTH(nb);
            ULONG copyLen = (bufLen < (sizeof(httpData) - 1 - dataLen)) ? bufLen : (sizeof(httpData) - 1 - dataLen);
            VOID* va = NdisGetDataBuffer(nb, copyLen, httpData + dataLen, 1, FALSE);
            if (va != NULL) {
                dataLen += copyLen;
            }
            nb = NET_BUFFER_NEXT_NB(nb);
        }

        if (dataLen >= 5) {
            /* 检测 HTTP POST 请求 */
            if (httpData[0] == 'P' && httpData[1] == 'O' &&
                httpData[2] == 'S' && httpData[3] == 'T' && httpData[4] == ' ')
            {
                /* 提取 Content-Length（简化版：如果 POST 请求 > 阈值则告警） */
                /* 检查是否有 Content-Length 头 */
                for (i = 0; i < dataLen - 15; i++) {
                    if (httpData[i] == 'C' && httpData[i+1] == 'o' &&
                        httpData[i+2] == 'n' && httpData[i+3] == 't' &&
                        httpData[i+4] == 'e' && httpData[i+5] == 'n' &&
                        httpData[i+6] == 't' && httpData[i+7] == '-' &&
                        (httpData[i+8] == 'L' || httpData[i+8] == 'l'))
                    {
                        /* 找到 Content-Length，解析值 */
                        CHAR lenStr[16] = { 0 };
                        ULONG j = i + 15;
                        ULONG k = 0;
                        while (j < dataLen && httpData[j] >= '0' && httpData[j] <= '9' && k < 15) {
                            lenStr[k++] = httpData[j++];
                        }
                        if (k > 0) {
                            INT64 contentLen = 0;
                            for (k = 0; lenStr[k]; k++) {
                                contentLen = contentLen * 10 + (lenStr[k] - '0');
                            }
                            if (contentLen > 4096) {
                                /* HTTP POST 大流量检测 */
                                WfpSendEvent((INT64)pid, NET_EVENT_HTTP_POST_LARGE,
                                    6 /* TCP */, 0, remotePort, NULL, 0, TRUE,
                                    procName, "Large HTTP POST data exfiltration");
                            }
                        }
                        break;
                    }
                }
            }

            /* 检测 DNS 隧道：HTTP 请求包含 /dns-query 路径（DoH 特征） */
            if (dataLen >= 10) {
                for (i = 0; i < dataLen - 10; i++) {
                    if (httpData[i] == '/' && httpData[i+1] == 'd' &&
                        httpData[i+2] == 'n' && httpData[i+3] == 's' &&
                        httpData[i+4] == '-' && httpData[i+5] == 'q' &&
                        httpData[i+6] == 'u' && httpData[i+7] == 'e' &&
                        httpData[i+8] == 'r' && httpData[i+9] == 'y')
                    {
                        /* DoH 请求特征路径 /dns-query */
                        WfpSendEvent((INT64)pid, NET_EVENT_DOH_CONNECT,
                            6, 0, 443, NULL, 0, TRUE,
                            procName, "DoH /dns-query path detected in HTTPS stream");
                        break;
                    }
                }
            }
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    classifyOut->actionType = FWP_ACTION_PERMIT;
    return;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * WfpRegisterCallouts — 注册 WFP callout
 * ═══════════════════════════════════════════════════════════════════════════ */
NTSTATUS WfpRegisterCallouts(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    FWPM_SESSION0 session = { 0 };
    FWPM_CALLOUT0 fwpmCallout = { 0 };
    FWPM_FILTER0 filter = { 0 };
    /* 使用固定 GUID 作为 sublayer key（全零 GUID 会被拒绝） */
    GUID defaultSublayerKey =
        { 0xabcd1234, 0x5678, 0x9abc, { 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc } };
    UNICODE_STRING sublayerNameU = RTL_CONSTANT_STRING(L"TianHongHips.Network Sublayer");
    UNICODE_STRING sublayerDescU = RTL_CONSTANT_STRING(L"Sublayer for TianHongHips.Network monitoring");

    KeInitializeSpinLock(&g_DohServerLock);
    KeInitializeSpinLock(&g_NetEventRing.Lock);
    g_NetEventRing.Head = 0;
    g_NetEventRing.Tail = 0;

    /* 打开 WFP Engine — FWPM_SESSION0 + FWPM_SESSION_FLAG_DYNAMIC 使对象在会话结束时自动清除 */
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, &session, &g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] FwpmEngineOpen0 failed: 0x%X\n", status);
        return status;
    }

    /* 在事务中注册 callout 和 filter */
    status = FwpmTransactionBegin0(g_WfpEngineHandle, 0);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] FwpmTransactionBegin0 failed: 0x%X\n", status);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    /* 添加 sublayer */
    {
        FWPM_SUBLAYER0 sublayer = { 0 };
        sublayer.subLayerKey = defaultSublayerKey;
        sublayer.displayData.name = sublayerNameU.Buffer;
        sublayer.displayData.description = sublayerDescU.Buffer;
        sublayer.flags = 0;
        sublayer.weight = 0xFFFF;
        status = FwpmSubLayerAdd0(g_WfpEngineHandle, &sublayer, NULL);
        if (!NT_SUCCESS(status) && status != STATUS_FWP_ALREADY_EXISTS) {
            DbgPrint("[TianHongHips.Network] FwpmSubLayerAdd0 failed: 0x%X\n", status);
            goto abort_txn;
        }
    }

    /* 注册 ALE Auth Connect V4 callout */
    {
        GUID calloutKey =
            { 0x12345678, 0x1234, 0x1234, { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } };
        FWPS_CALLOUT2 fwpsCallout = { 0 };

        /* 1. 用 FwpsCalloutRegister2 注册运行时 callout（函数指针） */
        fwpsCallout.calloutKey = calloutKey;
        fwpsCallout.flags = 0;
        fwpsCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)WfpAleConnectCalloutV4;
        fwpsCallout.notifyFn = NULL;
        fwpsCallout.flowDeleteFn = NULL;
        status = FwpsCalloutRegister2(DriverObject, &fwpsCallout, &g_WfpCalloutIdV4);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[TianHongHips.Network] FwpsCalloutRegister2 (V4) failed: 0x%X\n", status);
            goto abort_txn;
        }

        /* 2. 用 FwpmCalloutAdd0 将 callout 添加到 WFP 引擎（关联层 GUID） */
        RtlZeroMemory(&fwpmCallout, sizeof(fwpmCallout));
        fwpmCallout.calloutKey = calloutKey;
        fwpmCallout.displayData.name = sublayerNameU.Buffer;
        fwpmCallout.displayData.description = sublayerDescU.Buffer;
        fwpmCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        fwpmCallout.flags = 0;
        status = FwpmCalloutAdd0(g_WfpEngineHandle, &fwpmCallout, NULL, &g_WfpCalloutIdV4);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[TianHongHips.Network] FwpmCalloutAdd0 (V4) failed: 0x%X\n", status);
        }

        /* 3. 添加 filter 关联 callout */
        RtlZeroMemory(&filter, sizeof(filter));
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        filter.subLayerKey = defaultSublayerKey;
        filter.weight.type = FWP_UINT8;
        filter.weight.uint8 = 0x0F;
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        filter.action.calloutKey = calloutKey;
        status = FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, NULL);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[TianHongHips.Network] FwpmFilterAdd0 (V4) failed: 0x%X\n", status);
        }
    }

    /* 注册 ALE Auth Connect V6 callout */
    {
        GUID calloutKey =
            { 0x87654321, 0x4321, 0x4321, { 0x43, 0x21, 0x87, 0x65, 0x43, 0x21, 0xfe, 0xdc } };
        FWPS_CALLOUT2 fwpsCallout = { 0 };

        fwpsCallout.calloutKey = calloutKey;
        fwpsCallout.flags = 0;
        fwpsCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)WfpAleConnectCalloutV6;
        fwpsCallout.notifyFn = NULL;
        fwpsCallout.flowDeleteFn = NULL;
        status = FwpsCalloutRegister2(DriverObject, &fwpsCallout, &g_WfpCalloutIdV6);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[TianHongHips.Network] FwpsCalloutRegister2 (V6) failed: 0x%X\n", status);
        } else {
            RtlZeroMemory(&fwpmCallout, sizeof(fwpmCallout));
            fwpmCallout.calloutKey = calloutKey;
            fwpmCallout.displayData.name = sublayerNameU.Buffer;
            fwpmCallout.displayData.description = sublayerDescU.Buffer;
            fwpmCallout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            fwpmCallout.flags = 0;
            FwpmCalloutAdd0(g_WfpEngineHandle, &fwpmCallout, NULL, &g_WfpCalloutIdV6);

            RtlZeroMemory(&filter, sizeof(filter));
            filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
            filter.subLayerKey = defaultSublayerKey;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 0x0F;
            filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
            filter.action.calloutKey = calloutKey;
            FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, NULL);
        }
    }

    /* 注册 Stream V4 callout */
    {
        GUID calloutKey =
            { 0xaabbccdd, 0xeeff, 0x0011, { 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 } };
        FWPS_CALLOUT2 fwpsCallout = { 0 };

        fwpsCallout.calloutKey = calloutKey;
        fwpsCallout.flags = 0;
        fwpsCallout.classifyFn = (FWPS_CALLOUT_CLASSIFY_FN2)WfpStreamCalloutV4;
        fwpsCallout.notifyFn = NULL;
        fwpsCallout.flowDeleteFn = NULL;
        status = FwpsCalloutRegister2(DriverObject, &fwpsCallout, &g_WfpCalloutIdStreamV4);
        if (!NT_SUCCESS(status)) {
            DbgPrint("[TianHongHips.Network] FwpsCalloutRegister2 (Stream V4) failed: 0x%X\n", status);
        } else {
            RtlZeroMemory(&fwpmCallout, sizeof(fwpmCallout));
            fwpmCallout.calloutKey = calloutKey;
            fwpmCallout.displayData.name = sublayerNameU.Buffer;
            fwpmCallout.displayData.description = sublayerDescU.Buffer;
            fwpmCallout.applicableLayer = FWPM_LAYER_STREAM_V4;
            fwpmCallout.flags = 0;
            FwpmCalloutAdd0(g_WfpEngineHandle, &fwpmCallout, NULL, &g_WfpCalloutIdStreamV4);

            RtlZeroMemory(&filter, sizeof(filter));
            filter.layerKey = FWPM_LAYER_STREAM_V4;
            filter.subLayerKey = defaultSublayerKey;
            filter.weight.type = FWP_UINT8;
            filter.weight.uint8 = 0x0F;
            filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
            filter.action.calloutKey = calloutKey;
            FwpmFilterAdd0(g_WfpEngineHandle, &filter, NULL, NULL);
        }
    }

    status = FwpmTransactionCommit0(g_WfpEngineHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[TianHongHips.Network] FwpmTransactionCommit0 failed: 0x%X\n", status);
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
        return status;
    }

    /* 添加默认 DoH 服务器域名（R3 可以后续通过 IOCTL 添加 IP） */
    {
        ULONG i;
        for (i = 0; i < g_defaultDohDomainCount; i++) {
            DOH_SERVER_ENTRY entry;
            RtlZeroMemory(&entry, sizeof(entry));
            entry.AddressType = 2; /* domain */
            {
                ULONG dlen = 0;
                while (g_defaultDohDomains[i][dlen] && dlen < 63) dlen++;
                RtlCopyMemory(entry.Address, g_defaultDohDomains[i], dlen + 1);
            }
            entry.Port = 443;
            WfpAddDohServer(&entry);
        }
    }

    DbgPrint("[TianHongHips.Network] WFP callouts registered successfully\n");
    return STATUS_SUCCESS;

abort_txn:
    FwpmTransactionAbort0(g_WfpEngineHandle);
    FwpmEngineClose0(g_WfpEngineHandle);
    g_WfpEngineHandle = NULL;
    return status;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * WfpUnregisterCallouts — 注销 WFP callout
 * ═══════════════════════════════════════════════════════════════════════════ */
VOID WfpUnregisterCallouts(VOID)
{
    if (g_WfpEngineHandle != NULL) {
        FwpmEngineClose0(g_WfpEngineHandle);
        g_WfpEngineHandle = NULL;
    }
    if (g_WfpCalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdV4);
        g_WfpCalloutIdV4 = 0;
    }
    if (g_WfpCalloutIdV6 != 0) {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdV6);
        g_WfpCalloutIdV6 = 0;
    }
    if (g_WfpCalloutIdStreamV4 != 0) {
        FwpsCalloutUnregisterById0(g_WfpCalloutIdStreamV4);
        g_WfpCalloutIdStreamV4 = 0;
    }
    DbgPrint("[TianHongHips.Network] WFP callouts unregistered\n");
}
