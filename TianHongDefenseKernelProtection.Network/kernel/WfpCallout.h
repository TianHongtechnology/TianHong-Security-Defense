#pragma once

/* WFP callout 驱动使用纯 WDM，不依赖 minifilter（fltKernel.h）。
 * 自包含所需类型定义，避免引入 Common.h（含 fltKernel.h）导致 NDIS 类型冲突。 */
#include <ntddk.h>

/* ── IOCTL 代码（与 Common.h 保持一致） ── */
#define IOCTL_NETWORK_SET_ENABLED          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_POLL_EVENT           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x841, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_GET_STATUS           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x842, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_ADD_DOH_SERVER       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x843, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NETWORK_CLEAR_DOH_SERVERS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x844, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* ── 设备/符号链接名（与 Common.h 保持一致） ── */
#define NETWORK_DEVICE_NAME          L"\\Device\\TianHongNetworkFilter"
#define NETWORK_SYMLINK_NAME         L"\\??\\TianHongNetworkFilter"
#define NETWORK_DRIVER_PREFIX        "[TianHongHips.Network] "

/* ── 网络事件类型 ── */
#define NET_EVENT_DOH_CONNECT        0   /* 连接到已知 DoH 服务器 */
#define NET_EVENT_C2_CONNECT         1   /* 连接到已知 C2 端口 */
#define NET_EVENT_HTTP_POST_LARGE    2   /* 大流量 HTTP POST（外传） */
#define NET_EVENT_DNS_QUERY          3   /* DNS 查询 */
#define NET_EVENT_DNS_TUNNEL         5   /* DNS 隧道检测 */
#define NET_EVENT_C2_PORT            6   /* 连接到已知 C2 端口 */
#define NET_EVENT_TCP_CONNECT        7   /* 出站 TCP 连接（非 HTTP/HTTPS） */

/* ── 网络事件数据（kernel -> R3 共享，与 Common.h 保持一致） ── */
#pragma pack(push, 8)
typedef struct _NETWORK_EVENT_DATA {
    INT64   CallerPid;
    ULONG   EventType;
    ULONG   Protocol;
    ULONG   LocalPort;
    ULONG   RemotePort;
    UCHAR   RemoteAddress[16];
    ULONG   RemoteAddressType;
    ULONG   IsOutbound;
    ULONG   ProcessNameOffset;
    ULONG   PayloadSize;
    UCHAR   Payload[256];
} NETWORK_EVENT_DATA, *PNETWORK_EVENT_DATA;
#pragma pack(pop)

/* ── DoH 服务器条目（R3 -> kernel 共享，与 Common.h 保持一致） ── */
#pragma pack(push, 8)
typedef struct _DOH_SERVER_ENTRY {
    UCHAR   AddressType;
    UCHAR   Address[64];
    ULONG   Port;
} DOH_SERVER_ENTRY, *PDOH_SERVER_ENTRY;
#pragma pack(pop)

/* ============================================================================
 * WfpCallout.h — WFP Callout 注册与管理
 * 监控出站 TCP/UDP 连接，检测 DoH/C2/DNS 隧道
 * ========================================================================== */

/* 已知 DoH 服务器域名列表（运行时可由 R3 通过 IOCTL 添加） */
#define MAX_DOH_SERVERS         32
#define MAX_DOH_DOMAIN_LEN      128

/* DoH 服务器记录 */
typedef struct _DOH_SERVER_RECORD {
    UCHAR   AddressType;            /* 0=IPv4, 1=IPv6, 2=domain */
    UCHAR   Address[64];            /* IP 或域名 */
    ULONG   Port;                   /* 端口 */
    BOOLEAN Active;
} DOH_SERVER_RECORD;

/* 已知 C2 端口列表 */
#define C2_PORT_COUNT   12
extern const USHORT g_c2Ports[C2_PORT_COUNT];

/* 全局状态 */
extern BOOLEAN g_bNetworkProtectionEnabled;
extern HANDLE g_WfpEngineHandle;
extern UINT32 g_WfpCalloutIdV4;
extern UINT32 g_WfpCalloutIdV6;
extern UINT32 g_WfpCalloutIdStreamV4;
extern DOH_SERVER_RECORD g_DohServers[MAX_DOH_SERVERS];
extern KSPIN_LOCK g_DohServerLock;

/* 环形缓冲区：存储网络事件供 R3 轮询 */
#define MAX_NETWORK_EVENTS   64
typedef struct _NETWORK_EVENT_RING {
    KSPIN_LOCK Lock;
    volatile LONG Head;
    volatile LONG Tail;
    NETWORK_EVENT_DATA Events[MAX_NETWORK_EVENTS];
} NETWORK_EVENT_RING;
extern NETWORK_EVENT_RING g_NetEventRing;

/* API */
NTSTATUS WfpRegisterCallouts(PDRIVER_OBJECT DriverObject);
VOID WfpUnregisterCallouts(VOID);
VOID WfpAddEventToRing(PNETWORK_EVENT_DATA pEvent);
BOOLEAN WfpPollEvent(PNETWORK_EVENT_DATA pOutEvent);
NTSTATUS WfpAddDohServer(PDOH_SERVER_ENTRY pEntry);
VOID WfpClearDohServers(VOID);
BOOLEAN WfpIsDohServer(const UCHAR* ip, ULONG ipType, USHORT port);
BOOLEAN WfpIsDohDomain(const char* domain);

/* 默认 DoH 服务器域名 */
extern const char* g_defaultDohDomains[];
extern const ULONG g_defaultDohDomainCount;
