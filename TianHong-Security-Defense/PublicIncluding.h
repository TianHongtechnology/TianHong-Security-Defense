#pragma once

// 其他库
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <winsvc.h>
#include <Psapi.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include <mutex>
#include <aclapi.h>
#include <sddl.h>
#include <xstring>
#include <algorithm>
#include <io.h>
#include <iomanip>
#include <wintrust.h>
#include <softpub.h>
#include <wininet.h>
#include <shellapi.h>
#include <fstream>
#include <sstream>
#include <cstdint>
#include <winternl.h>
#include <versionhelpers.h>
#include <vector>
#include <set>
#include <unordered_map>
#include <chrono>
#include <unordered_set>
#include <sfc.h>
#include <Shlwapi.h>
#include <yara.h>
#include <atlstr.h>
#include <gdiplus.h>
#include <map>
#include <cctype>
#include <regex>
#include <shlobj.h>
#include "ClamAV/clamav-main/libclamav/clamav.h"

// ELA 库
#include <ElaWindow.h>
#include <ElaApplication.h>
#include <ElaScrollPage.h>
#include <ElaToggleSwitch.h>
#include <ElaScrollPageArea.h>
#include <ElaText.h>
#include <ElaMenu.h>
#include <ElaTheme.h>
#include <ElaToolButton.h>
#include <ElaMessageBar.h>
#include <ElaProgressRing.h>
#include <ElaProgressBar.h>
#include <ElaImageCard.h>
#include <ElaScrollArea.h>
#include <ElaDialog.h>
#include <ElaPushButton.h>
#include <ElaContentDialog.h>
#include <ElaTableView.h>
#include <ElaCheckBox.h>
#include <ElaIcon.h>
#include <ElaDrawerArea.h>
#include <ElaRoller.h>
#include <ElaContentDialog.h>
#include <ElaListView.h>

// Qt 库
#include <QApplication>
#include <QMainWindow>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QTimer>
#include <QPropertyAnimation>
#include <QParallelAnimationGroup>
#include <QPainter>
#include <QScreen>
#include <QThread>
#include <QPainterPath>
#include <QFile>
#include <QCloseEvent>
#include <QGraphicsDropShadowEffect>
#include <QStyle>
#include <QDateTime>
#include <QRandomGenerator>
#include <QFileDialog>
#include <QStandardItemModel>
#include <QListWidgetItem>
#include <QHeaderView>
#include <QFuture>
#include <QFutureWatcher>
#include <QStyledItemDelegate>
#include <QCheckBox>
#include <QtConcurrent\QtConcurrent>
#include <QVariantAnimation>
#include <QStackedLayout>

#include <LightGBM/c_api.h>

#pragma comment(lib, "lightgbm_objs.lib")
#pragma comment(lib, "lightgbm_capi_objs.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "sfc.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "libyara64.lib")
#pragma comment(lib, "ElaWidgetTools.lib")
#pragma comment(lib, "Gdiplus.lib")

using std::string;
using std::wstring;
using std::ifstream;
using std::ios;
using std::vector;
using std::stringstream;
using std::ofstream;
