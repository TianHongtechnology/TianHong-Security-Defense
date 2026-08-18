#define _CRT_SECURE_NO_WARNINGS

#include "PublicFunction.h"
#include "VirusScanPage.h"
#include <QPushButton>
#include <QLabel>
#include <QScrollArea>
#include <QCheckBox>
#include <QProgressDialog>
#include <QApplication>
#include <tuple>
#include <memory>
#include <functional>
#include "ProtectionSettingPage.h"
#include "PEScan.h"
#include "BrokeAnimation.h"
#include "BatchScan.h"
#include "MsgDialog.h"
#include "LoggerPage.h"
#include <QTextEdit>
#include <QFileInfo>
#include <QPixmap>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QUrl>
#include <QUuid>
#include "Sandbox.h"

// Windows 现代 Toast/App 通知
#include <windows.ui.notifications.h>
#include <windows.data.xml.dom.h>
#include <wrl/client.h>
#include <wrl/wrappers/corewrappers.h>
#include <propkey.h>
#include <propvarutil.h>
#include <shobjidl_core.h>
#include <roapi.h>
#include <versionhelpers.h>

#pragma comment(lib, "runtimeobject.lib")
#pragma comment(lib, "propsys.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "shlwapi.lib")

using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Wrappers::HStringReference;

extern BOOL g_bSilentModeEnabled;
extern wchar_t g_wszMainExeDir[MAX_PATH];   // 主程序目录（用于磁盘日志缓存）

extern BOOL Windows_IsNowUAC;
extern HDESK Windows_OrgDesktop, Windows_UacDesktop;

extern YR_COMPILER* Yara_Compiler;
extern BOOL Yara_IsReady;
extern YR_RULES* Yara_Rules; // YARA 规则
extern YR_RULES* Yara_MemRules; // YARA 规则Memory版

extern SOCKET Tran_ClientInjector;

extern BOOL Process_IsInjectorReady;

typedef int (*cl_scanfile_type)(const char* filename, const char** virname, unsigned long int* scanned,
    const struct cl_engine* engine, cl_scan_options* options);//传入文件路径；病毒引擎，执行扫描，返回值：CL_VIRUS表示有病毒；CL_CLEAN表示无病毒；

extern cl_engine* mClamAVEngine;
extern cl_scan_options mClamOptions;
extern unsigned int mClamScanned;
extern cl_scanfile_type pcl_scanfile;

// sha256
extern string* VirusNameList;
extern string* VirusSha256List;
extern int Sha256Count;
extern string* WhiteSha256List;
extern int WhiteSha256Count;
extern std::unordered_map<std::string, std::string> WhiteSha256ListCache;
extern std::vector<std::string> WhiteDirListCache;  // 临时目录白名单
extern std::set<std::string> WhitePathListCache;    // 强化白名单（路径免扫）
extern string* VirusInformation;
extern std::atomic<int> VirusInfoCount;
extern std::unordered_set<std::string> HasBeenScanedSha256WhiteList;
extern std::unordered_map<std::string, std::string> HasBeenScanedSha256BlackList;
extern std::vector<std::string> HasBeenScanedTypeBlackList;
extern CRITICAL_SECTION g_csScanCache;

// PE
extern LightGBMClassifier mPEModel;

extern VirusScanPage* pVirusScanPage;
extern ProtectionSettingPage* pProtectionSettingPage;
extern LoggerPage* pLoggerPage;

extern MainWindow* pMainWindow;

extern BOOL ClamAV_IsReady;
extern BOOL PE_IsReady;
extern BOOL Yara_IsReady;
extern BOOL Yara_MemIsReady;
extern BOOL Sha256Black_IsReady;
extern BOOL Sha256White_IsReady;
extern BOOL DataBaseLoad_IsEnd;

// 处理文本：在长英文字母序列中插入换行机会
QString processTextForWrap(const QString& text) {
    QString result;

    // 正则匹配连续的英文字母（长度>18）
    QRegularExpression longEngRegex(R"([a-zA-Z]{19,})");
    QRegularExpressionMatchIterator it = longEngRegex.globalMatch(text);

    QString processedText = text;

    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        QString word = match.captured();

        // 在长单词中每10个字母插入一个零宽空格
        QString wrappedWord;
        for (int i = 0; i < word.length(); ++i) {
            wrappedWord.append(word[i]);
            if ((i + 1) % 10 == 0 && i < word.length() - 1) {
                wrappedWord.append(QChar(0x200B)); // Unicode零宽空格
            }
        }

        processedText.replace(match.capturedStart(), word.length(), wrappedWord);
    }

    return processedText;
}

bool g_bOverlayRunning = false;

// 获取当前壁纸路径
std::wstring GetWallpaperPath() {
    wchar_t path[MAX_PATH] = { 0 };
    SystemParametersInfo(SPI_GETDESKWALLPAPER, MAX_PATH, path, 0);
    return path;
}

// 窗口过程
LRESULT CALLBACK OverlayWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_KEYDOWN:
        // 拦截按键
        if (wParam == VK_F4 || wParam == VK_RETURN || wParam == VK_ESCAPE) {
            return 0;
        }
        break;

    case WM_SYSKEYDOWN:
        // 拦截 Alt+F4
        if (wParam == VK_F4 && (lParam & (1 << 29))) {
            return 0;
        }
        break;

    case WM_CLOSE:
    case WM_DESTROY:
        g_bOverlayRunning = false;
        break;

    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// 注册窗口类
void RegisterOverlayWindowClass() {
    static bool bRegistered = false;
    if (bRegistered) return;

    WNDCLASSEXW wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.lpfnWndProc = OverlayWndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"TianHongSafeOverlay";
    wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
    RegisterClassExW(&wc);

    bRegistered = true;
}

// 创建壁纸覆盖层窗口（在单独的线程中运行）
void Window_CreateWallpaperWithDim() {
    RegisterOverlayWindowClass();

    // 2. 获取屏幕尺寸
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    // 3. 创建主窗口（作为画布）
    HWND hCanvas = CreateWindowEx(
        WS_EX_TOPMOST | WS_EX_LAYERED,
        L"TianHongSafeWindow", nullptr,
        WS_POPUP | WS_VISIBLE,
        0, 0, width, height,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr
    );

    // 4. 加载原壁纸
    Gdiplus::Bitmap wallpaper(GetWallpaperPath().c_str());
    if (wallpaper.GetLastStatus() != Gdiplus::Ok) {
        return;
    }

    // 5. 创建内存位图并绘制
    HDC hdcScreen = GetDC(hCanvas);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);

    {
        Gdiplus::Graphics g(hdcMem);
        // 绘制壁纸
        g.DrawImage(&wallpaper, 0, 0, width, height);
        // 添加暗色覆盖层
        Gdiplus::SolidBrush dimBrush(Gdiplus::Color(128, 0, 0, 0));
        g.FillRectangle(&dimBrush, 0, 0, width, height);

        // 1. 创建红色横幅 (屏幕顶部全宽，高度40像素)
        const int bannerHeight = 40;
        Gdiplus::SolidBrush redBrush(Gdiplus::Color(100, 255, 0, 0));
        g.FillRectangle(&redBrush, 0, 0, width, bannerHeight);

        // 2. 设置字体
        Gdiplus::FontFamily fontFamily(L"微软雅黑");
        Gdiplus::Font font(&fontFamily, 24, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);

        // 3. 设置文字格式（居中）
        Gdiplus::StringFormat format;
        format.SetAlignment(Gdiplus::StringAlignmentCenter);
        format.SetLineAlignment(Gdiplus::StringAlignmentCenter);

        // 4. 绘制白色文字
        Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255)); // 白色
        Gdiplus::RectF textRect(0, 0, width, bannerHeight);
        g.DrawString(L">>>>>>>>>> 危险操作已拦截 <<<<<<<<<<", -1, &font, textRect, &format, &whiteBrush);
    }

    // 6. 设置窗口内容
    POINT ptZero = { 0 };
    SIZE size = { width, height };
    BLENDFUNCTION blend = { AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
    UpdateLayeredWindow(hCanvas, hdcScreen, &ptZero, &size, hdcMem,
        &ptZero, 0, &blend, ULW_ALPHA);

	ShowWindow(hCanvas, SW_SHOW);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0) && g_bOverlayRunning) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // 销毁窗口
    if (hCanvas) {
        DestroyWindow(hCanvas);
    }

    // 7. 清理资源
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(hCanvas, hdcScreen);
}

DWORD WINAPI OverlayThreadProc(LPVOID lpParam) {
    Window_CreateWallpaperWithDim();
    return 0;
}

RelActWarnType OrgShowAlertDialog(const QString& title, const int& pid, const QString& context, bool isUAC = false)
{
    CString PIDCSTR;
    PIDCSTR.Format(L"%d", pid);

    int ParPid = Process_GetProcessParent(pid);

    CString ParPIDSTR;
    ParPIDSTR.Format(L"%d", ParPid);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    HANDLE ParhProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ParPid);

    CString ParNamecstred, Namecstr;

    // 获取 parent process 信息
    TCHAR ParPathcstr[MAX_PATH + 4];
    ZeroMemory(ParPathcstr, MAX_PATH + 4);
    if (ParhProcess)
    {
        DWORD pathSize = sizeof(ParPathcstr) / sizeof(TCHAR);
        if (QueryFullProcessImageName(ParhProcess, 0, ParPathcstr, &pathSize))
        {
            ParNamecstred = PathFindFileName(ParPathcstr);
        }
        CloseHandle(ParhProcess);
    }

    TCHAR processPath[MAX_PATH + 4];
    ZeroMemory(processPath, MAX_PATH + 4);
    if (hProcess)
    {
        DWORD pathSize = sizeof(processPath) / sizeof(TCHAR);
        if (QueryFullProcessImageName(hProcess, 0, processPath, &pathSize))
        {
            Namecstr = PathFindFileName(processPath);
        }
        CloseHandle(hProcess);
    }

    string SignContent;

    if (File_CheckFileSignature(processPath))
    {
        SignContent = "数字签名状态：有效的数字签名";
    }
    else
    {
        SignContent = "数字签名状态：无效的数字签名(危险)";
    }

    QString signatureInfo = SignContent.c_str();

    RelActWarnType localResult = AW_Prevent;

    /* 将技术性的 ThreatClass 字符串映射为普通用户可读的告警标题，
     * 统一使用“检测到...”格式 */
    auto mapAlertTitle = [](const QString& rawTitle) -> QString {
        QString t = rawTitle.toLower();
        if (t.contains("processhollowing"))
            return QStringLiteral("检测到进程镂空攻击");
        if (t.contains("criticalprocesshijack") || t.contains("set critical") || t.contains("processbreakontermination"))
            return QStringLiteral("检测到关键进程劫持");
        if (t.contains("remoteexecutableallocation") || t.contains("remotealloc"))
            return QStringLiteral("检测到远程分配可执行内存");
        if (t.contains("remoteprotectexecutable") || t.contains("remoteprotect"))
            return QStringLiteral("检测到远程修改内存为可执行");
        if (t.contains("remotemapviewexecutable") || t.contains("remotemapview"))
            return QStringLiteral("检测到远程映射可执行内存");
        if (t.contains("createremotethread") || t.contains("remote thread"))
            return QStringLiteral("检测到远程线程注入");
        if (t.contains("apcinjection") || t.contains("queueapc"))
            return QStringLiteral("检测到 APC 注入");
        if (t.contains("sectionmap") || t.contains("mapviewofsection"))
            return QStringLiteral("检测到内存映射注入");
        if (t.contains("processmemorywrite") || t.contains("cross-process write") || t.contains("cross-process memory write"))
            return QStringLiteral("检测到跨进程内存写入");
        if (t.contains("threadhijacking") || t.contains("setthreadcontext"))
            return QStringLiteral("检测到线程劫持");
        if (t.contains("poolparty"))
            return QStringLiteral("检测到 PoolParty 线程池注入");
        if (t.contains("injection chain") || t.contains("injectionchain"))
            return QStringLiteral("检测到注入链行为");
        if (t.contains("shellcoderemotethread") || t.contains("remotethread"))
            return QStringLiteral("检测到远程线程 Shellcode 注入");
        if (t.contains("shellcodeallocate") || t.contains("allocate then execute"))
            return QStringLiteral("检测到 Shellcode 分配执行");
        if (t.contains("shellcodewrite") || t.contains("write then execute"))
            return QStringLiteral("检测到 Shellcode 写入执行");
        if (t.contains("self-loading") || t.contains("selfloading"))
            return QStringLiteral("检测到自加载攻击");
        if (t.contains("dll side-load") || t.contains("dll sideload") || t.contains("sideload"))
            return QStringLiteral("检测到DLL侧载攻击");
        if (t.contains("ransom") || t.contains("encrypt"))
            return QStringLiteral("检测到勒索软件行为");
        if (t.contains("credential") || t.contains("credsteal") || t.contains("lsass"))
            return QStringLiteral("检测到凭据窃取");
        if (t.contains("registry"))
            return QStringLiteral("检测到注册表防护事件");
        if (t.contains("file") && (t.contains("system dir") || t.contains("driver") || t.contains("startup")))
            return QStringLiteral("检测到文件系统防护事件");
        if (!rawTitle.trimmed().isEmpty())
            return QStringLiteral("检测到可疑行为: %1").arg(rawTitle.trimmed());
        return QStringLiteral("检测到安全威胁");
    };

    // HIPS 告警标题已格式化为 [注册表防护 · 操作]/[文件防护 · 操作]，直接保留；
    // 其他告警继续通过 mapAlertTitle 映射为中文标题。
    QString displayTitle = title;
    if (!title.startsWith("[注册表防护") && !title.startsWith("[文件防护"))
        displayTitle = mapAlertTitle(title);

    ElaDialog* ElaDia = new ElaDialog(nullptr);

    // 设置无边框和置顶属性
    ElaDia->setWindowTitle("天宏安全防御 - 主动防护");

    HANDLE hOverlayThread = nullptr;
    if (isUAC) {
        g_bOverlayRunning = true;
        // 创建覆盖窗口线程
        hOverlayThread = CreateThread(nullptr, 0, OverlayThreadProc, nullptr, 0, nullptr);
    }

    ElaDia->setWindowFlags(Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint | Qt::Tool);
    ElaDia->setWindowButtonFlags(ElaAppBarType::NoneButtonHint);
    ElaDia->setAttribute(Qt::WA_DeleteOnClose);
    ElaDia->setFixedSize(750, 450);
    ElaDia->setIsFixedSize(true);

    // 颜色配置函数
    auto getTitleColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "#ff6b6b" : "#d32f2f";
        };

    auto getSignatureColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "#feca57" : "#e67e22";
        };

    // 新增：获取进程信息背景色
    auto getProcessInfoBgColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "rgba(52, 73, 94, 0.7)" : "rgba(52, 152, 219, 0.1)";
        };

    // 更新样式函数
    auto updateStyle = [ElaDia, getTitleColor, getSignatureColor, getProcessInfoBgColor]() {
        ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
        ElaDia->setStyleSheet(QString("QDialog {"
            "background: %1;"
            "border: 2px solid #e74c3c;"
            "border-radius: 15px;"
            "}").arg(ElaThemeColor(themeMode, WindowBase).name()));

        QList<QLabel*> labels = ElaDia->findChildren<QLabel*>();
        for (QLabel* label : labels) {
            if (label->objectName() == "titleLabel") {
                label->setStyleSheet(QString("QLabel {"
                    "font-size: 22px;"
                    "font-weight: bold;"
                    "color: %1;"
                    "background: transparent;"
                    "}").arg(getTitleColor(themeMode)));
            }
            else if (label->objectName() == "processInfoLabel" && label->isVisible()) {
                label->setStyleSheet(QString("QLabel {"
                    "font-size: 14px;"
                    "color: %1;"
                    "background: %2;"
                    "padding: 8px 12px;"
                    "border-radius: 6px;"
                    "border-left: 3px solid #3498db;"
                    "}").arg(ElaThemeColor(themeMode, BasicText).name())
                    .arg(getProcessInfoBgColor(themeMode)));
            }
            else if (label->objectName() == "signatureLabel" && label->isVisible()) {
                label->setStyleSheet(QString("QLabel {"
                    "font-size: 13px;"
                    "color: %1;"
                    "background: rgba(243, 156, 18, 0.1);"
                    "padding: 8px 12px;"
                    "border-radius: 6px;"
                    "border-left: 3px solid #f39c12;"
                    "}").arg(getSignatureColor(themeMode)));
            }
            else if ((label->objectName() == "processPathLabel" || label->objectName() == "parentPathLabel") && label->isVisible()) {
                label->setStyleSheet(QString("QLabel {"
                    "font-size: 12px;"
                    "color: %1;"
                    "background: rgba(127, 140, 141, 0.1);"
                    "padding: 6px 10px;"
                    "border-radius: 4px;"
                    "border-left: 3px solid #7f8c8d;"
                    "}").arg(ElaThemeColor(themeMode, BasicText).name()));
            }

        }
        };

    // 初始设置样式
    updateStyle();

    // 连接主题变化信号
    QObject::connect(eTheme, &ElaTheme::themeModeChanged, ElaDia, [ElaDia, updateStyle](ElaThemeType::ThemeMode themeMode) {
        updateStyle();
        ElaDia->update();
        });

    // 主布局
    QHBoxLayout* mainLayout = new QHBoxLayout(ElaDia);
    mainLayout->setContentsMargins(20, 20, 20, 20);
    mainLayout->setSpacing(20);

    // 左侧区域
    QWidget* leftWidget = new QWidget();
    leftWidget->setFixedWidth(130);
    leftWidget->setStyleSheet("QWidget {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #e74c3c, stop:1 #c0392b);"
        "border-radius: 10px;"
        "}");

    QVBoxLayout* leftLayout = new QVBoxLayout(leftWidget);
    leftLayout->setContentsMargins(10, 20, 10, 20);
    leftLayout->setSpacing(15);
    leftLayout->setAlignment(Qt::AlignTop);

    // 右侧内容区域
    QWidget* rightWidget = new QWidget();
    rightWidget->setStyleSheet("QWidget { background: transparent; }");
    QVBoxLayout* rightMainLayout = new QVBoxLayout(rightWidget);
    rightMainLayout->setContentsMargins(0, 0, 0, 0);
    rightMainLayout->setSpacing(15);

    // 大标题（使用友好中文标题，避免直接显示技术性 ThreatClass）
    QLabel* titleLabel = new QLabel(displayTitle);
    titleLabel->setObjectName("titleLabel");
    titleLabel->setStyleSheet(QString("QLabel {"
        "font-size: 22px;"
        "font-weight: bold;"
        "color: %1;"
        "background: transparent;"
        "}").arg(getTitleColor(eTheme->getThemeMode())));
    titleLabel->setAlignment(Qt::AlignCenter);

    // 右侧内容水平布局容器
    QWidget* contentContainer = new QWidget();
    contentContainer->setStyleSheet("QWidget { background: transparent; }");
    QHBoxLayout* contentContainerLayout = new QHBoxLayout(contentContainer);
    contentContainerLayout->setContentsMargins(0, 0, 0, 0);
    contentContainerLayout->setSpacing(20);

    // 左侧内容区域
    QWidget* contentWidget = new QWidget();
    contentWidget->setStyleSheet("QWidget { background: transparent; }");
    QVBoxLayout* contentLayout = new QVBoxLayout(contentWidget);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(12);

    // 右侧按钮区域
    QWidget* buttonWidget = new QWidget();
    buttonWidget->setFixedWidth(80);
    buttonWidget->setStyleSheet("QWidget { background: transparent; }");
    QVBoxLayout* buttonLayout = new QVBoxLayout(buttonWidget);
    buttonLayout->setContentsMargins(0, 0, 0, 0);
    buttonLayout->setSpacing(8);
    buttonLayout->setAlignment(Qt::AlignTop);

    // 进程信息：进程名(PID) -> 父进程名(PID)
    QString processInfoText;
    processInfoText = QString::fromWCharArray(Namecstr);
    processInfoText += "  (";
    processInfoText += QString::fromWCharArray(PIDCSTR);
    processInfoText += ")";

    processInfoText += " 归属于 -> ";
    processInfoText += QString::fromWCharArray(ParNamecstred);
    processInfoText += "[";
    processInfoText += QString::fromWCharArray(ParPIDSTR);
    processInfoText += "]";

    QLabel* processInfoLabel = new QLabel();
    processInfoLabel->setObjectName("processInfoLabel");
    if (!processInfoText.isEmpty()) {
        processInfoLabel->setText(processInfoText);

        // 获取当前主题模式
        ElaThemeType::ThemeMode currentTheme = eTheme->getThemeMode();

        // 根据主题设置背景色
        QString bgColor = currentTheme == ElaThemeType::Dark
            ? "rgba(52, 73, 94, 0.7)"
            : "rgba(52, 152, 219, 0.1)";

        processInfoLabel->setStyleSheet(QString("QLabel {"
            "font-size: 14px;"
            "color: %1;"
            "background: %2;"
            "padding: 8px 12px;"
            "border-radius: 6px;"
            "border-left: 3px solid #3498db;"
            "}").arg(ElaThemeColor(currentTheme, BasicText).name())
            .arg(bgColor));
    }
    else
    {
        processInfoLabel->setVisible(false);
    }

    // 数字签名信息
    QLabel* signatureLabel = new QLabel();
    signatureLabel->setObjectName("signatureLabel");
    if (!signatureInfo.isEmpty()) {
        signatureLabel->setText(QString("%1").arg(signatureInfo));
        signatureLabel->setStyleSheet(QString("QLabel {"
            "font-size: 13px;"
            "color: %1;"
            "background: rgba(243, 156, 18, 0.1);"
            "padding: 8px 12px;"
            "border-radius: 6px;"
            "border-left: 3px solid #f39c12;"
            "}").arg(getSignatureColor(eTheme->getThemeMode())));
    }
    else {
        signatureLabel->setVisible(false);
    }

    // 上下文信息（使用 QTextEdit 支持滚动，避免内容过长无法查看）
    QTextEdit* contextEdit = new QTextEdit();
    /* 末尾追加空行并去掉文档边距，解决滑到底部时最后一行被遮挡的问题 */
    QString wrappedContext = context;
    /* 去掉 [content] 前缀：该标记是日志详情渲染器的内部元标记，
     * 用于 LoggerPage 切换灰色渲染模式，不应在 AlertDialog 中显示 */
    if (wrappedContext.startsWith("[content]\r\n"))
        wrappedContext = wrappedContext.mid(11);
    else if (wrappedContext.startsWith("[content]\n"))
        wrappedContext = wrappedContext.mid(10);
    if (!wrappedContext.endsWith("\n"))
        wrappedContext += "\n";
    wrappedContext += " ";
    contextEdit->setPlainText(wrappedContext);
    contextEdit->document()->setDocumentMargin(2);
    contextEdit->setReadOnly(true);
    contextEdit->setObjectName("contextEdit");
    contextEdit->setStyleSheet(QString("QTextEdit {"
        "font-size: 14px;"
        "color: %1;"
        "background: rgba(231, 76, 60, 0.1);"
        "padding: 12px 15px;"
        "border-radius: 8px;"
        "border-left: 3px solid #e74c3c;"
        "line-height: 1.5;"
        "}"
        "QScrollBar:vertical {"
        "background: rgba(0, 0, 0, 0.05);"
        "width: 10px;"
        "border-radius: 5px;"
        "margin: 0px;"
        "}"
        "QScrollBar::handle:vertical {"
        "background: rgba(231, 76, 60, 0.6);"
        "min-height: 30px;"
        "border-radius: 5px;"
        "}"
        "QScrollBar::handle:vertical:hover {"
        "background: rgba(231, 76, 60, 0.9);"
        "}"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
        "height: 0px;"
        "}"
        "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {"
        "background: transparent;"
        "}"
        "QScrollBar:horizontal {"
        "background: rgba(0, 0, 0, 0.05);"
        "height: 8px;"
        "border-radius: 4px;"
        "margin: 0px;"
        "}"
        "QScrollBar::handle:horizontal {"
        "background: rgba(231, 76, 60, 0.6);"
        "min-width: 30px;"
        "border-radius: 4px;"
        "}"
        "QScrollBar::handle:horizontal:hover {"
        "background: rgba(231, 76, 60, 0.9);"
        "}"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {"
        "width: 0px;"
        "}"
        "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {"
        "background: transparent;"
        "}").arg(ElaThemeColor(eTheme->getThemeMode(), BasicText).name()));
    contextEdit->setMinimumHeight(140);
    contextEdit->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    contextEdit->setFocusPolicy(Qt::StrongFocus);
    contextEdit->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard | Qt::LinksAccessibleByMouse);
    contextEdit->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    contextEdit->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    contextEdit->setLineWrapMode(QTextEdit::WidgetWidth);
    contextEdit->setWordWrapMode(QTextOption::WrapAnywhere);
    /* 初始化后滚动到顶部，避免自动滚动到底部导致顶部信息看不到 */
    contextEdit->moveCursor(QTextCursor::Start);

    // 底部按钮区域
    QHBoxLayout* bottomButtonLayout = new QHBoxLayout();
    bottomButtonLayout->setSpacing(15);

    QPushButton* allowButton = new QPushButton("允许");
    QPushButton* blockButton = new QPushButton("立即拦截 (30s)");
    QPushButton* killProcessButton = new QPushButton("结束进程");
    QPushButton* autoBlockButton = new QPushButton("自动拦截");
    QPushButton* autoAllowButton = new QPushButton("自动允许");

    // 按钮样式
    QString buttonStyle = "QPushButton {"
        "font-size: 14px;"
        "font-weight: bold;"
        "padding: 12px 20px;"
        "border: none;"
        "border-radius: 8px;"
        "min-width: 160px;"
        "}";

    QString verticalButtonStyle = "QPushButton {"
        "font-size: 12px;"
        "font-weight: bold;"
        "padding: 10px 8px;"
        "border: none;"
        "border-radius: 6px;"
        "min-width: 60px;"
        "max-width: 60px;"
        "}";

    // 设置按钮样式
    killProcessButton->setStyleSheet(verticalButtonStyle +
        "QPushButton {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #e67e22, stop:1 #d35400);"
        "color: white;"
        "}"
        "QPushButton:hover {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #d35400, stop:1 #ba4a00);"
        "}"
        "QPushButton:pressed {"
        "background: #ba4a00;"
        "}");

    autoBlockButton->setStyleSheet(verticalButtonStyle +
        "QPushButton {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #c0392b, stop:1 #a93226);"
        "color: white;"
        "}"
        "QPushButton:hover {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #a93226, stop:1 #922b21);"
        "}"
        "QPushButton:pressed {"
        "background: #922b21;"
        "}");

    autoAllowButton->setStyleSheet(verticalButtonStyle +
        "QPushButton {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #27ae60, stop:1 #229954);"
        "color: white;"
        "}"
        "QPushButton:hover {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #229954, stop:1 #1e8449);"
        "}"
        "QPushButton:pressed {"
        "background: #1e8449;"
        "}");

    allowButton->setStyleSheet(buttonStyle +
        "QPushButton {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #27ae60, stop:1 #229954);"
        "color: white;"
        "min-width: 100px;"
        "}"
        "QPushButton:hover {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #2ecc71, stop:1 #27ae60);"
        "}"
        "QPushButton:pressed {"
        "background: #1e8449;"
        "}");

    blockButton->setStyleSheet(buttonStyle +
        "QPushButton {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #e74c3c, stop:1 #c0392b);"
        "color: white;"
        "min-width: 350px;"
        "}"
        "QPushButton:hover {"
        "background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
        "stop:0 #ec7063, stop:1 #e74c3c);"
        "}"
        "QPushButton:pressed {"
        "background: #a93226;"
        "}");

    // 组装竖直排列按钮
    buttonLayout->addSpacing(40);
    buttonLayout->addWidget(killProcessButton);
    buttonLayout->addWidget(autoBlockButton);
    buttonLayout->addWidget(autoAllowButton);
    buttonLayout->addStretch();

    // 组装底部按钮行
    bottomButtonLayout->addStretch();
    bottomButtonLayout->addWidget(allowButton);
    bottomButtonLayout->addStretch();
    bottomButtonLayout->addWidget(blockButton);
    bottomButtonLayout->addStretch();

    // 组装左侧内容布局
    contentLayout->addWidget(processInfoLabel);
    if (!signatureInfo.isEmpty()) {
        contentLayout->addWidget(signatureLabel);
    }
    contentLayout->addWidget(contextEdit, 1);
    /* contextEdit 已设置 stretch=1，不再添加额外 stretch，确保长文本区域
     * 占用所有剩余垂直空间并正确显示滚动条。 */

    // 组装内容容器布局
    contentContainerLayout->addWidget(contentWidget);
    contentContainerLayout->addWidget(buttonWidget);

    // 组装右侧主布局
    rightMainLayout->addWidget(titleLabel);
    rightMainLayout->addWidget(contentContainer);
    rightMainLayout->addLayout(bottomButtonLayout);

    // 组装主布局
    mainLayout->addWidget(leftWidget);
    mainLayout->addWidget(rightWidget);

    // 居中显示
    QScreen* screen = QGuiApplication::primaryScreen();
    if (screen) {
        QRect screenGeometry = screen->geometry();
        QPoint center = screenGeometry.center() - QPoint(ElaDia->width() / 2, ElaDia->height() / 2);
        ElaDia->move(center);
    }

    RelActWarnType dialogResult = AW_Prevent;
    QEventLoop eventLoop;

    // 置顶定时器
    QTimer* stayOnTopTimer = new QTimer(ElaDia);
    QObject::connect(stayOnTopTimer, &QTimer::timeout, ElaDia, [ElaDia]() {
        if (ElaDia->isVisible()) {
            ElaDia->raise();
        }
        });
    stayOnTopTimer->start(100);

    // 统一的按钮处理函数
    auto handleButtonClick = [&](RelActWarnType result) {
        dialogResult = result;
        stayOnTopTimer->stop();

        if (g_bOverlayRunning) {
            g_bOverlayRunning = false;
            if (hOverlayThread) {
                WaitForSingleObject(hOverlayThread, 500);
                CloseHandle(hOverlayThread);
                hOverlayThread = nullptr;
            }
        }

        ElaDia->accept();
        eventLoop.quit();
        };

    // 自动退出定时器
    short* NowTime = new short;
    *NowTime = 30;
    QTimer* OutTimer = new QTimer(ElaDia);
    QObject::connect(OutTimer, &QTimer::timeout, ElaDia, [=]() {
        (*NowTime)--;
        if (*NowTime == 0)
        {
            OutTimer->stop();
            OutTimer->deleteLater();

            handleButtonClick(AW_Prevent);
        }
        else
        {
            blockButton->setText(((QString)"立即拦截 (%1s)").arg(*NowTime));
        }
        });
    OutTimer->start(1000);

    // 连接按钮
    QObject::connect(allowButton, &QPushButton::clicked, ElaDia, [&]() { handleButtonClick(AW_Allow); });
    QObject::connect(blockButton, &QPushButton::clicked, ElaDia, [&]() { handleButtonClick(AW_Prevent); });
    QObject::connect(killProcessButton, &QPushButton::clicked, ElaDia, [&]() { handleButtonClick(AW_Terminate); });
    QObject::connect(autoBlockButton, &QPushButton::clicked, ElaDia, [&]() { handleButtonClick(AW_AutoPrevent); });
    QObject::connect(autoAllowButton, &QPushButton::clicked, ElaDia, [&]() { handleButtonClick(AW_AutoAllow); });

    // 处理窗口关闭
    QObject::connect(ElaDia, &QDialog::rejected, ElaDia, [&]() {
        handleButtonClick(AW_Prevent);
        });

    // 显示动画
    QPropertyAnimation* animation = new QPropertyAnimation(ElaDia, "windowOpacity");
    animation->setDuration(300);
    animation->setStartValue(0.0);
    animation->setEndValue(1.0);
    animation->start();

    // 设置应用模态，确保事件循环阻塞期间其他窗口无法抢占焦点
    ElaDia->setWindowModality(Qt::ApplicationModal);

    // 显示并强制置顶/前台，避免被其他窗口遮挡导致用户看不到告警
    ElaDia->show();
    ElaDia->raise();
    ElaDia->activateWindow();
    if (ElaDia->winId() != 0)
    {
        HWND hWnd = reinterpret_cast<HWND>(ElaDia->winId());
        SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
        SetForegroundWindow(hWnd);
        FlashWindow(hWnd, TRUE);
    }

    // 确认对话框已真正可见，若异步渲染失败则记录日志并返回默认阻止
    bool visibleConfirmed = false;
    for (int i = 0; i < 20; ++i)
    {
        QCoreApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 50);
        if (ElaDia->isVisible())
        {
            visibleConfirmed = true;
            break;
        }
        Sleep(10);
    }

    if (!visibleConfirmed)
    {
        Log_AddLogSimple(QString("告警对话框显示失败 PID=%1，默认阻止").arg(pid), LOG_ERROR);
        if (g_bOverlayRunning) {
            g_bOverlayRunning = false;
            if (hOverlayThread) {
                WaitForSingleObject(hOverlayThread, 500);
                CloseHandle(hOverlayThread);
                hOverlayThread = nullptr;
            }
        }
        stayOnTopTimer->stop();
        OutTimer->stop();
        ElaDia->close();
        return AW_Prevent;
    }

    contextEdit->setFocus(Qt::OtherFocusReason);
    eventLoop.exec();

    return dialogResult;
}

// ==================== 临时白名单管理 ====================

bool Whitelist_AddTemporary(const std::string& filePath)
{
    if (filePath.empty()) return false;

    string sha = Encrypt_CalculateFileSHA256(filePath);
    if (sha.empty()) return false;

    std::transform(sha.begin(), sha.end(), sha.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // 规范化路径为小写用于比较
    std::string lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    EnterCriticalSection(&g_csScanCache);

    // 检查该路径是否已在白名单中（通过值查找 WhiteSha256ListCache）
    bool pathExists = false;
    for (const auto& kv : WhiteSha256ListCache) {
        std::string existingPath = kv.second;
        std::transform(existingPath.begin(), existingPath.end(), existingPath.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (existingPath == lowerPath) {
            pathExists = true;
            break;
        }
    }

    // 添加新的 sha256 → path 映射（如果是同一文件内容没变，sha256 相同，map 会覆盖）
    WhiteSha256ListCache[sha] = filePath;
    // 同时从黑名单缓存移除，避免冲突
    HasBeenScanedSha256BlackList.erase(sha);

    // 如果路径已存在（第二次添加同一路径），升级为强化白名单
    if (pathExists) {
        WhitePathListCache.insert(lowerPath);
    }

    LeaveCriticalSection(&g_csScanCache);

    Whitelist_SaveTemporary();
    if (pathExists) Whitelist_SaveEnhancedPath();
    return true;
}

bool Whitelist_AddTemporary(const QString& filePath)
{
    return Whitelist_AddTemporary(filePath.toLocal8Bit().toStdString());
}

bool Whitelist_RemoveTemporary(const std::string& sha256)
{
    string lowerSha = sha256;
    std::transform(lowerSha.begin(), lowerSha.end(), lowerSha.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    EnterCriticalSection(&g_csScanCache);
    auto it = WhiteSha256ListCache.find(lowerSha);
    bool removed = (it != WhiteSha256ListCache.end());
    if (removed) {
        WhiteSha256ListCache.erase(it);
    }
    LeaveCriticalSection(&g_csScanCache);

    if (removed) {
        Whitelist_SaveTemporary();
    }
    return removed;
}

void Whitelist_SaveTemporary()
{
    CString csPath = Process_GetCurrentProcessPath().c_str();
    csPath += L"\\Resources\\DataBase\\whitecache.sha256";
    string cachePath = (char*)(CW2A)csPath;

    EnterCriticalSection(&g_csScanCache);
    std::string cacheContent;
    for (const auto& kv : WhiteSha256ListCache) {
        cacheContent += kv.first;
        cacheContent += '\t';
        cacheContent += kv.second;
        cacheContent += '\n';
    }
    LeaveCriticalSection(&g_csScanCache);

    ofstream cacheOut(cachePath, ios::out | ios::trunc);
    if (cacheOut.is_open()) {
        cacheOut.write(cacheContent.c_str(), static_cast<std::streamsize>(cacheContent.size()));
        cacheOut.close();
    }
}

void Whitelist_LoadTemporary()
{
    CString csPath = Process_GetCurrentProcessPath().c_str();
    csPath += L"\\Resources\\DataBase\\whitecache.sha256";
    string cachePath = (char*)(CW2A)csPath;

    ifstream cacheIn(cachePath, ios::in);
    if (!cacheIn.is_open()) return;

    std::string line;
    EnterCriticalSection(&g_csScanCache);
    while (std::getline(cacheIn, line)) {
        if (line.empty()) continue;
        size_t tab = line.find('\t');
        if (tab == std::string::npos) continue;
        std::string sha = line.substr(0, tab);
        std::string path = line.substr(tab + 1);
        if (!sha.empty() && !path.empty()) {
            WhiteSha256ListCache[sha] = path;
        }
    }
    LeaveCriticalSection(&g_csScanCache);
    cacheIn.close();
}

// ==================== 强化白名单（路径免扫） ====================

bool Whitelist_AddEnhancedPath(const std::string& filePath)
{
    if (filePath.empty()) return false;
    std::string lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    EnterCriticalSection(&g_csScanCache);
    auto result = WhitePathListCache.insert(lowerPath);
    LeaveCriticalSection(&g_csScanCache);

    if (result.second) Whitelist_SaveEnhancedPath();
    return result.second;
}

bool Whitelist_IsPathEnhanced(const std::string& filePath)
{
    if (filePath.empty()) return false;
    std::string lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    EnterCriticalSection(&g_csScanCache);
    bool found = WhitePathListCache.find(lowerPath) != WhitePathListCache.end();
    LeaveCriticalSection(&g_csScanCache);
    return found;
}

bool Whitelist_RemoveEnhancedPath(const std::string& filePath)
{
    if (filePath.empty()) return false;
    std::string lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    EnterCriticalSection(&g_csScanCache);
    auto it = WhitePathListCache.find(lowerPath);
    bool removed = (it != WhitePathListCache.end());
    if (removed) WhitePathListCache.erase(it);
    LeaveCriticalSection(&g_csScanCache);

    if (removed) Whitelist_SaveEnhancedPath();
    return removed;
}

int Whitelist_RemoveAllSha256ByPath(const std::string& filePath)
{
    if (filePath.empty()) return 0;
    std::string lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    int removedCount = 0;
    EnterCriticalSection(&g_csScanCache);
    for (auto it = WhiteSha256ListCache.begin(); it != WhiteSha256ListCache.end(); ) {
        std::string existingPath = it->second;
        std::transform(existingPath.begin(), existingPath.end(), existingPath.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (existingPath == lowerPath) {
            it = WhiteSha256ListCache.erase(it);
            ++removedCount;
        } else {
            ++it;
        }
    }
    LeaveCriticalSection(&g_csScanCache);

    if (removedCount > 0) Whitelist_SaveTemporary();
    return removedCount;
}

void Whitelist_SaveEnhancedPath()
{
    CString csPath = Process_GetCurrentProcessPath().c_str();
    csPath += L"\\Resources\\DataBase\\whitepath.cache";
    string cachePath = (char*)(CW2A)csPath;

    EnterCriticalSection(&g_csScanCache);
    std::string cacheContent;
    for (const auto& path : WhitePathListCache) {
        cacheContent += path;
        cacheContent += '\n';
    }
    LeaveCriticalSection(&g_csScanCache);

    ofstream cacheOut(cachePath, ios::out | ios::trunc);
    if (cacheOut.is_open()) {
        cacheOut.write(cacheContent.c_str(), static_cast<std::streamsize>(cacheContent.size()));
        cacheOut.close();
    }
}

void Whitelist_LoadEnhancedPath()
{
    CString csPath = Process_GetCurrentProcessPath().c_str();
    csPath += L"\\Resources\\DataBase\\whitepath.cache";
    string cachePath = (char*)(CW2A)csPath;

    ifstream cacheIn(cachePath, ios::in);
    if (!cacheIn.is_open()) return;

    std::string line;
    EnterCriticalSection(&g_csScanCache);
    while (std::getline(cacheIn, line)) {
        if (!line.empty()) WhitePathListCache.insert(line);
    }
    LeaveCriticalSection(&g_csScanCache);
    cacheIn.close();
}

// ==================== 临时目录白名单 ====================

// 将目录路径规范化为小写、末尾带'\'
static std::string NormalizeDirPath(const std::string& dirPath)
{
    std::string normalized = dirPath;
    if (normalized.empty()) return normalized;
    // 统一斜杠为反斜杠
    std::replace(normalized.begin(), normalized.end(), '/', '\\');
    // 末尾确保有反斜杠
    if (normalized.back() != '\\') normalized += '\\';
    // 转小写
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return normalized;
}

bool Whitelist_AddTemporaryDir(const std::string& dirPath)
{
    if (dirPath.empty()) return false;
    std::string normalized = NormalizeDirPath(dirPath);
    if (normalized.empty()) return false;

    EnterCriticalSection(&g_csScanCache);
    // 去重
    bool exists = false;
    for (const auto& d : WhiteDirListCache) {
        if (d == normalized) { exists = true; break; }
    }
    if (!exists) WhiteDirListCache.push_back(normalized);
    LeaveCriticalSection(&g_csScanCache);

    Whitelist_SaveTemporaryDir();
    return true;
}

bool Whitelist_AddTemporaryDir(const QString& dirPath)
{
    return Whitelist_AddTemporaryDir(dirPath.toLocal8Bit().toStdString());
}

bool Whitelist_RemoveTemporaryDir(const std::string& dirPath)
{
    std::string normalized = NormalizeDirPath(dirPath);
    EnterCriticalSection(&g_csScanCache);
    auto it = std::find(WhiteDirListCache.begin(), WhiteDirListCache.end(), normalized);
    bool removed = (it != WhiteDirListCache.end());
    if (removed) WhiteDirListCache.erase(it);
    LeaveCriticalSection(&g_csScanCache);

    if (removed) Whitelist_SaveTemporaryDir();
    return removed;
}

bool Whitelist_IsPathInTempDir(const std::string& filePath)
{
    if (filePath.empty()) return false;
    std::string fpLower = filePath;
    std::replace(fpLower.begin(), fpLower.end(), '/', '\\');
    std::transform(fpLower.begin(), fpLower.end(), fpLower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    bool hit = false;
    EnterCriticalSection(&g_csScanCache);
    for (const auto& dir : WhiteDirListCache) {
        if (dir.size() <= fpLower.size() &&
            fpLower.compare(0, dir.size(), dir) == 0) {
            hit = true;
            break;
        }
    }
    LeaveCriticalSection(&g_csScanCache);
    return hit;
}

void Whitelist_SaveTemporaryDir()
{
    CString csPath = Process_GetCurrentProcessPath().c_str();
    csPath += L"\\Resources\\DataBase\\whitedir.cache";
    string cachePath = (char*)(CW2A)csPath;

    EnterCriticalSection(&g_csScanCache);
    std::string cacheContent;
    for (const auto& dir : WhiteDirListCache) {
        cacheContent += dir;
        cacheContent += '\n';
    }
    LeaveCriticalSection(&g_csScanCache);

    ofstream cacheOut(cachePath, ios::out | ios::trunc);
    if (cacheOut.is_open()) {
        cacheOut.write(cacheContent.c_str(), static_cast<std::streamsize>(cacheContent.size()));
        cacheOut.close();
    }
}

void Whitelist_LoadTemporaryDir()
{
    CString csPath = Process_GetCurrentProcessPath().c_str();
    csPath += L"\\Resources\\DataBase\\whitedir.cache";
    string cachePath = (char*)(CW2A)csPath;

    ifstream cacheIn(cachePath, ios::in);
    if (!cacheIn.is_open()) return;

    std::string line;
    EnterCriticalSection(&g_csScanCache);
    while (std::getline(cacheIn, line)) {
        if (line.empty()) continue;
        // 规范化：确保末尾带反斜杠、小写
        std::string normalized = NormalizeDirPath(line);
        if (!normalized.empty()) {
            // 去重
            bool exists = false;
            for (const auto& d : WhiteDirListCache) {
                if (d == normalized) { exists = true; break; }
            }
            if (!exists) WhiteDirListCache.push_back(normalized);
        }
    }
    LeaveCriticalSection(&g_csScanCache);
    cacheIn.close();
}

BOOL OrgShowThreatDialog(const QString& filePath, const QString& threatType)
{
    BOOL localResult = FALSE;

    QDialog* threatDialog = new QDialog();
    threatDialog->setWindowFlags(Qt::WindowStaysOnTopHint | Qt::FramelessWindowHint | Qt::Tool);
    threatDialog->setWindowTitle("天宏安全防御 - 静态防护");
    threatDialog->setFixedSize(520, 420);
    threatDialog->setAttribute(Qt::WA_DeleteOnClose);
    threatDialog->setAttribute(Qt::WA_TranslucentBackground);

    // 设置圆角样式
    threatDialog->setStyleSheet(
        "QDialog {"
        "   border-radius: 12px;"
        "}"
    );

    // 创建主布局
    QVBoxLayout* verticalLayout = new QVBoxLayout(threatDialog);
    verticalLayout->setSpacing(0);
    verticalLayout->setContentsMargins(0, 0, 0, 0);

    // 顶部红色横线
    QFrame* redLine = new QFrame();
    redLine->setFixedHeight(6);
    redLine->setFrameShape(QFrame::HLine);
    verticalLayout->addWidget(redLine);

    // 右侧内容区域
    QWidget* contentWidget = new QWidget();
    contentWidget->setObjectName("contentWidget");
    QVBoxLayout* mainLayout = new QVBoxLayout(contentWidget);
    mainLayout->setSpacing(15);
    mainLayout->setContentsMargins(25, 25, 25, 25);

    verticalLayout->addWidget(contentWidget);

    QHBoxLayout* titleLayout = new QHBoxLayout();
    QLabel* iconLabel = new QLabel();
    iconLabel->setObjectName("iconLabel");
    iconLabel->setPixmap(QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning).pixmap(36, 36));
    iconLabel->setFixedSize(36, 36);

    QLabel* titleLabel = new QLabel("发现恶意项目，天宏安全防御已拦截。");
    titleLabel->setObjectName("titleLabel");

    titleLayout->addWidget(iconLabel);
    titleLayout->addWidget(titleLabel);
    titleLayout->addStretch();

    // 添加拖动功能到标题区域
    // 设置可拖动的组件
    QWidget* dragWidget = new QWidget();
    dragWidget->setFixedHeight(60);
    dragWidget->setCursor(Qt::SizeAllCursor);
    dragWidget->setStyleSheet("background: transparent;");

    // 将标题布局放入拖动widget
    QHBoxLayout* dragLayout = new QHBoxLayout(dragWidget);
    dragLayout->setContentsMargins(0, 0, 0, 0);
    dragLayout->addLayout(titleLayout);

    ElaText* filePathLabel = new ElaText();
    filePathLabel->setObjectName("filePathLabel");
    filePathLabel->setText(QString("文件: %1").arg(filePath));
    filePathLabel->setToolTip(filePath);
    filePathLabel->setMinimumHeight(35);
    filePathLabel->setMaximumHeight(70);
    filePathLabel->setWordWrap(true);
    filePathLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    filePathLabel->setCursor(Qt::IBeamCursor);
    filePathLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    ElaText* typeLabel = new ElaText(QString("威胁类型: %1").arg(threatType));
    typeLabel->setObjectName("typeLabel");
    typeLabel->setMinimumHeight(30);
    typeLabel->setWordWrap(true);
    typeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    typeLabel->setCursor(Qt::IBeamCursor);
    typeLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    ElaText* descriptionLabel = new ElaText("此项目对你的设备有危害，建议立即隔离。");
    descriptionLabel->setObjectName("descriptionLabel");
    descriptionLabel->setMinimumHeight(30);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    descriptionLabel->setCursor(Qt::IBeamCursor);
    descriptionLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    // 检测时间
    QString currentTime = QDateTime::currentDateTime().toString("yyyy.MM.dd hh:mm:ss");
    ElaText* timeLabel = new ElaText(QString("检测时间: %1").arg(currentTime));
    timeLabel->setObjectName("timeLabel");
    timeLabel->setMinimumHeight(20);
    timeLabel->setWordWrap(true);
    timeLabel->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
    timeLabel->setCursor(Qt::IBeamCursor);
    timeLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    // 按钮区域
    QHBoxLayout* buttonLayout = new QHBoxLayout();
    QPushButton* isolateButton = new QPushButton("隔离文件");
    isolateButton->setObjectName("isolateButton");
    QPushButton* noActionButton = new QPushButton("不处理");
    noActionButton->setObjectName("noActionButton");
    QPushButton* whitelistButton = new QPushButton("添加到临时白名单");
    whitelistButton->setObjectName("whitelistButton");

    isolateButton->setFixedSize(130, 35);
    noActionButton->setFixedSize(90, 35);
    whitelistButton->setFixedSize(140, 35);

    buttonLayout->addStretch();
    buttonLayout->addWidget(isolateButton);
    buttonLayout->addSpacing(8);
    buttonLayout->addWidget(whitelistButton);
    buttonLayout->addSpacing(8);
    buttonLayout->addWidget(noActionButton);

    mainLayout->addWidget(dragWidget);  // 使用可拖动的widget替换原来的titleLayout
    mainLayout->addWidget(filePathLabel);
    mainLayout->addWidget(typeLabel);
    mainLayout->addWidget(descriptionLabel);
    mainLayout->addSpacing(8);
    mainLayout->addWidget(timeLabel);
    mainLayout->addStretch();
    mainLayout->addLayout(buttonLayout);

    // ============ 拖动功能 ============
    QPoint m_dragPosition;
    bool m_dragging = false;

    auto mousePressHandler = [&](QMouseEvent* event) {
        if (event->button() == Qt::LeftButton) {
            m_dragging = true;
            m_dragPosition = event->globalPosition().toPoint() - threatDialog->frameGeometry().topLeft();
            event->accept();
        }
        };

    auto mouseMoveHandler = [&](QMouseEvent* event) {
        if (m_dragging && (event->buttons() & Qt::LeftButton)) {
            threatDialog->move(event->globalPosition().toPoint() - m_dragPosition);
            event->accept();
        }
        };

    auto mouseReleaseHandler = [&](QMouseEvent* event) {
        if (event->button() == Qt::LeftButton) {
            m_dragging = false;
            event->accept();
        }
        };

    class DragEventFilter : public QObject {
    private:
        std::function<void(QMouseEvent*)> m_pressHandler;
        std::function<void(QMouseEvent*)> m_moveHandler;
        std::function<void(QMouseEvent*)> m_releaseHandler;

    public:
        DragEventFilter(
            std::function<void(QMouseEvent*)> pressHandler,
            std::function<void(QMouseEvent*)> moveHandler,
            std::function<void(QMouseEvent*)> releaseHandler,
            QObject* parent = nullptr)
            : QObject(parent)
            , m_pressHandler(pressHandler)
            , m_moveHandler(moveHandler)
            , m_releaseHandler(releaseHandler) {
        }

    protected:
        bool eventFilter(QObject* obj, QEvent* event) override {
            QMouseEvent* mouseEvent = nullptr;

            switch (event->type()) {
            case QEvent::MouseButtonPress:
                mouseEvent = static_cast<QMouseEvent*>(event);
                m_pressHandler(mouseEvent);
                break;

            case QEvent::MouseMove:
                mouseEvent = static_cast<QMouseEvent*>(event);
                m_moveHandler(mouseEvent);
                break;

            case QEvent::MouseButtonRelease:
                mouseEvent = static_cast<QMouseEvent*>(event);
                m_releaseHandler(mouseEvent);
                break;

            default:
                break;
            }

            return QObject::eventFilter(obj, event);
        }
    };

    // 安装事件过滤器
    DragEventFilter* dragFilter = new DragEventFilter(
        mousePressHandler, mouseMoveHandler, mouseReleaseHandler, threatDialog);

    dragWidget->installEventFilter(dragFilter);
    // ============ 拖动功能结束 ============

    auto getTitleColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "#ff6b6b" : "#d32f2f";
        };

    auto getWarningColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "#ffa726" : "#f57c00";
        };

    auto getFilePathBgColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "rgba(52, 73, 94, 0.7)" : "rgba(243, 242, 241, 1.0)";
        };

    auto getFilePathColor = [](ElaThemeType::ThemeMode themeMode) {
        return themeMode == ElaThemeType::Dark ? "#bdc3c7" : "#605e5c";
        };

    auto updateStyle = [threatDialog, redLine, getTitleColor, getWarningColor, getFilePathBgColor, getFilePathColor, contentWidget]() {
        ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();

        // 顶部红色横线样式
        redLine->setStyleSheet(QString("QFrame {"
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
            "stop:0 #e74c3c, stop:0.3 #e74c3c, stop:0.7 #e74c3c, stop:1 #c0392b);"
            "border: none;"
            "border-top-left-radius: 12px;"
            "border-top-right-radius: 12px;"
            "}"));

        threatDialog->setStyleSheet(QString("QDialog {"
            "background: %1;"
            "border: 2px solid #e74c3c;"
            "border-radius: 15px;"
            "border-top: none;"
            "}"
            "#contentWidget {"
            "background: %1;"
            "border-bottom-left-radius: 15px;"
            "border-bottom-right-radius: 15px;"
            "}").arg(ElaThemeColor(themeMode, WindowBase).name()));

        QList<QLabel*> labels = contentWidget->findChildren<QLabel*>();
        for (QLabel* label : labels) {
            if (label->objectName() == "titleLabel") {
                label->setStyleSheet(QString("QLabel {"
                    "font-size: 20px;"
                    "font-weight: bold;"
                    "color: %1;"
                    "background: transparent;"
                    "padding: 5px;"
                    "}").arg(getTitleColor(themeMode)));
            }
            else if (label->objectName() == "iconLabel") {
                label->setStyleSheet("QLabel { background: transparent; }");
            }
        }

        QList<ElaText*> elaTexts = contentWidget->findChildren<ElaText*>();
        for (ElaText* elaText : elaTexts) {
            if (elaText->objectName() == "filePathLabel") {
                elaText->setStyleSheet(QString("ElaText {"
                    "color: %1;"
                    "font-size: 14px;"
                    "background-color: %2;"
                    "padding: 8px;"
                    "border-radius: 6px;"
                    "border-left: 3px solid #3498db;"
                    "}").arg(getFilePathColor(themeMode), getFilePathBgColor(themeMode)));
            }
            else if (elaText->objectName() == "typeLabel") {
                elaText->setStyleSheet(QString("ElaText {"
                    "color: %1;"
                    "font-size: 14px;"
                    "font-weight: bold;"
                    "padding: 6px;"
                    "background: rgba(231, 76, 60, 0.1);"
                    "border-radius: 6px;"
                    "border-left: 3px solid #e74c3c;"
                    "}").arg(getTitleColor(themeMode)));
            }
            else if (elaText->objectName() == "descriptionLabel") {
                elaText->setStyleSheet(QString("ElaText {"
                    "color: %1;"
                    "font-size: 14px;"
                    "padding: 6px;"
                    "background: rgba(243, 156, 18, 0.1);"
                    "border-radius: 6px;"
                    "border-left: 3px solid #f39c12;"
                    "}").arg(ElaThemeColor(themeMode, BasicText).name()));
            }
            else if (elaText->objectName() == "timeLabel") {
                elaText->setStyleSheet(QString("ElaText {"
                    "color: %1;"
                    "font-size: 12px;"
                    "padding: 4px;"
                    "background: transparent;"
                    "}").arg(ElaThemeColor(themeMode, BasicText).name()));
            }
        }

        QList<QPushButton*> buttons = contentWidget->findChildren<QPushButton*>();
        for (QPushButton* button : buttons) {
            if (button->objectName() == "isolateButton") {
                button->setStyleSheet(QString(
                    "QPushButton {"
                    "    background-color: %1;"
                    "    color: white;"
                    "    border: none;"
                    "    border-radius: 5px;"
                    "    font-weight: bold;"
                    "    font-size: 13px;"
                    "}"
                    "QPushButton:hover {"
                    "    background-color: #106ebe;"
                    "}"
                    "QPushButton:pressed {"
                    "    background-color: #005a9e;"
                    "}").arg(themeMode == ElaThemeType::Dark ? "#2980b9" : "#0078d4"));
            }
            else if (button->objectName() == "noActionButton") {
                button->setStyleSheet(QString(
                    "QPushButton {"
                    "    background-color: transparent;"
                    "    color: %1;"
                    "    border: 1px solid #000000;"
                    "    border-radius: 5px;"
                    "    font-size: 13px;"
                    "}"
                    "QPushButton:hover {"
                    "    background-color: %3;"
                    "}"
                    "QPushButton:pressed {"
                    "    background-color: %4;"
                    "}").arg(ElaThemeColor(themeMode, BasicText).name(),
                        themeMode == ElaThemeType::Dark ? "#555" : "#ddd",
                        themeMode == ElaThemeType::Dark ? "rgba(255,255,255,0.1)" : "#f3f2f1",
                        themeMode == ElaThemeType::Dark ? "rgba(255,255,255,0.2)" : "#edebe9"));
            }
            else if (button->objectName() == "whitelistButton") {
                button->setStyleSheet(QString(
                    "QPushButton {"
                    "    background-color: %1;"
                    "    color: white;"
                    "    border: none;"
                    "    border-radius: 5px;"
                    "    font-size: 13px;"
                    "}"
                    "QPushButton:hover {"
                    "    background-color: %2;"
                    "}"
                    "QPushButton:pressed {"
                    "    background-color: %3;"
                    "}").arg(themeMode == ElaThemeType::Dark ? "#27ae60" : "#2e7d32",
                            themeMode == ElaThemeType::Dark ? "#229954" : "#1b5e20",
                            themeMode == ElaThemeType::Dark ? "#1e8449" : "#0d3f12"));
            }
        }
        };

    QObject::connect(eTheme, &ElaTheme::themeModeChanged, threatDialog, [threatDialog, updateStyle](ElaThemeType::ThemeMode themeMode) {
        updateStyle();
        threatDialog->update();
        });

    auto centerDialog = [threatDialog]() {
        QScreen* screen = QGuiApplication::primaryScreen();
        if (screen) {
            QRect screenGeometry = screen->availableGeometry();
            int x = (screenGeometry.width() - threatDialog->width()) / 2;
            int y = (screenGeometry.height() - threatDialog->height()) / 2;
            threatDialog->move(x, y);
        }
        };

    QEventLoop eventLoop;

    QPropertyAnimation* animation = new QPropertyAnimation(threatDialog, "windowOpacity");
    animation->setDuration(300);
    animation->setStartValue(0.0);
    animation->setEndValue(1.0);
    animation->start();

    auto handleButtonClick = [&](BOOL result) {
        localResult = result;

        if (result)
        {
            showFileIconBreakAnimationAsync(filePath, nullptr);

            Encrypt_EncrptFile((wstring)CString(((string)filePath.toLocal8Bit()).c_str()));
        }

        threatDialog->hide();
        eventLoop.quit();
        };

    QObject::connect(isolateButton, &QPushButton::clicked, threatDialog, [&]() { handleButtonClick(TRUE); });
    QObject::connect(noActionButton, &QPushButton::clicked, threatDialog, [&]() { handleButtonClick(FALSE); });

    // 添加到临时白名单：计算SHA256，加入缓存并持久化，然后关闭对话框（不处理文件）
    QObject::connect(whitelistButton, &QPushButton::clicked, threatDialog, [&]() {
        bool ok = Whitelist_AddTemporary(filePath);
        if (ok) {
            NewMessageBox(QString("已将 %1 添加到临时白名单。").arg(QFileInfo(filePath).fileName()), 1, 3);
        } else {
            NewMessageBox(QString("添加临时白名单失败，可能无法访问文件。"), 3, 3);
        }
        handleButtonClick(FALSE);  // 不隔离文件
        });

    QObject::connect(threatDialog, &QDialog::rejected, threatDialog, [&]() {
        handleButtonClick(FALSE);
        });

    threatDialog->show();
    threatDialog->hide();
    updateStyle(); // 应用样式
    centerDialog(); // 居中
    threatDialog->show();
    eventLoop.exec();

    return localResult;
}
static QString GetProcessNameByPid(int pid)
{
    QString processName = "Unknown";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess)
    {
        TCHAR path[MAX_PATH + 4] = { 0 };
        DWORD size = sizeof(path) / sizeof(TCHAR);
        if (QueryFullProcessImageName(hProcess, 0, path, &size))
        {
            processName = QString::fromWCharArray(PathFindFileName(path));
        }
        CloseHandle(hProcess);
    }
    return processName;
}

RelActWarnType ShowAlertDialog(const QString& title, const int& pid, const QString& context)
{
    UNREFERENCED_PARAMETER(context);

    // 静默模式：自动阻止，使用 NewMessageBox 弹窗通知
    if (g_bSilentModeEnabled)
    {
        QString processName = GetProcessNameByPid(pid);
        NewMessageBox(QString("%1 (%2, PID=%3)").arg(title).arg(processName).arg(pid), 2, 10, title);
        return AW_Prevent;
    }

    // 确保在主线程中创建对话框（Qt GUI 控件必须在主线程操作）
    if (QThread::currentThread() != QCoreApplication::instance()->thread())
    {
        RelActWarnType result = AW_Prevent;
        QMetaObject::invokeMethod(QCoreApplication::instance(), [&]() {
            result = OrgShowAlertDialog(title, pid, context, false);
        }, Qt::BlockingQueuedConnection);
        return result;
    }

    // 普通模式：弹出模态询问对话框，让用户选择允许/阻止
    return OrgShowAlertDialog(title, pid, context, false);
}

RelActWarnType ShowAlertDialogWithUAC(const QString& title, const int& pid, const QString& context)
{
    UNREFERENCED_PARAMETER(context);

    // 静默模式：自动阻止，使用 NewMessageBox 弹窗通知
    if (g_bSilentModeEnabled)
    {
        QString processName = GetProcessNameByPid(pid);
        NewMessageBox(QString("%1 (%2, PID=%3)").arg(title).arg(processName).arg(pid), 2, 10, title);
        return AW_Prevent;
    }

    // 确保在主线程中创建对话框（Qt GUI 控件必须在主线程操作）
    if (QThread::currentThread() != QCoreApplication::instance()->thread())
    {
        RelActWarnType result = AW_Prevent;
        QMetaObject::invokeMethod(QCoreApplication::instance(), [&]() {
            result = OrgShowAlertDialog(title, pid, context, true);
        }, Qt::BlockingQueuedConnection);
        return result;
    }

    // 普通模式：弹出 UAC 安全桌面询问对话框，让用户选择允许/阻止
    return OrgShowAlertDialog(title, pid, context, true);
}

BOOL ShowThreatDialog(const QString& filePath, const QString& threatType)
{
    // 静默模式：不弹模态威胁对话框，使用 NewMessageBox 泡泡弹窗
    if (g_bSilentModeEnabled)
    {
        QString text = QString("已拦截威胁：%1 (%2)").arg(QFileInfo(filePath).fileName()).arg(threatType);
        NewMessageBox(text, 2, 5, "威胁拦截");
        return FALSE;
    }

    BOOL result = FALSE;

    if (QThread::currentThread() != QCoreApplication::instance()->thread())
    {
        QMetaObject::invokeMethod(qApp, [&]() {
            result = OrgShowThreatDialog(filePath, threatType);
            }, Qt::BlockingQueuedConnection);
    }
    else
    {
        result = OrgShowThreatDialog(filePath, threatType);
    }

    return result;
}


// Transport Function

extern int Tran_RecvPacket(SOCKET s, Packet& PacketOut)
{
    char recvbuf[sizeof(Packet)];
    Packet* Packetrecv;
    int result = recv(s, recvbuf, sizeof(recvbuf), 0);
    Packetrecv = (Packet*)recvbuf;
    PacketOut = *Packetrecv;
    return result;
}

int Violation(LPEXCEPTION_POINTERS p_exinfo)
{
    if (p_exinfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
    {
        return EXCEPTION_EXECUTE_HANDLER; //告诉except处理这个异常
    }
    else
    {
        return EXCEPTION_CONTINUE_SEARCH; //不告诉except处理这个异常
    }
}

extern int Tran_OrgSendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char WarnTitle[128], int Pid, char InfoTitle[32], WarnDlgType DlgIconType, bool NeedTerminate)
{
    Packet Packetsend{};

    Packetsend.Pid = Pid;
    Packetsend.PacketTyped = PacketTypeIn;
    Packetsend.WarnType = DlgIconType;
    Packetsend.NeedTerminate = NeedTerminate;

    // 使用 _TRUNCATE 防止源字符串过长导致运行时断言；保留截断语义
    strncpy_s(Packetsend.Message, sizeof(Packetsend.Message), text, _TRUNCATE);
    strncpy_s(Packetsend.WarnTitle, sizeof(Packetsend.WarnTitle), WarnTitle, _TRUNCATE);
    strncpy_s(Packetsend.InfoTitle, sizeof(Packetsend.InfoTitle), InfoTitle, _TRUNCATE);

    char SendBuff[sizeof(Packet)] = "";
    memcpy(SendBuff, &Packetsend, sizeof(Packet));

    // 循环发送，确保完整写出或返回 SOCKET_ERROR
    int totalSent = 0;
    int toSend = sizeof(SendBuff);
    while (totalSent < toSend)
    {
        int sent = send(s, SendBuff + totalSent, toSend - totalSent, 0);
        if (sent == SOCKET_ERROR)
            return SOCKET_ERROR;
        totalSent += sent;
    }
    return totalSent;
}

extern int Tran_SendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char Title[128], int Pid)
{
    return Tran_OrgSendPacket(s, text, PacketTypeIn, Title, Pid, (char*)"", WDT_Normal, false);
}

extern bool Tran_IsSocketClosed(SOCKET clientSocket)
{
    bool ret = false;
    HANDLE closeEvent = WSACreateEvent();
    WSAEventSelect(clientSocket, closeEvent, FD_CLOSE);

    DWORD dwRet = WaitForSingleObject(closeEvent, 0);

    if (dwRet == WSA_WAIT_EVENT_0)
        ret = true;
    else if (dwRet == WSA_WAIT_TIMEOUT)
        ret = false;

    WSACloseEvent(closeEvent);
    return ret;
}


// File Function

// 检查是否为系统文件
bool File_VerifySystemFile(wstring filePath)
{
    BOOL isProtected = SfcIsFileProtected(NULL, filePath.c_str());

    return isProtected;
}

wstring File_GetFirstSignerName(const wchar_t* filePath) {
    wstring signerName;

    // 初始化WINTRUST_FILE_INFO结构
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // 初始化WINTRUST_DATA结构
    WINTRUST_DATA wintrustData = { 0 };
    wintrustData.cbStruct = sizeof(wintrustData);
    wintrustData.pPolicyCallbackData = NULL;
    wintrustData.pSIPClientData = NULL;
    wintrustData.dwUIChoice = WTD_UI_NONE;  // 不显示UI
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.hWVTStateData = NULL;
    wintrustData.pwszURLReference = NULL;
    wintrustData.dwProvFlags = WTD_REVOCATION_CHECK_NONE;
    wintrustData.dwUIContext = 0;

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // 验证文件签名
    LONG trustStatus = WinVerifyTrust(
        NULL,
        &policyGuid,
        &wintrustData);

    if (trustStatus == ERROR_SUCCESS) {
        // 获取签名信息
        HCERTSTORE certStore = NULL;
        HCRYPTMSG cryptMsg = NULL;

        CRYPT_PROVIDER_DATA* providerData = WTHelperProvDataFromStateData(
            wintrustData.hWVTStateData);

        if (providerData) {
            CRYPT_PROVIDER_SGNR* providerSigner = WTHelperGetProvSignerFromChain(
                providerData,  // 第一个签名者
                0,             // 索引
                FALSE,         // 不获取计数器签名
                0);            // 标志

            if (providerSigner && providerSigner->pasCertChain) {
                PCCERT_CONTEXT certContext = providerSigner->pasCertChain[0].pCert;

                if (certContext) {
                    // 获取证书主题名称
                    DWORD nameSize = CertGetNameStringW(
                        certContext,
                        CERT_NAME_SIMPLE_DISPLAY_TYPE,
                        0,
                        NULL,
                        NULL,
                        0);

                    if (nameSize > 1) {
                        wchar_t* name = new wchar_t[nameSize];
                        if (CertGetNameStringW(
                            certContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            NULL,
                            name,
                            nameSize) > 1) {
                            signerName = name;
                        }
                        delete[] name;
                    }
                }
            }
        }
    }

    // 清理状态数据
    wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGuid, &wintrustData);

    return signerName;
}

// 检查文件合法签名并可选验证签名者名称
bool File_CheckFileSignature(const wstring& filePath, const wstring& certName)
{
    bool isValid = false;
    wstring signerCertName = L"";

    // 初始化文件信息
    WINTRUST_FILE_INFO fileInfo = { 0 };
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    // 初始化信任数据
    WINTRUST_DATA trustData = { 0 };
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.pPolicyCallbackData = NULL;
    trustData.pSIPClientData = NULL;
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.hWVTStateData = NULL;
    trustData.pwszURLReference = NULL;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    trustData.dwUIContext = WTD_UICONTEXT_EXECUTE;

    // 验证签名
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

    // 检查签名有效性
    if (result == ERROR_SUCCESS)
    {
        isValid = true;

        // 如果指定了签名者名称，需要进一步验证
        if (!certName.empty())
        {
            signerCertName = File_GetFirstSignerName(filePath.c_str());

            // 比较签名者名称
            if (!signerCertName.empty())
            {
                wstring signerLower = signerCertName;
                wstring certNameLower = certName;

                // 转换为小写进行比较
                transform(signerLower.begin(), signerLower.end(), signerLower.begin(), ::towlower);
                transform(certNameLower.begin(), certNameLower.end(), certNameLower.begin(), ::towlower);

                // 检查是否包含指定的签名者名称（部分匹配）
                if (signerLower.find(certNameLower) == wstring::npos)
                {
                    isValid = false;  // 名称不匹配
                }
            }
            else
            {
                // 指定了证书名称但未获取到签名者名称
                isValid = false;
            }
        }
    }

    // 清理WinVerifyTrust资源
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    return isValid;
}

// 检查文件夹及其所有子文件夹中所有可执行文件的签名有效性
// 返回所有无效签名文件的完整路径列表
vector<wstring> File_CheckFolderSignature(const wstring& folderPath)
{
    vector<wstring> invalidFiles;
    vector<wstring> foldersToCheck;

    // 检查文件夹路径是否有效
    if (folderPath.empty())
    {
        return invalidFiles;
    }

    // 将初始文件夹加入待检查列表
    foldersToCheck.push_back(folderPath);

    // 可执行文件扩展名
    static const vector<wstring> exeExtensions = {
        L".exe", L".dll", L".sys"
    };

    // 循环处理所有文件夹（包括子文件夹）
    size_t currentFolderIndex = 0;
    while (currentFolderIndex < foldersToCheck.size())
    {
        wstring currentFolder = foldersToCheck[currentFolderIndex];
        currentFolderIndex++;

        // 确保文件夹路径以反斜杠结尾
        if (currentFolder.back() != L'\\' && currentFolder.back() != L'/')
        {
            currentFolder += L'\\';
        }

        // 构建搜索路径
        wstring searchPath = currentFolder + L"*.*";

        // 开始搜索文件
        WIN32_FIND_DATA findFileData;
        HANDLE hFind = FindFirstFile(searchPath.c_str(), &findFileData);

        if (hFind == INVALID_HANDLE_VALUE)
        {
            // 无法访问的文件夹，跳过
            continue;
        }

        do
        {
            // 跳过 "." 和 ".."
            if (wcscmp(findFileData.cFileName, L".") == 0 ||
                wcscmp(findFileData.cFileName, L"..") == 0)
            {
                continue;
            }

            // 构建完整路径
            wstring fullPath = currentFolder + findFileData.cFileName;

            // 如果是子文件夹，加入待检查列表
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                foldersToCheck.push_back(fullPath);
                continue;
            }

            // 检查文件扩展名
            wstring filename = findFileData.cFileName;
            size_t dotPos = filename.rfind(L'.');

            if (dotPos == wstring::npos)
            {
                continue;  // 没有扩展名，跳过
            }

            wstring extension = filename.substr(dotPos);
            // 转换为小写
            transform(extension.begin(), extension.end(), extension.begin(), ::towlower);

            // 检查是否为可执行文件类型
            bool isExecutable = false;
            for (const auto& ext : exeExtensions)
            {
                if (extension == ext)
                {
                    isExecutable = true;
                    break;
                }
            }

            if (!isExecutable)
            {
                continue;  // 不是可执行文件，跳过
            }

            // 检查文件签名
            bool isValid = File_CheckFileSignature(fullPath);

            if (!isValid)
            {
                invalidFiles.push_back(fullPath);
            }

        } while (FindNextFile(hFind, &findFileData) != 0);

        FindClose(hFind);
    }

    return invalidFiles;
}

// 计算文件熵值
double File_CalculateEntropy(const string& filePath) {
    // 打开文件
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file) {
        // std::cerr << "无法打开文件: " << filePath << std::endl;
        return -1.0;
    }

    // 获取文件大小
    std::streamsize fileSize = file.tellg();
    if (fileSize <= 0) {
        // std::cerr << "文件为空或无法获取大小" << std::endl;
        return 0.0;
    }

    // 回到文件开头
    file.seekg(0, std::ios::beg);

    // 统计每个字节的出现次数
    unsigned int byteCount[256] = { 0 };
    unsigned char buffer[4096];

    while (file) {
        file.read(reinterpret_cast<char*>(buffer), sizeof(buffer));
        std::streamsize bytesRead = file.gcount();

        for (std::streamsize i = 0; i < bytesRead; ++i) {
            byteCount[buffer[i]]++;
        }
    }

    // 计算熵值
    double entropy = 0.0;
    double totalBytes = static_cast<double>(fileSize);

    for (int i = 0; i < 256; ++i) {
        if (byteCount[i] > 0) {
            double probability = static_cast<double>(byteCount[i]) / totalBytes;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

string File_GetShortFileName(string longFileName)
{
    char shortPath[MAX_PATH];
    DWORD result = GetShortPathNameA(longFileName.c_str(), shortPath, MAX_PATH);
    if (result == 0)
    {
        return longFileName;
    }
    else
    {
        return longFileName.substr(0, longFileName.find_last_of('\\')) + ((string)shortPath).substr(((string)shortPath).find_last_of('\\'));
    }
}

bool File_IsModifiedOverOneDay(wchar_t* filePath)
{
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
    {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    // 转换为系统时间
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ftWrite, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    // 转换为time_t
    struct tm tm;
    tm.tm_year = stLocal.wYear - 1900;
    tm.tm_mon = stLocal.wMonth - 1;
    tm.tm_mday = stLocal.wDay;
    tm.tm_hour = stLocal.wHour;
    tm.tm_min = stLocal.wMinute;
    tm.tm_sec = stLocal.wSecond;
    tm.tm_isdst = -1;
    time_t fileTime = mktime(&tm);

    // 当前时间
    time_t now = time(NULL);

    // 计算时间差（秒）
    double diff = difftime(now, fileTime);

    return diff > 24 * 3600; // 超过1天
}

// 检查文件是否为PE格式（EXE/DLL）
bool File_IsPEFile(wchar_t* filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file)
    {
        return false;
    }

    IMAGE_DOS_HEADER dosHeader;
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }

    file.seekg(dosHeader.e_lfanew, ios::beg);
    DWORD peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    if (peSignature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    return true;
}

// 检查PE文件是否包含图标资源
bool File_HasIconResource(wchar_t* filePath)
{
    HMODULE hModule = LoadLibraryEx(filePath, NULL, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
    if (hModule == NULL)
    {
        return false;
    }

    HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(1), RT_GROUP_ICON);
    if (hResource == NULL)
    {
        hResource = FindResource(hModule, MAKEINTRESOURCE(1), RT_ICON);
    }

    FreeLibrary(hModule);
    return hResource != NULL;
}

// 检查文件大小是否正常（大于20KB）
bool File_IsFileSizeNormal(wchar_t* filePath)
{
    HANDLE hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize))
    {
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);
    return fileSize.QuadPart > 20 * 1024; // 大于20KB
}

void File_SetFileHidden(string FilePath)
{
    // 获取文件属性
    DWORD attributes = GetFileAttributesA(FilePath.c_str());

    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        return;
    }

    // 设置隐藏属性
    attributes |= FILE_ATTRIBUTE_HIDDEN;

    SetFileAttributesA(FilePath.c_str(), attributes);
}

bool File_DeleteDirectory(string path)
{
    // 创建一个搜索句柄
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    do
    {
        // 忽略当前目录和父目录
        if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0)
        {
            continue;
        }

        string fullPath = path + "\\" + findFileData.cFileName;

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            // 如果是子目录，递归删除
            if (!File_DeleteDirectory(fullPath))
            {
                FindClose(hFind);
                return false;
            }
        }
        else
        {
            // 如果是文件，直接删除
            if (!DeleteFileA(fullPath.c_str()))
            {
                FindClose(hFind);
                return false;
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    // 关闭搜索句柄
    FindClose(hFind);

    // 删除空目录
    if (!RemoveDirectoryA(path.c_str()))
    {
        return false;
    }

    return true;
}

// 获得文件夹文件数
int File_GetFileCount(wstring dir)
{
    wstring ndir = dir + L"\\*.*";
    int HasScaned = 0;
    HANDLE hFind;
    WIN32_FIND_DATA findData;
    hFind = FindFirstFile(ndir.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        return -1;
    }
    do
    {
        // 忽略"."和".."两个结果 
        if (wcscmp(findData.cFileName, L"..") != 0 && wcscmp(findData.cFileName, L".") != 0)
        {
            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)    // 是否是目录 
            {
                HasScaned += File_GetFileCount(dir + L"\\" + findData.cFileName);
            }
            else
            {
                HasScaned++;
            }
        }
    } while (FindNextFile(hFind, &findData));
    return HasScaned;
}

// 压缩文件格式魔数定义
namespace ArchiveSignatures {
    // ZIP 及相关格式
    const std::vector<uint8_t> ZIP_LOCAL = { 0x50, 0x4B, 0x03, 0x04 };     // ZIP 本地文件头
    const std::vector<uint8_t> ZIP_EMPTY = { 0x50, 0x4B, 0x05, 0x05 };     // ZIP 空归档
    const std::vector<uint8_t> ZIP_SPANNED = { 0x50, 0x4B, 0x07, 0x08 };    // ZIP 分卷
    const std::vector<uint8_t> ZIP_CENTRAL = { 0x50, 0x4B, 0x01, 0x02 };    // ZIP 中央目录
    const std::vector<uint8_t> ZIP_EOCD = { 0x50, 0x4B, 0x05, 0x06 };       // ZIP 结束记录
    const std::vector<uint8_t> ZIP_7Z = { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }; // 7z 格式

    // RAR 格式
    const std::vector<uint8_t> RAR_1_5 = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00 }; // RAR 1.5
    const std::vector<uint8_t> RAR_5_0 = { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00 }; // RAR 5.0

    // GZIP
    const std::vector<uint8_t> GZIP = { 0x1F, 0x8B };

    // TAR
    const std::vector<uint8_t> TAR_USTAR = { 0x75, 0x73, 0x74, 0x61, 0x72 }; // ustar 偏移257

    // CAB
    const std::vector<uint8_t> CAB = { 0x4D, 0x53, 0x43, 0x46 }; // MSCF

    // BZIP2
    const std::vector<uint8_t> BZIP2 = { 0x42, 0x5A, 0x68 };

    // XZ
    const std::vector<uint8_t> XZ = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };

    // ISO
    const std::vector<uint8_t> ISO_9660 = { 0x43, 0x44, 0x30, 0x30, 0x31 }; // CD001 偏移32769

    // ARJ
    const std::vector<uint8_t> ARJ = { 0x60, 0xEA };

    // LZH/LHA
    const std::vector<uint8_t> LZH = { 0x2D, 0x6C, 0x68, 0x2D }; // -lh-
}

// 检查文件头是否匹配魔数
bool CheckSignature(const uint8_t* data, size_t data_len, const std::vector<uint8_t>& sig, size_t offset = 0) {
    if (data_len < offset + sig.size()) {
        return false;
    }
    return memcmp(data + offset, sig.data(), sig.size()) == 0;
}

// 通过扩展名判断
bool IsArchiveByExtension(const std::string& path) {
    std::string ext;
    size_t pos = path.find_last_of(".");
    if (pos != std::string::npos) {
        ext = path.substr(pos + 1);
        // 转换为小写
        for (char& c : ext) c = tolower(c);

        // 常见压缩文件扩展名
        std::vector<std::string> archive_exts = {
            "zip", "rar", "7z", "gz", "gzip", "tar", "tgz", "bz2", "bz",
            "xz", "z", "lz", "lzma", "lzo", "arj", "cab", "iso", "img",
            "dmg", "pkg", "deb", "rpm", "zst", "tzst", "tbz2", "tlz",
            "tz", "taz", "tz2", "t7z", "apk", "jar", "war", "ear", "xpi",
            "cbz", "cbr", "epub", "dmg", "vhd", "vmdk", "ova", "msi"
        };

        for (const auto& archive_ext : archive_exts) {
            if (ext == archive_ext) {
                return true;
            }
        }
    }
    return false;
}

bool File_IsArchive(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    // 读取文件头（前512字节足够检测大部分格式）
    const size_t HEADER_SIZE = 512;
    std::vector<uint8_t> header(HEADER_SIZE);
    file.read(reinterpret_cast<char*>(header.data()), HEADER_SIZE);
    size_t read_size = file.gcount();

    if (read_size < 4) { // 至少需要4字节
        return false;
    }

    // 1. 检查文件头魔数
    using namespace ArchiveSignatures;

    // ZIP 格式检测
    if (CheckSignature(header.data(), read_size, ZIP_LOCAL) ||
        CheckSignature(header.data(), read_size, ZIP_EMPTY) ||
        CheckSignature(header.data(), read_size, ZIP_SPANNED) ||
        CheckSignature(header.data(), read_size, ZIP_CENTRAL) ||
        CheckSignature(header.data(), read_size, ZIP_EOCD)) {
        return true;
    }

    // 7z 格式检测
    if (CheckSignature(header.data(), read_size, ZIP_7Z)) {
        return true;
    }

    // RAR 格式检测
    if (CheckSignature(header.data(), read_size, RAR_1_5) ||
        CheckSignature(header.data(), read_size, RAR_5_0)) {
        return true;
    }

    // GZIP 格式检测
    if (CheckSignature(header.data(), read_size, GZIP)) {
        return true;
    }

    // CAB 格式检测
    if (CheckSignature(header.data(), read_size, CAB)) {
        return true;
    }

    // BZIP2 格式检测
    if (CheckSignature(header.data(), read_size, BZIP2)) {
        return true;
    }

    // XZ 格式检测
    if (CheckSignature(header.data(), read_size, XZ)) {
        return true;
    }

    // ARJ 格式检测
    if (CheckSignature(header.data(), read_size, ARJ)) {
        return true;
    }

    // LZH/LHA 格式检测
    if (CheckSignature(header.data(), read_size, LZH)) {
        return true;
    }

    // TAR 格式检测（ustar 签名在偏移257处）
    if (read_size > 257 + 5) {
        if (CheckSignature(header.data(), read_size, TAR_USTAR, 257)) {
            return true;
        }
    }

    // ISO 格式检测（CD001 签名在偏移32769处，但这里只读512字节，所以作为备选）
    if (read_size > 32769 + 5) {
        // 需要读取更多数据
        file.clear();
        file.seekg(32769, std::ios::beg);
        std::vector<uint8_t> iso_sig(5);
        file.read(reinterpret_cast<char*>(iso_sig.data()), 5);
        if (file.gcount() == 5 && memcmp(iso_sig.data(), ISO_9660.data(), 5) == 0) {
            return true;
        }
    }

    return false;
}


// Window Function

// 转至安全桌面
void Windows_TurnToUac()
{
    if (!Windows_IsNowUAC)
    {
        Windows_IsNowUAC = TRUE;
        if (Windows_UacDesktop && Windows_OrgDesktop)
        {
            SetThreadDesktop(Windows_UacDesktop);
            SwitchDesktop(Windows_UacDesktop);
        }
    }
}

// 退出安全桌面
void Windows_BackFromUac()
{
    if (Windows_IsNowUAC)
    {
        if (Windows_UacDesktop && Windows_OrgDesktop)
        {
            SwitchDesktop(Windows_OrgDesktop);
            SetThreadDesktop(Windows_OrgDesktop);
        }
        Windows_IsNowUAC = FALSE;
    }
}




// Process Function

// 当前路径
inline wstring Process_GetCurrentProcessPath()
{
    TCHAR szDir[MAX_PATH];
    HMODULE hModule;

    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPTSTR)Process_GetCurrentProcessPath, &hModule);
    if (NULL != hModule)
    {
        GetModuleFileName(hModule, szDir, MAX_PATH);
        PathRemoveFileSpec(szDir);
    }
    wstring result = szDir;
    return result;
}

// 获得dll路径
wstring Process_GetCurrentProcessPathWithDll()
{
    wstring result = Process_GetCurrentProcessPath();
    result += L"\\Resources\\BinaryFiles\\TianHongDefense";
    return result;
}

void Process_SuspendProcess(HANDLE processHandle, bool CloseHandleit)
{
    HMODULE hM = GetModuleHandle(L"ntdll");
    if (hM && processHandle)
    {
        typeNtSuspendProcess pfnNtSuspendProcess =
            (typeNtSuspendProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSuspendProcess");
        if (pfnNtSuspendProcess) pfnNtSuspendProcess(processHandle);
        if (CloseHandleit) CloseHandle(processHandle);
    }
}

void Process_ResumeProcess(HANDLE processHandle, bool CloseHandleit)
{
    HMODULE hM = GetModuleHandle(L"ntdll");
    if (hM && processHandle)
    {
        typeNtResumeProcess pfnNtResumeProcess =
            (typeNtResumeProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtResumeProcess");
        if (pfnNtResumeProcess) pfnNtResumeProcess(processHandle);
        if (CloseHandleit) CloseHandle(processHandle);
    }
}

// 检测是否是64bit进程
bool Process_IsProcess64Bit(HANDLE hProcess)
{
    BOOL isWow64 = FALSE;
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = nullptr;

    // 获取IsWow64Process函数的地址
    HMODULE hM = GetModuleHandle(TEXT("kernel32"));
    if (hM)
    {
        fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(
            hM, "IsWow64Process");

        if (NULL != fnIsWow64Process)
        {
            if (!fnIsWow64Process(hProcess, &isWow64))
            {
                // 处理错误
                return false;
            }
        }
    }
    return !isWow64;
}

// 辅助函数：检查目标进程中是否已加载指定DLL
BOOL IsModuleLoadedInProcess(HANDLE hProcess, const wstring& moduleName)
{
    // 使用 EnumProcessModulesEx 而非 TH32CS_SNAPMODULE
    // TH32CS_SNAPMODULE 在 x64 进程中只能枚举到 x86 模块（通过 WoW64 层），无法正确检测 x64 DLL
    HMODULE hModules[1024];
    DWORD cbNeeded = 0;

    if (!EnumProcessModulesEx(hProcess, hModules, sizeof(hModules), &cbNeeded, LIST_MODULES_ALL))
    {
        return FALSE;
    }

    DWORD numModules = cbNeeded / sizeof(HMODULE);
    BOOL bFound = FALSE;

    for (DWORD i = 0; i < numModules; i++)
    {
        wchar_t szModuleName[MAX_PATH] = { 0 };
        if (GetModuleFileNameExW(hProcess, hModules[i], szModuleName, MAX_PATH) == 0)
            continue;

        // 提取文件名进行比较
        wstring loadedModule = szModuleName;
        size_t pos = loadedModule.find_last_of(L"\\/");
        if (pos != wstring::npos)
        {
            loadedModule = loadedModule.substr(pos + 1);
        }

        wstring targetModule = moduleName;
        pos = targetModule.find_last_of(L"\\/");
        if (pos != wstring::npos)
        {
            targetModule = targetModule.substr(pos + 1);
        }

        if (_wcsicmp(loadedModule.c_str(), targetModule.c_str()) == 0)
        {
            bFound = TRUE;
            break;
        }
    }

    return bFound;
}

// 注入函数
int Process_InjectDll(DWORD dwProcessId)
{
    HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (NULL == hProcess)
    {
        return FALSE;
    }

    // 获取目标DLL路径
    wstring pDll = Process_GetCurrentProcessPathWithDll().c_str();
    BOOL is64Bit = Process_IsProcess64Bit(hProcess);

    if (is64Bit)
        pDll += L"64.dll";
    else
        pDll += L"32.dll";

    // 检查模块是否已存在
    if (IsModuleLoadedInProcess(hProcess, pDll))
    {
        // 模块已加载，直接返回2
        CloseHandle(hProcess);
        return 2;
    }

    // 32位进程通过helper.exe注入
    if (!is64Bit)
    {
        USES_CONVERSION;
        string par = W2A(pDll.c_str());
        string eventName = GenerateUniqueEventName(dwProcessId);

        HANDLE hHookReady = CreateEventA(NULL, TRUE, FALSE, eventName.c_str());
        if (!hHookReady)
        {
            CloseHandle(hProcess);
            return FALSE;
        }

        if (Process_IsInjectorReady)
        {
            Tran_SendPacket(Tran_ClientInjector, (char*)par.c_str(),
                PTCreateProcessRoutine, (char*)eventName.c_str(), dwProcessId);

            CloseHandle(hProcess);
            return TRUE;
        }

        CloseHandle(hProcess);
        return FALSE;
    }

    // 64位进程直接注入
    const TCHAR* ptszDllFile = pDll.c_str();
    if (NULL == ptszDllFile || 0 == ::_tcslen(ptszDllFile))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (-1 == _taccess(ptszDllFile, 0))
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 检查进程是否已被挂起（如果是，需要先恢复）
    DWORD suspendCount = 0;
    typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    NtQueryInformationProcess_t pNtQueryInformationProcess =
        (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (pNtQueryInformationProcess)
    {
        PROCESS_BASIC_INFORMATION pbi = { 0 };
        NTSTATUS status = pNtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
        if (NT_SUCCESS(status))
        {
            // PebBaseAddress->BeingDebugged 偏移为 2，SuspendCount 在 PEB+0x0018
            // 通过 NtQueryInformationProcess 获取 HangCount 来判断挂起状态（简化处理：直接尝试注入）
            suspendCount = (DWORD)(ULONG_PTR)pbi.PebBaseAddress;
        }
    }

    // 分配内存并写入DLL路径
    DWORD dwSize = (DWORD)::_tcslen(ptszDllFile) + 1;
    TCHAR* ptszRemoteBuf = (TCHAR*)::VirtualAllocEx(hProcess, NULL, dwSize * sizeof(TCHAR),
        MEM_COMMIT, PAGE_READWRITE);
    if (NULL == ptszRemoteBuf)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (FALSE == ::WriteProcessMemory(hProcess, ptszRemoteBuf, (LPVOID)ptszDllFile,
        dwSize * sizeof(TCHAR), NULL))
    {
        ::VirtualFreeEx(hProcess, ptszRemoteBuf, NULL, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 获取LoadLibraryW地址
    HMODULE hM = ::GetModuleHandle(_T("Kernel32"));
    LPTHREAD_START_ROUTINE lpThreadFun = NULL;

    if (hM)
        lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(hM, "LoadLibraryW");

    if (NULL == lpThreadFun)
    {
        ::VirtualFreeEx(hProcess, ptszRemoteBuf, NULL, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 创建远程线程
    HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, ptszRemoteBuf, 0, NULL);
    if (NULL == hThread)
    {
        // CreateRemoteThread 失败，可能是因为进程被挂起，释放内存后返回
        ::VirtualFreeEx(hProcess, ptszRemoteBuf, NULL, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // 等待远程线程完成（最多10秒，给挂起进程足够时间执行）
    DWORD waitResult = ::WaitForSingleObject(hThread, 10000);
    if (waitResult == WAIT_TIMEOUT)
    {
        // 目标进程可能仍处于挂起状态，远程线程无法执行
        // 释放远程内存句柄，但保留内存由目标进程自行管理
        ::CloseHandle(hThread);
        ::CloseHandle(hProcess);
        return FALSE;
    }
    else if (waitResult == WAIT_FAILED)
    {
        ::CloseHandle(hThread);
        ::CloseHandle(hProcess);
        return FALSE;
    }

    ::CloseHandle(hThread);
    ::CloseHandle(hProcess);

    return TRUE;
}

BOOL Process_SetProcessAsNonCritical(HANDLE hProcess)
{
    if (!hProcess) return FALSE;

    // 获取函数指针
    typeNtSetInformationProcess pNtSetInformationProcess =
        (typeNtSetInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");

    if (pNtSetInformationProcess)
    {
        ULONG isCritical = 0; // 0 = 非关键进程
        NTSTATUS status = pNtSetInformationProcess(
            hProcess,
            ProcessBreakOnTermination,
            &isCritical,
            sizeof(isCritical));

        if (status != 0)
        {
            return FALSE;
        }
        else
        {
            return TRUE;
        }
    }
    else return FALSE;
}

BOOL Process_ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitCode)
{
    typeZwTerminateProcess pZwTerminateProcess;

    pZwTerminateProcess = (typeZwTerminateProcess)GetProcAddress(LoadLibrary(L"NtDll.dll"), "ZwTerminateProcess");

    if (pZwTerminateProcess)
    {
        /* 先尝试清除 BreakOnTermination 关键标志；若句柄权限不足导致失败，
         * 仍继续尝试 ZwTerminateProcess，避免仅因无法清标志就放弃终止。 */
        Process_SetProcessAsNonCritical(ProcessHandle);

        return (pZwTerminateProcess(ProcessHandle, ExitCode) == STATUS_SUCCESS);
    }
    else
    {
        return (TerminateProcess(ProcessHandle, ExitCode) != 0);
    }
}

int Process_GetProcessParent(int pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    typeNtQueryInformationProcess pNtQueryInformationProcess;

    pNtQueryInformationProcess = (typeNtQueryInformationProcess)GetProcAddress(LoadLibrary(L"NtDll.dll"), "NtQueryInformationProcess");

    if (pNtQueryInformationProcess == NULL) return -1;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS Nstatus = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (Nstatus != 0) return -1;

    return (DWORD)pbi.Reserved3;
}

// 获取命令行参数
string Process_GetProcessCommandLine(HANDLE hProcess)
{
    typeNtQueryInformationProcess pNtQueryInformationProcess;

    pNtQueryInformationProcess = (typeNtQueryInformationProcess)GetProcAddress(LoadLibrary(L"NtDll.dll"), "NtQueryInformationProcess");

    if (!pNtQueryInformationProcess)
    {
        return "";
    }

    if (!hProcess)
    {
        return "";
    }

    PROCESS_BASIC_INFORMATION pi;

    memset(&pi, 0, sizeof(pi));

    NTSTATUS re = pNtQueryInformationProcess(hProcess, ProcessBasicInformation, &pi, sizeof(pi), NULL);

    if (!NT_SUCCESS(re))
    {
        return "";
    }

    PEB peb;
    RTL_USER_PROCESS_PARAMETERS para;
    ReadProcessMemory(hProcess, pi.PebBaseAddress, &peb, sizeof(PEB), NULL);
    ReadProcessMemory(hProcess, peb.ProcessParameters, &para, sizeof(para), NULL);
    TCHAR CommandLine[1024];
    ReadProcessMemory(hProcess, para.CommandLine.Buffer, CommandLine, 1024 * 2, NULL);

    return (char*)(CW2A)(::CString)CommandLine;
}

BOOL Process_GetDebugPrivilege(LPCWSTR lPcstr, DWORD* backCode)
{
    HANDLE Token = NULL;
    LUID luid = { 0 };
    TOKEN_PRIVILEGES Token_privileges = { 0 };
    //内存初始化为zero
    memset(&luid, 0x00, sizeof(luid));
    memset(&Token_privileges, 0x00, sizeof(Token_privileges));

    //打开进程令牌
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &Token))
    {
        *backCode = 0x01;
        return FALSE;
    }

    //获取特权luid
    if (!LookupPrivilegeValue(NULL, lPcstr, &luid))
    {
        *backCode = 0x02;
        return FALSE;
    }

    //设定结构体luid与特权
    Token_privileges.PrivilegeCount = 1;
    Token_privileges.Privileges[0].Luid = luid;
    Token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    //修改进程特权
    if (!AdjustTokenPrivileges(Token, FALSE, &Token_privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        *backCode = 0x03;
        return FALSE;
    }
    *backCode = 0x00;
    return TRUE;
}

// 获取进程路径
string Process_GetProcessPath(HANDLE hProcess)
{
    char processPath[MAX_PATH + 4];
    ZeroMemory(processPath, MAX_PATH + 4);
    if (hProcess)
    {
        DWORD pathSize = sizeof(processPath) / sizeof(char);
        QueryFullProcessImageNameA(hProcess, 0, processPath, &pathSize);
    }

    return processPath;
}

bool Process_WaitForProcessPebInitialized(HANDLE hProcess, DWORD timeoutMs) {
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return false;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    auto NtQueryInformationProcess = (typeNtQueryInformationProcess)
        GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return false;

    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < timeoutMs) {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength = 0;

        NTSTATUS status = NtQueryInformationProcess(hProcess,
            ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);

        if (status == 0 && pbi.PebBaseAddress) {
            PEB peb = { 0 };
            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(hProcess, pbi.PebBaseAddress,
                &peb, sizeof(peb), &bytesRead) && bytesRead == sizeof(peb)) {

                if (peb.Ldr) {
                    PEB_LDR_DATA ldr = { 0 };
                    if (ReadProcessMemory(hProcess, peb.Ldr,
                        &ldr, sizeof(ldr), &bytesRead) && bytesRead == sizeof(ldr)) {

                        if (ldr.InMemoryOrderModuleList.Flink &&
                            ldr.InMemoryOrderModuleList.Flink != ldr.InMemoryOrderModuleList.Blink) {
                            return true;
                        }
                    }
                }
            }
        }

        Sleep(50);
    }

    return false;
}



// Encrypt Function

// SHA-256 计算模块

inline uint32_t Encrypt_RightRotate(uint32_t x, int n)
{
    return (x >> n) | (x << (32 - n));
}

void Encrypt_ProcessBlock(const unsigned char* block, uint32_t* h)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
    {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++)
    {
        uint32_t s0 = Encrypt_RightRotate(w[i - 15], 7) ^ Encrypt_RightRotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Encrypt_RightRotate(w[i - 2], 17) ^ Encrypt_RightRotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];

    for (int i = 0; i < 64; i++)
    {
        uint32_t S1 = Encrypt_RightRotate(e, 6) ^ Encrypt_RightRotate(e, 11) ^ Encrypt_RightRotate(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h_val + S1 + ch + K[i] + w[i];
        uint32_t S0 = Encrypt_RightRotate(a, 2) ^ Encrypt_RightRotate(a, 13) ^ Encrypt_RightRotate(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h_val = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
}

// 计算文件sha256
string Encrypt_CalculateFileSHA256(string filePath){
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                     0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    FILE* file = fopen(filePath.c_str(), "rb");
    if (!file) return "";

    unsigned char buffer[64];
    size_t bytesRead;
    uint64_t totalBytes = 0;

    while ((bytesRead = fread(buffer, 1, 64, file)) == 64)
    {
        Encrypt_ProcessBlock(buffer, h);
        totalBytes += 64;
    }
    totalBytes += bytesRead;

    unsigned char lastBlock[128] = { 0 };
    if (bytesRead > 0) memcpy(lastBlock, buffer, bytesRead);

    uint64_t bitLength = totalBytes * 8;
    size_t rem = bytesRead;

    if (rem < 56)
    {
        lastBlock[rem] = 0x80;
        memset(lastBlock + rem + 1, 0, 55 - rem);
        for (int i = 0; i < 8; i++)
            lastBlock[56 + i] = (bitLength >> (56 - i * 8)) & 0xFF;
        Encrypt_ProcessBlock(lastBlock, h);
    }
    else
    {
        lastBlock[rem] = 0x80;
        memset(lastBlock + rem + 1, 0, 63 - rem);
        Encrypt_ProcessBlock(lastBlock, h);
        memset(lastBlock, 0, 56);
        for (int i = 0; i < 8; i++)
            lastBlock[56 + i] = (bitLength >> (56 - i * 8)) & 0xFF;
        Encrypt_ProcessBlock(lastBlock, h);
    }

    fclose(file);

    stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint32_t val : h) ss << std::setw(8) << val;
    return ss.str();
}

int Encrypt_OrgEncrptFile(string sPath, string asPath, string sKey)
{
    FILE* f = fopen(sPath.c_str(), "rb");
    FILE* fw = nullptr;
    if (f) fw = fopen(asPath.c_str(), "wb");

    if (f == NULL || fw == NULL)
    {
        ::CString ErrorInfomation;
        int Er = GetLastError();
        ErrorInfomation.Format(L"删除病毒原文件出错。\n错误码: %d\n处理文件: ", Er);
        ErrorInfomation += sPath.c_str();
        Log_AddLogSimple("文件[ " + QString::fromLocal8Bit(sPath) + " ] 删除病毒原文件出错，错误码：[ " + QString::fromLocal8Bit(to_string(Er)) + " ]", LOG_ERROR);
        if (f) fclose(f);
        if (fw) fclose(fw);
        return -1;
    }

    const int buffer_size = 1024;
    int read_size = 0;
    char buffer[1024 + 1] = { 0 };

    int i;
    size_t keyLen = sKey.length();  // 缓存密钥长度

    memset(buffer, 0, buffer_size + 1);
    while ((read_size = static_cast<int>(fread(buffer, sizeof(char), buffer_size, f))) > 0)
    {
        for (i = 0; i < read_size; i++)
        {
            buffer[i] ^= sKey[i % keyLen];  // 使用缓存的长度
        }
        fwrite(buffer, sizeof(char), read_size, fw);
    }
    fclose(f);
    fclose(fw);

    DWORD attributes = FILE_ATTRIBUTE_NORMAL;
    if (!SetFileAttributesA(sPath.c_str(), attributes))
    {
        ::CString ErrorInfomation;
        int Er = GetLastError();
        ErrorInfomation.Format(L"设置文件属性失败。\n错误码: %d\n处理文件: ", Er);
        ErrorInfomation += sPath.c_str();
        Log_AddLogSimple("文件[ " + QString::fromLocal8Bit(sPath) + " ] 设置文件属性失败，错误码：[ " + QString::fromLocal8Bit(to_string(Er)) + " ]", LOG_ERROR);
        return -1;
    }

    if (!DeleteFileA(sPath.c_str()))
    {
        ::CString ErrorInfomation;
        int Er = GetLastError();
        ErrorInfomation.Format(L"删除病毒原文件出错。\n错误码: %d\n处理文件: ", Er);
        ErrorInfomation += sPath.c_str();
        Log_AddLogSimple("文件[ " + QString::fromLocal8Bit(sPath) + " ] 删除病毒原文件出错，错误码：[ " + QString::fromLocal8Bit(to_string(Er)) + " ]", LOG_ERROR);
    }
    else
    {
        // mlog.LogWrite(Good, "文件[ " + sPath + " ] 删除病毒原文件完成");
    }

    return 0;
}

DWORD Encrypt_DecrptFileT(LPVOID lpParam)
{
    wstring* pwsPath = (wstring*)lpParam;
    if (pwsPath == NULL) return -1;

    wstring wsPath = *pwsPath;
    delete pwsPath;

    string sourcePath = (string)(CW2A)wsPath.c_str();
    if (sourcePath.length() < 4) return -1;

    string destPath = (string)(CW2A)wsPath.substr(0, wsPath.length() - 4).c_str();

    Encrypt_OrgEncrptFile(sourcePath, destPath, ENCRPT_XOR_PASSWORD);

    return 0;
}

DWORD Encrypt_EncrptFileT(LPVOID lpParam)
{
    wstring* pwsPath = (wstring*)lpParam;
    if (pwsPath == NULL) return -1;

    wstring wsPath = *pwsPath;
    delete pwsPath;

    string sourcePath = (string)(CW2A)wsPath.c_str();
    string destPath = sourcePath + ".iot";

    Encrypt_OrgEncrptFile(sourcePath, destPath, ENCRPT_XOR_PASSWORD);

    return 0;
}

// 加密
void Encrypt_EncrptFile(wstring sPath)
{
    wstring* swPath = new wstring;
    if (swPath == NULL) return;

    *swPath = sPath;

    HANDLE hThread = CreateThread(0, 0, Encrypt_EncrptFileT, swPath, 0, 0);
    if (hThread == NULL) {
        // 线程创建失败，清理资源
        delete swPath;

        ::CString ErrorInfomation;
        ErrorInfomation.Format(L"创建加密线程失败。\n处理文件: ");
        ErrorInfomation += sPath.c_str();
        Log_AddLogSimple("文件[ " + QString::fromLocal8Bit((string)(CW2A)sPath.c_str()) + " ] 创建加密线程失败", LOG_ERROR);
        return;
    }

    // 关闭线程句柄，让线程独立运行
    CloseHandle(hThread);
}

// 解密
void Encrypt_DecrptFile(wstring sPath){
    wstring* swPath = new wstring;
    *swPath = sPath;

    CreateThread(0, 0, Encrypt_DecrptFileT, swPath, 0, 0);
}

// Yara
// 文件类型枚举
enum Yara_FileType {
    YAFILE_TYPE_UNKNOWN = 0,
    YAFILE_TYPE_PE,      // PE文件
    YAFILE_TYPE_ARCHIVE  // 压缩文件
};

// 回调函数
int Yara_ScanFileCallBack(YR_SCAN_CONTEXT* context, int message, void* data, void* user) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* result = (std::string*)user;
        YR_RULE* rule = (YR_RULE*)data;

        // 已找到结果，跳过
        if (!result->empty()) {
            return CALLBACK_CONTINUE;
        }

        // 获取文件类型（从user_data高位传入）
        int file_type = (int)(uintptr_t)user & 0xFF;

        // 提取description
        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (meta->type == META_TYPE_STRING &&
                strcmp(meta->identifier, "description") == 0 &&
                meta->string) {

                std::string desc = meta->string;

                // PE签名验证
                if (file_type == YAFILE_TYPE_PE &&
                    desc.find("SIGNATURE_TYPE_PEHSTR_EXT") != std::string::npos) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }

                // 压缩文件签名验证
                if (file_type == YAFILE_TYPE_ARCHIVE &&
                    desc.find("SIGNATURE_TYPE_ARHSTR_EXT") != std::string::npos) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }

                // 无签名类型，直接命中
                if (desc.find("SIGNATURE_TYPE_") == std::string::npos) {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }

                break;
            }
            else if (meta->type == META_TYPE_STRING &&
                strcmp(meta->identifier, "filetype") == 0 &&
                meta->string) {
                std::string desc = meta->string;
                if (strcmp(desc.c_str(), "memory") != 0)
                {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
            }
            else if (meta->type == META_TYPE_STRING &&
                strcmp(meta->identifier, "rule_usage") == 0 &&
                meta->string) {
                std::string desc = meta->string;
                if (strcmp(desc.c_str(), "memory scan") != 0)
                {
                    *result = "Yara/" + std::string(rule->identifier);
                    return CALLBACK_ABORT;
                }
            }
        }
    }

    return CALLBACK_CONTINUE;
}

// 扫描函数
bool Yara_ScanFile(const std::string& path, std::string& virus_name) {
    if (!Yara_IsReady) {
        virus_name = "Empty";
        return false;
    }

    // 判断文件类型
    int file_type = FILE_TYPE_UNKNOWN;
    if (File_IsPEFile((wchar_t*)((wstring)CString(path.c_str())).c_str())) {
        file_type = YAFILE_TYPE_PE;
    }
    else if (File_IsArchive(path)) {
        file_type = YAFILE_TYPE_ARCHIVE;
    }

    // 文件类型作为user_data传入
    void* user_data = (void*)(uintptr_t)file_type;
    std::string result;

    int ret = yr_rules_scan_file(Yara_Rules, path.c_str(),
        SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING,
        Yara_ScanFileCallBack, &result, 2000);

    if (ret == ERROR_SUCCESS && !result.empty()) {
        virus_name = result;
        return true;
    }

    virus_name = "Empty";
    return false;
}

// 回调函数
int Yara_ScanMemCallBack(YR_SCAN_CONTEXT* context, int message, void* data, void* user) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        auto* result = (std::string*)user;
        YR_RULE* rule = (YR_RULE*)data;

        // 已找到结果，跳过
        if (!result->empty()) {
            return CALLBACK_CONTINUE;
        }

        // 直接命中规则
        *result = "YaraMemory/" + std::string(rule->identifier);
        return CALLBACK_ABORT;
    }

    return CALLBACK_CONTINUE;
}

// 读取进程内存的辅助函数
std::vector<BYTE> ReadProcessMemoryRegion(HANDLE hProcess, LPCVOID baseAddress, SIZE_T size) {
    std::vector<BYTE> buffer(size);
    SIZE_T bytesRead = 0;

    if (ReadProcessMemory(hProcess, baseAddress, buffer.data(), size, &bytesRead) && bytesRead > 0) {
        buffer.resize(bytesRead);
        return buffer;
    }

    return std::vector<BYTE>();
}

// 进程内存扫描函数
bool Yara_ScanMemory(HANDLE hProcess, std::string& virus_name) {
    if (!Yara_MemIsReady) {
        virus_name = "Empty";
        return false;
    }

    // 检查Yara引擎开关是否开启
    if (pVirusScanPage && pVirusScanPage->pYaraEngineSwitch &&
        !pVirusScanPage->pYaraEngineSwitch->getIsToggled()) {
        virus_name = "Empty";
        return false;
    }

    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        virus_name = "Empty";
        return false;
    }

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    LPCVOID address = sysInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    std::string result;

    // 遍历进程内存空间
    while (address < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            // 只扫描已提交且可读的内存
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {

                // 限制单次读取大小（避免读取过大内存）
                SIZE_T readSize = qMin(mbi.RegionSize, (SIZE_T)1024 * 1024); // 最多读1MB

                std::vector<BYTE> buffer = ReadProcessMemoryRegion(hProcess, mbi.BaseAddress, readSize);

                if (!buffer.empty()) {
                    // 扫描当前内存块
                    int ret = yr_rules_scan_mem(Yara_MemRules,
                        buffer.data(),
                        buffer.size(),
                        SCAN_FLAGS_FAST_MODE | SCAN_FLAGS_REPORT_RULES_MATCHING,
                        Yara_ScanMemCallBack,
                        &result,
                        1000);  // 每个内存块超时1秒

                    if (ret == ERROR_SUCCESS && !result.empty()) {
                        virus_name = result;
                        return true;
                    }
                }
            }

            // 移动到下一个内存区域
            address = (LPCVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        }
        else {
            break;
        }
    }

    virus_name = "Empty";
    return false;
}


// ScanFunction

static bool EndsWith(const std::string& str, const std::string& suffix)
{
    if (suffix.size() > str.size()) return false;
    return std::equal(suffix.rbegin(), suffix.rend(), str.rbegin());
}

string Scan_GeneralScan(string FilePath, string thisSha256)
{
    string VirusName;
    int isVir = FALSE;
    bool isSuspiciousNeedHEUR = false;

    // 如果运行时白名单缓存中存在，直接视为无毒
    string lowerSha256 = thisSha256;
    std::transform(lowerSha256.begin(), lowerSha256.end(), lowerSha256.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (WhiteSha256ListCache.find(lowerSha256) != WhiteSha256ListCache.end()) {
        return "Empty";
    }

    // 缓存 wstring 转换，避免后续重复构造
    wstring wFilePath = (wstring)(CString)FilePath.c_str();

    if (File_VerifySystemFile(wFilePath)) // 系统文件不杀
    {
        return "Empty";
    }

    // 缓存引擎开关状态，避免多次重复查询
    bool sha256EngineOn = pVirusScanPage->pSHA256EngineSwitch->getIsToggled();
    bool peEngineOn = pVirusScanPage->pPEEngineSwitch->getIsToggled();
    bool yaraEngineOn = pVirusScanPage->pYaraEngineSwitch->getIsToggled();
    bool clamavEngineOn = pVirusScanPage->pClamAVEngineSwitch->getIsToggled();
    bool scriptEngineOn = pVirusScanPage->pScriptEngineSwitch ? pVirusScanPage->pScriptEngineSwitch->getIsToggled() : true;

    if (sha256EngineOn && Sha256Black_IsReady)
    {
        for (int i = 0; i < Sha256Count; i++)
        {
            if (CompareWithoutCap(VirusSha256List[i], thisSha256))
            {
                VirusName = VirusNameList[i];
                isVir = true;
                break; // 找到即跳出，避免无意义遍历
            }
        }
    }

    bool isPEFile = File_IsPEFile((wchar_t*)wFilePath.c_str());

    // Extension whitelist: only feed actual script files to BatchScan
    // and ScriptSandbox to avoid crashes / false positives on binary
    // files (.dmp, .obj, .dll, .dll.iot, etc.) that can be hundreds of MB.
    static const std::vector<std::string> s_scriptBatchExts = {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".js", ".jse",
        ".hta", ".wsf", ".scf", ".lnk", ".vbe", ".ps1xml", ".psc1", ".cdxml"
    };
    bool isBatchScriptExt = false;
    {
        std::string lowerPath = FilePath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        for (const auto& ext : s_scriptBatchExts) {
            if (EndsWith(lowerPath, ext)) {
                isBatchScriptExt = true;
                break;
            }
        }
    }

    if (!isPEFile && !isVir && peEngineOn && isBatchScriptExt)
    {
        ScriptDetectionEngine engine;

        RiskReport Report = engine.scanFile(FilePath.c_str());

        if (Report.isMalicious) {
            VirusName = Report.family;
            isVir = true;
		}
    }

    if (!isVir && scriptEngineOn && isBatchScriptExt)
    {
        string sbClass = Scan_ScriptSandbox(FilePath);
        if (sbClass != "BSD/Clean" && !sbClass.empty())
        {
            VirusName = sbClass;
            isVir = true;
        }
    }

    if (!isVir && yaraEngineOn && Yara_IsReady)
    {
        string sVirus;

        if (Yara_ScanFile(FilePath, sVirus))
        {
            if (IsExceptYaraRule(sVirus))
            {
                isSuspiciousNeedHEUR = true;
            }
            else if (strcmp(sVirus.c_str(), "Empty") != 0)
            {
                VirusName = sVirus;
                isVir = true;
            }
        }
    }

    if (!isVir && ClamAV_IsReady && clamavEngineOn)
    {
        char* pVirName = nullptr;
        unsigned long nPos = 0;
        int ret = pcl_scanfile(FilePath.c_str(), (const char**)&pVirName, &nPos, mClamAVEngine, &mClamOptions);

        if (ret == CL_VIRUS)
        {
            VirusName = "ClamAV/" + (string)pVirName;
            if (VirusName != "ClamAV/Win.Virus.Expiro-10015928-0") isVir = true; // 排除误报
        }
    }

    if (!isVir && PE_IsReady && peEngineOn && isPEFile)
    {
        PEFileAnalyzer analyzer32(FilePath);

        if (analyzer32.isValid())
        {
            // 直接提取600维特征
            RawSample sample;
            sample.base_features = analyzer32.extractFeatures();
            sample.imports = analyzer32.getImportedFunctionsRef();

            double confid = 0.0;
            if (mPEModel.Predict(sample, confid, pVirusScanPage->pExtraPEEngineSwitch->getIsToggled())) {

                confid = confid * 2.0 - 1.0;

                confid *= 100;

                if (File_CheckFileSignature(wFilePath))
                {
                    confid -= 15;
                }
                else
                {
                    if (analyzer32.isSigValid() == false)
                    {
                        // 有签名数据但签名无效/过期，额外加分（伪造签名的强信号）
                        confid += 8;
                        if (pVirusScanPage->pHighSensitiveSwitch->getIsToggled())
                        {
                            return "Sign/Trojan.Unsigned.Generic (HIGH SENSITIVE MODEL)";
                        }
                    }
                    else
                    {
                        if (pVirusScanPage->pHighSensitiveSwitch->getIsToggled())
                        {
                            return "Sign/Trojan.Unsigned.Generic (HIGH SENSITIVE MODEL)";
                        }
                        confid += 5;
                    }
                }

                BOOL TimeMark = FALSE, SizeMark = TRUE, IconMark = TRUE;
                const wchar_t* wPath = wFilePath.c_str();

                SizeMark = File_IsFileSizeNormal((wchar_t*)wPath);
                TimeMark = File_IsModifiedOverOneDay((wchar_t*)wPath);
                IconMark = File_HasIconResource((wchar_t*)wPath);

                if (!SizeMark) confid += 0.8; else confid -= 2.3;
                if (TimeMark) confid += 1.7; else confid -= 2.3;
                if (!IconMark) confid += 2; else confid -= 2.3;

                if (isSuspiciousNeedHEUR) confid += 5; // Yara可疑结果加分

                confid += pProtectionSettingPage->pHeurSensitivity->getCurrentData().toInt();

                if (confid > 100) confid = 100;
                else if (confid < -100) confid = -100;

                if (confid > 57) {
                    HeuristicRulesEngine engine;
                    VirusClassResult cls = engine.classifyByAnalyzer(analyzer32);

                    if (confid > 67) {
                        if (cls.category == "Trojan" && cls.variant == "Generic") {
                            std::ostringstream newFamily;
                            newFamily << "ML/Malware.Generic!" << fixed << setprecision(0) << confid;
                            cls.family = newFamily.str();
                            cls.confidence = confid;
                        }

                        isVir = true;
                        VirusName = cls.family;
                    }
                    else
                    {
                        if (cls.category == "Trojan" && cls.variant == "Generic") {
                            std::ostringstream newFamily;
                            newFamily << "ML/Suspicious.Generic!" << fixed << setprecision(0) << confid;
                            cls.family = newFamily.str();
                            cls.confidence = confid;
                        }

                        isVir = true;
                        VirusName = cls.family;
                    }
                }
                else {
                    isVir = false;
                }
            }
        }
    }

    if (isVir) return VirusName;
    else return "Empty";
}

// 新增：基于行为链的脚本沙盒检测
std::string Scan_ScriptSandbox(const std::string& filePath)
{
    // Extension whitelist: only analyze actual script files to avoid false
    // positives from binary files (.dmp, .obj, .dll, etc.) that happen to
    // contain byte patterns matching script detection rules.
    static const std::vector<std::string> scriptExts = {
        ".js", ".vbs", ".hta", ".ps1", ".psm1", ".psd1", ".wsf", ".scf",
        ".jsl", ".jse", ".vbe", ".ps1xml", ".psc1", ".cdxml"
    };
    std::string lowPath = filePath;
    std::transform(lowPath.begin(), lowPath.end(), lowPath.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    bool isScript = false;
    for (const auto& ext : scriptExts) {
        if (lowPath.size() >= ext.size() &&
            lowPath.substr(lowPath.size() - ext.size()) == ext) {
            isScript = true;
            break;
        }
    }
    if (!isScript)
        return "BSD/Clean";

    // File size protection: skip files > 20MB to avoid OOM / heap corruption
    QFileInfo fi(QString::fromLocal8Bit(filePath.c_str()));
    if (fi.size() > 20 * 1024 * 1024)
        return "BSD/Clean";

    QFile file(QString::fromLocal8Bit(filePath.c_str()));
    if (!file.open(QIODevice::ReadOnly))
        return "BSD/Clean";

    QByteArray data = file.readAll();
    std::string script(data.constData(), data.size());
    if (script.empty())
        return "BSD/Clean";

    ScriptSandbox::Sandbox sandbox;
    ScriptSandbox::DetectionResult result = sandbox.AnalyzeFile(filePath);

    if (result.malicious && !result.family.empty() && result.family != "Clean")
        return result.family;

    return "BSD/Clean";
}

// General Function

string ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)
{
    wstring ws = lpwszStrIn;
    _bstr_t t = ws.c_str();
    char* pt = _strdup(t);
    string s = pt;
    free(pt);   // _strdup 使用 malloc 分配，必须用 free 释放
    return s;
}

// 脚本静态检测：仅依赖后缀名，不依赖启发引擎开关
std::string Scan_ScriptBatch(const std::string& filePath)
{
    static const std::vector<std::string> scriptExts = {
        ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe",
        ".js", ".jse", ".hta", ".wsf", ".scf", ".lnk", ".ps1xml", ".psc1", ".cdxml"
    };
    std::string lowPath = filePath;
    std::transform(lowPath.begin(), lowPath.end(), lowPath.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    bool isScript = false;
    for (const auto& ext : scriptExts) {
        if (lowPath.size() >= ext.size() &&
            lowPath.substr(lowPath.size() - ext.size()) == ext) {
            isScript = true;
            break;
        }
    }
    if (!isScript) return "Empty";

    ScriptDetectionEngine engine;
    RiskReport Report = engine.scanFile(filePath.c_str());
    if (Report.isMalicious) return Report.family;
    return "Empty";
}

bool CompareWithoutCap(const string& str1, const string& str2)
{
    if (str1.size() != str2.size())
        return false;

    for (size_t i = 0; i < str1.size(); ++i)
    {
        if (::tolower(static_cast<unsigned char>(str1[i])) !=
            ::tolower(static_cast<unsigned char>(str2[i])))
            return false;
    }
    return true;
}

// type: 1:right，2:warn，3:error，4:info, 5:勒索
// title: 自定义标题，为空时按类型使用默认标题
void NewMessageBox(const QString& text, int type, int sDuring, const QString& title)
{
    if (QThread::currentThread() != QApplication::instance()->thread()) {
        QMetaObject::invokeMethod(QApplication::instance(), [text, type, sDuring, title]() {
            MyShowMessageBox(text, type, sDuring, title);
            }, Qt::QueuedConnection);
    }
    else {
        MyShowMessageBox(text, type, sDuring, title);
    }
}

bool IsWindows11()
{
    OSVERSIONINFOEX osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
    osvi.dwMajorVersion = 10; // Windows 10 和 Windows 11 的主版本号都是 10
    osvi.dwMinorVersion = 0;   // 次版本号为 0
    osvi.dwBuildNumber = 22000; // Windows 11 的构建号从 22000 开始

    DWORDLONG dwlConditionMask = 0;
    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_BUILDNUMBER, VER_GREATER_EQUAL);

    if (VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER, dwlConditionMask))
    {
        return true;
    }
    else
    {
        return false;
    }
}

string GenerateUniqueEventName(DWORD pid)
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    char eventName[MAX_PATH];
    sprintf(eventName, "Global\\TianHongSafety$S3bjewd4ni_%d_%04d%02d%02d_%02d%02d%02d_%03d_%04d",
        pid,
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond,
        st.wMilliseconds,
        rand() % 10000);

    return eventName;
}

string GenerateFileName()
{
    // 30个勒索诱捕关键词
    const QStringList baitWords = {
        "Data", "Backup", "Database", "Document", "File",
        "Record", "Archive", "BackupData", "Important", "Critical",
        "Confidential", "Secret", "Finance", "Account", "Personal",
        "Project", "Report", "Analysis", "Budget", "Contract",
        "Client", "Customer", "Employee", "Salary", "Tax",
        "Invoice", "Receipt", "Transaction", "Payment", "Financial"
    };

    const QString charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    // 随机选择诱捕词
    int wordIndex = QRandomGenerator::global()->bounded(baitWords.size());
    QString filename = baitWords[wordIndex];

    // 计算需要添加的随机字符长度（总长度8-14）
    int totalLength = QRandomGenerator::global()->bounded(8, 15);
    int randomCharsNeeded = totalLength - filename.length();

    if (randomCharsNeeded <= 0) {
        return filename.toStdString();
    }

    // 添加随机字符
    for (int i = 0; i < randomCharsNeeded; ++i)
    {
        int index = QRandomGenerator::global()->bounded(charset.length());
        filename.append(charset.at(index));
    }

    return filename.toStdString();
}

bool IsExceptYaraRule(std::string name)
{
    for (int i = 0; i < sizeof(HeurExceptYaraRuleName); i++)
    {
        if (HeurExceptYaraRuleName[i] == name)
        {
            return true;
        }
    }
    return false;
}

// 单个条目的控件结构
struct InfoBar::EntryWidget : public QFrame
{
    QLabel* iconLabel;
    QLabel* titleLabel;        // 黑体病毒名称
    QLabel* pathLabel;         // 灰体文件路径
    QLabel* timeLabel;
    QWidget* button;           // ElaToolButton* / QPushButton*
    QDateTime timestamp;
    std::function<void()> buttonCallback;
    const int m_id;
    InfoBar::Type m_type;

    EntryWidget(const QString& title,           // 病毒名称
        const QString& filePath,        // 文件路径
        InfoBar::Type type,
        bool showButton,
        const QString& buttonText,
        std::function<void()> callback,
        ElaMenu* dropdownMenu,
        int id,
        QWidget* parent = nullptr)
        : QFrame(parent)
        , button(nullptr)
        , timestamp(QDateTime::currentDateTime())
        , buttonCallback(std::move(callback))
        , m_id(id)
        , m_type(type)
    {
        // 基础样式
        setObjectName("InfoBarEntry");
        setStyleSheet(R"(
            #InfoBarEntry {
                background: transparent;
                border-radius: 4px;
                padding: 8px 12px;
            }
            #InfoBarEntry:hover {
                background: #FAFAFA;
            }
        )");

        // ========== 左侧图标 ==========
        iconLabel = new QLabel;
        iconLabel->setFixedSize(32, 32);  // 卡巴斯基风格稍大的图标
        iconLabel->setScaledContents(true);

        // 根据不同 type 设置图标
        QStyle::StandardPixmap pixmap;
        switch (type) {
        case InfoBar::Info:
            pixmap = QStyle::SP_MessageBoxInformation;
            break;
        case InfoBar::Warning:
            pixmap = QStyle::SP_MessageBoxWarning;
            break;
        case InfoBar::Error:
            pixmap = QStyle::SP_MessageBoxCritical;
            break;
        default:
            pixmap = QStyle::SP_MessageBoxInformation;
            break;
        }
        QIcon icon = qApp->style()->standardIcon(pixmap);
        iconLabel->setPixmap(icon.pixmap(32, 32));

        // ========== 中间文本区域（垂直布局）==========
        QWidget* textWidget = new QWidget;
        QVBoxLayout* textLayout = new QVBoxLayout(textWidget);
        textLayout->setContentsMargins(0, 0, 0, 0);
        textLayout->setSpacing(2);

        // 黑体病毒名称
        titleLabel = new QLabel(title);
        titleLabel->setStyleSheet("QLabel { color: #303030; font-weight: bold; font-size: 10pt; }");
        titleLabel->setWordWrap(true);
        {
            QSizePolicy sp(QSizePolicy::Ignored, QSizePolicy::Preferred);
            sp.setHeightForWidth(true);
            titleLabel->setSizePolicy(sp);
        }
        textLayout->addWidget(titleLabel);

        // 灰体文件路径（只有非空时才显示）
        pathLabel = new QLabel(filePath);
        pathLabel->setStyleSheet("QLabel { color: #909090; font-size: 9pt; }");
        pathLabel->setWordWrap(true);
        {
            QSizePolicy sp(QSizePolicy::Ignored, QSizePolicy::Preferred);
            sp.setHeightForWidth(true);
            pathLabel->setSizePolicy(sp);
        }

        if (filePath.isEmpty()) {
            pathLabel->hide();  // 隐藏空的路径标签
        }
        textLayout->addWidget(pathLabel);

        {
            QSizePolicy sp(QSizePolicy::Expanding, QSizePolicy::Preferred);
            sp.setHeightForWidth(true);
            textWidget->setSizePolicy(sp);
        }

        // ========== 主布局 ==========
        QHBoxLayout* mainLayout = new QHBoxLayout(this);
        mainLayout->setContentsMargins(0, 0, 0, 0);
        mainLayout->setSpacing(10);

        // EntryWidget 启用 heightForWidth，使容器布局能根据宽度自动调整高度
        {
            QSizePolicy sp = sizePolicy();
            sp.setHeightForWidth(true);
            setSizePolicy(sp);
        }

        mainLayout->addWidget(iconLabel, 0, Qt::AlignTop);  // 图标靠上对齐
        mainLayout->addWidget(textWidget, 1);  // 文本区域占剩余空间，高度自适应

        // 根据 type 计算文字按钮配色
        QString textColor, borderColor, hoverBg, pressedBg;
        switch (type) {
        case InfoBar::Warning:
            textColor = "#E67E22";
            borderColor = "#F0B27A";
            hoverBg = "#FEF5E7";
            pressedBg = "#FAD7A0";
            break;
        case InfoBar::Error:
            textColor = "#E74C3C";
            borderColor = "#F1948A";
            hoverBg = "#FDEDEC";
            pressedBg = "#F5B7B1";
            break;
        default:
            textColor = "#3498DB";
            borderColor = "#85C1E9";
            hoverBg = "#EBF5FB";
            pressedBg = "#AED6F1";
            break;
        }

        // ========== 按钮区域 ==========
        if (showButton) {
            if (dropdownMenu) {
                ElaToolButton* elaBtn = new ElaToolButton(parent);
                elaBtn->setFixedHeight(30);
                elaBtn->setIsTransparent(false);
                elaBtn->setText(buttonText);
                elaBtn->setMenu(dropdownMenu);
                elaBtn->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);

                QObject::connect(elaBtn, &ElaToolButton::clicked, [this]() {
                    if (buttonCallback) buttonCallback();
                });

                button = elaBtn;
                mainLayout->addWidget(button, 0, Qt::AlignTop);
            }
            else {
                // 文字类型按钮：无图标，点击跳转
                QPushButton* textBtn = new QPushButton(buttonText, parent);
                textBtn->setFixedHeight(30);
                textBtn->setCursor(Qt::PointingHandCursor);
                textBtn->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
                textBtn->setStyleSheet(QString(R"(
                    QPushButton {
                        background-color: transparent;
                        color: %1;
                        border: 1px solid %2;
                        border-radius: 6px;
                        padding: 0 12px;
                        font-weight: 600;
                    }
                    QPushButton:hover {
                        background-color: %3;
                    }
                    QPushButton:pressed {
                        background-color: %4;
                    }
                )").arg(textColor, borderColor, hoverBg, pressedBg));

                QObject::connect(textBtn, &QPushButton::clicked, [this]() {
                    if (buttonCallback) buttonCallback();
                });

                button = textBtn;
                mainLayout->addWidget(button, 0, Qt::AlignTop);
            }
        }

        // ========== 右侧时间 ==========
        timeLabel = new QLabel(formatTimeSince(timestamp));
        timeLabel->setStyleSheet("QLabel { color: #909090; font-size: 8pt; }");
        timeLabel->setAlignment(Qt::AlignRight | Qt::AlignTop);
        timeLabel->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Fixed);
        mainLayout->addWidget(timeLabel, 0, Qt::AlignTop);  // 时间靠上对齐，避免长文本时被遮蔽
    }

    void updateTimeText() {
        timeLabel->setText(formatTimeSince(timestamp));
    }

    static QString formatTimeSince(const QDateTime& timestamp) {
        qint64 secs = timestamp.secsTo(QDateTime::currentDateTime());
        if (secs < 60)
            return QObject::tr("刚刚");
        if (secs < 3600)
            return QObject::tr("%1分钟前").arg(secs / 60);
        if (secs < 86400)
            return QObject::tr("%1小时前").arg(secs / 3600);
        if (secs < 2592000)
            return QObject::tr("%1天前").arg(secs / 86400);
        return timestamp.toString("yyyy-MM-dd");
    }
};

// ========== 格式化时间差（保持不变）==========
QString InfoBar::formatTimeSince(const QDateTime& timestamp)
{
    qint64 secs = timestamp.secsTo(QDateTime::currentDateTime());
    if (secs < 60)
        return QObject::tr("刚刚");
    if (secs < 3600)
        return QObject::tr("%1分钟前").arg(secs / 60);
    if (secs < 86400)
        return QObject::tr("%1小时前").arg(secs / 3600);
    if (secs < 2592000) // 30天
        return QObject::tr("%1天前").arg(secs / 86400);
    return timestamp.toString("yyyy-MM-dd");
}

// ========== 构造函数 ==========
InfoBar::InfoBar(QWidget* parent) : QWidget(parent)
{
    setMinimumWidth(500);
    setMinimumHeight(200);

    setAutoFillBackground(true);
    setStyleSheet(R"(
        InfoBar {
            background-color: #F5F5F5;
            border: 1px solid #E0E0E0;
            border-radius: 6px;
        }
    )");

    QVBoxLayout* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // ========== 滚动区域 ==========
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scrollArea->setFrameShape(QFrame::NoFrame);
    scrollArea->setStyleSheet(R"(
        QScrollArea {
            background: transparent;
            border: none;
        }
        QScrollArea > QWidget > QWidget {
            background: transparent;
        }
        QScrollBar:vertical {
            width: 6px;
            background: transparent;
        }
        QScrollBar::handle:vertical {
            background: #CCCCCC;
            border-radius: 3px;
            min-height: 20px;
        }
        QScrollBar::handle:vertical:hover {
            background: #AAAAAA;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: transparent;
        }
    )");

    // 条目容器
    QWidget* container = new QWidget;
    container->setObjectName("InfoBarContainer");
    container->setStyleSheet("#InfoBarContainer { background: transparent; }");
    m_layout = new QVBoxLayout(container);
    m_layout->setContentsMargins(4, 4, 4, 4);
    m_layout->setSpacing(2);
    m_layout->setAlignment(Qt::AlignTop);

    scrollArea->setWidget(container);
    outerLayout->addWidget(scrollArea);

    // 时间刷新定时器
    m_timeRefreshTimer = new QTimer(this);
    connect(m_timeRefreshTimer, &QTimer::timeout, this, &InfoBar::refreshTimes);
    m_timeRefreshTimer->start(10000);
}

// ========== 析构函数（保持不变）==========
InfoBar::~InfoBar()
{
    clearEntries();
}

// ========== 添加条目 ==========
int InfoBar::addEntry(const QString& title,           // 病毒名称
    const QString& filePath,       // 文件路径
    Type type,
    bool showButton,
    const QString& buttonText,
    std::function<void()> callback,
    ElaMenu* dropdownMenu,
    int autoRemoveSeconds)
{
    int newId = m_nextId++;
    auto* entry = new EntryWidget(title, filePath, type, showButton, buttonText,
        std::move(callback), dropdownMenu, newId, this);
    m_entries.append(entry);
    m_layout->addWidget(entry);

    // 应用当前主题
    applyThemeToEntry(entry);

    // 自动删除
    if (autoRemoveSeconds > 0) {
        QTimer* timer = new QTimer(this);
        timer->setSingleShot(true);
        int removeId = newId;
        connect(timer, &QTimer::timeout, this, [this, removeId]() {
            removeEntryById(removeId);
            });
        timer->start(autoRemoveSeconds * 1000);
    }

    Q_EMIT entryCountChanged(m_entries.size());
    return newId;
}

// ========== 清空条目 ==========
void InfoBar::clearEntries()
{
    for (EntryWidget* entry : m_entries) {
        m_layout->removeWidget(entry);
        delete entry;
    }
    m_entries.clear();
    Q_EMIT entryCountChanged(0);
}

// ========== 移除指定条目 ==========
bool InfoBar::removeEntryById(int id)
{
    for (int i = 0; i < m_entries.size(); ++i) {
        if (m_entries[i]->m_id == id) {
            EntryWidget* entry = m_entries.takeAt(i);
            m_layout->removeWidget(entry);
            delete entry;
            Q_EMIT entryCountChanged(m_entries.size());
            return true;
        }
    }
    return false;
}

// ========== 按文件路径移除条目 ==========
void InfoBar::removeEntriesByPath(const QString& filePath)
{
    if (filePath.isEmpty())
        return;
    for (int i = m_entries.size() - 1; i >= 0; --i) {
        if (m_entries[i]->pathLabel->text() == filePath) {
            EntryWidget* entry = m_entries.takeAt(i);
            m_layout->removeWidget(entry);
            delete entry;
        }
    }
    Q_EMIT entryCountChanged(m_entries.size());
}

// ========== 当前条目数 ==========
int InfoBar::entryCount() const
{
    return m_entries.size();
}

// ========== 刷新时间 ==========
void InfoBar::refreshTimes()
{
    for (EntryWidget* entry : m_entries) {
        entry->updateTimeText();
    }
}

// ========== 更新样式 ==========
void InfoBar::updateStyle()
{
    QScrollArea* scrollArea = findChild<QScrollArea*>();

    if (m_isDark) {
        // ========== 深色主题 ==========
        setStyleSheet(R"(
            InfoBar {
                background-color: #1E1E1E;
                border: 1px solid #333333;
                border-radius: 6px;
            }
        )");

        if (scrollArea) {
            scrollArea->setStyleSheet(R"(
                QScrollArea {
                    background: transparent;
                    border: none;
                }
                QScrollArea > QWidget > QWidget {
                    background: transparent;
                }
                QScrollBar:vertical {
                    width: 6px;
                    background: transparent;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #555555;
                    border-radius: 3px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #777777;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    height: 0px;
                }
                QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                    background: transparent;
                }
            )");
        }
    }
    else {
        // ========== 浅色主题 ==========
        setStyleSheet(R"(
            InfoBar {
                background-color: #F5F5F5;
                border: 1px solid #E0E0E0;
                border-radius: 6px;
            }
        )");

        if (scrollArea) {
            scrollArea->setStyleSheet(R"(
                QScrollArea {
                    background: transparent;
                    border: none;
                }
                QScrollArea > QWidget > QWidget {
                    background: transparent;
                }
                QScrollBar:vertical {
                    width: 6px;
                    background: transparent;
                    margin: 0px;
                }
                QScrollBar::handle:vertical {
                    background: #CCCCCC;
                    border-radius: 3px;
                    min-height: 20px;
                }
                QScrollBar::handle:vertical:hover {
                    background: #AAAAAA;
                }
                QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                    height: 0px;
                }
                QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                    background: transparent;
                }
            )");
        }
    }

    // 更新所有条目的主题
    for (EntryWidget* entry : m_entries) {
        applyThemeToEntry(entry);
    }
}

// ========== 设置主题模式 ==========
void InfoBar::setThemeMode(bool isDark)
{
    m_isDark = isDark;
    updateStyle();
}

// ========== 应用主题到条目 ==========
void InfoBar::applyThemeToEntry(EntryWidget* entry)
{
    if (m_isDark) {
        // 深色主题
        entry->setStyleSheet(R"(
            #InfoBarEntry {
                background: transparent;
                border-radius: 4px;
                padding: 8px 12px;
            }
            #InfoBarEntry:hover {
                background: #2A2A2A;
            }
        )");
        // 黑体标题 - 白色
        entry->titleLabel->setStyleSheet(
            "QLabel { color: #E0E0E0; font-weight: bold; font-size: 10pt; }"
        );
        // 灰体路径 - 浅灰色
        entry->pathLabel->setStyleSheet(
            "QLabel { color: #909090; font-size: 9pt; }"
        );
    }
    else {
        // 浅色主题
        entry->setStyleSheet(R"(
            #InfoBarEntry {
                background: transparent;
                border-radius: 4px;
                padding: 8px 12px;
            }
            #InfoBarEntry:hover {
                background: #FAFAFA;
            }
        )");
        // 黑体标题 - 深色
        entry->titleLabel->setStyleSheet(
            "QLabel { color: #303030; font-weight: bold; font-size: 10pt; }"
        );
        // 灰体路径 - 灰色
        entry->pathLabel->setStyleSheet(
            "QLabel { color: #909090; font-size: 9pt; }"
        );
    }

    // 时间标签样式（深浅主题通用）
    entry->timeLabel->setStyleSheet(
        "QLabel { color: #909090; font-size: 8pt; }"
    );

    // 文字跳转按钮随主题更新
    QPushButton* textBtn = qobject_cast<QPushButton*>(entry->button);
    if (textBtn) {
        auto getButtonColors = [](InfoBar::Type type, bool isDark) -> std::tuple<QString, QString, QString, QString> {
            QString textColor, borderColor, hoverBg, pressedBg;
            switch (type) {
            case InfoBar::Warning:
                textColor = isDark ? "#F5B041" : "#E67E22";
                borderColor = isDark ? "#B7791F" : "#F0B27A";
                hoverBg = isDark ? "#4A3B1A" : "#FEF5E7";
                pressedBg = isDark ? "#5C4A1F" : "#FAD7A0";
                break;
            case InfoBar::Error:
                textColor = isDark ? "#EC7063" : "#E74C3C";
                borderColor = isDark ? "#A93226" : "#F1948A";
                hoverBg = isDark ? "#4A1A1A" : "#FDEDEC";
                pressedBg = isDark ? "#5C1F1F" : "#F5B7B1";
                break;
            default:
                textColor = isDark ? "#5DADE2" : "#3498DB";
                borderColor = isDark ? "#2471A3" : "#85C1E9";
                hoverBg = isDark ? "#1A3A4A" : "#EBF5FB";
                pressedBg = isDark ? "#1F4A5C" : "#AED6F1";
                break;
            }
            return { textColor, borderColor, hoverBg, pressedBg };
        };

        auto [textColor, borderColor, hoverBg, pressedBg] = getButtonColors(entry->m_type, m_isDark);
        textBtn->setStyleSheet(QString(R"(
            QPushButton {
                background-color: transparent;
                color: %1;
                border: 1px solid %2;
                border-radius: 6px;
                padding: 0 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: %3;
            }
            QPushButton:pressed {
                background-color: %4;
            }
        )").arg(textColor, borderColor, hoverBg, pressedBg));
    }
}

// 日志等级前缀文本
static const char* g_LogLevelPrefix[] = { "[INFO]", "[SUCCESS]", "[WARN]", "[ERROR]" };

// 日志等级对应颜色（浅色主题）
static const char* g_LogLevelColorLight[] = { "#1565C0", "#2E7D32", "#E65100", "#C62828" };
// 日志等级对应颜色（深色主题）
static const char* g_LogLevelColorDark[] = { "#64B5F6", "#81C784", "#FFB74D", "#EF9A9A" };

// 日志等级对应现代化图标（ElaAwesome 字体图标）
static const ElaIconType::IconName g_LogLevelIcon[] = {
    ElaIconType::CircleInfo,           // INFO
    ElaIconType::CircleCheck,          // SUCCESS
    ElaIconType::CircleExclamation,    // WARN
    ElaIconType::TriangleExclamation   // ERROR
};

// ==================== 磁盘日志缓存（回滚参考旧数据）====================
// 在主程序同目录下缓存历史日志，上限 300MB，超出时清除最旧数据。
// 回滚确认时从缓存检索当前 PID 的历史日志，辅助用户决策。
#define BEHAVIOR_CACHE_MAX_BYTES  300LL * 1024LL * 1024LL   // 300MB 上限
#define BEHAVIOR_CACHE_TRIM_BYTES 200LL * 1024LL * 1024LL   // 超限后保留最近 200MB
#define BEHAVIOR_CACHE_FILE       L"behavior_cache.log"

// 返回缓存文件完整路径（主程序同目录）
static QString BehaviorCacheFilePath()
{
    QString dir = QString::fromWCharArray(g_wszMainExeDir);
    if (dir.isEmpty())
        return QString();
    return dir + QString::fromWCharArray(BEHAVIOR_CACHE_FILE);
}

// 缓存文件超限时，保留最近 TRIM_BYTES 字节（删除最旧部分）
static void BehaviorCacheTrimIfNeeded()
{
    QString path = BehaviorCacheFilePath();
    if (path.isEmpty()) return;

    QFileInfo fi(path);
    if (!fi.exists() || fi.size() <= BEHAVIOR_CACHE_MAX_BYTES)
        return;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return;

    qint64 total = f.size();
    qint64 keep = BEHAVIOR_CACHE_TRIM_BYTES;
    if (keep >= total) { f.close(); return; }

    // 从文件尾部保留下，跳过一个可能的半行，保证从完整行开始
    qint64 keepStart = total - keep;
    f.seek(keepStart);
    // 丢弃第一个不完整的行：若当前位置不是行首，向后读到下一个换行符
    {
        char c = 0;
        if (f.read(&c, 1) == 1 && c != '\n') {
            while (f.read(&c, 1) == 1 && c != '\n') { }
        }
    }

    QByteArray tailData = f.readAll();
    f.close();

    QFile fo(path);
    if (fo.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        fo.write(tailData);
        fo.close();
    }
}

// 追加一行日志到磁盘缓存（带时间戳）
static void BehaviorCacheAppend(const QString& line)
{
    if (line.isEmpty()) return;
    QString path = BehaviorCacheFilePath();
    if (path.isEmpty()) return;

    QFile f(path);
    if (!f.open(QIODevice::Append | QIODevice::WriteOnly))
        return;

    QByteArray data = line.toUtf8();
    data.append('\n');
    f.write(data);
    f.close();

    // 若超限则立即裁剪（低频操作，仅在超限时发生）
    BehaviorCacheTrimIfNeeded();
}

// 从磁盘缓存中检索指定 PID 相关的历史日志行（回滚时参考旧数据）
// 返回最近最多 maxLines 条匹配行；同时通过 total 输出该 PID 的全部匹配条数
static QStringList BehaviorCacheQueryPid(qint64 pid, int maxLines, int* total = NULL)
{
    QStringList result;
    if (total) *total = 0;
    QString path = BehaviorCacheFilePath();
    if (path.isEmpty() || pid <= 0 || maxLines <= 0)
        return result;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return result;

    QString pidStr = QString("PID=%1").arg(pid);
    QStringList matched;
    while (!f.atEnd()) {
        QByteArray line = f.readLine();
        QString s = QString::fromUtf8(line).trimmed();
        if (s.contains(pidStr, Qt::CaseInsensitive))
            matched.append(s);
    }
    f.close();

    if (total) *total = matched.size();

    // 返回最近的 maxLines 条
    int start = matched.size() - maxLines;
    if (start < 0) start = 0;
    for (int i = start; i < matched.size(); i++)
        result.append(matched[i]);
    return result;
}

// 判断日志是否属于注册表防护或文件防护（磁盘缓存仅保存这两类，供回滚参考）
// Provider 规范：R0 为 Kernel.RegistryProtection / Kernel.FileProtection，
//                R3 为 User.RegistryProtection / User.FileProtection
static bool BehaviorCacheIsRegOrFile(const QString& Provider)
{
    QString p = Provider.trimmed().toLower();
    if (p.isEmpty())
        return false;
    return p.contains("registry") || p.contains("file");
}

// ==================== 回滚记录磁盘持久化（结构化）====================
// 驱动 g_baDroppedFiles / g_baRegOps 环形缓冲区溢出时上报的 BA_ROLLBACK_LOG_RECORD，
// 主程序以 "RB;..." 前缀行落盘（与文本日志混合在同一缓存文件，300MB 上限）。
// 回滚时结合驱动当前 BA_ROLLBACK_LIST 与磁盘中的回滚记录一起执行。
#define ROLLBACK_LINE_PREFIX    "RB;"

// 追加一条回滚记录到磁盘缓存（结构化，供回滚时检索）
void BehaviorCacheAppendRollbackRecord(const BA_ROLLBACK_LOG_RECORD& rec)
{
    QString line;
    line += QString("%1%2;%3;%4;%5;%6;%7;%8;%9;")
        .arg(ROLLBACK_LINE_PREFIX)
        .arg(rec.type)
        .arg((qint64)rec.pid)
        .arg(QString::fromLatin1(rec.path))
        .arg(QString::fromLatin1(rec.valueName))
        .arg(rec.regOp)
        .arg(rec.hadExisting)
        .arg(rec.originalType)
        .arg(rec.originalDataLen);
    // 原始值备份以十六进制追加，避免二进制与文本日志冲突
    DWORD dl = rec.originalDataLen;
    if (dl > BA_RBLOG_BACKUP_LEN) dl = BA_RBLOG_BACKUP_LEN;
    for (DWORD i = 0; i < dl; i++)
        line += QString("%1").arg((unsigned char)rec.originalData[i], 2, 16, QLatin1Char('0'));
    BehaviorCacheAppend(line);
}

// 从磁盘缓存检索指定 PID 的回滚记录（结构化），返回最近最多 maxRecords 条
static QVector<BA_ROLLBACK_LOG_RECORD> BehaviorCacheQueryRollbackRecords(qint64 pid, int maxRecords)
{
    QVector<BA_ROLLBACK_LOG_RECORD> out;
    QVector<BA_ROLLBACK_LOG_RECORD> matched;
    QString path = BehaviorCacheFilePath();
    if (path.isEmpty() || pid <= 0 || maxRecords <= 0)
        return out;

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        return out;

    while (!f.atEnd()) {
        QByteArray raw = f.readLine();
        if (!raw.startsWith(ROLLBACK_LINE_PREFIX))
            continue;
        QString line = QString::fromLatin1(raw).trimmed();
        QStringList parts = line.split(';');
        if (parts.size() < 9)
            continue;

        BA_ROLLBACK_LOG_RECORD rec;
        memset(&rec, 0, sizeof(rec));
        rec.type = (UINT8)parts[1].toUInt();
        qint64 recPid = parts[2].toLongLong();
        if (recPid != pid)
            continue;
        rec.pid = recPid;

        QByteArray pb = parts[3].toLatin1();
        memcpy(rec.path, pb.constData(), qMin(pb.size(), BA_RBLOG_PATH_LEN - 1));
        QByteArray vb = parts[4].toLatin1();
        memcpy(rec.valueName, vb.constData(), qMin(vb.size(), BA_RBLOG_VALUE_NAME_LEN - 1));
        rec.regOp = (UINT8)parts[5].toUInt();
        rec.hadExisting = (UINT8)parts[6].toUInt();
        rec.originalType = parts[7].toUInt();
        DWORD dl = parts[8].toUInt();
        if (dl > BA_RBLOG_BACKUP_LEN) dl = BA_RBLOG_BACKUP_LEN;
        rec.originalDataLen = dl;
        if (parts.size() > 9) {
            QByteArray hex = parts[9].toLatin1();
            for (DWORD i = 0; i < dl && (i * 2 + 1) < (DWORD)hex.size(); i++)
                rec.originalData[i] = (UINT8)hex.mid(i * 2, 2).toUInt(nullptr, 16);
        }
        matched.append(rec);
    }
    f.close();

    int start = matched.size() - maxRecords;
    if (start < 0) start = 0;
    for (int i = start; i < matched.size(); i++)
        out.append(matched[i]);
    return out;
}

// 通用日志写入核心：摘要 + 详情 + 等级 + 提供者
static void Log_AddLogCore(QString Summary, QString Detail, LogLevel level, QString Provider)
{
    if (!pLoggerPage || !pLoggerPage->LogModel)
        return;

    QString cTime;
    time_t timep;
    struct tm* tim;
    time(&timep);
    tim = localtime(&timep);

    cTime = QString("[%1.%2.%3:%4°%5''%6]")
        .arg(1900 + tim->tm_year).arg(1 + tim->tm_mon).arg(tim->tm_mday)
        .arg(tim->tm_hour).arg(tim->tm_min).arg(tim->tm_sec);

    // 磁盘缓存：仅落盘注册表/文件防护日志（时间戳 + 摘要 + 提供者 + 详情）
    if (BehaviorCacheIsRegOrFile(Provider))
    {
        QString cacheLine = cTime + " " + Summary;
        if (!Provider.isEmpty())
            cacheLine += " [提供者:" + Provider + "]";
        if (!Detail.isEmpty())
            cacheLine += " | " + Detail;
        BehaviorCacheAppend(cacheLine);
    }

    /* 列表只显示摘要（无 [INFO] 等级前缀），等级信息通过图标颜色体现。
     * 详情存入 UserRole 供右侧面板展示。 */
    QStandardItem* newItem = new QStandardItem(Summary);
    newItem->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

    /* 设置等级图标：使用 ElaAwesome 现代化图标，颜色与等级一致 */
    bool isDark = (eTheme->getThemeMode() == ElaThemeType::Dark);
    QColor levelColor(isDark ? g_LogLevelColorDark[level] : g_LogLevelColorLight[level]);
    QIcon levelIcon = ElaIcon::getInstance()->getElaIcon(g_LogLevelIcon[level], 32, levelColor);
    newItem->setIcon(levelIcon);

    /* 完整详情 = 时间戳 + 提供者 + 摘要 + 详细内容（不再包含 [INFO] 等等级前缀，
     * 等级信息已通过详情面板顶部的等级名标签与图标颜色体现） */
    QString fullDetail = cTime + " " + Summary;
    if (!Provider.isEmpty())
        fullDetail += "\n提供者：" + Provider;
    if (!Detail.isEmpty())
        fullDetail += "\n" + Detail;

    newItem->setData(fullDetail, Qt::UserRole);
    newItem->setData((int)level, Qt::UserRole + 1);
    newItem->setData(QDateTime::currentMSecsSinceEpoch(), Qt::UserRole + 2);

    /* 根据日志等级设置文字颜色 */
    newItem->setForeground(QBrush(levelColor));

    pLoggerPage->LogModel->appendRow(newItem);
}

// LogType: 0 - 一般日志，1 - +日志，2 - -日志
inline void Log_AddLog(string LogContent, int LogType )
{
    /* 旧接口兼容：LogType 2=错误，其他=INFO */
    LogLevel level = (LogType == 2) ? LOG_ERROR : LOG_INFO;
    Log_AddLogCore(QString::fromStdString(LogContent.c_str()), QString(), level, QString());
}

// LogType: 0 - 一般日志，1 - +日志，2 - -日志
inline void Log_AddLogUni(QString LogContent, int LogType)
{
    /* 旧接口兼容：LogType 2=错误，其他=INFO */
    LogLevel level = (LogType == 2) ? LOG_ERROR : LOG_INFO;
    Log_AddLogCore(LogContent, QString(), level, QString());
}

// 新接口：带日志等级 + 摘要 + 详情 + 提供者
void Log_AddLogEx(QString Summary, QString Detail, LogLevel level, QString Provider)
{
    Log_AddLogCore(Summary, Detail, level, Provider);
}

// 新接口：带日志等级 + 提供者，仅摘要
void Log_AddLogSimple(QString Summary, LogLevel level, QString Provider)
{
    Log_AddLogCore(Summary, QString(), level, Provider);
}

// ==================== 用户态回滚执行（磁盘记录部分）====================
// 驱动当前 BA_ROLLBACK_LIST 由驱动侧 BehaviorExecuteRollbackSelected 执行；
// 磁盘缓存中的溢出回滚记录驱动已不再持有，由主程序在此执行。
// 文件：设备路径 -> DOS 路径后删除；注册表：内核路径 -> Win 根键后恢复原值。
struct RollbackOp {
    int type;              // 0=file, 1=registry
    qint64 pid;
    QString path;          // 文件路径 或 注册表键路径
    QString valueName;     // 注册表值名（文件为空）
    int regOp;             // 0=SetValue, 1=DeleteValue
    bool hadExisting;
    DWORD originalType;
    QByteArray originalData;
    bool fromDriver;       // true=驱动当前 list；false=磁盘记录（主程序执行）
};

// 设备路径 -> DOS 路径（\\Device\\HarddiskVolume3\\... -> C:\\...）
static bool DevicePathToDosPath(const QString& devicePath, QString& dosPath)
{
    for (wchar_t drv = L'A'; drv <= L'Z'; drv++) {
        wchar_t root[8];
        swprintf_s(root, 8, L"%c:", drv);
        wchar_t target[512];
        DWORD len = QueryDosDeviceW(root, target, 512);
        if (len == 0)
            continue;
        QString dev = QString::fromWCharArray(target);
        if (devicePath.startsWith(dev, Qt::CaseInsensitive)) {
            dosPath = QString(QChar(drv)) + ":" + devicePath.mid(dev.length());
            return true;
        }
    }
    return false;
}

// 内核注册表路径 -> Win 根键 + 相对子键（\\REGISTRY\\MACHINE\\... -> HKLM + ...）
static bool KernelRegPathToWin(const QString& kernelPath, HKEY* outRoot, QString& subKey)
{
    QString p = kernelPath;
    QString lower = p.toLower();
    if (lower.startsWith("\\registry\\machine")) {
        *outRoot = HKEY_LOCAL_MACHINE;
        subKey = p.mid(QString("\\REGISTRY\\MACHINE").length());
        return true;
    }
    if (lower.startsWith("\\registry\\user")) {
        *outRoot = HKEY_USERS;
        subKey = p.mid(QString("\\REGISTRY\\USER").length());
        return true;
    }
    return false;
}

// 执行磁盘回滚记录（带进度条 + 失败统计），返回失败条目描述（空串表示全部成功）
static QString ExecuteDiskRollback(const QVector<RollbackOp>& ops, QWidget* parent)
{
    QStringList failures;
    int total = ops.size();
    if (total == 0)
        return QString();

    QProgressDialog progress(parent);
    progress.setWindowTitle(QString::fromUtf8("回滚"));
    progress.setLabelText(QString::fromUtf8("正在回滚磁盘缓存中的历史操作..."));
    progress.setRange(0, total);
    progress.setCancelButton(nullptr);
    progress.setMinimumDuration(0);
    progress.setWindowModality(Qt::WindowModal);
    progress.show();

    for (int i = 0; i < total; i++) {
        const RollbackOp& op = ops[i];
        progress.setValue(i);
        QApplication::processEvents();

        if (op.type == 0) {
            // 文件删除
            QString dosPath;
            if (!DevicePathToDosPath(op.path, dosPath))
                dosPath = op.path;  // 可能已是 DOS 路径
            if (DeleteFileW((LPCWSTR)dosPath.utf16())) {
                // 成功
            } else {
                DWORD err = GetLastError();
                if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                    ;  // 文件已不存在，视为成功
                else
                    failures.append(QString::fromUtf8("文件删除失败: %1 (err=%2)").arg(dosPath).arg(err));
            }
        } else {
            // 注册表恢复
            HKEY hRoot = NULL;
            QString subKey;
            if (KernelRegPathToWin(op.path, &hRoot, subKey)) {
                HKEY hKey = NULL;
                LONG r = RegOpenKeyExW(hRoot, (LPCWSTR)subKey.utf16(), 0, KEY_SET_VALUE, &hKey);
                if (r == ERROR_SUCCESS) {
                    LPCWSTR valName = op.valueName.isEmpty() ? NULL : (LPCWSTR)op.valueName.utf16();
                    if (op.regOp == 0) {  // SetValue
                        if (op.hadExisting && op.originalData.size() > 0)
                            r = RegSetValueExW(hKey, valName, 0, op.originalType,
                                (const BYTE*)op.originalData.constData(), op.originalData.size());
                        else
                            r = RegDeleteValueW(hKey, valName);
                    } else if (op.regOp == 1) {  // DeleteValue
                        if (op.hadExisting && op.originalData.size() > 0)
                            r = RegSetValueExW(hKey, valName, 0, op.originalType,
                                (const BYTE*)op.originalData.constData(), op.originalData.size());
                        else
                            r = ERROR_SUCCESS;  // 原本无值可恢复
                    }
                    if (r != ERROR_SUCCESS)
                        failures.append(QString::fromUtf8("注册表恢复失败: %1\\%2 (err=%3)")
                            .arg(op.path).arg(op.valueName).arg(r));
                    RegCloseKey(hKey);
                } else {
                    failures.append(QString::fromUtf8("注册表打开失败: %1 (err=%2)").arg(op.path).arg(r));
                }
            } else {
                failures.append(QString::fromUtf8("注册表路径无法识别: %1").arg(op.path));
            }
        }
    }
    progress.setValue(total);
    progress.close();

    return failures.join(QString::fromUtf8("\n"));
}

// ==================== 威胁回滚确认弹窗（非阻塞 modeless）====================
void ShowRollbackConfirmPopup(
    const BA_ROLLBACK_LIST* rollbackList,
    std::function<void(const BA_ROLLBACK_SELECTION&)> callback,
    QWidget* parent)
{
    if (rollbackList == nullptr || callback == nullptr)
        return;

    ElaDialog* dlg = new ElaDialog(parent);
    dlg->setWindowTitle(QString::fromUtf8("威胁回滚确认"));
    dlg->setWindowButtonFlags(ElaAppBarType::CloseButtonHint);
    dlg->setMinimumSize(520, 420);
    dlg->setFixedSize(560, 480);
    dlg->setIsFixedSize(true);
    dlg->setAttribute(Qt::WA_DeleteOnClose, true);

    QWidget* content = new QWidget(dlg);
    QVBoxLayout* layout = new QVBoxLayout(content);
    layout->setContentsMargins(24, 18, 24, 14);
    layout->setSpacing(8);

    // ── 标题行（图标 + 标题）──
    QWidget* headerWidget = new QWidget();
    QHBoxLayout* headerLayout = new QHBoxLayout(headerWidget);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(10);

    QLabel* iconLabel = new QLabel();
    iconLabel->setObjectName("rbIcon");
    QPixmap warnIcon(28, 28);
    warnIcon.fill(Qt::transparent);
    {
        QPainter painter(&warnIcon);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.setBrush(QColor("#F39C12"));
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(2, 2, 24, 24);
        painter.setPen(QPen(Qt::white, 2.5, Qt::SolidLine, Qt::RoundCap));
        painter.drawLine(14, 8, 14, 15);
        painter.setBrush(Qt::white);
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(12, 18, 4, 4);
    }
    iconLabel->setPixmap(warnIcon);

    QString threatClassStr = QString::fromUtf8(rollbackList->threatClass);
    QString rootNameStr = QString::fromUtf8(rollbackList->rootProcessName);
    QLabel* titleLabel = new QLabel(QString::fromUtf8("检测到威胁，需要回滚"));
    titleLabel->setObjectName("rbTitle");
    titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; border: none;");

    headerLayout->addWidget(iconLabel);
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();

    // ── 信息行 ──
    QLabel* infoLabel = new QLabel(
        QString::fromUtf8("威胁类型: %1\n根进程: %2 (PID=%3)\n以下为检测到的可回滚操作，默认全选。")
            .arg(threatClassStr.isEmpty() ? QString::fromUtf8("未知") : threatClassStr)
            .arg(rootNameStr.isEmpty() ? QString::fromUtf8("未知") : rootNameStr)
            .arg((qint64)rollbackList->rootPid));
    infoLabel->setObjectName("rbInfo");
    infoLabel->setWordWrap(true);
    infoLabel->setStyleSheet("font-size: 13px; border: none;");

    // ── 回滚项列表（可滚动）──
    QScrollArea* scrollArea = new QScrollArea();
    scrollArea->setObjectName("rbScroll");
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* listWidget = new QWidget();
    QVBoxLayout* listLayout = new QVBoxLayout(listWidget);
    listLayout->setContentsMargins(0, 0, 0, 0);
    listLayout->setSpacing(4);

    // 存储 checkbox 指针用于后续读取状态
    QVector<QCheckBox*> itemCheckBoxes;
    // 合并后的回滚操作列表：先驱动当前 list，后磁盘缓存记录
    QVector<RollbackOp> ops;
    int driverCount = rollbackList->itemCount;
    if (driverCount > BA_MAX_ROLLBACK_ITEMS) driverCount = BA_MAX_ROLLBACK_ITEMS;

    // 1) 驱动当前 BA_ROLLBACK_LIST（由驱动执行）
    for (int i = 0; i < driverCount; i++)
    {
        const BA_ROLLBACK_ITEM* item = &rollbackList->items[i];
        RollbackOp op;
        op.type = item->type;
        op.pid = item->pid;
        op.path = QString::fromUtf8(item->path);
        op.valueName = QString::fromUtf8(item->valueName);
        op.regOp = item->regOp;
        op.hadExisting = (item->hadExisting != 0);
        op.originalType = 0;
        op.originalData.clear();
        op.fromDriver = true;
        ops.append(op);
    }

    // 2) 磁盘缓存回滚记录（驱动溢出上报，由主程序执行，去重）
    {
        QVector<BA_ROLLBACK_LOG_RECORD> diskRecs =
            BehaviorCacheQueryRollbackRecords((qint64)rollbackList->rootPid, 1000);
        for (const BA_ROLLBACK_LOG_RECORD& r : diskRecs)
        {
            // 与驱动 list 去重（type + path + valueName）
            bool dup = false;
            for (const RollbackOp& op : ops) {
                if (op.type == (int)r.type &&
                    op.path.compare(QString::fromLatin1(r.path), Qt::CaseInsensitive) == 0 &&
                    op.valueName.compare(QString::fromLatin1(r.valueName), Qt::CaseInsensitive) == 0) {
                    dup = true;
                    break;
                }
            }
            if (dup) continue;

            RollbackOp op;
            op.type = r.type;
            op.pid = r.pid;
            op.path = QString::fromLatin1(r.path);
            op.valueName = QString::fromLatin1(r.valueName);
            op.regOp = r.regOp;
            op.hadExisting = (r.hadExisting != 0);
            op.originalType = r.originalType;
            op.originalData = QByteArray((const char*)r.originalData, r.originalDataLen);
            op.fromDriver = false;
            ops.append(op);
        }
    }

    // 3) 生成 checkbox 列表
    for (int i = 0; i < ops.size(); i++)
    {
        const RollbackOp& op = ops[i];
        QString itemText;
        if (op.type == 0)
            itemText = QString::fromUtf8("[文件] %1").arg(op.path);
        else {
            QString opStr = (op.regOp == 0) ? QString::fromUtf8("设置值") : QString::fromUtf8("删除值");
            itemText = QString::fromUtf8("[注册表-%1] %2 \\ %3")
                .arg(opStr).arg(op.path).arg(op.valueName);
        }
        if (!op.fromDriver)
            itemText += QString::fromUtf8("（磁盘缓存）");

        QCheckBox* cb = new QCheckBox(itemText);
        cb->setChecked(true);  // 默认全选
        cb->setObjectName(QString("rbItem_%1").arg(i));
        itemCheckBoxes.append(cb);
        listLayout->addWidget(cb);
    }
    listLayout->addStretch();

    scrollArea->setWidget(listWidget);

    // ── 按钮区 ──
    QWidget* btnWidget = new QWidget();
    QHBoxLayout* btnLayout = new QHBoxLayout(btnWidget);
    btnLayout->setContentsMargins(0, 0, 0, 0);
    btnLayout->addStretch();

    ElaPushButton* btnRollback = new ElaPushButton(QString::fromUtf8("回滚"));
    btnRollback->setObjectName("btnRollback");
    btnRollback->setFixedHeight(36);
    btnRollback->setFixedWidth(120);

    ElaPushButton* btnIgnore = new ElaPushButton(QString::fromUtf8("忽略"));
    btnIgnore->setObjectName("btnIgnore");
    btnIgnore->setFixedHeight(36);
    btnIgnore->setFixedWidth(120);

    btnLayout->addWidget(btnRollback);
    btnLayout->addSpacing(10);
    btnLayout->addWidget(btnIgnore);

    layout->addWidget(headerWidget);
    layout->addWidget(infoLabel);

    // ── 历史日志参考（从磁盘缓存加载该 PID 的旧数据，辅助回滚决策）──
    {
        int totalCount = 0;
        QStringList hist = BehaviorCacheQueryPid((qint64)rollbackList->rootPid, 1000, &totalCount);
        if (!hist.isEmpty())
        {
            QLabel* histLabel = new QLabel();
            histLabel->setObjectName("rbHistory");
            histLabel->setWordWrap(true);
            histLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            QString txt = QString::fromUtf8("📋 历史行为日志（磁盘缓存）");
            if (totalCount > hist.size())
                txt += QString::fromUtf8("：共 %1 条，仅显示最近 %2 条\n").arg(totalCount).arg(hist.size());
            else
                txt += QString::fromUtf8("：共 %1 条\n").arg(totalCount);
            for (int i = 0; i < hist.size(); i++)
                txt += QString::fromUtf8("• ") + hist[i] + "\n";
            histLabel->setText(txt);
            histLabel->setContentsMargins(8, 6, 8, 6);
            layout->addWidget(histLabel);
        }
    }

    layout->addWidget(scrollArea, 1);
    layout->addWidget(btnWidget);

    QVBoxLayout* dlgLayout = new QVBoxLayout(dlg);
    dlgLayout->setContentsMargins(0, 0, 0, 0);
    dlgLayout->setSpacing(0);
    dlgLayout->addWidget(content);

    // ── 主题样式更新 ──
    auto updateStyle = [dlg]() {
        ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
        bool isDark = (themeMode == ElaThemeType::Dark);
        QString bgColor = ElaThemeColor(themeMode, WindowBase).name();
        QString textColor = isDark ? "#E5E7EB" : "#333333";
        QString descColor = isDark ? "#9CA3AF" : "#666666";
        // 回滚按钮: orange
        QString btnRollbackBg = isDark ? "#E67E22" : "#F39C12";
        QString btnRollbackHover = isDark ? "#D35400" : "#E67E22";
        // 忽略按钮: gray
        QString btnIgnoreBg = isDark ? "#374151" : "#F3F4F6";
        QString btnIgnoreText = isDark ? "#F9FAFB" : "#1F2937";
        QString btnIgnoreHover = isDark ? "#4B5563" : "#E5E7EB";
        // 复选框样式
        QString cbStyle = isDark ? "color: #E5E7EB;" : "color: #333333;";
        QString scrollBg = isDark ? "#1F2937" : "#FFFFFF";

        dlg->setStyleSheet(QString("QDialog { background: %1; border-radius: 12px; }").arg(bgColor));

        QLabel* t = dlg->findChild<QLabel*>("rbTitle");
        if (t) t->setStyleSheet(QString("font-size: 16px; font-weight: bold; color: %1; border: none;").arg(textColor));

        QLabel* d = dlg->findChild<QLabel*>("rbInfo");
        if (d) d->setStyleSheet(QString("font-size: 13px; color: %1; border: none;").arg(descColor));

        QScrollArea* sa = dlg->findChild<QScrollArea*>("rbScroll");
        if (sa) {
            sa->setStyleSheet(QString(
                "QScrollArea { background: %1; border: none; }"
                "QScrollBar:vertical { background: %1; width: 8px; }"
                "QScrollBar::handle:vertical { background: %2; border-radius: 4px; }"
                "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }")
                .arg(scrollBg)
                .arg(isDark ? "#4B5563" : "#D1D5DB"));
        }

        // 更新所有复选框样式
        QList<QCheckBox*> cbs = dlg->findChildren<QCheckBox*>();
        for (QCheckBox* cb : cbs) {
            cb->setStyleSheet(QString(
                "QCheckBox { %1 font-size: 13px; spacing: 8px; padding: 4px; border: none; }"
                "QCheckBox::indicator { width: 16px; height: 16px; border-radius: 3px; }"
                "QCheckBox::indicator:unchecked { border: 2px solid %2; background: transparent; }"
                "QCheckBox::indicator:checked { border: 2px solid #E67E22; background: #E67E22; }")
                .arg(cbStyle)
                .arg(isDark ? "#6B7280" : "#D1D5DB"));
        }

        ElaPushButton* br = dlg->findChild<ElaPushButton*>("btnRollback");
        if (br) br->setStyleSheet(QString(
            "ElaPushButton { background: %1; color: #FFFFFF; border: none; border-radius: 8px; font-size: 13px; }"
            "ElaPushButton:hover { background: %3; }").arg(btnRollbackBg).arg(btnRollbackHover).arg(btnRollbackHover));

        ElaPushButton* bi = dlg->findChild<ElaPushButton*>("btnIgnore");
        if (bi) bi->setStyleSheet(QString(
            "ElaPushButton { background: %1; color: %2; border: none; border-radius: 8px; font-size: 13px; }"
            "ElaPushButton:hover { background: %3; }").arg(btnIgnoreBg).arg(btnIgnoreText).arg(btnIgnoreHover));
    };
    updateStyle();
    QObject::connect(eTheme, &ElaTheme::themeModeChanged, dlg, [&updateStyle]() { updateStyle(); });

    // ── 按钮事件（使用 guard 防止 double-callback）──
    auto guard = std::make_shared<bool>(false);

    QObject::connect(btnRollback, &ElaPushButton::clicked, dlg, [dlg, itemCheckBoxes, ops, driverCount, callback, guard]() {
        if (*guard) return;
        *guard = true;

        // 驱动当前 list 部分：构造 selection 交由驱动执行
        BA_ROLLBACK_SELECTION sel = {0};
        sel.decision = 1;  // rollback
        sel.itemCount = driverCount;
        for (int i = 0; i < itemCheckBoxes.size() && i < BA_MAX_ROLLBACK_ITEMS; i++) {
            if (i < driverCount)
                sel.selected[i] = itemCheckBoxes[i]->isChecked() ? 1 : 0;
        }

        // 磁盘缓存记录部分：主程序执行（带进度条，失败弹窗告知）
        QVector<RollbackOp> diskOps;
        for (int i = driverCount; i < itemCheckBoxes.size(); i++) {
            if (itemCheckBoxes[i]->isChecked() && i < ops.size() && !ops[i].fromDriver)
                diskOps.append(ops[i]);
        }
        if (!diskOps.isEmpty()) {
            QString failures = ExecuteDiskRollback(diskOps, dlg);
            if (!failures.isEmpty()) {
                Log_AddLogSimple(QString::fromUtf8("磁盘缓存回滚完成但有失败: %1 项")
                    .arg(diskOps.size()), LOG_WARN);
                MyShowMessageBox(QString::fromUtf8("部分磁盘缓存回滚失败:\n%1").arg(failures),
                    NotificationPopup::Error, 8, QString::fromUtf8("回滚完成（有失败）"));
            } else {
                Log_AddLogSimple(QString::fromUtf8("磁盘缓存历史操作回滚成功: %1 项")
                    .arg(diskOps.size()), LOG_SUCCESS);
                MyShowMessageBox(QString::fromUtf8("磁盘缓存历史操作回滚成功（%1 项）").arg(diskOps.size()),
                    NotificationPopup::Success, 4, QString::fromUtf8("回滚完成"));
            }
        }

        callback(sel);
        dlg->close();
    });

    QObject::connect(btnIgnore, &ElaPushButton::clicked, dlg, [dlg, callback, guard]() {
        if (*guard) return;
        *guard = true;
        BA_ROLLBACK_SELECTION sel = {0};
        sel.decision = 0;  // ignore
        sel.itemCount = 0;
        callback(sel);
        dlg->close();
    });

    // 关闭按钮（X）：视为忽略
    QObject::connect(dlg, &ElaDialog::closeButtonClicked, dlg, [callback, guard]() {
        if (*guard) return;
        *guard = true;
        BA_ROLLBACK_SELECTION sel = {0};
        sel.decision = 0;
        callback(sel);
    });

    dlg->moveToCenter();
    dlg->show();
    dlg->raise();
    dlg->activateWindow();
    // show 之后再次应用样式，确保 eTheme 的 themeMode 已就绪
    QTimer::singleShot(50, dlg, [dlg]() {
        auto theme = eTheme;
        if (theme && dlg->isVisible()) {
            ElaThemeType::ThemeMode tm = theme->getThemeMode();
            bool isDark = (tm == ElaThemeType::Dark);
            QString bgColor = ElaThemeColor(tm, WindowBase).name();
            QString textColor = isDark ? "#E5E7EB" : "#333333";
            QString descColor = isDark ? "#9CA3AF" : "#666666";
            dlg->setStyleSheet(QString("QDialog { background: %1; border-radius: 12px; }").arg(bgColor));
            QLabel* t = dlg->findChild<QLabel*>("rbTitle");
            if (t) t->setStyleSheet(QString("font-size: 16px; font-weight: bold; color: %1; border: none;").arg(textColor));
            QLabel* d = dlg->findChild<QLabel*>("rbInfo");
            if (d) d->setStyleSheet(QString("font-size: 13px; color: %1; border: none;").arg(descColor));
        }
    });
}
