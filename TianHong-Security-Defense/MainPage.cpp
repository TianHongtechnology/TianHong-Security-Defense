#include "MainPage.h"
#include "ActiveIcon.h"
#include "ProtectionSettingPage.h"
#include "VirusScanPage.h"
#include "LoggerPage.h"

extern ProtectionSettingPage* pProtectionSettingPage;
extern VirusScanPage* pVirusScanPage;
extern LoggerPage* pLoggerPage;
extern MainWindow* pMainWindow;

MainPage::MainPage(QWidget* parent)
{
    // ============ 顶层容器 ============
    QWidget* centralWidget = new QWidget(this);
    centralWidget->setObjectName("mainPageCentral");
    QVBoxLayout* rootLayout = new QVBoxLayout(centralWidget);
    rootLayout->setContentsMargins(24, 20, 24, 24);
    rootLayout->setSpacing(20);

    // ============ 顶部状态面板 ============
    QWidget* topPanel = new QWidget(centralWidget);
    topPanel->setObjectName("mainTopPanel");
    topPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    topPanel->setMinimumHeight(200);

    QGraphicsDropShadowEffect* topShadow = new QGraphicsDropShadowEffect(topPanel);
    topShadow->setBlurRadius(30);
    topShadow->setColor(QColor(0, 0, 0, 50));
    topShadow->setOffset(0, 8);
    topPanel->setGraphicsEffect(topShadow);

    QHBoxLayout* topLayout = new QHBoxLayout(topPanel);
    topLayout->setContentsMargins(28, 24, 28, 24);
    topLayout->setSpacing(28);

    // 左侧大状态指示器
    mIndicator = new ActiveIcon::StateIndicatorWidget(topPanel);
    mIndicator->setFixedSize(150, 150);
    mIndicator->setState(ActiveIcon::IndicatorState::Right);

    // 右侧状态文字区
    QVBoxLayout* statusLayout = new QVBoxLayout();
    statusLayout->setSpacing(8);
    statusLayout->setAlignment(Qt::AlignVCenter);

    QFont titleFont("Microsoft YaHei", 20, QFont::Bold);
    ElaText* titleText = new ElaText("天宏安全防御", topPanel);
    titleText->setFont(titleFont);
    titleText->setTextPixelSize(24);

    QFont statusFont("Microsoft YaHei");
    statusFont.setPixelSize(16);
    statusFont.setWeight(QFont::DemiBold);
    mStatusText = new QLabel("正在检测防护状态...", topPanel);
    mStatusText->setFont(statusFont);

    // 状态胶囊
    mStatusBadge = new QWidget(topPanel);
    mStatusBadge->setObjectName("statusBadge");
    mStatusBadge->setFixedSize(90, 26);
    QHBoxLayout* badgeLayout = new QHBoxLayout(mStatusBadge);
    badgeLayout->setContentsMargins(6, 2, 6, 2);
    QFont badgeFont("Microsoft YaHei");
    badgeFont.setPixelSize(11);
    mStatusBadgeText = new QLabel("检查中", mStatusBadge);
    mStatusBadgeText->setFont(badgeFont);
    mStatusBadgeText->setAlignment(Qt::AlignCenter);
    badgeLayout->addWidget(mStatusBadgeText);

    QFont detailFont("Microsoft YaHei");
    detailFont.setPixelSize(12);
    mSubText = new QLabel("", topPanel);
    mSubText->setFont(detailFont);
    mSubText->setWordWrap(true);

    statusLayout->addWidget(titleText);
    statusLayout->addWidget(mStatusText);
    statusLayout->addWidget(mStatusBadge, 0, Qt::AlignLeft);
    statusLayout->addWidget(mSubText);
    statusLayout->addStretch();

    topLayout->addWidget(mIndicator, 0, Qt::AlignVCenter);
    topLayout->addLayout(statusLayout, 1);

    // ============ 底部内容区 ============
    QWidget* bottomPanel = new QWidget(centralWidget);
    bottomPanel->setObjectName("mainBottomPanel");
    bottomPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    QHBoxLayout* bottomLayout = new QHBoxLayout(bottomPanel);
    bottomLayout->setContentsMargins(0, 0, 0, 0);
    bottomLayout->setSpacing(16);

    // 左侧事件栏
    mInfoBar = new InfoBar(bottomPanel);
    mInfoBar->setMaximumHeight(260);
    mInfoBar->setMinimumWidth(300);
    mInfoBar->setMinimumHeight(180);
    mInfoBar->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // 左侧无消息占位框（不是 InfoBar 条目）
    m_infoBarPlaceholder = new QWidget(bottomPanel);
    m_infoBarPlaceholder->setObjectName("infoBarPlaceholder");
    m_infoBarPlaceholder->setMaximumHeight(260);
    m_infoBarPlaceholder->setMinimumWidth(300);
    m_infoBarPlaceholder->setMinimumHeight(180);
    m_infoBarPlaceholder->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    QVBoxLayout* placeholderLayout = new QVBoxLayout(m_infoBarPlaceholder);
    placeholderLayout->setContentsMargins(0, 0, 0, 0);
    placeholderLayout->setAlignment(Qt::AlignCenter);

    QFont placeholderFont("Microsoft YaHei");
    placeholderFont.setPixelSize(13);
    QLabel* placeholderLabel = new QLabel("当前无消息", m_infoBarPlaceholder);
    placeholderLabel->setFont(placeholderFont);
    placeholderLabel->setAlignment(Qt::AlignCenter);
    placeholderLayout->addWidget(placeholderLabel);

    // 根据 InfoBar 条目数切换显示
    connect(mInfoBar, &InfoBar::entryCountChanged, this, [this](int count) {
        bool hasItems = (count > 0);
        mInfoBar->setVisible(hasItems);
        m_infoBarPlaceholder->setVisible(!hasItems);
    });
    // 初始状态同步
    mInfoBar->setVisible(false);
    m_infoBarPlaceholder->setVisible(true);

    // 右侧快捷操作面板
    QWidget* quickPanel = new QWidget(bottomPanel);
    quickPanel->setObjectName("quickPanel");
    quickPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    quickPanel->setMinimumWidth(260);

    QGraphicsDropShadowEffect* quickShadow = new QGraphicsDropShadowEffect(quickPanel);
    quickShadow->setBlurRadius(24);
    quickShadow->setColor(QColor(0, 0, 0, 45));
    quickShadow->setOffset(0, 6);
    quickPanel->setGraphicsEffect(quickShadow);

    QVBoxLayout* quickLayout = new QVBoxLayout(quickPanel);
    quickLayout->setContentsMargins(20, 20, 20, 20);
    quickLayout->setSpacing(qApp->style()->pixelMetric(QStyle::PM_LayoutVerticalSpacing) / 2);

    QFont quickTitleFont("Microsoft YaHei");
    quickTitleFont.setPixelSize(15);
    quickTitleFont.setWeight(QFont::DemiBold);
    m_quickPanelTitle = new QLabel("快捷操作", quickPanel);
    m_quickPanelTitle->setObjectName("quickTitle");
    m_quickPanelTitle->setFont(quickTitleFont);
    quickLayout->addWidget(m_quickPanelTitle);

    struct QuickAction {
        ElaIconType::IconName icon;
        QString title;
        QString desc;
        QString pageKey;
    };
    QuickAction actions[4] = {
        { ElaIconType::MagnifyingGlassChart, "快速扫描", "立即执行快速病毒扫描", "病毒查杀" },
        { ElaIconType::Swords, "全面扫描", "深度检查系统关键区域", "病毒查杀" },
        { ElaIconType::RectangleList, "查看日志", "浏览拦截记录与事件", "日志" },
        { ElaIconType::ScrewdriverWrench, "防护设置", "自定义模块与灵敏度", "防护设置" }
    };

    for (int i = 0; i < 4; ++i) {
        QPushButton* actionBtn = new QPushButton(quickPanel);
        actionBtn->setObjectName("quickActionButton");
        actionBtn->setCursor(Qt::PointingHandCursor);
        actionBtn->setFixedHeight(64);
        actionBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

        ElaText* iconText = new ElaText(actionBtn);
        iconText->setElaIcon(actions[i].icon);
        iconText->setTextPixelSize(24);
        iconText->setFixedWidth(56);
        iconText->setAlignment(Qt::AlignCenter);

        QFont btnTitleFont("Microsoft YaHei");
        btnTitleFont.setPixelSize(13);
        btnTitleFont.setWeight(QFont::DemiBold);
        QLabel* btnTitle = new QLabel(actions[i].title, actionBtn);
        btnTitle->setFont(btnTitleFont);

        QFont btnDescFont("Microsoft YaHei");
        btnDescFont.setPixelSize(10);
        QLabel* btnDesc = new QLabel(actions[i].desc, actionBtn);
        btnDesc->setFont(btnDescFont);

        m_quickBtnTitles.append(btnTitle);
        m_quickBtnDescs.append(btnDesc);

        QVBoxLayout* btnTextLayout = new QVBoxLayout();
        btnTextLayout->setSpacing(2);
        btnTextLayout->addWidget(btnTitle);
        btnTextLayout->addWidget(btnDesc);
        btnTextLayout->addStretch();

        QHBoxLayout* btnLayout = new QHBoxLayout(actionBtn);
        btnLayout->setContentsMargins(16, 10, 16, 10);
        btnLayout->setSpacing(12);
        btnLayout->addWidget(iconText);
        btnLayout->addLayout(btnTextLayout, 1);

        // 子控件不拦截鼠标点击，确保整个按钮区域都可响应
        iconText->setAttribute(Qt::WA_TransparentForMouseEvents);
        btnTitle->setAttribute(Qt::WA_TransparentForMouseEvents);
        btnDesc->setAttribute(Qt::WA_TransparentForMouseEvents);

        connect(actionBtn, &QPushButton::clicked, this, [i]() {
            if (!pMainWindow) {
                return;
            }
            QString pageKey;
            switch (i) {
            case 0:
            case 1:
                if (pVirusScanPage) {
                    pageKey = pVirusScanPage->property("ElaPageKey").toString();
                }
                break;
            case 2:
                if (pLoggerPage) {
                    pageKey = pLoggerPage->property("ElaPageKey").toString();
                }
                break;
            case 3:
                if (pProtectionSettingPage) {
                    pageKey = pProtectionSettingPage->property("ElaPageKey").toString();
                }
                break;
            }
            if (!pageKey.isEmpty()) {
                pMainWindow->navigation(pageKey);
            }
        });

        quickLayout->addWidget(actionBtn);
    }

    quickLayout->addStretch();

    bottomLayout->addWidget(mInfoBar, 3);
    bottomLayout->addWidget(m_infoBarPlaceholder, 3);
    bottomLayout->addWidget(quickPanel, 2);

    // ============ 组装 ============
    rootLayout->addWidget(topPanel);
    rootLayout->addWidget(bottomPanel, 1);

    addCentralWidget(centralWidget);
    setWindowTitle("天宏安全防御");
    setTitleVisible(false);

    // ============ 主题样式同步 ============
    auto applyThemeStyle = [this, topPanel, quickPanel]() {
        bool isDark = (eTheme->getThemeMode() == ElaThemeType::Dark);
        mInfoBar->setThemeMode(isDark);

        // 无消息占位框样式
        if (m_infoBarPlaceholder) {
            QString placeholderStyle = isDark
                ? "QWidget#infoBarPlaceholder { background-color: #1E1E2E; border: 1px solid #2D2D44; border-radius: 18px; }"
                  "QWidget#infoBarPlaceholder QLabel { color: #94A3B8; background: transparent; }"
                : "QWidget#infoBarPlaceholder { background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 18px; }"
                  "QWidget#infoBarPlaceholder QLabel { color: #64748B; background: transparent; }";
            m_infoBarPlaceholder->setStyleSheet(placeholderStyle);
        }

        QString panelStyle = isDark
            ? "QWidget#mainTopPanel { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1E1E2E, stop:1 #252538); border: 1px solid #2D2D44; border-radius: 20px; }"
            : "QWidget#mainTopPanel { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #FFFFFF, stop:1 #F8FAFC); border: 1px solid #E2E8F0; border-radius: 20px; }";
        topPanel->setStyleSheet(panelStyle);

        QString quickStyle = isDark
            ? "QWidget#quickPanel { background-color: #1E1E2E; border: 1px solid #2D2D44; border-radius: 18px; }"
            : "QWidget#quickPanel { background-color: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 18px; }";

        QString btnStyle = isDark
            ? "QPushButton#quickActionButton { background-color: #252538; border: 1px solid #2D2D44; border-radius: 12px; text-align: left; }"
              "QPushButton#quickActionButton:hover { background-color: #2E2E48; border: 1px solid #3A3A58; }"
              "QPushButton#quickActionButton:pressed { background-color: #1A1A28; }"
            : "QPushButton#quickActionButton { background-color: #F8FAFC; border: 1px solid #E2E8F0; border-radius: 12px; text-align: left; }"
              "QPushButton#quickActionButton:hover { background-color: #F1F5F9; border: 1px solid #CBD5E1; }"
              "QPushButton#quickActionButton:pressed { background-color: #E2E8F0; }";
        quickPanel->setStyleSheet(quickStyle + btnStyle);

        // 右下角快捷操作标题/描述随主题换色
        QString quickTitleColor = isDark ? "#F1F5F9" : "#0F172A";
        QString quickDescColor = isDark ? "#94A3B8" : "#64748B";
        if (m_quickPanelTitle) {
            m_quickPanelTitle->setStyleSheet(QString("QLabel { color: %1; background: transparent; }").arg(quickTitleColor));
        }
        for (QLabel* title : m_quickBtnTitles) {
            if (title) title->setStyleSheet(QString("QLabel { color: %1; background: transparent; }").arg(quickTitleColor));
        }
        for (QLabel* desc : m_quickBtnDescs) {
            if (desc) desc->setStyleSheet(QString("QLabel { color: %1; background: transparent; }").arg(quickDescColor));
        }

        // 状态显示按当前最高优先级刷新
        recalcStatus();
    };

    connect(eTheme, &ElaTheme::themeModeChanged, this, applyThemeStyle);
    applyThemeStyle();

    // ============ 定时刷新真实开关状态 ============
    m_refreshTimer = new QTimer(this);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        this->refreshProtectionStatus();
    });
    m_refreshTimer->start(1000);

    // 开关变化时立即刷新状态（实时刷新）
    if (pProtectionSettingPage) {
        auto connectSwitch = [this](ElaToggleSwitch* sw) {
            if (sw) {
                connect(sw, &ElaToggleSwitch::toggled, this, &MainPage::refreshProtectionStatus);
            }
        };
        connectSwitch(pProtectionSettingPage->pRegistrySwitch);
        connectSwitch(pProtectionSettingPage->pFileSwitch);
        connectSwitch(pProtectionSettingPage->pProcessSwitch);
        connectSwitch(pProtectionSettingPage->pMemorySwitch);
        connectSwitch(pProtectionSettingPage->pDriverLoadSwitch);
        connectSwitch(pProtectionSettingPage->pDirectSyscallSwitch);
        connectSwitch(pProtectionSettingPage->pBehaviorDetectionSwitch);
        connectSwitch(pProtectionSettingPage->pDllProtectionSwitch);
        connectSwitch(pProtectionSettingPage->pDriverProtectionSwitch);
    }

    // 添加初始条目
    mInfoBar->addEntry("天宏安全防御已启动，主动防御正常运行", "",
        InfoBar::Info, false, "", nullptr, nullptr, 10);

    // 欢迎提示
    ElaMessageBar::success(ElaMessageBarType::BottomRight, "初始化成功",
        "天宏安全防御已启动，主动防御正常运行", 2000);
}

void MainPage::setSourceStatus(StatusSource source, StatusLevel level, const QString& message)
{
    updateSourceInternal(source, level, message);
    recalcStatus();
}

void MainPage::updateSourceInternal(StatusSource source, StatusLevel level, const QString& message)
{
    switch (source) {
    case StatusSource::ProtectionSwitches:
        m_levelProtectionSwitches = level;
        m_msgProtectionSwitches = message;
        break;
    case StatusSource::R3R0Protection:
        m_levelR3R0 = level;
        m_msgR3R0 = message;
        break;
    case StatusSource::Threat:
        m_levelThreat = level;
        m_msgThreat = message;
        break;
    case StatusSource::LoadFailure:
        m_levelLoadFailure = level;
        m_msgLoadFailure = message;
        break;
    }
}

void MainPage::recalcStatus()
{
    StatusLevel maxLevel = StatusLevel::Success;
    QString maxMessage = "全部防护已开启";
    QString detailText;

    auto consider = [&](StatusLevel level, const QString& message) {
        if (level > maxLevel) {
            maxLevel = level;
            if (!message.isEmpty()) {
                maxMessage = message;
            }
        }
    };

    consider(m_levelProtectionSwitches, m_msgProtectionSwitches);
    consider(m_levelR3R0, m_msgR3R0);
    consider(m_levelThreat, m_msgThreat);
    consider(m_levelLoadFailure, m_msgLoadFailure);

    // 根据最高优先级来源构造明细
    switch (maxLevel) {
    case StatusLevel::Success:
        detailText = "注册表 / 文件 / 进程 / 内存 / DLL注入 / 驱动加载 / R0驱动";
        break;
    case StatusLevel::Warn:
        detailText = "部分防护未开启或加载失败，建议检查设置";
        break;
    case StatusLevel::Critical:
        detailText = "检测到未处理威胁或核心防护未开启";
        break;
    case StatusLevel::Error:
        detailText = "存在严重安全问题，请立即处理";
        break;
    }

    setDisplayStatus(maxLevel, maxMessage, detailText);

    // 独立计算防护问题级别：即使存在更严重的加载失败/威胁，也要在 InfoBar 中提示可跳转的防护未开启项
    StatusLevel protectionLevel = (m_levelR3R0 > m_levelProtectionSwitches) ? m_levelR3R0 : m_levelProtectionSwitches;
    bool hasProtectionIssue = (protectionLevel > StatusLevel::Success);
    if (hasProtectionIssue) {
        QString protectionMessage = (m_levelR3R0 > m_levelProtectionSwitches) ? m_msgR3R0 : m_msgProtectionSwitches;
        updateWarningInfoBar(protectionLevel, protectionMessage);
    } else {
        updateWarningInfoBar(StatusLevel::Success, QString());
    }
}

void MainPage::setDisplayStatus(StatusLevel level, const QString& message, const QString& detail)
{
    bool isDark = (eTheme->getThemeMode() == ElaThemeType::Dark);

    mStatusText->setText(message);
    mSubText->setText(detail);

    switch (level) {
    case StatusLevel::Success:
        mStatusText->setStyleSheet(isDark ? "color: #69F0AE;" : "color: #2E7D32;");
        mSubText->setStyleSheet(isDark ? "color: #94A3B8;" : "color: #64748B;");
        mIndicator->setState(ActiveIcon::IndicatorState::Right);
        mStatusBadgeText->setText("受保护");
        {
            QString badgeStyle = isDark
                ? "QWidget#statusBadge { background-color: #1B3A2B; border-radius: 13px; border: 1px solid #2E7D52; }"
                : "QWidget#statusBadge { background-color: #E8F5E9; border-radius: 13px; border: 1px solid #A5D6A7; }";
            mStatusBadge->setStyleSheet(badgeStyle);
        }
        mStatusBadgeText->setStyleSheet(isDark ? "color: #69F0AE;" : "color: #2E7D32;");
        break;

    case StatusLevel::Warn:
        mStatusText->setStyleSheet(isDark ? "color: #FFB74D;" : "color: #E65100;");
        mSubText->setStyleSheet(isDark ? "color: #94A3B8;" : "color: #64748B;");
        mIndicator->setState(ActiveIcon::IndicatorState::Warn);
        mStatusBadgeText->setText("有提醒");
        {
            QString badgeStyle = isDark
                ? "QWidget#statusBadge { background-color: #3E2A0F; border-radius: 13px; border: 1px solid #B7791F; }"
                : "QWidget#statusBadge { background-color: #FFF3E0; border-radius: 13px; border: 1px solid #FFCC80; }";
            mStatusBadge->setStyleSheet(badgeStyle);
        }
        mStatusBadgeText->setStyleSheet(isDark ? "color: #FFB74D;" : "color: #E65100;");
        break;

    case StatusLevel::Critical:
        mStatusText->setStyleSheet(isDark ? "color: #FF8A80;" : "color: #C62828;");
        mSubText->setStyleSheet(isDark ? "color: #94A3B8;" : "color: #64748B;");
        mIndicator->setState(ActiveIcon::IndicatorState::Critical);
        mStatusBadgeText->setText("有威胁");
        {
            QString badgeStyle = isDark
                ? "QWidget#statusBadge { background-color: #4A1515; border-radius: 13px; border: 1px solid #A53838; }"
                : "QWidget#statusBadge { background-color: #FFEBEE; border-radius: 13px; border: 1px solid #EF9A9A; }";
            mStatusBadge->setStyleSheet(badgeStyle);
        }
        mStatusBadgeText->setStyleSheet(isDark ? "color: #FF8A80;" : "color: #C62828;");
        break;

    case StatusLevel::Error:
        mStatusText->setStyleSheet(isDark ? "color: #FF5252;" : "color: #B71C1C;");
        mSubText->setStyleSheet(isDark ? "color: #94A3B8;" : "color: #64748B;");
        mIndicator->setState(ActiveIcon::IndicatorState::Error);
        mStatusBadgeText->setText("严重");
        {
            QString badgeStyle = isDark
                ? "QWidget#statusBadge { background-color: #3E1B1B; border-radius: 13px; border: 1px solid #8E3535; }"
                : "QWidget#statusBadge { background-color: #FFEBEE; border-radius: 13px; border: 1px solid #EF9A9A; }";
            mStatusBadge->setStyleSheet(badgeStyle);
        }
        mStatusBadgeText->setStyleSheet(isDark ? "color: #FF5252;" : "color: #B71C1C;");
        break;
    }
}

void MainPage::updateWarningInfoBar(StatusLevel level, const QString& message)
{
    if (m_warningInfoBarId != -1) {
        mInfoBar->removeEntryById(m_warningInfoBarId);
        m_warningInfoBarId = -1;
    }

    if (level == StatusLevel::Success) {
        return;
    }

    InfoBar::Type infoBarType = InfoBar::Type::Warning;
    if (level == StatusLevel::Critical || level == StatusLevel::Error) {
        infoBarType = InfoBar::Type::Error;
    }

    auto navigateAndScroll = [this]() {
        if (!pMainWindow || !pProtectionSettingPage) {
            return;
        }
        QString pageKey = pProtectionSettingPage->property("ElaPageKey").toString();
        if (pageKey.isEmpty()) {
            return;
        }
        pMainWindow->navigation(pageKey);

        // 延迟滚动到第一个未开启的开关项
        QTimer::singleShot(150, this, [this]() {
            if (!pProtectionSettingPage) {
                return;
            }

            ElaToggleSwitch* firstOffSwitch = nullptr;

            struct SwitchCheck {
                ElaToggleSwitch* sw;
                const char* name;
            };
            SwitchCheck checks[] = {
                { pProtectionSettingPage->pRegistrySwitch, "注册表" },
                { pProtectionSettingPage->pFileSwitch, "文件" },
                { pProtectionSettingPage->pProcessSwitch, "进程" },
                { pProtectionSettingPage->pMemorySwitch, "内存" },
                { pProtectionSettingPage->pDllProtectionSwitch, "DLL注入" },
                { pProtectionSettingPage->pDriverLoadSwitch, "驱动加载" },
                { pProtectionSettingPage->pDriverProtectionSwitch, "R0驱动" }
            };

            // 优先滚动到 R3/R0 相关项
            if (pProtectionSettingPage->pDllProtectionSwitch &&
                !pProtectionSettingPage->pDllProtectionSwitch->getIsToggled()) {
                firstOffSwitch = pProtectionSettingPage->pDllProtectionSwitch;
            }
            else if (pProtectionSettingPage->pDriverProtectionSwitch &&
                     !pProtectionSettingPage->pDriverProtectionSwitch->getIsToggled()) {
                firstOffSwitch = pProtectionSettingPage->pDriverProtectionSwitch;
            }
            else {
                for (const auto& check : checks) {
                    if (check.sw && !check.sw->getIsToggled()) {
                        firstOffSwitch = check.sw;
                        break;
                    }
                }
            }

            if (!firstOffSwitch) {
                return;
            }

            QWidget* targetArea = firstOffSwitch->parentWidget();
            if (!targetArea) {
                return;
            }

            QList<ElaScrollArea*> scrollAreas = pProtectionSettingPage->findChildren<ElaScrollArea*>();
            if (!scrollAreas.isEmpty()) {
                scrollAreas.first()->ensureWidgetVisible(targetArea);
            }
        });
    };

    m_warningInfoBarId = mInfoBar->addEntry(
        message.isEmpty() ? "部分防护未开启" : message,
        "点击右侧按钮前往防护设置开启",
        infoBarType,
        true,
        "前往开启",
        navigateAndScroll,
        nullptr,
        0);
}

void MainPage::refreshProtectionStatus()
{
    if (!pProtectionSettingPage) {
        setSourceStatus(StatusSource::ProtectionSwitches, StatusLevel::Success, "防护设置尚未加载");
        setSourceStatus(StatusSource::R3R0Protection, StatusLevel::Success, QString());
        return;
    }

    struct SwitchInfo {
        ElaToggleSwitch* sw;
        const char* name;
    };
    SwitchInfo switches[] = {
        { pProtectionSettingPage->pRegistrySwitch, "注册表" },
        { pProtectionSettingPage->pFileSwitch, "文件" },
        { pProtectionSettingPage->pProcessSwitch, "进程" },
        { pProtectionSettingPage->pMemorySwitch, "内存" },
        { pProtectionSettingPage->pDriverLoadSwitch, "驱动加载" }
    };

    int total = sizeof(switches) / sizeof(switches[0]);
    int enabled = 0;
    QStringList disabledNames;

    for (int i = 0; i < total; ++i) {
        if (switches[i].sw && switches[i].sw->getIsToggled()) {
            enabled++;
        } else {
            disabledNames.append(QString::fromUtf8(switches[i].name));
        }
    }

    if (enabled == total) {
        setSourceStatus(StatusSource::ProtectionSwitches, StatusLevel::Success, "全部防护已开启");
    } else {
        setSourceStatus(StatusSource::ProtectionSwitches, StatusLevel::Warn,
            QString("%1 项常规防护未开启").arg(total - enabled));
    }

    // R3/R0 防护：仅当两个都关闭时使用 Critical，否则不提示
    bool r3On = pProtectionSettingPage->pDllProtectionSwitch &&
                pProtectionSettingPage->pDllProtectionSwitch->getIsToggled();
    bool r0On = pProtectionSettingPage->pDriverProtectionSwitch &&
                pProtectionSettingPage->pDriverProtectionSwitch->getIsToggled();

    if (!r3On && !r0On) {
        setSourceStatus(StatusSource::R3R0Protection, StatusLevel::Critical,
            "R3 DLL 与 R0 驱动防护均未开启");
    } else {
        setSourceStatus(StatusSource::R3R0Protection, StatusLevel::Success, QString());
    }
}

MainPage::~MainPage()
{
}
