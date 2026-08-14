#include "ProtectionSettingPage.h"

void ProtectionSettingPage::CreateContentOptions(ElaToggleSwitch*& pWidget, QString Content, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType, ElaProgressRing** progressRing)
{
    pWidget = new ElaToggleSwitch(this);
    pWidget->setIsToggled(true);
    toggleSwitchArea = new ElaScrollPageArea(this);
    toggleSwitchArea->setFixedHeight(50);

    QHBoxLayout* toggleSwitchLayout = new QHBoxLayout(toggleSwitchArea);
    ElaText* toggleSwitchIcon = new ElaText(this);
    ElaText* toggleSwitchText = new ElaText(Content, this);
    toggleSwitchIcon->setElaIcon(EiType);
    toggleSwitchIcon->setFixedWidth(30);
    toggleSwitchText->setTextPixelSize(15);
    toggleSwitchText->setFixedWidth(360);
    toggleSwitchLayout->addWidget(toggleSwitchIcon);
    toggleSwitchLayout->addSpacing(10);
    toggleSwitchLayout->addWidget(toggleSwitchText);
    toggleSwitchLayout->addStretch();

    if (progressRing && *progressRing == nullptr)
    {
        *progressRing = new ElaProgressRing(this);
        (*progressRing)->setIsBusying(true);
        (*progressRing)->setIsTransparent(true);
        (*progressRing)->setFixedHeight(25);
        (*progressRing)->setFixedWidth(25);
        (*progressRing)->setBusyingWidth(3);
        (*progressRing)->setVisible(false);
        toggleSwitchLayout->addSpacing(10);
        toggleSwitchLayout->addWidget(*progressRing);
    }

    toggleSwitchLayout->addSpacing(10);
    toggleSwitchLayout->addWidget(pWidget);
}

void ProtectionSettingPage::CreateContentOptionsWithRoller(ElaRoller*& pWidget, QString Content, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType, QStringList strList)
{
    pWidget = new ElaRoller(this);
    pWidget->setItemList(strList);
    pWidget->setMaxVisibleItems(1);
    toggleSwitchArea = new ElaScrollPageArea(this);
    toggleSwitchArea->setFixedHeight(60);

    QHBoxLayout* toggleSwitchLayout = new QHBoxLayout(toggleSwitchArea);
    ElaText* toggleSwitchIcon = new ElaText(this);
    ElaText* toggleSwitchText = new ElaText(Content, this);
    toggleSwitchIcon->setElaIcon(EiType);
    toggleSwitchIcon->setFixedWidth(40);
    toggleSwitchText->setTextPixelSize(15);
    toggleSwitchText->setFixedWidth(360);
    toggleSwitchLayout->addWidget(toggleSwitchIcon);
    toggleSwitchLayout->addSpacing(10);
    toggleSwitchLayout->addWidget(toggleSwitchText);
    toggleSwitchLayout->addStretch();
    toggleSwitchLayout->addWidget(pWidget);
}


ProtectionSettingPage::ProtectionSettingPage(QWidget* parent)
{
    createCustomWidget("配置多层防护策略，平衡安全性与用户体验。");

    // 分组标题
    ElaText* Et = new ElaText;
    Et->setText("主动防护设置");
    Et->setTextPixelSize(18);

    ElaText* Et2 = new ElaText;
    Et2->setText("防护模式设置");
    Et2->setTextPixelSize(18);

    ElaText* Et3 = new ElaText;
    Et3->setText("高级防护设置");
    Et3->setTextPixelSize(18);

    ElaScrollPageArea* s1 = nullptr, * s2 = nullptr, * s3 = nullptr, * s4 = nullptr, * s5 = nullptr, * s6 = nullptr, * s7 = nullptr, * s8 = nullptr, * s9 = nullptr, * s10 = nullptr, * s11 = nullptr, * s12 = nullptr, * s13 = nullptr, * s14 = nullptr, * s15 = nullptr;
    QStringList HeurSensitivityList;

    for (int i = -11; i < 10; i++)
    {
        HeurSensitivityList.append(QString::number(i + 1));
    }

    CreateContentOptions(pRegistrySwitch, "注册表防护", s1, ElaIconType::RectangleList, nullptr);
    CreateContentOptions(pFileSwitch, "文件防护", s2, ElaIconType::FileShield, nullptr);
    CreateContentOptions(pProcessSwitch, "进程防护", s3, ElaIconType::DiagramProject, nullptr);
    CreateContentOptions(pMemorySwitch, "内存防护", s4, ElaIconType::Memory, nullptr);
    CreateContentOptions(pDriverLoadSwitch, "驱动加载防护", s5, ElaIconType::HardDrive, nullptr);
    CreateContentOptions(pDirectSyscallSwitch, "系统调用绕过防护（有限）", s11, ElaIconType::Swords, nullptr);
    CreateContentOptions(pIsUsingSafeDesktopSwitch, "拦截时进入安全桌面（伪）", s6, ElaIconType::DesktopArrowDown, nullptr);
    CreateContentOptions(pDllProtectionSwitch, "R3 DLL防护", s7, ElaIconType::FileBinary, nullptr);
    CreateContentOptions(pDriverProtectionSwitch, "R0驱动防护", s8, ElaIconType::ShieldHalved, &pDriverProtectionRing);
    CreateContentOptions(pIsFullScanSwitch, "进程启动前进行完整扫描（关闭可优化用户体验）", s9, ElaIconType::ForwardFast, nullptr);
    CreateContentOptions(pBehaviorDetectionSwitch, "行为检测", s12, ElaIconType::MagnifyingGlassChart, nullptr);
    CreateContentOptionsWithRoller(pHeurSensitivity, "启发扫描灵敏度", s10, ElaIconType::ArrowUpShortWide, HeurSensitivityList);
    pHeurSensitivity->setCurrentIndex(10); // 默认值：0
    CreateContentOptions(pSilentModeSwitch, "静默模式（自动阻止并仅显示通知）", s13, ElaIconType::BellSlash, nullptr);
    CreateContentOptions(pExtractFilesSwitch, "提取文件资源进行扫描（仅文件/文件夹扫描）", s14, ElaIconType::FolderTree, nullptr);
    CreateContentOptions(pRansomProtectionSwitch, "勒索防护（文件诱捕）", s15, ElaIconType::Bug, &pRansomProtectionRing);
    ElaScrollPageArea* s16 = nullptr;
    CreateContentOptions(pDcomProtectionSwitch, "DCOM防护", s16, ElaIconType::ShareNodes, nullptr);

    pDriverProtectionSwitch->setIsToggled(false);
    pIsUsingSafeDesktopSwitch->setIsToggled(false);
    pDirectSyscallSwitch->setIsToggled(false);
    pBehaviorDetectionSwitch->setIsToggled(false);
    pSilentModeSwitch->setIsToggled(false); // 静默模式默认关闭
    pExtractFilesSwitch->setIsToggled(false); // 提取文件资源扫描默认关闭
    pRansomProtectionSwitch->setIsToggled(true); // 勒索防护（文件诱捕）默认开启
    pDcomProtectionSwitch->setIsToggled(false); // DCOM防护默认关闭
    pIsUsingSafeDesktopSwitch->setDisabled(true); // 由于QtUI必须只有mainThread处理，setThreadDesktop将失败，无法启用安全桌面。

    // 将设置项分组装入卡片
    auto buildSectionCard = [this](QList<QWidget*> items) -> QWidget* {
        QWidget* card = new QWidget(this);
        card->setObjectName("protectionSectionCard");
        QVBoxLayout* cardLayout = new QVBoxLayout(card);
        cardLayout->setContentsMargins(12, 12, 12, 12);
        cardLayout->setSpacing(8);
        for (int i = 0; i < items.size(); ++i) {
            cardLayout->addWidget(items[i]);
        }
        return card;
    };

    QWidget* activeCard = buildSectionCard({ s1, s2, s3, s4, s5, s11, s6, s16 });
    QWidget* modeCard = buildSectionCard({ s7, s8 });
    QWidget* advancedCard = buildSectionCard({ s9, s12, s10, s13, s14, s15 });

    QWidget* centralWidget = new QWidget(this);
    centralWidget->setWindowTitle("防护设置");
    QVBoxLayout* centerLayout = new QVBoxLayout(centralWidget);
    centerLayout->setContentsMargins(0, 0, 0, 0);
    centerLayout->setSpacing(20);

    centerLayout->addWidget(Et);
    centerLayout->addSpacing(8);
    centerLayout->addWidget(activeCard);

    centerLayout->addWidget(Et2);
    centerLayout->addSpacing(8);
    centerLayout->addWidget(modeCard);

    centerLayout->addWidget(Et3);
    centerLayout->addSpacing(8);
    centerLayout->addWidget(advancedCard);

    centerLayout->addSpacing(10);
    centerLayout->addStretch();

    addCentralWidget(centralWidget, true, true, 0);

    // 主题同步
    auto applyProtectionTheme = [this, activeCard, modeCard, advancedCard]() {
        bool isDark = (eTheme->getThemeMode() == ElaThemeType::Dark);

        QString cardStyle = isDark
            ? "QWidget#protectionSectionCard { background-color: #1E1E2E; border: 1px solid #2D2D44; border-radius: 16px; }"
            : "QWidget#protectionSectionCard { background-color: #FFFFFF; border: 1px solid #E8E8EF; border-radius: 16px; }";
        activeCard->setStyleSheet(cardStyle);
        modeCard->setStyleSheet(cardStyle);
        advancedCard->setStyleSheet(cardStyle);
    };

    connect(eTheme, &ElaTheme::themeModeChanged, this, applyProtectionTheme);
    applyProtectionTheme();
}

ProtectionSettingPage::~ProtectionSettingPage()
{
}
