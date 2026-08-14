#include "WhitelistPage.h"
#include <QFileIconProvider>
#include <QFileDialog>
#include <QHeaderView>
#include <QLabel>
#include <QPainter>
#include <QScrollArea>

// 临时白名单全局缓存（sha256(小写) -> 文件路径）
extern std::unordered_map<std::string, std::string> WhiteSha256ListCache;
// 临时目录白名单全局缓存（规范化后的小写目录路径，末尾带'\'）
extern std::vector<std::string> WhiteDirListCache;
// 强化白名单全局缓存（小写文件路径，命中则该路径文件免扫）
extern std::set<std::string> WhitePathListCache;
extern CRITICAL_SECTION g_csScanCache;

// ==================== 现代化确认弹窗（参考 VirusScan AskDisableYaraForQuickScan）====================
static bool ShowModernConfirmDialog(QWidget* parent, const QString& title,
    const QString& message, const QString& confirmText, const QString& cancelText,
    bool confirmIsDanger = true)
{
    ElaDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.setWindowButtonFlags(ElaAppBarType::CloseButtonHint);
    dlg.setFixedSize(440, 280);
    dlg.setIsFixedSize(true);

    QWidget* content = new QWidget(&dlg);
    QVBoxLayout* layout = new QVBoxLayout(content);
    layout->setContentsMargins(28, 20, 28, 16);
    layout->setSpacing(10);

    // 标题行（图标 + 标题）
    QWidget* headerWidget = new QWidget();
    QHBoxLayout* headerLayout = new QHBoxLayout(headerWidget);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(10);

    QLabel* iconLabel = new QLabel();
    iconLabel->setObjectName("confirmIcon");
    QPixmap warnIcon(28, 28);
    warnIcon.fill(Qt::transparent);
    {
        QPainter painter(&warnIcon);
        painter.setRenderHint(QPainter::Antialiasing);
        QColor iconColor = confirmIsDanger ? QColor("#EF4444") : QColor("#F39C12");
        painter.setBrush(iconColor);
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(2, 2, 24, 24);
        painter.setPen(QPen(Qt::white, 2.5, Qt::SolidLine, Qt::RoundCap));
        painter.drawLine(14, 8, 14, 15);
        painter.setBrush(Qt::white);
        painter.setPen(Qt::NoPen);
        painter.drawEllipse(12, 18, 4, 4);
    }
    iconLabel->setPixmap(warnIcon);

    QLabel* titleLabel = new QLabel(title);
    titleLabel->setObjectName("confirmTitle");
    titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; border: none;");

    headerLayout->addWidget(iconLabel);
    headerLayout->addWidget(titleLabel);
    headerLayout->addStretch();

    // 说明文字
    QLabel* descLabel = new QLabel(message);
    descLabel->setObjectName("confirmDesc");
    descLabel->setWordWrap(true);
    descLabel->setStyleSheet("font-size: 13px; border: none;");

    // 按钮区
    QWidget* btnWidget = new QWidget();
    QHBoxLayout* btnLayout = new QHBoxLayout(btnWidget);
    btnLayout->setContentsMargins(0, 0, 0, 0);
    btnLayout->addStretch();

    ElaPushButton* btnConfirm = new ElaPushButton(confirmText);
    btnConfirm->setObjectName("btnConfirm");
    btnConfirm->setFixedHeight(36);
    btnConfirm->setFixedWidth(110);

    ElaPushButton* btnCancel = new ElaPushButton(cancelText);
    btnCancel->setObjectName("btnCancel");
    btnCancel->setFixedHeight(36);
    btnCancel->setFixedWidth(110);

    btnLayout->addWidget(btnConfirm);
    btnLayout->addSpacing(10);
    btnLayout->addWidget(btnCancel);

    layout->addWidget(headerWidget);
    layout->addWidget(descLabel);
    layout->addStretch();
    layout->addWidget(btnWidget);

    QVBoxLayout* dlgLayout = new QVBoxLayout(&dlg);
    dlgLayout->setContentsMargins(0, 0, 0, 0);
    dlgLayout->setSpacing(0);
    dlgLayout->addWidget(content);

    // 主题样式更新
    auto updateStyle = [&dlg, confirmIsDanger]() {
        ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
        bool isDark = (themeMode == ElaThemeType::Dark);
        QString bgColor = ElaThemeColor(themeMode, WindowBase).name();
        QString textColor = isDark ? "#E5E7EB" : "#333333";
        QString descColor = isDark ? "#9CA3AF" : "#666666";
        QString btnCancelBg = isDark ? "#374151" : "#F3F4F6";
        QString btnCancelText = isDark ? "#F9FAFB" : "#1F2937";
        QString btnCancelHover = isDark ? "#4B5563" : "#E5E7EB";
        QString btnConfirmBg = confirmIsDanger ? (isDark ? "#DC2626" : "#EF4444") : (isDark ? "#2563EB" : "#3B82F6");
        QString btnConfirmText = "#FFFFFF";
        QString btnConfirmHover = confirmIsDanger ? (isDark ? "#B91C1C" : "#DC2626") : (isDark ? "#1D4ED8" : "#2563EB");

        dlg.setStyleSheet(QString("QDialog { background: %1; border-radius: 12px; }").arg(bgColor));

        QLabel* t = dlg.findChild<QLabel*>("confirmTitle");
        if (t) t->setStyleSheet(QString("font-size: 16px; font-weight: bold; color: %1; border: none;").arg(textColor));

        QLabel* d = dlg.findChild<QLabel*>("confirmDesc");
        if (d) d->setStyleSheet(QString("font-size: 13px; color: %1; border: none;").arg(descColor));

        ElaPushButton* bc = dlg.findChild<ElaPushButton*>("btnCancel");
        if (bc) bc->setStyleSheet(QString(
            "ElaPushButton { background: %1; color: %2; border: none; border-radius: 8px; font-size: 13px; }"
            "ElaPushButton:hover { background: %3; }").arg(btnCancelBg).arg(btnCancelText).arg(btnCancelHover));

        ElaPushButton* bf = dlg.findChild<ElaPushButton*>("btnConfirm");
        if (bf) bf->setStyleSheet(QString(
            "ElaPushButton { background: %1; color: %2; border: none; border-radius: 8px; font-size: 13px; }"
            "ElaPushButton:hover { background: %3; }").arg(btnConfirmBg).arg(btnConfirmText).arg(btnConfirmHover));
    };
    updateStyle();
    QObject::connect(eTheme, &ElaTheme::themeModeChanged, &dlg, [&updateStyle]() { updateStyle(); });

    bool confirmed = false;
    QObject::connect(btnConfirm, &ElaPushButton::clicked, &dlg, [&]() {
        confirmed = true;
        dlg.accept();
    });
    QObject::connect(btnCancel, &ElaPushButton::clicked, &dlg, [&]() {
        confirmed = false;
        dlg.reject();
    });

    dlg.moveToCenter();
    dlg.exec();
    return confirmed;
}

// ==================== WhitelistPage 实现 ====================

WhitelistPage::WhitelistPage(QWidget* parent)
    : BasePage(parent)
{
    createCustomWidget("管理临时白名单。支持添加文件或目录（目录下所有文件及子文件夹免扫描）。仅显示用户手动添加的临时白名单（不含默认白名单）。");

    // ============ 顶部标题 + 操作按钮 ============
    ElaText* titleText = new ElaText("临时白名单", this);
    titleText->setTextPixelSize(20);

    m_countLabel = new ElaText("共 0 项", this);
    m_countLabel->setTextPixelSize(13);

    m_addFileBtn = new ElaPushButton("添加文件", this);
    m_addFileBtn->setFixedHeight(32);
    m_addFileBtn->setMinimumWidth(100);

    m_addFolderBtn = new ElaPushButton("添加目录", this);
    m_addFolderBtn->setFixedHeight(32);
    m_addFolderBtn->setMinimumWidth(100);

    m_refreshBtn = new ElaPushButton("刷新", this);
    m_refreshBtn->setFixedHeight(32);
    m_refreshBtn->setMinimumWidth(80);

    m_removeBtn = new ElaPushButton("移除选中", this);
    m_removeBtn->setFixedHeight(32);
    m_removeBtn->setMinimumWidth(100);

    m_removeAllBtn = new ElaPushButton("全部移除", this);
    m_removeAllBtn->setFixedHeight(32);
    m_removeAllBtn->setMinimumWidth(100);

    QHBoxLayout* btnLayout = new QHBoxLayout();
    btnLayout->setSpacing(10);
    btnLayout->addWidget(titleText, 1);
    btnLayout->addWidget(m_countLabel, 0);
    btnLayout->addStretch();
    btnLayout->addWidget(m_addFileBtn);
    btnLayout->addSpacing(8);
    btnLayout->addWidget(m_addFolderBtn);
    btnLayout->addSpacing(8);
    btnLayout->addWidget(m_refreshBtn);
    btnLayout->addSpacing(8);
    btnLayout->addWidget(m_removeBtn);
    btnLayout->addSpacing(8);
    btnLayout->addWidget(m_removeAllBtn);

    // ============ 表格 ============
    // 列：名称（图标+名称）| 类型 | 路径 | SHA256（文件项完整展示，目录项显示“目录免扫”）
    m_tableView = new ElaTableView(this);
    m_model = new QStandardItemModel(this);
    m_model->setHorizontalHeaderLabels({ "名称", "类型", "路径", "SHA256" });
    m_tableView->setModel(m_model);
    m_tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_tableView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_tableView->setAlternatingRowColors(true);
    m_tableView->verticalHeader()->setVisible(false);
    m_tableView->horizontalHeader()->setStretchLastSection(false);
    // 四列均使用 Interactive 模式，宽度由 setColumnWidth 指定，
    // 总宽超过视口时自动出现水平滚动条，确保 SHA256 与长路径完整展示
    m_tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Interactive);
    m_tableView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Interactive);
    m_tableView->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Interactive);
    m_tableView->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Interactive);
    m_tableView->setColumnWidth(0, 240);   // 名称（图标+名称）
    m_tableView->setColumnWidth(1, 90);    // 类型
    m_tableView->setColumnWidth(2, 480);   // 路径
    m_tableView->setColumnWidth(3, 560);   // SHA256
    m_tableView->setIconSize(QSize(24, 24));
    m_tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    // ============ 布局 ============
    QWidget* centralWidget = new QWidget(this);
    centralWidget->setWindowTitle("临时白名单");
    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(10);
    mainLayout->addLayout(btnLayout);
    mainLayout->addWidget(m_tableView, 1);

    addCentralWidget(centralWidget, true, true, 0);

    // ============ 信号槽连接 ============
    connect(m_addFileBtn, &ElaPushButton::clicked, this, &WhitelistPage::OnAddFile);
    connect(m_addFolderBtn, &ElaPushButton::clicked, this, &WhitelistPage::OnAddFolder);
    connect(m_refreshBtn, &ElaPushButton::clicked, this, &WhitelistPage::refreshWhitelist);
    connect(m_removeBtn, &ElaPushButton::clicked, this, &WhitelistPage::OnRemoveSelected);
    connect(m_removeAllBtn, &ElaPushButton::clicked, this, &WhitelistPage::OnRemoveAll);
    connect(eTheme, &ElaTheme::themeModeChanged, this, &WhitelistPage::OnThemeModeChanged);

    ApplyThemeStyle();
    // 注意：不在此处调用 refreshWhitelist()，因为 g_csScanCache 可能尚未初始化
    // refreshWhitelist() 会在首次 showEvent 时触发
}

WhitelistPage::~WhitelistPage()
{
}

void WhitelistPage::showEvent(QShowEvent* event)
{
    BasePage::showEvent(event);
    // 每次显示时刷新白名单，保证数据为最新
    refreshWhitelist();
}

QIcon WhitelistPage::LoadFileIcon(const QString& filePath)
{
    if (filePath.isEmpty())
        return QApplication::style()->standardIcon(QStyle::SP_FileIcon);

    QFileInfo fi(filePath);
    if (!fi.exists())
        return QApplication::style()->standardIcon(QStyle::SP_FileIcon);

    QFileIconProvider provider;
    QIcon icon = provider.icon(fi);
    if (icon.isNull())
        icon = provider.icon(QFileIconProvider::File);
    if (icon.isNull())
        icon = QApplication::style()->standardIcon(QStyle::SP_FileIcon);
    return icon;
}

QIcon WhitelistPage::LoadFolderIcon()
{
    QFileIconProvider provider;
    QIcon icon = provider.icon(QFileIconProvider::Folder);
    if (icon.isNull())
        icon = QApplication::style()->standardIcon(QStyle::SP_DirIcon);
    return icon;
}

void WhitelistPage::refreshWhitelist()
{
    // 拷贝一份缓存，避免长时间持锁阻塞扫描线程
    std::vector<std::pair<std::string, std::string>> snapshot;  // (sha256, path)
    std::vector<std::string> dirSnapshot;
    std::set<std::string> enhancedSnapshot;  // 强化白名单路径（小写）
    EnterCriticalSection(&g_csScanCache);
    snapshot.reserve(WhiteSha256ListCache.size());
    for (const auto& kv : WhiteSha256ListCache)
        snapshot.emplace_back(kv.first, kv.second);
    dirSnapshot.reserve(WhiteDirListCache.size());
    for (const auto& d : WhiteDirListCache)
        dirSnapshot.push_back(d);
    enhancedSnapshot = WhitePathListCache;
    LeaveCriticalSection(&g_csScanCache);

    // 统一排序：文件项按文件名，目录项按路径
    auto getFileName = [](const std::string& p) -> std::string {
        size_t pos = p.find_last_of("\\/");
        return (pos == std::string::npos) ? p : p.substr(pos + 1);
    };
    auto lowerPathOf = [](const std::string& p) -> std::string {
        std::string lp = p;
        std::transform(lp.begin(), lp.end(), lp.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return lp;
    };

    // 分离强化白名单条目与普通文件条目
    // 强化条目：路径在 enhancedSnapshot 中，只显示一行（取最新的 sha256）
    // 普通条目：路径不在 enhancedSnapshot 中，正常显示
    struct EnhancedEntry {
        std::string path;       // 原始路径（保留大小写用于展示）
        std::string lowerPath;  // 小写路径（用于匹配）
        std::string sha256;     // 最新的 sha256（找不到则为空）
    };
    std::vector<EnhancedEntry> enhancedEntries;
    std::vector<std::pair<std::string, std::string>> normalFiles;  // (sha256, path)

    // 为每个强化路径从 snapshot 中找出对应的 sha256（取最后一个匹配的作为"最新"）
    for (const auto& enhancedPath : enhancedSnapshot)
    {
        EnhancedEntry ee;
        ee.lowerPath = enhancedPath;
        ee.sha256.clear();
        for (const auto& kv : snapshot)
        {
            if (lowerPathOf(kv.second) == enhancedPath)
            {
                ee.path = kv.second;  // 保留原始大小写路径
                ee.sha256 = kv.first; // 取最后一个匹配的 sha256
            }
        }
        // 如果 snapshot 中没有对应的 sha256 条目（理论上不应该发生），仍显示路径
        if (ee.path.empty())
            ee.path = enhancedPath;
        enhancedEntries.push_back(std::move(ee));
    }

    // 普通文件条目：路径不在强化白名单中
    for (const auto& kv : snapshot)
    {
        if (enhancedSnapshot.find(lowerPathOf(kv.second)) == enhancedSnapshot.end())
        {
            normalFiles.emplace_back(kv.first, kv.second);
        }
    }

    std::sort(normalFiles.begin(), normalFiles.end(),
        [&getFileName](const std::pair<std::string, std::string>& a,
           const std::pair<std::string, std::string>& b) {
            std::string na = getFileName(a.second);
            std::string nb = getFileName(b.second);
            std::transform(na.begin(), na.end(), na.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(nb.begin(), nb.end(), nb.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return na < nb;
        });
    std::sort(enhancedEntries.begin(), enhancedEntries.end(),
        [&getFileName](const EnhancedEntry& a, const EnhancedEntry& b) {
            std::string na = getFileName(a.path);
            std::string nb = getFileName(b.path);
            std::transform(na.begin(), na.end(), na.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            std::transform(nb.begin(), nb.end(), nb.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return na < nb;
        });
    std::sort(dirSnapshot.begin(), dirSnapshot.end());

    m_model->removeRows(0, m_model->rowCount());

    QFont monoFont("Consolas", 9);

    // 目录项（优先展示，便于区分）
    QIcon folderIcon = LoadFolderIcon();
    for (const auto& dir : dirSnapshot)
    {
        QString qPath = QString::fromLocal8Bit(dir.c_str());
        // 目录路径已规范化为小写末尾带'\'，这里展示时去掉末尾反斜杠以便美观
        QString displayPath = qPath;
        if (displayPath.endsWith('\\'))
            displayPath.chop(1);
        QFileInfo fi(displayPath);
        QString displayName = fi.fileName();
        if (displayName.isEmpty())
            displayName = displayPath;
        if (displayName.isEmpty())
            displayName = QString::fromUtf8("未知目录");

        QStandardItem* nameItem = new QStandardItem(displayName);
        nameItem->setIcon(folderIcon);
        nameItem->setEditable(false);
        nameItem->setToolTip(displayPath);
        // Qt::UserRole 存标识（目录用规范化路径），UserRole+1 存类型标记
        nameItem->setData(qPath, Qt::UserRole);
        nameItem->setData(QString::fromLatin1("dir"), Qt::UserRole + 1);

        QStandardItem* typeItem = new QStandardItem(QString::fromUtf8("目录"));
        typeItem->setEditable(false);
        typeItem->setTextAlignment(Qt::AlignCenter);

        QStandardItem* pathItem = new QStandardItem(displayPath);
        pathItem->setEditable(false);
        pathItem->setToolTip(displayPath);
        pathItem->setFont(monoFont);

        QStandardItem* shaItem = new QStandardItem(QString::fromUtf8("目录免扫"));
        shaItem->setEditable(false);
        shaItem->setTextAlignment(Qt::AlignCenter);

        m_model->appendRow({ nameItem, typeItem, pathItem, shaItem });
    }

    // 普通文件项
    for (const auto& kv : normalFiles)
    {
        const std::string& sha = kv.first;
        const std::string& path = kv.second;
        QString qPath = QString::fromLocal8Bit(path.c_str());
        QString qSha = QString::fromStdString(sha);

        // 名称列：图标 + 完整文件名（含后缀）一体显示
        QFileInfo fi(qPath);
        QString displayName = fi.fileName();  // 保留后缀名
        if (displayName.isEmpty())
            displayName = QString::fromUtf8("未知");

        QStandardItem* nameItem = new QStandardItem(displayName);
        nameItem->setIcon(LoadFileIcon(qPath));
        nameItem->setEditable(false);
        nameItem->setToolTip(qPath);
        nameItem->setData(qSha, Qt::UserRole);  // 关联 sha256，便于删除时取用
        nameItem->setData(QString::fromLatin1("file"), Qt::UserRole + 1);

        QStandardItem* typeItem = new QStandardItem(QString::fromUtf8("文件"));
        typeItem->setEditable(false);
        typeItem->setTextAlignment(Qt::AlignCenter);

        // 路径列
        QStandardItem* pathItem = new QStandardItem(qPath);
        pathItem->setEditable(false);
        pathItem->setToolTip(qPath);
        pathItem->setFont(monoFont);

        // SHA256 列：完整展示，不截断
        QStandardItem* shaItem = new QStandardItem(qSha);
        shaItem->setEditable(false);
        shaItem->setToolTip(qSha);
        shaItem->setFont(monoFont);
        shaItem->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        m_model->appendRow({ nameItem, typeItem, pathItem, shaItem });
    }

    // 强化白名单文件项（路径免扫，显示最新 sha256）
    for (const auto& ee : enhancedEntries)
    {
        QString qPath = QString::fromLocal8Bit(ee.path.c_str());
        QString qSha = ee.sha256.empty() ? QString::fromUtf8("路径免扫") : QString::fromStdString(ee.sha256);

        QFileInfo fi(qPath);
        QString displayName = fi.fileName();
        if (displayName.isEmpty())
            displayName = QString::fromUtf8("未知");

        QStandardItem* nameItem = new QStandardItem(displayName);
        nameItem->setIcon(LoadFileIcon(qPath));
        nameItem->setEditable(false);
        nameItem->setToolTip(qPath);
        // 强化条目用原始路径（小写）作为标识，便于删除时取用
        nameItem->setData(QString::fromLocal8Bit(ee.lowerPath.c_str()), Qt::UserRole);
        nameItem->setData(QString::fromLatin1("enhanced_file"), Qt::UserRole + 1);

        QStandardItem* typeItem = new QStandardItem(QString::fromUtf8("文件(强化白名单)"));
        typeItem->setEditable(false);
        typeItem->setTextAlignment(Qt::AlignCenter);

        QStandardItem* pathItem = new QStandardItem(qPath);
        pathItem->setEditable(false);
        pathItem->setToolTip(qPath);
        pathItem->setFont(monoFont);

        QStandardItem* shaItem = new QStandardItem(qSha);
        shaItem->setEditable(false);
        shaItem->setToolTip(qSha);
        shaItem->setFont(monoFont);
        shaItem->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);

        m_model->appendRow({ nameItem, typeItem, pathItem, shaItem });
    }

    int total = static_cast<int>(dirSnapshot.size() + normalFiles.size() + enhancedEntries.size());
    m_countLabel->setText(QString("共 %1 项（目录 %2，文件 %3，强化 %4）")
        .arg(total)
        .arg(static_cast<int>(dirSnapshot.size()))
        .arg(static_cast<int>(normalFiles.size()))
        .arg(static_cast<int>(enhancedEntries.size())));
}

void WhitelistPage::OnRemoveSelected()
{
    QModelIndexList selected = m_tableView->selectionModel()->selectedRows();
    if (selected.isEmpty())
    {
        NewMessageBox("请先选择要移除的白名单项。", 4, 2);
        return;
    }

    // 收集待删除项：区分文件（sha256）与目录（规范化路径）
    struct RemoveItem {
        QString type;       // "file" 或 "dir"
        QString identifier; // 文件: sha256；目录: 规范化路径
    };
    std::vector<RemoveItem> toRemove;
    for (const QModelIndex& idx : selected)
    {
        QStandardItem* nameItem = m_model->item(idx.row(), 0);
        if (nameItem)
        {
            RemoveItem item;
            item.type = nameItem->data(Qt::UserRole + 1).toString();
            item.identifier = nameItem->data(Qt::UserRole).toString();
            if (!item.identifier.isEmpty())
                toRemove.push_back(item);
        }
    }

    if (toRemove.empty())
        return;

    // 现代化确认弹窗
    bool confirmed = ShowModernConfirmDialog(
        this,
        "确认移除",
        QString("将移除选中的 %1 项白名单，移除后这些文件/目录将恢复扫描。是否继续？").arg(toRemove.size()),
        "移除",
        "取消",
        true);

    if (!confirmed)
        return;

    int removedCount = 0;
    for (const RemoveItem& item : toRemove)
    {
        if (item.type == QString::fromLatin1("dir"))
        {
            if (Whitelist_RemoveTemporaryDir(item.identifier.toLocal8Bit().toStdString()))
                ++removedCount;
        }
        else if (item.type == QString::fromLatin1("enhanced_file"))
        {
            // 强化白名单：移除路径免扫标记 + 该路径下所有 sha256 条目
            std::string path = item.identifier.toLocal8Bit().toStdString();
            Whitelist_RemoveEnhancedPath(path);
            Whitelist_RemoveAllSha256ByPath(path);
            ++removedCount;
        }
        else
        {
            if (Whitelist_RemoveTemporary(item.identifier.toStdString()))
                ++removedCount;
        }
    }

    refreshWhitelist();
    NewMessageBox(QString("已移除 %1 项白名单。").arg(removedCount), 1, 3);
}

void WhitelistPage::OnRemoveAll()
{
    if (m_model->rowCount() == 0)
    {
        NewMessageBox("当前没有可移除的临时白名单。", 4, 2);
        return;
    }

    bool confirmed = ShowModernConfirmDialog(
        this,
        "确认全部移除",
        QString("将移除全部 %1 项临时白名单，移除后这些文件/目录将恢复扫描。是否继续？").arg(m_model->rowCount()),
        "全部移除",
        "取消",
        true);

    if (!confirmed)
        return;

    // 收集所有项后逐个移除（区分文件/目录）
    struct RemoveItem {
        QString type;
        QString identifier;
    };
    std::vector<RemoveItem> all;
    all.reserve(m_model->rowCount());
    for (int r = 0; r < m_model->rowCount(); ++r)
    {
        QStandardItem* nameItem = m_model->item(r, 0);
        if (nameItem)
        {
            RemoveItem item;
            item.type = nameItem->data(Qt::UserRole + 1).toString();
            item.identifier = nameItem->data(Qt::UserRole).toString();
            if (!item.identifier.isEmpty())
                all.push_back(item);
        }
    }

    int removedCount = 0;
    for (const RemoveItem& item : all)
    {
        if (item.type == QString::fromLatin1("dir"))
        {
            if (Whitelist_RemoveTemporaryDir(item.identifier.toLocal8Bit().toStdString()))
                ++removedCount;
        }
        else if (item.type == QString::fromLatin1("enhanced_file"))
        {
            // 强化白名单：移除路径免扫标记 + 该路径下所有 sha256 条目
            std::string path = item.identifier.toLocal8Bit().toStdString();
            Whitelist_RemoveEnhancedPath(path);
            Whitelist_RemoveAllSha256ByPath(path);
            ++removedCount;
        }
        else
        {
            if (Whitelist_RemoveTemporary(item.identifier.toStdString()))
                ++removedCount;
        }
    }

    refreshWhitelist();
    NewMessageBox(QString("已移除全部 %1 项白名单。").arg(removedCount), 1, 3);
}

void WhitelistPage::OnAddFile()
{
    // 支持多选文件一次性添加
    QStringList files = QFileDialog::getOpenFileNames(this, QString::fromUtf8("选择要加入白名单的文件"),
        QDir::homePath(), QString::fromUtf8("所有文件 (*.*)"));
    if (files.isEmpty())
        return;

    int addedCount = 0;
    for (const QString& file : files)
    {
        if (Whitelist_AddTemporary(file))
            ++addedCount;
    }

    refreshWhitelist();
    if (addedCount > 0)
        NewMessageBox(QString::fromUtf8("已添加 %1 个文件到白名单。").arg(addedCount), 1, 3);
    else
        NewMessageBox(QString::fromUtf8("所选文件已在白名单中或添加失败。"), 2, 3);
}

void WhitelistPage::OnAddFolder()
{
    QString folder = QFileDialog::getExistingDirectory(this, QString::fromUtf8("选择要加入白名单的目录（该目录下所有文件及子文件夹将免扫描）"),
        QDir::homePath(), QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (folder.isEmpty())
        return;

    if (Whitelist_AddTemporaryDir(folder))
    {
        refreshWhitelist();
        NewMessageBox(QString::fromUtf8("已添加目录到白名单，该目录下所有文件及子文件夹将免扫描：\n%1").arg(folder), 1, 3);
    }
    else
    {
        NewMessageBox(QString::fromUtf8("添加目录白名单失败。"), 3, 3);
    }
}

void WhitelistPage::OnThemeModeChanged(ElaThemeType::ThemeMode themeMode)
{
    Q_UNUSED(themeMode);
    ApplyThemeStyle();
}

void WhitelistPage::ApplyThemeStyle()
{
    ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
    bool isDark = (themeMode == ElaThemeType::Dark);

    QColor baseBg = ElaThemeColor(themeMode, WindowBase);
    QColor textCol = ElaThemeColor(themeMode, BasicText);
    QColor altRowBg = ElaThemeColor(themeMode, BasicAlternating);
    QColor borderCol = isDark ? QColor("#3a3a3a") : QColor("#e0e0e0");
    QColor selBg = ElaThemeColor(themeMode, BasicSelectedHover);

    // 注意：ElaTableView 使用自定义 ElaTableViewStyle 绘制表头（CE_HeaderSection/CE_HeaderLabel），
    // 表头的背景和文字颜色由 ElaThemeColor(_themeMode, BasicBaseDeepAlpha / BasicText) 控制，
    // 此处不覆盖 QHeaderView::section 样式，避免与自定义样式冲突导致表头黑底看不清。
    m_tableView->setStyleSheet(QString(
        "QTableView {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 6px;"
        "  gridline-color: %3;"
        "  selection-background-color: %4;"
        "  alternate-background-color: %5;"
        "}"
        "QTableView::item { padding: 6px; }"
        "QHeaderView { background-color: transparent; border: 0px; }"
        ).arg(baseBg.name(), textCol.name(), borderCol.name(),
              selBg.name(), altRowBg.name()));

    m_countLabel->setStyleSheet(QString("color: %1;").arg(isDark ? "#9CA3AF" : "#6B7280"));

    // 按钮颜色：使用主题色与红色（移除按钮）
    QColor primaryCol = ElaThemeColor(themeMode, PrimaryNormal);
    QColor primaryHover = ElaThemeColor(themeMode, PrimaryHover);
    QColor primaryPress = ElaThemeColor(themeMode, PrimaryPress);

    m_refreshBtn->setLightDefaultColor(primaryCol);
    m_refreshBtn->setDarkDefaultColor(primaryCol);
    m_refreshBtn->setLightHoverColor(primaryHover);
    m_refreshBtn->setDarkHoverColor(primaryHover);
    m_refreshBtn->setLightPressColor(primaryPress);
    m_refreshBtn->setDarkPressColor(primaryPress);
    m_refreshBtn->setLightTextColor(Qt::white);
    m_refreshBtn->setDarkTextColor(Qt::white);

    // 添加文件/目录按钮：绿色（正向操作）
    QColor addCol = isDark ? QColor("#22C55E") : QColor("#16A34A");
    QColor addHover = isDark ? QColor("#16A34A") : QColor("#15803D");
    QColor addPress = isDark ? QColor("#15803D") : QColor("#166534");
    auto styleAddBtn = [&](ElaPushButton* btn) {
        btn->setLightDefaultColor(addCol);
        btn->setDarkDefaultColor(addCol);
        btn->setLightHoverColor(addHover);
        btn->setDarkHoverColor(addHover);
        btn->setLightPressColor(addPress);
        btn->setDarkPressColor(addPress);
        btn->setLightTextColor(Qt::white);
        btn->setDarkTextColor(Qt::white);
    };
    styleAddBtn(m_addFileBtn);
    styleAddBtn(m_addFolderBtn);

    // 移除按钮：橙色（危险但可逆）
    QColor removeCol = isDark ? QColor("#e67e22") : QColor("#d35400");
    QColor removeHover = isDark ? QColor("#d35400") : QColor("#a04000");
    QColor removePress = isDark ? QColor("#a04000") : QColor("#6e2c00");
    m_removeBtn->setLightDefaultColor(removeCol);
    m_removeBtn->setDarkDefaultColor(removeCol);
    m_removeBtn->setLightHoverColor(removeHover);
    m_removeBtn->setDarkHoverColor(removeHover);
    m_removeBtn->setLightPressColor(removePress);
    m_removeBtn->setDarkPressColor(removePress);
    m_removeBtn->setLightTextColor(Qt::white);
    m_removeBtn->setDarkTextColor(Qt::white);

    // 全部移除按钮：红色（强危险）
    QColor allRemoveCol = isDark ? QColor("#e74c3c") : QColor("#c0392b");
    QColor allRemoveHover = isDark ? QColor("#c0392b") : QColor("#922b21");
    QColor allRemovePress = isDark ? QColor("#922b21") : QColor("#641e16");
    m_removeAllBtn->setLightDefaultColor(allRemoveCol);
    m_removeAllBtn->setDarkDefaultColor(allRemoveCol);
    m_removeAllBtn->setLightHoverColor(allRemoveHover);
    m_removeAllBtn->setDarkHoverColor(allRemoveHover);
    m_removeAllBtn->setLightPressColor(allRemovePress);
    m_removeAllBtn->setDarkPressColor(allRemovePress);
    m_removeAllBtn->setLightTextColor(Qt::white);
    m_removeAllBtn->setDarkTextColor(Qt::white);
}
