#include "LoggerPage.h"
#include <QTextBrowser>
#include <QPainter>
#include <QTimer>

void LogItemDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    painter->save();

    bool isDark = (eTheme->getThemeMode() == ElaThemeType::Dark);
    bool isSelected = (option.state & QStyle::State_Selected);
    bool isHovered = (option.state & QStyle::State_MouseOver);

    /* 绘制选中/悬停背景 —— 使用 ElaTheme 适配颜色，确保与文字有足够对比度 */
    if (isSelected)
    {
        QColor selBg = isDark ? QColor(0x30, 0x50, 0x80) : QColor(0xCC, 0xE0, 0xFF);
        painter->fillRect(option.rect, selBg);
    }
    else if (isHovered)
    {
        QColor hoverBg = ElaThemeColor(isDark ? ElaThemeType::Dark : ElaThemeType::Light, BasicHover);
        painter->fillRect(option.rect, hoverBg);
    }

    QRect rect = option.rect;
    int iconSize = 18;
    int margin = 6;

    /* 1. 绘制图标 */
    QIcon icon = index.data(Qt::DecorationRole).value<QIcon>();
    if (!icon.isNull())
    {
        QRect iconRect(rect.left() + margin, rect.top() + (rect.height() - iconSize) / 2,
                       iconSize, iconSize);
        icon.paint(painter, iconRect);
    }

    /* 2. 绘制时间戳（灰色，小字体） */
    qint64 msSinceEpoch = index.data(Qt::UserRole + 2).toLongLong();
    QString timeStr = msSinceEpoch > 0 ? formatTimestamp(msSinceEpoch) : QString();

    QColor grayColor = isDark ? QColor("#9CA3AF") : QColor("#6B7280");

    int timeX = rect.left() + margin + iconSize + margin;
    int timeWidth = 0;

    if (!timeStr.isEmpty())
    {
        QFont timeFont = option.font;
        timeFont.setPixelSize(12);
        painter->setFont(timeFont);
        painter->setPen(isSelected ? (isDark ? QColor("#B0C8E0") : QColor("#405570")) : grayColor);

        /* 计算时间戳所需宽度 */
        timeWidth = QFontMetrics(timeFont).horizontalAdvance(timeStr) + margin;
        QRect timeRect(timeX, rect.top(), timeWidth, rect.height());
        painter->drawText(timeRect, Qt::AlignLeft | Qt::AlignVCenter, timeStr);
    }

    /* 3. 绘制文字 */
    QString text = index.data(Qt::DisplayRole).toString();
    if (!text.isEmpty())
    {
        QFont textFont = option.font;
        painter->setFont(textFont);

        QColor textColor;
        if (isSelected)
            textColor = isDark ? QColor("#FFFFFF") : QColor("#000000");
        else
            textColor = index.data(Qt::ForegroundRole).value<QColor>();

        painter->setPen(textColor);

        int textX = timeX + timeWidth;
        QRect textRect(textX, rect.top(),
                       rect.right() - textX - margin, rect.height());
        painter->drawText(textRect, Qt::AlignLeft | Qt::AlignVCenter,
                          painter->fontMetrics().elidedText(text, Qt::ElideRight, textRect.width()));
    }

    painter->restore();
}

QSize LogItemDelegate::sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const
{
    QSize size = QStyledItemDelegate::sizeHint(option, index);
    size.setHeight(qMax(size.height(), 36));  /* 确保最小高度 */
    return size;
}

QString LogItemDelegate::formatTimestamp(qint64 msSinceEpoch)
{
    QDateTime logTime = QDateTime::fromMSecsSinceEpoch(msSinceEpoch);
    qint64 secs = logTime.secsTo(QDateTime::currentDateTime());

    if (secs < 0)
        return logTime.toString("yyyy/M/d HH:mm:ss");
    if (secs < 60)
        return QString::fromUtf8("刚刚");
    if (secs < 3600)
        return QString("%1分钟前").arg(secs / 60);
    if (secs < 86400)
        return QString("%1小时前").arg(secs / 3600);
    return logTime.toString("yyyy/M/d HH:mm:ss");
}

void LoggerPage::CreateContentOptions(ElaToggleSwitch*& pWidget, QString Content, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType)
{
    pWidget = new ElaToggleSwitch(this);
    pWidget->setIsToggled(true);
    toggleSwitchArea = new ElaScrollPageArea(this);
    toggleSwitchArea->setFixedHeight(50);

    QHBoxLayout* toggleSwitchLayout = new QHBoxLayout(toggleSwitchArea);
    ElaText* toggleSwitchIcon = new ElaText(this);
    ElaText* toggleSwitchText = new ElaText(Content, this);
    toggleSwitchIcon->setElaIcon(EiType);
    toggleSwitchIcon->setFixedWidth(35);
    toggleSwitchText->setTextPixelSize(15);
    toggleSwitchText->setFixedWidth(360);
    toggleSwitchLayout->addWidget(toggleSwitchIcon);
    toggleSwitchLayout->addSpacing(10);
    toggleSwitchLayout->addWidget(toggleSwitchText);
    toggleSwitchLayout->addStretch();
    toggleSwitchLayout->addWidget(pWidget);
}

LoggerPage::LoggerPage(QWidget* pParent)
{
    createCustomWidget("此处是天宏安全防御的日志记录。左侧列表显示日志摘要，选中项目后右侧显示详细信息，Ctrl+C可复制。");

    ElaText* Et = new ElaText;
    Et->setText("日志列表");
    Et->setTextPixelSize(20);

    /* 左侧日志列表 */
    LogArea = new ElaListView(this);
    LogModel = new QStandardItemModel(this);
    LogArea->setModel(LogModel);
    /* 设置图标显示尺寸，确保等级图标足够大 */
    LogArea->setIconSize(QSize(18, 18));

    /* 设置自定义代理，在列表项右侧显示时间戳 */
    m_delegate = new LogItemDelegate(this);
    LogArea->setItemDelegate(m_delegate);

    /* 每30秒刷新时间戳显示 */
    m_timestampTimer = new QTimer(this);
    connect(m_timestampTimer, &QTimer::timeout, this, &LoggerPage::UpdateTimestamps);
    m_timestampTimer->start(30000);

    /* 右侧详情面板：QTextBrowser 支持 HTML 富文本层次化展示，且只读可选中 */
    LogDetailArea = new QTextBrowser(this);
    LogDetailArea->setReadOnly(true);
    LogDetailArea->setOpenExternalLinks(false);
    LogDetailArea->setPlaceholderText("单击日志查看详细信息");
    QFont detailFont = LogDetailArea->font();
    detailFont.setPixelSize(14);
    LogDetailArea->setFont(detailFont);

    /* 连接选择变化信号：点击日志项时显示详情 */
    QItemSelectionModel* selModel = LogArea->selectionModel();
    if (selModel)
    {
        connect(selModel, &QItemSelectionModel::currentChanged,
                this, &LoggerPage::OnLogSelectionChanged);
    }

    /* 监听主题变化：动态更新详情面板背景与文字颜色 */
    connect(eTheme, &ElaTheme::themeModeChanged,
            this, &LoggerPage::OnThemeModeChanged);

    /* 水平布局：左侧日志列表（占 60%），右侧详情面板（占 40%） */
    QWidget* centralWidget = new QWidget(this);
    centralWidget->setWindowTitle("日志记录");
    QHBoxLayout* hLayout = new QHBoxLayout(centralWidget);
    hLayout->setContentsMargins(0, 0, 0, 0);
    hLayout->setSpacing(8);

    /* 左侧：标题 + 日志列表 */
    QWidget* leftWidget = new QWidget(this);
    QVBoxLayout* leftLayout = new QVBoxLayout(leftWidget);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->addWidget(Et);
    leftLayout->addSpacing(10);
    leftLayout->addWidget(LogArea, 1);  /* 让日志列表占据剩余空间 */

    /* 右侧：详情标题 + 详情面板 */
    ElaText* detailTitle = new ElaText;
    detailTitle->setText("详细信息");
    detailTitle->setTextPixelSize(20);

    QWidget* rightWidget = new QWidget(this);
    QVBoxLayout* rightLayout = new QVBoxLayout(rightWidget);
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->addWidget(detailTitle);
    rightLayout->addSpacing(10);
    rightLayout->addWidget(LogDetailArea, 1);  /* 让详情面板占据剩余空间 */

    /* 按比例分配：左 3 : 右 2 */
    hLayout->addWidget(leftWidget, 3);
    hLayout->addWidget(rightWidget, 2);

    QVBoxLayout* centerLayout = new QVBoxLayout;
    centerLayout->setContentsMargins(0, 0, 0, 0);
    centerLayout->addLayout(hLayout);

    addCentralWidget(centralWidget, true, true, 0);

    /* 初始应用主题样式 */
    ApplyThemeStyle();
}

LoggerPage::~LoggerPage() {}

void LoggerPage::OnLogSelectionChanged(const QModelIndex& current, const QModelIndex& previous)
{
    Q_UNUSED(previous);

    m_lastSelectedIndex = current;

    if (!current.isValid() || !LogModel)
    {
        LogDetailArea->clear();
        return;
    }

    QStandardItem* item = LogModel->itemFromIndex(current);
    if (!item)
    {
        LogDetailArea->clear();
        return;
    }

    /* 从 UserRole 取出完整详情文本，转换为层次化 HTML 显示 */
    QString detail = item->data(Qt::UserRole).toString();
    if (detail.isEmpty())
        detail = item->text();

    /* 从 UserRole+1 取出日志等级，用于在详情头部显示对应图标 */
    int level = item->data(Qt::UserRole + 1).toInt();
    if (level < 0 || level > 3)
        level = 0;

    LogDetailArea->setHtml(BuildDetailHtml(detail, (LogLevel)level));
}

void LoggerPage::OnThemeModeChanged(ElaThemeType::ThemeMode themeMode)
{
    Q_UNUSED(themeMode);
    ApplyThemeStyle();
    RefreshDetailHtml();
}

void LoggerPage::ApplyThemeStyle()
{
    /* 根据 ElaTheme 主题设置详情面板的背景与基础文字颜色 */
    ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
    bool isDark = (themeMode == ElaThemeType::Dark);

    QColor bgColor = ElaThemeColor(themeMode, WindowBase);
    QColor textColor = ElaThemeColor(themeMode, BasicText);

    LogDetailArea->setStyleSheet(QString(
        "QTextBrowser {"
        "  background-color: %1;"
        "  color: %2;"
        "  border: 1px solid %3;"
        "  border-radius: 6px;"
        "  padding: 8px;"
        "}").arg(bgColor.name(), textColor.name(),
                 isDark ? "#3a3a3a" : "#dcdcdc"));
}

QString LoggerPage::BuildDetailHtml(const QString& plainDetail, LogLevel level) const
{
    /* 将 plain text 详情解析为层次化 HTML：
     * - 顶部：大图标 + 时间戳/等级 + 摘要标题
     * - 分隔线
     * - 提供者字段（如有）特殊高亮
     * - 后续字段：标签（灰色）+ 值（主题色）对齐布局
     * - 路径类值使用等宽字体
     */
    ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
    bool isDark = (themeMode == ElaThemeType::Dark);

    /* 主题相关颜色 */
    QString labelColor = isDark ? "#9CA3AF" : "#6B7280";   /* 标签：灰色 */
    QString valueColor = isDark ? "#E5E7EB" : "#1F2937";   /* 值：主题文字色 */
    QString titleColor = isDark ? "#60A5FA" : "#1565C0";   /* 标题：蓝色 */
    QString providerColor = isDark ? "#A78BFA" : "#7C3AED"; /* 提供者：紫色 */
    QString borderColor = isDark ? "#374151" : "#E5E7EB";   /* 分隔线 */
    QString monoFont = "Consolas, 'Courier New', monospace";

    /* 等级对应的 Unicode 图标（使用 ElaAwesome 字体映射） */
    const QString levelIcons[4] = {
        QString(QChar(0xead0)),  /* INFO: CircleInfo */
        QString(QChar(0xeab4)),  /* SUCCESS: CircleCheck */
        QString(QChar(0xeac7)),  /* WARN: CircleExclamation */
        QString(QChar(0xf3be))   /* ERROR: TriangleExclamation */
    };
    const QString levelColorHex[4] = {
        isDark ? "#64B5F6" : "#1565C0",  /* INFO 蓝 */
        isDark ? "#81C784" : "#2E7D32",  /* SUCCESS 绿 */
        isDark ? "#FFB74D" : "#E65100",  /* WARN 橙 */
        isDark ? "#EF9A9A" : "#C62828"   /* ERROR 红 */
    };
    static const char* levelNames[4] = { "INFO", "SUCCESS", "WARN", "ERROR" };

    QStringList lines = plainDetail.split('\n', Qt::KeepEmptyParts);
    if (lines.isEmpty())
        return QString();

    QString html;
    html.reserve(plainDetail.size() * 3);

    /* ===== 顶部标题区：大图标 + 等级名 + 摘要 ===== */
    QString titleLine = lines.first().trimmed();

    /* 图标 + 右侧（等级名小标签 + 摘要大标题）垂直布局 */
    html.append(QString("<div style='display:flex;align-items:flex-start;margin-bottom:10px;'>"
                        "<span style='font-family:\"ElaAwesome\";font-size:36px;"
                        "color:%1;margin-right:14px;line-height:1;'>%2</span>"
                        "<div style='flex:1;'>"
                        "<div style='color:%3;font-size:12px;font-weight:600;"
                        "letter-spacing:1px;margin-bottom:2px;'>%4</div>"
                        "<div style='color:%5;font-weight:bold;font-size:16px;line-height:1.3;'>%6</div>"
                        "</div></div>")
                    .arg(levelColorHex[level], levelIcons[level],
                         levelColorHex[level], levelNames[level],
                         titleColor, titleLine.toHtmlEscaped()));

    if (lines.size() > 1)
    {
        html.append(QString("<hr style='border:none;border-top:1px solid %1;margin:6px 0 10px 0;'>")
                        .arg(borderColor));

        /* ===== 字段区 ===== */
        bool greyContentMode = false;  /* [content] 标记后所有行均以灰色渲染 */
        for (int i = 1; i < lines.size(); ++i)
        {
            QString line = lines[i].trimmed();
            if (line.isEmpty())
            {
                html.append("<div style='height:6px;'></div>");
                continue;
            }

            /* 同时支持全角「：」和半角":"，优先匹配第一个冒号 */
            int colonIdx = -1;
            bool fullWidth = false;
            int idx = line.indexOf(QChar(0xFF1A));  /* 全角冒号 ： */
            if (idx != -1)
            {
                colonIdx = idx;
                fullWidth = true;
            }
            else
            {
                idx = line.indexOf(QChar(':'));     /* 半角冒号 : */
                if (idx != -1)
                    colonIdx = idx;
            }

            QString label;
            QString value;

            if (colonIdx > 0 && colonIdx < line.length() - 1)
            {
                /* 冒号在行中：标签和值在同一行 */
                label = line.left(colonIdx).trimmed();
                value = line.mid(colonIdx + 1).trimmed();
            }
            else if (colonIdx > 0 && colonIdx == line.length() - 1 && i + 1 < lines.size())
            {
                /* 冒号在行尾：值在下一行，且下一行不含冒号时合并 */
                QString nextLine = lines[i + 1].trimmed();
                int nextColon = nextLine.indexOf(QChar(0xFF1A));
                if (nextColon == -1) nextColon = nextLine.indexOf(QChar(':'));
                if (nextColon == -1 && !nextLine.isEmpty())
                {
                    label = line.left(colonIdx).trimmed();
                    value = nextLine;
                    i++;  /* 跳过下一行 */
                }
            }

            if (!label.isEmpty())
            {
                /* 提供者字段特殊样式 */
                bool isProvider = (label == "提供者" || label == "Provider");

                /* 仅当值本身看起来像路径时才使用等宽字体渲染 */
                bool isPath = value.startsWith('\\') || value.startsWith('/') ||
                              value.contains(":\\") || value.contains(":/") ||
                              value.contains("\\REGISTRY\\") || value.length() > 60;

                /* [content] 标记后所有行均以灰色渲染，包括带冒号的结构化字段 */
                QString effLabelColor = greyContentMode ? (isDark ? "#7F8C8D" : "#95A5A6") : labelColor;
                QString effValueColor = greyContentMode ? (isDark ? "#7F8C8D" : "#95A5A6") : valueColor;

                if (isProvider)
                {
                    /* 提供者：用紫色徽章样式（灰色模式下也变灰） */
                    html.append(QString("<div style='margin:6px 0;'>"
                                         "<span style='color:%1;font-weight:500;'>提供者：</span>"
                                         "<span style='color:%2;font-weight:600;"
                                         "background:%3;padding:2px 8px;border-radius:4px;'>%4</span>"
                                         "</div>")
                                    .arg(effLabelColor, greyContentMode ? effValueColor : providerColor,
                                         isDark ? "rgba(167,139,250,0.15)" : "rgba(124,58,237,0.1)",
                                         value.toHtmlEscaped()));
                }
                else if (isPath)
                {
                    html.append(QString("<div style='margin:6px 0;'>"
                                         "<div style='color:%1;font-weight:500;margin-bottom:2px;'>%2</div>"
                                         "<div style='color:%3;font-family:%4;"
                                         "word-break:break-all;white-space:pre-wrap;"
                                         "padding:4px 8px;background:%5;border-radius:3px;'>%6</div>"
                                         "</div>")
                                    .arg(effLabelColor,
                                         label.toHtmlEscaped() + (fullWidth ? "：" : ":"),
                                         effValueColor, monoFont,
                                         isDark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.03)",
                                         value.toHtmlEscaped()));
                }
                else
                {
                    html.append(QString("<div style='margin:5px 0;'>"
                                         "<span style='color:%1;font-weight:500;'>%2</span>"
                                         "<span style='color:%3;font-weight:400;'>%4</span>"
                                         "</div>")
                                    .arg(effLabelColor,
                                         label.toHtmlEscaped() + (fullWidth ? "：" : ":"),
                                         effValueColor, value.toHtmlEscaped()));
                }
            }
            else
            {
                /* 无冒号行：作为普通段落。
                 * 支持 [content] 前缀标记：遇到 [content] 行后，该行及后续所有行均以灰色渲染，
                 * 用于表示告警对话框内容，使其与结构化的进程信息区分开来。 */
                QString displayLine = line;
                if (line.startsWith("[content]"))
                {
                    greyContentMode = true;
                    displayLine = line.mid(9).trimmed();  /* 去掉 "[content]" 前缀 */
                    if (displayLine.isEmpty())
                        continue;  /* [content] 单独一行时跳过，不渲染空行 */
                }

                QString lineColor = greyContentMode ? (isDark ? "#7F8C8D" : "#95A5A6") : valueColor;
                html.append(QString("<div style='color:%1;margin:6px 0;line-height:1.5;'>%2</div>")
                                .arg(lineColor, displayLine.toHtmlEscaped()));
            }
        }
    }

    return html;
}

void LoggerPage::RefreshDetailHtml()
{
    /* 主题变化后，重新渲染当前选中项的 HTML */
    if (!m_lastSelectedIndex.isValid() || !LogModel)
    {
        LogDetailArea->clear();
        return;
    }

    QStandardItem* item = LogModel->itemFromIndex(m_lastSelectedIndex);
    if (!item)
    {
        LogDetailArea->clear();
        return;
    }

    QString detail = item->data(Qt::UserRole).toString();
    if (detail.isEmpty())
        detail = item->text();

    int level = item->data(Qt::UserRole + 1).toInt();
    if (level < 0 || level > 3)
        level = 0;

    LogDetailArea->setHtml(BuildDetailHtml(detail, (LogLevel)level));
}

void LoggerPage::UpdateTimestamps()
{
    /* 定时刷新列表视图，更新时间戳显示（如"刚刚"→"1分钟前"） */
    if (LogArea)
        LogArea->viewport()->update();
}
