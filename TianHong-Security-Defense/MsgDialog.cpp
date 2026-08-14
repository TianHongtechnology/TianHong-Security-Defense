#include "MsgDialog.h"
#include <QPainterPath>

NotificationPopup::NotificationPopup(const QString& text, MsgType type, int duration, const QString& title, QWidget* parent)
    : QWidget(parent, Qt::FramelessWindowHint | Qt::Tool | Qt::WindowStaysOnTopHint)
    , m_text(text)
    , m_title(title)
    , m_type(type)
    , m_duration(duration)
    , m_currentProgress(0.0)
    , m_showing(false)
    , m_pressed(false)
    , m_autoCloseTimer(nullptr)
    , m_animation(nullptr)
    , m_targetX(0)
    , m_targetY(0)
{
    setAttribute(Qt::WA_TranslucentBackground);
    setAttribute(Qt::WA_ShowWithoutActivating);

    setupUi();
    setupStyle(type);

    m_progress = 0.0;

    // 动画驱动自定义 progress 属性
    m_animation = new QPropertyAnimation(this, "progress", this);
    m_animation->setDuration(ANIMATION_DURATION);
    m_animation->setEasingCurve(QEasingCurve::Linear);

    connect(m_animation, &QPropertyAnimation::valueChanged, this, [this](const QVariant& value) {
        onAnimationValueChanged(value.toReal());
        });
    connect(m_animation, &QPropertyAnimation::finished, this, &NotificationPopup::onAnimationFinished);

    // 默认点击行为：关闭窗口
    connect(this, &NotificationPopup::clicked, this, [this]() {
        if (m_showing) {
            if (m_autoCloseTimer) {
                m_autoCloseTimer->stop();
            }
            startHideAnimation();
        }
        });

    // 连接主题变化信号
    if (eTheme) {
        connect(eTheme, &ElaTheme::themeModeChanged, this, [this](ElaThemeType::ThemeMode themeMode) {
            Q_UNUSED(themeMode)
                updateThemeStyle();
            });
    }
}

void NotificationPopup::setupUi()
{
    m_contentWidget = new QWidget(this);
    m_contentWidget->setObjectName("contentWidget");

    QVBoxLayout* mainLayout = new QVBoxLayout(m_contentWidget);
    mainLayout->setContentsMargins(16, 12, 16, 12);
    mainLayout->setSpacing(8);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setSpacing(8);

    m_iconLabel = new QLabel();
    m_iconLabel->setFixedSize(24, 24);

    m_titleLabel = new QLabel();

    m_closeLabel = new QLabel();
    m_closeLabel->setText("×");
    m_closeLabel->setFixedSize(20, 20);
    m_closeLabel->setAlignment(Qt::AlignCenter);
    m_closeLabel->setCursor(Qt::PointingHandCursor);
    m_closeLabel->installEventFilter(this);

    headerLayout->addWidget(m_iconLabel);
    headerLayout->addWidget(m_titleLabel, 1);
    headerLayout->addWidget(m_closeLabel);
    mainLayout->addLayout(headerLayout);

    m_textLabel = new QLabel();
    m_textLabel->setWordWrap(true);
    mainLayout->addWidget(m_textLabel);
    mainLayout->addStretch();

    m_blockWidget = new QWidget(this);
    m_blockWidget->setAttribute(Qt::WA_StyledBackground);
}

bool NotificationPopup::eventFilter(QObject* obj, QEvent* event)
{
    if (obj == m_closeLabel && event->type() == QEvent::MouseButtonPress) {
        emit dialogClosed();
        startHideAnimation();
        return true;
    }
    return QWidget::eventFilter(obj, event);
}

void NotificationPopup::setupStyle(MsgType type)
{
    m_type = type;

    QString titleText = m_title;
    if (titleText.isEmpty()) {
        switch (type) {
        case Success:
            m_icoPath = ":/Resources/Image/right.ico";
            titleText = QString::fromUtf8("成功");
            break;
        case Warning:
            m_icoPath = ":/Resources/Image/warn.ico";
            titleText = QString::fromUtf8("警告");
            break;
        case Error:
            m_icoPath = ":/Resources/Image/error.ico";
            titleText = QString::fromUtf8("错误");
            break;
        case Info:
            m_icoPath = ":/Resources/Image/info.ico";
            titleText = QString::fromUtf8("信息");
            break;
        case Ransomware:
            m_icoPath = ":/Resources/Image/warn.ico";
            titleText = QString::fromUtf8("安全警告");
            break;
        }
    }
    else {
        // 当调用方自定义标题时，仍按类型选择图标
        switch (type) {
        case Success: m_icoPath = ":/Resources/Image/right.ico"; break;
        case Warning:
        case Ransomware: m_icoPath = ":/Resources/Image/warn.ico"; break;
        case Error: m_icoPath = ":/Resources/Image/error.ico"; break;
        case Info: m_icoPath = ":/Resources/Image/info.ico"; break;
        }
    }

    m_titleLabel->setText(titleText);
    m_textLabel->setText(m_text);

    if (QFile::exists(m_icoPath)) {
        QPixmap pixmap(m_icoPath);
        if (!pixmap.isNull()) {
            m_iconLabel->setPixmap(pixmap.scaled(24, 24, Qt::KeepAspectRatio, Qt::SmoothTransformation));
        }
    }
    else {
        m_iconLabel->setPixmap(QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation).pixmap(24, 24));
    }

    // 应用主题样式
    updateThemeStyle();
}

void NotificationPopup::updateThemeStyle()
{
    bool isDark = false;

    // 检测当前主题模式
    if (eTheme) {
        isDark = (eTheme->getThemeMode() == ElaThemeType::Dark);
    }
    else {
        // 回退：通过系统调色板判断
        QPalette palette = QApplication::palette();
        isDark = (palette.color(QPalette::Window).lightness() < 128);
    }

    // 更新色块样式
    m_blockWidget->setStyleSheet(QString(
        "background-color: %1;"
        "border-top-left-radius: 8px;"
        "border-bottom-left-radius: 8px;")
        .arg(getBlockColor(isDark)));

    // 更新内容区域样式
    m_contentWidget->setStyleSheet(QString(
        "#contentWidget {"
        "  background-color: %1;"
        "  border-top-right-radius: 8px;"
        "  border-bottom-right-radius: 8px;"
        "}").arg(getContentBgColor(isDark)));

    // 更新标题样式
    m_titleLabel->setStyleSheet(QString(
        "font-size: 15px; font-weight: bold; color: %1;")
        .arg(getTitleColor(isDark)));

    // 更新文本样式
    m_textLabel->setStyleSheet(QString(
        "font-size: 14px; color: %1; margin-left: 0px;")
        .arg(getTextColor(isDark)));

    // 更新关闭按钮样式
    m_closeLabel->setStyleSheet(QString(
        "QLabel {"
        "  color: %1;"
        "  font-size: 16px;"
        "  font-weight: bold;"
        "  border-radius: 10px;"
        "}"
        "QLabel:hover {"
        "  background-color: %2;"
        "  color: %3;"
        "}")
        .arg(getCloseBtnColor(isDark), getCloseBtnHoverBg(isDark), getCloseBtnHoverColor(isDark)));
}

// 主题颜色函数实现
QString NotificationPopup::getBlockColor(bool isDark) const
{
    if (isDark) {
        switch (m_type) {
        case Success: return "#81C784";
        case Warning: return "#FFD54F";
        case Error:   return "#EF5350";
        case Info:    return "#4FC3F7";
        case Ransomware: return "#EF5350";
        default:      return "#78909C";
        }
    }
    else {
        switch (m_type) {
        case Success: return "#4CAF50";
        case Warning: return "#FFB300";
        case Error:   return "#E53935";
        case Info:    return "#039BE5";
        case Ransomware: return "#EF5350";
        default:      return "#90A4AE";
        }
    }
}

QString NotificationPopup::getContentBgColor(bool isDark) const
{
    return isDark ? "#2C3E50" : "#FFFFFF";
}

QString NotificationPopup::getTextColor(bool isDark) const
{
    return isDark ? "#BDC3C7" : "#666666";
}

QString NotificationPopup::getTitleColor(bool isDark) const
{
    return isDark ? "#ECF0F1" : "#333333";
}

QString NotificationPopup::getCloseBtnColor(bool isDark) const
{
    return isDark ? "#95A5A6" : "#999999";
}

QString NotificationPopup::getCloseBtnHoverBg(bool isDark) const
{
    return isDark ? "rgba(255,255,255,0.1)" : "rgba(0,0,0,0.1)";
}

QString NotificationPopup::getCloseBtnHoverColor(bool isDark) const
{
    return isDark ? "#ECF0F1" : "#333333";
}

void NotificationPopup::showPopup()
{
    // 计算尺寸
    QFontMetrics fm(m_textLabel->font());
    QRect textRect = fm.boundingRect(0, 0, CONTENT_WIDTH - 60, 0, Qt::TextWordWrap, m_text);
    int textHeight = textRect.height();
    m_totalHeight = qMax(MIN_HEIGHT, textHeight + 80);
    m_totalWidth = WINDOW_WIDTH;
    setFixedSize(m_totalWidth, m_totalHeight);

    QScreen* screen = QGuiApplication::primaryScreen();
    if (!screen) return;

    QRect screenGeometry = screen->availableGeometry();
    m_targetX = screenGeometry.right() - m_totalWidth - 10;
    m_targetY = calculateDynamicY();

    // 先设置到最终位置的子控件布局，但不显示
    m_blockWidget->setGeometry(0, 0, BLOCK_WIDTH, m_totalHeight);
    m_contentWidget->setGeometry(BLOCK_WIDTH, 0, CONTENT_WIDTH, m_totalHeight);

    // 确保初始主题正确
    updateThemeStyle();

    // 窗口放到屏幕右侧外，然后显示
    move(screenGeometry.right(), m_targetY);
    show();
    setupAutoClose(m_duration);

    // 启动显示动画
    startShowAnimation(m_targetX, m_targetY);
}

int NotificationPopup::calculateDynamicY()
{
    QScreen* screen = QGuiApplication::primaryScreen();
    QRect screenGeometry = screen->availableGeometry();
    int targetY = screenGeometry.bottom() - m_totalHeight - 10;

    int currentCount = WindowsYcount.load();
    if (currentCount == 0) {
        WindowsYcount.store(targetY);
    }
    else if (currentCount - m_totalHeight - 20 > 0) {
        targetY = currentCount - m_totalHeight - 20;
        WindowsYcount.store(targetY);
    }
    else {
        WindowsYcount.store(targetY);
    }

    return targetY;
}

void NotificationPopup::startShowAnimation(int targetX, int targetY)
{
    Q_UNUSED(targetX)
        Q_UNUSED(targetY)

        m_showing = true;
    m_animation->stop();

    m_blockCurveShow = QEasingCurve(QEasingCurve::OutExpo);
    m_contentCurveShow = QEasingCurve(QEasingCurve::OutCubic);

    m_animation->setStartValue(0.0);
    m_animation->setEndValue(1.0);
    m_animation->setDuration(ANIMATION_DURATION);
    m_animation->setEasingCurve(QEasingCurve::Linear);
    m_animation->start();
}

void NotificationPopup::startHideAnimation()
{
    m_showing = false;
    m_animation->stop();

    m_blockCurveHide = QEasingCurve(QEasingCurve::InQuad);
    m_contentCurveHide = QEasingCurve(QEasingCurve::InCubic);

    m_animation->setStartValue(0.0);
    m_animation->setEndValue(1.0);
    m_animation->setDuration(ANIMATION_DURATION);
    m_animation->setEasingCurve(QEasingCurve::Linear);
    m_animation->start();
}

void NotificationPopup::onAnimationValueChanged(qreal value)
{
    qreal t = qMin(value, 1.0);

    qreal blockProgress, contentProgress;
    if (m_showing) {
        blockProgress = m_blockCurveShow.valueForProgress(t);
        contentProgress = m_contentCurveShow.valueForProgress(t);
    }
    else {
        blockProgress = m_blockCurveHide.valueForProgress(t);
        contentProgress = m_contentCurveHide.valueForProgress(t);
    }

    updateWidgetsGeometry(blockProgress, contentProgress);
}

void NotificationPopup::updateWidgetsGeometry(qreal blockProgress, qreal contentProgress)
{
    QScreen* screen = QGuiApplication::primaryScreen();
    int screenRight = screen ? screen->availableGeometry().right() : 1920;

    qreal contentDelay = 0.12;
    qreal blockDelay = 0.15;  // 色块延迟比例
    qreal adjustedContentProgress = qMin(1.0, qMax(0.0, contentProgress - contentDelay) / (1.0 - contentDelay));

    int blockX, contentX, dynamicBlockW;

    if (m_showing) {
        int windowX = screenRight - static_cast<int>((screenRight - m_targetX) * adjustedContentProgress);
        move(windowX, m_targetY);

        blockX = m_totalWidth - static_cast<int>(blockProgress * m_totalWidth);
        contentX = m_totalWidth + BLOCK_WIDTH - static_cast<int>(adjustedContentProgress * m_totalWidth);
    }
    else {
        // 内容直接使用原进度（无延迟，先动）
        contentX = BLOCK_WIDTH + static_cast<int>(contentProgress * m_totalWidth);

        // 窗口与内容同步移动（无延迟）
        int windowX = m_targetX + static_cast<int>((screenRight - m_targetX) * contentProgress);
        move(windowX, m_targetY);

        // 色块使用内容的延迟进度（后动），且永远贴在内容左侧
        qreal delayedContentProgress = qMin(1.0, qMax(0.0, contentProgress - blockDelay) / (1.0 - blockDelay));
        blockX = BLOCK_WIDTH + static_cast<int>(delayedContentProgress * m_totalWidth) - BLOCK_WIDTH;
    }

    dynamicBlockW = contentX - blockX;
    if (dynamicBlockW < 0) dynamicBlockW = 0;

    m_blockWidget->setGeometry(blockX, 0, dynamicBlockW, m_totalHeight);
    m_contentWidget->setGeometry(contentX, 0, CONTENT_WIDTH, m_totalHeight);
}

void NotificationPopup::onAnimationFinished()
{
    if (!m_showing) {
        if (WindowsYcount.load() == m_targetY) {
            WindowsYcount.store(0);
        }
        emit dialogClosed();
        deleteLater();
    }
}

void NotificationPopup::setupAutoClose(int duration)
{
    if (duration <= 0) return;

    m_autoCloseTimer = new QTimer(this);
    m_autoCloseTimer->setSingleShot(true);

    connect(m_autoCloseTimer, &QTimer::timeout, this, [this]() {
        if (m_showing) {
            startHideAnimation();
        }
        });

    m_autoCloseTimer->start(duration * 1000);
    connect(this, &NotificationPopup::dialogClosed, m_autoCloseTimer, &QTimer::stop);
}

void NotificationPopup::mousePressEvent(QMouseEvent* event)
{
    if (event->button() == Qt::LeftButton && rect().contains(event->pos())) {
        m_pressed = true;
        m_pressPos = event->pos();
        animateScale(0.95);
    }
    QWidget::mousePressEvent(event);
}

void NotificationPopup::mouseReleaseEvent(QMouseEvent* event)
{
    if (m_pressed && event->button() == Qt::LeftButton) {
        animateScale(1.0);
        if (rect().contains(event->pos())) {
            emit clicked();
        }
        m_pressed = false;
    }
    QWidget::mouseReleaseEvent(event);
}

void NotificationPopup::animateScale(qreal factor)
{
    QRect currentGeo = geometry();
    QSize newSize = currentGeo.size() * factor;
    int dx = (currentGeo.width() - newSize.width()) / 2;
    int dy = (currentGeo.height() - newSize.height()) / 2;
    QRect targetGeo(currentGeo.x() + dx, currentGeo.y() + dy, newSize.width(), newSize.height());

    QPropertyAnimation* anim = new QPropertyAnimation(this, "geometry", this);
    anim->setDuration(100);
    anim->setStartValue(currentGeo);
    anim->setEndValue(targetGeo);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void NotificationPopup::paintEvent(QPaintEvent* event)
{
    Q_UNUSED(event);

}

qreal NotificationPopup::progress() const
{
    return m_progress;
}

void NotificationPopup::setProgress(qreal progress)
{
    if (qFuzzyCompare(m_progress, progress))
        return;
    m_progress = progress;
    emit progressChanged();
}