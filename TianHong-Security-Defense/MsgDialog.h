#pragma once
#include "PublicIncluding.h"

// 全局变量
static std::atomic<int> WindowsYcount{ 0 };
const int WINDOW_WIDTH = 450;
const int ANIMATION_DURATION = 800;

class NotificationPopup : public QWidget
{
    Q_OBJECT
        Q_PROPERTY(qreal progress READ progress WRITE setProgress NOTIFY progressChanged)

public:
    enum MsgType {
        Success = 1,
        Warning = 2,
        Error = 3,
        Info = 4,
        Ransomware = 5
    };

    explicit NotificationPopup(const QString& text, MsgType type, int duration = 3, const QString& title = QString(), QWidget* parent = nullptr);
    ~NotificationPopup() = default;

    void showPopup();

signals:
    void clicked();
    void dialogClosed();
    void progressChanged();

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;
    void paintEvent(QPaintEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;

private slots:
    void onAnimationValueChanged(qreal value);
    void onAnimationFinished();

private:
    void setupUi();
    void setupStyle(MsgType type);
    void updateThemeStyle();  // 更新主题样式
    void startShowAnimation(int targetX, int targetY);
    void startHideAnimation();
    void updateWidgetsGeometry(qreal blockProgress, qreal contentProgress);
    void animateScale(qreal factor);
    void setupAutoClose(int duration);
    int calculateDynamicY();

    // UI 组件
    QWidget* m_blockWidget;
    QWidget* m_contentWidget;
    QLabel* m_iconLabel;
    QLabel* m_titleLabel;
    QLabel* m_textLabel;
    QLabel* m_closeLabel;

    // 动画相关
    QPropertyAnimation* m_animation;
    qreal m_currentProgress;
    bool m_showing;
    int m_duration;

    // 尺寸常量
    static const int BLOCK_WIDTH = 12;
    static const int CONTENT_WIDTH = 438;
    static const int MIN_HEIGHT = 80;
    int m_totalWidth;
    int m_totalHeight;

    // 位置信息
    int m_targetX;
    int m_targetY;

    // 缓动曲线
    QEasingCurve m_blockCurveShow;
    QEasingCurve m_contentCurveShow;
    QEasingCurve m_blockCurveHide;
    QEasingCurve m_contentCurveHide;

    // 外观
    QString m_icoPath;
    QString m_text;
    QString m_title;
    MsgType m_type;

    // 交互状态
    bool m_pressed;
    QPoint m_pressPos;

    qreal m_progress;
    void setProgress(qreal progress);

    // 自动关闭
    QTimer* m_autoCloseTimer;

    // 主题相关颜色函数
    QString getBlockColor(bool isDark) const;
    QString getContentBgColor(bool isDark) const;
    QString getTextColor(bool isDark) const;
    QString getTitleColor(bool isDark) const;
    QString getCloseBtnColor(bool isDark) const;
    QString getCloseBtnHoverBg(bool isDark) const;
    QString getCloseBtnHoverColor(bool isDark) const;
    qreal progress() const;
};

inline void MyShowMessageBox(const QString& text, int type = 1, int duration = 3, const QString& title = QString())
{
    auto* popup = new NotificationPopup(text, static_cast<NotificationPopup::MsgType>(type), duration, title);

    QObject::connect(popup, &NotificationPopup::dialogClosed, [popup]() {
        int y = popup->y();
        if (WindowsYcount.load() == y) {
            WindowsYcount.store(0);
        }
        });

    popup->showPopup();
}