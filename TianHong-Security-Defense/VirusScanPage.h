#pragma once
#include "BasePage.h"
#include "PublicIncluding.h"
#include <QStackedWidget>

class VirusScanPage : public BasePage
{
    Q_OBJECT
private:
	void CreateEngineOptions(ElaToggleSwitch*& pWidget, QString EngineName, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType);
    void CreateEngineOptionsWithRing(ElaToggleSwitch*& pWidget, QString EngineName, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType, ElaProgressRing*& progressBusyTransparentRing);
	void createCustomWidget(QString desText);
  // 增加记录：支持传入主文件路径和提取文件路径（提取文件可为空）
    void addVirusRecord(const QString& virusName, const QString& mainFilePath, const QString& extractedFilePath = QString(), const quint32 PID = 0);
    // 增量添加：支持用单独的提取文件路径列表避免分割字符串
    void appendVirusRecords(const QStringList& virusNames, const QStringList& mainFilePaths, const QStringList& extractedFilePaths = QStringList(), bool isEnablePID = false, vector<quint32> PIDList = { 0 });

	QPropertyAnimation* progressAnimation;

protected:
    void resizeEvent(QResizeEvent* event) override;

public:
	VirusScanPage(QWidget* parent);
	~VirusScanPage();

	ElaProgressBar* pScanProgressBar;
	ElaToggleSwitch* pYaraEngineSwitch;
	ElaToggleSwitch* pPEEngineSwitch;
	ElaToggleSwitch* pSHA256EngineSwitch;
	ElaToggleSwitch* pClamAVEngineSwitch;
	ElaToggleSwitch* pScriptEngineSwitch;
	ElaToggleSwitch* pHighSensitiveSwitch;
    ElaToggleSwitch* pExtraPEEngineSwitch;

    ElaProgressRing* pClamAVEngineRing;
    ElaProgressRing* pYaraEngineRing;
    ElaProgressRing* pPEEngineRing;

	ElaToolButton* documentationButton;

	ElaPushButton* pButtonLeft, * pButtonRight, * pButtonDecrypt;
	ElaPushButton* pButtonAddWhite;

	ElaTableView* pVirusTable;
	QStandardItemModel* pVirusTableModel;

	ElaScrollPageArea* spYaraEngineSwitch, * spPEEngineSwitch, * spSHA256EngineSwitch, * spClamAVEngineSwitch, * spScriptEngineSwitch, * spHighSensitiveSwitch, * spExtraPEEngineSwitch;

	ElaText* EngineMainTitle;

	ElaText* pProgressDesc;

    ElaDrawerArea* mDrawer1;

    QStackedWidget* m_stackedWidget;  // 页面切换容器
    QWidget* m_scanPageWidget;        // 扫描页面
    QWidget* m_resultPageWidget;      // 结果页面
    QLabel* resultIconLabel;
    QLabel* resultTitleLabel;
    QWidget* resultDetailContainer = nullptr;  // 详情面板容器
    ElaPushButton* resultBackButton;

	QWidget* m_scanLoadingOverlay;     // 扫描加载遮罩
	ElaProgressRing* m_scanLoadingRing; // 扫描加载动画

    void showScanResultView(bool clean, int totalScanned, int virusHandled);
    void updateResultViewStyle();
    void updateScanLoadingOverlayStyle();  // 根据主题更新遮罩背景与文字颜色
	void showScanLoading(const QString& text = QString());
	void hideScanLoading();

    // 当前扫描参数指针，用于终止扫描时通知工作线程停止领取新文件
    void* m_pCurrentScanParam = nullptr;
    int   m_nCurrentScanType = 0; // 1=WorkerTParam, 2=DirWorkerTParam, 3=ProcessWorkerTParam

    // 当前活跃的扫描进度轮询定时器（用于终止扫描时立即停止并替换为快速停止轮询）
    QTimer* m_pScanCheckTimer = nullptr;

    // ===== 快速扫描多阶段指示器 =====
    QWidget* m_quickScanPhaseBar = nullptr;   // 阶段卡片容器
    struct QuickScanPhaseCard {
        QWidget* card = nullptr;
        QLabel* titleLabel = nullptr;
        ElaProgressRing* ring = nullptr;
        QLabel* statusLabel = nullptr;
    };
    QList<QuickScanPhaseCard> m_quickScanPhaseCards;
    int m_quickScanCurrentPhase = -1;        // 当前正在执行的阶段索引
    bool m_bQuickScanMode = false;            // 是否处于快速扫描模式
    int m_quickScanTotalThreats = 0;          // 快速扫描累计威胁数

    // ===== 快速扫描预收集文件与整体进度跟踪 =====
    QStringList m_quickScanStartupFiles;       // 预收集的启动项文件
    QStringList m_quickScanScheduledTaskFiles;  // 预收集的计划任务文件
    QStringList m_quickScanUserDirFiles;        // 预收集的用户目录文件
    int m_quickScanTotalFiles = 0;              // 所有阶段文件总数（进度条最大值）
    int m_quickScanCumulativeScanned = 0;       // 已完成阶段的累计扫描数（当前阶段的起始偏移）
    int m_quickScanPhase0Count = 0;             // 阶段0（进程扫描）的文件数

    bool m_bScanPreparing = false;              // 是否处于扫描准备阶段（收集文件列表期间），用于准备阶段立即响应终止扫描
    quint64 m_scanGeneration = 0;               // 扫描代数：每次发起新扫描或准备阶段终止时自增，用于作废旧 watcher 回调，防止干扰新扫描

    void showQuickScanPhaseBar(bool show);
    void updateQuickScanPhaseCard(int index, const QString& status, bool scanning);
    void setQuickScanPhaseDone(int index, int threatCount);
    void startQuickScanPhase(int phase);
    void finishQuickScan();
};

class CheckBoxDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit CheckBoxDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        // 只对第一列绘制复选框
        if (index.column() == 0) {
            // 保存painter状态
            painter->save();

            // 设置抗锯齿
            painter->setRenderHint(QPainter::Antialiasing, true);
            painter->setRenderHint(QPainter::SmoothPixmapTransform, true);

            // 计算复选框位置（居中）
            QRect checkRect = getCheckBoxRect(option);

            // 获取复选框状态
            Qt::CheckState state = static_cast<Qt::CheckState>(index.data(Qt::CheckStateRole).toInt());
            bool checked = (state == Qt::Checked);

            // 绘制背景
            QColor bgColor = checked ? QColor(65, 148, 255) : QColor(240, 240, 240);
            QColor borderColor = checked ? QColor(45, 128, 235) : QColor(200, 200, 200);

            painter->setPen(QPen(borderColor, 1.5));
            painter->setBrush(bgColor);
            painter->drawRoundedRect(checkRect, 4, 4);

            // 绘制勾选标记
            if (checked) {
                painter->setPen(QPen(Qt::white, 2));
                painter->setBrush(Qt::NoBrush);

                // 绘制对勾
                QPainterPath path;
                path.moveTo(checkRect.left() + checkRect.width() * 0.3, checkRect.center().y());
                path.lineTo(checkRect.left() + checkRect.width() * 0.45, checkRect.bottom() - checkRect.height() * 0.3);
                path.lineTo(checkRect.right() - checkRect.width() * 0.3, checkRect.top() + checkRect.height() * 0.3);
                painter->drawPath(path);
            }

            painter->restore();
        }
        else {
            // 其他列使用默认绘制
            QStyledItemDelegate::paint(painter, option, index);
        }
    }

    bool editorEvent(QEvent* event, QAbstractItemModel* model, const QStyleOptionViewItem& option, const QModelIndex& index) override
    {
        // 只处理第一列的鼠标事件
        if (index.column() == 0 && event->type() == QEvent::MouseButtonRelease) {
            QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
            QRect checkRect = getCheckBoxRect(option);

            // 检查是否点击在复选框区域内 - 使用相同的矩形计算
            if (checkRect.contains(mouseEvent->pos())) {
                // 切换复选框状态
                Qt::CheckState currentState = static_cast<Qt::CheckState>(index.data(Qt::CheckStateRole).toInt());
                Qt::CheckState newState = (currentState == Qt::Checked) ? Qt::Unchecked : Qt::Checked;
                model->setData(index, newState, Qt::CheckStateRole);

                // 请求视图更新
                emit const_cast<QAbstractItemModel*>(model)->dataChanged(index, index);
                return true;
            }
        }
        return QStyledItemDelegate::editorEvent(event, model, option, index);
    }

private:
    QRect getCheckBoxRect(const QStyleOptionViewItem& option) const
    {
        // 使用与paint方法完全相同的计算逻辑
        int size = qMin(option.rect.width(), option.rect.height()) - 8;
        return QRect(option.rect.center() - QPoint(size / 2, size / 2), QSize(size, size));
    }
};

// 病毒名称列委托：暗红色圆角矩形框突出显示
class VirusNameDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    explicit VirusNameDelegate(QObject* parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setRenderHint(QPainter::TextAntialiasing, true);

        // 获取显示文本
        QString text = index.data(Qt::DisplayRole).toString();
        if (text.isEmpty()) {
            painter->restore();
            return;
        }

        // 计算完整文本所需的尺寸
        QFont font = painter->font();
        font.setBold(true);
        painter->setFont(font);
        QFontMetrics fm(font);
        int fullTextWidth = fm.horizontalAdvance(text);
        int textHeight = fm.height();

        // 圆角矩形内边距
        int paddingH = 12;
        int paddingV = 5;
        int fullRectWidth = fullTextWidth + paddingH * 2;
        int rectHeight = textHeight + paddingV * 2;

        // 单元格可用宽度（左右各留边距）
        QRect cellRect = option.rect;
        int sideMargin = 4;
        int maxAvailableWidth = cellRect.width() - sideMargin * 2;

        // 安全余量，避免因字体渲染导致最后几个字符被截断
        const int SAFE_EXTRA = 0;
        bool canFitFullText = (fullRectWidth + SAFE_EXTRA) <= maxAvailableWidth;

        QString displayText;
        int actualRectWidth;
        int actualTextWidth;

        if (canFitFullText) {
            // 完整文本可以安全放下
            displayText = text;
            actualRectWidth = fullRectWidth;
            actualTextWidth = fullTextWidth;
        }
        else {
            // 完整文本放不下，需要截断
            int maxTextWidth = maxAvailableWidth - paddingH * 2 - SAFE_EXTRA; // 同样为截断预留余量
            if (maxTextWidth <= 0) {
                displayText = "...";
                actualTextWidth = fm.horizontalAdvance("...");
                actualRectWidth = actualTextWidth + paddingH * 2;
            }
            else {
                displayText = fm.elidedText(text, Qt::ElideRight, maxTextWidth);
                actualTextWidth = fm.horizontalAdvance(displayText);
                actualRectWidth = actualTextWidth + paddingH * 2;
            }
        }

        // 最终确保矩形不超出单元格
        if (actualRectWidth > maxAvailableWidth) {
            actualRectWidth = maxAvailableWidth;
        }

        // 计算绘制位置：靠左对齐，垂直居中
        int x = cellRect.left() + sideMargin;
        int y = cellRect.top() + (cellRect.height() - rectHeight) / 2;
        QRect badgeRect(x, y, actualRectWidth, rectHeight);

        // 绘制暗红色圆角矩形背景
        painter->setBrush(QColor(180, 40, 50));
        painter->setPen(Qt::NoPen);
        painter->drawRoundedRect(badgeRect, 6, 6);

        // 绘制文字（白色，居中）
        painter->setPen(Qt::white);
        QRect textRect = badgeRect.adjusted(paddingH, 0, -paddingH, 0);
        painter->drawText(textRect, Qt::AlignCenter | Qt::AlignVCenter, displayText);

        painter->restore();
    }

    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        QString text = index.data(Qt::DisplayRole).toString();
        QFontMetrics fm(option.font);
        int textWidth = fm.horizontalAdvance(text);
        int textHeight = fm.height();
        // 最小宽度保证短文本也有足够空间，最大不限宽由列宽决定
        return QSize(qMax(textWidth + 24, 120), textHeight + 14);
    }
};