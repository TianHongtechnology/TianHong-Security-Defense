#pragma once
#include "BasePage.h"
#include "PublicIncluding.h"
#include "PublicFunction.h"  // LogLevel 枚举定义在此

QT_BEGIN_NAMESPACE
class QTextBrowser;
class QTimer;
QT_END_NAMESPACE

/* 自定义代理：在日志列表项右侧显示灰色时间戳 */
class LogItemDelegate : public QStyledItemDelegate
{
    Q_OBJECT
public:
    using QStyledItemDelegate::QStyledItemDelegate;
    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override;
    QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override;

    static QString formatTimestamp(qint64 msSinceEpoch);
};

class LoggerPage : public BasePage
{
    Q_OBJECT
private:
	void CreateContentOptions(ElaToggleSwitch*& pWidget, QString Content, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType);

public:
	LoggerPage(QWidget* parent);
	~LoggerPage();

	ElaListView* LogArea;
	QStandardItemModel* LogModel;
	QTextBrowser* LogDetailArea;  // 右侧详情面板（支持 HTML 富文本层次化展示）

private slots:
	void OnLogSelectionChanged(const QModelIndex& current, const QModelIndex& previous);
	void OnThemeModeChanged(ElaThemeType::ThemeMode themeMode);
	void UpdateTimestamps();

private:
	QModelIndex m_lastSelectedIndex;  // 记录上次选中项，主题变化时重绘
	QTimer* m_timestampTimer;
	LogItemDelegate* m_delegate;
	QString BuildDetailHtml(const QString& plainDetail, LogLevel level) const;
	void RefreshDetailHtml();
	void ApplyThemeStyle();
};
