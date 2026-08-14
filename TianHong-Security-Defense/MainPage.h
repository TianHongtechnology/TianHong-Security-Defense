#pragma once
#include "BasePage.h"
#include "PublicIncluding.h"
#include "ActiveIcon.h"
#include "PublicFunction.h"
#include <QLabel>

class MainPage : public ElaScrollPage
{
public:
	enum class StatusLevel {
		Success = 0,
		Warn = 1,
		Critical = 2,
		Error = 3
	};

	enum class StatusSource {
		ProtectionSwitches,
		R3R0Protection,
		Threat,
		LoadFailure
	};

	MainPage(QWidget* parent);
	~MainPage();

	ActiveIcon::StateIndicatorWidget* mIndicator;

	void setSourceStatus(StatusSource source, StatusLevel level, const QString& message = QString());
	void refreshProtectionStatus();

	QLabel* mStatusText;
	QLabel* mSubText;
	QLabel* mStatusBadgeText;
	QWidget* mStatusBadge;

	// 快捷操作按钮文本（跟随主题换色）
	QLabel* m_quickPanelTitle = nullptr;
	QVector<QLabel*> m_quickBtnTitles;
	QVector<QLabel*> m_quickBtnDescs;

	InfoBar* mInfoBar;
	QWidget* m_infoBarPlaceholder = nullptr;

private:
	void recalcStatus();
	void setDisplayStatus(StatusLevel level, const QString& message, const QString& detail);
	void updateWarningInfoBar(StatusLevel level, const QString& message);
	void updateSourceInternal(StatusSource source, StatusLevel level, const QString& message);

	QTimer* m_refreshTimer = nullptr;

	// 各来源当前状态（避免 enum class 作为 QMap 键的编译问题）
	StatusLevel m_levelProtectionSwitches = StatusLevel::Success;
	QString m_msgProtectionSwitches;
	StatusLevel m_levelR3R0 = StatusLevel::Success;
	QString m_msgR3R0;
	StatusLevel m_levelThreat = StatusLevel::Success;
	QString m_msgThreat;
	StatusLevel m_levelLoadFailure = StatusLevel::Success;
	QString m_msgLoadFailure;

	int m_warningInfoBarId = -1;
};
