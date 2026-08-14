#pragma once
#include "BasePage.h"
#include "PublicIncluding.h"

class ProtectionSettingPage : public BasePage
{
private:
	void CreateContentOptions(ElaToggleSwitch*& pWidget, QString Content, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType, ElaProgressRing** progressRing = nullptr);
	void CreateContentOptionsWithRoller(ElaRoller*& pWidget, QString Content, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType, QStringList strList);

public:
	ProtectionSettingPage(QWidget* parent);
	~ProtectionSettingPage();

	ElaToggleSwitch* pRegistrySwitch;
	ElaToggleSwitch* pFileSwitch;
	ElaToggleSwitch* pProcessSwitch;
	ElaToggleSwitch* pMemorySwitch;
	ElaToggleSwitch* pDriverLoadSwitch;
	ElaToggleSwitch* pDirectSyscallSwitch;
	ElaToggleSwitch* pIsUsingSafeDesktopSwitch;
	ElaToggleSwitch* pDllProtectionSwitch;
	ElaToggleSwitch* pDriverProtectionSwitch;
	ElaToggleSwitch* pIsFullScanSwitch;
	ElaToggleSwitch* pBehaviorDetectionSwitch;
	ElaToggleSwitch* pSilentModeSwitch;
	ElaToggleSwitch* pExtractFilesSwitch;
	ElaToggleSwitch* pRansomProtectionSwitch;
	ElaToggleSwitch* pDcomProtectionSwitch;         // DCOM防护

	ElaRoller* pHeurSensitivity;

	ElaProgressRing* pDriverProtectionRing;
	ElaProgressRing* pRansomProtectionRing;
};