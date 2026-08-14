#pragma once
#include "BasePage.h"
#include "PublicIncluding.h"
#include "PublicFunction.h"

class WhitelistPage : public BasePage
{
    Q_OBJECT
public:
    explicit WhitelistPage(QWidget* parent = nullptr);
    ~WhitelistPage() override;

    // 刷新白名单表格（从 WhiteSha256ListCache、WhiteDirListCache 和 WhitePathListCache 重新读取）
    void refreshWhitelist();

protected:
    void showEvent(QShowEvent* event) override;

private slots:
    void OnRemoveSelected();
    void OnRemoveAll();
    void OnAddFile();
    void OnAddFolder();
    void OnThemeModeChanged(ElaThemeType::ThemeMode themeMode);

private:
    void ApplyThemeStyle();
    QIcon LoadFileIcon(const QString& filePath);
    QIcon LoadFolderIcon();

    ElaTableView* m_tableView;
    QStandardItemModel* m_model;
    ElaPushButton* m_refreshBtn;
    ElaPushButton* m_addFileBtn;
    ElaPushButton* m_addFolderBtn;
    ElaPushButton* m_removeBtn;
    ElaPushButton* m_removeAllBtn;
    ElaText* m_countLabel;
};
