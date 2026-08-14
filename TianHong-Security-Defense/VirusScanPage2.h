#pragma once
#include "BasePage.h"
#include "PublicIncluding.h"

// 病毒扫描页面
class VirusScanPage : public BasePage
{
    Q_OBJECT

public:
    VirusScanPage(QWidget* parent);
    ~VirusScanPage();

    // 引擎开关
    ElaToggleSwitch* pYaraEngineSwitch;
    ElaToggleSwitch* pPEEngineSwitch;
    ElaToggleSwitch* pSHA256EngineSwitch;
    ElaToggleSwitch* pClamAVEngineSwitch;
    ElaToggleSwitch* pHighSensitiveSwitch;

    bool m_scanCancelRequested = false;

    void setupUI();
    void createEngineOption(ElaToggleSwitch*& switchWidget, const QString& name);

    // 扫描控制
    void startScan(ScanWorker::ScanType type, const QVariant& target);
    void toggleScanState();
    void stopScan();
    bool quarantineFile(const QString& filePath);

    // UI状态管理
    void setScanningUI(bool scanning);
    void addVirusResult(const QString& filePath, const QString& virusName);

    // UI组件
    ElaProgressBar* m_progressBar;
    ElaTableView* m_virusTable;
    QStandardItemModel* m_virusModel;
    QLabel* m_statusLabel;
    QLabel* m_countLabel;
    QPushButton* m_controlButton;
    QPushButton* m_stopButton;

    QVector<QWidget*> m_engineAreas; // 引擎设置区域

    // 扫描状态
    enum ScanState { IDLE, RUNNING, PAUSED };
    ScanState m_scanState = IDLE;
    QThread* m_scanThread = nullptr;

private slots:
    void onScanFile();
    void onScanFolder();
    void onControlClicked();
    void onStopClicked();
    void onScanFinished(int virusCount);
    void onVirusFound(const QString& filePath, const QString& virusName);
    void onProgressUpdated(int current, int total, int virusCount);
};

// 扫描工作者
class ScanWorker : public QObject {
    Q_OBJECT
public:
    enum ScanType { FILE_SCAN, FOLDER_SCAN };

    ScanWorker(ScanType type, const QVariant& target, VirusScanPage* parent);

    void scanFileList(const QStringList& files);
    void scanFolder(const QString& folderPath);
    void scanDirectory(const QString& path, int& fileCount, int& virusCount);

    ScanType m_type;
    QVariant m_target;
    VirusScanPage* m_parent;
    int m_virusCount = 0;

public slots:
    void startScan();

signals:
    void scanFinished(int virusCount);
    void virusFound(const QString& filePath, const QString& virusName);
    void progressUpdated(int current, int total, int virusCount);
    void fileScanned(const QString& filePath);
};