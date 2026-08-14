#include "VirusScanPage.h"
#include "MainPage.h"
#include "ProtectionSettingPage.h"
#include "PublicIncluding.h"
#include "PublicPageFunction.h"
#include "PublicFunction.h"
#include "PEScan.h"

typedef int (*cl_scanfile_type)(const char* filename, const char** virname, unsigned long int* scanned,
	const struct cl_engine* engine, cl_scan_options* options);//传入文件路径；病毒引擎，执行扫描，返回值：CL_VIRUS表示有病毒；CL_CLEAN表示无病毒；

extern cl_engine* mClamAVEngine;
extern cl_scan_options mClamOptions;
extern unsigned int mClamScanned;
extern cl_scanfile_type pcl_scanfile;

// sha256
extern string* VirusNameList;
extern string* VirusSha256List;
extern int Sha256Count;
extern string* WhiteSha256List;
extern int WhiteSha256Count;
extern std::unordered_set<std::string> HasBeenScanedSha256WhiteList;
extern int HasBeenScanedCount;
extern std::unordered_map<std::string, std::string> HasBeenScanedSha256BlackList;
extern std::vector<std::string> HasBeenScanedTypeBlackList;
extern std::unordered_map<std::string, std::string> WhiteSha256ListCache;
extern int HasBeenScanedCountBlack;

// PE
extern NaiveBayesClassifier mPEModel;

extern YR_COMPILER* Yara_Compiler;
extern YR_RULES* Yara_Rules; // YARA 规则

extern BOOL ClamAV_IsReady;
extern BOOL PE_IsReady;
extern BOOL Yara_IsReady;
extern BOOL Sha256Black_IsReady;
extern BOOL Sha256White_IsReady;

extern MainPage* pMainPage;
extern VirusScanPage* pVirusScanPage;
extern ProtectionSettingPage* pProtectionSettingPage;

BOOL ScanPath(wstring nowpath, string& VirusName)
{
    string thisSha256;
    int isVirus = false;
    bool isDoYara = true;

    string nowpathA = (string)(CW2A)nowpath.c_str();

    thisSha256 = Encrypt_CalculateFileSHA256((char*)nowpathA.c_str());

#ifdef _DEBUG
    OutputDebugStringA(thisSha256.c_str());
#endif

    if (pVirusScanPage->pSHA256EngineSwitch->getIsToggled())
    {
        for (int i = 0; i < Sha256Count; i++)
        {
            if (CompareWithoutCap(VirusSha256List[i], thisSha256))
            {
                VirusName = VirusNameList[i].c_str();
                isVirus = true;
                break;
            }
        }
    }

    string lowerSha256 = thisSha256;
    std::transform(lowerSha256.begin(), lowerSha256.end(), lowerSha256.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (std::binary_search(WhiteSha256List, WhiteSha256List + WhiteSha256Count, lowerSha256))
    {
        isVirus = 2;
    }

    // 临时白名单检查
    if (!isVirus && WhiteSha256ListCache.find(lowerSha256) != WhiteSha256ListCache.end())
    {
        isVirus = 2;
    }

    if (!isVirus && !File_IsPEFile((wchar_t*)nowpath.c_str()))
    {
        HANDLE hFile;
        hFile = CreateFileW(nowpath.c_str(), GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (hFile)
        {
            LARGE_INTEGER size;
            if (!GetFileSizeEx(hFile, &size))
            {
                if (size.QuadPart >= (long long)1024 * 1024 * 100) // 超过 100 MB 的不扫描
                {
                    isDoYara = false;
                }
            }

            CloseHandle(hFile);
        }
    }

    if (isDoYara && !isVirus && Yara_IsReady && pVirusScanPage->pYaraEngineSwitch->getIsToggled())
    {
        string sVirus;

        if (Yara_ScanFile((char*)nowpathA.c_str(), sVirus))
        {
            if (strcmp(sVirus.c_str(), "Empty") != 0)
            {
                isVirus = true;
                VirusName = sVirus;
            }
        }
    }

    if (!isVirus && ClamAV_IsReady && pVirusScanPage->pClamAVEngineSwitch->getIsToggled())
    {
        char* pVirName = nullptr;
        unsigned long nPos = 0;
        int ret = pcl_scanfile((char*)nowpathA.c_str(), (const char**)&pVirName, &nPos, mClamAVEngine, &mClamOptions);

        if (ret == CL_VIRUS)
        {
            VirusName = "ClamAV/" + (string)pVirName;
            isVirus = true;
        }
    }

    if (!isVirus && PE_IsReady && pVirusScanPage->pPEEngineSwitch->getIsToggled())
    {
        PEFileAnalyzer analyzer32((char*)nowpathA.c_str());

        std::unordered_set<string> imports = analyzer32.getImportedFunctions();

        if (!imports.empty())
        {
            BOOL isHighSensitiveKill = FALSE;
            double confid = 0.0;
            isVirus = mPEModel.Predict(imports, confid);

            if (File_CheckFileSignature(nowpath))
            {
                confid -= 25;
            }
            else
            {
                if (pVirusScanPage->pHighSensitiveSwitch->getIsToggled())
                {
                    isHighSensitiveKill = TRUE;
                    isVirus = true;
                    VirusName = "Sign/Trojan.Unsigned.Generic (HIGH SENSITIVE MODEL)";
                }

                confid += 10;

                double Entropy = File_CalculateEntropy(nowpathA);

                if (Entropy >= 7.62)
                {
                    confid += int(2 * Entropy);
                }
                else
                {
                    confid -= 5;
                }

                BOOL TimeMark = FALSE, SizeMark = TRUE, IconMark = TRUE;

                SizeMark = File_IsFileSizeNormal((wchar_t*)nowpath.c_str());
                TimeMark = File_IsModifiedOverOneDay((wchar_t*)nowpath.c_str());
                IconMark = File_HasIconResource((wchar_t*)nowpath.c_str());

                if (!SizeMark) confid += 2.5; else confid -= 2.5;
                if (TimeMark) confid += 2.5; else confid -= 2.5;
                if (!IconMark) confid += 2.5; else confid -= 2.5;
            }

            if (confid > 0) isVirus = true;
            else if (!isHighSensitiveKill) isVirus = false;

            if (isVirus && !isHighSensitiveKill)
            {
                if (confid < 15)
                {
                    isVirus = false;
                }
                else
                {
                    CString confidence;
                    confidence.Format("%.2lf", confid);

                    VirusName = "Heur/PEEngine:Trojan.Generic (Confidence: " + (string)confidence + ")";
                }
            }
        }
    }

    if (isVirus == 2) isVirus = false;

    return isVirus;
}

// ScanWorker 实现
ScanWorker::ScanWorker(ScanType type, const QVariant& target, VirusScanPage* parent)
    : m_type(type), m_target(target), m_parent(parent) {
}

void ScanWorker::startScan() {
    m_virusCount = 0;

    switch (m_type) {
    case FILE_SCAN:
        scanFileList(m_target.toStringList());
        break;
    case FOLDER_SCAN:
        scanFolder(m_target.toString());
        break;
    }

    emit scanFinished(m_virusCount);
}

void ScanWorker::scanFileList(const QStringList& files) {
    int totalFiles = files.size();

    for (int i = 0; i < totalFiles; ++i) {
        if (m_parent->m_scanCancelRequested) break;

        // 处理暂停
        while (m_parent->m_scanState == VirusScanPage::PAUSED &&
            !m_parent->m_scanCancelRequested) {
            QThread::msleep(100);
        }
        if (m_parent->m_scanCancelRequested) break;

        const QString& filePath = files[i];
        emit fileScanned(filePath);

        // 执行扫描
        std::string virusName;
        bool isVirus = ScanPath(filePath.toStdWString(), virusName);

        if (isVirus) {
            m_virusCount++;
            emit virusFound(filePath, QString::fromStdString(virusName));
            m_parent->quarantineFile(filePath); // 自动隔离
        }

        emit progressUpdated(i + 1, totalFiles, m_virusCount);
    }
}

void ScanWorker::scanFolder(const QString& folderPath) {
    int totalFiles = 0;
    int currentCount = 0;

    // 统计文件总数
    scanDirectory(folderPath, totalFiles, currentCount);

    // 实际扫描
    currentCount = 0;
    m_virusCount = 0;
    scanDirectory(folderPath, currentCount, m_virusCount);
}

void ScanWorker::scanDirectory(const QString& path, int& fileCount, int& virusCount) {
    QDir dir(path);
    auto entries = dir.entryInfoList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden);

    for (const auto& entry : entries) {
        if (m_parent->m_scanCancelRequested) return;

        while (m_parent->m_scanState == VirusScanPage::PAUSED &&
            !m_parent->m_scanCancelRequested) {
            QThread::msleep(100);
        }
        if (m_parent->m_scanCancelRequested) return;

        if (entry.isDir()) {
            scanDirectory(entry.filePath(), fileCount, virusCount);
        }
        else {
            fileCount++;
            emit fileScanned(entry.filePath());
            emit progressUpdated(fileCount, 0, virusCount);

            std::string virusName;
            bool isVirus = ScanPath(entry.filePath().toStdWString(), virusName);

            if (isVirus) {
                virusCount++;
                emit virusFound(entry.filePath(), QString::fromStdString(virusName));
                m_parent->quarantineFile(entry.filePath());
            }
        }
    }
}

// VirusScanPage 实现
VirusScanPage::VirusScanPage(QWidget* parent) : BasePage(parent) {
    setupUI();
}

VirusScanPage::~VirusScanPage() {
    if (m_scanThread && m_scanThread->isRunning()) {
        m_scanCancelRequested = true;
        m_scanThread->quit();
        m_scanThread->wait();
    }
}

void VirusScanPage::setupUI() {
    // 创建自定义控件
    QWidget* customWidget = new QWidget(this);
    QVBoxLayout* customLayout = new QVBoxLayout(customWidget);

    ElaText* descText = new ElaText("定期查杀文件、文件夹，保证电脑安全。", this);
    descText->setTextPixelSize(13);

    ElaToolButton* scanButton = new ElaToolButton(this);
    scanButton->setText("自定义查杀");
    scanButton->setElaIcon(ElaIconType::Files);

    ElaMenu* scanMenu = new ElaMenu(this);
    QAction* pa = scanMenu->addElaIconAction(ElaIconType::File, "查杀文件");
    QAction* pb = scanMenu->addElaIconAction(ElaIconType::Folder, "查杀文件夹");
    connect(pa, &QAction::triggered, this, &VirusScanPage::onScanFile);
    connect(pb, &QAction::triggered, this, &VirusScanPage::onScanFolder);
    scanButton->setMenu(scanMenu);

    customLayout->addWidget(descText);
    customLayout->addSpacing(20);
    customLayout->addWidget(scanButton);
    setCustomWidget(customWidget);

    // 创建主界面
    QWidget* centralWidget = new QWidget(this);
    QVBoxLayout* mainLayout = new QVBoxLayout(centralWidget);

    // 扫描进度和状态
    m_progressBar = new ElaProgressBar(this);
    m_progressBar->setVisible(false);

    m_statusLabel = new QLabel("准备就绪...", this);
    m_countLabel = new QLabel("", this);

    // 病毒表格
    m_virusTable = new ElaTableView(this);
    m_virusModel = new QStandardItemModel(this);
    m_virusModel->setHorizontalHeaderLabels({ "文件路径", "病毒类型", "状态" });
    m_virusTable->setModel(m_virusModel);
    m_virusTable->setVisible(false);

    // 控制按钮
    m_controlButton = new QPushButton("开始扫描", this);
    m_stopButton = new QPushButton("终止", this);
    m_stopButton->setVisible(false);

    m_controlButton->connect(m_controlButton, &QPushButton::clicked, this, &VirusScanPage::onControlClicked);
    m_stopButton->connect(m_stopButton, &QPushButton::clicked, this, &VirusScanPage::onStopClicked);

    // 引擎设置
    ElaText* engineTitle = new ElaText("引擎设置", this);
    engineTitle->setTextPixelSize(20);

    createEngineOption(pYaraEngineSwitch, "Yara 引擎");
    createEngineOption(pPEEngineSwitch, "PE 导入表启发式引擎");
    createEngineOption(pSHA256EngineSwitch, "SHA256 特征码引擎");
    createEngineOption(pClamAVEngineSwitch, "ClamAV 引擎");
    createEngineOption(pHighSensitiveSwitch, "高敏感度模式");

    // 布局
    mainLayout->addWidget(m_progressBar);
    mainLayout->addWidget(m_statusLabel);
    mainLayout->addWidget(m_countLabel);
    mainLayout->addWidget(m_virusTable);

    QHBoxLayout* buttonLayout = new QHBoxLayout();
    buttonLayout->addWidget(m_controlButton);
    buttonLayout->addWidget(m_stopButton);
    mainLayout->addLayout(buttonLayout);

    mainLayout->addSpacing(20);
    mainLayout->addWidget(engineTitle);

    for (QWidget* area : m_engineAreas) {
        mainLayout->addWidget(area);
    }

    mainLayout->addStretch();
    addCentralWidget(centralWidget, true, true, 0);
}

void VirusScanPage::createEngineOption(ElaToggleSwitch*& switchWidget, const QString& name) {
    switchWidget = new ElaToggleSwitch(this);
    switchWidget->setIsToggled(true);

    ElaScrollPageArea* area = new ElaScrollPageArea(this);
    area->setFixedHeight(50);

    QHBoxLayout* layout = new QHBoxLayout(area);
    ElaText* text = new ElaText(name, this);
    text->setTextPixelSize(15);
    text->setFixedWidth(360);

    layout->addWidget(text);
    layout->addStretch();
    layout->addWidget(switchWidget);

    m_engineAreas.append(area);
}

// 扫描控制
void VirusScanPage::onScanFile() {
    if (m_scanState != IDLE) {
        toggleScanState();
        return;
    }

    QStringList files = QFileDialog::getOpenFileNames(nullptr, "选择文件", QDir::homePath(), "所有文件 (*.*)");
    if (!files.isEmpty()) {
        startScan(ScanWorker::FILE_SCAN, files);
    }
}

void VirusScanPage::onScanFolder() {
    if (m_scanState != IDLE) {
        toggleScanState();
        return;
    }

    QString folder = QFileDialog::getExistingDirectory(nullptr, "选择文件夹", QDir::homePath());
    if (!folder.isEmpty()) {
        startScan(ScanWorker::FOLDER_SCAN, folder);
    }
}

void VirusScanPage::startScan(ScanWorker::ScanType type, const QVariant& target) {
    setScanningUI(true);
    m_virusModel->removeRows(0, m_virusModel->rowCount());

    ScanWorker* worker = new ScanWorker(type, target, this);
    m_scanThread = new QThread();
    worker->moveToThread(m_scanThread);

    connect(m_scanThread, &QThread::started, worker, &ScanWorker::startScan);
    connect(worker, &ScanWorker::scanFinished, this, &VirusScanPage::onScanFinished);
    connect(worker, &ScanWorker::virusFound, this, &VirusScanPage::onVirusFound);
    connect(worker, &ScanWorker::progressUpdated, this, &VirusScanPage::onProgressUpdated);
    connect(worker, &ScanWorker::scanFinished, worker, &QObject::deleteLater);
    connect(m_scanThread, &QThread::finished, m_scanThread, &QObject::deleteLater);

    m_scanThread->start();
    m_scanState = RUNNING;
    m_controlButton->setText("暂停扫描");
    m_stopButton->setVisible(true);
}

void VirusScanPage::toggleScanState() {
    if (m_scanState == RUNNING) {
        m_scanState = PAUSED;
        m_controlButton->setText("继续扫描");
        m_statusLabel->setText("扫描已暂停");
    }
    else if (m_scanState == PAUSED) {
        m_scanState = RUNNING;
        m_controlButton->setText("暂停扫描");
        m_statusLabel->setText("继续扫描...");
    }
}

void VirusScanPage::stopScan() {
    if (m_scanState != IDLE) {
        m_scanCancelRequested = true;
        if (m_scanThread && m_scanThread->isRunning()) {
            m_scanThread->quit();
        }
    }
}

// UI 状态管理
void VirusScanPage::setScanningUI(bool scanning) {
    m_progressBar->setVisible(scanning);
    m_virusTable->setVisible(scanning);

    for (QWidget* area : m_engineAreas) {
        area->setVisible(!scanning);
    }

    if (!scanning) {
        m_controlButton->setText("开始扫描");
        m_stopButton->setVisible(false);
        m_statusLabel->setText("准备就绪...");
    }
}

void VirusScanPage::addVirusResult(const QString& filePath, const QString& virusName) {
    int row = m_virusModel->rowCount();
    m_virusModel->insertRow(row);

    m_virusModel->setItem(row, 0, new QStandardItem(filePath));

    QStandardItem* virusItem = new QStandardItem(virusName);
    virusItem->setForeground(Qt::red);
    m_virusModel->setItem(row, 1, virusItem);

    QStandardItem* statusItem = new QStandardItem("已发现");
    m_virusModel->setItem(row, 2, statusItem);

    m_virusTable->scrollToBottom();
}

// 槽函数
void VirusScanPage::onControlClicked() {
    if (m_scanState == IDLE) {
        onScanFile(); // 默认开始文件扫描
    }
    else {
        toggleScanState();
    }
}

void VirusScanPage::onStopClicked() {
    stopScan();
}

void VirusScanPage::onScanFinished(int virusCount) {
    m_scanState = IDLE;
    m_scanCancelRequested = false;
    m_scanThread = nullptr;

    setScanningUI(false);

    // 更新状态
    for (int row = 0; row < m_virusModel->rowCount(); ++row) {
        QStandardItem* statusItem = m_virusModel->item(row, 2);
        if (statusItem) {
            statusItem->setText("已隔离");
            statusItem->setForeground(Qt::darkGreen);
        }
    }

    QString message = virusCount > 0 ?
        QString("扫描完成，发现 %1 个病毒文件").arg(virusCount) :
        "扫描完成，未发现病毒";
    NewMessageBox(message, 1, 3);
}

void VirusScanPage::onVirusFound(const QString& filePath, const QString& virusName) {
    addVirusResult(filePath, virusName);
}

void VirusScanPage::onProgressUpdated(int current, int total, int virusCount) {
    m_progressBar->setMaximum(total > 0 ? total : 100);
    m_progressBar->setValue(current);

    QString text = total > 0 ?
        QString("正在扫描 (%1/%2，发现%3个病毒)").arg(current).arg(total).arg(virusCount) :
        QString("正在扫描 (%1，发现%2个病毒)").arg(current).arg(virusCount);
    m_countLabel->setText(text);
}

bool VirusScanPage::quarantineFile(const QString& filePath) {
    try {
        std::wstring wFilePath = filePath.toStdWString();
        Encrypt_EncrptFile(wFilePath);
        return true;
    }
    catch (...) {
        return false;
    }
}
