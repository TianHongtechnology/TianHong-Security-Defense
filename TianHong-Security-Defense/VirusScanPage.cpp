#include "VirusScanPage.h"
#include "MainPage.h"
#include "ProtectionSettingPage.h"
#include "PublicIncluding.h"
#include "PublicPageFunction.h"
#include "PublicFunction.h"
#include "PEScan.h"
#include "PasswordAskDialog.h"
#include "ArchiveManager.h"
#include "QProgressDialog"
#include <shlobj.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")

const int MAX_SCAN_THREAD = 15;

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
extern string* VirusInformation;
extern std::atomic<int> VirusInfoCount;
extern std::unordered_set<std::string> HasBeenScanedSha256WhiteList;
extern std::unordered_map<std::string, std::string> HasBeenScanedSha256BlackList;
extern std::vector<std::string> HasBeenScanedTypeBlackList;
extern CRITICAL_SECTION g_csScanCache;

// PE
extern LightGBMClassifier mPEModel;

extern YR_COMPILER* Yara_Compiler;
extern YR_RULES* Yara_Rules; // YARA 规则
extern YR_RULES* Yara_MemRules; // YARA 规则Memory版

extern BOOL ClamAV_IsReady;
extern BOOL PE_IsReady;
extern BOOL Yara_IsReady;
extern BOOL Yara_MemIsReady;
extern BOOL Sha256Black_IsReady;
extern BOOL Sha256White_IsReady;

extern short isLoadReady;

// ClamAV手动加载线程函数
extern DWORD WINAPI LoadClamAVThread(LPVOID lpParam);

// 日志函数
extern void Log_AddLogSimple(QString Summary, LogLevel level, QString Provider);

extern MainPage* pMainPage;
extern VirusScanPage* pVirusScanPage;
extern ProtectionSettingPage* pProtectionSettingPage;
extern std::unordered_map<std::string, std::string> WhiteSha256ListCache;
extern BOOL g_bExtractFilesEnabled;

std::atomic<ScanState> mScanState{ ssPrepared };
std::atomic<int> RunningWorkerT = 0;
std::atomic<bool> g_scanCancelRequested(false); // 用户点击“终止扫描”后快速通知工作线程退出
BOOL CheckBoxAllChose = FALSE;
std::atomic<bool> ClamAV_IsLoading(false); // ClamAV手动加载状态标志

QMutex g_ScanCacheMutex;

BOOL IsPeFileValid(LPCSTR lpszPeFile)
{
	HANDLE hFile = CreateFileA(lpszPeFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}

	// 读取DOS头
	IMAGE_DOS_HEADER dosHeader;
	DWORD dwRead;
	if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &dwRead, NULL) || dwRead != sizeof(dosHeader))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// 检查MZ签名
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// 移动到PE头
	if (SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// 读取PE签名
	DWORD dwPeSignature;
	if (!ReadFile(hFile, &dwPeSignature, sizeof(dwPeSignature), &dwRead, NULL) || dwRead != sizeof(dwPeSignature))
	{
		CloseHandle(hFile);
		return FALSE;
	}

	// 检查PE签名
	if (dwPeSignature != IMAGE_NT_SIGNATURE)
	{
		CloseHandle(hFile);
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

BOOL ExtractSpecificResources(LPCSTR lpszPeFile, LPCSTR lpszOutputDir)
{
	// 验证PE文件有效性
	if (!IsPeFileValid(lpszPeFile))
	{
		return FALSE;
	}

	// 定义上下文结构
	struct CallbackContext {
		LPCSTR outputDir;
		HMODULE hModule;      // 保存模块句柄
		volatile LONG errorCount;
		volatile BOOL bModuleValid;
	};

	CallbackContext context;
	context.outputDir = lpszOutputDir;
	context.hModule = NULL;
	context.errorCount = 0;
	context.bModuleValid = TRUE;

	// 将PE文件作为数据文件加载
	HMODULE hModule = LoadLibraryExA(lpszPeFile, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (hModule == NULL)
	{
		return FALSE;
	}
	context.hModule = hModule;

	// 使用 __try/__except 保护整个枚举过程
	__try {
		BOOL result = EnumResourceTypesA(hModule,
			[](HMODULE hModule, LPSTR lpszType, LONG_PTR lParam) -> BOOL {
				CallbackContext* pCtx = (CallbackContext*)lParam;
				if (!pCtx || !pCtx->bModuleValid) return FALSE;

				// 枚举资源名称
				return EnumResourceNamesA(hModule, lpszType,
					[](HMODULE hModule, LPCSTR lpszType, LPSTR lpszName, LONG_PTR lParam) -> BOOL {
						CallbackContext* pCtx = (CallbackContext*)lParam;
						if (!pCtx || !pCtx->bModuleValid) return FALSE;

						__try {
							HRSRC hResource = FindResourceA(hModule, lpszName, lpszType);
							if (hResource == NULL) return TRUE;

							HGLOBAL hGlobal = LoadResource(hModule, hResource);
							if (hGlobal == NULL) return TRUE;

							LPVOID lpResourceData = LockResource(hGlobal);
							if (lpResourceData == NULL) return TRUE;

							DWORD dwSize = SizeofResource(hModule, hResource);
							if (dwSize == 0 || dwSize > 50 * 1024 * 1024) {
								return TRUE;
							}

							// 使用静态缓冲区
							char szResourceName[64] = { 0 };
							char szOutputPath[MAX_PATH] = { 0 };

							// 安全构建文件名
							if (IS_INTRESOURCE(lpszName)) {
								sprintf_s(szResourceName, sizeof(szResourceName),
									"res_%u", (DWORD)(ULONG_PTR)lpszName);
							}
							else {
								size_t srcLen = min(strlen(lpszName), sizeof(szResourceName) - 1);
								strncpy_s(szResourceName, sizeof(szResourceName),
									lpszName, srcLen);
								// 过滤非法字符
								for (char* p = szResourceName; *p; ++p) {
									if (*p == '\\' || *p == '/' || *p == ':' ||
										*p == '*' || *p == '?' || *p == '"' ||
										*p == '<' || *p == '>' || *p == '|') {
										*p = '_';
									}
								}
							}

							// 构建输出路径
							if (IS_INTRESOURCE(lpszType)) {
								sprintf_s(szOutputPath, sizeof(szOutputPath),
									"%s\\%s.bin", pCtx->outputDir, szResourceName);
							}
							else {
								sprintf_s(szOutputPath, sizeof(szOutputPath),
									"%s\\%s.%s", pCtx->outputDir, szResourceName, lpszType);
							}

							// 创建目录
							CreateDirectoryA(pCtx->outputDir, NULL);

							// 写入文件
							HANDLE hFile = CreateFileA(szOutputPath, GENERIC_WRITE, 0, NULL,
								CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
							if (hFile != INVALID_HANDLE_VALUE) {
								DWORD dwWritten;
								WriteFile(hFile, lpResourceData, dwSize, &dwWritten, NULL);
								CloseHandle(hFile);
							}

						}
						__except (EXCEPTION_EXECUTE_HANDLER) {
							InterlockedIncrement(&pCtx->errorCount);
							return TRUE;
						}

						return TRUE;
					},
					(LONG_PTR)pCtx);
			},
			(LONG_PTR)&context);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// 枚举过程中发生异常
		context.bModuleValid = FALSE;
	}

	// 安全释放模块
	if (context.hModule != NULL) {
		__try {
			FreeLibrary((HMODULE)context.hModule);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// 释放时发生异常，忽略
		}
		context.hModule = NULL;
	}

	return (context.errorCount == 0);
}

// 递归提取资源，支持多层嵌套提取。collectedFiles 返回所有被提取出的文件（包括中间层）。
static bool ExtractResourcesRecursive(const std::string& peFile, const std::string& outDir, int depth, int maxDepth, std::vector<std::string>& collectedFiles)
{
	if (depth > maxDepth) return false;
	if (!IsPeFileValid(peFile.c_str())) return false;

	// 确保输出目录存在
	CreateDirectoryA(outDir.c_str(), NULL);

	if (!ExtractSpecificResources(peFile.c_str(), outDir.c_str())) return false;

	// 列举输出目录内所有文件，收集并对可再提取的PE文件进行递归提取
	WIN32_FIND_DATAA findData;
	string pattern = outDir + "\\*";
	HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE) return true; // 没有文件也算成功

	do {
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
		string child = outDir + "\\" + findData.cFileName;
		// 记录被提取出的文件
		collectedFiles.push_back(child);

		// 如果是PE且允许更深度的提取，则为该文件创建子目录并递归提取
		if (depth + 1 <= maxDepth && IsPeFileValid(child.c_str())) {
			string subOut = outDir + "\\_sub_extract_" + to_string(depth + 1) + "_" + findData.cFileName;
			// 保证子目录唯一（若存在先删除）
			CreateDirectoryA(subOut.c_str(), NULL);
			ExtractResourcesRecursive(child, subOut, depth + 1, maxDepth, collectedFiles);
		}
	} while (FindNextFileA(hFind, &findData));

	FindClose(hFind);
	return true;
}

// 递归删除目录及其内容（用于清理临时提取目录）
static void RemoveDirectoryRecursiveA(const std::string& dirPath)
{
	WIN32_FIND_DATAA findData;
	string pattern = dirPath + "\\*";
	HANDLE hFind = FindFirstFileA(pattern.c_str(), &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		RemoveDirectoryA(dirPath.c_str());
		return;
	}

	do {
		string name = findData.cFileName;
		if (name == "." || name == "..") continue;
		string full = dirPath + "\\" + name;
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			RemoveDirectoryRecursiveA(full);
		}
		else {
			// 尝试删除文件属性只读标志
			SetFileAttributesA(full.c_str(), FILE_ATTRIBUTE_NORMAL);
			DeleteFileA(full.c_str());
		}
	} while (FindNextFileA(hFind, &findData));

	FindClose(hFind);
	// 最后删除目录本身
	SetFileAttributesA(dirPath.c_str(), FILE_ATTRIBUTE_NORMAL);
	RemoveDirectoryA(dirPath.c_str());
}

// 递归获取文件夹下所有文件
void GetAllFilesInFolder(const QString& folderPath, QStringList& fileList, bool recursive)
{
	QString searchPath = folderPath + "\\*";

	WIN32_FIND_DATAW findData;
	HANDLE hFind = FindFirstFileW((LPCWSTR)searchPath.utf16(), &findData);

	if (hFind == INVALID_HANDLE_VALUE) {
		return;
	}

	do {
		if (wcscmp(findData.cFileName, L".") == 0 ||
			wcscmp(findData.cFileName, L"..") == 0) {
			continue;
		}

		QString qPath = folderPath + "\\" + QString::fromWCharArray(findData.cFileName);

		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (recursive) {
				GetAllFilesInFolder(qPath, fileList, recursive);
			}
		}
		else {
			fileList.append(qPath);
		}
	} while (FindNextFileW(hFind, &findData));

	FindClose(hFind);
}

struct WorkerTParam
{
	QStringList fileNames;

	int AllVirusCount = 0;
	int HasScanedCount = 0;

	QStringList VirusPath;
	QStringList VirusName;
	QStringList ExtractedFilePaths;
	QString currentScanningFile;

	bool onlyPEEnabled;
	bool sha256Enabled;
	bool yaraEnabled;
	bool clamavEnabled;
	bool scriptEnabled;  // 脚本检测引擎开关

	QMutex mutex;
};

struct DirWorkerTParam
{
	QString folderPath;

	QMutex fileListMutex;
	QStringList allFiles;
	int currentFileIndex = 0;

	QMutex resultMutex;
	int AllVirusCount = 0;
	int HasScanedCount = 0;
	QStringList VirusPath;
	QStringList VirusName;
	QStringList ExtractedFilePaths;
	QString currentScanningFile;

	bool onlyPEEnabled;
	bool sha256Enabled;
	bool yaraEnabled;
	bool clamavEnabled;
	bool scriptEnabled;  // 脚本检测引擎开关

	bool stopRequested = false;
};

struct ProcessWorkerTParam
{
	QStringList fileNames;
	std::vector<quint32> pidList;
	std::unordered_map<QString, std::vector<quint32>> fileToPidsMap;

	QMutex fileListMutex;
	int currentFileIndex = 0;
	bool stopRequested = false;

	int AllVirusCount = 0;
	int HasScanedCount = 0;

	QStringList VirusPath;
	QStringList VirusName;
	QStringList ExtractedFilePaths;
	std::vector<quint32> VirusPidList;
	QString currentScanningFile;

	bool onlyPEEnabled;
	bool sha256Enabled;
	bool yaraEnabled;
	bool clamavEnabled;
	bool scriptEnabled;  // 脚本检测引擎开关

	QMutex mutex;

	// 跨线程共享：记录已完成内存扫描的 PID，避免多线程重复扫描同一进程内存
	QMutex processedPidsMutex;
	std::vector<DWORD> processedPids;
};

// 通知工作线程停止领取新文件（已在线程中的当前文件仍需完成或取消）
static inline void SetScanParamStopRequested(void* pParam, int type)
{
	if (!pParam) return;
	if (type == 2) {
		((DirWorkerTParam*)pParam)->stopRequested = true;
	}
	else if (type == 3) {
		((ProcessWorkerTParam*)pParam)->stopRequested = true;
	}
	// WorkerTParam (type==1) 通过 g_scanCancelRequested 控制，无需 stopRequested
}

static QString AskPasswordFromUI(const QString& archivePath) {
	QString password;
	QEventLoop loop;
	QMetaObject::invokeMethod(QApplication::instance(), [&]() {
		ElaPasswordDialog dlg(archivePath);
		if (dlg.exec() == QDialog::Accepted) {
			password = dlg.password();
		}
		loop.quit();
		}, Qt::BlockingQueuedConnection);
	loop.exec();
	return password;
}

// 收集启动项相关文件路径（注册表 Run 键 + 自启动服务）
static QStringList CollectStartupItemFiles()
{
	QStringList files;

	// 从命令行字符串中提取首个文件路径（处理引号包裹的情况）
	auto extractFirstPath = [](const QString& cmdLine) -> QString {
		QString s = cmdLine.trimmed();
		if (s.isEmpty()) return QString();
		if (s.startsWith('"')) {
			int end = s.indexOf('"', 1);
			if (end > 0) return s.mid(1, end - 1);
			return s.mid(1);
		}
		int sp = -1;
		for (int i = 0; i < s.size(); i++) {
			if (s[i].isSpace()) { sp = i; break; }
		}
		if (sp > 0) return s.left(sp);
		return s;
	};

	// 过滤系统路径（C:\Windows\System32 等已在系统文件排除中覆盖）
	auto isSystemPath = [](const QString& path) -> bool {
		QString lower = path.toLower();
		return lower.startsWith("c:\\windows\\system32\\") ||
		       lower.startsWith("c:\\windows\\syswow64\\") ||
		       lower.startsWith("c:\\windows\\system\\");
	};

	auto addIfValid = [&](const QString& cmdLine) {
		QString p = extractFirstPath(cmdLine);
		if (p.isEmpty()) return;
		if (isSystemPath(p)) return;
		files << p;
	};

	// 注册表 Run / RunOnce 键
	struct RegKey { HKEY root; LPCWSTR subKey; };
	RegKey regKeys[] = {
		{ HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
		{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
		{ HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
		{ HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
		{ HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" }
	};

	for (const auto& rk : regKeys) {
		HKEY hKey = NULL;
		if (RegOpenKeyExW(rk.root, rk.subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) continue;
		DWORD index = 0;
		for (;;) {
			WCHAR valueName[MAX_PATH];
			DWORD valueNameLen = MAX_PATH;
			WCHAR data[2048];
			DWORD dataSize = sizeof(data);
			DWORD type = 0;
			LONG res = RegEnumValueW(hKey, index, valueName, &valueNameLen, NULL, &type,
				reinterpret_cast<LPBYTE>(data), &dataSize);
			if (res == ERROR_NO_MORE_ITEMS) break;
			index++;
			if (res != ERROR_SUCCESS) continue;
			if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
			DWORD chars = dataSize / sizeof(WCHAR);
			if (chars > 0 && data[chars - 1] == 0) chars--; // 去除末尾空字符
			if (chars == 0) continue;
			std::wstring wstr(data, chars);
			if (type == REG_EXPAND_SZ) {
				WCHAR expanded[2048];
				DWORD expChars = ExpandEnvironmentStringsW(wstr.c_str(), expanded, 2048);
				if (expChars > 0 && expChars <= 2048) {
					wstr.assign(expanded, expChars - 1); // expChars 包含末尾空字符
				}
			}
			addIfValid(QString::fromStdWString(wstr));
		}
		RegCloseKey(hKey);
	}

	// 自启动服务：枚举所有 Win32 服务，过滤 dwStartType == SERVICE_AUTO_START
	SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
	if (scm) {
		DWORD bytesNeeded = 0;
		DWORD servicesReturned = 0;
		DWORD resumeHandle = 0;
		EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
			NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
		if (bytesNeeded > 0) {
			std::vector<BYTE> buffer(bytesNeeded);
			if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
				buffer.data(), (DWORD)buffer.size(), &bytesNeeded, &servicesReturned,
				&resumeHandle, NULL) && servicesReturned > 0) {
				ENUM_SERVICE_STATUS_PROCESSW* svc =
					reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buffer.data());
				for (DWORD i = 0; i < servicesReturned; i++) {
					SC_HANDLE hSvc = OpenServiceW(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG);
					if (hSvc) {
						DWORD needed = 0;
						QueryServiceConfigW(hSvc, NULL, 0, &needed);
						if (needed > 0) {
							std::vector<BYTE> cfgBuf(needed);
							QUERY_SERVICE_CONFIGW* cfg =
								reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
							if (QueryServiceConfigW(hSvc, cfg, needed, &needed) &&
								cfg->dwStartType == SERVICE_AUTO_START &&
								cfg->lpBinaryPathName) {
								addIfValid(QString::fromWCharArray(cfg->lpBinaryPathName));
							}
						}
						CloseServiceHandle(hSvc);
					}
				}
			}
		}
		CloseServiceHandle(scm);
	}

	return files;
}

// 收集计划任务中的可执行文件路径（ITaskService COM 递归枚举）
static QStringList CollectScheduledTaskPaths()
{
	QStringList files;

	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	bool doUninit = SUCCEEDED(hr); // S_OK / S_FALSE 需配对 CoUninitialize；RPC_E_CHANGED_MODE 则无需
	if (FAILED(hr)) return files;

	ITaskService* pSvc = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
		IID_ITaskService, (void**)&pSvc);
	if (SUCCEEDED(hr) && pSvc) {
		hr = pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
		if (SUCCEEDED(hr)) {
			ITaskFolder* pRoot = NULL;
			hr = pSvc->GetFolder(_bstr_t(L"\\"), &pRoot);
			if (SUCCEEDED(hr) && pRoot) {
				// 使用栈进行迭代式递归遍历所有任务文件夹
				std::vector<ITaskFolder*> folders;
				folders.push_back(pRoot);
				while (!folders.empty()) {
					ITaskFolder* pFolder = folders.back();
					folders.pop_back();

					IRegisteredTaskCollection* pTasks = NULL;
					if (SUCCEEDED(pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTasks)) && pTasks) {
						LONG count = 0;
						pTasks->get_Count(&count);
						for (LONG i = 1; i <= count; i++) {
							IRegisteredTask* pTask = NULL;
							if (SUCCEEDED(pTasks->get_Item(_variant_t(i), &pTask)) && pTask) {
								ITaskDefinition* pDef = NULL;
								if (SUCCEEDED(pTask->get_Definition(&pDef)) && pDef) {
									IActionCollection* pActions = NULL;
									if (SUCCEEDED(pDef->get_Actions(&pActions)) && pActions) {
										LONG actCount = 0;
										pActions->get_Count(&actCount);
										for (LONG a = 1; a <= actCount; a++) {
											IAction* pAct = NULL;
											if (SUCCEEDED(pActions->get_Item(a, &pAct)) && pAct) {
												IExecAction* pExec = NULL;
												if (SUCCEEDED(pAct->QueryInterface(IID_IExecAction, (void**)&pExec)) && pExec) {
													BSTR bstrPath = NULL;
													if (SUCCEEDED(pExec->get_Path(&bstrPath)) && bstrPath) {
														QString p = QString::fromWCharArray(bstrPath);
														if (!p.isEmpty()) files << p;
														SysFreeString(bstrPath);
													}
													pExec->Release();
												}
												pAct->Release();
											}
										}
										pActions->Release();
									}
									pDef->Release();
								}
								pTask->Release();
							}
						}
						pTasks->Release();
					}

					// 枚举子文件夹并入栈
					ITaskFolderCollection* pSubFolders = NULL;
					if (SUCCEEDED(pFolder->GetFolders(0, &pSubFolders)) && pSubFolders) {
						LONG fcount = 0;
						pSubFolders->get_Count(&fcount);
						for (LONG f = 1; f <= fcount; f++) {
							ITaskFolder* pSub = NULL;
							if (SUCCEEDED(pSubFolders->get_Item(_variant_t(f), &pSub)) && pSub) {
								folders.push_back(pSub);
							}
						}
						pSubFolders->Release();
					}

					pFolder->Release();
				}
			}
		}
		pSvc->Release();
	}

	if (doUninit) CoUninitialize();

	return files;
}

// 收集用户目录下的可疑文件
// 策略：仅扫描已知高风险子目录（启动目录、Temp、WER），不递归扫描整个 AppData
// 限制：每个目录最多 200 个文件，总计最多 800 个文件，递归深度不超过 2 层
static QStringList CollectUserDirectoryFiles()
{
	QStringList files;
	QStringList dirs;
	WCHAR path[MAX_PATH];

	// 仅扫描已知高风险子目录，不扫描整个 AppData 顶层（文件过多易崩溃）
	if (SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, path) == S_OK) {
		QString appData = QString::fromWCharArray(path);
		// 启动目录（自启动恶意软件常见位置）
		dirs << appData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
	}
	if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path) == S_OK) {
		QString localAppData = QString::fromWCharArray(path);
		// Temp 目录（恶意软件释放常见位置）
		dirs << localAppData + "\\Temp";
		// WER 错误报告目录
		dirs << localAppData + "\\Microsoft\\Windows\\WER";
	}
	DWORD tempLen = GetTempPathW(MAX_PATH, path);
	if (tempLen > 0 && tempLen < MAX_PATH) {
		QString tempPath = QString::fromWCharArray(path, tempLen);
		while (tempPath.endsWith('\\')) tempPath.chop(1);
		if (!tempPath.isEmpty()) dirs << tempPath;
	}

	// 仅收集可执行/脚本类扩展名
	QStringList exts = QStringList() << ".exe" << ".dll" << ".sys"
		<< ".bat" << ".cmd" << ".ps1" << ".vbs" << ".js" << ".hta";

	const int MAX_FILES_PER_DIR = 200;   // 每个根目录最多收集 200 个文件
	const int MAX_TOTAL_FILES = 800;      // 总计最多 800 个文件
	const int MAX_DEPTH = 2;              // 递归深度不超过 2 层

	for (const QString& dir : dirs) {
		if (files.size() >= MAX_TOTAL_FILES) break;

		int filesInThisDir = 0;
		// stack: pair<目录路径, 当前深度>
		std::vector<std::pair<std::wstring, int>> stack;
		stack.push_back({ dir.toStdWString(), 0 });

		while (!stack.empty() && filesInThisDir < MAX_FILES_PER_DIR && files.size() < MAX_TOTAL_FILES) {
			auto [current, depth] = stack.back();
			stack.pop_back();

			std::wstring pattern = current + L"\\*";
			WIN32_FIND_DATAW fd;
			HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
			if (hFind == INVALID_HANDLE_VALUE) continue;

			do {
				if (files.size() >= MAX_TOTAL_FILES || filesInThisDir >= MAX_FILES_PER_DIR) break;

				if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
				if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue; // 跳过重解析点避免循环

				std::wstring full = current + L"\\" + fd.cFileName;

				if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
					// 仅在未达到最大深度时递归
					if (depth < MAX_DEPTH) {
						stack.push_back({ full, depth + 1 });
					}
				} else {
					std::wstring fname = fd.cFileName;
					size_t dot = fname.find_last_of(L'.');
					if (dot != std::wstring::npos) {
						QString qext = QString::fromStdWString(fname.substr(dot));
						if (exts.contains(qext, Qt::CaseInsensitive)) {
							files << QString::fromStdWString(full);
							filesInThisDir++;
						}
					}
				}
			} while (FindNextFileW(hFind, &fd));
			FindClose(hFind);
		}
	}

	return files;
}

// 询问用户是否在本次快速扫描中临时关闭 Yara 引擎
// 返回 true 表示用户选择"不启用"（本次扫描临时关闭 Yara）
static bool AskDisableYaraForQuickScan(QWidget* parent)
{
	// 注意：此函数在主线程调用，直接使用 exec() 模态阻塞即可，
	// 不能使用 BlockingQueuedConnection（会导致主线程自等待死锁）
	ElaDialog dlg(parent);
	dlg.setWindowTitle("Yara 引擎建议");
	dlg.setWindowButtonFlags(ElaAppBarType::CloseButtonHint);
	dlg.setFixedSize(480, 340);
	dlg.setIsFixedSize(true);

	QWidget* content = new QWidget(&dlg);
	QVBoxLayout* layout = new QVBoxLayout(content);
	layout->setContentsMargins(28, 20, 28, 16);
	layout->setSpacing(10);

	// 标题行（图标 + 标题）
	QWidget* headerWidget = new QWidget();
	QHBoxLayout* headerLayout = new QHBoxLayout(headerWidget);
	headerLayout->setContentsMargins(0, 0, 0, 0);
	headerLayout->setSpacing(10);

	QLabel* iconLabel = new QLabel();
	iconLabel->setObjectName("yaraAdviceIcon");
	QPixmap warnIcon(28, 28);
	warnIcon.fill(Qt::transparent);
	QPainter painter(&warnIcon);
	painter.setRenderHint(QPainter::Antialiasing);
	painter.setBrush(QColor("#F39C12"));
	painter.setPen(Qt::NoPen);
	painter.drawEllipse(2, 2, 24, 24);
	painter.setPen(QPen(Qt::white, 2.5, Qt::SolidLine, Qt::RoundCap));
	painter.drawLine(14, 8, 14, 15);
	painter.setBrush(Qt::white);
	painter.setPen(Qt::NoPen);
	painter.drawEllipse(12, 18, 4, 4);
	painter.end();
	iconLabel->setPixmap(warnIcon);

	QLabel* titleLabel = new QLabel("建议不启用 Yara 引擎");
	titleLabel->setObjectName("yaraAdviceTitle");
	titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; border: none;");

	headerLayout->addWidget(iconLabel);
	headerLayout->addWidget(titleLabel);
	headerLayout->addStretch();

	// 说明文字
	QLabel* descLabel = new QLabel(
		"快速扫描会遍历进程内存空间，Yara 内存扫描对每个进程都会\n"
		"逐区域读取并匹配规则，开销较大且可能产生误报。\n\n"
		"建议本次扫描临时关闭 Yara 引擎以提升速度。\n"
		"扫描结束后 Yara 开关状态不会被更改。");
	descLabel->setObjectName("yaraAdviceDesc");
	descLabel->setWordWrap(true);
	descLabel->setStyleSheet("font-size: 13px; border: none;");

	// 按钮区
	QWidget* btnWidget = new QWidget();
	QHBoxLayout* btnLayout = new QHBoxLayout(btnWidget);
	btnLayout->setContentsMargins(0, 0, 0, 0);
	btnLayout->addStretch();

	ElaPushButton* btnDisable = new ElaPushButton("不启用");
	btnDisable->setObjectName("btnDisable");
	btnDisable->setFixedHeight(36);
	btnDisable->setFixedWidth(100);

	ElaPushButton* btnKeep = new ElaPushButton("仍然启用");
	btnKeep->setObjectName("btnKeep");
	btnKeep->setFixedHeight(36);
	btnKeep->setFixedWidth(100);

	btnLayout->addWidget(btnDisable);
	btnLayout->addSpacing(10);
	btnLayout->addWidget(btnKeep);

	layout->addWidget(headerWidget);
	layout->addWidget(descLabel);
	layout->addStretch();
	layout->addWidget(btnWidget);

	// 将布局设置到 ElaDialog
	QVBoxLayout* dlgLayout = new QVBoxLayout(&dlg);
	dlgLayout->setContentsMargins(0, 0, 0, 0);
	dlgLayout->setSpacing(0);
	dlgLayout->addWidget(content);

	// 主题样式更新
	auto updateStyle = [&dlg]() {
		ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
		bool isDark = (themeMode == ElaThemeType::Dark);
		QString bgColor = ElaThemeColor(themeMode, WindowBase).name();
		QString textColor = isDark ? "#E5E7EB" : "#333333";
		QString descColor = isDark ? "#9CA3AF" : "#666666";
		QString btnDisableBg = isDark ? "#374151" : "#F3F4F6";
		QString btnDisableText = isDark ? "#F9FAFB" : "#1F2937";
		QString btnDisableHover = isDark ? "#4B5563" : "#E5E7EB";
		QString btnKeepBg = isDark ? "#DC2626" : "#EF4444";
		QString btnKeepText = "#FFFFFF";
		QString btnKeepHover = isDark ? "#B91C1C" : "#DC2626";

		dlg.setStyleSheet(QString("QDialog { background: %1; border-radius: 12px; }").arg(bgColor));

		QLabel* t = dlg.findChild<QLabel*>("yaraAdviceTitle");
		if (t) t->setStyleSheet(QString("font-size: 16px; font-weight: bold; color: %1; border: none;").arg(textColor));

		QLabel* d = dlg.findChild<QLabel*>("yaraAdviceDesc");
		if (d) d->setStyleSheet(QString("font-size: 13px; color: %1; border: none;").arg(descColor));

		ElaPushButton* bd = dlg.findChild<ElaPushButton*>("btnDisable");
		if (bd) bd->setStyleSheet(QString(
			"ElaPushButton { background: %1; color: %2; border: none; border-radius: 8px; font-size: 13px; }"
			"ElaPushButton:hover { background: %3; }").arg(btnDisableBg).arg(btnDisableText).arg(btnDisableHover));

		ElaPushButton* bk = dlg.findChild<ElaPushButton*>("btnKeep");
		if (bk) bk->setStyleSheet(QString(
			"ElaPushButton { background: %1; color: %2; border: none; border-radius: 8px; font-size: 13px; }"
			"ElaPushButton:hover { background: %3; }").arg(btnKeepBg).arg(btnKeepText).arg(btnKeepHover));
	};
	updateStyle();
	QObject::connect(eTheme, &ElaTheme::themeModeChanged, &dlg, [&updateStyle]() { updateStyle(); });

	bool userChoseDisable = false;
	QObject::connect(btnDisable, &ElaPushButton::clicked, &dlg, [&]() {
		userChoseDisable = true;
		dlg.accept();
		});
	QObject::connect(btnKeep, &ElaPushButton::clicked, &dlg, [&]() {
		userChoseDisable = false;
		dlg.reject();
		});

	dlg.moveToCenter();
	dlg.exec();
	return userChoseDisable;
}

static bool IsArchiveFile(const std::string& path) {
	static const std::vector<std::string> exts = {
		".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz",
		".tgz", ".tbz2", ".txz", ".zst", ".lz4"
	};
	filesystem::path p(path);
	std::string ext = p.extension().string();
	for (auto& c : ext) c = tolower(c);
	for (const auto& e : exts) if (ext == e) return true;
	std::string stem_ext = filesystem::path(p.stem()).extension().string();
	for (auto& c : stem_ext) c = tolower(c);
	return stem_ext == ".tar";
}

// 扫描工作线程统一取消判断：终止/暂停/恢复时让线程尽快退出当前文件。
static inline bool ScanWorkerShouldCancel()
{
	return g_scanCancelRequested.load() ||
		   mScanState.load() == ssEnding ||
		   mScanState.load() == ssPrepared ||
		   mScanState.load() == ssScanResult;
}

static bool IsScriptFile(const std::string& path)
{
	static const char* scriptExts[] = {
		".ps1", ".psm1", ".psd1", ".ps1xml", ".psc1", ".cdxml",
		".bat", ".cmd",
		".vbs", ".vbe",
		".js", ".jse", ".wsf",
		".hta"
	};
	std::string low = path;
	std::transform(low.begin(), low.end(), low.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	for (const auto* ext : scriptExts) {
		if (low.size() >= strlen(ext) &&
			low.compare(low.size() - strlen(ext), strlen(ext), ext) == 0) {
			return true;
		}
	}
	return false;
}

DWORD WorkerT(LPVOID lpParam)
{
	WorkerTParam* pParam = (WorkerTParam*)lpParam;
	RunningWorkerT.fetch_add(1);

	const bool onlyPE = pParam->onlyPEEnabled;
	const bool sha256En = pParam->sha256Enabled;
	const bool yaraEn = pParam->yaraEnabled;
	const bool clamavEn = pParam->clamavEnabled;
	const bool scriptEn = pParam->scriptEnabled;
	const bool onlyPEEnabled = onlyPE && !sha256En && !yaraEn && !clamavEn;

	for (int fileIndex = 0; fileIndex < pParam->fileNames.count(); fileIndex++) {
		QString currentFile = pParam->fileNames[fileIndex];

		// 临时方案：等待停止状态，降低忙等频率以减少上下文切换（建议后续改为 QWaitCondition）
		while (mScanState.load() == ssStopping) { Sleep(100); }
		if (ScanWorkerShouldCancel()) break;

		string fileName = currentFile.toLocal8Bit().toStdString();

		bool mainFileCounted = false;
		auto scanSingleFile = [&](const string& fileToScan,
			const QString& originalVirusPath,
			const QString& extractedPathForVirus,
			const QString& displayName) -> bool
			{
				if (ScanWorkerShouldCancel()) return false;

				{
					QMutexLocker locker(&pParam->mutex);
					pParam->currentScanningFile = displayName;
				}

				if (onlyPEEnabled && !IsPeFileValid(fileToScan.c_str()) && !IsScriptFile(fileToScan)) {
				if (!mainFileCounted) {
					QMutexLocker locker(&pParam->mutex);
					pParam->HasScanedCount++;
					mainFileCounted = true;
				}
				return true;
			}

			// 临时目录白名单检查（命中则该目录下所有文件免扫，无需计算SHA256）
			if (Whitelist_IsPathInTempDir(fileToScan)) {
				if (!mainFileCounted) {
					QMutexLocker locker(&pParam->mutex);
					pParam->HasScanedCount++;
					mainFileCounted = true;
				}
				return true;
			}

		if (ScanWorkerShouldCancel()) return false;
		string sha256 = Encrypt_CalculateFileSHA256(fileToScan);
			std::transform(sha256.begin(), sha256.end(), sha256.begin(),
				[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			RelScanVirus isVirus = UnDefined;
			string virusName;
			string foundVirusName;

			{
				QMutexLocker cacheLock(&g_ScanCacheMutex);

					if (Sha256White_IsReady) {
					if (std::binary_search(WhiteSha256List, WhiteSha256List + WhiteSha256Count, sha256)) {
						isVirus = ByScanedWhiteList;
					}
				}

				if (isVirus == UnDefined && WhiteSha256ListCache.find(sha256) != WhiteSha256ListCache.end()) {
					isVirus = ByScanedWhiteList;
				}

				if (isVirus == UnDefined && HasBeenScanedSha256WhiteList.find(sha256) != HasBeenScanedSha256WhiteList.end()) {
					isVirus = ByScanedWhiteList;
				}

					if (isVirus == UnDefined) {
						auto itBlack = HasBeenScanedSha256BlackList.find(sha256);
						if (itBlack != HasBeenScanedSha256BlackList.end()) {
							isVirus = ByScanedBlackList;
							foundVirusName = itBlack->second;
						}
					}
				}

				if (isVirus == ByScanedBlackList) {
					QMutexLocker locker(&pParam->mutex);
					if (!mainFileCounted) {
						pParam->HasScanedCount++;
						mainFileCounted = true;
					}
					pParam->AllVirusCount++;
					pParam->VirusPath.append(originalVirusPath);
					pParam->VirusName.append(QString::fromUtf8(foundVirusName.c_str()));
					pParam->ExtractedFilePaths.append(extractedPathForVirus);
					return true;
				}

				if (isVirus == UnDefined) {
				if (ScanWorkerShouldCancel()) return false;
				isVirus = IsntVirus;
				virusName = Scan_GeneralScan(fileToScan, sha256);
				if (virusName != "Empty") isVirus = ByCommonScaned;
				if (isVirus == IsntVirus && scriptEn)
				{
					string scriptResult = Scan_ScriptBatch(fileToScan);
					if (scriptResult != "Empty")
					{
						virusName = scriptResult;
						isVirus = ByCommonScaned;
					}
				}
			}

			if (isVirus == IsntVirus) {
				QMutexLocker cacheLock(&g_ScanCacheMutex);
				HasBeenScanedSha256WhiteList.insert(sha256);
			}
			else if (isVirus == ByCommonScaned) {
				{
					QMutexLocker cacheLock(&g_ScanCacheMutex);
					HasBeenScanedSha256BlackList[sha256] = virusName;
				}

				QMutexLocker locker(&pParam->mutex);
				if (!mainFileCounted) {
					pParam->HasScanedCount++;
					mainFileCounted = true;
				}
				pParam->AllVirusCount++;
				pParam->VirusPath.append(originalVirusPath);
				pParam->VirusName.append(QString::fromUtf8(virusName.c_str()));
				pParam->ExtractedFilePaths.append(extractedPathForVirus);
				return true;
			}

				if (!mainFileCounted) {
					QMutexLocker locker(&pParam->mutex);
					pParam->HasScanedCount++;
					mainFileCounted = true;
				}
				return true;
			};

		if (FALSE && IsArchiveFile(fileName)) {
		}
		else {
			if (IsPeFileValid(fileName.c_str())) {
				char TempPathBuffer[MAX_PATH];
				string tempDir;
				if (GetTempPathA(MAX_PATH, TempPathBuffer) > 0) {
					tempDir = string(TempPathBuffer) + "TianHongScan_Extract_" +
						std::to_string(GetCurrentThreadId()) + "_" + std::to_string(fileIndex);
				}
				else {
					tempDir = (CW2A)Process_GetCurrentProcessPath().c_str();
					tempDir += "TianHongScan_Extract_" +
						std::to_string(GetCurrentThreadId()) + "_" + std::to_string(fileIndex);
				}

				vector<string> filesToScan;
			filesToScan.push_back(fileName);

			if (g_bExtractFilesEnabled) {
				std::vector<std::string> extractedFiles;
				if (ExtractResourcesRecursive(fileName, tempDir, 0, 4, extractedFiles)) {
					for (const auto& ef : extractedFiles) {
						if (IsPeFileValid(ef.c_str())) filesToScan.push_back(ef);
					}
				}
			}

				for (size_t i = 0; i < filesToScan.size(); i++) {
					string fileToScan = filesToScan[i];
					QString displayName;
					QString extractedPathForVirus;

					if (i == 0) {
						displayName = currentFile;
						extractedPathForVirus = QString();
					}
					else {
						string fileNameOnly = fileToScan.substr(fileToScan.find_last_of("\\") + 1);
						displayName = currentFile + " >> " + QString::fromLocal8Bit(fileNameOnly.c_str());
						extractedPathForVirus = QString::fromLocal8Bit(fileToScan.c_str());
					}

					if (!scanSingleFile(fileToScan, currentFile, extractedPathForVirus, displayName))
						break;
				}

				if (filesToScan.size() > 1) {
					RemoveDirectoryRecursiveA(tempDir);
				}
			}
			else {
				if (!scanSingleFile(fileName, currentFile, QString(), currentFile))
					break;
			}
		}

		if (mScanState.load() == ssStoppingPreparing) {
			mScanState.store(ssStopping);
		}
	}

	RunningWorkerT.fetch_add(-1);
	return 0;
}

DWORD DirWorkerT(LPVOID lpParam)
{
	DirWorkerTParam* pDirParam = (DirWorkerTParam*)lpParam;
	RunningWorkerT.fetch_add(1);

	const bool onlyPE = pDirParam->onlyPEEnabled;
	const bool sha256En = pDirParam->sha256Enabled;
	const bool yaraEn = pDirParam->yaraEnabled;
	const bool clamavEn = pDirParam->clamavEnabled;
	const bool onlyPEEnabled = onlyPE && !sha256En && !yaraEn && !clamavEn;

	while (true) {
		QString currentFile;
		{
			QMutexLocker locker(&pDirParam->fileListMutex);
			if (pDirParam->currentFileIndex >= pDirParam->allFiles.count() || pDirParam->stopRequested) {
				break;
			}
			currentFile = pDirParam->allFiles[pDirParam->currentFileIndex];
			pDirParam->currentFileIndex++;
		}

		// 临时方案：等待停止状态，降低忙等频率以减少上下文切换（建议后续改为 QWaitCondition）
		while (mScanState.load() == ssStopping) { Sleep(100); }
		if (ScanWorkerShouldCancel()) break;

		{
			QMutexLocker locker(&pDirParam->resultMutex);
			pDirParam->currentScanningFile = currentFile;
		}

		string fileName = currentFile.toLocal8Bit().toStdString();

		char TempPathbuffer[MAX_PATH];
		string tempDir;
		if (GetTempPathA(MAX_PATH, TempPathbuffer) > 0) {
			tempDir = string(TempPathbuffer) + "TianHongScan_Extract_" +
				std::to_string(GetCurrentThreadId()) + "_" +
				std::to_string(pDirParam->currentFileIndex);
		}
		else {
			tempDir = (CW2A)Process_GetCurrentProcessPath().c_str();
			tempDir += "TianHongScan_Extract_" +
				std::to_string(GetCurrentThreadId()) + "_" +
				std::to_string(pDirParam->currentFileIndex);
		}

		vector<string> filesToScan;
		filesToScan.push_back(fileName);

		if (g_bExtractFilesEnabled && ExtractSpecificResources(fileName.c_str(), tempDir.c_str())) {
			WIN32_FIND_DATAA findData;
			HANDLE hFind = FindFirstFileA((tempDir + "\\*").c_str(), &findData);
			if (hFind != INVALID_HANDLE_VALUE) {
				do {
					if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
						string extractedFile = tempDir + "\\" + findData.cFileName;
						if (IsPeFileValid(extractedFile.c_str())) {
							filesToScan.push_back(extractedFile);
						}
					}
				} while (FindNextFileA(hFind, &findData));
				FindClose(hFind);
			}
		}

		for (size_t i = 0; i < filesToScan.size(); i++) {
			if (ScanWorkerShouldCancel()) break;
			string fileToScan = filesToScan[i];

			if (i > 0) {
				string fileNameOnly = fileToScan.substr(fileToScan.find_last_of("\\") + 1);
				string displayName = filesToScan[0] + " >> " + fileNameOnly;
				QMutexLocker locker(&pDirParam->resultMutex);
				pDirParam->currentScanningFile = QString::fromLocal8Bit(displayName.c_str());
			}

			if (onlyPEEnabled && !IsPeFileValid(fileToScan.c_str()) && !IsScriptFile(fileToScan)) {
				if (i == 0) {
					QMutexLocker locker(&pDirParam->resultMutex);
					pDirParam->HasScanedCount++;
				}
				continue;
			}

			// 临时目录白名单检查（命中则该目录下所有文件免扫，无需计算SHA256）
			if (Whitelist_IsPathInTempDir(fileToScan)) {
				if (i == 0) {
					QMutexLocker locker(&pDirParam->resultMutex);
					pDirParam->HasScanedCount++;
				}
				continue;
			}

			if (ScanWorkerShouldCancel()) break;
			string thisSha256 = Encrypt_CalculateFileSHA256(fileToScan);
			std::transform(thisSha256.begin(), thisSha256.end(), thisSha256.begin(),
				[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			RelScanVirus isVirus = UnDefined;
			string virusName;
			string foundVirusName;

			// 查找缓存（全局锁）
			{
				QMutexLocker cacheLock(&g_ScanCacheMutex);
				if (Sha256White_IsReady) {
					if (std::binary_search(WhiteSha256List, WhiteSha256List + WhiteSha256Count, thisSha256)) {
						isVirus = ByScanedWhiteList;
					}
				}
				if (isVirus == UnDefined && WhiteSha256ListCache.find(thisSha256) != WhiteSha256ListCache.end()) {
					isVirus = ByScanedWhiteList;
				}
				if (isVirus == UnDefined && HasBeenScanedSha256WhiteList.find(thisSha256) != HasBeenScanedSha256WhiteList.end()) {
					isVirus = ByScanedWhiteList;
				}
				if (isVirus == UnDefined) {
					auto itBlack = HasBeenScanedSha256BlackList.find(thisSha256);
					if (itBlack != HasBeenScanedSha256BlackList.end()) {
						isVirus = ByScanedBlackList;
						foundVirusName = itBlack->second;
					}
				}
			}

			if (isVirus == ByScanedBlackList) {
				QMutexLocker locker(&pDirParam->resultMutex);
				if (i == 0) pDirParam->HasScanedCount++;
				pDirParam->AllVirusCount++;
				pDirParam->VirusPath.append(currentFile);
				pDirParam->VirusName.append(foundVirusName.c_str());
				pDirParam->ExtractedFilePaths.append(QString()); // 黑名单复用无提取
				break; // 主文件报毒后无需继续
			}

			if (ScanWorkerShouldCancel()) break;
			if (isVirus == UnDefined) {
				isVirus = IsntVirus;
				virusName = Scan_GeneralScan(fileToScan, thisSha256);
				if (virusName != "Empty") isVirus = ByCommonScaned;
			}

			// 更新缓存与结果
			if (isVirus == IsntVirus) {
				QMutexLocker cacheLock(&g_ScanCacheMutex);
				HasBeenScanedSha256WhiteList.insert(thisSha256);
			}
			else if (isVirus == ByCommonScaned) {
				{
					QMutexLocker cacheLock(&g_ScanCacheMutex);
					HasBeenScanedSha256BlackList[thisSha256] = virusName;
				}

				QMutexLocker locker(&pDirParam->resultMutex);
				if (i == 0) pDirParam->HasScanedCount++;
				pDirParam->AllVirusCount++;
				pDirParam->VirusPath.append(currentFile);
				if (i == 0) {
					pDirParam->ExtractedFilePaths.append(QString());
					pDirParam->VirusName.append(virusName.c_str());
				}
				else {
					pDirParam->ExtractedFilePaths.append(QString::fromLocal8Bit(fileToScan.c_str()));
					pDirParam->VirusName.append(virusName.c_str());
				}
				break;
			}

			// 纯白名单计数
			if (i == 0) {
				QMutexLocker locker(&pDirParam->resultMutex);
				pDirParam->HasScanedCount++;
			}
		}

		// 清理临时目录
		if (filesToScan.size() > 1) {
			WIN32_FIND_DATAA findData;
			HANDLE hFind = FindFirstFileA((tempDir + "\\*").c_str(), &findData);
			if (hFind != INVALID_HANDLE_VALUE) {
				do {
					if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
						string fileToDelete = tempDir + "\\" + findData.cFileName;
						DeleteFileA(fileToDelete.c_str());
					}
				} while (FindNextFileA(hFind, &findData));
				FindClose(hFind);
			}
			RemoveDirectoryA(tempDir.c_str());
		}

		if (mScanState.load() == ssStoppingPreparing) {
			mScanState.store(ssStopping);
		}
	}

	RunningWorkerT.fetch_add(-1);
	return 0;
}

DWORD ProcessWorkerT(LPVOID lpParam)
{
	ProcessWorkerTParam* pWorkerParam = (ProcessWorkerTParam*)lpParam;
	RunningWorkerT.fetch_add(1);

	const bool onlyPE = pWorkerParam->onlyPEEnabled;
	const bool sha256En = pWorkerParam->sha256Enabled;
	const bool yaraEn = pWorkerParam->yaraEnabled;
	const bool clamavEn = pWorkerParam->clamavEnabled;
	const bool scriptEn = pWorkerParam->scriptEnabled;
	const bool onlyPEEnabled = onlyPE && !sha256En && !yaraEn && !clamavEn;

	std::unordered_map<QString, std::pair<bool, QString>> processedResults;
	std::unordered_map<QString, QString> processedExtracted;

	while (true) {
		int NowScanPos;
		QString QfileName;
		{
			QMutexLocker locker(&pWorkerParam->fileListMutex);
			if (pWorkerParam->currentFileIndex >= pWorkerParam->fileNames.size() || pWorkerParam->stopRequested) {
				break;
			}
			NowScanPos = pWorkerParam->currentFileIndex;
			QfileName = pWorkerParam->fileNames[NowScanPos];
			pWorkerParam->currentFileIndex++;
		}

		string fileName = (string)QfileName.toLocal8Bit();

		// 临时方案：等待停止状态，降低忙等频率以减少上下文切换（建议后续改为 QWaitCondition）
		while (mScanState.load() == ssStopping) { Sleep(100); }
		if (ScanWorkerShouldCancel()) break;

		// 检查本地缓存
		auto it = processedResults.find(QfileName);
		if (it != processedResults.end()) {
			QMutexLocker locker(&pWorkerParam->mutex);
			if (it->second.first) {
				pWorkerParam->AllVirusCount++;
				pWorkerParam->VirusPath.append(QfileName);
				pWorkerParam->VirusName.append(it->second.second);
				auto itex = processedExtracted.find(QfileName);
				if (itex != processedExtracted.end()) pWorkerParam->ExtractedFilePaths.append(itex->second);
				else pWorkerParam->ExtractedFilePaths.append(QString());
				pWorkerParam->VirusPidList.push_back(pWorkerParam->pidList[NowScanPos]);
			}
			pWorkerParam->HasScanedCount++;
			continue;
		}

		{
			QMutexLocker locker(&pWorkerParam->mutex);
			pWorkerParam->currentScanningFile = QfileName;
		}

		vector<string> filesToScan;
		filesToScan.push_back(fileName);

		size_t FilePos = 0;
		string outfileToScan = "";
		string outVirusName = "";
		BOOL isVirusBoolean = FALSE;

		for (; FilePos < filesToScan.size(); FilePos++) {
			string fileToScan = filesToScan[FilePos];

			if (FilePos > 0) {
				string fileNameOnly = fileToScan.substr(fileToScan.find_last_of("\\") + 1);
				string displayName = filesToScan[0] + " >> " + fileNameOnly;
				QMutexLocker locker(&pWorkerParam->mutex);
				pWorkerParam->currentScanningFile = QString::fromLocal8Bit(displayName.c_str());
			}

			if (onlyPEEnabled && !IsPeFileValid(fileToScan.c_str()) && !IsScriptFile(fileToScan)) {
				if (FilePos == 0) {
					QMutexLocker locker(&pWorkerParam->mutex);
					pWorkerParam->HasScanedCount++;
				}
				continue;
			}

			// 临时目录白名单检查（命中则该目录下所有文件免扫，无需计算SHA256）
			if (Whitelist_IsPathInTempDir(fileToScan)) {
				if (FilePos == 0) {
					QMutexLocker locker(&pWorkerParam->mutex);
					pWorkerParam->HasScanedCount++;
				}
				continue;
			}

			if (ScanWorkerShouldCancel()) break;
			string thisSha256 = Encrypt_CalculateFileSHA256(fileToScan);
			std::transform(thisSha256.begin(), thisSha256.end(), thisSha256.begin(),
				[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
			RelScanVirus isVirus = UnDefined;
			string virusName;
			string foundVirusName;

			{
				QMutexLocker cacheLock(&g_ScanCacheMutex);
				if (Sha256White_IsReady) {
					if (std::binary_search(WhiteSha256List, WhiteSha256List + WhiteSha256Count, thisSha256)) {
						isVirus = ByScanedWhiteList;
					}
				}
				if (isVirus == UnDefined && WhiteSha256ListCache.find(thisSha256) != WhiteSha256ListCache.end()) {
					isVirus = ByScanedWhiteList;
				}
				if (isVirus == UnDefined && HasBeenScanedSha256WhiteList.find(thisSha256) != HasBeenScanedSha256WhiteList.end()) {
					isVirus = ByScanedWhiteList;
				}
				if (isVirus == UnDefined) {
					auto itBlack = HasBeenScanedSha256BlackList.find(thisSha256);
					if (itBlack != HasBeenScanedSha256BlackList.end()) {
						isVirus = ByScanedBlackList;
						foundVirusName = itBlack->second;
					}
				}
			}

			if (isVirus == ByScanedBlackList) {
				QMutexLocker locker(&pWorkerParam->mutex);
				if (FilePos == 0) pWorkerParam->HasScanedCount++;
				outVirusName = foundVirusName;
				outfileToScan = fileToScan;
				isVirusBoolean = TRUE;
				break;
			}

			if (isVirus == UnDefined) {
				if (ScanWorkerShouldCancel()) break;
				isVirus = IsntVirus;
				virusName = Scan_GeneralScan(fileToScan, thisSha256);
				if (virusName != "Empty") isVirus = ByCommonScaned;
				if (isVirus == IsntVirus && scriptEn)
				{
					string scriptResult = Scan_ScriptBatch(fileToScan);
					if (scriptResult != "Empty")
					{
						virusName = scriptResult;
						isVirus = ByCommonScaned;
					}
				}
			}

			// 更新缓存与计数
			if (isVirus == IsntVirus) {
				QMutexLocker cacheLock(&g_ScanCacheMutex);
				HasBeenScanedSha256WhiteList.insert(thisSha256);
			}
			else if (isVirus == ByCommonScaned) {
				{
					QMutexLocker cacheLock(&g_ScanCacheMutex);
					HasBeenScanedSha256BlackList[thisSha256] = virusName;
				}
				QMutexLocker locker(&pWorkerParam->mutex);
				if (FilePos == 0) pWorkerParam->HasScanedCount++;
				outfileToScan = fileToScan;
				outVirusName = virusName;
				isVirusBoolean = TRUE;
				break;
			}

			if (FilePos == 0) {
				QMutexLocker locker(&pWorkerParam->mutex);
				pWorkerParam->HasScanedCount++;
			}

			if (mScanState.load() == ssStoppingPreparing) {
				mScanState.store(ssStopping);
			}
		}

		if (isVirusBoolean) {
			QMutexLocker locker(&pWorkerParam->mutex);
			pWorkerParam->AllVirusCount++;
			pWorkerParam->VirusPath.append(QfileName);
			pWorkerParam->VirusName.append(outVirusName.c_str());
			if (!outfileToScan.empty() && outfileToScan != fileName) {
				pWorkerParam->ExtractedFilePaths.append(QString::fromLocal8Bit(outfileToScan.c_str()));
			}
			else {
				pWorkerParam->ExtractedFilePaths.append(QString());
			}
			auto itPids = pWorkerParam->fileToPidsMap.find(QfileName);
			if (itPids != pWorkerParam->fileToPidsMap.end() && !itPids->second.empty()) {
				pWorkerParam->VirusPidList.push_back(itPids->second[0]);
			}
			else {
				pWorkerParam->VirusPidList.push_back(pWorkerParam->pidList[NowScanPos]);
			}
		}
		else {
			DWORD currentPid = pWorkerParam->pidList[NowScanPos];
			bool pidAlreadyProcessed;
			{
				QMutexLocker locker(&pWorkerParam->processedPidsMutex);
				pidAlreadyProcessed = std::find(pWorkerParam->processedPids.begin(),
					pWorkerParam->processedPids.end(), currentPid) != pWorkerParam->processedPids.end();
				if (!pidAlreadyProcessed) {
					pWorkerParam->processedPids.push_back(currentPid);
				}
			}
			if (!pidAlreadyProcessed && Yara_MemIsReady && yaraEn) {
				// 跨线程去重后，每个 PID 只打开一次
				HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, currentPid);
				if (hProcess) {
					string VirusNameMem;
					if (Yara_ScanMemory(hProcess, VirusNameMem)) {
						QMutexLocker locker(&pWorkerParam->mutex);
						pWorkerParam->VirusPath.append(QfileName);
						pWorkerParam->VirusName.append(QString::fromStdString(VirusNameMem));
						pWorkerParam->VirusPidList.push_back(currentPid);
					}
					CloseHandle(hProcess);
				}
			}
		}

		// 记录本地结果
		processedResults[QfileName] = std::make_pair((bool)isVirusBoolean, QString::fromStdString(outVirusName));
		if (!outfileToScan.empty() && outfileToScan != fileName) {
			processedExtracted[QfileName] = QString::fromLocal8Bit(outfileToScan.c_str());
		}
		else {
			processedExtracted[QfileName] = QString();
		}
	}

	RunningWorkerT.fetch_add(-1);
	return 0;
}

bool mScanResultClean = true;      // 本次扫描是否安全
int  mTotalScannedFiles = 0;    // 本次扫描的文件总数
int  mVirusHandled = 0;         // 本次扫描已处理（隔离/拦截）的威胁数
int mTotalVirusFound = 0;       // 本次扫描发现的威胁总数（包括已处理和未处理）

void VirusScanPage::updateResultViewStyle()
{
	ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
	bool isDark = (themeMode == ElaThemeType::Dark);

	// 结果页面背景透明，由底层组件决定
	m_resultPageWidget->setStyleSheet("QWidget#resultPageWidget { background: transparent; }");

	// 卡片背景
	QString cardBg = isDark ? "rgba(40, 40, 45, 0.95)" : "rgba(255, 255, 255, 0.95)";
	QString cardBorder = isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(0, 0, 0, 0.08)";

	QWidget* resultCard = m_resultPageWidget->findChild<QWidget*>("resultCard");
	if (resultCard) {
		resultCard->setStyleSheet(QString(
			"QWidget#resultCard {"
			"   background: %1;"
			"   border: 1px solid %2;"
			"   border-radius: 16px;"
			"}"
		).arg(cardBg).arg(cardBorder));
	}

	// 标题颜色
	QString titleColor;
	if (mScanResultClean) {
		titleColor = isDark ? "#2ECC71" : "#27AE60";
	}
	else {
		titleColor = isDark ? "#F39C12" : "#E67E22";
	}
	if (resultTitleLabel) {
		resultTitleLabel->setStyleSheet(QString(
			"QLabel#resultTitleLabel {"
			"   font-size: 20px;"
			"   font-weight: bold;"
			"   color: %1;"
			"   background: transparent;"
			"   padding: 5px 10px;"
			"}"
		).arg(titleColor));
	}

	// 刷新详情面板的主题颜色
	if (resultDetailContainer) {
		// 更新容器背景和边框
		QWidget* detailWidget = resultDetailContainer->findChild<QWidget*>("detailWidget");
		if (detailWidget) {
			detailWidget->setStyleSheet(QString(
				"QWidget#detailWidget {"
				"  background: %1;"
				"  border: 1px solid %2;"
				"  border-radius: 10px;"
				"}"
			).arg(isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.03)",
				isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(0, 0, 0, 0.08)"));
		}

		// 更新所有文本标签的颜色
		QColor textColor = isDark ? QColor("#E0E0E0") : QColor("#333333");
		QList<QLabel*> labels = resultDetailContainer->findChildren<QLabel*>();
		for (QLabel* label : labels) {
			QString objName = label->objectName();
			if (objName == "threatValue") {
				QColor threatColor = mTotalVirusFound > 0
					? (isDark ? QColor("#E74C3C") : QColor("#C0392B"))
					: (isDark ? QColor("#2ECC71") : QColor("#27AE60"));
				label->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: bold;").arg(threatColor.name()));
			}
			else if (objName == "handledValue") {
				// 需要记录virusHandled的值才能判断颜色
				// 这里暂时设为绿色
				label->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: bold;").arg(isDark ? "#2ECC71" : "#27AE60"));
			}
			else if (objName == "remainingValue") {
				label->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: bold;").arg(isDark ? "#E74C3C" : "#C0392B"));
			}
			else if (objName == "safeLabel") {
				label->setStyleSheet(QString("color: %1; font-size: 14px; font-weight: bold; padding: 8px;").arg(isDark ? "#2ECC71" : "#27AE60"));
			}
			else {
				// 普通文本标签（如"扫描总数"等）
				label->setStyleSheet(QString("color: %1; font-size: 14px;").arg(textColor.name()));
			}
		}
	}

	// 返回按钮样式
	QString backBtnStyle = QString(
		"QPushButton {"
		"   font-size: 14px;"
		"   font-weight: bold;"
		"   padding: 12px 24px;"
		"   border: none;"
		"   border-radius: 8px;"
		"   color: white;"
		"   background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
		"       stop:0 %1, stop:1 %2);"
		"}"
		"QPushButton:hover {"
		"   background: qlineargradient(x1:0, y1:0, x2:0, y2:1,"
		"       stop:0 %2, stop:1 %3);"
		"}"
		"QPushButton:pressed {"
		"   background: %3;"
		"}"
	).arg(isDark ? "#4A90D9" : "#4A90E2",
		isDark ? "#3A7BC8" : "#357ABD",
		isDark ? "#2D6DA8" : "#2A6DB5");

	resultBackButton->setStyleSheet(backBtnStyle);
}

void VirusScanPage::showScanResultView(bool clean, int totalScanned, int virusHandled)
{
	// 记录安全状态，供样式函数使用
	mScanResultClean = clean;

	// ---------- 1. 清空病毒列表 ----------
	if (pVirusTableModel) {
		pVirusTableModel->removeRows(0, pVirusTableModel->rowCount());
	}

	// ---------- 2. 清理进程扫描 PID 列 ----------
	if (pVirusTableModel && pVirusTableModel->columnCount() == 5) {
		pVirusTableModel->removeColumn(4);
		QStringList headers;
		headers << "是否隔离" << "文件名" << "病毒名称" << "文件路径";
		pVirusTableModel->setHorizontalHeaderLabels(headers);
		pVirusTable->setColumnWidth(0, 80);
		pVirusTable->setColumnWidth(1, 200);
		pVirusTable->setColumnWidth(2, 150);
		pVirusTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
	}

	// ---------- 3. 更新主题样式（卡片背景、边框、标题颜色等） ----------
	updateResultViewStyle();

	// ---------- 4. 绘制图标 ----------
	ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
	bool isDark = (themeMode == ElaThemeType::Dark);

	QPixmap iconPixmap(80, 80);
	iconPixmap.fill(Qt::transparent);
	QPainter painter(&iconPixmap);
	painter.setRenderHint(QPainter::Antialiasing);

	if (clean) {
		QColor greenColor = isDark ? QColor("#2ECC71") : QColor("#27AE60");
		painter.setBrush(greenColor);
		painter.setPen(Qt::NoPen);
		painter.drawEllipse(8, 8, 64, 64);
		painter.setPen(QPen(Qt::white, 4.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
		painter.drawLine(22, 40, 35, 53);
		painter.drawLine(35, 53, 55, 30);
	}
	else {
		QColor warnColor = isDark ? QColor("#F39C12") : QColor("#E67E22");
		painter.setBrush(warnColor);
		painter.setPen(Qt::NoPen);
		painter.drawEllipse(8, 8, 64, 64);
		painter.setPen(QPen(Qt::white, 5, Qt::SolidLine, Qt::RoundCap));
		painter.drawLine(40, 22, 40, 44);
		painter.setBrush(Qt::white);
		painter.setPen(Qt::NoPen);
		painter.drawEllipse(36, 52, 8, 8);
	}
	painter.end();
	resultIconLabel->setPixmap(iconPixmap);

	// ---------- 5. 设置标题 ----------
	QString titleText;
	if (clean) {
		titleText = virusHandled > 0
			? QString::fromUtf8("扫描完成，所有威胁已处理！")
			: QString::fromUtf8("好消息！文件看上去很安全！");
	}
	else {
		int remaining = mTotalVirusFound - virusHandled;
		titleText = QString::fromUtf8("发现 %1 个威胁，%2 个未处理")
			.arg(mTotalVirusFound)
			.arg(remaining);
	}
	resultTitleLabel->setText(titleText);

	// ---------- 6. 构建详情面板（使用Qt原生布局） ----------
	int remaining = mTotalVirusFound - virusHandled;

	// 主题相关颜色
	QColor textColor = isDark ? QColor("#E0E0E0") : QColor("#333333");
	QColor threatColor = mTotalVirusFound > 0
		? (isDark ? QColor("#E74C3C") : QColor("#C0392B"))
		: (isDark ? QColor("#2ECC71") : QColor("#27AE60"));
	QColor handledColor = virusHandled > 0
		? (isDark ? QColor("#2ECC71") : QColor("#27AE60"))
		: (isDark ? QColor("#888888") : QColor("#999999"));
	QColor remainingColor = isDark ? QColor("#E74C3C") : QColor("#C0392B");
	QColor safeColor = isDark ? QColor("#2ECC71") : QColor("#27AE60");

	// 清空旧内容
	if (resultDetailContainer) {
		QLayout* layout = resultDetailContainer->layout();
		if (layout) {
			QLayoutItem* item;
			while ((item = layout->takeAt(0)) != nullptr) {
				if (item->widget())
					item->widget()->deleteLater();
				delete item;
			}
		}

		// 创建详情Widget
		QWidget* detailWidget = new QWidget();
		detailWidget->setObjectName("detailWidget");
		detailWidget->setStyleSheet(QString(
			"QWidget#detailWidget {"
			"  background: %1;"
			"  border: 1px solid %2;"
			"  border-radius: 10px;"
			"}"
		).arg(isDark ? "rgba(255, 255, 255, 0.06)" : "rgba(0, 0, 0, 0.03)",
			isDark ? "rgba(255, 255, 255, 0.1)" : "rgba(0, 0, 0, 0.08)"));

		QVBoxLayout* mainLayout = new QVBoxLayout(detailWidget);
		mainLayout->setContentsMargins(16, 12, 16, 12);
		mainLayout->setSpacing(8);

		// 创建一行数据的lambda
		auto createRow = [&](const QString& label, const QString& value, const QColor& valueColor, const QString& valueObjName = "") -> QWidget* {
			QWidget* row = new QWidget();
			QHBoxLayout* rowLayout = new QHBoxLayout(row);
			rowLayout->setContentsMargins(8, 4, 8, 4);
			rowLayout->setSpacing(0);

			QLabel* labelWidget = new QLabel(label);
			labelWidget->setStyleSheet(QString("color: %1; font-size: 14px;").arg(textColor.name()));
			labelWidget->setAlignment(Qt::AlignLeft | Qt::AlignVCenter);

			QLabel* valueWidget = new QLabel(value);
			valueWidget->setStyleSheet(QString(
				"color: %1; font-size: 14px; font-weight: bold;"
			).arg(valueColor.name()));
			valueWidget->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
			if (!valueObjName.isEmpty()) {
				valueWidget->setObjectName(valueObjName);
			}

			rowLayout->addWidget(labelWidget);
			rowLayout->addStretch();
			rowLayout->addWidget(valueWidget);

			return row;
			};

		// 添加数据行
		mainLayout->addWidget(createRow(QString::fromUtf8("扫描总数"), QString::number(totalScanned), textColor));
		mainLayout->addWidget(createRow(QString::fromUtf8("发现威胁"), QString::number(mTotalVirusFound), threatColor, "threatValue"));
		mainLayout->addWidget(createRow(QString::fromUtf8("已处理"), QString::number(virusHandled), handledColor, "handledValue"));

		if (!clean && remaining > 0) {
			mainLayout->addWidget(createRow(QString::fromUtf8("剩余未处理"), QString::number(remaining), remainingColor, "remainingValue"));
		}



		layout->addWidget(detailWidget);
	}

	// ---------- 7. 切换到结果页面 ----------
	m_stackedWidget->setCurrentIndex(1);

	// ---------- 8. 淡入动画 ----------
	QGraphicsOpacityEffect* effect = new QGraphicsOpacityEffect(m_resultPageWidget);
	m_resultPageWidget->setGraphicsEffect(effect);
	QPropertyAnimation* anim = new QPropertyAnimation(effect, "opacity");
	anim->setDuration(350);
	anim->setStartValue(0.0);
	anim->setEndValue(1.0);
	anim->setEasingCurve(QEasingCurve::OutCubic);
	anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void VirusScanPage::createCustomWidget(QString desText)
{
    QWidget* customWidget = new QWidget(this);

    ElaText* descText = new ElaText(this);
    descText->setText(desText);
    descText->setTextPixelSize(13);

    documentationButton = new ElaToolButton(this);
    documentationButton->setFixedSize(QSize(200, 35));
    documentationButton->setFixedHeight(35);
    documentationButton->setIsTransparent(false);
    documentationButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    documentationButton->setText("自定义查杀");
    documentationButton->setElaIcon(ElaIconType::Files);
    ElaMenu* documentationMenu = new ElaMenu(this);
    QAction* pa = documentationMenu->addElaIconAction(ElaIconType::File, "查杀文件");
    QAction* pb = documentationMenu->addElaIconAction(ElaIconType::Folder, "查杀文件夹");
	QAction* pc = documentationMenu->addElaIconAction(ElaIconType::Bolt, "全局快速扫描");
    documentationMenu->setFixedWidth(200);
    documentationButton->setMenu(documentationMenu);

	// ========== 文件查杀 ==========
	connect(pa, &QAction::triggered, this, [this]() {
		QSettings settings("TianHongTechnology", "TianHongSecurity");
		QString lastPath = settings.value("ScanFileLastOpenPath",
			QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)).toString();

		QStringList fileNames = QFileDialog::getOpenFileNames(
			nullptr,
			"选择多个文件进行查杀",
			lastPath,
			"可执行文件 (*.exe *.dll *.sys);;"
			"脚本 (*.bat *.cmd *.ps1 *.vbs *.js *.reg);;"
			"所有文件 (*.*)"
		);

		if (!fileNames.isEmpty()) {
			settings.setValue("ScanFileLastOpenPath", fileNames.first());

			CheckBoxAllChose = TRUE;
			documentationButton->setEnabled(false);

			spYaraEngineSwitch->setVisible(false);
			spPEEngineSwitch->setVisible(false);
			spSHA256EngineSwitch->setVisible(false);
			spClamAVEngineSwitch->setVisible(false);
			spScriptEngineSwitch->setVisible(false);
			spHighSensitiveSwitch->setVisible(false);
			spExtraPEEngineSwitch->setVisible(false);
			pButtonDecrypt->setVisible(false);

			EngineMainTitle->setText("威胁列表");
			pProgressDesc->setText("准备就绪\n");

			pButtonLeft->setVisible(true);
			pButtonRight->setVisible(true);
			pButtonLeft->setText("暂停扫描");
			pButtonRight->setText("终止扫描");

			pVirusTable->setVisible(true);
			pScanProgressBar->setRange(0, fileNames.count() * 10);
			pScanProgressBar->reset();
			slideProgressInOut(pScanProgressBar, true);

			mTotalScannedFiles = fileNames.count();

			WorkerTParam* pParam = new WorkerTParam;
			pParam->fileNames = fileNames;
			pVirusScanPage->m_pCurrentScanParam = pParam;
			pVirusScanPage->m_nCurrentScanType = 1;

			// ===== 捕获引擎开关状态（避免线程访问 UI） =====
			pParam->onlyPEEnabled = pVirusScanPage->pPEEngineSwitch->getIsToggled();
			pParam->sha256Enabled = pVirusScanPage->pSHA256EngineSwitch->getIsToggled();
			pParam->yaraEnabled = pVirusScanPage->pYaraEngineSwitch->getIsToggled();
			pParam->clamavEnabled = pVirusScanPage->pClamAVEngineSwitch->getIsToggled();
			pParam->scriptEnabled = pVirusScanPage->pScriptEngineSwitch->getIsToggled();

			mTotalVirusFound = 0;
			mVirusHandled = 0;
			mScanResultClean = true;

			g_scanCancelRequested = false;
			mScanState.store(ssRunning);
			CreateThread(0, 0, WorkerT, pParam, 0, 0);

			QTimer* checkTimer = new QTimer(this);
			m_pScanCheckTimer = checkTimer;
			QObject::connect(checkTimer, &QTimer::timeout, this, [=]() {
				if (mScanState.load() == ssEnding) {
					pProgressDesc->setText("等待选择隔离项目...");
				}
				else if (mScanState.load() == ssScanResult) {
					checkTimer->stop();
					checkTimer->deleteLater();
					m_pScanCheckTimer = nullptr;
					hideScanLoading();
					showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
				}
				else {
					int scannedCount = 0, virusCount = 0;
					QStringList currentVirusNames, currentVirusPaths, currentExtractedPaths;
					QString currentScanningFile;

					pParam->mutex.lock();
					scannedCount = pParam->HasScanedCount;
					virusCount = pParam->AllVirusCount;
					currentVirusNames = pParam->VirusName;
					currentVirusPaths = pParam->VirusPath;
					currentExtractedPaths = pParam->ExtractedFilePaths;
					currentScanningFile = pParam->currentScanningFile;
					pParam->VirusName.clear();
					pParam->VirusPath.clear();
					pParam->ExtractedFilePaths.clear();
					pParam->mutex.unlock();

					mTotalScannedFiles = scannedCount;

					if (!currentVirusPaths.isEmpty()) {
						appendVirusRecords(currentVirusNames, currentVirusPaths, currentExtractedPaths);
					}

					if (scannedCount >= fileNames.count()) {
						pParam->mutex.lock();
						if (!pParam->VirusPath.isEmpty()) {
							appendVirusRecords(pParam->VirusName, pParam->VirusPath, pParam->ExtractedFilePaths);
						}
						pParam->mutex.unlock();

						QTimer::singleShot(300, this, [=]() {
							if (this) {
								pScanProgressBar->setValue(pScanProgressBar->maximum());
								pProgressDesc->setText("准备就绪\n");
							}
							});

						// 等待线程退出后释放内存
						QtConcurrent::run([=]() {
							while (RunningWorkerT.load() > 0) {
								QThread::msleep(50);
							}
							delete pParam;
							});

						m_pCurrentScanParam = nullptr;
						m_nCurrentScanType = 0;

						if (pVirusTableModel->rowCount() == 0) {
							mScanResultClean = true;
							mVirusHandled = 0;
							mScanState.store(ssScanResult);
							hideScanLoading();
							NewMessageBox("扫描完成：没有发现病毒。", 1, 3);
							Log_AddLogSimple(QString::fromUtf8("扫描完成：没有发现病毒。共扫描 %1 个文件。")
							.arg(mTotalScannedFiles), LOG_SUCCESS);
						}
						else {
							mTotalVirusFound = pVirusTableModel->rowCount();
							pButtonRight->setText("隔离选中");
							pButtonLeft->setText("全部选中");
							mScanState.store(ssEnding);
							pButtonAddWhite->setVisible(true);
							hideScanLoading();
							NewMessageBox(QString("扫描完成：发现 %1 个病毒。")
								.arg(pVirusTableModel->rowCount()), 2, 3);
							Log_AddLogSimple(QString::fromUtf8("扫描完成：共发现 %1 个威胁，等待用户处理。")
							.arg(pVirusTableModel->rowCount()), LOG_WARN);
						}
					}
					else {
						if (progressAnimation->state() == QPropertyAnimation::Running)
							progressAnimation->stop();

						if (mScanState.load() == ssStopping) {
							pProgressDesc->setText("文件扫描已暂停。");
						}
						else {
							if (!currentScanningFile.isEmpty()) {
								QString displayText;
								if (currentScanningFile.contains(" >> ")) {
									if (virusCount != 0)
										displayText = QString("文件扫描中 (%2/%3), 发现 %4 个威胁: %1")
										.arg(currentScanningFile).arg(scannedCount)
										.arg(fileNames.count()).arg(virusCount);
									else
										displayText = QString("文件扫描中 (%2/%3): %1")
										.arg(currentScanningFile).arg(scannedCount)
										.arg(fileNames.count());
								}
								else {
									int fileIndex = qMin(scannedCount, fileNames.count() - 1);
									QString fileName = fileNames[fileIndex];
									if (currentScanningFile != fileName)
										currentScanningFile = fileName;

									if (virusCount != 0)
										displayText = QString("文件扫描中 (%2/%3), 发现 %4 个威胁: %1")
										.arg(currentScanningFile).arg(scannedCount)
										.arg(fileNames.count()).arg(virusCount);
									else
										displayText = QString("文件扫描中 (%2/%3): %1")
										.arg(currentScanningFile).arg(scannedCount)
										.arg(fileNames.count());
								}
								pProgressDesc->setText(displayText);
							}
							else {
								int fileIndex = qMin(scannedCount, fileNames.count() - 1);
								QString fileName = fileNames[fileIndex];
								if (virusCount != 0)
									pProgressDesc->setText(QString("文件扫描中 (%2/%3), 发现 %4 个威胁: %1")
										.arg(currentScanningFile).arg(scannedCount)
										.arg(fileNames.count()).arg(virusCount));
								else
									pProgressDesc->setText(QString("文件扫描中 (%2/%3): %1")
										.arg(currentScanningFile).arg(scannedCount)
										.arg(fileNames.count()));
							}
						}

						progressAnimation->setStartValue(pScanProgressBar->value());
						int progressValue = scannedCount * 10;
						int maxProgress = fileNames.count() * 10;
						if (progressValue > maxProgress) progressValue = maxProgress;
						progressAnimation->setEndValue(progressValue);
						progressAnimation->start();
					}
				}
				});

			checkTimer->start(100);
		}
		});


	// ========== 文件夹查杀 ==========
	connect(pb, &QAction::triggered, this, [this]() {
		QSettings settings("TianHongTechnology", "TianHongSecurity");
		QString lastPath = settings.value("ScanDirectoryLastOpenPath",
			QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation)).toString();

		QString folderPath = QFileDialog::getExistingDirectory(
			nullptr,
			"选择文件夹",
			lastPath,
			QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks
		);

		if (!folderPath.isEmpty()) {
			settings.setValue("ScanDirectoryLastOpenPath", folderPath);

			CheckBoxAllChose = TRUE;
			documentationButton->setEnabled(false);

			spYaraEngineSwitch->setVisible(false);
			spPEEngineSwitch->setVisible(false);
			spSHA256EngineSwitch->setVisible(false);
			spClamAVEngineSwitch->setVisible(false);
			spScriptEngineSwitch->setVisible(false);
			spHighSensitiveSwitch->setVisible(false);
			spExtraPEEngineSwitch->setVisible(false);
			pButtonDecrypt->setVisible(false);

			EngineMainTitle->setText("威胁列表");
			pProgressDesc->setText("正在枚举文件夹中的文件...");
			pButtonLeft->setVisible(true);
			pButtonRight->setVisible(true);
			pVirusTable->setVisible(true);

			slideProgressInOut(pScanProgressBar, true);

			pButtonLeft->setText("暂停扫描");
			pButtonRight->setText("终止扫描");

			// 标记进入准备阶段（收集文件列表期间），使终止扫描能立即响应
			++m_scanGeneration;			// 本次新扫描：作废此前遗留的 watcher 回调
			m_bScanPreparing = true;
			showScanLoading("正在准备文件夹扫描...");

			QFutureWatcher<QStringList>* fileListWatcher = new QFutureWatcher<QStringList>(this);
			const quint64 gen = m_scanGeneration;
			connect(fileListWatcher, &QFutureWatcher<QStringList>::finished, this, [=]() {
				fileListWatcher->deleteLater();

				// 准备期间用户点击了"终止扫描"或期间又发起了新扫描：
				// 旧 watcher 结果作废，当前 UI 状态由终止处理/新扫描接管，直接忽略。
				if (gen != m_scanGeneration) return;

				QStringList allFiles = fileListWatcher->result();
				hideScanLoading();

				if (allFiles.isEmpty()) {
					NewMessageBox("选择的文件夹中没有找到文件。", 4, 3);
					pProgressDesc->setText("准备就绪\n");
					hideScanLoading();
					slideProgressInOut(pScanProgressBar, false);

					pVirusTable->setVisible(false);
					pButtonLeft->setVisible(false);
					pButtonRight->setVisible(false);
					EngineMainTitle->setVisible(false);

					QTimer::singleShot(800, this, [=]() {
						pScanProgressBar->reset();
						documentationButton->setEnabled(true);
						spYaraEngineSwitch->setVisible(true);
						spPEEngineSwitch->setVisible(true);
						spSHA256EngineSwitch->setVisible(true);
						spClamAVEngineSwitch->setVisible(true);
						spScriptEngineSwitch->setVisible(true);
						spHighSensitiveSwitch->setVisible(true);
						spExtraPEEngineSwitch->setVisible(true);
						pButtonDecrypt->setVisible(true);

						EngineMainTitle->setVisible(true);
						EngineMainTitle->setText("引擎设置");
						});
					return;
				}

				mTotalScannedFiles = allFiles.count();

				pScanProgressBar->setRange(0, allFiles.count() * 10);
				pScanProgressBar->reset();

				DirWorkerTParam* pDirParam = new DirWorkerTParam;
				pDirParam->folderPath = folderPath;
				pDirParam->allFiles = allFiles;
				pVirusScanPage->m_pCurrentScanParam = pDirParam;
				pVirusScanPage->m_nCurrentScanType = 2;

				// ===== 捕获引擎开关状态 =====
				pDirParam->onlyPEEnabled = pVirusScanPage->pPEEngineSwitch->getIsToggled();
				pDirParam->sha256Enabled = pVirusScanPage->pSHA256EngineSwitch->getIsToggled();
				pDirParam->yaraEnabled = pVirusScanPage->pYaraEngineSwitch->getIsToggled();
				pDirParam->clamavEnabled = pVirusScanPage->pClamAVEngineSwitch->getIsToggled();
				pDirParam->scriptEnabled = pVirusScanPage->pScriptEngineSwitch->getIsToggled();

				mTotalVirusFound = 0;
				mVirusHandled = 0;
				mScanResultClean = true;

				g_scanCancelRequested = false;
				m_bScanPreparing = false;
				mScanState.store(ssRunning);
				int threadCount = qMin(MAX_SCAN_THREAD, allFiles.count());
				for (int i = 0; i < threadCount; i++) {
					CreateThread(0, 0, DirWorkerT, pDirParam, 0, 0);
				}

				QTimer* checkTimer = new QTimer(this);
				m_pScanCheckTimer = checkTimer;
				connect(checkTimer, &QTimer::timeout, this, [=]() {
					if (mScanState.load() == ssPrepared) {
						checkTimer->stop();
						checkTimer->deleteLater();
						m_pScanCheckTimer = nullptr;
						hideScanLoading();

						pVirusTableModel->removeRows(0, pVirusTableModel->rowCount());
						pScanProgressBar->reset();
						pVirusTable->setVisible(false);
						pButtonLeft->setVisible(false);
						pButtonRight->setVisible(false);
						EngineMainTitle->setVisible(false);
						pProgressDesc->setText("准备就绪\n");

						if (mDrawer1) mDrawer1->setVisible(false);

						QTimer::singleShot(500, this, [=]() {
							if (this) slideProgressInOut(pScanProgressBar, false);
							});
						QTimer::singleShot(1300, this, [=]() {
							if (this) {
								pScanProgressBar->reset();
								documentationButton->setEnabled(true);
								spYaraEngineSwitch->setVisible(true);
								spPEEngineSwitch->setVisible(true);
								spSHA256EngineSwitch->setVisible(true);
								spClamAVEngineSwitch->setVisible(true);
								spScriptEngineSwitch->setVisible(true);
								spHighSensitiveSwitch->setVisible(true);
								spExtraPEEngineSwitch->setVisible(true);
								pButtonDecrypt->setVisible(true);

								EngineMainTitle->setVisible(true);
								EngineMainTitle->setText("引擎设置");
							}
							});

						QtConcurrent::run([=]() {
							while (RunningWorkerT.load() > 0) {
								QThread::msleep(50);
							}
							delete pDirParam;
							});
					}
					else if (mScanState.load() == ssEnding) {
						pProgressDesc->setText("等待选择隔离项目...");
					}
					else if (mScanState.load() == ssScanResult) {
						checkTimer->stop();
						checkTimer->deleteLater();
						m_pScanCheckTimer = nullptr;
						hideScanLoading();
						showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
					}
					else {
						int scannedCount, virusCount;
						QStringList currentVirusNames, currentVirusPaths, currentExtracted;
						QString currentScanningFile;

						{
							QMutexLocker locker(&pDirParam->resultMutex);
							scannedCount = pDirParam->HasScanedCount;
							virusCount = pDirParam->AllVirusCount;
							currentVirusNames = pDirParam->VirusName;
							currentVirusPaths = pDirParam->VirusPath;
							currentExtracted = pDirParam->ExtractedFilePaths;
							currentScanningFile = pDirParam->currentScanningFile;
							pDirParam->VirusName.clear();
							pDirParam->VirusPath.clear();
							pDirParam->ExtractedFilePaths.clear();
						}

						mTotalScannedFiles = scannedCount;

						if (!currentVirusPaths.isEmpty()) {
							appendVirusRecords(currentVirusNames, currentVirusPaths, currentExtracted);
						}

						if (scannedCount >= allFiles.count()) {
							{
								QMutexLocker locker(&pDirParam->resultMutex);
								if (!pDirParam->VirusPath.isEmpty()) {
									appendVirusRecords(pDirParam->VirusName, pDirParam->VirusPath, pDirParam->ExtractedFilePaths);
								}
							}

							QTimer::singleShot(300, this, [=]() {
								if (this) pScanProgressBar->setValue(pScanProgressBar->maximum());
								});

							m_pCurrentScanParam = nullptr;
							m_nCurrentScanType = 0;

						if (pVirusTableModel->rowCount() == 0) {
							mScanResultClean = true;
							mVirusHandled = 0;
							mScanState.store(ssScanResult);
							hideScanLoading();
							NewMessageBox("扫描完成：没有发现病毒。", 1, 3);
							Log_AddLogSimple(QString::fromUtf8("扫描完成：没有发现病毒。共扫描 %1 个文件。")
							.arg(mTotalScannedFiles), LOG_SUCCESS);
						}
						else {
							mTotalVirusFound = pVirusTableModel->rowCount();
							pButtonRight->setText("隔离选中");
							pButtonLeft->setText("全部选中");
							mScanState.store(ssEnding);
							pButtonAddWhite->setVisible(true);
							hideScanLoading();
							NewMessageBox(QString("扫描完成：发现 %1 个病毒。")
								.arg(pVirusTableModel->rowCount()), 2, 3);
							Log_AddLogSimple(QString::fromUtf8("扫描完成：共发现 %1 个威胁，等待用户处理。")
							.arg(pVirusTableModel->rowCount()), LOG_WARN);
						}
						}
						else {
							if (progressAnimation->state() == QPropertyAnimation::Running)
								progressAnimation->stop();

							if (mScanState.load() == ssStopping) {
								pProgressDesc->setText("文件夹扫描已暂停。");
							}
							else {
								if (!currentScanningFile.isEmpty()) {
									if (virusCount != 0)
										pProgressDesc->setText(QString("扫描文件夹中 (%2/%3)，发现 %4 个威胁：%1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count()).arg(virusCount));
									else
										pProgressDesc->setText(QString("扫描文件夹中 (%2/%3)：%1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count()));
								}
								else {
									if (virusCount != 0)
										pProgressDesc->setText(QString("扫描文件夹中 (%2/%3)，发现 %4 个威胁：%1")
											.arg(folderPath).arg(scannedCount)
											.arg(allFiles.count()).arg(virusCount));
									else
										pProgressDesc->setText(QString("扫描文件夹中 (%2/%3)：%1")
											.arg(folderPath).arg(scannedCount)
											.arg(allFiles.count()));
								}
							}

							progressAnimation->setStartValue(pScanProgressBar->value());
							progressAnimation->setEndValue(scannedCount * 10);
							progressAnimation->start();
						}
					}
					});

				checkTimer->start(100);
				});

			QFuture<QStringList> future = QtConcurrent::run([folderPath]() {
				QStringList fileList;
				GetAllFilesInFolder(folderPath, fileList, true);
				return fileList;
				});
			fileListWatcher->setFuture(future);
		}
		});


	// ========== 进程查杀 ==========
	connect(pc, &QAction::triggered, this, [this]() {
		CheckBoxAllChose = TRUE;

		documentationButton->setEnabled(false);
		spYaraEngineSwitch->setVisible(false);
		spPEEngineSwitch->setVisible(false);
		spSHA256EngineSwitch->setVisible(false);
		spClamAVEngineSwitch->setVisible(false);
		spScriptEngineSwitch->setVisible(false);
		spHighSensitiveSwitch->setVisible(false);
		spExtraPEEngineSwitch->setVisible(false);
		pButtonDecrypt->setVisible(false);

		// 快速扫描模式：不显示大标题和病毒表格，改为显示阶段指示器
		m_bQuickScanMode = true;
		m_quickScanCurrentPhase = 0;
		m_quickScanTotalThreats = 0;
		showQuickScanPhaseBar(true);
		// 重置所有阶段卡片为"等待中"
		for (int i = 0; i < m_quickScanPhaseCards.size(); i++) {
			updateQuickScanPhaseCard(i, "等待中", false);
		}
		updateQuickScanPhaseCard(0, "扫描中...", true);

		EngineMainTitle->setVisible(false);
		pVirusTable->setVisible(false);
		pProgressDesc->setText("正在枚举进程...\n");
		pButtonLeft->setVisible(true);
		pButtonRight->setVisible(true);

		slideProgressInOut(pScanProgressBar, true);

		pButtonLeft->setText("暂停扫描");
		pButtonRight->setText("终止扫描");

		// ===== 唯一一次遮罩：在此期间并行预收集所有阶段的文件列表 =====
		++m_scanGeneration;			// 本次新扫描：作废此前遗留的 watcher 回调
		m_bScanPreparing = true;
		showScanLoading("正在准备扫描...");
		const quint64 gen = m_scanGeneration;

		// 启动 3 个非进程阶段的文件收集（与进程文件收集并行）
		{
			auto* wStartup = new QFutureWatcher<QStringList>(this);
			auto* wSchedTask = new QFutureWatcher<QStringList>(this);
			auto* wUserDir = new QFutureWatcher<QStringList>(this);
			connect(wStartup, &QFutureWatcher<QStringList>::finished, this, [this, wStartup, gen]() {
				wStartup->deleteLater();
				if (gen != m_scanGeneration) return;   // 旧收集结果作废
				m_quickScanStartupFiles = wStartup->result();
				});
			connect(wSchedTask, &QFutureWatcher<QStringList>::finished, this, [this, wSchedTask, gen]() {
				wSchedTask->deleteLater();
				if (gen != m_scanGeneration) return;   // 旧收集结果作废
				m_quickScanScheduledTaskFiles = wSchedTask->result();
				});
			connect(wUserDir, &QFutureWatcher<QStringList>::finished, this, [this, wUserDir, gen]() {
				wUserDir->deleteLater();
				if (gen != m_scanGeneration) return;   // 旧收集结果作废
				m_quickScanUserDirFiles = wUserDir->result();
				});
			wStartup->setFuture(QtConcurrent::run([]() { return CollectStartupItemFiles(); }));
			wSchedTask->setFuture(QtConcurrent::run([]() { return CollectScheduledTaskPaths(); }));
			wUserDir->setFuture(QtConcurrent::run([]() { return CollectUserDirectoryFiles(); }));
		}

		QFutureWatcher<vector<std::pair<QString, quint32>>>* fileListWatcher =
			new QFutureWatcher<vector<std::pair<QString, quint32>>>(this);
		connect(fileListWatcher,
			&QFutureWatcher<std::vector<std::pair<QString, quint32>>>::finished,
			this, [=]() {
				// 准备期间用户点击了"终止扫描"或期间又发起了新扫描：
				// 旧 watcher 结果作废，当前 UI 状态由终止处理/新扫描接管，直接忽略。
				if (gen != m_scanGeneration) {
					fileListWatcher->deleteLater();
					return;
				}

				vector<std::pair<QString, quint32>> allFilesWithPid = fileListWatcher->result();
				QStringList allFiles;
				vector<quint32> allPids;
				std::unordered_map<QString, vector<quint32>> fileToPidsMap;
				for (const auto& item : allFilesWithPid) {
					allFiles.append(item.first);
					allPids.push_back(item.second);
				}

				// 重新构建完整的 fileToPidsMap
				HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				if (hSnapshot != INVALID_HANDLE_VALUE) {
					PROCESSENTRY32 pe32;
					pe32.dwSize = sizeof(PROCESSENTRY32);
					if (Process32First(hSnapshot, &pe32)) {
						do {
							HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
							if (hModuleSnapshot != INVALID_HANDLE_VALUE) {
								MODULEENTRY32 me32;
								me32.dwSize = sizeof(MODULEENTRY32);
								if (Module32First(hModuleSnapshot, &me32)) {
									do {
										QString modulePath = QString::fromWCharArray(me32.szExePath);
										if (!modulePath.isEmpty()) {
											fileToPidsMap[modulePath].push_back(pe32.th32ProcessID);
										}
									} while (Module32Next(hModuleSnapshot, &me32));
								}
								CloseHandle(hModuleSnapshot);
							}
						} while (Process32Next(hSnapshot, &pe32));
					}
					CloseHandle(hSnapshot);
				}

				if (allFiles.isEmpty()) {
					// 快速扫描模式下无可扫描进程：直接跳到下一阶段
					if (m_bQuickScanMode) {
						hideScanLoading();
						setQuickScanPhaseDone(0, 0);
						startQuickScanPhase(1);
						return;
					}
					NewMessageBox("无可扫描进程。", 4, 3);
					pProgressDesc->setText("准备就绪\n");
					hideScanLoading();
					slideProgressInOut(pScanProgressBar, false);
					pVirusTable->setVisible(false);
					pButtonLeft->setVisible(false);
					pButtonRight->setVisible(false);
					EngineMainTitle->setVisible(false);

					QTimer::singleShot(800, this, [=]() {
						if (this) {
							pScanProgressBar->reset();
							documentationButton->setEnabled(true);
							spYaraEngineSwitch->setVisible(true);
							spPEEngineSwitch->setVisible(true);
							spSHA256EngineSwitch->setVisible(true);
							spClamAVEngineSwitch->setVisible(true);
							spScriptEngineSwitch->setVisible(true);
							spHighSensitiveSwitch->setVisible(true);
							spExtraPEEngineSwitch->setVisible(true);
							pButtonDecrypt->setVisible(true);

							EngineMainTitle->setVisible(true);
							EngineMainTitle->setText("引擎设置");
						}
						});
					return;
				}

				mTotalScannedFiles = allFiles.count();

				// ===== 设置整体进度条（所有阶段文件总数之和） =====
				m_quickScanPhase0Count = allFiles.count();
				m_quickScanTotalFiles = m_quickScanPhase0Count
					+ m_quickScanStartupFiles.size()
					+ m_quickScanScheduledTaskFiles.size()
					+ m_quickScanUserDirFiles.size();
				m_quickScanCumulativeScanned = 0;
				pScanProgressBar->setRange(0, m_quickScanTotalFiles * 10);
				pScanProgressBar->reset();

				pVirusTableModel->insertColumn(4);
				QStringList headers;
				headers << "是否拦截" << "文件名" << "病毒名称" << "文件路径" << "加载进程";
				pVirusTableModel->setHorizontalHeaderLabels(headers);
				pVirusTable->setColumnWidth(4, 160);

				ProcessWorkerTParam* pParam = new ProcessWorkerTParam;
				pParam->fileNames = allFiles;
				pParam->pidList = allPids;
				pParam->fileToPidsMap = fileToPidsMap;
				pVirusScanPage->m_pCurrentScanParam = pParam;
				pVirusScanPage->m_nCurrentScanType = 3;

				// ===== 捕获引擎开关状态 =====
				pParam->onlyPEEnabled = pVirusScanPage->pPEEngineSwitch->getIsToggled();
				pParam->sha256Enabled = pVirusScanPage->pSHA256EngineSwitch->getIsToggled();
				pParam->yaraEnabled = pVirusScanPage->pYaraEngineSwitch->getIsToggled();
				pParam->clamavEnabled = pVirusScanPage->pClamAVEngineSwitch->getIsToggled();
				pParam->scriptEnabled = pVirusScanPage->pScriptEngineSwitch->getIsToggled();

				// 快速扫描时若 Yara 引擎已启用，提示用户是否临时关闭
				if (pParam->yaraEnabled && AskDisableYaraForQuickScan(this)) {
					pParam->yaraEnabled = false;
					Log_AddLogSimple(QString::fromUtf8("快速扫描：用户选择本次扫描临时关闭 Yara 引擎。"), LOG_INFO);
				}

				mTotalVirusFound = 0;
				mVirusHandled = 0;
				mScanResultClean = true;

				g_scanCancelRequested = false;
				m_bScanPreparing = false;
				mScanState.store(ssRunning);
				int threadCount = qMin(MAX_SCAN_THREAD, allFiles.count());
				for (int i = 0; i < threadCount; i++) {
					CreateThread(0, 0, ProcessWorkerT, pParam, 0, 0);
				}

				QTimer* checkTimer = new QTimer(this);
				m_pScanCheckTimer = checkTimer;
				QObject::connect(checkTimer, &QTimer::timeout, this, [=]() {
					if (mScanState.load() == ssPrepared) {
						checkTimer->stop();
						checkTimer->deleteLater();
						m_pScanCheckTimer = nullptr;
						hideScanLoading();
						// 快速扫描模式清理
						if (m_bQuickScanMode) {
							m_bQuickScanMode = false;
							if (m_quickScanPhaseBar) m_quickScanPhaseBar->hide();
						}

						pVirusTableModel->removeRows(0, pVirusTableModel->rowCount());
						pScanProgressBar->reset();
						pVirusTable->setVisible(false);
						pButtonLeft->setVisible(false);
						pButtonRight->setVisible(false);
						EngineMainTitle->setVisible(false);
						pProgressDesc->setText("准备就绪\n");

						if (mDrawer1) mDrawer1->setVisible(false);

						QStringList headers;
						headers << "是否隔离" << "文件名" << "病毒名称" << "文件路径";
						pVirusTableModel->setHorizontalHeaderLabels(headers);
						pVirusTableModel->removeColumn(4);

						QTimer::singleShot(500, this, [=]() {
							if (this) slideProgressInOut(pScanProgressBar, false);
							});
						QTimer::singleShot(1300, this, [=]() {
							if (this) {
								pScanProgressBar->reset();
								documentationButton->setEnabled(true);
								spYaraEngineSwitch->setVisible(true);
								spPEEngineSwitch->setVisible(true);
								spSHA256EngineSwitch->setVisible(true);
								spClamAVEngineSwitch->setVisible(true);
								spScriptEngineSwitch->setVisible(true);
								spHighSensitiveSwitch->setVisible(true);
								spExtraPEEngineSwitch->setVisible(true);
								pButtonDecrypt->setVisible(true);

								EngineMainTitle->setVisible(true);
								EngineMainTitle->setText("引擎设置");
							}
							});

						QtConcurrent::run([=]() {
							while (RunningWorkerT.load() > 0) {
								QThread::msleep(50);
							}
							delete pParam;
							});
					}
					else if (mScanState.load() == ssEnding) {
						pProgressDesc->setText("等待选择拦截项目...");
					}
					else if (mScanState.load() == ssScanResult) {
						checkTimer->stop();
						checkTimer->deleteLater();
						m_pScanCheckTimer = nullptr;
						hideScanLoading();
						showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
					}
					else {
						int scannedCount, virusCount;
						QStringList currentVirusNames, currentVirusPaths, currentExtractedPaths;
						QString currentScanningFile;
						vector<quint32> currentVirusPidList;

						pParam->mutex.lock();
						scannedCount = pParam->HasScanedCount;
						virusCount = pParam->AllVirusCount;
						currentVirusNames = pParam->VirusName;
						currentVirusPaths = pParam->VirusPath;
						currentExtractedPaths = pParam->ExtractedFilePaths;
						currentScanningFile = pParam->currentScanningFile;
						currentVirusPidList = pParam->VirusPidList;
						pParam->VirusName.clear();
						pParam->VirusPath.clear();
						pParam->VirusPidList.clear();
						pParam->ExtractedFilePaths.clear();
						pParam->mutex.unlock();

						mTotalScannedFiles = scannedCount;

						if (!currentVirusPaths.isEmpty()) {
							appendVirusRecords(currentVirusNames, currentVirusPaths, currentExtractedPaths, true, currentVirusPidList);
						}

						if (scannedCount >= allFiles.count()) {
							pParam->mutex.lock();
							if (!pParam->VirusPath.isEmpty()) {
								appendVirusRecords(pParam->VirusName, pParam->VirusPath, pParam->ExtractedFilePaths, true, pParam->VirusPidList);
							}
							pParam->mutex.unlock();

							QTimer::singleShot(300, this, [=]() {
								if (this) {
									pScanProgressBar->setValue(pScanProgressBar->maximum());
									pProgressDesc->setText("准备就绪\n");
								}
								});

							QtConcurrent::run([=]() {
								while (RunningWorkerT.load() > 0) {
									QThread::msleep(50);
								}
								delete pParam;
								});

							m_pCurrentScanParam = nullptr;
							m_nCurrentScanType = 0;

							if (m_bQuickScanMode) {
								// 快速扫描模式：进程扫描阶段完成，启动下一阶段
								checkTimer->stop();
								checkTimer->deleteLater();
								m_pScanCheckTimer = nullptr;

								int phase0Threats = pVirusTableModel->rowCount();
								m_quickScanTotalThreats = phase0Threats;
								setQuickScanPhaseDone(0, phase0Threats);

								// 更新累计扫描数（后续阶段的进度条从此偏移开始）
								m_quickScanCumulativeScanned = m_quickScanPhase0Count;

								// 保持 ssRunning 状态，启动阶段 1（启动项扫描）
								startQuickScanPhase(1);
							}
							else if (pVirusTableModel->rowCount() == 0) {
							if (pButtonAddWhite) pButtonAddWhite->setVisible(false);
							mScanResultClean = true;
							mVirusHandled = 0;
							mScanState.store(ssScanResult);
							hideScanLoading();
							NewMessageBox("快速扫描完成：没有发现病毒。", 1, 3);
						}
						else {
							mTotalVirusFound = pVirusTableModel->rowCount();
							pButtonRight->setText("隔离选中");
							pButtonLeft->setText("全部选中");
							mScanState.store(ssEnding);
							pButtonAddWhite->setVisible(true);
							hideScanLoading();
							NewMessageBox(QString("快速扫描完成：发现 %1 个病毒。")
								.arg(pVirusTableModel->rowCount()), 2, 3);
						}
						}
						else {
							if (progressAnimation->state() == QPropertyAnimation::Running)
								progressAnimation->stop();

							if (mScanState.load() == ssStopping) {
								pProgressDesc->setText("快速扫描已暂停。");
							}
							else {
								if (!currentScanningFile.isEmpty()) {
									QString displayText;
									if (currentScanningFile.contains(" >> ")) {
										if (virusCount != 0)
											displayText = QString("进程扫描中 (%2/%3), 发现 %4 个威胁: %1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count()).arg(virusCount);
										else
											displayText = QString("进程扫描中 (%2/%3): %1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count());
									}
									else {
										int fileIndex = qMin(scannedCount, allFiles.count() - 1);
										QString fileName = allFiles[fileIndex];
										if (currentScanningFile != fileName)
											currentScanningFile = fileName;

										if (virusCount != 0)
											displayText = QString("进程扫描中 (%2/%3), 发现 %4 个威胁: %1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count()).arg(virusCount);
										else
											displayText = QString("进程扫描中 (%2/%3): %1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count());
									}
									pProgressDesc->setText(displayText);
								}
								else {
									int fileIndex = qMin(scannedCount, allFiles.count() - 1);
									QString fileName = allFiles[fileIndex];
									if (virusCount != 0)
										pProgressDesc->setText(QString("进程扫描中 (%2/%3), 发现 %4 个威胁: %1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count()).arg(virusCount));
									else
										pProgressDesc->setText(QString("进程扫描中 (%2/%3): %1")
											.arg(currentScanningFile).arg(scannedCount)
											.arg(allFiles.count()));
								}
							}

							progressAnimation->setStartValue(pScanProgressBar->value());
							int progressValue = (m_quickScanCumulativeScanned + scannedCount) * 10;
							int maxProgress = m_quickScanTotalFiles * 10;
							if (progressValue > maxProgress) progressValue = maxProgress;
							progressAnimation->setEndValue(progressValue);
							progressAnimation->start();
						}
					}
					});

				hideScanLoading();
				checkTimer->start(100);

				fileListWatcher->deleteLater();
			});

		QFuture<vector<std::pair<QString, quint32>>> future = QtConcurrent::run([=]() {
			std::unordered_map<QString, vector<quint32>> fileToPidsMap;
			QList<quint32> pids;
			HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (hSnapshot != INVALID_HANDLE_VALUE) {
				PROCESSENTRY32 pe32;
				pe32.dwSize = sizeof(PROCESSENTRY32);
				if (Process32First(hSnapshot, &pe32)) {
					do {
						pids.append(pe32.th32ProcessID);
					} while (Process32Next(hSnapshot, &pe32));
				}
				CloseHandle(hSnapshot);
			}
			for (quint32 pid : pids) {
				HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
				if (hModuleSnapshot != INVALID_HANDLE_VALUE) {
					MODULEENTRY32 me32;
					me32.dwSize = sizeof(MODULEENTRY32);
					if (Module32First(hModuleSnapshot, &me32)) {
						do {
							QString modulePath = QString::fromWCharArray(me32.szExePath);
							if (!modulePath.isEmpty()) {
								fileToPidsMap[modulePath].push_back(pid);
							}
						} while (Module32Next(hModuleSnapshot, &me32));
					}
					CloseHandle(hModuleSnapshot);
				}
			}
			vector<std::pair<QString, quint32>> fileListWithPid;
			for (const auto& item : fileToPidsMap) {
				if (!item.second.empty()) {
					fileListWithPid.push_back(std::pair(item.first, item.second[0]));
				}
			}
			return fileListWithPid;
			});
		fileListWatcher->setFuture(future);
		});


	// ========== 按钮初始化 ==========
	pButtonLeft = new ElaPushButton;
	pButtonRight = new ElaPushButton;
	pButtonAddWhite = new ElaPushButton;

	pButtonLeft->setText("暂停扫描");
	pButtonRight->setText("终止扫描");
	pButtonLeft->setVisible(false);
	pButtonRight->setVisible(false);

	QHBoxLayout* bLayout = new QHBoxLayout();
	bLayout->addWidget(documentationButton);
	bLayout->addStretch();
	bLayout->addWidget(pButtonLeft);
	bLayout->addSpacing(5);

	pButtonAddWhite->setText("添加白名单");
	pButtonAddWhite->setVisible(false);
	bLayout->addWidget(pButtonAddWhite);
	bLayout->addSpacing(5);
	bLayout->addWidget(pButtonRight);


	// ========== 左按钮（暂停/恢复/全选/全不选） ==========
	connect(pButtonLeft, &ElaPushButton::clicked, this, [this]() {
		if (mScanState == ssRunning) {
			pButtonLeft->setText("恢复扫描");
			mScanState = ssStoppingPreparing;
			pButtonLeft->setEnabled(false);

			QTimer* checkTimer = new QTimer(this);
			QObject::connect(checkTimer, &QTimer::timeout, this, [=]() {
				if (mScanState == ssStopping || mScanState == ssEnding || mScanState == ssPrepared) {
					checkTimer->stop();
					pButtonLeft->setEnabled(true);
				}
				});
			checkTimer->start(100);
		}
		else if (mScanState == ssStopping) {
			pButtonLeft->setText("暂停扫描");
			mScanState = ssRunning;
		}
		else if (mScanState == ssEnding) {
			for (int row = 0; row < pVirusTableModel->rowCount(); ++row) {
				QStandardItem* item = pVirusTableModel->item(row, 0);
				if (item) {
					item->setCheckState((CheckBoxAllChose) ? Qt::Checked : Qt::Unchecked);
				}
			}
			if (CheckBoxAllChose) {
				pButtonLeft->setText("全部不选");
				CheckBoxAllChose = FALSE;
			}
			else {
				pButtonLeft->setText("全部选中");
				CheckBoxAllChose = TRUE;
			}
		}
		});


	// ========== 右按钮（终止/隔离/拦截） ==========
	connect(pButtonRight, &ElaPushButton::clicked, this, [this]() {
		if (mScanState == ssPrepared && m_bScanPreparing) {
			// 准备阶段（收集文件列表期间）点击终止：立即取消准备，恢复初始状态
			++m_scanGeneration;			// 作废 pending watcher 回调，防止干扰下次扫描
			g_scanCancelRequested = true;
			m_bScanPreparing = false;

			if (m_bQuickScanMode) {
				m_bQuickScanMode = false;
				if (m_quickScanPhaseBar) m_quickScanPhaseBar->hide();
			}

			hideScanLoading();
			pVirusTableModel->removeRows(0, pVirusTableModel->rowCount());
			pScanProgressBar->reset();
			slideProgressInOut(pScanProgressBar, false);
			pVirusTable->setVisible(false);
			pButtonLeft->setVisible(false);
			pButtonRight->setVisible(false);
			EngineMainTitle->setVisible(false);
			pProgressDesc->setText("准备就绪\n");
			if (mDrawer1) mDrawer1->setVisible(false);

			QTimer::singleShot(500, this, [=]() {
				if (this) {
					pScanProgressBar->reset();
					documentationButton->setEnabled(true);
					spYaraEngineSwitch->setVisible(true);
					spPEEngineSwitch->setVisible(true);
					spSHA256EngineSwitch->setVisible(true);
					spClamAVEngineSwitch->setVisible(true);
					spScriptEngineSwitch->setVisible(true);
					spHighSensitiveSwitch->setVisible(true);
					spExtraPEEngineSwitch->setVisible(true);
					pButtonDecrypt->setVisible(true);

					EngineMainTitle->setVisible(true);
					EngineMainTitle->setText("引擎设置");
				}
				});
			return;
		}
		if (mScanState == ssRunning || mScanState == ssStopping || mScanState == ssStoppingPreparing) {
			// 快速扫描模式终止：隐藏阶段指示器，恢复标准模式
			if (m_bQuickScanMode) {
				m_bQuickScanMode = false;
				if (m_quickScanPhaseBar) m_quickScanPhaseBar->hide();
				EngineMainTitle->setVisible(true);
				EngineMainTitle->setText("快速扫描威胁列表");
				pVirusTable->setVisible(true);
			}
			if (pVirusTableModel->rowCount() == 0) {
				mTotalVirusFound = 0;
				mScanResultClean = true;
				mVirusHandled = 0;

				// 通知工作线程停止领取新文件
				g_scanCancelRequested = true;
				SetScanParamStopRequested(m_pCurrentScanParam, m_nCurrentScanType);
				mScanState = ssScanResult;

				// 隐藏"正在扫描"提示框并恢复提示文字
				hideScanLoading();
				pProgressDesc->setText("准备就绪\n");

				// 停止轮询定时器（原 checkTimer 会在下次 tick 检测到 ssScanResult 并切换页面，但终止时立即停止避免继续显示扫描中状态）
				if (m_pScanCheckTimer) {
					m_pScanCheckTimer->stop();
					m_pScanCheckTimer->deleteLater();
					m_pScanCheckTimer = nullptr;
				}

				// 等待工作线程退出后释放 pParam（避免内存泄漏）
				void* pParamToClean = m_pCurrentScanParam;
				int scanType = m_nCurrentScanType;
				m_pCurrentScanParam = nullptr;
				m_nCurrentScanType = 0;
				QtConcurrent::run([pParamToClean, scanType]() {
					while (RunningWorkerT.load() > 0) {
						QThread::msleep(50);
					}
					if (scanType == 1) delete (WorkerTParam*)pParamToClean;
					else if (scanType == 2) delete (DirWorkerTParam*)pParamToClean;
					else if (scanType == 3) delete (ProcessWorkerTParam*)pParamToClean;
					});

				NewMessageBox("扫描完成：没有发现病毒。", 1, 3);
				Log_AddLogSimple(QString::fromUtf8("扫描完成：没有发现病毒。共扫描 %1 个文件。").arg(mTotalScannedFiles), LOG_SUCCESS);

				// 切换到扫描结果视图
				showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
			}
			else {
			mTotalVirusFound = pVirusTableModel->rowCount();
			mVirusHandled = 0;

			pButtonRight->setText("隔离选中");
			pButtonLeft->setText("全部选中");
			mScanState = ssEnding;
			g_scanCancelRequested = true;

			// 通知工作线程停止领取新文件，避免终止后各线程继续扫描队列中剩余文件
			SetScanParamStopRequested(m_pCurrentScanParam, m_nCurrentScanType);

			// 隐藏"正在扫描"提示框并更新提示文字
			hideScanLoading();
			pProgressDesc->setText("等待选择隔离项目...");

			pButtonLeft->setEnabled(false);
			pButtonRight->setEnabled(false);

				if (progressAnimation->state() == QPropertyAnimation::Running)
					progressAnimation->stop();

				// 停止正常轮询定时器，避免资源浪费和双重处理
				if (m_pScanCheckTimer) {
					m_pScanCheckTimer->stop();
					m_pScanCheckTimer->deleteLater();
					m_pScanCheckTimer = nullptr;
				}

				// 创建快速停止轮询定时器（20ms 间隔，比原来的 100ms 更快响应）
				QTimer* stopCheckTimer = new QTimer(this);
				m_pScanCheckTimer = stopCheckTimer;
				QObject::connect(stopCheckTimer, &QTimer::timeout, this, [=]() {
					if (RunningWorkerT.load() == 0) {
						stopCheckTimer->stop();
						stopCheckTimer->deleteLater();
						m_pScanCheckTimer = nullptr;

						// 排空工作线程缓冲区中剩余的扫描结果（避免丢失威胁）
						void* pParamRaw = m_pCurrentScanParam;
						int scanType = m_nCurrentScanType;
						if (pParamRaw) {
							if (scanType == 1) {
								WorkerTParam* p = (WorkerTParam*)pParamRaw;
								p->mutex.lock();
								if (!p->VirusPath.isEmpty()) {
									appendVirusRecords(p->VirusName, p->VirusPath, p->ExtractedFilePaths);
								}
								mTotalScannedFiles = p->HasScanedCount;
								p->mutex.unlock();
							}
							else if (scanType == 2) {
								DirWorkerTParam* p = (DirWorkerTParam*)pParamRaw;
								p->resultMutex.lock();
								if (!p->VirusPath.isEmpty()) {
									appendVirusRecords(p->VirusName, p->VirusPath, p->ExtractedFilePaths);
								}
								mTotalScannedFiles = p->HasScanedCount;
								p->resultMutex.unlock();
							}
							else if (scanType == 3) {
								ProcessWorkerTParam* p = (ProcessWorkerTParam*)pParamRaw;
								p->mutex.lock();
								if (!p->VirusPath.isEmpty()) {
									appendVirusRecords(p->VirusName, p->VirusPath, p->ExtractedFilePaths, true, p->VirusPidList);
								}
								mTotalScannedFiles = p->HasScanedCount;
								p->mutex.unlock();
							}

							// 更新发现的威胁总数（排空后可能有新增）
							if (pVirusTableModel->rowCount() > mTotalVirusFound) {
								mTotalVirusFound = pVirusTableModel->rowCount();
							}
						}

						// 释放 pParam（避免内存泄漏）
						m_pCurrentScanParam = nullptr;
						m_nCurrentScanType = 0;
						QtConcurrent::run([pParamRaw, scanType]() {
							if (scanType == 1) delete (WorkerTParam*)pParamRaw;
							else if (scanType == 2) delete (DirWorkerTParam*)pParamRaw;
							else if (scanType == 3) delete (ProcessWorkerTParam*)pParamRaw;
							});

						pButtonLeft->setEnabled(true);
						pButtonRight->setEnabled(true);
						if (pButtonAddWhite) pButtonAddWhite->setVisible(true);

						progressAnimation->setStartValue(pScanProgressBar->value());
						progressAnimation->setEndValue(pScanProgressBar->maximum());
						progressAnimation->start();
					}
					});
				stopCheckTimer->start(20);
			}
		}
		else if (mScanState == ssEnding) {
			int handled = 0;
			// 使用 unordered_set 记录已结束的PID，避免重复结束同一进程
			std::unordered_set<quint32> terminatedPids;

			// 收集所有需要处理的文件路径
			QStringList filesToProcess;
			QList<quint32> pidsToTerminate;
			QList<int> processRows;  // 记录进程对应的行号，用于获取pathItem

			for (int row = 0; row < pVirusTableModel->rowCount(); ++row) {
				QStandardItem* checkItem = pVirusTableModel->item(row, 0);
				if (checkItem && checkItem->checkState() == Qt::Checked) {
					QStandardItem* pathItem = pVirusTableModel->item(row, 3);

					if (pVirusTableModel->columnCount() == 4) {
						// 文件/文件夹扫描的隔离
						if (pathItem) {
							QString mainPath = pathItem->data(Qt::UserRole).toString();
							if (!mainPath.isEmpty()) {
								filesToProcess.append(mainPath);
							}
						}
					}
					else {
						// 进程扫描的拦截
						QStandardItem* pidItem = pVirusTableModel->item(row, 4);
						if (pidItem && !pidItem->text().isEmpty()) {
							quint32 pid = pidItem->text().toUInt();
							// 查重：避免重复结束同一进程
							if (terminatedPids.find(pid) == terminatedPids.end()) {
								terminatedPids.insert(pid);
								pidsToTerminate.append(pid);
								processRows.append(row);
							}
						}
					}
					handled++;
				}
			}

			// 先处理进程终止（较快完成）
			for (int i = 0; i < pidsToTerminate.size(); ++i) {
				quint32 pid = pidsToTerminate[i];
				int row = processRows[i];
				QStandardItem* pathItem = pVirusTableModel->item(row, 3);

				HANDLE hPro = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				if (hPro) {
					if (!Process_ZwTerminateProcess(hPro, 0)) {
						if (pathItem) {
							QString mainPath = pathItem->data(Qt::UserRole).toString();
							QString name = QFileInfo(mainPath).fileName();
							NewMessageBox(QString("进程 %1 (PID: %2) 拦截失败。").arg(name).arg(pid), 3);
						}
					}
					CloseHandle(hPro);
				}
				else if (pathItem) {
					QString mainPath = pathItem->data(Qt::UserRole).toString();
					QString name = QFileInfo(mainPath).fileName();
					NewMessageBox(QString("进程 %1 (PID: %2) 拦截失败。").arg(name).arg(pid), 3);
				}
			}

			// 处理文件加密（使用线程池限制并发数）
			// 现代化进度对话框（参考 WhitelistPage::ShowModernConfirmDialog 样式：主题感知、深色模式支持）
			if (!filesToProcess.isEmpty()) {
				// 设置最大线程数为6
				QThreadPool::globalInstance()->setMaxThreadCount(6);

				// 创建美观的进度对话框
				ElaDialog* progressDialog = new ElaDialog();
				progressDialog->setWindowTitle("正在隔离文件");
				progressDialog->setWindowButtonFlags(ElaAppBarType::CloseButtonHint);
				progressDialog->setFixedSize(440, 240);
				progressDialog->setIsFixedSize(true);
				progressDialog->setWindowModality(Qt::WindowModal);

				// 创建现代化内容（参考 WhitelistPage::ShowModernConfirmDialog 样式）
				QWidget* content = new QWidget(progressDialog);
				QVBoxLayout* layout = new QVBoxLayout(content);
				layout->setContentsMargins(28, 20, 28, 20);
				layout->setSpacing(12);

				// 标题行（图标 + 标题）
				QWidget* headerWidget = new QWidget();
				QHBoxLayout* headerLayout = new QHBoxLayout(headerWidget);
				headerLayout->setContentsMargins(0, 0, 0, 0);
				headerLayout->setSpacing(10);

				QLabel* iconLabel = new QLabel();
				iconLabel->setObjectName("progressIcon");
				QPixmap progIcon(28, 28);
				progIcon.fill(Qt::transparent);
				{
					QPainter painter(&progIcon);
					painter.setRenderHint(QPainter::Antialiasing);
					painter.setBrush(QColor("#3B82F6"));
					painter.setPen(Qt::NoPen);
					painter.drawEllipse(2, 2, 24, 24);
					painter.setPen(QPen(Qt::white, 2.5, Qt::SolidLine, Qt::RoundCap));
					painter.drawLine(10, 14, 13, 18);
					painter.drawLine(13, 18, 19, 9);
				}
				iconLabel->setPixmap(progIcon);

				QLabel* titleLabel = new QLabel(QString::fromUtf8("正在处理文件..."));
				titleLabel->setObjectName("progressTitle");
				titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; border: none;");

				headerLayout->addWidget(iconLabel);
				headerLayout->addWidget(titleLabel);
				headerLayout->addStretch();

				// 进度条
				QProgressBar* progressBar = new QProgressBar();
				progressBar->setObjectName("progressBar");
				progressBar->setRange(0, filesToProcess.size());
				progressBar->setTextVisible(true);
				progressBar->setFixedHeight(24);
				progressBar->setValue(0);

				// 详细信息标签
				QLabel* detailLabel = new QLabel(QString::fromUtf8("共 %1 个文件待处理").arg(filesToProcess.size()));
				detailLabel->setObjectName("progressDetail");
				detailLabel->setStyleSheet("font-size: 12px; border: none;");

				layout->addWidget(headerWidget);
				layout->addWidget(progressBar);
				layout->addWidget(detailLabel);
				layout->addStretch();

				QVBoxLayout* dlgLayout = new QVBoxLayout(progressDialog);
				dlgLayout->setContentsMargins(0, 0, 0, 0);
				dlgLayout->setSpacing(0);
				dlgLayout->addWidget(content);

				// 主题样式更新（深色/浅色模式自适应）
				auto updateStyle = [progressDialog]() {
					ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
					bool isDark = (themeMode == ElaThemeType::Dark);
					QString bgColor = ElaThemeColor(themeMode, WindowBase).name();
					QString textColor = isDark ? "#E5E7EB" : "#333333";
					QString descColor = isDark ? "#9CA3AF" : "#666666";
					QString trackBg = isDark ? "#374151" : "#F3F4F6";
					QString trackBorder = isDark ? "#4B5563" : "#E5E7EB";

					progressDialog->setStyleSheet(
						QString("QDialog { background: %1; border-radius: 12px; }").arg(bgColor));

					QLabel* t = progressDialog->findChild<QLabel*>("progressTitle");
					if (t) t->setStyleSheet(
						QString("font-size: 16px; font-weight: bold; color: %1; border: none;").arg(textColor));

					QLabel* d = progressDialog->findChild<QLabel*>("progressDetail");
					if (d) d->setStyleSheet(
						QString("font-size: 12px; color: %1; border: none;").arg(descColor));

					QProgressBar* pb = progressDialog->findChild<QProgressBar*>("progressBar");
					if (pb) pb->setStyleSheet(QString(
						"QProgressBar {"
						"  border: 2px solid %1;"
						"  border-radius: 8px;"
						"  background-color: %2;"
						"  text-align: center;"
						"  font-size: 12px;"
						"  color: %3;"
						"}"
						"QProgressBar::chunk {"
						"  background: qlineargradient(x1:0, y1:0, x2:1, y2:0,"
						"    stop:0 #3B82F6, stop:1 #60A5FA);"
						"  border-radius: 6px;"
						"}").arg(trackBorder).arg(trackBg).arg(textColor));
				};
				updateStyle();
				QObject::connect(eTheme, &ElaTheme::themeModeChanged, progressDialog, [&updateStyle]() { updateStyle(); });

				progressDialog->moveToCenter();
				progressDialog->show();

				// 使用原子计数器跟踪完成进度
				QAtomicInt completedCount(0);
				QAtomicInt errorCount(0);

				// 使用QFutureWatcher监控所有任务
				QFutureWatcher<void> watcher;
				QList<QFuture<void>> futures;

				for (const QString& filePath : filesToProcess) {
					QFuture<void> future = QtConcurrent::run([filePath, &completedCount, &errorCount]() {
						int result = Encrypt_OrgEncrptFile(
							QString(filePath).toLocal8Bit().toStdString(),
							QString(filePath + ".iot").toLocal8Bit().toStdString(),
							ENCRPT_XOR_PASSWORD
						);

						completedCount.fetchAndAddOrdered(1);
						if (result != 0) {
							errorCount.fetchAndAddOrdered(1);
						}
						});
					futures.append(future);
				}

				// 等待所有任务完成，同时更新进度
				for (int i = 0; i < futures.size(); ++i) {
					futures[i].waitForFinished();
					progressBar->setValue(completedCount.loadRelaxed());
					detailLabel->setText(QString::fromUtf8("已完成 %1/%2").arg(completedCount.loadRelaxed()).arg(filesToProcess.size()));
					QApplication::processEvents();  // 保持UI响应
				}

				// 关闭进度对话框
				progressDialog->close();
				progressDialog->deleteLater();

				// 显示处理结果
				if (errorCount.loadRelaxed() > 0) {
					NewMessageBox(QString::fromUtf8("处理完成，共 %1 个文件，其中 %2 个处理失败。")
						.arg(filesToProcess.size())
						.arg(errorCount.loadRelaxed()), 1);
				}
			}

			// 设置结果状态：使用实际处理的计数量
			mScanResultClean = (handled >= pVirusTableModel->rowCount());
			mVirusHandled = handled;  // FIX: 使用隔离循环中实际统计的已处理数
            mScanState = ssScanResult;

			// 显示扫描结果提示并登记日志到主页面
			{
				int totalFound = mTotalVirusFound > 0 ? mTotalVirusFound : pVirusTableModel->rowCount();
				int handledCount = mVirusHandled;
				if (handledCount >= totalFound) {
					NewMessageBox("扫描完成，所有威胁已处理！", 1, 3);
					Log_AddLogSimple(QString::fromUtf8("扫描完成：发现 %1 个威胁，已处理 %2 个。所有威胁已处理。").arg(totalFound).arg(handledCount), LOG_SUCCESS);
				}
				else {
					NewMessageBox(QString::fromUtf8("扫描完成：共发现 %1 个威胁，已处理 %2 个。").arg(totalFound).arg(handledCount), 2, 3);
					Log_AddLogSimple(QString::fromUtf8("扫描完成：发现 %1 个威胁，已处理 %2 个，存在未处理项。").arg(totalFound).arg(handledCount), LOG_WARN);
				}
			}

			if (pButtonAddWhite) pButtonAddWhite->setVisible(false);

			// 切换到扫描结果视图（修复隔离选中后页面未退出的问题）
			hideScanLoading();
			showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
		}
		});


	// ========== 添加白名单 ==========
	connect(pButtonAddWhite, &ElaPushButton::clicked, this, [this]() {
		if (mScanState != ssEnding) return;

		QList<int> checkedRows;
		for (int row = 0; row < pVirusTableModel->rowCount(); ++row) {
			QStandardItem* checkItem = pVirusTableModel->item(row, 0);
			if (checkItem && checkItem->checkState() == Qt::Checked)
				checkedRows.append(row);
		}

		for (int i = checkedRows.size() - 1; i >= 0; --i) {
			int row = checkedRows[i];
			QStandardItem* pathItem = pVirusTableModel->item(row, 3);
			if (pathItem && !pathItem->text().isEmpty()) {
				QString targetPath = pathItem->data(Qt::UserRole).toString();
				if (!targetPath.isEmpty()) {
					string spath = targetPath.toLocal8Bit().toStdString();
					string sha = Encrypt_CalculateFileSHA256(spath);
					std::transform(sha.begin(), sha.end(), sha.begin(),
						[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
					EnterCriticalSection(&g_csScanCache);
					WhiteSha256ListCache[sha] = spath;
					HasBeenScanedSha256BlackList.erase(sha);
					LeaveCriticalSection(&g_csScanCache);
				}
			}
			pVirusTableModel->removeRow(row);
		}

		// 计算剩余
		int remaining = pVirusTableModel->rowCount();

		// 全部移除后自动转到结果页
		if (remaining == 0) {
			mScanResultClean = true;
			mVirusHandled = mTotalVirusFound;  // 全部处理完了
			mScanState = ssScanResult;
            if (pButtonAddWhite) pButtonAddWhite->setVisible(false);

			// 提示并记录日志：所有威胁已被添加到白名单并处理
			NewMessageBox(QString::fromUtf8("已将选中项添加到白名单并处理完成：共 %1 个威胁已处理。")
				.arg(mVirusHandled), 1, 3);
			Log_AddLogSimple(QString::fromUtf8("扫描结果：用户将 %1 个威胁添加到白名单并处理。")
			.arg(mVirusHandled), LOG_INFO);

			// 切换到扫描结果视图（修复添加白名单后剩余总数归零未跳转结果界面的问题）
			hideScanLoading();
			showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
		}

		HasBeenScanedSha256BlackList.clear();
		HasBeenScanedTypeBlackList.clear();
		HasBeenScanedSha256WhiteList.clear();

		NewMessageBox("已将选中项添加到白名单并从结果中移除。", 1, 2);
		});

    QVBoxLayout* topLayout = new QVBoxLayout(customWidget);
    topLayout->setContentsMargins(0, 0, 0, 0);
    topLayout->addWidget(descText);
    topLayout->addSpacing(20);
    topLayout->addLayout(bLayout);

    setCustomWidget(customWidget);
}

// 截断文件名显示：根据列宽和字体自动适配，优先使用像素级别的中间截断；
// 若未提供列宽则回退到保留前20+后10字符的策略
static QString shortenFileName(const QString& name, int columnWidth = 0, const QFont& font = QFont())
{
	// 如果有列宽信息，使用 QFontMetrics::elidedText 做像素级截断（中间省略）
	if (columnWidth > 0) {
		QFontMetrics fm(font);
		const int padding = 12; // 预留一些内边距
		int avail = columnWidth - padding;
		if (avail <= 0) return name;
		return fm.elidedText(name, Qt::ElideMiddle, avail);
	}

	// 回退策略：按字符截断以避免中文半字
	int len = name.size();
	if (len <= 30) return name; // 前20 + 后10
	QString head = name.left(20);
	QString tail = name.right(10);
	return head + "..." + tail;
}

// 根据 PID 获取进程可执行文件名（如 "explorer.exe"）
static QString GetProcessExeNameFromPid(quint32 pid)
{
	if (pid == 0) return QString();
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (!hProcess) return QString();
	WCHAR pathBuffer[MAX_PATH] = { 0 };
	DWORD pathSize = MAX_PATH;
	QString processName;
	if (QueryFullProcessImageNameW(hProcess, 0, pathBuffer, &pathSize)) {
		processName = QFileInfo(QString::fromWCharArray(pathBuffer)).fileName();
	}
	CloseHandle(hProcess);
	return processName;
}

// 添加病毒记录，支持主文件路径与提取文件路径分开存储
void VirusScanPage::addVirusRecord(const QString& virusName, const QString& mainFilePath, const QString& extractedFilePath, const quint32 PID)
{
	// 去重：检查主文件路径是否已存在于表格中（避免同一文件重复报毒）
	for (int row = 0; row < pVirusTableModel->rowCount(); ++row)
	{
		QStandardItem* existingPathItem = pVirusTableModel->item(row, 3);
		if (existingPathItem)
		{
			QString existingPath = existingPathItem->data(Qt::UserRole).toString();
			if (!existingPath.isEmpty() && existingPath.compare(mainFilePath, Qt::CaseInsensitive) == 0)
			{
				return; // 已存在相同路径，跳过
			}
		}
	}

	QList<QStandardItem*> rowItems;

	// 第0列：复选框（使用CheckStateRole）
	QStandardItem* checkItem = new QStandardItem();
	checkItem->setCheckable(true);
	checkItem->setCheckState(Qt::Unchecked);
	checkItem->setTextAlignment(Qt::AlignCenter);
	rowItems.append(checkItem);

    // 第1列：文件名 - 根据当前列宽与字体进行像素级截断（中间省略）以适配用户调整列宽
	QString mainName = QFileInfo(mainFilePath).fileName();
	QString displayName;
	QFont tableFont = pVirusTable ? pVirusTable->font() : QFont();
	int colWidth = (pVirusTable) ? pVirusTable->columnWidth(1) : 0;
	if (!extractedFilePath.isEmpty()) {
		QString extractName = QFileInfo(extractedFilePath).fileName();
		// 将列宽平均分配给主名与提取名以获得更合理的显示
		int halfWidth = (colWidth > 0) ? (colWidth / 2) : 0;
		QString mainShort = shortenFileName(mainName, halfWidth, tableFont);
		QString extractShort = shortenFileName(extractName, halfWidth, tableFont);
		displayName = mainShort + " >> " + extractShort;
	}
	else {
		displayName = shortenFileName(mainName, colWidth, tableFont);
	}
	// Tooltip 显示完整原始名（方便查看），Item 文本显示截断后的名字
	QString fullDisplayTooltip = !extractedFilePath.isEmpty()
		? (mainName + " >> " + QFileInfo(extractedFilePath).fileName())
		: mainName;
	QStandardItem* nameItem = new QStandardItem(displayName);
	nameItem->setToolTip(fullDisplayTooltip);
	rowItems.append(nameItem);

	// 第2列：病毒名称（由VirusNameDelegate绘制红色圆角矩形框）
	QStandardItem* virusItem = new QStandardItem(virusName);
	virusItem->setToolTip(virusName);
	// 不设置前景色，由VirusNameDelegate全权负责绘制样式
	rowItems.append(virusItem);

    // 第3列：文件路径（显示为 "主路径 >> 提取文件名"，但将主路径和提取路径分别保存到数据中）
	QString displayPath;
	if (!extractedFilePath.isEmpty()) {
		QString extractName = QFileInfo(extractedFilePath).fileName();
		displayPath = mainFilePath + " >> " + extractName;
	}
	else {
		displayPath = mainFilePath;
	}

	QStandardItem* pathItem = new QStandardItem(displayPath);
	pathItem->setToolTip(displayPath);
	// 保存主文件完整路径（供隔离等操作使用）
	pathItem->setData(mainFilePath, Qt::UserRole);
	// 保存提取文件完整路径（若无则为空）
	pathItem->setData(extractedFilePath, Qt::UserRole + 1);
	rowItems.append(pathItem);

	if (PID != 0)
	{
		// 第4列：加载进程（进程名 + PID）
		QString procName = GetProcessExeNameFromPid(PID);
		QString displayText = procName.isEmpty()
			? QString("%1").arg(PID)
			: QString("%1 (%2)").arg(procName).arg(PID);
		QStandardItem* PIDItem = new QStandardItem(displayText);
		PIDItem->setToolTip(displayText);
		rowItems.append(PIDItem);
	}

	pVirusTableModel->appendRow(rowItems);
}

// 增量添加（支持提取文件路径单独传入，避免使用字符串分割）
void VirusScanPage::appendVirusRecords(const QStringList& virusNames, const QStringList& mainFilePaths, const QStringList& extractedFilePaths, bool isEnablePID, vector<quint32> PIDList)
{
	// 列表以最短为准
	int count = qMin(virusNames.size(), mainFilePaths.size());
	int haveExtract = extractedFilePaths.size();
	for (int i = 0; i < count; ++i)
	{
		QString mainPath = mainFilePaths.value(i);
		QString extractedPath = (i < haveExtract) ? extractedFilePaths.value(i) : QString();
		if (!isEnablePID || PIDList.empty()) addVirusRecord(virusNames.value(i), mainPath, extractedPath);
		else addVirusRecord(virusNames.value(i), mainPath, extractedPath, PIDList[i]);
	}

	pVirusTable->resizeColumnsToContents();
}


void VirusScanPage::CreateEngineOptions(ElaToggleSwitch*& pWidget, QString EngineName, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType)
{
    pWidget = new ElaToggleSwitch(this);
    pWidget->setIsToggled(true);
    toggleSwitchArea = new ElaScrollPageArea(this);
    toggleSwitchArea->setFixedHeight(50);

    QHBoxLayout* toggleSwitchLayout = new QHBoxLayout(toggleSwitchArea);
	ElaText* toggleSwitchIcon = new ElaText(this);
    ElaText* toggleSwitchText = new ElaText(EngineName, this);
	toggleSwitchIcon->setElaIcon(EiType);
	toggleSwitchIcon->setFixedWidth(30);
    toggleSwitchText->setTextPixelSize(15);
    toggleSwitchText->setFixedWidth(430);
	toggleSwitchLayout->addWidget(toggleSwitchIcon);
	toggleSwitchLayout->addSpacing(10);
    toggleSwitchLayout->addWidget(toggleSwitchText);
    toggleSwitchLayout->addStretch();
    toggleSwitchLayout->addWidget(pWidget);

	connect(pWidget, &ElaToggleSwitch::toggled, this, [](bool checked){
		HasBeenScanedSha256BlackList.clear();
		HasBeenScanedTypeBlackList.clear();
		HasBeenScanedSha256WhiteList.clear();
		});
}

void VirusScanPage::CreateEngineOptionsWithRing(ElaToggleSwitch*& pWidget, QString EngineName, ElaScrollPageArea*& toggleSwitchArea, ElaIconType::IconName EiType, ElaProgressRing*& progressBusyTransparentRing)
{
	pWidget = new ElaToggleSwitch(this);
	pWidget->setIsToggled(true);
	toggleSwitchArea = new ElaScrollPageArea(this);
	toggleSwitchArea->setFixedHeight(50);

	progressBusyTransparentRing = new ElaProgressRing(this);
	progressBusyTransparentRing->setIsBusying(true);
	progressBusyTransparentRing->setIsTransparent(true);
	progressBusyTransparentRing->setFixedHeight(25);
	progressBusyTransparentRing->setFixedWidth(25);
	progressBusyTransparentRing->setBusyingWidth(3);

	QHBoxLayout* toggleSwitchLayout = new QHBoxLayout(toggleSwitchArea);
	ElaText* toggleSwitchIcon = new ElaText(this);
	ElaText* toggleSwitchText = new ElaText(EngineName, this);
	toggleSwitchIcon->setElaIcon(EiType);
	toggleSwitchIcon->setFixedWidth(30);
	toggleSwitchText->setTextPixelSize(15);
	toggleSwitchText->setFixedWidth(360);
	toggleSwitchLayout->addWidget(toggleSwitchIcon);
	toggleSwitchLayout->addSpacing(10);
	toggleSwitchLayout->addWidget(toggleSwitchText);
	toggleSwitchLayout->addStretch();
	toggleSwitchLayout->addWidget(progressBusyTransparentRing);
	toggleSwitchLayout->addSpacing(10);
	toggleSwitchLayout->addWidget(pWidget);

	connect(pWidget, &ElaToggleSwitch::toggled, this, [](bool checked) {
		HasBeenScanedSha256BlackList.clear();
		HasBeenScanedTypeBlackList.clear();
		HasBeenScanedSha256WhiteList.clear();
		});
}


VirusScanPage::VirusScanPage(QWidget* parent)
{
	createCustomWidget("定期查杀文件、文件夹，保证电脑安全。");

	// ========== 创建页面切换容器 ==========
	m_stackedWidget = new QStackedWidget(this);
	m_stackedWidget->setObjectName("scanStackedWidget");

	// ========== 第1页：扫描页面 ==========
	m_scanPageWidget = new QWidget();
	m_scanPageWidget->setObjectName("scanPageWidget");
	QVBoxLayout* scanPageLayout = new QVBoxLayout(m_scanPageWidget);
	scanPageLayout->setContentsMargins(0, 0, 0, 0);
	scanPageLayout->setSpacing(0);

	// --- 引擎标题布局 ---
	QHBoxLayout* EngineLayout = new QHBoxLayout;

	EngineMainTitle = new ElaText;
	EngineMainTitle->setText("引擎设置");
	EngineMainTitle->setTextPixelSize(20);

	EngineLayout->addWidget(EngineMainTitle);

	// --- 进度条 ---
	pScanProgressBar = new ElaProgressBar;
	pScanProgressBar->setVisible(false);

	pProgressDesc = new ElaText(this);
	pProgressDesc->setText("准备就绪\n");
	pProgressDesc->setTextPixelSize(12);

	progressAnimation = new QPropertyAnimation(pScanProgressBar, "value");
	progressAnimation->setDuration(300);
	progressAnimation->setEasingCurve(QEasingCurve::OutCubic);

	// --- 扫描加载遮罩 ---
	m_scanLoadingOverlay = new QWidget(m_scanPageWidget);
	m_scanLoadingOverlay->setAttribute(Qt::WA_TransparentForMouseEvents, false);
	m_scanLoadingOverlay->hide();

	m_scanLoadingRing = new ElaProgressRing(m_scanLoadingOverlay);
	m_scanLoadingRing->setIsBusying(true);
	m_scanLoadingRing->setIsTransparent(true);
	m_scanLoadingRing->setFixedHeight(48);
	m_scanLoadingRing->setFixedWidth(48);
	m_scanLoadingRing->setBusyingWidth(3);

	QLabel* scanLoadingText = new QLabel("正在准备扫描引擎...", m_scanLoadingOverlay);
	scanLoadingText->setObjectName("scanLoadingText");
	scanLoadingText->setAlignment(Qt::AlignCenter);

	QVBoxLayout* overlayLayout = new QVBoxLayout(m_scanLoadingOverlay);
	overlayLayout->setContentsMargins(0, 0, 0, 0);
	overlayLayout->setSpacing(12);
	overlayLayout->addStretch();
	overlayLayout->addWidget(m_scanLoadingRing, 0, Qt::AlignCenter);
	overlayLayout->addWidget(scanLoadingText, 0, Qt::AlignCenter);
	overlayLayout->addStretch();

	/* 根据当前主题应用遮罩样式 */
	updateScanLoadingOverlayStyle();

	// --- 病毒表格 ---
	pVirusTable = new ElaTableView;
	pVirusTableModel = new QStandardItemModel(this);

	QStringList headers;
	headers << "是否隔离" << "文件名" << "病毒名称" << "文件路径";
	pVirusTableModel->setHorizontalHeaderLabels(headers);
	pVirusTable->setModel(pVirusTableModel);

	CheckBoxDelegate* checkBoxDelegate = new CheckBoxDelegate(this);
	pVirusTable->setItemDelegateForColumn(0, checkBoxDelegate);

	VirusNameDelegate* virusNameDelegate = new VirusNameDelegate(this);
	pVirusTable->setItemDelegateForColumn(2, virusNameDelegate);

	pVirusTable->setSelectionBehavior(QAbstractItemView::SelectRows);
	pVirusTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
	pVirusTable->verticalHeader()->setVisible(false);
	// 启用横向滚动条
	pVirusTable->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    // 列宽可由用户拖动调整，初始设置：增宽文件名列以便显示更多信息
	pVirusTable->setColumnWidth(0, 80);
	pVirusTable->setColumnWidth(1, 320);
	pVirusTable->setColumnWidth(2, 300);  // 病毒名称列加宽，容纳更长名称
	pVirusTable->setColumnWidth(3, 420);  // 文件路径列
	// 允许用户交互调整列宽，最后一列自动拉伸填充
	pVirusTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
	pVirusTable->horizontalHeader()->setMinimumSectionSize(60);
	pVirusTable->setFixedHeight(300);
	pVirusTable->setVisible(false);

	// 当文件名列宽调整时，自动重新计算并更新截断显示
	connect(pVirusTable->horizontalHeader(), &QHeaderView::sectionResized, this, [this](int logicalIndex, int /*oldSize*/, int /*newSize*/) {
		if (logicalIndex != 1) return; // 只有文件名列
		int colWidth = pVirusTable->columnWidth(1);
		QFont f = pVirusTable->font();
		int rows = pVirusTableModel->rowCount();
		for (int r = 0; r < rows; ++r) {
			QStandardItem* nameItem = pVirusTableModel->item(r, 1);
			QStandardItem* pathItem = pVirusTableModel->item(r, 3);
			if (!nameItem || !pathItem) continue;
			QString mainPath = pathItem->data(Qt::UserRole).toString();
			QString extracted = pathItem->data(Qt::UserRole + 1).toString();
			QString mainName = QFileInfo(mainPath).fileName();
			QString display;
			if (!extracted.isEmpty()) {
				QString exName = QFileInfo(extracted).fileName();
				QString mainShort = shortenFileName(mainName, colWidth / 2, f);
				QString exShort = shortenFileName(exName, colWidth / 2, f);
				display = mainShort + " >> " + exShort;
				nameItem->setToolTip(mainName + " >> " + exName);
			}
			else {
				display = shortenFileName(mainName, colWidth, f);
				nameItem->setToolTip(mainName);
			}
			nameItem->setText(display);
		}
	});

	// --- 引擎开关 ---
	CreateEngineOptionsWithRing(pYaraEngineSwitch, "Yara 引擎", spYaraEngineSwitch, ElaIconType::FileContract, pYaraEngineRing);
	CreateEngineOptionsWithRing(pPEEngineSwitch, "综合查杀 引擎", spPEEngineSwitch, ElaIconType::FileImport, pPEEngineRing);
	CreateEngineOptions(pSHA256EngineSwitch, "SHA256 特征码 引擎", spSHA256EngineSwitch, ElaIconType::Fingerprint);
	CreateEngineOptionsWithRing(pClamAVEngineSwitch, "ClamAV 引擎", spClamAVEngineSwitch, ElaIconType::C, pClamAVEngineRing);
	CreateEngineOptions(pScriptEngineSwitch, "脚本检测引擎", spScriptEngineSwitch, ElaIconType::Code);  // 新增脚本引擎开关，默认开启
	CreateEngineOptions(pHighSensitiveSwitch, "高敏感度模式（拦截所有无签名可执行程序）", spHighSensitiveSwitch, ElaIconType::ChartRadar);
	CreateEngineOptions(pExtraPEEngineSwitch, "Extra 引擎（仅在启用机器学习引擎时有效）", spExtraPEEngineSwitch, ElaIconType::E);

	pYaraEngineSwitch->setIsToggled(false);
	pYaraEngineSwitch->setEnabled(false);
	pPEEngineSwitch->setIsToggled(false);
	pPEEngineSwitch->setEnabled(false);
	pClamAVEngineSwitch->setIsToggled(false);
	pClamAVEngineSwitch->setEnabled(true); // ClamAV改为手动加载，开关初始可用
	pClamAVEngineRing->setVisible(false);  // 初始隐藏loading ring，点击后才显示
	pScriptEngineSwitch->setIsToggled(true);  // 脚本引擎默认开启
	pHighSensitiveSwitch->setIsToggled(false);
	pExtraPEEngineSwitch->setEnabled(false);
	pExtraPEEngineSwitch->setIsToggled(false);

	// --- ClamAV手动加载逻辑 ---
	// 断开CreateEngineOptionsWithRing中的通用连接，替换为手动加载逻辑
	pClamAVEngineSwitch->disconnect();
	connect(pClamAVEngineSwitch, &ElaToggleSwitch::toggled, this, [=](bool checked) {
		// 清除扫描缓存
		HasBeenScanedSha256BlackList.clear();
		HasBeenScanedTypeBlackList.clear();
		HasBeenScanedSha256WhiteList.clear();

		if (checked && !ClamAV_IsReady && !ClamAV_IsLoading.load()) {
			// 用户启用且尚未加载：立即禁用开关并进入加载状态，防止重复点击
			ClamAV_IsLoading = true;
			pClamAVEngineSwitch->setEnabled(false); // 禁用开关，防止重复点击
			pClamAVEngineSwitch->setVisible(false); // 隐藏开关
			pClamAVEngineRing->setVisible(true);    // 显示loading动画

			QtConcurrent::run([=]() {
				// 传入非NULL参数表示手动加载模式，不增加isLoadReady计数
				CreateThread(NULL, 0, LoadClamAVThread, (LPVOID)1, 0, 0);

				// 等待ClamAV加载完成或超时（最多30秒）
				int waitCount = 0;
				while (!ClamAV_IsReady && waitCount < 300) {
					QThread::msleep(100);
					waitCount++;
				}

				ClamAV_IsLoading = false;

				QMetaObject::invokeMethod(qApp, [=]() {
					if (ClamAV_IsReady) {
						// 加载成功：恢复开关为启用状态
						pClamAVEngineSwitch->setVisible(true);
						pClamAVEngineSwitch->setEnabled(true);
						pClamAVEngineSwitch->setIsToggled(true);
						pClamAVEngineRing->setVisible(false);
						Log_AddLogSimple("ClamAV查杀引擎已手动启用。", LOG_SUCCESS);
					}
					else {
						// 加载失败：恢复开关为可用但未启用状态
						pClamAVEngineSwitch->setVisible(true);
						pClamAVEngineSwitch->setEnabled(true);
						pClamAVEngineSwitch->setIsToggled(false);
						pClamAVEngineRing->setVisible(false);
						NewMessageBox("ClamAV查杀引擎加载失败。", 3);
					}
					}, Qt::QueuedConnection);
				});
		}
		else if (!checked) {
			// 用户关闭：允许直接关闭，不做额外处理
		}
		});

	// --- 解密按钮 ---
	pButtonDecrypt = new ElaPushButton;
	pButtonDecrypt->setText("恢复被隔离的文件");

	connect(pButtonDecrypt, &QPushButton::clicked, this, [this]() {
		QStringList fileNames = QFileDialog::getOpenFileNames(
			nullptr,
			"选择多个被隔离文件进行恢复",
			QDir::currentPath(),
			"被加密的文件 (*.iot);;"
			"所有文件 (*.*)"
		);

		if (!fileNames.isEmpty()) {
			for (const QString& QfileName : fileNames) {
				Encrypt_DecrptFile(wstring(CString(QfileName.toLocal8Bit())));
			}
			NewMessageBox("隔离文件恢复工作已启动。", 1, 2);
		}
		});

	// --- 引擎加载状态检测 ---
	QtConcurrent::run([=]() {
		short PreviousLoadValue = 0;
		while (true) {
			if (isLoadReady != PreviousLoadValue) {
				PreviousLoadValue = isLoadReady;
				QMetaObject::invokeMethod(qApp, [=]() {
					if (Yara_IsReady) {
						pYaraEngineSwitch->setEnabled(true);
						pYaraEngineSwitch->setIsToggled(true);
						pYaraEngineRing->setVisible(false);
					}
					if (PE_IsReady) {
						pPEEngineSwitch->setEnabled(true);
						pExtraPEEngineSwitch->setEnabled(true);
						pPEEngineSwitch->setIsToggled(true);
						pExtraPEEngineSwitch->setIsToggled(true);
						pPEEngineRing->setVisible(false);
					}
					}, Qt::QueuedConnection);
			}
			if (PreviousLoadValue == 2) break;
			QThread::msleep(100);
		}
		if (!Yara_IsReady) { NewMessageBox("Yara查杀引擎启动失败。", 3); pYaraEngineRing->setVisible(false); }
		if (!PE_IsReady) { NewMessageBox("PE查杀引擎启动失败。", 3); pPEEngineRing->setVisible(false); }
		});

	// --- 内存扫描抽屉 ---
	mDrawer1 = new ElaDrawerArea(this);
	mDrawer1->setHeaderHeight(60);

	QWidget* drawerHeader = new QWidget(this);
	QHBoxLayout* drawerHeaderLayout = new QHBoxLayout(drawerHeader);
	ElaText* drawerIcon = new ElaText(this);
	drawerIcon->setTextPixelSize(15);
	drawerIcon->setElaIcon(ElaIconType::Memory);
	drawerIcon->setFixedSize(25, 25);
	ElaText* drawerText = new ElaText("内存扫描", this);
	drawerText->setTextPixelSize(15);

	ElaProgressRing* progressRing = new ElaProgressRing(this);
	progressRing->setIsBusying(true);
	progressRing->setIsTransparent(true);
	progressRing->setFixedHeight(20);
	progressRing->setFixedWidth(20);
	progressRing->setBusyingWidth(3);

	drawerHeaderLayout->addWidget(drawerIcon);
	drawerHeaderLayout->addWidget(drawerText);
	drawerHeaderLayout->addStretch();
	drawerHeaderLayout->addWidget(progressRing);

	mDrawer1->setDrawerHeader(drawerHeader);
	mDrawer1->setVisible(false);

	// --- 扫描页面布局 ---
	scanPageLayout->addWidget(pScanProgressBar);
	scanPageLayout->addSpacing(0);
	scanPageLayout->addWidget(pProgressDesc);
	scanPageLayout->addSpacing(5);
	scanPageLayout->addWidget(mDrawer1);
	scanPageLayout->addSpacing(5);
	scanPageLayout->addLayout(EngineLayout);
	scanPageLayout->addSpacing(15);
	scanPageLayout->addWidget(spYaraEngineSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(spPEEngineSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(spSHA256EngineSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(spClamAVEngineSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(spScriptEngineSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(spExtraPEEngineSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(spHighSensitiveSwitch);
	scanPageLayout->addSpacing(2);
	scanPageLayout->addWidget(pVirusTable);
	scanPageLayout->addSpacing(10);
	scanPageLayout->addWidget(pButtonDecrypt);
	scanPageLayout->addStretch();

	// 将加载遮罩作为扫描页面的直接子控件，不放入布局管理，避免被其他控件刷新挤压
	m_scanLoadingOverlay->setParent(m_scanPageWidget);
	m_scanLoadingOverlay->raise();
	m_scanLoadingOverlay->hide();

	// ========== 第2页：结果页面 ==========
	m_resultPageWidget = new QWidget();
	m_resultPageWidget->setObjectName("resultPageWidget");
	QVBoxLayout* resultPageLayout = new QVBoxLayout(m_resultPageWidget);
	resultPageLayout->setContentsMargins(0, 0, 0, 0);
	resultPageLayout->setAlignment(Qt::AlignCenter);

	// 外层布局用于控制卡片左右边距
	QVBoxLayout* resultOuterLayout = new QVBoxLayout();
	resultOuterLayout->setContentsMargins(30, 0, 30, 0);   // 左右边距，卡片自动拉伸到最宽
	resultOuterLayout->setSpacing(0);

	// 结果卡片容器（不再设置固定宽度）
	QWidget* resultCard = new QWidget(m_resultPageWidget);
	resultCard->setObjectName("resultCard");
	resultCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred); // 水平扩展

	QVBoxLayout* resultCardLayout = new QVBoxLayout(resultCard);
	resultCardLayout->setContentsMargins(30, 25, 30, 25);
	resultCardLayout->setSpacing(15);

	// 图标
	resultIconLabel = new QLabel(resultCard);
	resultIconLabel->setObjectName("resultIconLabel");
	resultIconLabel->setFixedSize(80, 80);
	resultIconLabel->setAlignment(Qt::AlignCenter);
	resultCardLayout->addWidget(resultIconLabel, 0, Qt::AlignCenter);

	// 标题
	resultTitleLabel = new QLabel(resultCard);
	resultTitleLabel->setObjectName("resultTitleLabel");
	resultTitleLabel->setAlignment(Qt::AlignCenter);
	resultTitleLabel->setWordWrap(true);
	resultTitleLabel->setMinimumWidth(500);   // 避免文字压缩
	resultCardLayout->addWidget(resultTitleLabel, 0, Qt::AlignCenter);

	// 详情容器（用于动态替换内容）
	resultDetailContainer = new QWidget(resultCard);
	resultDetailContainer->setObjectName("resultDetailContainer");
	QVBoxLayout* detailContainerLayout = new QVBoxLayout(resultDetailContainer);
	detailContainerLayout->setContentsMargins(0, 0, 0, 0);
	resultCardLayout->addWidget(resultDetailContainer);

	// 按钮容器
	QWidget* resultButtonContainer = new QWidget(resultCard);
	QHBoxLayout* resultButtonLayout = new QHBoxLayout(resultButtonContainer);
	resultButtonLayout->setContentsMargins(0, 10, 0, 0);
	resultButtonLayout->setSpacing(15);
	resultButtonLayout->setAlignment(Qt::AlignCenter);

	// 返回按钮
	resultBackButton = new ElaPushButton("返回引擎设置", resultButtonContainer);
	resultBackButton->setObjectName("resultBackButton");
	resultBackButton->setFixedSize(160, 42);
	resultBackButton->setCursor(Qt::PointingHandCursor);
	resultButtonLayout->addWidget(resultBackButton);

	resultCardLayout->addWidget(resultButtonContainer, 0, Qt::AlignCenter);

	// 将卡片放入外层布局，并让卡片横向填满
	resultOuterLayout->addWidget(resultCard);
	resultOuterLayout->addStretch();

	resultPageLayout->addLayout(resultOuterLayout);
	resultPageLayout->addStretch();   // 上下居中
	// ========== 添加页面到 StackedWidget ==========
	m_stackedWidget->addWidget(m_scanPageWidget);   // index 0
	m_stackedWidget->addWidget(m_resultPageWidget);  // index 1
	m_stackedWidget->setCurrentIndex(0);  // 默认显示扫描页

	// ========== 初始主题设置 ==========
	updateResultViewStyle();

	// ========== 主题切换连接 ==========
	connect(eTheme, &ElaTheme::themeModeChanged, this, [this](ElaThemeType::ThemeMode themeMode) {
		updateResultViewStyle();
		updateScanLoadingOverlayStyle();
		if (m_stackedWidget->currentIndex() == 1) {
			resultDetailContainer->update();
		}
		});

	// ========== 返回按钮连接 ==========
	connect(resultBackButton, &QPushButton::clicked, this, [this]() {
		// 切回扫描页面
		m_stackedWidget->setCurrentIndex(0);

		// 恢复引擎设置界面
		documentationButton->setEnabled(true);
		spYaraEngineSwitch->setVisible(true);
		spPEEngineSwitch->setVisible(true);
		spSHA256EngineSwitch->setVisible(true);
		spClamAVEngineSwitch->setVisible(true);
		spScriptEngineSwitch->setVisible(true);
		spHighSensitiveSwitch->setVisible(true);
		spExtraPEEngineSwitch->setVisible(true);
		pVirusTable->setVisible(false);
		pButtonLeft->setVisible(false);
		pButtonRight->setVisible(false);
		pButtonDecrypt->setVisible(true);
		pButtonAddWhite->setVisible(false);

		EngineMainTitle->setVisible(true);
		EngineMainTitle->setText("引擎设置");

		pProgressDesc->setVisible(true);
		pProgressDesc->setText("准备就绪\n");

		pScanProgressBar->reset();
		pScanProgressBar->setVisible(false);

		if (mDrawer1)
			mDrawer1->setVisible(false);

		mScanState = ssPrepared;
		});

	// ========== 设置中心部件 ==========
	QWidget* theFirstWidget = new QWidget(this);
	theFirstWidget->setWindowTitle("病毒查杀");
	QVBoxLayout* mainLayout = new QVBoxLayout(theFirstWidget);
	mainLayout->setContentsMargins(0, 0, 0, 0);
	mainLayout->addWidget(m_stackedWidget);

	addCentralWidget(theFirstWidget, true, true, 0);
}

VirusScanPage::~VirusScanPage()
{
}

void VirusScanPage::showScanLoading(const QString& text)
{
	if (!m_scanLoadingOverlay || !m_scanLoadingRing) return;

	if (!text.isEmpty())
	{
		QLabel* label = m_scanLoadingOverlay->findChild<QLabel*>();
		if (label) label->setText(text);
	}

	if (m_scanLoadingOverlay->isHidden())
	{
		m_scanLoadingOverlay->setGeometry(QRect(QPoint(0, 0), m_scanPageWidget->size()));
		m_scanLoadingOverlay->show();
		m_scanLoadingOverlay->raise();
		m_scanLoadingRing->setIsBusying(true);
	}
}

void VirusScanPage::hideScanLoading()
{
	if (m_scanLoadingOverlay && m_scanLoadingRing)
	{
		m_scanLoadingRing->setIsBusying(false);
		m_scanLoadingOverlay->hide();
	}
}

void VirusScanPage::updateScanLoadingOverlayStyle()
{
	/* 根据当前 ElaTheme 主题动态设置遮罩背景与文字颜色，
	 * 避免 dark 主题下纯白遮罩过于突兀。 */
	if (!m_scanLoadingOverlay)
		return;

	ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
	bool isDark = (themeMode == ElaThemeType::Dark);

	/* 遮罩背景：light=半透明白，dark=半透明深灰 */
	QString overlayBg = isDark ? "rgba(30, 30, 32, 200)" : "rgba(255, 255, 255, 180)";
	/* 文字颜色：light=深灰，dark=浅灰 */
	QString textColor = isDark ? "#E5E7EB" : "#444444";

	m_scanLoadingOverlay->setStyleSheet(QString("background: %1;").arg(overlayBg));

	/* 更新文字标签样式 */
	QLabel* scanLoadingText = m_scanLoadingOverlay->findChild<QLabel*>("scanLoadingText");
	if (scanLoadingText)
	{
		scanLoadingText->setStyleSheet(QString(
			"font-size: 15px; color: %1; font-weight: bold; background: transparent; border: none;")
			.arg(textColor));
	}
}

void VirusScanPage::resizeEvent(QResizeEvent* event)
{
	if (m_scanLoadingOverlay && m_scanPageWidget)
	{
		m_scanLoadingOverlay->setGeometry(QRect(QPoint(0, 0), m_scanPageWidget->size()));
	}
	BasePage::resizeEvent(event);
}

// ===== 快速扫描多阶段指示器实现 =====

void VirusScanPage::showQuickScanPhaseBar(bool show)
{
	if (!m_quickScanPhaseBar)
	{
		// 首次创建阶段卡片容器
		m_quickScanPhaseBar = new QWidget(m_scanPageWidget);
		m_quickScanPhaseBar->setObjectName("quickScanPhaseBar");
		QVBoxLayout* barLayout = new QVBoxLayout(m_quickScanPhaseBar);
		barLayout->setContentsMargins(20, 10, 20, 10);
		barLayout->setSpacing(8);

		// 阶段标题列表
		QStringList phaseTitles = {
			"进程扫描",
			"启动项扫描",
			"计划任务扫描",
			"用户关键目录"
		};

		for (int i = 0; i < phaseTitles.size(); i++)
		{
			QuickScanPhaseCard card;
			card.card = new QWidget(m_quickScanPhaseBar);
			card.card->setObjectName(QString("phaseCard_%1").arg(i));
			card.card->setFixedHeight(56);

			QHBoxLayout* cardLayout = new QHBoxLayout(card.card);
			cardLayout->setContentsMargins(16, 8, 16, 8);
			cardLayout->setSpacing(12);

			// 状态指示圆点（用 QLabel 模拟）
			QLabel* dotLabel = new QLabel();
			dotLabel->setFixedSize(10, 10);
			dotLabel->setObjectName(QString("phaseDot_%1").arg(i));

			// 标题
			card.titleLabel = new QLabel(phaseTitles[i]);
			card.titleLabel->setObjectName(QString("phaseTitle_%1").arg(i));
			card.titleLabel->setStyleSheet("font-size: 14px; font-weight: bold; border: none;");

			// loading ring
			card.ring = new ElaProgressRing(card.card);
			card.ring->setIsBusying(false);
			card.ring->setIsTransparent(true);
			card.ring->setFixedHeight(20);
			card.ring->setFixedWidth(20);
			card.ring->setBusyingWidth(2);
			card.ring->setVisible(false);

			// 状态文字
			card.statusLabel = new QLabel("等待中");
			card.statusLabel->setObjectName(QString("phaseStatus_%1").arg(i));
			card.statusLabel->setStyleSheet("font-size: 12px; border: none;");

			cardLayout->addWidget(dotLabel);
			cardLayout->addWidget(card.titleLabel);
			cardLayout->addStretch();
			cardLayout->addWidget(card.ring);
			cardLayout->addWidget(card.statusLabel);

			barLayout->addWidget(card.card);
			m_quickScanPhaseCards.append(card);
		}

		// 将 phaseBar 插入到 scanPageLayout 中 pProgressDesc 之后
		// 找到 scanPageLayout
		QVBoxLayout* scanPageLayout = qobject_cast<QVBoxLayout*>(m_scanPageWidget->layout());
		if (scanPageLayout)
		{
			int idx = scanPageLayout->indexOf(pProgressDesc);
			if (idx >= 0) scanPageLayout->insertWidget(idx + 2, m_quickScanPhaseBar);
			else scanPageLayout->insertWidget(0, m_quickScanPhaseBar);
		}
	}

	// 主题样式
	auto updatePhaseBarStyle = [this]() {
		ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
		bool isDark = (themeMode == ElaThemeType::Dark);
		QString cardBg = isDark ? "rgba(45, 45, 48, 200)" : "rgba(248, 249, 250, 200)";
		QString cardBorder = isDark ? "rgba(55, 55, 58, 200)" : "rgba(229, 231, 235, 200)";
		QString titleColor = isDark ? "#E5E7EB" : "#1F2937";
		QString statusColor = isDark ? "#9CA3AF" : "#6B7280";
		QString dotPending = isDark ? "#4B5563" : "#D1D5DB";
		QString dotScanning = "#3B82F6";
		QString dotDone = "#10B981";
		QString dotThreat = "#EF4444";

		for (int i = 0; i < m_quickScanPhaseCards.size(); i++)
		{
			auto& card = m_quickScanPhaseCards[i];
			card.card->setStyleSheet(QString(
				"QWidget#phaseCard_%1 { background: %2; border: 1px solid %3; border-radius: 10px; }")
				.arg(i).arg(cardBg).arg(cardBorder));
			card.titleLabel->setStyleSheet(QString(
				"font-size: 14px; font-weight: bold; color: %1; border: none;").arg(titleColor));
			card.statusLabel->setStyleSheet(QString(
				"font-size: 12px; color: %1; border: none;").arg(statusColor));

			// 更新圆点颜色
			QLabel* dot = card.card->findChild<QLabel*>(QString("phaseDot_%1").arg(i));
			if (dot)
			{
				QString dotColor = dotPending;
				QString statusText = card.statusLabel->text();
				if (statusText.contains("扫描中")) dotColor = dotScanning;
				else if (statusText.contains("完成") && statusText.contains("威胁")) dotColor = dotThreat;
				else if (statusText.contains("完成")) dotColor = dotDone;
				dot->setStyleSheet(QString(
					"background: %1; border-radius: 5px; border: none; min-width: 10px; min-height: 10px;")
					.arg(dotColor));
			}
		}
	};
	updatePhaseBarStyle();
	// 连接主题切换
	static bool themeConnected = false;
	if (!themeConnected)
	{
		connect(eTheme, &ElaTheme::themeModeChanged, this, [updatePhaseBarStyle]() { updatePhaseBarStyle(); });
		themeConnected = true;
	}

	m_quickScanPhaseBar->setVisible(show);
}

void VirusScanPage::updateQuickScanPhaseCard(int index, const QString& status, bool scanning)
{
	if (index < 0 || index >= m_quickScanPhaseCards.size()) return;
	auto& card = m_quickScanPhaseCards[index];
	card.statusLabel->setText(status);
	card.ring->setVisible(scanning);
	card.ring->setIsBusying(scanning);

	// 更新圆点颜色
	QLabel* dot = card.card->findChild<QLabel*>(QString("phaseDot_%1").arg(index));
	if (dot)
	{
		ElaThemeType::ThemeMode themeMode = eTheme->getThemeMode();
		bool isDark = (themeMode == ElaThemeType::Dark);
		QString dotColor;
		if (scanning) dotColor = "#3B82F6";
		else if (status.contains("完成") && status.contains("威胁")) dotColor = "#EF4444";
		else if (status.contains("完成")) dotColor = "#10B981";
		else dotColor = isDark ? "#4B5563" : "#D1D5DB";
		dot->setStyleSheet(QString(
			"background: %1; border-radius: 5px; border: none; min-width: 10px; min-height: 10px;")
			.arg(dotColor));
	}
}

void VirusScanPage::setQuickScanPhaseDone(int index, int threatCount)
{
	QString status = (threatCount > 0)
		? QString("完成 (发现 %1 个威胁)").arg(threatCount)
		: QString("完成");
	updateQuickScanPhaseCard(index, status, false);
}

void VirusScanPage::startQuickScanPhase(int phase)
{
	if (!m_bQuickScanMode) return; // 终止后不再启动新阶段
	m_quickScanCurrentPhase = phase;

	// 阶段 0: 进程扫描由快速扫描触发器直接处理
	if (phase == 0)
	{
		updateQuickScanPhaseCard(0, "扫描中...", true);
		return;
	}

	// 阶段 1-3: 使用预收集的文件列表直接扫描（不再弹遮罩、不再异步收集）
	QStringList filesToScan;
	QString phaseDescText;

	if (phase == 1)      { filesToScan = m_quickScanStartupFiles;       phaseDescText = "启动项扫描中"; }
	else if (phase == 2) { filesToScan = m_quickScanScheduledTaskFiles; phaseDescText = "计划任务扫描中"; }
	else if (phase == 3) { filesToScan = m_quickScanUserDirFiles;       phaseDescText = "用户关键目录扫描中"; }
	else return;

	updateQuickScanPhaseCard(phase, "扫描中...", true);
	pProgressDesc->setText(phaseDescText + "\n");

	if (g_scanCancelRequested.load() || mScanState.load() == ssScanResult || mScanState.load() == ssEnding)
	{
		setQuickScanPhaseDone(phase, 0);
		if (phase < 3) startQuickScanPhase(phase + 1);
		else finishQuickScan();
		return;
	}

	if (filesToScan.isEmpty())
	{
		setQuickScanPhaseDone(phase, 0);
		if (phase < 3) startQuickScanPhase(phase + 1);
		else finishQuickScan();
		return;
	}

	WorkerTParam* pParam = new WorkerTParam;
	pParam->fileNames = filesToScan;
	m_pCurrentScanParam = pParam;
	m_nCurrentScanType = 1;
	pParam->onlyPEEnabled = pPEEngineSwitch->getIsToggled();
	pParam->sha256Enabled = pSHA256EngineSwitch->getIsToggled();
	pParam->yaraEnabled = pYaraEngineSwitch->getIsToggled();
	pParam->clamavEnabled = pClamAVEngineSwitch->getIsToggled();
	pParam->scriptEnabled = pScriptEngineSwitch->getIsToggled();

	int totalForPhase = filesToScan.size();
	mTotalScannedFiles += totalForPhase;

	CreateThread(0, 0, WorkerT, pParam, 0, 0);

	QTimer* phaseTimer = new QTimer(this);
	m_pScanCheckTimer = phaseTimer;
	int phaseStartThreats = pVirusTableModel->rowCount();

	connect(phaseTimer, &QTimer::timeout, this, [=]() {
		if (g_scanCancelRequested.load() || mScanState.load() == ssScanResult || mScanState.load() == ssEnding)
		{
			phaseTimer->stop();
			phaseTimer->deleteLater();
			m_pScanCheckTimer = nullptr;
			int newThreats = pVirusTableModel->rowCount() - phaseStartThreats;
			setQuickScanPhaseDone(phase, newThreats);
			if (pParam && !pParam->VirusPath.isEmpty())
			{
				QMutexLocker locker(&pParam->mutex);
				appendVirusRecords(pParam->VirusName, pParam->VirusPath, pParam->ExtractedFilePaths);
				pParam->VirusName.clear();
				pParam->VirusPath.clear();
				pParam->ExtractedFilePaths.clear();
			}
			m_quickScanTotalThreats += newThreats;
			m_quickScanCumulativeScanned += totalForPhase;
			m_pCurrentScanParam = nullptr;
			m_nCurrentScanType = 0;
			QtConcurrent::run([pParam]() { while (RunningWorkerT.load() > 0) QThread::msleep(50); delete pParam; });
			if (phase < 3) startQuickScanPhase(phase + 1);
			else finishQuickScan();
			return;
		}

		QStringList virusNames, virusPaths, extractedPaths;
		pParam->mutex.lock();
		virusNames = pParam->VirusName;
		virusPaths = pParam->VirusPath;
		extractedPaths = pParam->ExtractedFilePaths;
		pParam->VirusName.clear();
		pParam->VirusPath.clear();
		pParam->ExtractedFilePaths.clear();
		QString currentFile = pParam->currentScanningFile;
		int scanned = pParam->HasScanedCount;
		pParam->mutex.unlock();

		if (!virusPaths.isEmpty())
			appendVirusRecords(virusNames, virusPaths, extractedPaths);

		if (!currentFile.isEmpty())
			pProgressDesc->setText(QString("%1 (%2/%3): %4\n").arg(phaseDescText).arg(scanned).arg(totalForPhase).arg(currentFile));

		// 更新整体进度条（累计偏移 + 当前阶段扫描数）
		if (progressAnimation->state() == QPropertyAnimation::Running)
			progressAnimation->stop();
		progressAnimation->setStartValue(pScanProgressBar->value());
		int progressValue = (m_quickScanCumulativeScanned + scanned) * 10;
		int maxProgress = m_quickScanTotalFiles * 10;
		if (progressValue > maxProgress) progressValue = maxProgress;
		progressAnimation->setEndValue(progressValue);
		progressAnimation->start();

		if (scanned >= totalForPhase)
		{
			phaseTimer->stop();
			phaseTimer->deleteLater();
			m_pScanCheckTimer = nullptr;

			pParam->mutex.lock();
			if (!pParam->VirusPath.isEmpty())
				appendVirusRecords(pParam->VirusName, pParam->VirusPath, pParam->ExtractedFilePaths);
			pParam->mutex.unlock();

			int newThreats = pVirusTableModel->rowCount() - phaseStartThreats;
			m_quickScanTotalThreats += newThreats;
			setQuickScanPhaseDone(phase, newThreats);

			// 更新累计扫描数
			m_quickScanCumulativeScanned += totalForPhase;

			m_pCurrentScanParam = nullptr;
			m_nCurrentScanType = 0;
			QtConcurrent::run([pParam]() { while (RunningWorkerT.load() > 0) QThread::msleep(50); delete pParam; });

			if (phase < 3) startQuickScanPhase(phase + 1);
			else finishQuickScan();
		}
	});
	phaseTimer->start(100);
}

void VirusScanPage::finishQuickScan()
{
	if (!m_bQuickScanMode) return; // 终止后不再处理
	hideScanLoading();
	m_bQuickScanMode = false;

	// 隐藏阶段指示器
	if (m_quickScanPhaseBar) m_quickScanPhaseBar->hide();

	int totalThreats = pVirusTableModel->rowCount();
	mTotalVirusFound = totalThreats;
	mVirusHandled = 0;

	if (totalThreats == 0)
	{
		mScanResultClean = true;
		mScanState.store(ssScanResult);
		pProgressDesc->setText("准备就绪\n");
		NewMessageBox("快速扫描完成：没有发现病毒。", 1, 3);
		Log_AddLogSimple(QString::fromUtf8("快速扫描完成：没有发现病毒。共扫描 %1 个文件。").arg(mTotalScannedFiles), LOG_SUCCESS);
		showScanResultView(mScanResultClean, mTotalScannedFiles, mVirusHandled);
	}
	else
	{
		mScanResultClean = false;
		mScanState.store(ssEnding);
		pButtonRight->setText("隔离选中");
		pButtonLeft->setText("全部选中");
		pProgressDesc->setText("等待选择隔离项目...");
		pVirusTable->setVisible(true);
		EngineMainTitle->setText("快速扫描威胁列表");
		EngineMainTitle->setVisible(true);
		if (pButtonAddWhite) pButtonAddWhite->setVisible(true);

		NewMessageBox(QString("快速扫描完成：发现 %1 个病毒。").arg(totalThreats), 2, 3);
	}
}

