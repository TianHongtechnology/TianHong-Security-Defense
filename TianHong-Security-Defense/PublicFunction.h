#pragma once
#include "PublicIncluding.h"
#include "PublicDefine.h"
#include "../TianHongDefenseKernelProtectionClient/shared/SocketProtocol.h"

// type: 1:right，2:warn，3:error，4:info, 5:勒索
/**
 * @brief 显示自定义样式的信息弹窗
 * @param text 要显示的文本内容（QString）
 * @param type 弹窗类型，1=成功，2=警告，3=错误，4=信息，5=勒索提示
 * @param sDuring 显示时长（秒），默认为3秒
 */
void NewMessageBox(const QString& text, int type, int sDuring = 3, const QString& title = QString());

/**
 * @brief 弹出主动防护告警对话框（普通桌面）
 * @param title 对话框标题文本
 * @param pid 关联的进程ID
 * @param context 告警上下文描述文本
 * @return RelActWarnType 用户选择或处理结果
 */
RelActWarnType ShowAlertDialog(
    const QString& title,
    const int& pid,
    const QString& context);

/**
 * @brief 弹出主动防护告警对话框（带UAC桌面切换）
 * @param title 对话框标题文本
 * @param pid 关联的进程ID
 * @param context 告警上下文描述文本
 * @return RelActWarnType 用户选择或处理结果
 */
RelActWarnType ShowAlertDialogWithUAC(const QString& title, const int& pid, const QString& context);

/**
 * @brief 显示威胁检测对话框，提示用户该文件存在的威胁类型
 * @param filePath 被检测的文件路径（QString）
 * @param threatType 威胁类型描述文本
 * @return BOOL 返回TRUE表示已处理/确认，FALSE表示取消或失败
 */
BOOL ShowThreatDialog(const QString& filePath, const QString& threatType);

// ---- 临时白名单管理 ----
//  WhiteSha256ListCache: sha256(小写) -> 文件路径

/**
 * @brief 将文件添加到临时白名单（计算SHA256并缓存路径，持久化到磁盘）
 * @param filePath 文件路径（std::string，ANSI）
 * @return bool 成功返回true，失败返回false
 */
bool Whitelist_AddTemporary(const std::string& filePath);

/**
 * @brief 将文件添加到临时白名单（QString 重载，方便UI层调用）
 * @param filePath 文件路径（QString）
 * @return bool 成功返回true，失败返回false
 */
bool Whitelist_AddTemporary(const QString& filePath);

/**
 * @brief 从临时白名单移除指定SHA256，并持久化到磁盘
 * @param sha256 要移除的SHA256（小写十六进制字符串）
 * @return bool 成功移除返回true，不存在返回false
 */
bool Whitelist_RemoveTemporary(const std::string& sha256);

/**
 * @brief 持久化临时白名单到 whitecache.sha256 文件
 */
void Whitelist_SaveTemporary();

/**
 * @brief 从 whitecache.sha256 文件加载临时白名单
 */
void Whitelist_LoadTemporary();

// ==================== 临时目录白名单 ====================

/**
 * @brief 将目录添加到临时目录白名单（该目录下所有文件免扫描）
 * @param dirPath 目录路径（std::string，ANSI）
 * @return bool 成功返回true，失败返回false
 */
bool Whitelist_AddTemporaryDir(const std::string& dirPath);

/**
 * @brief 将目录添加到临时目录白名单（QString 重载）
 */
bool Whitelist_AddTemporaryDir(const QString& dirPath);

/**
 * @brief 从临时目录白名单移除指定目录
 * @param dirPath 要移除的目录路径（小写、末尾带'\'）
 * @return bool 成功移除返回true，不存在返回false
 */
bool Whitelist_RemoveTemporaryDir(const std::string& dirPath);

/**
 * @brief 检查文件路径是否在临时目录白名单中（线程安全）
 * @param filePath 文件路径（ANSI）
 * @return bool 命中返回true
 */
bool Whitelist_IsPathInTempDir(const std::string& filePath);

/**
 * @brief 持久化临时目录白名单到 whitedir.cache 文件
 */
void Whitelist_SaveTemporaryDir();

/**
 * @brief 从 whitedir.cache 文件加载临时目录白名单
 */
void Whitelist_LoadTemporaryDir();

// ==================== 增强路径白名单 ====================

/**
 * @brief 持久化增强路径白名单到 whitepath.cache 文件
 */
void Whitelist_SaveEnhancedPath();

/**
 * @brief 从 whitepath.cache 文件加载增强路径白名单
 */
void Whitelist_LoadEnhancedPath();

/**
 * @brief 检查文件路径是否在增强路径白名单中（线程安全）
 * @param filePath 文件路径（ANSI）
 * @return bool 命中返回true
 */
bool Whitelist_IsPathEnhanced(const std::string& filePath);

/**
 * @brief 从增强路径白名单移除指定路径，并持久化
 * @param filePath 要移除的文件路径（ANSI）
 * @return bool 成功移除返回true，不存在返回false
 */
bool Whitelist_RemoveEnhancedPath(const std::string& filePath);

/**
 * @brief 移除临时白名单中所有属于指定路径的SHA256条目，并持久化
 * @param filePath 文件路径（ANSI）
 * @return int 移除的条目数量
 */
int Whitelist_RemoveAllSha256ByPath(const std::string& filePath);


/**
 * @brief 接收网络传输包并解析到PacketOut
 * @param s 套接字句柄
 * @param PacketOut 输出的Packet结构
 * @return int 返回接收结果或错误码
 */
extern int Tran_RecvPacket(SOCKET s, Packet& PacketOut);

/**
 * @brief 以原始/完整格式发送告警包到目标（内部使用）
 * @param s 目标套接字句柄
 * @param text 要发送的文本内容（缓冲区，最多4096字节）
 * @param PacketTypeIn 包类型
 * @param WarnTitle 警告标题（缓冲区，最多128字节）
 * @param Pid 关联进程ID
 * @param InfoTitle 信息标题（缓冲区，最多32字节）
 * @param DlgIconType 对话框图标类型
 * @param NeedTerminate 是否要求对端终止进程
 * @return int 发送结果或错误码
 */
extern int Tran_OrgSendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char WarnTitle[128], int Pid, char InfoTitle[32], WarnDlgType DlgIconType, bool NeedTerminate);

/**
 * @brief 发送通用传输包到目标
 * @param s 目标套接字句柄
 * @param text 要发送的文本内容（缓冲区，最多4096字节）
 * @param PacketTypeIn 包类型
 * @param Title 显示标题（缓冲区，最多128字节）
 * @param Pid 关联进程ID，默认-1表示无
 * @return int 发送结果或错误码
 */
extern int Tran_SendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char Title[128], int Pid = -1);

/**
 * @brief 检查套接字是否已关闭
 * @param clientSocket 套接字句柄
 * @return bool 返回true表示已关闭，否则false
 */
extern bool Tran_IsSocketClosed(SOCKET clientSocket);

/**
 * @brief 验证给定路径是否为系统文件（基于签名/路径等规则）
 * @param filePath 要验证的宽字符文件路径
 * @return bool 返回true表示为系统文件，false表示非系统文件或验证失败
 */
bool File_VerifySystemFile(wstring filePath);

/**
 * @brief 检查文件的数字签名是否匹配指定证书名称（若提供）
 * @param filePath 要检查的宽字符串文件路径
 * @param certName 可选的证书名称过滤（默认为空，表示只检查签名有效性）
 * @return bool 返回true表示签名有效且匹配，否则false
 */
bool File_CheckFileSignature(const wstring& filePath, const wstring& certName = L"");

/**
 * @brief 扫描文件夹下所有文件并返回签名异常或无签名文件列表
 * @param folderPath 要扫描的文件夹路径（宽字符串）
 * @return vector<wstring> 返回发现的文件路径列表
 */
vector<wstring> File_CheckFolderSignature(const wstring& folderPath);

/**
 * @brief 计算指定文件的熵值（用于判断文件是否被加密或打包）
 * @param filePath 文件路径（string）
 * @return double 返回计算得到的熵值
 */
double File_CalculateEntropy(const string& filePath);

/**
 * @brief 从完整文件路径中提取短文件名（文件名+扩展名）
 * @param longFileName 完整路径或长文件名
 * @return string 返回提取的短文件名
 */
string File_GetShortFileName(string longFileName);

/**
 * @brief 判断文件是否在超过一天之前被修改
 * @param filePath 宽字符文件路径
 * @return bool 若修改时间超过一天返回true，否则false
 */
bool File_IsModifiedOverOneDay(wchar_t* filePath);

/**
 * @brief 判断指定文件是否为PE可执行文件格式
 * @param filePath 宽字符文件路径
 * @return bool 为PE文件返回true，否则false
 */
bool File_IsPEFile(wchar_t* filePath);

/**
 * @brief 检查PE文件是否包含图标资源
 * @param filePath 宽字符文件路径
 * @return bool 存在图标资源返回true，否则false
 */
bool File_HasIconResource(wchar_t* filePath);

/**
 * @brief 判断文件大小是否在正常范围内（防止极大或极小异常文件）
 * @param filePath 宽字符文件路径
 * @return bool 大小正常返回true，否则false
 */
bool File_IsFileSizeNormal(wchar_t* filePath);

/**
 * @brief 将指定文件设置为隐藏属性
 * @param FilePath 要设置为隐藏的文件路径（string）
 */
void File_SetFileHidden(string FilePath);

/**
 * @brief 递归删除目录及其所有内容
 * @param path 要删除的目录路径
 * @return bool 删除成功返回true，失败返回false
 */
bool File_DeleteDirectory(string path);

/**
 * @brief 获取目录下文件数量（不包含子目录）
 * @param dir 宽字符串目录路径
 * @return int 返回文件数量
 */
int File_GetFileCount(wstring dir);

class FileRollback {
public:
	struct BackupInfo {
		std::string originalPath;
		std::string backupPath;
		std::time_t backupTime;
	};

	FileRollback() {
		// 获取当前程序目录
		char currentDir[MAX_PATH];
		GetModuleFileNameA(NULL, currentDir, MAX_PATH);
		PathRemoveFileSpecA(currentDir);

		// 设置备份目录路径
		backupDir = std::string(currentDir) + "\\TianHongRestore";
		infoFile = backupDir + "\\RestoreInfomation.lnfo";

		// 创建备份目录
		CreateDirectoryA(backupDir.c_str(), NULL);
	}

	// 备份文件
	bool backup(const std::string& filePath) {
		// 检查源文件是否存在
		if (GetFileAttributesA(filePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
			// std::cerr << "Error: Source file does not exist.\n";
			return false;
		}

		// 获取原始文件名
		char filename[MAX_PATH];
		strcpy_s(filename, filePath.c_str());
		PathStripPathA(filename);

		// 生成备份文件名
		std::string backupFilename = generateBackupFilename(filename);
		std::string backupPath = backupDir + "\\" + backupFilename;

		// 复制文件到备份目录
		if (!CopyFileA(filePath.c_str(), backupPath.c_str(), FALSE)) {
			// std::cerr << "Backup failed. Error: " << GetLastError() << "\n";
			return false;
		}

		// 创建备份信息
		BackupInfo info;
		info.originalPath = filePath;
		info.backupPath = backupPath;
		info.backupTime = time(nullptr);

		// 添加到备份列表
		backupList.push_back(info);

		// 更新信息文件
		updateInfoFile();

		/*std::cout << "Backup successful: " << filename
			<< " -> " << backupFilename << "\n";*/
		return true;
	}

	// 加载备份信息
	bool loadRestoreInfo() {
		backupList.clear();

		// 检查信息文件是否存在
		if (GetFileAttributesA(infoFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
			// std::cout << "No backup information found.\n";
			return true;
		}

		HANDLE hFile = CreateFileA(infoFile.c_str(), GENERIC_READ, FILE_SHARE_READ,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE) {
			// std::cerr << "Error opening info file. Error: " << GetLastError() << "\n";
			return false;
		}

		DWORD fileSize = GetFileSize(hFile, NULL);
		if (fileSize == INVALID_FILE_SIZE) {
			CloseHandle(hFile);
			return false;
		}

		char* buffer = new char[fileSize + 1];
		DWORD bytesRead;
		if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
			delete[] buffer;
			CloseHandle(hFile);
			return false;
		}
		buffer[bytesRead] = '\0';

		CloseHandle(hFile);

		// 解析文件内容
		std::istringstream ss(buffer);
		delete[] buffer;

		std::string line;
		while (std::getline(ss, line)) {
			if (line.empty()) continue;

			BackupInfo info;
			size_t pos1 = line.find('\t');
			if (pos1 == std::string::npos) continue;

			size_t pos2 = line.find('\t', pos1 + 1);
			if (pos2 == std::string::npos) continue;

			info.originalPath = line.substr(0, pos1);
			info.backupPath = line.substr(pos1 + 1, pos2 - pos1 - 1);
			std::string timeStr = line.substr(pos2 + 1);

			try {
				info.backupTime = std::stoll(timeStr);
				backupList.push_back(info);
			}
			catch (...) {
				// std::cerr << "Invalid timestamp format: " << timeStr << "\n";
			}
		}

		// std::cout << "Loaded " << backupList.size() << " backup records.\n";
		return true;
	}

	// 文件回滚
	bool rollback(size_t index) {
		if (index >= backupList.size()) {
			// std::cerr << "Invalid backup index.\n";
			return false;
		}

		const BackupInfo& info = backupList[index];

		// 检查备份文件是否存在
		if (GetFileAttributesA(info.backupPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
			// std::cerr << "Backup file not found.\n";
			return false;
		}

		// 备份原始文件（如果存在）
		if (GetFileAttributesA(info.originalPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
			std::string backup = info.originalPath + ".old";
			if (!MoveFileA(info.originalPath.c_str(), backup.c_str())) {
				// std::cerr << "Failed to backup existing file. Error: " << GetLastError() << "\n";
				return false;
			}
		}

		// 恢复文件
		if (!CopyFileA(info.backupPath.c_str(), info.originalPath.c_str(), FALSE)) {
			// std::cerr << "Rollback failed. Error: " << GetLastError() << "\n";
			return false;
		}

		/*std::cout << "Rollback successful: "
			<< PathFindFileNameA(info.backupPath.c_str())
			<< " -> " << PathFindFileNameA(info.originalPath.c_str()) << "\n";*/
		return true;
	}

	// 删除备份
	bool deleteBackup(size_t index) {
		if (index >= backupList.size()) {
			// std::cerr << "Invalid backup index.\n";
			return false;
		}

		BackupInfo info = backupList[index];

		// 删除备份文件
		if (!DeleteFileA(info.backupPath.c_str())) {
			// std::cerr << "Failed to delete backup file. Error: " << GetLastError() << "\n";
			return false;
		}

		// 从列表中移除
		backupList.erase(backupList.begin() + index);

		// 更新信息文件
		updateInfoFile();

		// std::cout << "Backup deleted: " << PathFindFileNameA(info.backupPath.c_str()) << "\n";
		return true;
	}

	// 获取备份列表
	const std::vector<BackupInfo>& getBackupList() const {
		return backupList;
	}

private:
	std::string backupDir;
	std::string infoFile;
	std::vector<BackupInfo> backupList;

	// 生成备份文件名
	std::string generateBackupFilename(const std::string& originalName) {
		int maxIndex = 0;
		std::string pattern = originalName + ".ret";
		std::string pattern2 = originalName + ".*.ret";

		// 查找匹配的文件
		WIN32_FIND_DATAA findData;
		HANDLE hFind = FindFirstFileA((backupDir + "\\" + pattern).c_str(), &findData);
		if (hFind != INVALID_HANDLE_VALUE) {
			maxIndex = std::max(maxIndex, 1);
			FindClose(hFind);
		}

		hFind = FindFirstFileA((backupDir + "\\" + pattern2).c_str(), &findData);
		if (hFind != INVALID_HANDLE_VALUE) {
			do {
				if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
					std::string filename = findData.cFileName;
					// 提取索引号
					size_t start = originalName.length() + 1;
					size_t end = filename.rfind(".ret");
					if (end != std::string::npos && end > start) {
						std::string numStr = filename.substr(start, end - start);
						try {
							int num = std::stoi(numStr);
							maxIndex = std::max(maxIndex, num);
						}
						catch (...) {
							// 忽略转换错误
						}
					}
				}
			} while (FindNextFileA(hFind, &findData));
			FindClose(hFind);
		}

		// 根据索引生成新文件名
		if (maxIndex == 0) {
			return originalName + ".ret";
		}
		else {
			return originalName + "." + std::to_string(maxIndex + 1) + ".ret";
		}
	}

	// 更新信息文件
	void updateInfoFile() {
		HANDLE hFile = CreateFileA(infoFile.c_str(), GENERIC_WRITE, 0,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			// std::cerr << "Error creating info file. Error: " << GetLastError() << "\n";
			return;
		}

		for (const auto& info : backupList) {
			std::string line = info.originalPath + "\t" +
				info.backupPath + "\t" +
				std::to_string(info.backupTime) + "\n";

			DWORD bytesWritten;
			WriteFile(hFile, line.c_str(), static_cast<DWORD>(line.length()),
				&bytesWritten, NULL);
		}

		CloseHandle(hFile);
	}
};

void Windows_TurnToUac();
void Windows_BackFromUac();

/**
 * @brief 切换到UAC桌面以便在受保护桌面上显示提示（用于提升或UAC交互）
 */
void Windows_TurnToUac();

/**
 * @brief 从UAC桌面还原回原始桌面
 */
void Windows_BackFromUac();

/**
 * @brief 获取当前进程的可执行文件路径（宽字符串）
 * @return wstring 返回当前进程的完整路径
 */
inline wstring Process_GetCurrentProcessPath();

/**
 * @brief 获取当前进程路径（包含注入的DLL信息）
 * @return wstring 进程路径，可能带有模块信息
 */
wstring Process_GetCurrentProcessPathWithDll();

/**
 * @brief 挂起指定进程句柄（暂停执行）
 * @param processHandle 要挂起的进程句柄
 * @param CloseHandleit 是否在完成后关闭句柄（默认false）
 */
void Process_SuspendProcess(HANDLE processHandle, bool CloseHandleit = false);

/**
 * @brief 恢复指定进程句柄（继续执行）
 * @param processHandle 要恢复的进程句柄
 * @param CloseHandleit 是否在完成后关闭句柄（默认true）
 */
void Process_ResumeProcess(HANDLE processHandle, bool CloseHandleit = true);

/**
 * @brief 判断目标进程是否为64位
 * @param hProcess 要检测的进程句柄
 * @return bool 是64位返回true，否则false
 */
bool Process_IsProcess64Bit(HANDLE hProcess);

/**
 * @brief 向目标进程注入DLL（32/64位实现取决于编译器与目标）
 * @param dwProcessId 目标进程ID
 * @return int 返回注入结果码（0表示成功或根据实现定义）
 */
int Process_InjectDll(DWORD dwProcessId);

/**
 * @brief 使用ZwTerminate终止指定进程
 * @param ProcessHandle 要终止的进程句柄
 * @param ExitCode 传递给目标进程的退出代码
 * @return BOOL 成功返回TRUE，失败返回FALSE
 */
BOOL Process_ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitCode);

/**
 * @brief 获取指定PID的父进程ID
 * @param pid 子进程的PID
 * @return int 返回父进程ID，失败返回-1
 */
int Process_GetProcessParent(int pid);

/**
 * @brief 获取进程的命令行字符串
 * @param hProcess 要查询的进程句柄
 * @return string 返回命令行文本
 */
string Process_GetProcessCommandLine(HANDLE hProcess);

/**
 * @brief 为进程/操作获取调试权限（SeDebugPrivilege）
 * @param lPcstr 需要设置的权限名称（宽字符串）
 * @param backCode 输出的返回代码或错误码
 * @return BOOL 成功返回TRUE，否则FALSE
 */
BOOL Process_GetDebugPrivilege(LPCWSTR lPcstr, DWORD* backCode);

/**
 * @brief 获取指定进程的可执行文件路径（ANSI字符串）
 * @param hProcess 要查询的进程句柄
 * @return string 返回进程路径文本
 */
string Process_GetProcessPath(HANDLE hProcess);

/**
 * @brief 等待目标进程的PEB初始化完成
 * @param hProcess 要等待的进程句柄
 * @param timeoutMs 超时时间（毫秒），默认2000
 * @return bool 初始化完成返回true，否则超时返回false
 */
bool Process_WaitForProcessPebInitialized(HANDLE hProcess, DWORD timeoutMs = 2000);
// 动态捕捉
class ProcessRansomwareDetector
{
private:
	vector<string> ProFilePath;
	int pid;
	int suspiciousScore;

	// NtAPI函数指针
	typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
		ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(NTAPI* _NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);

	_NtQuerySystemInformation pNtQuerySystemInformation;
	_NtQueryObject pNtQueryObject;

	// 初始化NtAPI
	void InitNtAPI()
	{
		HMODULE ntdll = GetModuleHandleA("ntdll.dll");
		pNtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
		pNtQueryObject = (_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
	}

	// 路径处理辅助函数
	string ToLower(const string& str)
	{
		string ret = str;
		transform(ret.begin(), ret.end(), ret.begin(), ::tolower);
		return ret;
	}

	bool EndWithWhat(string str, string suffix)
	{
		if (suffix.size() > str.size())
		{
			return false;
		}

		return equal(suffix.rbegin(), suffix.rend(), str.rbegin(),
			[](char a, char b)
			{
				return tolower(a) == tolower(b);
			});
	}

	string ReplaceSlash(string path)
	{
		replace(path.begin(), path.end(), '/', '\\');
		return path;
	}

	string EnsureEndSlash(string path)
	{
		if (!path.empty() && path.back() != '\\') path += '\\';
		return path;
	}

	string GetParentPath(const string& path)
	{
		string tmp = ReplaceSlash(path);
		size_t pos = tmp.find_last_of('\\');
		if (pos != string::npos)
		{
			return tmp.substr(0, pos + 1);
		}
		return "";
	}

	// 获取Windows目录
	string GetWindowsDir()
	{
		char buffer[MAX_PATH];
		GetWindowsDirectoryA(buffer, MAX_PATH);
		string path = ReplaceSlash(buffer);
		return EnsureEndSlash(ToLower(path));
	}

	// 设备路径映射
	string MapDevicePath(const wstring& devicePath)
	{
		wchar_t drivePaths[512];
		if (!GetLogicalDriveStringsW(512, drivePaths)) return "";

		wchar_t* drive = drivePaths;
		while (*drive) {
			wchar_t device[512];
			if (QueryDosDeviceW(drive, device, 512))
			{
				if (devicePath.find(device) == 0)
				{
					wstring mapped = drive + devicePath.substr(wcslen(device));
					return ReplaceSlash((string)CW2A(mapped.c_str()));
				}
			}
			drive += wcslen(drive) + 1;
		}
		return "";
	}

	// 获取进程文件句柄（完整实现）
	vector<string> GetProcessFileHandles(DWORD pid)
	{
		vector<string> handles;
		NTSTATUS status;
		PSYSTEM_HANDLE_INFORMATION handleInfo;
		ULONG handleInfoSize = 0x10000;

		if (!pNtQuerySystemInformation || !pNtQueryObject)
			return handles;

		handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		// 动态调整缓冲区大小
		while ((status = pNtQuerySystemInformation(
			SystemHandleInformation,
			handleInfo,
			handleInfoSize,
			NULL
		)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
		}

		if (!NT_SUCCESS(status))
		{
			free(handleInfo);
			return handles;
		}

		// 遍历所有句柄
		for (ULONG i = 0; i < handleInfo->NumberOfHandles; ++i)
		{
			SYSTEM_HANDLE_TABLE_ENTRY_INFO handle = handleInfo->Handles[i];
			if (handle.UniqueProcessId != pid) continue;

			HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId);
			if (!hProcess) continue;

			HANDLE hObject;
			if (DuplicateHandle(
				hProcess,
				(HANDLE)handle.HandleValue,
				GetCurrentProcess(),
				&hObject,
				0,
				FALSE,
				DUPLICATE_SAME_ACCESS))
			{
				// 检查文件类型
				ULONG typeBufferSize = 0;
				pNtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &typeBufferSize);
				POBJECT_TYPE_INFORMATION typeInfo = (POBJECT_TYPE_INFORMATION)malloc(typeBufferSize);

				if (NT_SUCCESS(pNtQueryObject(hObject, ObjectTypeInformation,
					typeInfo, typeBufferSize, NULL)))
				{
					// 验证是否为文件对象
					if (wcsncmp(typeInfo->TypeName.Buffer, L"File", 4) == 0)
					{
						// 获取规范化路径
						ULONG nameBufferSize = 0;
						pNtQueryObject(hObject, 1, NULL, 0, &nameBufferSize);
						PUNICODE_STRING nameInfo = (PUNICODE_STRING)malloc(nameBufferSize);

						if (NT_SUCCESS(pNtQueryObject(hObject, 1,
							nameInfo, nameBufferSize, NULL)))
						{
							// 路径转换和规范化
							if (nameInfo->Buffer)
							{
								wstring widePath(nameInfo->Buffer, nameInfo->Length / sizeof(WCHAR));
								string path = NormalizePath(widePath);
								if (!path.empty())
								{
									handles.push_back(path);
								}
							}
						}
						free(nameInfo);
					}
				}
				free(typeInfo);
				CloseHandle(hObject);
			}
			CloseHandle(hProcess);
		}
		free(handleInfo);
		return handles;
	}

	// 路径规范化
	string NormalizePath(const wstring& widePath)
	{
		string path = (char*)CW2A(widePath.c_str());
		path = ReplaceSlash(path);

		// 处理设备路径
		if (path.find("\\device\\") == 0)
		{
			string mapped = MapDevicePath(widePath);
			if (!mapped.empty()) path = mapped;
		}

		// 转换为标准格式
		char buffer[MAX_PATH];
		if (GetFullPathNameA(path.c_str(), MAX_PATH, buffer, NULL))
		{
			path = ToLower(buffer);
		}
		return ReplaceSlash(path);
	}

	// 检测规则实现
	bool IsInWindowsDir(const string& path)
	{
		static string winDir = GetWindowsDir();
		string target = EnsureEndSlash(ToLower(GetParentPath(path)));
		return target.find(winDir) == 0;
	}

	bool IsHiddenFile(const string& path)
	{
		DWORD attrs = GetFileAttributesA(path.c_str());
		return (attrs != INVALID_FILE_ATTRIBUTES) &&
			(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM));
	}

	bool IsRecentModified(const string& path)
	{
		FILETIME ftWrite;
		if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &ftWrite))
		{
			return false;
		}

		SYSTEMTIME stNow, stFile;
		GetSystemTime(&stNow);
		FileTimeToSystemTime(&ftWrite, &stFile);

		// 转换为time_t比较
		auto now = std::chrono::system_clock::now();
		auto fileTime = std::chrono::system_clock::from_time_t(
			(stFile.wHour * 3600 + stFile.wMinute * 60 + stFile.wSecond));

		return (now - fileTime) < std::chrono::seconds(10);
	}

	string GetExtension(const string& path)
	{
		size_t pos = path.find_last_of('.');
		if (pos != string::npos)
		{
			return ToLower(path.substr(pos + 1));
		}
		return "";
	}

	// 目录文件计数
	int CountFilesInDir(const string& dir)
	{
		WIN32_FIND_DATAA fd;
		HANDLE hFind = FindFirstFileA((dir + "*").c_str(), &fd);
		if (hFind == INVALID_HANDLE_VALUE) return 0;

		int count = 0;
		do {
			if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				count++;
			}
		} while (FindNextFileA(hFind, &fd));
		FindClose(hFind);
		return count;
	}

public:
	ProcessRansomwareDetector(int npid) : pid(npid), suspiciousScore(0)
	{
		InitNtAPI();
		RefreshProcessFileHandleList();
	}

	void RefreshProcessFileHandleList()
	{
		ProFilePath = GetProcessFileHandles(static_cast<DWORD>(pid));
	}

	int GetResult()
	{
		suspiciousScore = 0;

		// 规则1: 非Windows目录文件数≥15
		std::unordered_map<string, bool> dirCache;
		for (auto& path : ProFilePath)
		{
			string dir = GetParentPath(path);
			if (dir.empty() || dirCache[dir]) continue;

			dirCache[dir] = true;
			if (!IsInWindowsDir(dir))
			{
				int cnt = CountFilesInDir(dir);
				if (cnt >= 15) suspiciousScore += 3;
			}
		}

		// 规则2: 隐藏文件且扩展名在特定列表
		static const std::unordered_set<string> rule2Ext = { "dll", "bat", "cmd", "ps1", "reg", "sys", "vbs", "exe", "com", "js", "hta", "htm", "iso", "bin" };
		for (const auto& filePath : ProFilePath)
		{
			if (IsHiddenFile(filePath))
			{
				string ext = GetExtension(filePath);
				if (rule2Ext.count(ext)) suspiciousScore += 6;
			}
		}

		// 规则3: 隐藏文件且修改时间<10秒
		for (const auto& filePath : ProFilePath)
		{
			if (IsHiddenFile(filePath) && IsRecentModified(filePath))
			{
				suspiciousScore += 3;
			}
		}

		// 规则4: 扩展名长度≥10
		for (const auto& filePath : ProFilePath)
		{
			string ext = GetExtension(filePath);
			if (ext.length() >= 10) suspiciousScore += 2;
		}

		// 规则5: 常见扩展名数量每满2个加3分
		static const std::unordered_set<string> rule5Ext = { "xls", "xlsx", "ppt", "pptx", "doc", "docx", "txt",
			"html", "htm", "hta", "jpg", "jpeg", "png", "gif", "ico", "pdf", "db", "mp4", "mp3" };
		int count = 0;
		for (const auto& filePath : ProFilePath)
		{
			string ext = GetExtension(filePath);
			if (rule5Ext.count(ext)) count++;
		}
		suspiciousScore += (count / 2) * 3;

		wchar_t processPath[MAX_PATH + 4];
		ZeroMemory(processPath, MAX_PATH + 4);
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProcess)
		{
			DWORD pathSize = sizeof(processPath) / sizeof(wchar_t);
			QueryFullProcessImageNameW(hProcess, 0, processPath, &pathSize);
			CloseHandle(hProcess);
		}

		BOOL isScript = FALSE;

		if (!IsInWindowsDir((string)(CW2A)(::CString)processPath))
		{
			suspiciousScore += 2;
			isScript = TRUE;
		}
		if (EndWithWhat((string)(CW2A)(::CString)processPath, "cmd.exe"))
		{
			suspiciousScore += 3;
			isScript = TRUE;
		}
		else if (EndWithWhat((string)(CW2A)(::CString)processPath, "powershell.exe"))
		{
			suspiciousScore += 3;
			isScript = TRUE;
		}
		else if (EndWithWhat((string)(CW2A)(::CString)processPath, "wscript.exe"))
		{
			suspiciousScore += 3;
			isScript = TRUE;
		}
		else if (EndWithWhat((string)(CW2A)(::CString)processPath, "cscript.exe"))
		{
			suspiciousScore += 4;
			isScript = TRUE;
		}

		if (File_CheckFileSignature(processPath))
		{
			suspiciousScore -= 15;
		}

		if (File_VerifySystemFile(processPath) && !isScript)
		{
			suspiciousScore -= 15;
		}

		return suspiciousScore;
	}
};

/**
 * @brief 计算指定文件的SHA256值（用于完整性或白/黑名单比较）
 * @param filePath 文件路径
 * @return string 返回SHA256的十六进制字符串表示
 */
string Encrypt_CalculateFileSHA256(string filePath);

int Encrypt_OrgEncrptFile(string sPath, string asPath, string sKey);

/**
 * @brief 对指定路径的文件执行加密操作（用于模拟/测试或实际加密流程）
 * @param sPath 要加密的文件路径（宽字符串）
 */
void Encrypt_EncrptFile(wstring sPath);

/**
 * @brief 对指定路径的文件执行解密操作
 * @param sPath 要解密的文件路径（宽字符串）
 */
void Encrypt_DecrptFile(wstring sPath);

// Yara
/**
 * @brief YARA 扫描回调函数，用于接收扫描过程中触发的事件
 * @param context YARA 扫描上下文指针
 * @param message 回调消息类型
 * @param message_data 消息相关数据指针
 * @param user_data 用户自定义数据指针
 * @return int 根据YARA回调规范返回处理结果
 */
int Yara_ScanFileCallBack(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data);

/**
 * @brief 使用已编译的YARA规则扫描指定文件
 * @param path 要扫描的文件路径（std::string）
 * @param virus_name 输出检测到的规则/病毒名称（若有）
 * @return bool 检测到匹配返回true，否则false
 */
bool Yara_ScanFile(const std::string& path, std::string& virus_name);

/**
 * @brief 使用已编译的YARA规则扫描指定文件
 * @param hProcess 要扫描的ProcessHandle
 * @param virus_name 输出检测到的规则/病毒名称（若有）
 * @return bool 检测到匹配返回true，否则false
 */
bool Yara_ScanMemory(HANDLE hProcess, std::string& virus_name);

// Scan
/**
 * @brief 执行通用扫描流程，结合多种引擎/规则进行检测
 * @param FilePath 要扫描的文件路径
 * @param thisSha256 该文件的SHA256（可用于缓存/快速比较）
 * @return string 返回检测结果/标签或空字符串表示未检测到恶意
 */
string Scan_GeneralScan(string FilePath, string thisSha256);

/**
 * @brief 对脚本文件（PowerShell / CMD / BAT）进行沙盒行为分析
 * @param filePath 要扫描的脚本文件路径
 * @return std::string 返回沙盒检测家族标签，BSD/Clean 表示未检测到威胁
 */
std::string Scan_ScriptSandbox(const std::string& filePath);

/**
 * @brief 将宽字符串（LPWSTR）转换为ANSI字符串（LPSTR）
 * @param lpwszStrIn 输入的宽字符串
 * @return string 返回转换后的ANSI字符串
 */
string ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn);

/**
 * @brief 不区分大小写比较两个字符串
 * @param str1 第一个字符串
 * @param str2 第二个字符串
 * @return bool 相等返回true，否则false
 */
bool CompareWithoutCap(const string& str1, const string& str2);

/**
 * @brief 检测当前系统是否为Windows 11（基于系统版本/特征）
 * @return bool 是Windows 11返回true，否则false
 */
bool IsWindows11();

/**
 * @brief 生成一个与进程ID相关的唯一事件名（用于进程间同步/事件对象）
 * @param pid 进程ID
 * @return string 返回生成的唯一事件名
 */
string GenerateUniqueEventName(DWORD pid);

/**
 * @brief 生成一个唯一的文件名（用于临时文件/备份等）
 * @return string 返回生成的文件名
 */
string GenerateFileName();

/**
 * @brief 检查YARA规则名称是否属于例外规则（需要忽略的规则）
 * @param name 规则名称
 * @return bool 是例外规则返回true，否则false
 */
bool IsExceptYaraRule(std::string name);

/**
 * @brief 创建暗色窗口
 * @return void
 */
void Window_CreateWallpaperWithDim();

/**
 * @brief 卡巴斯基风格信息栏组件
 *
 * 每行条目包含：类型图标、信息文本、相对时间、可选按钮。
 * 支持动态添加、删除条目，时间自动格式化为“刚刚/X分钟前”等。
 */
class InfoBar : public QWidget
{
	Q_OBJECT

public:
	enum Type {
		Info,
		Warning,
		Error
	};
	Q_ENUM(Type)

		explicit InfoBar(QWidget* parent = nullptr);
	~InfoBar();

	int addEntry(const QString& title,
		const QString& filePath,
		Type type = Type::Info,
		bool showButton = false,
		const QString& buttonText = QString(),
		std::function<void()> callback = nullptr,
		ElaMenu* dropdownMenu = nullptr,
		int autoRemoveSeconds = 0);

	void clearEntries();
	bool removeEntryById(int id);
	void removeEntriesByPath(const QString& filePath);
	void refreshTimes();
	void setThemeMode(bool isDark);

	int entryCount() const;

Q_SIGNALS:
	void entryCountChanged(int count);

private:
	struct EntryWidget;

	QVBoxLayout* m_layout;
	QList<EntryWidget*> m_entries;
	QTimer* m_timeRefreshTimer;
	int m_nextId = 1;
	bool m_isDark = false;

	void applyThemeToEntry(EntryWidget* entry);
	void updateStyle();
	static QString formatTimeSince(const QDateTime& timestamp);
};

// 日志等级
enum LogLevel
{
    LOG_INFO    = 0,    // 一般信息
    LOG_SUCCESS = 1,    // 成功操作
    LOG_WARN    = 2,    // 警告
    LOG_ERROR   = 3     // 错误
};

// 兼容旧接口：LogType 参数已废弃，内部按 LogLevel::LOG_INFO 处理
inline void Log_AddLog(string LogContent, int LogType = 1);

// 兼容旧接口：LogType 参数已废弃，内部按 LogLevel::LOG_INFO 处理
inline void Log_AddLogUni(QString LogContent, int LogType = 1);

// 新接口：带日志等级 + 提供者
void Log_AddLogEx(QString Summary, QString Detail, LogLevel level = LOG_INFO, QString Provider = QString());

// 新接口：带日志等级 + 提供者（无详情，摘要即详情）
void Log_AddLogSimple(QString Summary, LogLevel level = LOG_INFO, QString Provider = QString());

// ==================== 威胁回滚确认弹窗（非阻塞 modeless）====================
// 显示回滚项列表（文件+注册表），默认全选，用户选择回滚/忽略后通过 callback 返回选择结果。
// callback 在主线程中调用，可安全发送 socket 响应。
void ShowRollbackConfirmPopup(
    const BA_ROLLBACK_LIST* rollbackList,
    std::function<void(const BA_ROLLBACK_SELECTION&)> callback,
    QWidget* parent = nullptr);