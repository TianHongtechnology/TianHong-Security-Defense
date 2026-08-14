#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <tchar.h>
#include <WinSock2.h>
#include <Windows.h>
#include <comutil.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comsuppw.lib")

enum PacketType
{
	PTConnection,
	PTVirusOpreationConfirm,
	PTProtectFile,
	PTHideFile,
	PTCreateProcessRoutine
};

enum WarnDlgType
{
	WDT_Normal,
	WDT_Setting,
	WDT_Wifi
};

struct Packet
{
	PacketType PacketTyped;    // 类型
	char Message[1024];        // 信息
	int Pid;                   // 进程pid
	char WarnTitle[128];       // 作为WarnDlg标题
	char InfoTitle[32];        // 作为Info类型标题
	bool NeedTerminate = false;// 拦截直接Terminate进程
	WarnDlgType WarnType;      // WarnDlg图标风格
};

using namespace std;

#ifdef _WIN32
#ifdef _WIN64
#error"Error: This progam should be complied in x32 mode."
#endif
#endif //_WIN32

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" ) // 设置入口地址

SOCKET Server;

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
void SuspendProcess(HANDLE processHandle, bool CloseHandleit = false)
{
	NtSuspendProcess pfnNtSuspendProcess =
		(NtSuspendProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtSuspendProcess");
	pfnNtSuspendProcess(processHandle);
	if (CloseHandleit) CloseHandle(processHandle);
}

typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);
void ResumeProcess(HANDLE processHandle, bool CloseHandleit = false)
{
	NtResumeProcess pfnNtResumeProcess =
		(NtResumeProcess)GetProcAddress(GetModuleHandle(L"ntdll"), "NtResumeProcess");
	pfnNtResumeProcess(processHandle);
	if (CloseHandleit) CloseHandle(processHandle);
}

wstring string2wstring(const string s)
{
	_bstr_t t = s.c_str();
	wchar_t* pwchar = (wchar_t*)t;
	wstring result = pwchar;
	return result;
}

bool InjectDll(DWORD dwProcessId, wstring pDll)
{
	HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
	if (NULL == hProcess)
	{
		return false;
	}

	const TCHAR* ptszDllFile = pDll.c_str();
	// 参数无效  
	if (NULL == ptszDllFile || 0 == ::_tcslen(ptszDllFile))
	{
		return false;
	}
	// 指定 Dll 文件不存在  
	if (-1 == _taccess(ptszDllFile, 0))
	{
		return false;
	}
	HANDLE hThread = NULL;
	DWORD dwSize = 0;
	TCHAR* ptszRemoteBuf = NULL;
	LPTHREAD_START_ROUTINE lpThreadFun = NULL;
	// 在目标进程中分配内存空间  
	dwSize = (DWORD)::_tcslen(ptszDllFile) + 1;
	ptszRemoteBuf = (TCHAR*)::VirtualAllocEx(hProcess, NULL, dwSize * sizeof(TCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (NULL == ptszRemoteBuf)
	{
		::CloseHandle(hProcess);
		return false;
	}
	// 在目标进程的内存空间中写入所需参数(模块名)  
	if (FALSE == ::WriteProcessMemory(hProcess, ptszRemoteBuf, (LPVOID)ptszDllFile, dwSize * sizeof(TCHAR), NULL))
	{
		::VirtualFreeEx(hProcess, ptszRemoteBuf, dwSize, MEM_DECOMMIT);
		::CloseHandle(hProcess);
		return false;
	}
	// 从 Kernel32.dll 中获取 LoadLibrary 函数地址  
#ifdef _UNICODE  
	lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryW");
#else  
	lpThreadFun = (PTHREAD_START_ROUTINE)::GetProcAddress(::GetModuleHandle(_T("Kernel32")), "LoadLibraryA");
#endif  
	if (NULL == lpThreadFun)
	{
		::VirtualFreeEx(hProcess, ptszRemoteBuf, dwSize, MEM_DECOMMIT);
		::CloseHandle(hProcess);
		return false;
	}
	// 创建远程线程调用 LoadLibrary  
	hThread = ::CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, ptszRemoteBuf, 0, NULL);
	if (NULL == hThread)
	{
		::VirtualFreeEx(hProcess, ptszRemoteBuf, dwSize, MEM_DECOMMIT);
		::CloseHandle(hProcess);
		return false;
	}
	//ResumeThread(hThread);
	//ThreadResumeProcess(dwProcessId);
	// 等待远程线程结束（最多5秒，避免目标进程挂起导致无限等待）
	DWORD waitResult = ::WaitForSingleObject(hThread, 5000);
	if (waitResult == WAIT_TIMEOUT)
	{
		// 远程线程仍在运行 LoadLibraryW，不能释放远程内存，否则目标进程会
		// 因访问已释放的字符串缓冲区而崩溃。远程内存由目标进程退出时自动回收。
		::CloseHandle(hThread);
		::CloseHandle(hProcess);
		return false;
	}
	else if (waitResult == WAIT_FAILED)
	{
		// 等待失败，同样不释放远程内存以避免 UAF。
		::CloseHandle(hThread);
		::CloseHandle(hProcess);
		return false;
	}
	// 远程线程已完成。不释放远程内存：LoadLibraryW 可能仍在收尾（如 DllMain 回调），
	// 释放可能导致竞态。远程内存由目标进程退出时自动回收。
	::CloseHandle(hThread);
	::CloseHandle(hProcess);
	return true;
}

struct InjectPacket
{
	int pid;
	string path;
	string EventName;
};

static DWORD __stdcall InjectT(LPVOID lpParam)
{
	InjectPacket* pip = (InjectPacket*)lpParam;
	InjectPacket ip = *pip;

	delete pip;

	InjectDll(ip.pid, string2wstring(ip.path));

	HANDLE hEvent = OpenEventA(
		EVENT_MODIFY_STATE,  // 需要修改状态的权限
		FALSE,              // 不继承句柄
		ip.EventName.c_str()   // 与注入器相同的事件名称
	);

	if (hEvent != NULL)
	{
		SetEvent(hEvent);
		CloseHandle(hEvent);
	}

	// ResumeProcess(OpenProcess(PROCESS_ALL_ACCESS, FALSE, ip.pid));

	return 0;
}

extern int Tran_RecvPacket(SOCKET s, Packet& PacketOut)
{
	char recvbuf[sizeof(Packet)];
	Packet* Packetrecv;
	int result = recv(s, recvbuf, sizeof(recvbuf), 0);
	Packetrecv = (Packet*)recvbuf;
	PacketOut = *Packetrecv;
	return result;
}

int Violation(LPEXCEPTION_POINTERS p_exinfo)
{
	if (p_exinfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		return EXCEPTION_EXECUTE_HANDLER; //告诉except处理这个异常
	}
	else
	{
		return EXCEPTION_CONTINUE_SEARCH; //不告诉except处理这个异常
	}
}

extern int Tran_OrgSendPacket(SOCKET s, char text[1024], PacketType PacketTypeIn, char WarnTitle[128], int Pid, char InfoTitle[32], WarnDlgType DlgIconType, bool NeedTerminate)
{
	Packet Packetsend{};

	Packetsend.Pid = Pid;
	Packetsend.PacketTyped = PacketTypeIn;
	Packetsend.WarnType = DlgIconType;
	Packetsend.NeedTerminate = NeedTerminate;

	strcpy_s(Packetsend.Message, text);
	strcpy_s(Packetsend.WarnTitle, WarnTitle);
	strcpy_s(Packetsend.InfoTitle, InfoTitle);

	char SendBuff[sizeof(Packet)] = "";
	memcpy(SendBuff, &Packetsend, sizeof(Packet));

	return send(s, SendBuff, sizeof(SendBuff), 0);
}

extern int Tran_SendPacket(SOCKET s, char text[1024], PacketType PacketTypeIn, char Title[128], int Pid)
{
	return Tran_OrgSendPacket(s, text, PacketTypeIn, Title, Pid, (char*)"", WDT_Normal, false);
}

extern bool Tran_IsSocketClosed(SOCKET clientSocket)
{
	bool ret = false;
	HANDLE closeEvent = WSACreateEvent();
	WSAEventSelect(clientSocket, closeEvent, FD_CLOSE);

	DWORD dwRet = WaitForSingleObject(closeEvent, 0);

	if (dwRet == WSA_WAIT_EVENT_0)
		ret = true;
	else if (dwRet == WSA_WAIT_TIMEOUT)
		ret = false;

	WSACloseEvent(closeEvent);
	return ret;
}

static DWORD __stdcall RecvT(LPVOID lpParam)
{
	while (true)
	{
		Packet PacketRecv;

		if (Tran_IsSocketClosed(Server)) break;
		else if (Tran_RecvPacket(Server, PacketRecv) > 0)
		{
			// string FilePath;
			InjectPacket* pip;
			switch (PacketRecv.PacketTyped)
			{
			case PTCreateProcessRoutine:
				pip = new InjectPacket;
				pip->pid = PacketRecv.Pid;
				pip->path = PacketRecv.Message;
				pip->EventName = PacketRecv.WarnTitle;

				CreateThread(0, 0, InjectT, pip, 0, 0);
				break;
			default:
				break;
			}
		}
		Sleep(10);
	}

	closesocket(Server);
	return 0;
}

int main(int argc, char** argv)
{
	// 组网初始化
	WSADATA wsaData;
	struct sockaddr_in serverAddr;

	// 初始化 Winsock
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		// MessageBox(NULL, L"[-] WSAStartup失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
		return 1;
	}

	// 创建 socket
	if ((Server = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		// MessageBox(NULL, L"[-] 创建socket失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
		return 1;
	}

	// 设置服务器地址和端口
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1"); // 服务器 IP 地址
	serverAddr.sin_port = htons(12346); // 服务器端口

	// 连接到服务器
	if (connect(Server, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0)
	{
		// MessageBox(NULL, L"[-] 连接失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
		return 1;
	}

	u_long mode = 0;

	if (ioctlsocket(Server, FIONBIO, &mode) != 0)
	{
		// MessageBox(L"[-] 设置sock阻塞模式失败！", L"错误", MB_TOPMOST | MB_ICONERROR);
		return 1;
	}

	WaitForSingleObject(CreateThread(0, 0, RecvT, 0, 0, 0), INFINITE);

	return 0;
}