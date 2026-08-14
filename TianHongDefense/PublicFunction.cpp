#include "PublicFunction.h"

// ����ͨ��

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
        return EXCEPTION_EXECUTE_HANDLER; //����except��������쳣
    }
    else
    {
        return EXCEPTION_CONTINUE_SEARCH; //������except��������쳣
    }
}

extern int Tran_OrgSendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char WarnTitle[128], int Pid, char InfoTitle[32], WarnDlgType DlgIconType, bool NeedTerminate)
{
    Packet Packetsend{};

    Packetsend.Pid = Pid;
    Packetsend.PacketTyped = PacketTypeIn;
    Packetsend.WarnType = DlgIconType;
    Packetsend.NeedTerminate = NeedTerminate;

    // 使用 _TRUNCATE 防止源字符串过长导致运行时断言；保留截断语义
    strncpy_s(Packetsend.Message, sizeof(Packetsend.Message), text, _TRUNCATE);
    strncpy_s(Packetsend.WarnTitle, sizeof(Packetsend.WarnTitle), WarnTitle, _TRUNCATE);
    strncpy_s(Packetsend.InfoTitle, sizeof(Packetsend.InfoTitle), InfoTitle, _TRUNCATE);

    char SendBuff[sizeof(Packet)] = "";
    memcpy(SendBuff, &Packetsend, sizeof(Packet));

    // 循环发送，确保完整写出或返回 SOCKET_ERROR
    int totalSent = 0;
    int toSend = sizeof(SendBuff);
    while (totalSent < toSend)
    {
        int sent = send(s, SendBuff + totalSent, toSend - totalSent, 0);
        if (sent == SOCKET_ERROR)
            return SOCKET_ERROR;
        totalSent += sent;
    }
    return totalSent;
}

extern int Tran_SendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char Title[128], int Pid)
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



// �ַ�������
char* Str_ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)
{
    wstring ws = lpwszStrIn;
    _bstr_t t = ws.c_str();
    return strdup(t);
}

wchar_t* Str_ConvertLPSTRToLPWSTR(char* lpczStrIn)
{
    // ��std::stringת��Ϊ_bstr_t
    _bstr_t bstr(lpczStrIn);

    // ��_bstr_tת��Ϊstd::wstring
    return (wchar_t*)(wstring(bstr)).c_str();
}

wstring Str_PUNICODE_STRINGToWString(PUNICODE_STRING pUnicodeString)
{
	if (pUnicodeString == nullptr || pUnicodeString->Buffer == nullptr)
	{
		return L"";
	}

	wstring wstr(pUnicodeString->Buffer, pUnicodeString->Length / sizeof(wchar_t));

	return wstr;
}

bool Str_EndsWith(const std::string& str, const std::string& suffix)
{
    // ������ַ�������С�ں�׺�ַ������ȣ��򲻿���ƥ��
    if (str.size() < suffix.size())
    {
        return false;
    }

    // ʹ�� reverse iterators ���Ӻ���ǰ�Ƚ�
    auto strIt = str.rbegin();
    auto suffixIt = suffix.rbegin();

    while (suffixIt != suffix.rend())
    {
        // �Ƚ������ַ��Ƿ���ȣ����Դ�Сд��
        if (std::tolower(*strIt) != std::tolower(*suffixIt))
        {
            return false;
        }
        ++strIt;
        ++suffixIt;
    }

    return true;
}

string Str_ExtractContentBetweenSecondAndThirdSlashes(const string input)
{
    size_t firstSlashPos = input.find('\\');
    if (firstSlashPos == string::npos)
    {
        return "";
    }

    size_t secondSlashPos = input.find('\\', firstSlashPos + 1);
    if (secondSlashPos == string::npos)
    {
        return "";
    }

    size_t thirdSlashPos = input.find('\\', secondSlashPos + 1);
    if (thirdSlashPos == string::npos)
    {
        return "";
    }

    return input.substr(secondSlashPos + 1, thirdSlashPos - secondSlashPos - 1);
}

string Str_ExtractContentBetweenThirdAndForthSlashes(const string input)
{
    size_t firstSlashPos = input.find('\\');
    if (firstSlashPos == string::npos)
    {
        return "";
    }

    size_t secondSlashPos = input.find('\\', firstSlashPos + 1);
    if (secondSlashPos == string::npos)
    {
        return "";
    }

    size_t thirdSlashPos = input.find('\\', secondSlashPos + 1);
    if (thirdSlashPos == string::npos)
    {
        return "";
    }

    size_t forthSlashPos = input.find('\\', thirdSlashPos + 1);
    if (forthSlashPos == string::npos)
    {
        return "";
    }

    return input.substr(thirdSlashPos + 1, forthSlashPos - thirdSlashPos - 1);
}

bool Str_CompareWithoutCap(string str1, string str2)
{
    // ������ʱ�����㷨����ʱ������������
    string str1Cpy(str1);
    string str2Cpy(str2);
    transform(str1Cpy.begin(), str1Cpy.end(), str1Cpy.begin(), ::tolower);
    transform(str2Cpy.begin(), str2Cpy.end(), str2Cpy.begin(), ::tolower);

    return (strcmp(str1Cpy.c_str(), str2Cpy.c_str()) == 0);
}

string Str_ExtractContentAfterNSlash(const string input, int N)
{
    size_t SlashPos = -1;
    for (int i = 0; i < N; i++)
    {
        SlashPos = input.find('\\', SlashPos + 1);
        if (SlashPos == string::npos)
        {
            return "";
        }
    }

    if (SlashPos != -1) return input.substr(SlashPos + 1);
    else return "";
}

bool Str_StartsWithWithoutCap(const std::string& str, const std::string& prefix) {
    if (prefix.size() > str.size()) return false;

    for (size_t i = 0; i < prefix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(prefix[i])) !=
            std::tolower(static_cast<unsigned char>(str[i]))) {
            return false;
        }
    }
    return true;
}

wstring File_GetFilePathFromHFILE(HANDLE hFile, int type)
{
    WCHAR wcRet[MAX_PATH + 20];

    if (!GetFinalPathNameByHandleW(hFile, wcRet, MAX_PATH, type))
    {
        return (WCHAR*)L"";
    }

    wstring wsRet;

    wsRet = wcRet;

    return wsRet;
}

wstring Reg_GetKeyPathFromKKEY(HKEY key)
{
    wstring keyPath;
    if (key != NULL)
    {
        HMODULE dll = LoadLibrary(L"ntdll.dll");
        if (dll != NULL)
        {
            typedef DWORD(__stdcall* ZwQueryKeyType)(
                HANDLE  KeyHandle,
                int  KeyInformationClass,
                PVOID  KeyInformation,
                ULONG  Length,
                PULONG  ResultLength);

            ZwQueryKeyType func = reinterpret_cast<ZwQueryKeyType>(::GetProcAddress(dll, "ZwQueryKey"));

            if (func != NULL)
            {
                DWORD size = 0;
                DWORD result = 0;
                result = func(key, 3, 0, 0, &size);
                if (result == STATUS_BUFFER_TOO_SMALL)
                {
                    size = size + 2;
                    wchar_t* buffer = new (nothrow)wchar_t[size];
                    if (buffer != NULL)
                    {
                        result = func(key, 3, buffer, size, &size);
                        if (result == STATUS_SUCCESS)
                        {
                            buffer[size / sizeof(wchar_t)] = L'\0';
                            keyPath = wstring(buffer + 2);
                        }

                        delete[] buffer;
                    }
                }
            }

            FreeLibrary(dll);
        }
    }
    return keyPath;
}


// ����Ƿ�Ϊϵͳ�ļ�
bool File_VerifySystemFile(wstring filePath)
{
    BOOL isProtected = SfcIsFileProtected(NULL, filePath.c_str());

    return isProtected;
}