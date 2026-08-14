#pragma once

#include "define.h"

#ifndef STATUS_SUCCESS
#define  STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_BUFFER_TOO_SMALL
#define  STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif

extern int Tran_RecvPacket(SOCKET s, Packet& PacketOut);
extern int Tran_OrgSendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char WarnTitle[128], int Pid, char InfoTitle[32], WarnDlgType DlgIconType = WDT_Normal, bool NeedTerminate = false);
extern int Tran_SendPacket(SOCKET s, char text[4096], PacketType PacketTypeIn, char Title[128], int Pid = -1);
extern bool Tran_IsSocketClosed(SOCKET clientSocket);

char* Str_ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn);
wchar_t* Str_ConvertLPSTRToLPWSTR(char* lpczStrIn);
bool Str_EndsWith(const std::string& str, const std::string& suffix);
wstring Str_PUNICODE_STRINGToWString(PUNICODE_STRING pUnicodeString);
string Str_ExtractContentBetweenSecondAndThirdSlashes(const string input);
string Str_ExtractContentBetweenThirdAndForthSlashes(const string input);
bool Str_CompareWithoutCap(string str1, string str2);
string Str_ExtractContentAfterNSlash(const string input, int N = 3);
bool Str_StartsWithWithoutCap(const std::string& str, const std::string& prefix);

wstring File_GetFilePathFromHFILE(HANDLE hFile, int type = VOLUME_NAME_NT);

wstring Reg_GetKeyPathFromKKEY(HKEY key);

bool File_VerifySystemFile(wstring filePath);