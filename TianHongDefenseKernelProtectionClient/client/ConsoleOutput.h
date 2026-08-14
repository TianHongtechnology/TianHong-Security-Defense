#pragma once
#include <windows.h>
#include <string>

// 控制台颜色枚举
enum class ConsoleColor {
    Black = 0,
    Blue = 1,
    Green = 2,
    Cyan = 3,
    Red = 4,
    Magenta = 5,
    Yellow = 6,
    White = 7,
    Gray = 8,
    BrightBlue = 9,
    BrightGreen = 10,
    BrightCyan = 11,
    BrightRed = 12,
    BrightMagenta = 13,
    BrightYellow = 14,
    BrightWhite = 15,
    DarkGray = 8
};

// 输出前缀
#define PREFIX_SUCCESS "[+]"
#define PREFIX_FAILURE "[-]"
#define PREFIX_WARNING "[!]"
#define PREFIX_INFO    "[*]"
#define PREFIX_COMPLETE "[>]"
#define PREFIX_PROGRESS "[.]"
#define PREFIX_DEBUG   "[D]"

// RAII 颜色管理
class ColorGuard {
public:
    ColorGuard(ConsoleColor fg);
    ~ColorGuard();
private:
    WORD m_originalAttributes;
};

// 输出函数
void SetConsoleColor(ConsoleColor fg, ConsoleColor bg = ConsoleColor::Black);
void ResetConsoleColor();
void PrintSuccess(const char* format, ...);
void PrintFailure(const char* format, ...);
void PrintWarning(const char* format, ...);
void PrintInfo(const char* format, ...);
void PrintComplete(const char* format, ...);
void PrintProgress(const char* format, ...);
void PrintDebug(const char* format, ...);
void PrintSeparator();
