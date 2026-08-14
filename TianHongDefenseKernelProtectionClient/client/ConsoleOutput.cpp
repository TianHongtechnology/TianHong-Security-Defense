#include "ConsoleOutput.h"
#include <cstdio>
#include <cstdarg>

// ============================================================================
// 内部辅助函数
// ============================================================================

static HANDLE GetConsoleHandle()
{
    return GetStdHandle(STD_OUTPUT_HANDLE);
}

static WORD MakeAttributes(ConsoleColor fg, ConsoleColor bg)
{
    return (static_cast<WORD>(bg) << 4) | static_cast<WORD>(fg);
}

static void PrintColored(ConsoleColor fg, const char* prefix, const char* format, va_list args)
{
    HANDLE hConsole = GetConsoleHandle();
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD originalAttrs = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    if (GetConsoleScreenBufferInfo(hConsole, &csbi))
    {
        originalAttrs = csbi.wAttributes;
    }

    // 设置前景色，背景始终为黑色
    SetConsoleTextAttribute(hConsole, MakeAttributes(fg, ConsoleColor::Black));

    // 打印前缀
    printf("%s ", prefix);

    // 打印格式化消息
    vprintf(format, args);
    printf("\n");

    // 恢复原始颜色
    SetConsoleTextAttribute(hConsole, originalAttrs);
}

// ============================================================================
// ColorGuard 实现
// ============================================================================

ColorGuard::ColorGuard(ConsoleColor fg)
{
    HANDLE hConsole = GetConsoleHandle();
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi))
    {
        m_originalAttributes = csbi.wAttributes;
    }
    else
    {
        m_originalAttributes = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }

    SetConsoleTextAttribute(hConsole, MakeAttributes(fg, ConsoleColor::Black));
}

ColorGuard::~ColorGuard()
{
    SetConsoleTextAttribute(GetConsoleHandle(), m_originalAttributes);
}

// ============================================================================
// 颜色设置函数
// ============================================================================

void SetConsoleColor(ConsoleColor fg, ConsoleColor bg)
{
    SetConsoleTextAttribute(GetConsoleHandle(), MakeAttributes(fg, bg));
}

void ResetConsoleColor()
{
    SetConsoleTextAttribute(GetConsoleHandle(),
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// ============================================================================
// 格式化输出函数
// ============================================================================

void PrintSuccess(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Green, PREFIX_SUCCESS, format, args);
    va_end(args);
}

void PrintFailure(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Red, PREFIX_FAILURE, format, args);
    va_end(args);
}

void PrintWarning(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Yellow, PREFIX_WARNING, format, args);
    va_end(args);
}

void PrintInfo(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Cyan, PREFIX_INFO, format, args);
    va_end(args);
}

void PrintComplete(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Green, PREFIX_COMPLETE, format, args);
    va_end(args);
}

void PrintProgress(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Blue, PREFIX_PROGRESS, format, args);
    va_end(args);
}

void PrintDebug(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    PrintColored(ConsoleColor::Gray, PREFIX_DEBUG, format, args);
    va_end(args);
}

void PrintSeparator()
{
    HANDLE hConsole = GetConsoleHandle();
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    WORD originalAttrs = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    if (GetConsoleScreenBufferInfo(hConsole, &csbi))
    {
        originalAttrs = csbi.wAttributes;
    }

    SetConsoleTextAttribute(hConsole, MakeAttributes(ConsoleColor::Gray, ConsoleColor::Black));
    printf("========================================\n");
    SetConsoleTextAttribute(hConsole, originalAttrs);
}