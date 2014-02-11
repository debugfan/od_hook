#include "debug_log.h"
#include <Windows.h>
#include <stdarg.h>
#include <stdio.h>

void _Output(const char *fmt_str, ...)
{
    int nSize = 0;
    char buff[1024];
    memset(buff, 0, sizeof(buff));
    va_list args;
    va_start(args, fmt_str);
    nSize = _vsnprintf(buff, sizeof(buff) - 1, fmt_str, args);
    va_end(args);
    if(nSize <= 0)
    {
        OutputDebugString("_vsnprintf failed");
    }
    else 
    {
        OutputDebugString(buff);
    }
}
