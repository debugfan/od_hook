#ifndef DEBUG_LOG_H
#define DEBUG_LOG_H

void _Output(const char *fmt_str, ...);

#ifdef _DEBUG
#define log_debug(x) _Output x
#define log_info(x) _Output x
#define log_info2(x) _Output x
#define log_error(x) _Output x
#define log_warn(x) _Output x
#else
#define log_debug(x)
#define log_info(x) _Output x
#define log_info2(x) _Output x
#define log_error(x) _Output x
#define log_warn(x) _Output x
#endif

#endif