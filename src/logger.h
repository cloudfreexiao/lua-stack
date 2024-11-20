#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>


#define LEVEL_TO_STR(x) x, #x


// 定义日志等级的枚举和对应的字符串
#define LOG_LEVELS \
    X(DEBUG, "DEBUG") \
    X(INFO, "INFO") \
    X(WARN, "WARN") \
    X(ERROR, "ERROR") \
    X(FATAL, "FATAL")
    

#define X(level, string) level,
typedef enum {
    LOG_LEVELS
} LogLevel;
#undef X

#define X(level, string) string,
static const char* LogLevelStrings[] = {
    LOG_LEVELS
};
#undef X

// 定义日志打印函数
#define LOG(level, format, ...) do {\
    printf("[%s] " format "\n", LogLevelStrings[level], ##__VA_ARGS__); \
    if (level >= FATAL) exit(1); } \
while (0)



#endif

