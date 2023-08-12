
#pragma once

// When using this logging tool, please define LOG_TAG to determine
// the TAG of the log. Otherwise, the default TAG will be used.
#ifndef LOG_TAG
#define LOG_TAG "CONFIG_FS"
#endif

// Output more detailed information, very large quantity!
#ifndef VERBOSE_DEBUG
#define VERBOSE_DEBUG 1
#endif

// Control whether DEBUG is effective
#ifndef MIUIDEBUG
#define MIUIDEBUG 1
#endif

// Encapsulate a generic logging function.
// Use different log output methods for different system platforms.
#if defined(__Android__)
    // Log output method on Android platform.
    // needed "liblog" shared lib
    #include <android/log.h>
    #define LogE(format, ...) \
        __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, format, ##__VA_ARGS__)
    #define LogW(format, ...) \
        __android_log_print(ANDROID_LOG_WARN, LOG_TAG, format, ##__VA_ARGS__)
    #define LogI(format, ...) \
        __android_log_print(ANDROID_LOG_INFO, LOG_TAG, format, ##__VA_ARGS__)
    #define LogD(format, ...) \
        if(MIUIDEBUG) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, "[MIUIBPFDEBUG] " format, ##__VA_ARGS__)
#elif defined(__Linux__)
    // Log output method on Linux base platform.
    #include <syslog.h>
    #define LogE(format, ...) \
        syslog(LOG_ERR, "[%s] " format, LOG_TAG, ##__VA_ARGS__)
    #define LogW(format, ...) \
        syslog(LOG_WARNING, "[%s] " format, LOG_TAG, ##__VA_ARGS__)
    #define LogI(format, ...) \
        syslog(LOG_INFO, "[%s] " format, LOG_TAG, ##__VA_ARGS__)
    #define LogD(format, ...) \
        if(MIUIDEBUG) syslog(LOG_DEBUG, "[MIUIBPFDEBUG] [%s] " format, LOG_TAG, ##__VA_ARGS__)
#else
    // Universal log output method, supported by any system.
    #include <stdio.h>
    #define LogE(format, ...) \
        printf("[%s] [%s] " format "\n", "ERROR", LOG_TAG, ##__VA_ARGS__)
    #define LogW(format, ...) \
        printf("[%s] [%s] " format "\n", "WARN", LOG_TAG, ##__VA_ARGS__)
    #define LogI(format, ...) \
        printf("[%s] [%s] " format "\n", "INFO", LOG_TAG, ##__VA_ARGS__)
    #define LogD(format, ...) \
        if(MIUIDEBUG) printf("[MIUIBPFDEBUG] [%s] [%s] " format "\n", "DEBUG", LOG_TAG, ##__VA_ARGS__)
#endif
