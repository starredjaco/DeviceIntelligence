#pragma once

#include <android/log.h>

#define DICORE_LOG_TAG "dicore"

#define RLOGI(...) __android_log_print(ANDROID_LOG_INFO,  DICORE_LOG_TAG, __VA_ARGS__)
#define RLOGW(...) __android_log_print(ANDROID_LOG_WARN,  DICORE_LOG_TAG, __VA_ARGS__)
#define RLOGE(...) __android_log_print(ANDROID_LOG_ERROR, DICORE_LOG_TAG, __VA_ARGS__)
#define RLOGD(...) __android_log_print(ANDROID_LOG_DEBUG, DICORE_LOG_TAG, __VA_ARGS__)
