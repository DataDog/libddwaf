// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <fmt/core.h>

#include "ddwaf.h"

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define DDWAF_COMPILE_LOG_TRACE 0
#define DDWAF_COMPILE_LOG_DEBUG 1
#define DDWAF_COMPILE_LOG_INFO 2
#define DDWAF_COMPILE_LOG_WARN 3
#define DDWAF_COMPILE_LOG_ERROR 4
#define DDWAF_COMPILE_LOG_OFF 5
// NOLINTEND(cppcoreguidelines-macro-usage)

static_assert(DDWAF_COMPILE_LOG_TRACE == DDWAF_LOG_TRACE);
static_assert(DDWAF_COMPILE_LOG_DEBUG == DDWAF_LOG_DEBUG);
static_assert(DDWAF_COMPILE_LOG_INFO == DDWAF_LOG_INFO);
static_assert(DDWAF_COMPILE_LOG_WARN == DDWAF_LOG_WARN);
static_assert(DDWAF_COMPILE_LOG_ERROR == DDWAF_LOG_ERROR);
static_assert(DDWAF_COMPILE_LOG_OFF == DDWAF_LOG_OFF);

#if !defined(DDWAF_COMPILE_LOG_LEVEL)
#  define DDWAF_COMPILE_LOG_LEVEL DDWAF_COMPILE_LOG_TRACE
#endif

// NOLINTBEGIN
#if DDWAF_COMPILE_LOG_LEVEL < DDWAF_COMPILE_LOG_OFF
constexpr const char *base_name(const char *path)
{
    const char *base = path;
    while (*path != '\0') {
#  ifdef _WIN32
        char separator = '\\';
#  else
        char separator = '/';
#  endif
        if (*path++ == separator) {
            base = path;
        }
    }
    return base;
}

#  define DDWAF_LOG_HELPER(level, function, file, line, fmt_str, ...)                              \
    {                                                                                              \
      if (ddwaf::logger::valid(level)) {                                                           \
        constexpr const char *filename = base_name(file);                                          \
        auto message = ddwaf::fmt::format(fmt_str, ##__VA_ARGS__);                                 \
        ddwaf::logger::log(level, function, filename, line, message.c_str(), message.size());      \
      }                                                                                            \
    }

#  define DDWAF_LOG(level, fmt, ...)                                                               \
    DDWAF_LOG_HELPER(level, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#endif

#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_TRACE
#  define DDWAF_TRACE(fmt, ...) DDWAF_LOG(DDWAF_LOG_TRACE, fmt, ##__VA_ARGS__)
#else
#  define DDWAF_TRACE(fmt, ...) (void)0
#endif
#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_DEBUG
#  define DDWAF_DEBUG(fmt, ...) DDWAF_LOG(DDWAF_LOG_DEBUG, fmt, ##__VA_ARGS__)
#else
#  define DDWAF_DEBUG(fmt, ...) (void)0
#endif
#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_INFO
#  define DDWAF_INFO(fmt, ...) DDWAF_LOG(DDWAF_LOG_INFO, fmt, ##__VA_ARGS__)
#else
#  define DDWAF_INFO(fmt, ...) (void)0
#endif
#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_WARN
#  define DDWAF_WARN(fmt, ...) DDWAF_LOG(DDWAF_LOG_WARN, fmt, ##__VA_ARGS__)
#else
#  define DDWAF_WARN(fmt, ...) (void)0
#endif
#if DDWAF_COMPILE_LOG_LEVEL <= DDWAF_COMPILE_LOG_ERROR
#  define DDWAF_ERROR(fmt, ...) DDWAF_LOG(DDWAF_LOG_ERROR, fmt, ##__VA_ARGS__)
#else
#  define DDWAF_ERROR(fmt, ...) (void)0
#endif
// NOLINTEND

namespace ddwaf {
class logger {
public:
    static void init(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level);
    static bool valid(DDWAF_LOG_LEVEL level) { return cb != nullptr && level >= min_level; }
    static void log(DDWAF_LOG_LEVEL level, const char *function, const char *file, unsigned line,
        const char *message, size_t length);

private:
    static ddwaf_log_cb cb;
    static DDWAF_LOG_LEVEL min_level;
};

} // namespace ddwaf
