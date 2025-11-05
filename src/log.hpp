// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include <fmt/core.h> // IWYU pragma: keep

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
constexpr const char *base_name(const char *path)
{
    const char *base = path;
    while (*path != '\0') {
#ifdef _WIN32
        char separator = '\\';
#else
        const char separator = '/';
#endif
        if (*path++ == separator) {
            base = path;
        }
    }
    return base;
}

#define DDWAF_LOG_HELPER(level, function, file, line, fmt_str, ...)                                \
    {                                                                                              \
        if (ddwaf::logger::valid(level)) {                                                         \
            try {                                                                                  \
                constexpr const char *filename = base_name(file);                                  \
                auto message = ddwaf::fmt::format(fmt_str, ##__VA_ARGS__);                         \
                ddwaf::logger::log(                                                                \
                    level, function, filename, line, message.c_str(), message.size());             \
            } catch (...) {}                                                                       \
        }                                                                                          \
    }

#define DDWAF_LOG(level, fmt, ...)                                                                 \
    DDWAF_LOG_HELPER(level, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__)

#define DDWAF_TRACE(fmt, ...) DDWAF_LOG(ddwaf::log_level::trace, fmt, ##__VA_ARGS__)
#define DDWAF_DEBUG(fmt, ...) DDWAF_LOG(ddwaf::log_level::debug, fmt, ##__VA_ARGS__)
#define DDWAF_INFO(fmt, ...) DDWAF_LOG(ddwaf::log_level::info, fmt, ##__VA_ARGS__)
#define DDWAF_WARN(fmt, ...) DDWAF_LOG(ddwaf::log_level::warn, fmt, ##__VA_ARGS__)
#define DDWAF_ERROR(fmt, ...) DDWAF_LOG(ddwaf::log_level::error, fmt, ##__VA_ARGS__)
// NOLINTEND(cppcoreguidelines-macro-usage)

namespace ddwaf {

// This enum is 32 bit for compatibility with DDWAF_LOG_LEVEL
// NOLINTNEXTLINE(performance-enum-size)
enum class log_level : uint32_t { trace, debug, info, warn, error, off };

inline std::string_view log_level_to_str(log_level level)
{
    switch (level) {
    case log_level::trace:
        return "trace";
    case log_level::debug:
        return "debug";
    case log_level::error:
        return "error";
    case log_level::warn:
        return "warn";
    case log_level::info:
        return "info";
    case log_level::off:
        break;
    }

    return "off";
}

class logger {
public:
    using log_cb_type = void (*)(log_level level, const char *function, const char *file,
        unsigned line, const char *message, uint64_t message_len);

    static void init(log_cb_type cb, log_level min_level);
    static bool valid(log_level level) { return cb != nullptr && level >= min_level; }
    static void log(log_level level, const char *function, const char *file, unsigned line,
        const char *message, size_t length);

private:
    static log_cb_type cb;
    static log_level min_level;
};

} // namespace ddwaf
