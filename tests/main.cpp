// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context_allocator.hpp"
#include "log.hpp"

#include "common/gtest_utils.hpp"

#include <string_view>

using namespace std::literals;

const char *level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level) {
    case DDWAF_LOG_TRACE:
        return "trace";
    case DDWAF_LOG_DEBUG:
        return "debug";
    case DDWAF_LOG_ERROR:
        return "error";
    case DDWAF_LOG_WARN:
        return "warn";
    case DDWAF_LOG_INFO:
        return "info";
    case DDWAF_LOG_OFF:
        break;
    }

    return "off";
}

DDWAF_LOG_LEVEL str_to_level(std::string_view str)
{
    if (str == "trace"sv || str == "TRACE"sv) {
        return DDWAF_LOG_TRACE;
    }

    if (str == "debug"sv || str == "DEBUG"sv) {
        return DDWAF_LOG_DEBUG;
    }

    if (str == "error"sv || str == "ERROR"sv) {
        return DDWAF_LOG_ERROR;
    }

    if (str == "warn"sv || str == "WARN"sv) {
        return DDWAF_LOG_WARN;
    }

    if (str == "info"sv || str == "INFO"sv) {
        return DDWAF_LOG_INFO;
    }

    return DDWAF_LOG_OFF;
}

void log_cb(DDWAF_LOG_LEVEL level, const char *function, const char *file, unsigned line,
    const char *message, [[maybe_unused]] uint64_t len)
{
    ddwaf::fmt::print("[{}][{}:{}:{}]: {}\n", level_to_str(level), file, function, line, message);
}

// NOLINTNEXTLINE(modernize-avoid-c-arrays)
DDWAF_LOG_LEVEL find_log_level(int argc, char *argv[])
{
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    auto *env_level = getenv("DDWAF_TEST_LOG_LEVEL");
    if (env_level != nullptr) {
        return str_to_level(env_level);
    }

    DDWAF_LOG_LEVEL level = DDWAF_LOG_TRACE;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--log_level" || arg == "--log-level") {
            if (i + 1 < argc) {
                level = str_to_level(argv[i + 1]);
            }
            break;
        }
    }
    return level;
}
int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, find_log_level(argc, argv));
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
