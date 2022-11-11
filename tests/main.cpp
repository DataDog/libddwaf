// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "log.hpp"
#include "test.h"

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

void log_cb(DDWAF_LOG_LEVEL level, const char *function, const char *file, unsigned line,
    const char *message, [[maybe_unused]] uint64_t len)
{
    printf("[%s][%s:%s:%u]: %s\n", level_to_str(level), file, function, line, message);
}

int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_WARN);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
