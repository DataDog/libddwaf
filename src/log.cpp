// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "log.hpp"
#include <cstdarg>
#include <cstdio>

namespace ddwaf
{

ddwaf_log_cb logger::cb           = nullptr;
DDWAF_LOG_LEVEL logger::min_level = DDWAF_LOG_OFF;

void logger::init(ddwaf_log_cb cb, DDWAF_LOG_LEVEL min_level)
{
    logger::cb        = cb;
    logger::min_level = min_level;
}

void logger::log(DDWAF_LOG_LEVEL level,
                 const char* function, const char* file, unsigned line,
                 const char* message, size_t length)
{
    logger::cb(level, function, file, line, message, length);
}

}
