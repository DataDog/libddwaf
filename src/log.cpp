// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdio>

#include "log.hpp"

namespace ddwaf {

logger::log_cb_type logger::cb = nullptr;
log_level logger::min_level = log_level::off;

void logger::init(log_cb_type cb, log_level min_level)
{
    logger::cb = cb;
    logger::min_level = min_level;
}

void logger::log(log_level level, const char *function, const char *file, unsigned line,
    const char *message, size_t length)
{
    logger::cb(level, function, file, line, message, length);
}

} // namespace ddwaf
