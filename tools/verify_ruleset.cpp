// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/utils.hpp"
#include "ddwaf.h"
#include "log.hpp"

#define LONG_TIME 1000000

int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);

    if (argc < 2) {
        DDWAF_ERROR("Usage: {} <json/yaml file>", argv[0]);
        return EXIT_FAILURE;
    }

    std::string rule_str = read_file(argv[1]);
    auto rule = json_to_object(rule_str);

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ddwaf_object_free(&rule);

    if (handle == nullptr) {
        DDWAF_ERROR("Failed to load ruleset");
        return EXIT_FAILURE;
    }

    DDWAF_INFO("Ruleset loaded successfully");

    DDWAF_INFO("Diagnostics:\n{}", object_to_json(diagnostics).c_str());
    ddwaf_object_free(&diagnostics);

    uint32_t required_size;
    const char *const *required = ddwaf_known_addresses(handle, &required_size);
    DDWAF_INFO("Required addresses: {}", required_size);
    for (uint32_t i = 0; i < required_size; i++) { DDWAF_INFO("    - {}", required[i]); }
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
