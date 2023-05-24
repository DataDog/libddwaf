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
        DDWAF_ERROR("Usage: %s <json/yaml file>", argv[0]);
        return EXIT_FAILURE;
    }

    std::string rule_str = read_file(argv[1]);
    YAML::Node doc = YAML::Load(rule_str);

    auto rule = doc.as<ddwaf_object>();
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);

    if (handle == nullptr) {
        DDWAF_ERROR("Failed to load ruleset");
        return EXIT_FAILURE;
    }

    DDWAF_INFO("Ruleset loaded successfully");

    uint32_t required_size;
    const char *const *required = ddwaf_required_addresses(handle, &required_size);
    DDWAF_INFO("Required addresses: %u", required_size);
    for (uint32_t i = 0; i < required_size; i++) { DDWAF_INFO("    - %s", required[i]); }
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
