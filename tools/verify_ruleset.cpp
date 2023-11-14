// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdlib>
#include <exception>
#include <iostream>
#include <string>
#include <yaml-cpp/node/parse.h>

#include "common/utils.hpp"
#include "ddwaf.h"

int main(int argc, char *argv[])
{
    int retval = EXIT_SUCCESS;

    try {
        ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);

        if (argc < 2) {
            std::cout << "Usage: " << argv[0] << " <json/yaml file>\n";
            return EXIT_FAILURE;
        }

        auto rule = YAML::Load(read_file(argv[1])).as<ddwaf_object>();

        ddwaf_object diagnostics;
        ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
        ddwaf_object_free(&rule);

        auto root = object_to_yaml(diagnostics);
        ddwaf_object_free(&diagnostics);

        ddwaf_destroy(handle);

        for (const auto node : root) {
            if (node.second.IsScalar()) {
                continue;
            }

            auto key = node.first.as<std::string>();

            auto error = node.second["error"];
            if (error.IsDefined()) {
                std::cout << key << " : " << error.as<std::string>() << '\n';
                retval = EXIT_FAILURE;
                continue;
            }

            auto errors = node.second["errors"];
            if (!errors.IsDefined() || errors.size() == 0) {
                continue;
            }

            for (const auto error_instance : errors) {
                auto err_msg = error_instance.first.as<std::string>();
                for (const auto feature_key_node : error_instance.second) {
                    auto feature_key = feature_key_node.as<std::string>();
                    std::cout << key << " : " << feature_key << " : " << err_msg << '\n';
                }
            }
            retval = EXIT_FAILURE;
        }
    } catch (const std::exception &e) {
        std::cout << "Unexpected exception: " << e.what() << '\n';
        retval = EXIT_FAILURE;
    }

    return retval;
}
