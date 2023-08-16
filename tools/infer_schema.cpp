// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "common/utils.hpp"
#include "generator/extract_schema.hpp"
#include "ddwaf.h"

#include <algorithm>
#include <stdexcept>
#include <type_traits>
#include <unordered_set>
#include <variant>


int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <json/yaml file> <json input>\n";
        return EXIT_FAILURE;
    }

    std::string rule_str = read_file(argv[1]);
    auto rule = YAML::Load(rule_str).as<ddwaf_object>();

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};
    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        std::cout << "Failed to load " << argv[1] << '\n';
        return EXIT_FAILURE;
    }

    std::string body_str = read_file(argv[2]);
    auto body = json_to_object(body_str);

    ddwaf_object tmp;
    ddwaf_object settings;
    ddwaf_object input;

    ddwaf_object_map(&input);
    ddwaf_object_map(&settings);
    ddwaf_object_map_add(&settings, "extract-schema", ddwaf_object_string(&tmp, "true"));
    ddwaf_object_map_add(&input, "waf.context.settings", &settings);
    ddwaf_object_map_add(&input, "server.request.body", &body);

    ddwaf_context context = ddwaf_context_init(handle);
    if (context == nullptr) {
        ddwaf_destroy(handle);
        return EXIT_FAILURE;
    }

    ddwaf_result ret;
    ddwaf_run(context, &input, &ret, std::numeric_limits<uint32_t>::max());
    if (ddwaf_object_size(&ret.derivatives) > 0) {
        std::cout << object_to_json(ret.derivatives) << '\n';
    }

    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);

    ddwaf_object_free(&input);
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
