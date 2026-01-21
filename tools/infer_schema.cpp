// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "common/utils.hpp"
#include "ddwaf.h"

#include <limits>


int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <json/yaml file> <json input>\n";
        return EXIT_FAILURE;
    }

    auto *alloc = ddwaf_get_default_allocator();

    std::string rule_str = read_file(argv[1]);
    auto rule = YAML::Load(rule_str).as<ddwaf_object>();

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    if (handle == nullptr) {
        std::cout << "Failed to load " << argv[1] << '\n';
        return EXIT_FAILURE;
    }

    std::string body_str = read_file(argv[2]);
    auto body = json_to_object(body_str);

    ddwaf_object settings;
    ddwaf_object input;

    ddwaf_object_set_map(&input, 2, alloc);
    ddwaf_object_set_map(&settings, 1, alloc);

    ddwaf_object *extract_schema = ddwaf_object_insert_literal_key(&settings, STRL("extract-schema"), alloc);
    ddwaf_object_set_bool(extract_schema, true);

    ddwaf_object *processor = ddwaf_object_insert_literal_key(&input, STRL("waf.context.processor"), alloc);
    *processor = settings;

    ddwaf_object *request_body = ddwaf_object_insert_literal_key(&input, STRL("server.request.body"), alloc);
    *request_body = body;

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    if (context == nullptr) {
        ddwaf_object_destroy(&input, alloc);
        ddwaf_destroy(handle);
        return EXIT_FAILURE;
    }

    ddwaf_object result;
    auto code = ddwaf_context_eval(context, &input, alloc, &result, std::numeric_limits<uint64_t>::max());
    if (code == DDWAF_MATCH) {
        const ddwaf_object *attributes = ddwaf_object_find(&result, STRL("attributes"));
        if (attributes != nullptr && ddwaf_object_get_size(attributes) > 0) {
            std::cout << object_to_json(*attributes) << '\n';
        }
    }

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
