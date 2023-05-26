// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "common/utils.hpp"
#include "ddwaf.h"

int main(int argc, char *argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <json/yaml file> [<json/yaml file>] <json input>\n";
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

    auto input = YAML::Load(argv[argc - 1]).as<ddwaf_object>();
    unsigned num_configs = argc - 2;
    for (unsigned i = 0; i < num_configs; ++i) {
        const char *config = argv[i + 1];
        if (i > 0) {
            std::string update_str = read_file(config);
            auto update = YAML::Load(update_str).as<ddwaf_object>();

            ddwaf_handle updated_handle = ddwaf_update(handle, &update, nullptr);
            ddwaf_object_free(&update);

            if (updated_handle == nullptr) {
                std::cout << "Failed to load " << config << '\n';
                return EXIT_FAILURE;
            }

            ddwaf_destroy(handle);
            handle = updated_handle;
        }

        std::cout << "Run with " << config << " :\n";

        ddwaf_context context = ddwaf_context_init(handle);
        if (context == nullptr) {
            ddwaf_destroy(handle);
            return EXIT_FAILURE;
        }

        ddwaf_result ret;
        auto code = ddwaf_run(context, &input, &ret, std::numeric_limits<uint32_t>::max());
        if (code == DDWAF_MATCH && ddwaf_object_size(&ret.events) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(ret.events);

            std::cout << ss.str() << '\n';
        } else {
            std::cout << "Nothing found\n";
        }
        std::cout << std::endl;

        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
    }

    ddwaf_object_free(&input);
    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
