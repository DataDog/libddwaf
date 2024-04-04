// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <yaml-cpp/emitter.h>
#include <yaml-cpp/emittermanip.h>
#include <yaml-cpp/node/parse.h>
#include <readline/readline.h>
#include <readline/history.h>

#include "common/utils.hpp"
#include "ddwaf.h"

// NOLINTNEXTLINE
auto parse_args(int argc, char *argv[])
{
    const std::map<std::string, std::string, std::less<>> arg_mapping{
        {"-r", "--ruleset"}, {"--ruleset", "--ruleset"}};

    std::unordered_map<std::string, std::string> args;
    auto last_arg = args.end();
    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg.starts_with('-')) {
            if (auto long_arg = arg_mapping.find(arg); long_arg != arg_mapping.end()) {
                arg = long_arg->second;
            } else {
                continue; // Unknown option
            }

            auto [it, res] = args.emplace(arg, std::string{});
            last_arg = it;
        } else if (last_arg != args.end()) {
            last_arg->second = arg;
        }
    }
    return args;
}

int main(int argc, char *argv[])
{
    auto args = parse_args(argc, argv);

    std::string ruleset = args["--ruleset"];
    if (ruleset.empty()) {
        std::cout << "Usage: " << argv[0] << " --ruleset <json/yaml file> [<json/yaml file>..]\n";
        return EXIT_FAILURE;
    }

    auto rule = YAML::Load(read_file(ruleset)).as<ddwaf_object>();
    const ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, ddwaf_object_free};
    auto handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        std::cout << "Failed to load " << ruleset << '\n';
        return EXIT_FAILURE;
    }

    while (true) {
        char *inpt = readline("Input: ");
        add_history(inpt);
        std::string json_str = inpt;


        ddwaf_context context = ddwaf_context_init(handle);
        if (context == nullptr) {
            ddwaf_destroy(handle);
            std::cout << "Failed to initialise context\n";
            return EXIT_FAILURE;
        }

        auto input = YAML::Load(json_str).as<ddwaf_object>();

        ddwaf_result ret;
        auto code =
            ddwaf_run(context, &input, nullptr, &ret, std::numeric_limits<uint32_t>::max());

        if (code == DDWAF_MATCH) {
            std::cout << "Evaluating " << json_str << " --> Match!\n";
        } else if (code == DDWAF_OK) {
            std::cout << "Evaluating " << json_str << " --> No match!\n";
        } else {
            std::cout << "Evaluating " << json_str << " --> Error!\n";
        }

        if (code == DDWAF_MATCH && ddwaf_object_size(&ret.events) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(ret.events);

            std::cout << "Events:\n" << ss.str() << "\n\n";
        }

        if (code == DDWAF_MATCH && ddwaf_object_size(&ret.actions) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(ret.actions);

            std::cout << "Actions:\n" << ss.str() << "\n\n";
        }

        if (ddwaf_object_size(&ret.derivatives) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(ret.derivatives);

            std::cout << "Derivatives:\n" << ss.str() << "\n\n";
        }

        ddwaf_result_free(&ret);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
