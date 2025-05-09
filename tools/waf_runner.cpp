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

#include "common/utils.hpp"
#include "ddwaf.h"

// NOLINTNEXTLINE
auto parse_args(int argc, char *argv[])
{
    const std::map<std::string, std::string, std::less<>> arg_mapping{
        {"-r", "--ruleset"}, {"-i", "--input"}, {"--ruleset", "--ruleset"},
        {"--input", "--input"}, {"-v", "--verbose"}, {"--verbose", "--verbose"}};

    std::unordered_map<std::string, std::vector<std::string>> args;
    auto last_arg = args.end();
    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg.starts_with('-')) {
            if (auto long_arg = arg_mapping.find(arg); long_arg != arg_mapping.end()) {
                arg = long_arg->second;
            } else {
                continue; // Unknown option
            }

            auto [it, res] = args.emplace(arg, std::vector<std::string>{});
            last_arg = it;
        } else if (last_arg != args.end()) {
            last_arg->second.emplace_back(arg);
        }
    }
    return args;
}
const char *key_regex = R"((?i)pass|pw(?:or)?d|secret|(?:api|private|public|access)[_-]?key|token|consumer[_-]?(?:id|key|secret)|sign(?:ed|ature)|bearer|authorization|jsessionid|phpsessid|asp\.net[_-]sessionid|sid|jwt)";

const char *value_regex = R"((?i)(?:p(?:ass)?w(?:or)?d|pass(?:[_-]?phrase)?|secret(?:[_-]?key)?|(?:(?:api|private|public|access)[_-]?)key(?:[_-]?id)?|(?:(?:auth|access|id|refresh)[_-]?)?token|consumer[_-]?(?:id|key|secret)|sign(?:ed|ature)?|auth(?:entication|orization)?|jsessionid|phpsessid|asp\.net(?:[_-]|-)sessionid|sid|jwt)(?:\s*=[^;]|"\s*:\s*"[^"]+")|bearer\s+[a-z0-9\._\-]+|token:[a-z0-9]{13}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L][\w=-]+\.ey[I-L][\w=-]+(?:\.[\w.+\/=-]+)?|[\-]{5}BEGIN[a-z\s]+PRIVATE\sKEY[\-]{5}[^\-]+[\-]{5}END[a-z\s]+PRIVATE\sKEY|ssh-rsa\s*[a-z0-9\/\.+]{100,})";

int main(int argc, char *argv[])
{
    auto args = parse_args(argc, argv);

    if (args.contains("--verbose")) {
        ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);
    } else {
        ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);
    }

    const std::vector<std::string> rulesets = args["--ruleset"];
    const std::vector<std::string> inputs = args["--input"];
    if (rulesets.empty() || inputs.empty()) {
        std::cout << "Usage: " << argv[0] << " --ruleset <json/yaml file>"
                  << " --input <json input> [<json input>..]\n";
        return EXIT_FAILURE;
    }

    const ddwaf_config config{{.key_regex=key_regex, .value_regex=value_regex}, ddwaf_object_free};
    ddwaf_builder builder = ddwaf_builder_init(&config);

    std::size_t index = 0;
    for (const auto & config : rulesets) {
        auto rule = YAML::Load(read_file(config)).as<ddwaf_object>();
        auto path = "config/" + std::to_string(index++);

        if (!ddwaf_builder_add_or_update_config(builder, path.data(), path.size(), &rule, nullptr)) {
            std::cout << "Failed to add configuration: " << config << '\n';
        }

        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle = ddwaf_builder_build_instance(builder);
    ddwaf_builder_destroy(builder);
    if (handle == nullptr) {
        std::cout << "Failed to instantiate handle\n";
        return EXIT_FAILURE;
    }

    ddwaf_context context = ddwaf_context_init(handle);
    if (context == nullptr) {
        ddwaf_destroy(handle);
        std::cout << "Failed to initialise context\n";
        return EXIT_FAILURE;
    }

    for (const auto &json_str : inputs) {

        std::cout << "---- Run with " << json_str << '\n';
        auto input = YAML::Load(json_str);

        ddwaf_object persistent;
        ddwaf_object ephemeral;

        auto persistent_input = input["persistent"];
        auto ephemeral_input = input["ephemeral"];
        if (!persistent_input.IsDefined() && !ephemeral_input.IsDefined()) {
            persistent = input.as<ddwaf_object>();
            ddwaf_object_map(&ephemeral);
        } else {
            if (input["persistent"].IsDefined()) {
                persistent = input["persistent"].as<ddwaf_object>();
            } else {
                ddwaf_object_map(&persistent);
            }

            if (input["ephemeral"].IsDefined()) {
                ephemeral = input["ephemeral"].as<ddwaf_object>();
            } else {
                ddwaf_object_map(&ephemeral);
            }
        }

        ddwaf_object ret;
        auto code =
            ddwaf_run(context, &persistent, &ephemeral, &ret, std::numeric_limits<uint64_t>::max());

        const auto *events = ddwaf_object_find(&ret, "events", sizeof("events") - 1);
        if (code == DDWAF_MATCH && ddwaf_object_size(events) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(*events);

            std::cout << "Events:\n" << ss.str() << "\n\n";
        }

        const auto *actions = ddwaf_object_find(&ret, "actions", sizeof("actions") - 1);
        if (code == DDWAF_MATCH && ddwaf_object_size(actions) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(*actions);

            std::cout << "Actions:\n" << ss.str() << "\n\n";
        }

        const auto *attributes = ddwaf_object_find(&ret, "attributes", sizeof("attributes") - 1);
        if (ddwaf_object_size(attributes) > 0) {
            std::stringstream ss;
            YAML::Emitter out(ss);
            out.SetIndent(2);
            out.SetMapFormat(YAML::Block);
            out.SetSeqFormat(YAML::Block);
            out << object_to_yaml(*attributes);

            std::cout << "Attributes:\n" << ss.str() << "\n\n";
        }

        const auto *duration = ddwaf_object_find(&ret, "duration", sizeof("duration") - 1);
        std::cout << "Total time: " << ddwaf_object_get_unsigned(duration) << '\n';
        ddwaf_object_free(&ret);
    }

    ddwaf_context_destroy(context);


    ddwaf_destroy(handle);

    return EXIT_SUCCESS;
}
