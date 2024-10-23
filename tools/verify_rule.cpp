// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/utils.hpp"
#include "ddwaf.h"
#include "semver.hpp"
#include "version.hpp"

#define LONG_TIME 1000000

ddwaf_object convertRuleToRuleset(const YAML::Node &rulePayload)
{
    auto rule = rulePayload.as<ddwaf_object>();
    ddwaf_object root;
    ddwaf_object version;
    ddwaf_object array;

    ddwaf_object_map(&root);
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, &rule);

    ddwaf_object_map_add(&root, "version", ddwaf_object_string(&version, "2.1"));
    ddwaf_object_map_add(&root, "rules", &array);
    return root;
}

bool runVectors(YAML::Node rule, ddwaf_handle handle, bool runPositiveMatches)
{
    bool success = true;
    auto ruleID = rule["id"].as<std::string>();
    YAML::Node matches = rule["test_vectors"][runPositiveMatches ? "matches" : "no_matches"];
    if (matches) {
        size_t counter = 0;
        for (YAML::const_iterator vector = matches.begin(); vector != matches.end();
             ++vector, ++counter) {
            auto root = vector->as<ddwaf_object>();
            if (root.type != DDWAF_OBJ_INVALID) {
                ddwaf_context ctx = ddwaf_context_init(handle);
                DDWAF_RET_CODE ret = ddwaf_run(ctx, &root, nullptr, nullptr, LONG_TIME);

                bool hadError = ret < DDWAF_OK;
                bool hadMatch = !hadError && ret != DDWAF_OK;

                if (hadError) {
                    printf(
                        "The WAF encountered an error processing rule %s and %s test vector #%zu\n",
                        rule["id"].as<std::string>().data(),
                        runPositiveMatches ? "positive" : "negative", counter);
                    success = false;
                } else if (runPositiveMatches && !hadMatch) {
                    printf("Rule %s didn't match positive test vector #%zu\n",
                        rule["id"].as<std::string>().data(), counter);
                    success = false;
                } else if (!runPositiveMatches && hadMatch) {
                    printf("Rule %s matched negative test vector #%zu\n",
                        rule["id"].as<std::string>().data(), counter);
                    success = false;
                }

                ddwaf_context_destroy(ctx);
            }
        }
    }
    return success;
}

int main(int argc, char *argv[])
{
#ifdef VERBOSE
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_TRACE);
#endif

    if (argc < 2) {
        printf("Usage: %s <json/yaml file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    bool success = true;
    for (int fileIndex = 1; fileIndex < argc; ++fileIndex) {
#ifdef VERBOSE
        printf("Processing %s\n", argv[fileIndex]);
#endif
        YAML::Node rule = YAML::Load(read_file(argv[fileIndex]));
        rule["enabled"] = true;

        ddwaf_object convertedRule = convertRuleToRuleset(rule);
        ddwaf_handle handle = ddwaf_init(&convertedRule, nullptr, nullptr);
        ddwaf_object_free(&convertedRule);

        if (handle == nullptr) {
            // Verify if the rule should've loaded successfully or not
            auto max_version = ddwaf::semantic_version::max();
            auto min_version = ddwaf::semantic_version::min();

            if (rule["max_version"].IsDefined()) {
                max_version = ddwaf::semantic_version{rule["max_version"].as<std::string>()};
            }

            if (rule["min_version"].IsDefined()) {
                min_version = ddwaf::semantic_version{rule["min_version"].as<std::string>()};
            }
            if (ddwaf::current_version < min_version || ddwaf::current_version > max_version) {
                // This rule is expected to fail to load
                continue;
            }

            printf("Failed to load rule %s\n", argv[fileIndex]);
            success = false;
            continue;
        }

        if (rule["test_vectors"]) {
            // Run positive test vectors (patterns the rule should match)
            success &= runVectors(rule, handle, true);

            // Run negative test vectors (patterns the rule shouldn't match)
            success &= runVectors(rule, handle, false);
        }

        ddwaf_destroy(handle);
    }

    if (success) {
        printf("Validated a total of %d rules\n", argc - 1);
    }

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
