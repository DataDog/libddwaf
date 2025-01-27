// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"

using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "integration/diagnostics/v1/";

void run_test(ddwaf_handle handle)
{
    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object param, arg2, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map(&arg2);

    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "string 1"));
    ddwaf_object_map_add(&arg2, "x", ddwaf_object_string(&tmp, "string 2"));
    ddwaf_object_map_add(&arg2, "y", ddwaf_object_string(&tmp, "string 3"));
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_result ret;

    // Run with just arg1
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_MATCH);
    EXPECT_FALSE(ret.timeout);
    EXPECT_EVENTS(ret, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = ".*",
                                           .highlight = "string 1",
                                           .args = {{
                                               .value = "string 1",
                                               .address = "arg1",
                                               .path = {},
                                           }}},
                               {.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 2",
                                   .args = {{
                                       .value = "string 2",
                                       .address = "arg2",
                                       .path = {"x"},
                                   }}},
                               {.op = "match_regex",
                                   .op_value = ".*",
                                   .highlight = "string 3",
                                   .args = {{
                                       .value = "string 3",
                                       .address = "arg2",
                                       .path = {"y"},
                                   }}}}});
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
}

TEST(TestDiagnosticsV1Integration, Basic)
{
    auto rule = yaml_to_object(
        R"({version: '1.1', events: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operation: match_regex, parameters: {inputs: [arg1], regex: .*}}, {operation: match_regex, parameters: {inputs: [arg2:x], regex: .*}},{operation: match_regex, parameters: {inputs: [arg2:y], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 0);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 0);

    ddwaf_object_free(&diagnostics);

    run_test(handle);

    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV1Integration, TestInvalidRule)
{
    auto rule = read_file("invalid_single_v1.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV1Integration, TestMultipleSameInvalidRules)
{
    auto rule = read_file("invalid_multiple_same_v1.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("missing key 'type'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 2);
    EXPECT_NE(error_rules.find("1"), error_rules.end());
    EXPECT_NE(error_rules.find("2"), error_rules.end());

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV1Integration, TestMultipleDiffInvalidRules)
{
    auto rule = read_file("invalid_multiple_diff_v1.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 2);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 2);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
    }

    {
        auto it = errors.find("unknown matcher: squash");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("2"), error_rules.end());
    }

    ddwaf_object_free(&diagnostics);
}

TEST(TestDiagnosticsV1Integration, TestMultipleMixInvalidRules)
{
    auto rule = read_file("invalid_multiple_mix_v1.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 4);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 3);

    {
        auto it = errors.find("missing key 'type'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 2);
        EXPECT_NE(error_rules.find("1"), error_rules.end());
        EXPECT_NE(error_rules.find("3"), error_rules.end());
    }

    {
        auto it = errors.find("unknown matcher: squash");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("2"), error_rules.end());
    }

    {
        auto it = errors.find("missing key 'inputs'");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("4"), error_rules.end());
    }

    ddwaf_object_free(&diagnostics);
    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV1Integration, TestInvalidDuplicate)
{
    auto rule = read_file("invalid_duplicate_v1.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 1);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("duplicate rule");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);
    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV1Integration, TestInvalidTooManyTransformers)
{
    auto rule = read_file("invalid_too_many_transformers_v1.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto loaded = ddwaf::at<parameter::vector>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<parameter::vector>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);

    auto errors = ddwaf::at<parameter::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("number of transformers beyond allowed limit");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::parameter::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_free(&diagnostics);
    ddwaf_destroy(handle);
}

TEST(TestDiagnosticsV1Integration, InvalidRulesContainer)
{
    auto rule = yaml_to_object(R"({version: '1.1', events: {}})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf::parameter root(diagnostics);
    auto root_map = static_cast<ddwaf::parameter::map>(root);

    auto version = ddwaf::at<std::string>(root_map, "ruleset_version", "");
    EXPECT_STREQ(version.c_str(), "");

    auto rules = ddwaf::at<parameter::map>(root_map, "rules");

    auto errors = ddwaf::at<std::string>(rules, "error");
    EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

    ddwaf_object_free(&diagnostics);
}

} // namespace
