// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/rules/rules_compat";

TEST(TestRulesCompatIntegration, VerifyBothBaseAndCompat)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 2, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value2"), alloc), STRL("rule2"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        EXPECT_EVENTS(result,
            {.id = "rule1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                .matches = {{.op = "match_regex",
                    .op_value = "^rule1",
                    .highlight = "rule1"sv,
                    .args = {{.value = "rule1"sv, .address = "value1"}}}}},
            {.id = "rule2",
                .name = "rule2",
                .tags = {{"type", "flow2"}, {"category", "category2"}},
                .matches = {{.op = "match_regex",
                    .op_value = "^rule2",
                    .highlight = "rule2"sv,
                    .args = {{.value = "rule2"sv, .address = "value2"}}}}});

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *tag = ddwaf_object_find(attributes, STRL("result.rule2"));
        EXPECT_NE(tag, nullptr);
        EXPECT_TRUE((ddwaf_object_get_type(tag) & DDWAF_OBJ_STRING) != 0);

        std::size_t length;
        const auto *str = ddwaf_object_get_string(tag, &length);

        std::string_view value{str, length};
        EXPECT_EQ(value, "something"sv);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, alloc);
    }
    ddwaf_context_destroy(context);
}

TEST(TestRulesCompatIntegration, DuplicateRules)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("duplicate_rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics{};

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    EXPECT_TRUE(ValidateDiagnosticsSchema(diagnostics));

    ddwaf::raw_configuration root(reinterpret_cast<const ddwaf::detail::object &>(diagnostics));
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    {
        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules_compat");

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 0);

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 1);
        EXPECT_NE(failed.find("rule1"), failed.end());

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 1);

        auto it = errors.find("duplicate rule");
        EXPECT_NE(it, errors.end());

        auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
        EXPECT_EQ(error_rules.size(), 1);
        EXPECT_NE(error_rules.find("rule1"), error_rules.end());
    }

    {
        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

        auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
        EXPECT_EQ(loaded.size(), 1);
        EXPECT_NE(loaded.find("rule1"), loaded.end());

        auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
        EXPECT_EQ(failed.size(), 0);

        auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
        EXPECT_EQ(errors.size(), 0);
    }

    ddwaf_object_destroy(&diagnostics, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 2, alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"));
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(&parameter, STRL("value2"), alloc), STRL("rule2"));

        ddwaf_object result;
        EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_MATCH);

        EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);

        EXPECT_EVENTS(
            result, {.id = "rule1",
                        .name = "rule1",
                        .tags = {{"type", "flow1"}, {"category", "category1"}, {"confidence", "1"}},
                        .matches = {{.op = "match_regex",
                            .op_value = "^rule1",
                            .highlight = "rule1"sv,
                            .args = {{.value = "rule1"sv, .address = "value1"}}}}});

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        EXPECT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        EXPECT_NE(keep, nullptr);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, alloc);
    }
    ddwaf_context_destroy(context);
}

TEST(TestRulesCompatIntegration, InvalidConfigType)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', metadata: {rules_version: '1.2.7'}, rules_compat: {}})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics{};
    ddwaf_builder_add_or_update_config(builder, LSTRARG("rules_compat"), &rule, &diagnostics);
    ddwaf_object_destroy(&rule, alloc);

    EXPECT_TRUE(ValidateDiagnosticsSchema(diagnostics));

    {
        ddwaf::raw_configuration root(reinterpret_cast<const ddwaf::detail::object &>(diagnostics));
        auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

        auto version = ddwaf::at<std::string>(root_map, "ruleset_version");
        EXPECT_STREQ(version.c_str(), "1.2.7");

        auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules_compat");

        auto errors = ddwaf::at<std::string>(rules, "error");
        EXPECT_STR(errors, "bad cast, expected 'array', obtained 'map'");

        ddwaf_object_destroy(&diagnostics, alloc);
    }

    ddwaf_builder_destroy(builder);
}

} // namespace
