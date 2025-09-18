// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/raw_configuration.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestRegexMatchWithChecksumIntegration, LuhnChecksumMatch)
{
    auto *alloc = ddwaf_get_default_allocator();

    // Initialize a WAF rule
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex_with_checksum, parameters: {inputs: [{address: arg1}], regex: '\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b', options: {min_length: 16}, checksum: luhn}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object param;
        ddwaf_object_set_map(&param, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&param, STRL("arg1"), alloc),
            STRL("4000-0000-0000-1000"), alloc);

        ddwaf_object ret;

        auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_MATCH);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        EXPECT_EVENTS(ret,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "flow1"}, {"category", "category1"}},
                .matches = {{.op = "match_regex_with_checksum",
                    .op_value =
                        R"(\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b)",
                    .highlight = "4000-0000-0000-1000"sv,
                    .args = {{
                        .value = "4000-0000-0000-1000"sv,
                        .address = "arg1",
                    }}}}});
        ddwaf_object_destroy(&ret, alloc);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object param;
        ddwaf_object_set_map(&param, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&param, STRL("arg1"), alloc),
            STRL("4000-0000-0000-0000"), alloc);

        ddwaf_object ret;

        auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
        EXPECT_EQ(code, DDWAF_OK);
        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));
        ddwaf_object_destroy(&ret, alloc);

        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRegexMatchWithChecksumIntegration, MinLengthBeyondInput)
{
    // Initialize a WAF rule
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex_with_checksum, parameters: {inputs: [{address: arg1}], regex: '\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b', options: {min_length: 20}, checksum: luhn}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param, STRL("arg1"), alloc), STRL("4000-0000-0000-1000"), alloc);

    ddwaf_object ret;

    auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
    EXPECT_EQ(code, DDWAF_OK);
    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    ddwaf_object_destroy(&ret, alloc);

    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);
}

TEST(TestRegexMatchWithChecksumIntegration, InvalidChecksum)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex_with_checksum, parameters: {inputs: [{address: arg1}], regex: '\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b', options: {}, checksum: none}}]}]})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    EXPECT_TRUE(ValidateDiagnosticsSchema(diagnostics));

    ddwaf::raw_configuration root(reinterpret_cast<const ddwaf::detail::object &>(diagnostics));
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);
    EXPECT_NE(failed.find("1"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("unknown checksum algorithm: 'none'");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_destroy(&diagnostics, alloc);
}

TEST(TestRegexMatchWithChecksumIntegration, InvalidMinLength)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = yaml_to_object<ddwaf_object>(
        R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex_with_checksum, parameters: {inputs: [{address: arg1}], regex: '\b4\d{3}(?:(?:,\d{4}){3}|(?:\s\d{4}){3}|(?:\.\d{4}){3}|(?:-\d{4}){3})\b', options: {min_length: -1}, checksum: luhn}}]}]})");
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, &diagnostics);
    ASSERT_EQ(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    EXPECT_TRUE(ValidateDiagnosticsSchema(diagnostics));

    ddwaf::raw_configuration root(reinterpret_cast<const ddwaf::detail::object &>(diagnostics));
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);

    auto rules = ddwaf::at<raw_configuration::map>(root_map, "rules");

    auto loaded = ddwaf::at<raw_configuration::string_set>(rules, "loaded");
    EXPECT_EQ(loaded.size(), 0);

    auto failed = ddwaf::at<raw_configuration::string_set>(rules, "failed");
    EXPECT_EQ(failed.size(), 1);
    EXPECT_NE(failed.find("1"), failed.end());

    auto errors = ddwaf::at<raw_configuration::map>(rules, "errors");
    EXPECT_EQ(errors.size(), 1);

    auto it = errors.find("min_length is a negative number");
    EXPECT_NE(it, errors.end());

    auto error_rules = static_cast<ddwaf::raw_configuration::string_set>(it->second);
    EXPECT_EQ(error_rules.size(), 1);
    EXPECT_NE(error_rules.find("1"), error_rules.end());

    ddwaf_object_destroy(&diagnostics, alloc);
}
} // namespace
