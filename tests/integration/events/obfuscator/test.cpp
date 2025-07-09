// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "obfuscator.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

constexpr std::string_view base_dir = "integration/events/obfuscator/";

TEST(TestObfuscatorIntegration, TestConfigKeyValue)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{"password", "rule1_obf"}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Both
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscatorIntegration, TestConfigKey)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{"password", nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1_obf"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscatorIntegration, TestConfigValue)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, "rule1_obf"}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscatorIntegration, TestConfigHighlight)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{.key_regex = nullptr, .value_regex = "^badvalue"}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // Highlight obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value"), alloc),
            STRL("badvalue_something"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "security_scanner"}, {"category", "category2"}},
                               .matches = {{.op = "phrase_match",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // No obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&parameter, STRL("value"), alloc),
            STRL("othervalue_badvalue"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "security_scanner"}, {"category", "category2"}},
                               .matches = {{.op = "phrase_match",
                                   .highlight = "othervalue"sv,
                                   .args = {{
                                       .value = "othervalue_badvalue"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscatorIntegration, TestConfigEmpty)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, ""}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1_obf"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscatorIntegration, TestInvalidConfigKey)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{"[", nullptr}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "<Redacted>"sv,
                                   .args = {{
                                       .value = "<Redacted>"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1_obf"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestObfuscatorIntegration, TestInvalidConfigValue)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("obfuscator.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{nullptr, "]"}};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ddwaf_object_destroy(&rule, alloc);
    ASSERT_NE(handle, nullptr);

    // No Obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Key-based obfuscation (?)
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);

        auto *inter = ddwaf_object_insert_key(&parameter, STRL("value"), alloc);
        ddwaf_object_set_map(inter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(inter, STRL("passwordle"), alloc), STRL("rule1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1"sv,
                                       .address = "value",
                                       .path = {"passwordle"},
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    // Value-based obfuscation
    {
        ddwaf_context context = ddwaf_context_init(handle, alloc);

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&parameter, STRL("value"), alloc), STRL("rule1_obf"), alloc);

        ddwaf_object out;
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, nullptr, true, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "security_scanner"}, {"category", "category1"}},
                               .matches = {{.op = "match_regex",
                                   .op_value = "rule1",
                                   .highlight = "rule1"sv,
                                   .args = {{
                                       .value = "rule1_obf"sv,
                                       .address = "value",
                                   }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

} // namespace
