// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

constexpr std::string_view base_dir = "integration/exclusion/rule_filter/";

TEST(TestRuleFilterIntegration, ExcludeSingleRule)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_one_rule.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByType)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_by_type.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByCategory)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_by_category.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByTags)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_by_tags.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeAllWithCondition)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_all_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_OK);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeSingleRuleWithCondition)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_one_rule_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeSingleRuleWithConditionAndTransformers)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule =
        read_file<ddwaf_object>("exclude_one_rule_with_condition_and_transformers.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("AD      MIN"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}
TEST(TestRuleFilterIntegration, ExcludeByTypeWithCondition)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_by_type_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByCategoryWithCondition)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_by_category_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_OK);

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByTagsWithCondition)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_by_tags_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "ip_match",
                    .highlight = "192.168.0.1"sv,
                    .args = {{
                        .value = "192.168.0.1"sv,
                        .address = "http.client_ip",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, MonitorSingleRule)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("monitor_one_rule.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, AvoidHavingTwoMonitorOnActions)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("multiple_monitor_on_match.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, MonitorBypassFilterModePrecedence)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("monitor_bypass_precedence.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, MonitorCustomFilterModePrecedence)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("monitor_custom_precedence.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"monitor"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, BypassCustomFilterModePrecedence)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("bypass_custom_precedence.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, nullptr, LONG_TIME), DDWAF_OK);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, UnconditionalCustomFilterMode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_with_custom_action.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .block_id = "*",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"block"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                               {"type", "auto"}, {"security_response_id", "*"}}}})

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ConditionalCustomFilterMode)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("exclude_with_custom_action_and_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .block_id = "*",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .actions = {"block"},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(
            out, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                        {"type", "auto"}, {"security_response_id", "*"}}}})

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.2"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.2"sv,
                                   .args = {{
                                       .value = "192.168.0.2"sv,
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(out, {})

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, CustomFilterModeUnknownAction)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_file<ddwaf_object>("exclude_with_unknown_action.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle1, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(out, {});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto actions = yaml_to_object<ddwaf_object>(
            R"({actions: [{id: block2, type: block_request, parameters: {}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_destroy(&actions, alloc);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        auto *alloc = ddwaf_get_default_allocator();
        ddwaf_context context = ddwaf_context_init(handle2, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 1, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .block_id = "*",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .actions = {"block2"},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(
            out, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                        {"type", "auto"}, {"security_response_id", "*"}}}})

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_builder_destroy(builder);
}

TEST(TestRuleFilterIntegration, CustomFilterModeNonblockingAction)
{
    auto *alloc = ddwaf_get_default_allocator();
    // In this test, the ruleset contains a rule filter with the action
    // generate_stack, which is neither a blocking, redirecting or monitoring
    // action, hence its ignored.
    auto rule = read_file<ddwaf_object>("exclude_with_nonblocking_action.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    auto *handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("192.168.0.1"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .block_id = "*",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"block"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                               {"type", "auto"}, {"security_response_id", "*"}}}})

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);
}

} // namespace
