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
    auto rule = read_file("exclude_one_rule.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByType)
{
    auto rule = read_file("exclude_by_type.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByCategory)
{
    auto rule = read_file("exclude_by_category.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByTags)
{
    auto rule = read_file("exclude_by_tags.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "type2"}, {"category", "category"}},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeAllWithCondition)
{
    auto rule = read_file("exclude_all_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeSingleRuleWithCondition)
{
    auto rule = read_file("exclude_one_rule_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeSingleRuleWithConditionAndTransformers)
{
    auto rule = read_file("exclude_one_rule_with_condition_and_transformers.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "AD      MIN"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}
TEST(TestRuleFilterIntegration, ExcludeByTypeWithCondition)
{
    auto rule = read_file("exclude_by_type_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByCategoryWithCondition)
{
    auto rule = read_file("exclude_by_category_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_OK);

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ExcludeByTagsWithCondition)
{
    auto rule = read_file("exclude_by_tags_with_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "2",
                               .name = "rule2",
                               .tags = {{"type", "type2"}, {"category", "category"}},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, MonitorSingleRule)
{
    auto rule = read_file("monitor_one_rule.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, AvoidHavingTwoMonitorOnActions)
{
    auto rule = read_file("multiple_monitor_on_match.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, MonitorBypassFilterModePrecedence)
{
    auto rule = read_file("monitor_bypass_precedence.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, MonitorCustomFilterModePrecedence)
{
    auto rule = read_file("monitor_custom_precedence.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, BypassCustomFilterModePrecedence)
{
    auto rule = read_file("bypass_custom_precedence.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    EXPECT_EQ(ddwaf_run(context, &root, nullptr, nullptr, LONG_TIME), DDWAF_OK);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, UnconditionalCustomFilterMode)
{
    auto rule = read_file("exclude_with_custom_action.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"block"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                               {"type", "auto"}}}})

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, ConditionalCustomFilterMode)
{
    auto rule = read_file("exclude_with_custom_action_and_condition.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .actions = {"block"},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(out, {{"block_request", {{"status_code", 403ULL},
                                                   {"grpc_status_code", 10ULL}, {"type", "auto"}}}})

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }
    ddwaf_destroy(handle);
}

TEST(TestRuleFilterIntegration, CustomFilterModeUnknownAction)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("exclude_with_unknown_action.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("default"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    auto *handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto actions =
            yaml_to_object(R"({actions: [{id: block2, type: block_request, parameters: {}}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("actions"), &actions, nullptr);
        ddwaf_object_free(&actions);
    }

    auto *handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out, {.id = "1",
                               .name = "rule1",
                               .tags = {{"type", "type1"}, {"category", "category"}},
                               .actions = {"block2"},
                               .matches = {{.op = "ip_match",
                                   .highlight = "192.168.0.1"sv,
                                   .args = {{
                                       .value = "192.168.0.1"sv,
                                       .address = "http.client_ip",
                                   }}}}});
        EXPECT_ACTIONS(out, {{"block_request", {{"status_code", 403ULL},
                                                   {"grpc_status_code", 10ULL}, {"type", "auto"}}}})

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_builder_destroy(builder);
}

TEST(TestRuleFilterIntegration, CustomFilterModeNonblockingAction)
{
    // In this test, the ruleset contains a rule filter with the action
    // generate_stack, which is neither a blocking, redirecting or monitoring
    // action, hence its ignored.
    auto rule = read_file("exclude_with_nonblocking_action.yaml", base_dir);
    ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);

    auto *handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf_object out;
    EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .actions = {"block"},
                           .matches = {{.op = "ip_match",
                               .highlight = "192.168.0.1"sv,
                               .args = {{
                                   .value = "192.168.0.1"sv,
                                   .address = "http.client_ip",
                               }}}}});
    EXPECT_ACTIONS(out, {{"block_request", {{"status_code", 403ULL}, {"grpc_status_code", 10ULL},
                                               {"type", "auto"}}}})

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);

    ddwaf_destroy(handle);
}

} // namespace
