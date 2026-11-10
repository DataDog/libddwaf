// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <set>
#include <string>
#include <string_view>

#include "common/gtest_utils.hpp"
#include "configuration/common/common.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/exclusion_data/";

TEST(TestExclusionDataIntegration, ExcludeRuleByUserID)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_file<ddwaf_object>("exclude_one_rule_by_user.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

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

    {
        auto data = yaml_to_object<ddwaf_object>(
            R"({exclusion_data: [{id: usr_data, type: data_with_expiration, data: [{value: admin, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_destroy(&data, alloc);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2, alloc);
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

    ddwaf_builder_remove_config(builder, LSTRARG("exclusion_data"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

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

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, ExcludeRuleByClientIP)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_file<ddwaf_object>("exclude_one_rule_by_ip.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object<ddwaf_object>(
            R"({exclusion_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.0.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_destroy(&data, alloc);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2, alloc);
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
                               .matches = {{.op = "exact_match",
                                   .highlight = "admin"sv,
                                   .args = {{
                                       .value = "admin"sv,
                                       .address = "usr.id",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("exclusion_data"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, UnknownDataTypeOnExclusionData)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_file<ddwaf_object>("exclude_one_rule_by_ip.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object<ddwaf_object>(
            R"({exclusion_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.0.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_destroy(&data, alloc);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2, alloc);
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
                               .matches = {{.op = "exact_match",
                                   .highlight = "admin"sv,
                                   .args = {{
                                       .value = "admin"sv,
                                       .address = "usr.id",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object<ddwaf_object>(
            R"({exclusion_data: [{id: ip_data, type: unknown_data, data: [{}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_destroy(&data, alloc);
    }

    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, ExcludeInputByClientIP)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    {
        auto rule = read_file<ddwaf_object>("exclude_one_input_by_ip.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_destroy(&rule, alloc);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object<ddwaf_object>(
            R"({exclusion_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.0.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_destroy(&data, alloc);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2, alloc);
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
                               .matches = {{.op = "exact_match",
                                   .highlight = "admin"sv,
                                   .args = {{
                                       .value = "admin"sv,
                                       .address = "usr.id",
                                   }}}}});

        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("exclusion_data"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3, alloc);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc),
            STRL("192.168.0.1"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(out,
            {.id = "1",
                .name = "rule1",
                .tags = {{"type", "type1"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}},
            {.id = "2",
                .name = "rule2",
                .tags = {{"type", "type2"}, {"category", "category"}},
                .matches = {{.op = "exact_match",
                    .highlight = "admin"sv,
                    .args = {{
                        .value = "admin"sv,
                        .address = "usr.id",
                    }}}}});
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

// Tests for exclusion data with an empty data list.
//
// The configuration has a single rule (rule 1). It always matches with the
// input used by these tests, so the rule is either active (DDWAF_MATCH and an
// event for rule 1) or excluded (DDWAF_OK and no events).
std::string empty_exclusion_config(std::string_view operator_name, std::string_view address,
    std::string_view data_id, std::string_view exclusion_data)
{
    std::string config = R"(
version: '2.1'
rules:
  - id: 1
    name: rule1
    tags: {type: type1, category: category}
    conditions:
      - operator: exact_match
        parameters:
          inputs: [{address: server.request.query}]
          list: [trigger]
exclusions:
  - id: 1
    rules_target: [{rule_id: 1}]
    conditions:
      - operator: ')";
    config += operator_name;
    config += "'\n        parameters:\n          inputs: [{address: ";
    config += address;
    config += "}]\n          data: ";
    config += data_id;
    config += "\n";
    config += exclusion_data;
    return config;
}

void expect_rule_1_active(ddwaf_handle handle)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 3, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        STRL("trigger"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("1.2.3.4"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_MATCH);
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1",
                           .tags = {{"type", "type1"}, {"category", "category"}},
                           .matches = {{.op = "exact_match",
                               .highlight = "trigger"sv,
                               .args = {{
                                   .value = "trigger"sv,
                                   .address = "server.request.query",
                               }}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
}

void expect_rule_1_excluded(ddwaf_handle handle)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object root;
    ddwaf_object_set_map(&root, 3, alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(&root, STRL("server.request.query"), alloc),
        STRL("trigger"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("1.2.3.4"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

    ddwaf_object out;
    EXPECT_EQ(ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME), DDWAF_OK);
    auto events = to_view(out).find("events");
    EXPECT_TRUE(!events.has_value() || events.empty());

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
}

// Adds the config to a fresh builder, and returns the diagnostics of the
// exclusion data section as a pair of (loaded, failed) id sets.
ddwaf_handle build_empty_exclusion_handle(ddwaf_builder builder, const std::string &config_yaml,
    std::set<std::string> &loaded, std::set<std::string> &failed)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto config = yaml_to_object<ddwaf_object>(config_yaml);
    EXPECT_NE(config.type, DDWAF_OBJ_INVALID);

    ddwaf_object diagnostics;
    EXPECT_TRUE(
        ddwaf_builder_add_or_update_config(builder, LSTRARG("config"), &config, &diagnostics));
    ddwaf_object_destroy(&config, alloc);

    ddwaf::raw_configuration root(reinterpret_cast<const ddwaf::detail::object &>(diagnostics));
    auto root_map = static_cast<ddwaf::raw_configuration::map>(root);
    auto it = root_map.find("exclusion_data");
    if (it != root_map.end()) {
        auto section = static_cast<ddwaf::raw_configuration::map>(it->second);
        for (auto id : ddwaf::at<ddwaf::raw_configuration::string_set>(section, "loaded")) {
            loaded.emplace(id);
        }
        for (auto id : ddwaf::at<ddwaf::raw_configuration::string_set>(section, "failed")) {
            failed.emplace(id);
        }
    }
    ddwaf_object_destroy(&diagnostics, alloc);

    return ddwaf_builder_build_instance(builder);
}

constexpr const char *empty_ip_exclusion_data = R"(
exclusion_data:
  - {id: ip_data, type: ip_with_expiration, data: []}
)";

constexpr const char *empty_string_exclusion_data = R"(
exclusion_data:
  - {id: usr_data, type: data_with_expiration, data: []}
)";

TEST(TestExclusionDataIntegration, EmptyIpDataPositiveExclusion)
{
    ddwaf_builder builder = ddwaf_builder_init();
    std::set<std::string> loaded;
    std::set<std::string> failed;
    ddwaf_handle handle = build_empty_exclusion_handle(builder,
        empty_exclusion_config("ip_match", "http.client_ip", "ip_data", empty_ip_exclusion_data),
        loaded, failed);
    ASSERT_NE(handle, nullptr);

    EXPECT_EQ(loaded, std::set<std::string>{"ip_data"});
    EXPECT_TRUE(failed.empty());

    // The data set is empty, so nothing is excluded
    expect_rule_1_active(handle);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, EmptyStringDataPositiveExclusion)
{
    ddwaf_builder builder = ddwaf_builder_init();
    std::set<std::string> loaded;
    std::set<std::string> failed;
    ddwaf_handle handle = build_empty_exclusion_handle(builder,
        empty_exclusion_config("exact_match", "usr.id", "usr_data", empty_string_exclusion_data),
        loaded, failed);
    ASSERT_NE(handle, nullptr);

    EXPECT_EQ(loaded, std::set<std::string>{"usr_data"});
    EXPECT_TRUE(failed.empty());

    expect_rule_1_active(handle);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

// A negated exclusion condition keeps its NOT semantics: the empty data set
// contains no value, so the condition is true and the rule is excluded.
TEST(TestExclusionDataIntegration, EmptyIpDataNegatedExclusion)
{
    ddwaf_builder builder = ddwaf_builder_init();
    std::set<std::string> loaded;
    std::set<std::string> failed;
    ddwaf_handle handle = build_empty_exclusion_handle(builder,
        empty_exclusion_config("!ip_match", "http.client_ip", "ip_data", empty_ip_exclusion_data),
        loaded, failed);
    ASSERT_NE(handle, nullptr);

    EXPECT_EQ(loaded, std::set<std::string>{"ip_data"});
    EXPECT_TRUE(failed.empty());

    expect_rule_1_excluded(handle);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, EmptyStringDataNegatedExclusion)
{
    ddwaf_builder builder = ddwaf_builder_init();
    std::set<std::string> loaded;
    std::set<std::string> failed;
    ddwaf_handle handle = build_empty_exclusion_handle(builder,
        empty_exclusion_config("!exact_match", "usr.id", "usr_data", empty_string_exclusion_data),
        loaded, failed);
    ASSERT_NE(handle, nullptr);

    EXPECT_EQ(loaded, std::set<std::string>{"usr_data"});
    EXPECT_TRUE(failed.empty());

    expect_rule_1_excluded(handle);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

// Control: with a data id which was never loaded there is no matcher, so the
// negated condition is false and the rule stays active.
TEST(TestExclusionDataIntegration, UnknownDataIdNegatedExclusion)
{
    ddwaf_builder builder = ddwaf_builder_init();
    std::set<std::string> loaded;
    std::set<std::string> failed;
    ddwaf_handle handle = build_empty_exclusion_handle(builder,
        empty_exclusion_config("!ip_match", "http.client_ip", "missing_id", ""), loaded, failed);
    ASSERT_NE(handle, nullptr);

    EXPECT_TRUE(loaded.empty());
    EXPECT_TRUE(failed.empty());

    expect_rule_1_active(handle);

    ddwaf_destroy(handle);
    ddwaf_builder_destroy(builder);
}

} // namespace
