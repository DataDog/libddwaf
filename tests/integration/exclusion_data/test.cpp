// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/exclusion_data/";

TEST(TestExclusionDataIntegration, ExcludeRuleByUserID)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("exclude_one_rule_by_user.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

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

    {
        auto data = yaml_to_object(
            R"({exclusion_data: [{id: usr_data, type: data_with_expiration, data: [{value: admin, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2);
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

    ddwaf_builder_remove_config(builder, LSTRARG("exclusion_data"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

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

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, ExcludeRuleByClientIP)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("exclude_one_rule_by_ip.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object(
            R"({exclusion_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.0.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2);
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
                               .matches = {{.op = "exact_match",
                                   .highlight = "admin"sv,
                                   .args = {{
                                       .value = "admin"sv,
                                       .address = "usr.id",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("exclusion_data"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, UnknownDataTypeOnExclusionData)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("exclude_one_rule_by_ip.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object(
            R"({exclusion_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.0.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2);
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
                               .matches = {{.op = "exact_match",
                                   .highlight = "admin"sv,
                                   .args = {{
                                       .value = "admin"sv,
                                       .address = "usr.id",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto data =
            yaml_to_object(R"({exclusion_data: [{id: ip_data, type: unknown_data, data: [{}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

TEST(TestExclusionDataIntegration, ExcludeInputByClientIP)
{
    ddwaf_builder builder = ddwaf_builder_init(nullptr);

    {
        auto rule = read_file("exclude_one_input_by_ip.yaml", base_dir);
        ASSERT_NE(rule.type, DDWAF_OBJ_INVALID);
        ddwaf_builder_add_or_update_config(builder, LSTRARG("rules"), &rule, nullptr);
        ddwaf_object_free(&rule);
    }

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle1);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    {
        auto data = yaml_to_object(
            R"({exclusion_data: [{id: ip_data, type: ip_with_expiration, data: [{value: 192.168.0.1, expiration: 0}]}]})");
        ddwaf_builder_add_or_update_config(builder, LSTRARG("exclusion_data"), &data, nullptr);
        ddwaf_object_free(&data);
    }

    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle2);
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
                               .matches = {{.op = "exact_match",
                                   .highlight = "admin"sv,
                                   .args = {{
                                       .value = "admin"sv,
                                       .address = "usr.id",
                                   }}}}});

        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_builder_remove_config(builder, LSTRARG("exclusion_data"));
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);

    {
        ddwaf_context context = ddwaf_context_init(handle3);
        ASSERT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_object out;
        EXPECT_EQ(ddwaf_run(context, &root, nullptr, &out, LONG_TIME), DDWAF_MATCH);
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
        ddwaf_object_free(&out);
        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle1);
    ddwaf_destroy(handle2);
    ddwaf_destroy(handle3);

    ddwaf_builder_destroy(builder);
}

} // namespace
