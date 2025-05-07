// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/conditions/exists";

TEST(TestConditionExistsIntegration, AddressAvailable)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&map, "input-1", ddwaf_object_invalid(&value));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1-exists",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = "",
                               .args = {{
                                   .address = "input-1",
                               }}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, AddressNotAvailable)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&map, "input", ddwaf_object_invalid(&value));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);
    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, KeyPathAvailable)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object intermediate = DDWAF_OBJECT_MAP;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&intermediate, "path", ddwaf_object_invalid(&value));
    ddwaf_object_map_add(&map, "input-2", &intermediate);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2-exists-kp",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = "",
                               .args = {{.address = "input-2", .path = {"path"}}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, KeyPathNotAvailable)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object intermediate = DDWAF_OBJECT_MAP;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&intermediate, "poth", ddwaf_object_invalid(&value));
    ddwaf_object_map_add(&map, "input-2", &intermediate);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, AddressAvailableVariadicRule)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&map, "input-3-1", ddwaf_object_invalid(&value));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-exists-multi",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = "",
                               .args = {{
                                   .address = "input-3-1",
                               }}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, KeyPathAvailableVariadicRule)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object intermediate = DDWAF_OBJECT_MAP;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&intermediate, "path", ddwaf_object_invalid(&value));
    ddwaf_object_map_add(&map, "input-3-2", &intermediate);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-exists-multi",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = "",
                               .args = {{.address = "input-3-2", .path = {"path"}}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, AddressAvailableKeyPathNotAvailableVariadicRule)
{
    auto rule = read_file("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object intermediate = DDWAF_OBJECT_MAP;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&intermediate, "poth", ddwaf_object_invalid(&value));
    ddwaf_object_map_add(&map, "input-3-2", &intermediate);
    ddwaf_object_map_add(&map, "input-3-1", ddwaf_object_invalid(&value));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-exists-multi",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = "",
                               .args = {{
                                   .address = "input-3-1",
                               }}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, AddressAvailable)
{
    auto rule = read_file("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&map, "input-1", ddwaf_object_invalid(&value));

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, AddressNotAvailable)
{
    auto rule = read_file("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&map, "input", ddwaf_object_invalid(&value));

    // Even though the address isn't present, this test shouldn't result in a match
    // as the !exists operator only supports address + key path, since we can't
    // assert the absence of an address given that these are provided in stages
    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, KeyPathNotAvailable)
{
    auto rule = read_file("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object intermediate = DDWAF_OBJECT_MAP;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&intermediate, "poth", ddwaf_object_invalid(&value));
    ddwaf_object_map_add(&map, "input-2", &intermediate);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2-not-exists-kp",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "!exists",
                               .highlight = "",
                               .args = {{.address = "input-2", .path = {"path"}}}}}});

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, KeyPathAvailable)
{
    auto rule = read_file("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object intermediate = DDWAF_OBJECT_MAP;
    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object value;
    ddwaf_object_map_add(&intermediate, "path", ddwaf_object_invalid(&value));
    ddwaf_object_map_add(&map, "input-2", &intermediate);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_run(context, &map, nullptr, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
