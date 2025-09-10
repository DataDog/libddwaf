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
constexpr std::string_view base_dir = "integration/conditions/exists";

TEST(TestConditionExistsIntegration, AddressAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_insert_key(&map, STRL("input-1"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "1",
                           .name = "rule1-exists",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = ""sv,
                               .args = {{
                                   .address = "input-1",
                               }}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, AddressNotAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_insert_key(&map, STRL("input"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_OK);
    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, KeyPathAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *intermediate = ddwaf_object_insert_key(&map, STRL("input-2"), alloc);
    ddwaf_object_set_map(intermediate, 1, alloc);
    ddwaf_object_insert_key(intermediate, STRL("path"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2-exists-kp",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = ""sv,
                               .args = {{.address = "input-2", .path = {"path"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, KeyPathNotAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *intermediate = ddwaf_object_insert_key(&map, STRL("input-2"), alloc);
    ddwaf_object_set_map(intermediate, 1, alloc);
    ddwaf_object_insert_key(intermediate, STRL("poth"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, AddressAvailableVariadicRule)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_insert_key(&map, STRL("input-3-1"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-exists-multi",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = ""sv,
                               .args = {{
                                   .address = "input-3-1",
                               }}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, KeyPathAvailableVariadicRule)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *intermediate = ddwaf_object_insert_key(&map, STRL("input-3-2"), alloc);
    ddwaf_object_set_map(intermediate, 1, alloc);
    ddwaf_object_insert_key(intermediate, STRL("path"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-exists-multi",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = ""sv,
                               .args = {{.address = "input-3-2", .path = {"path"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsIntegration, AddressAvailableKeyPathNotAvailableVariadicRule)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *intermediate = ddwaf_object_insert_key(&map, STRL("input-3-2"), alloc);
    ddwaf_object_set_map(intermediate, 1, alloc);
    ddwaf_object_insert_key(intermediate, STRL("poth"), alloc);

    ddwaf_object_insert_key(&map, STRL("input-3-1"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "3",
                           .name = "rule3-exists-multi",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "exists",
                               .highlight = ""sv,
                               .args = {{
                                   .address = "input-3-1",
                               }}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, AddressAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_insert_key(&map, STRL("input-1"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, AddressNotAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);
    ddwaf_object_insert_key(&map, STRL("input"), alloc);

    // Even though the address isn't present, this test shouldn't result in a match
    // as the !exists operator only supports address + key path, since we can't
    // assert the absence of an address given that these are provided in stages
    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, KeyPathNotAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *intermediate = ddwaf_object_insert_key(&map, STRL("input-2"), alloc);

    ddwaf_object_set_map(intermediate, 1, alloc);
    ddwaf_object_insert_key(intermediate, STRL("poth"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_MATCH);
    const auto *timeout = ddwaf_object_find(&out, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(out, {.id = "2",
                           .name = "rule2-not-exists-kp",
                           .tags = {{"type", "flow"}, {"category", "category"}},
                           .matches = {{.op = "!exists",
                               .highlight = ""sv,
                               .args = {{.address = "input-2", .path = {"path"}}}}}});

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestConditionExistsNegatedIntegration, KeyPathAvailable)
{
    auto *alloc = ddwaf_get_default_allocator();

    auto rule = read_file<ddwaf_object>("exists_negated.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object map;
    ddwaf_object_set_map(&map, 1, alloc);

    auto *intermediate = ddwaf_object_insert_key(&map, STRL("input-2"), alloc);

    ddwaf_object_set_map(intermediate, 1, alloc);
    ddwaf_object_insert_key(intermediate, STRL("path"), alloc);

    ddwaf_object out;
    ASSERT_EQ(ddwaf_context_eval(context, &map, true, &out, LONG_TIME), DDWAF_OK);

    ddwaf_object_destroy(&out, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
