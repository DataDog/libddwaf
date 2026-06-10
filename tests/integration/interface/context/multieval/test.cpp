// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include <stdexcept>

using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "integration/interface/context/multieval/";

void *throwing_alloc(void *, size_t, size_t) { throw std::runtime_error("allocation failure"); }
void noop_free(void *, void *, size_t, size_t) {}
//------------------------------------------------------------------------------
// ddwaf_context_multieval tests
//------------------------------------------------------------------------------

TEST(TestContextMultievalIntegration, InvalidArgumentNullContext)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 0, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(nullptr, &data, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_ARGUMENT);

    ddwaf_object_destroy(&data, alloc);
}

TEST(TestContextMultievalIntegration, InvalidArgumentNullData)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, nullptr, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_ARGUMENT);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, InvalidArgumentNotArray)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Pass a map instead of an array
    ddwaf_object data;
    ddwaf_object_set_map(&data, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    ddwaf_object_destroy(&data, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, InvalidArgumentNotArrayWithNullAlloc)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_map(&data, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, nullptr, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    ddwaf_object_destroy(&data, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, InternalErrorWhenInputAllocatorThrows)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *throwing_alloc_handle =
        ddwaf_user_allocator_init(throwing_alloc, noop_free, nullptr, nullptr);
    ASSERT_NE(throwing_alloc_handle, nullptr);

    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 1, alloc);
    ddwaf_object *elem = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, throwing_alloc_handle, &result, LONG_TIME),
        DDWAF_ERR_INTERNAL);

    ddwaf_object_destroy(&data, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_allocator_destroy(throwing_alloc_handle);
}
TEST(TestContextMultievalIntegration, SingleMapNoMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 1, alloc);

    ddwaf_object *elem = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem, STRL("value1"), alloc), STRL("no_match"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_OK);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 1);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, SingleMapWithMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 1, alloc);

    ddwaf_object *elem = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 1);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, MultipleMapsNoMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("no_match"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("no_match"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value3"), alloc), STRL("no_match"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_OK);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 3);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, MultipleMapsFirstMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("no_match"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value3"), alloc), STRL("no_match"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 3);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, MultipleMapsLastMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("no_match"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("no_match"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value3"), alloc), STRL("rule3"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 3);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, MultipleMapsAllMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("rule2"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value3"), alloc), STRL("rule3"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 3);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 3);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, NullResult)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("no_match"), alloc);

    // Pass nullptr for result - should still work
    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, NullAlloc)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("no_match"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    // Pass nullptr for alloc - data should be treated as borrowed (not freed)
    EXPECT_EQ(ddwaf_context_multieval(context, &data, nullptr, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 2);

    ddwaf_object_destroy(&result, alloc);

    // Manually destroy data since null alloc means context won't free it
    ddwaf_object_destroy(&data, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, ContextStateAccumulates)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // First multieval call
    ddwaf_object data1;
    ddwaf_object_set_array(&data1, 1, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data1, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result1;
    ddwaf_object_set_invalid(&result1);

    EXPECT_EQ(ddwaf_context_multieval(context, &data1, alloc, &result1, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result1), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result1, STRL("events"))), 1);
    ddwaf_object_destroy(&result1, alloc);

    // Second multieval call - same rule should not trigger again (already matched)
    ddwaf_object data2;
    ddwaf_object_set_array(&data2, 1, alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data2, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result2;
    ddwaf_object_set_invalid(&result2);

    EXPECT_EQ(ddwaf_context_multieval(context, &data2, alloc, &result2, LONG_TIME), DDWAF_OK);

    ASSERT_EQ(ddwaf_object_get_type(&result2), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result2, STRL("events"))), 0);
    ddwaf_object_destroy(&result2, alloc);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, EmptyArray)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_OK);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 0);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, InvalidArgumentArrayContainsNonMap)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Array where the middle element is a string, not a map
    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 0, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_string(elem1, STRL("not_a_map"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, SameRuleDoesNotDoubleFireWithinCall)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Both batches provide the same address with a matching value.
    // rule1 fires in batch 1; in batch 2 value1 is overwritten (still matching),
    // but the rule module cache prevents it from generating a second event.
    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextMultievalIntegration, CrossBatchDataCombination)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // rule4 requires both value_a (matching "rule4a") AND value_b (matching "rule4b").
    // Batch 1 satisfies only the first condition; rule4 cannot fire yet.
    // Batch 2 satisfies the second condition; the store still holds value_a from
    // batch 1, so rule4 now fires. This is the defining semantic of multieval.
    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *batch1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(batch1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(batch1, STRL("value_a"), alloc), STRL("rule4a"), alloc);

    ddwaf_object *batch2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(batch2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(batch2, STRL("value_b"), alloc), STRL("rule4b"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_multieval(context, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 2);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

//------------------------------------------------------------------------------
// ddwaf_subcontext_multieval tests
//------------------------------------------------------------------------------

TEST(TestSubcontextMultievalIntegration, InvalidArgumentNullSubcontext)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 0, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(nullptr, &data, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_ARGUMENT);

    ddwaf_object_destroy(&data, alloc);
}

TEST(TestSubcontextMultievalIntegration, InvalidArgumentNullData)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, nullptr, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_ARGUMENT);

    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, InvalidArgumentNotArray)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    // Pass a map instead of an array
    ddwaf_object data;
    ddwaf_object_set_map(&data, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    ddwaf_object_destroy(&data, alloc);
    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, InvalidArgumentNotArrayWithNullAlloc)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_map(&data, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, nullptr, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    ddwaf_object_destroy(&data, alloc);
    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, InternalErrorWhenInputAllocatorThrows)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto *throwing_alloc_handle =
        ddwaf_user_allocator_init(throwing_alloc, noop_free, nullptr, nullptr);
    ASSERT_NE(throwing_alloc_handle, nullptr);

    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 1, alloc);
    ddwaf_object *elem = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, throwing_alloc_handle, &result, LONG_TIME),
        DDWAF_ERR_INTERNAL);

    ddwaf_object_destroy(&data, alloc);
    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
    ddwaf_allocator_destroy(throwing_alloc_handle);
}
TEST(TestSubcontextMultievalIntegration, SingleMapNoMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 1, alloc);

    ddwaf_object *elem = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem, STRL("value1"), alloc), STRL("no_match"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, alloc, &result, LONG_TIME), DDWAF_OK);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 0);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 1);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, SingleMapWithMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 1, alloc);

    ddwaf_object *elem = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 1);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 1);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, MultipleMapsAllMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("rule2"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value3"), alloc), STRL("rule3"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, alloc, &result, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result, STRL("events"))), 3);
    EXPECT_EQ(ddwaf_object_get_unsigned(ddwaf_object_find(&result, STRL("evaluated"))), 3);

    ddwaf_object_destroy(&result, alloc);
    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, NullResult)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 2, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem0, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value2"), alloc), STRL("no_match"), alloc);

    // Pass nullptr for result - should still work
    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, alloc, nullptr, LONG_TIME), DDWAF_MATCH);

    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, SubcontextStateAccumulates)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    // First multieval call
    ddwaf_object data1;
    ddwaf_object_set_array(&data1, 1, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data1, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result1;
    ddwaf_object_set_invalid(&result1);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data1, alloc, &result1, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result1), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result1, STRL("events"))), 1);
    ddwaf_object_destroy(&result1, alloc);

    // Second multieval call - same rule should not trigger again
    ddwaf_object data2;
    ddwaf_object_set_array(&data2, 1, alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data2, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result2;
    ddwaf_object_set_invalid(&result2);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data2, alloc, &result2, LONG_TIME), DDWAF_OK);

    ASSERT_EQ(ddwaf_object_get_type(&result2), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result2, STRL("events"))), 0);
    ddwaf_object_destroy(&result2, alloc);

    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, MultipleSubcontextsIndependent)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Create two subcontexts
    ddwaf_subcontext subctx1 = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx1, nullptr);

    ddwaf_subcontext subctx2 = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx2, nullptr);

    // Trigger rule1 in subctx1
    ddwaf_object data1;
    ddwaf_object_set_array(&data1, 1, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data1, alloc);
    ddwaf_object_set_map(elem1, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem1, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result1;
    ddwaf_object_set_invalid(&result1);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx1, &data1, alloc, &result1, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result1), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result1, STRL("events"))), 1);
    ddwaf_object_destroy(&result1, alloc);

    // Same rule should still trigger in subctx2 (independent state)
    ddwaf_object data2;
    ddwaf_object_set_array(&data2, 1, alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data2, alloc);
    ddwaf_object_set_map(elem2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(elem2, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result2;
    ddwaf_object_set_invalid(&result2);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx2, &data2, alloc, &result2, LONG_TIME), DDWAF_MATCH);

    ASSERT_EQ(ddwaf_object_get_type(&result2), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(ddwaf_object_find(&result2, STRL("events"))), 1);
    ddwaf_object_destroy(&result2, alloc);

    ddwaf_subcontext_destroy(subctx1);
    ddwaf_subcontext_destroy(subctx2);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestSubcontextMultievalIntegration, InvalidArgumentArrayContainsNonMap)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("rules.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_subcontext subctx = ddwaf_subcontext_init(context);
    ASSERT_NE(subctx, nullptr);

    ddwaf_object data;
    ddwaf_object_set_array(&data, 3, alloc);

    ddwaf_object *elem0 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem0, 0, alloc);

    ddwaf_object *elem1 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_string(elem1, STRL("not_a_map"), alloc);

    ddwaf_object *elem2 = ddwaf_object_insert(&data, alloc);
    ddwaf_object_set_map(elem2, 0, alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_subcontext_multieval(subctx, &data, alloc, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    ddwaf_subcontext_destroy(subctx);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

} // namespace
