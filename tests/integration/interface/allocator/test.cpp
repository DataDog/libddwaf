// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"
#include "fmt/core.h"
#include "memory_resource.hpp"

using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "integration/interface/allocator/";

TEST(TestAllocatorIntegration, MonotonicAllocator)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto *alloc = ddwaf_monotonic_allocator_init();
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, alloc);

    auto *headers =
        ddwaf_object_insert_key(&parameter, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Arachni/v1"), alloc);

    auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc);

    // Force reallocation
    ddwaf_object_set_map(body, 0, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), alloc), true);
    ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), alloc), -42);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), alloc), 42);
    ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), alloc), 42.42);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(body, STRL("small_string"), alloc), STRL("hello"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), alloc),
        STRL("thisisanallocatedstring"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(body, STRL("literal_string"), alloc), STRL("literal string"));
    ddwaf_object_set_array(ddwaf_object_insert_key(body, STRL("array"), alloc), 25, alloc);
    ddwaf_object_set_map(ddwaf_object_insert_key(body, STRL("map"), alloc), 22, alloc);

    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 1);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_allocator_destroy(alloc);
}

TEST(TestAllocatorIntegration, UnsynchronizedPoolAllocator)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto *alloc = ddwaf_unsynchronized_pool_allocator_init();
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, alloc);

    auto *headers =
        ddwaf_object_insert_key(&parameter, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Arachni/v1"), alloc);

    auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc);

    // Force reallocation
    ddwaf_object_set_map(body, 0, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), alloc), true);
    ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), alloc), -42);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), alloc), 42);
    ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), alloc), 42.42);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(body, STRL("small_string"), alloc), STRL("hello"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), alloc),
        STRL("thisisanallocatedstring"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(body, STRL("literal_string"), alloc), STRL("literal string"));
    ddwaf_object_set_array(ddwaf_object_insert_key(body, STRL("array"), alloc), 25, alloc);
    ddwaf_object_set_map(ddwaf_object_insert_key(body, STRL("map"), alloc), 22, alloc);

    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 1);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_allocator_destroy(alloc);
}

TEST(TestAllocatorIntegration, SynchronizedPoolAllocator)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto *alloc = ddwaf_synchronized_pool_allocator_init();
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, alloc);

    auto *headers =
        ddwaf_object_insert_key(&parameter, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Arachni/v1"), alloc);

    auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc);

    // Force reallocation
    ddwaf_object_set_map(body, 0, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), alloc), true);
    ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), alloc), -42);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), alloc), 42);
    ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), alloc), 42.42);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(body, STRL("small_string"), alloc), STRL("hello"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), alloc),
        STRL("thisisanallocatedstring"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(body, STRL("literal_string"), alloc), STRL("literal string"));
    ddwaf_object_set_array(ddwaf_object_insert_key(body, STRL("array"), alloc), 25, alloc);
    ddwaf_object_set_map(ddwaf_object_insert_key(body, STRL("map"), alloc), 22, alloc);

    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 1);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_allocator_destroy(alloc);
}

TEST(TestAllocatorIntegration, SplitInputOutputAllocators)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto *input_alloc = ddwaf_monotonic_allocator_init();
    auto *output_alloc = ddwaf_unsynchronized_pool_allocator_init();

    ddwaf_context context = ddwaf_context_init(handle, output_alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, input_alloc);

    auto *headers =
        ddwaf_object_insert_key(&parameter, STRL("server.request.headers.no_cookies"), input_alloc);
    ddwaf_object_set_map(headers, 1, input_alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(headers, STRL("user-agent"), input_alloc),
        STRL("Arachni/v1"), input_alloc);

    auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), input_alloc);

    // Force reinput_allocation
    ddwaf_object_set_map(body, 0, input_alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), input_alloc), true);
    ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), input_alloc), -42);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), input_alloc), 42);
    ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), input_alloc), 42.42);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("small_string"), input_alloc),
        STRL("hello"), input_alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), input_alloc),
        STRL("thisisaninput_allocatedstring"), input_alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(body, STRL("literal_string"), input_alloc), STRL("literal string"));
    ddwaf_object_set_array(
        ddwaf_object_insert_key(body, STRL("array"), input_alloc), 25, input_alloc);
    ddwaf_object_set_map(ddwaf_object_insert_key(body, STRL("map"), input_alloc), 22, input_alloc);

    auto *settings =
        ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), input_alloc);
    ddwaf_object_set_map(settings, 1, input_alloc);
    ddwaf_object_set_bool(
        ddwaf_object_insert_key(settings, STRL("extract-schema"), input_alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, input_alloc, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 1);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, output_alloc);
    ddwaf_context_destroy(context);

    ddwaf_allocator_destroy(input_alloc);
    ddwaf_allocator_destroy(output_alloc);
}

TEST(TestAllocatorIntegration, MultiCallSplitInputOutputAllocators)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto *input_alloc0 = ddwaf_monotonic_allocator_init();
    auto *input_alloc1 = ddwaf_synchronized_pool_allocator_init();
    auto *output_alloc = ddwaf_unsynchronized_pool_allocator_init();

    ddwaf_context context = ddwaf_context_init(handle, output_alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, input_alloc0);

        auto *headers = ddwaf_object_insert_key(
            &parameter, STRL("server.request.headers.no_cookies"), input_alloc0);
        ddwaf_object_set_map(headers, 1, input_alloc0);
        ddwaf_object_set_string(ddwaf_object_insert_key(headers, STRL("user-agent"), input_alloc0),
            STRL("Arachni/v1"), input_alloc0);

        ddwaf_object result;
        ddwaf_object_set_invalid(&result);
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, input_alloc0, &result, LONG_TIME), DDWAF_OK);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        ASSERT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 1);

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        ASSERT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 1);

        const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
        ASSERT_NE(timeout, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *duration = ddwaf_object_find(&result, STRL("duration"));
        ASSERT_NE(duration, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
        EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        ASSERT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        ASSERT_NE(keep, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, output_alloc);
    }

    {
        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 2, input_alloc1);

        auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), input_alloc1);

        // Force reinput_alloc1ation
        ddwaf_object_set_map(body, 0, input_alloc1);
        ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), input_alloc1), true);
        ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), input_alloc1), -42);
        ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), input_alloc1), 42);
        ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), input_alloc1), 42.42);
        ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("small_string"), input_alloc1),
            STRL("hello"), input_alloc1);
        ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), input_alloc1),
            STRL("thisisaninput_alloc1atedstring"), input_alloc1);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(body, STRL("literal_string"), input_alloc1),
            STRL("literal string"));
        ddwaf_object_set_array(
            ddwaf_object_insert_key(body, STRL("array"), input_alloc1), 25, input_alloc1);
        ddwaf_object_set_map(
            ddwaf_object_insert_key(body, STRL("map"), input_alloc1), 22, input_alloc1);

        auto *settings =
            ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), input_alloc1);
        ddwaf_object_set_map(settings, 1, input_alloc1);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), input_alloc1), true);

        ddwaf_object result;
        ddwaf_object_set_invalid(&result);
        EXPECT_EQ(
            ddwaf_context_eval(context, &parameter, input_alloc1, &result, LONG_TIME), DDWAF_OK);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        ASSERT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        ASSERT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 0);

        const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
        ASSERT_NE(timeout, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *duration = ddwaf_object_find(&result, STRL("duration"));
        ASSERT_NE(duration, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
        EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        ASSERT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        ASSERT_NE(keep, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, output_alloc);
    }

    ddwaf_context_destroy(context);

    ddwaf_allocator_destroy(input_alloc0);
    ddwaf_allocator_destroy(input_alloc1);
    ddwaf_allocator_destroy(output_alloc);
}

struct counting_allocator {
    unsigned alloc_count{0};
    unsigned free_count{0};
    ddwaf_allocator underlying_alloc{ddwaf_get_default_allocator()};
};

void *counting_allocator_alloc(void *udata, std::size_t bytes, std::size_t alignment)
{
    auto *alloc = static_cast<counting_allocator *>(udata);
    alloc->alloc_count++;
    return ddwaf_allocator_alloc(alloc->underlying_alloc, bytes, alignment);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void counting_allocator_free(void *udata, void *p, std::size_t bytes, std::size_t alignment)
{
    auto *alloc = static_cast<counting_allocator *>(udata);
    alloc->free_count++;
    ddwaf_allocator_free(alloc->underlying_alloc, p, bytes, alignment);
}

TEST(TestAllocatorIntegration, UserAllocator)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    counting_allocator user_alloc;
    auto *alloc = ddwaf_user_allocator_init(
        &counting_allocator_alloc, &counting_allocator_free, &user_alloc, nullptr);
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, alloc);

    auto *headers =
        ddwaf_object_insert_key(&parameter, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Arachni/v1"), alloc);

    auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc);

    // Force reallocation
    ddwaf_object_set_map(body, 0, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), alloc), true);
    ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), alloc), -42);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), alloc), 42);
    ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), alloc), 42.42);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(body, STRL("small_string"), alloc), STRL("hello"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), alloc),
        STRL("thisisanallocatedstring"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(body, STRL("literal_string"), alloc), STRL("literal string"));
    ddwaf_object_set_array(ddwaf_object_insert_key(body, STRL("array"), alloc), 25, alloc);
    ddwaf_object_set_map(ddwaf_object_insert_key(body, STRL("map"), alloc), 22, alloc);

    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 1);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
    ddwaf_allocator_destroy(alloc);

    EXPECT_EQ(user_alloc.alloc_count, user_alloc.free_count);
}

TEST(TestAllocatorIntegration, UserAllocatorWithFreeableUdata)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto udata_free = [](void *p) { delete static_cast<counting_allocator *>(p); };

    auto *user_alloc = new counting_allocator;
    auto *alloc = ddwaf_user_allocator_init(
        &counting_allocator_alloc, &counting_allocator_free, user_alloc, udata_free);
    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, alloc);

    auto *headers =
        ddwaf_object_insert_key(&parameter, STRL("server.request.headers.no_cookies"), alloc);
    ddwaf_object_set_map(headers, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(headers, STRL("user-agent"), alloc), STRL("Arachni/v1"), alloc);

    auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc);

    // Force reallocation
    ddwaf_object_set_map(body, 0, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), alloc), true);
    ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), alloc), -42);
    ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), alloc), 42);
    ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), alloc), 42.42);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(body, STRL("small_string"), alloc), STRL("hello"), alloc);
    ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), alloc),
        STRL("thisisanallocatedstring"), alloc);
    ddwaf_object_set_string_literal(
        ddwaf_object_insert_key(body, STRL("literal_string"), alloc), STRL("literal string"));
    ddwaf_object_set_array(ddwaf_object_insert_key(body, STRL("array"), alloc), 25, alloc);
    ddwaf_object_set_map(ddwaf_object_insert_key(body, STRL("map"), alloc), 22, alloc);

    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 1);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 3);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);

    EXPECT_EQ(user_alloc->alloc_count, user_alloc->free_count);

    ddwaf_allocator_destroy(alloc);
}

TEST(TestAllocatorIntegration, UserAllocatorNullAllocCb)
{
    counting_allocator user_alloc;
    auto *alloc =
        ddwaf_user_allocator_init(nullptr, &counting_allocator_free, &user_alloc, nullptr);
    ASSERT_EQ(alloc, nullptr);
}

TEST(TestAllocatorIntegration, UserAllocatorNullFreeCb)
{
    counting_allocator user_alloc;
    auto *alloc =
        ddwaf_user_allocator_init(&counting_allocator_alloc, nullptr, &user_alloc, nullptr);
    ASSERT_EQ(alloc, nullptr);
}

TEST(TestAllocatorIntegration, MultiCallSplitInputOutputAllocatorsSubcontext)
{
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());

    auto *output_alloc = ddwaf_unsynchronized_pool_allocator_init();

    ddwaf_context context = ddwaf_context_init(handle, output_alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    {
        auto *input_alloc = ddwaf_monotonic_allocator_init();

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 1, input_alloc);

        auto *headers = ddwaf_object_insert_key(
            &parameter, STRL("server.request.headers.no_cookies"), input_alloc);
        ddwaf_object_set_map(headers, 1, input_alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(headers, STRL("user-agent"), input_alloc),
            STRL("Arachni/v1"), input_alloc);

        auto *sctx = ddwaf_subcontext_init(context);

        ddwaf_object result;
        ddwaf_object_set_invalid(&result);
        EXPECT_EQ(
            ddwaf_subcontext_eval(sctx, &parameter, input_alloc, &result, LONG_TIME), DDWAF_OK);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        ASSERT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 1);

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        ASSERT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 1);

        const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
        ASSERT_NE(timeout, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *duration = ddwaf_object_find(&result, STRL("duration"));
        ASSERT_NE(duration, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
        EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        ASSERT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 2);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        ASSERT_NE(keep, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
        EXPECT_TRUE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, output_alloc);
        ddwaf_subcontext_destroy(sctx);
        ddwaf_allocator_destroy(input_alloc);
    }

    {
        auto *input_alloc = ddwaf_synchronized_pool_allocator_init();

        ddwaf_object parameter;
        ddwaf_object_set_map(&parameter, 2, input_alloc);

        auto *body = ddwaf_object_insert_key(&parameter, STRL("server.request.body"), input_alloc);

        // Force reinput_allocation
        ddwaf_object_set_map(body, 0, input_alloc);
        ddwaf_object_set_bool(ddwaf_object_insert_key(body, STRL("bool"), input_alloc), true);
        ddwaf_object_set_signed(ddwaf_object_insert_key(body, STRL("int64"), input_alloc), -42);
        ddwaf_object_set_unsigned(ddwaf_object_insert_key(body, STRL("uint64"), input_alloc), 42);
        ddwaf_object_set_float(ddwaf_object_insert_key(body, STRL("float64"), input_alloc), 42.42);
        ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("small_string"), input_alloc),
            STRL("hello"), input_alloc);
        ddwaf_object_set_string(ddwaf_object_insert_key(body, STRL("string"), input_alloc),
            STRL("thisisaninput_allocatedstring"), input_alloc);
        ddwaf_object_set_string_literal(
            ddwaf_object_insert_key(body, STRL("literal_string"), input_alloc),
            STRL("literal string"));
        ddwaf_object_set_array(
            ddwaf_object_insert_key(body, STRL("array"), input_alloc), 25, input_alloc);
        ddwaf_object_set_map(
            ddwaf_object_insert_key(body, STRL("map"), input_alloc), 22, input_alloc);

        auto *settings =
            ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), input_alloc);
        ddwaf_object_set_map(settings, 1, input_alloc);
        ddwaf_object_set_bool(
            ddwaf_object_insert_key(settings, STRL("extract-schema"), input_alloc), true);

        auto *sctx = ddwaf_subcontext_init(context);

        ddwaf_object result;
        ddwaf_object_set_invalid(&result);
        EXPECT_EQ(
            ddwaf_subcontext_eval(sctx, &parameter, input_alloc, &result, LONG_TIME), DDWAF_OK);

        const auto *events = ddwaf_object_find(&result, STRL("events"));
        ASSERT_NE(events, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(events), 0);

        const auto *actions = ddwaf_object_find(&result, STRL("actions"));
        ASSERT_NE(actions, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(actions), 0);

        const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
        ASSERT_NE(timeout, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        const auto *duration = ddwaf_object_find(&result, STRL("duration"));
        ASSERT_NE(duration, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
        EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

        const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
        ASSERT_NE(attributes, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(attributes), 1);

        const auto *keep = ddwaf_object_find(&result, STRL("keep"));
        ASSERT_NE(keep, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(keep));

        ddwaf_object_destroy(&result, output_alloc);
        ddwaf_subcontext_destroy(sctx);
        ddwaf_allocator_destroy(input_alloc);
    }

    ddwaf_context_destroy(context);

    ddwaf_allocator_destroy(output_alloc);
}

} // namespace
