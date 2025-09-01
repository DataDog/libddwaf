// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "integration/interface/context/result/";

TEST(TestContextResultIntegration, ResultInvalidArgumentNullContext)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_object persistent;
    ddwaf_object_set_map(&persistent, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&persistent, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_eval(nullptr, &persistent, true, &result, LONG_TIME),
        DDWAF_ERR_INVALID_ARGUMENT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_INVALID);

    ddwaf_object_destroy(&persistent, alloc);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultInvalidArgumentNoData)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(
        ddwaf_context_eval(context, nullptr, true, &result, LONG_TIME), DDWAF_ERR_INVALID_ARGUMENT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_INVALID);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultInvalidObjectInvalidPersistentDataSchema)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object persistent;
    ddwaf_object_set_array(&persistent, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert(&persistent, alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    EXPECT_EQ(ddwaf_context_eval(context, &persistent, true, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_INVALID);

    // The persistent object, even though invalid, is freed on context destruction
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultInvalidObjectInvalidSubcontextDataSchema)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object ephemeral;
    ddwaf_object_set_array(&ephemeral, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert(&ephemeral, alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);

    auto *subctx = ddwaf_subcontext_init(context);
    EXPECT_EQ(ddwaf_subcontext_eval(subctx, &ephemeral, true, &result, LONG_TIME),
        DDWAF_ERR_INVALID_OBJECT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_get_type(&result), DDWAF_OBJ_INVALID);
    ddwaf_subcontext_destroy(subctx);

    // The ephemeral object, even though invalid, is freed on context destruction
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultOk)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 1, alloc);
    ddwaf_object_insert_key(&parameter, STRL("value1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, true, &result, LONG_TIME), DDWAF_OK);

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
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultOkWithAttributes)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 2, alloc);
    ddwaf_object_set_invalid(
        ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc));
    // Move the settings object to the parameter
    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);

    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, true, &result, LONG_TIME), DDWAF_OK);

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

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultOkWithTimeout)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 1, alloc);
    ddwaf_object_insert_key(&parameter, STRL("value1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, true, &result, 0), DDWAF_OK);

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
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultMatch)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, true, &result, LONG_TIME), DDWAF_MATCH);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

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
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultMatchWithTimeout)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"), alloc);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, true, &result, 0), DDWAF_MATCH);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultMatchWithTimeoutOnPreprocessor)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 3, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("value1"), alloc), STRL("rule1"), alloc);
    ddwaf_object_set_invalid(
        ddwaf_object_insert_key(&parameter, STRL("server.request.body"), alloc));
    // Move the settings object to the parameter
    auto *settings = ddwaf_object_insert_key(&parameter, STRL("waf.context.processor"), alloc);
    ddwaf_object_set_map(settings, 1, alloc);
    ddwaf_object_set_bool(ddwaf_object_insert_key(settings, STRL("extract-schema"), alloc), true);

    ddwaf_object result;
    ddwaf_object_set_invalid(&result);
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, true, &result, 0), DDWAF_MATCH);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(keep));

    ddwaf_object_destroy(&result, alloc);
    ddwaf_context_destroy(context);
}

} // namespace
