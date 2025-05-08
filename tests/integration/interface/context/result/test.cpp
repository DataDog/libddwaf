// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

#include <memory_resource>
#include <new>
using namespace ddwaf;

namespace {

constexpr std::string_view base_dir = "integration/interface/context/result/";

TEST(TestContextResultIntegration, ResultInvalidArgumentNullContext)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object tmp;
    ddwaf_object persistent = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&persistent, "value1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object result;
    ddwaf_object_invalid(&result);

    EXPECT_EQ(
        ddwaf_run(nullptr, &persistent, nullptr, &result, LONG_TIME), DDWAF_ERR_INVALID_ARGUMENT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_INVALID);

    ddwaf_object_free(&persistent);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultInvalidArgumentNoData)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object result;
    ddwaf_object_invalid(&result);

    EXPECT_EQ(ddwaf_run(context, nullptr, nullptr, &result, LONG_TIME), DDWAF_ERR_INVALID_ARGUMENT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_INVALID);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultInvalidObjectInvalidPersistentDataSchema)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;
    ddwaf_object persistent = DDWAF_OBJECT_ARRAY;
    ddwaf_object_array_add(&persistent, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object result;
    ddwaf_object_invalid(&result);

    EXPECT_EQ(
        ddwaf_run(context, &persistent, nullptr, &result, LONG_TIME), DDWAF_ERR_INVALID_OBJECT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_INVALID);

    // The persistent object, even though invalid, is freed on context destruction
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultInvalidObjectInvalidEphemeralDataSchema)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object tmp;
    ddwaf_object ephemeral = DDWAF_OBJECT_ARRAY;
    ddwaf_object_array_add(&ephemeral, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object result;
    ddwaf_object_invalid(&result);

    EXPECT_EQ(
        ddwaf_run(context, nullptr, &ephemeral, &result, LONG_TIME), DDWAF_ERR_INVALID_OBJECT);

    // The result object must be unchanged
    EXPECT_EQ(ddwaf_object_type(&result), DDWAF_OBJ_INVALID);

    // The ephemeral object, even though invalid, is freed on context destruction
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestContextResultIntegration, ResultOk)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "value1", ddwaf_object_invalid(&tmp));

    ddwaf_object result;
    ddwaf_object_invalid(&result);
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(events), 0);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_free(&result);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultOkWithAttributes)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "server.request.body", ddwaf_object_invalid(&tmp));

    ddwaf_object settings;
    ddwaf_object_map(&settings);
    ddwaf_object_map_add(&settings, "extract-schema", ddwaf_object_bool(&tmp, true));
    ddwaf_object_map_add(&parameter, "waf.context.processor", &settings);

    ddwaf_object result;
    ddwaf_object_invalid(&result);
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &result, LONG_TIME), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(events), 0);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(attributes), 1);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_free(&result);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultOkWithTimeout)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "value1", ddwaf_object_invalid(&tmp));

    ddwaf_object result;
    ddwaf_object_invalid(&result);
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &result, 0), DDWAF_OK);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(events), 0);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_free(&result);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultMatch)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object result;
    ddwaf_object_invalid(&result);
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &result, LONG_TIME), DDWAF_MATCH);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_free(&result);
    ddwaf_context_destroy(context);
}

TEST(TestContextResultIntegration, ResultMatchWithTimeout)
{
    auto rule = read_file("interface.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object tmp;
    ddwaf_object parameter = DDWAF_OBJECT_MAP;
    ddwaf_object_map_add(&parameter, "value1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object result;
    ddwaf_object_invalid(&result);
    EXPECT_EQ(ddwaf_run(context, &parameter, nullptr, &result, 0), DDWAF_MATCH);

    const auto *events = ddwaf_object_find(&result, STRL("events"));
    ASSERT_NE(events, nullptr);
    EXPECT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_size(events), 1);

    const auto *actions = ddwaf_object_find(&result, STRL("actions"));
    ASSERT_NE(actions, nullptr);
    EXPECT_EQ(ddwaf_object_type(actions), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(actions), 0);

    const auto *timeout = ddwaf_object_find(&result, STRL("timeout"));
    ASSERT_NE(timeout, nullptr);
    EXPECT_EQ(ddwaf_object_type(timeout), DDWAF_OBJ_BOOL);
    EXPECT_TRUE(ddwaf_object_get_bool(timeout));

    const auto *duration = ddwaf_object_find(&result, STRL("duration"));
    ASSERT_NE(duration, nullptr);
    EXPECT_EQ(ddwaf_object_type(duration), DDWAF_OBJ_UNSIGNED);
    EXPECT_GT(ddwaf_object_get_unsigned(duration), 0);

    const auto *attributes = ddwaf_object_find(&result, STRL("attributes"));
    ASSERT_NE(attributes, nullptr);
    EXPECT_EQ(ddwaf_object_type(attributes), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_size(attributes), 0);

    const auto *keep = ddwaf_object_find(&result, STRL("keep"));
    ASSERT_NE(keep, nullptr);
    EXPECT_EQ(ddwaf_object_type(keep), DDWAF_OBJ_BOOL);
    EXPECT_FALSE(ddwaf_object_get_bool(keep));

    ddwaf_object_free(&result);
    ddwaf_context_destroy(context);
}

} // namespace
