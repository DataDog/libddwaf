// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(test_metrics, no_rule)
{
    auto rule = readFile("metrics.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_metrics_collector collector;
    collector = ddwaf_metrics_collector_init(handle);

    ddwaf_context context = ddwaf_context_init(handle, NULL);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "what"));
    ddwaf_object_map_add(&parameter, "value4", &param_val);

    EXPECT_EQ(ddwaf_run(context, &parameter, collector, NULL, LONG_TIME), DDWAF_GOOD);

    ddwaf_metrics metrics;
    ddwaf_get_metrics(collector, &metrics);

    ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
    EXPECT_EQ(rule_runtime.size(), 0);

    ddwaf_metrics_free(&metrics);
    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);

    ddwaf_metrics_collector_destroy(collector);
    ddwaf_destroy(handle);
}

TEST(test_metrics, single_context_single_rule)
{
    auto rule = readFile("metrics.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_metrics_collector collector;
    collector = ddwaf_metrics_collector_init(handle);

    ddwaf_context context = ddwaf_context_init(handle, NULL);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));
    ddwaf_object_map_add(&parameter, "value1", &param_val);

    EXPECT_EQ(ddwaf_run(context, &parameter, collector, NULL, LONG_TIME), DDWAF_MONITOR);

    ddwaf_metrics metrics;
    ddwaf_get_metrics(collector, &metrics);

    ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
    EXPECT_EQ(rule_runtime.size(), 1);
    EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "1"), 0);

    ddwaf_metrics_free(&metrics);
    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);

    ddwaf_metrics_collector_destroy(collector);
    ddwaf_destroy(handle);
}

TEST(test_metrics, single_context_multiple_rules)
{
    auto rule = readFile("metrics.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_metrics_collector collector;
    collector = ddwaf_metrics_collector_init(handle);

    ddwaf_context context = ddwaf_context_init(handle, NULL);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));
    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map_add(&parameter, "value12", &param_val);

    EXPECT_EQ(ddwaf_run(context, &parameter, collector, NULL, LONG_TIME), DDWAF_MONITOR);

    ddwaf_metrics metrics;
    ddwaf_get_metrics(collector, &metrics);
    EXPECT_GE(metrics.total_runtime, 0);

    ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
    EXPECT_EQ(rule_runtime.size(), 2);
    EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "1"), 0);
    EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "2"), 0);

    ddwaf_metrics_free(&metrics);
    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);

    ddwaf_metrics_collector_destroy(collector);
    ddwaf_destroy(handle);
}

TEST(test_metrics, multiple_contexts_single_rule)
{
    auto rule = readFile("metrics.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_metrics_collector collector;
    collector = ddwaf_metrics_collector_init(handle);

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value1", &param_val);

        ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);

        EXPECT_EQ(ddwaf_run(context, &parameter, collector, nullptr, LONG_TIME), DDWAF_MONITOR);

        ddwaf_metrics metrics;
        ddwaf_get_metrics(collector, &metrics);
        EXPECT_GE(metrics.total_runtime, 0);

        ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
        EXPECT_EQ(rule_runtime.size(), 1);
        EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "1"), 0);

        ddwaf_metrics_free(&metrics);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value1", &param_val);

        ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);

        EXPECT_EQ(ddwaf_run(context, &parameter, collector, nullptr, LONG_TIME), DDWAF_MONITOR);

        ddwaf_metrics metrics;
        ddwaf_get_metrics(collector, &metrics);
        EXPECT_GE(metrics.total_runtime, 0);

        ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
        EXPECT_EQ(rule_runtime.size(), 1);
        EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "1"), 0);

        ddwaf_metrics_free(&metrics);
        ddwaf_context_destroy(context);
    }

    ddwaf_metrics_collector_destroy(collector);
    ddwaf_destroy(handle);
}

TEST(test_metrics, multiple_contexts_multiple_rules)
{
    auto rule = readFile("metrics.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_metrics_collector collector;
    collector = ddwaf_metrics_collector_init(handle);

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));
        ddwaf_object_map_add(&parameter, "value1", &param_val);

        ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);

        EXPECT_EQ(ddwaf_run(context, &parameter, collector, nullptr, LONG_TIME), DDWAF_MONITOR);

        ddwaf_metrics metrics;
        ddwaf_get_metrics(collector, &metrics);
        EXPECT_GE(metrics.total_runtime, 0);

        ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
        EXPECT_EQ(rule_runtime.size(), 1);
        EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "1"), 0);

        ddwaf_metrics_free(&metrics);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
        ddwaf_object param_val = DDWAF_OBJECT_ARRAY;

        ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule3"));
        ddwaf_object_map_add(&parameter, "value3", &param_val);

        ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);

        EXPECT_EQ(ddwaf_run(context, &parameter, collector, nullptr, LONG_TIME), DDWAF_MONITOR);

        ddwaf_metrics metrics;
        ddwaf_get_metrics(collector, &metrics);
        EXPECT_GE(metrics.total_runtime, 0);

        ddwaf::parameter::map rule_runtime = ddwaf::parameter(metrics.rule_runtime);
        EXPECT_EQ(rule_runtime.size(), 2);
        EXPECT_GT(ddwaf::parser::at<uint64_t>(rule_runtime, "3"), 0);

        ddwaf_metrics_free(&metrics);
        ddwaf_context_destroy(context);
    }

    ddwaf_metrics_collector_destroy(collector);
    ddwaf_destroy(handle);
}
