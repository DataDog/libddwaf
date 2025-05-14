// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "attribute_collector.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestAttributeCollector, EmplaceNoCopy)
{
    ddwaf_object expected;
    ddwaf_object_string(&expected, "value");

    attribute_collector collector;
    collector.emplace("address", expected, false);

    object_store store;
    auto attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 1);

    const auto *obtained = ddwaf_object_get_index(&attributes, 0);
    EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);
    EXPECT_EQ(obtained->stringValue, expected.stringValue);
    EXPECT_STREQ(obtained->stringValue, expected.stringValue);

    ddwaf_object_free(&attributes);
}

TEST(TestAttributeCollector, EmplaceCopy)
{
    ddwaf_object expected;
    ddwaf_object_string(&expected, "value");

    attribute_collector collector;
    collector.emplace("address", expected, true);

    object_store store;
    auto attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 1);

    const auto *obtained = ddwaf_object_get_index(&attributes, 0);
    EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);
    EXPECT_NE(obtained->stringValue, expected.stringValue);
    EXPECT_STREQ(obtained->stringValue, expected.stringValue);

    ddwaf_object_free(&expected);
    ddwaf_object_free(&attributes);
}

TEST(TestAttributeCollector, CollectAvailableScalar)
{
    ddwaf_object tmp;
    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", ddwaf_object_string(&tmp, "value"));

    object_store store;
    store.insert(input_map);

    attribute_collector collector;
    collector.collect(store, get_target_index("input_address"), {}, "output_address");
    auto attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 1);

    const auto *expected = ddwaf_object_get_index(&input_map, 0);
    const auto *obtained = ddwaf_object_get_index(&attributes, 0);
    EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);
    EXPECT_NE(obtained->stringValue, expected->stringValue);
    EXPECT_STREQ(obtained->stringValue, expected->stringValue);

    ddwaf_object_free(&attributes);
}

TEST(TestAttributeCollector, CollectAvailableScalarFromArray)
{
    ddwaf_object tmp;
    ddwaf_object intermediate_array;
    ddwaf_object_array(&intermediate_array);
    ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value"));

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);

    object_store store;
    store.insert(input_map);

    attribute_collector collector;
    collector.collect(store, get_target_index("input_address"), {}, "output_address");
    auto attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 1);

    const auto *expected = ddwaf_object_get_index(ddwaf_object_get_index(&input_map, 0), 0);
    const auto *obtained = ddwaf_object_get_index(&attributes, 0);
    EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);
    EXPECT_NE(obtained->stringValue, expected->stringValue);
    EXPECT_STREQ(obtained->stringValue, expected->stringValue);

    ddwaf_object_free(&attributes);
}

TEST(TestAttributeCollector, CollectInvalidScalarFromArray)
{
    ddwaf_object tmp;
    ddwaf_object intermediate_array;
    ddwaf_object_array(&intermediate_array);
    ddwaf_object_array_add(&intermediate_array, ddwaf_object_map(&tmp));

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);

    object_store store;
    store.insert(input_map);

    attribute_collector collector;
    collector.collect(store, get_target_index("input_address"), {}, "output_address");
    auto attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 0);

    ddwaf_object_free(&attributes);
}

TEST(TestAttributeCollector, CollectUnavailableScalar)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    collector.collect(store, get_target_index("input_address"), {}, "output_address");

    auto attributes = collector.collect_pending(store);
    EXPECT_EQ(ddwaf_object_size(&attributes), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    ddwaf_object tmp;
    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", ddwaf_object_string(&tmp, "value"));

    store.insert(input_map);
    attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 1);

    const auto *expected = ddwaf_object_get_index(&input_map, 0);
    const auto *obtained = ddwaf_object_get_index(&attributes, 0);
    EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);
    EXPECT_NE(obtained->stringValue, expected->stringValue);
    EXPECT_STREQ(obtained->stringValue, expected->stringValue);

    ddwaf_object_free(&attributes);
}

TEST(TestAttributeCollector, CollectUnavailableScalarFromArray)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    collector.collect(store, get_target_index("input_address"), {}, "output_address");

    auto attributes = collector.collect_pending(store);
    EXPECT_EQ(ddwaf_object_size(&attributes), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    ddwaf_object tmp;
    ddwaf_object intermediate_array;
    ddwaf_object_array(&intermediate_array);
    ddwaf_object_array_add(&intermediate_array, ddwaf_object_string(&tmp, "value"));

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &intermediate_array);

    store.insert(input_map);
    attributes = collector.collect_pending(store);

    EXPECT_EQ(ddwaf_object_size(&attributes), 1);

    const auto *expected = ddwaf_object_get_index(ddwaf_object_get_index(&input_map, 0), 0);
    const auto *obtained = ddwaf_object_get_index(&attributes, 0);
    EXPECT_EQ(ddwaf_object_type(obtained), DDWAF_OBJ_STRING);
    EXPECT_NE(obtained->stringValue, expected->stringValue);
    EXPECT_STREQ(obtained->stringValue, expected->stringValue);

    ddwaf_object_free(&attributes);
}

} // namespace
