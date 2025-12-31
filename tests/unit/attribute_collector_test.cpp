// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2025 Datadog, Inc.

#include "attribute_collector.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestAttributeCollector, InsertNoCopy)
{
    std::string_view expected = "value";
    owned_object input = test::ddwaf_object_da::make_string(expected);

    attribute_collector collector;
    EXPECT_TRUE(collector.insert("address", std::move(input)));

    object_store store;
    collector.collect_pending(store);
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, InsertDuplicate)
{
    std::string_view expected = "value";
    owned_object input = test::ddwaf_object_da::make_string(expected);

    attribute_collector collector;
    EXPECT_TRUE(collector.insert("address", input.clone(memory::get_default_resource())));
    EXPECT_FALSE(collector.insert("address", std::move(input)));

    object_store store;
    collector.collect_pending(store);
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableScalar)
{
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address", expected}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableKeyPathScalar)
{
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map({{"first", object_builder_da::map({{"second", expected}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
    EXPECT_TRUE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableKeyPathSingleValueArray)
{
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map({{"first",
            object_builder_da::map({{"second", object_builder_da::array({expected})}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
    EXPECT_TRUE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableKeyPathMultiValueArray)
{
    std::string_view expected = "value0";
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map(
            {{"first", object_builder_da::map({{"second",
                           object_builder_da::array({expected, "value1", "value2"})}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
    EXPECT_TRUE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableKeyPathWithinArrayPositiveIndex)
{
    std::string_view expected = "value1";
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map(
            {{"first", object_builder_da::map({{"second",
                           object_builder_da::array({"value0", expected, "value2"})}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second", 1};
    EXPECT_TRUE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableKeyPathWithinArrayNegativeIndex)
{
    std::string_view expected = "value1";
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map(
            {{"first", object_builder_da::map({{"second",
                           object_builder_da::array({"value0", expected, "value2"})}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second", -2};
    EXPECT_TRUE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectUnavailableKeyPath)
{
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map({{"first", object_builder_da::map({{"second",
                                              object_builder_da::map({{"third", "value"}})}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
    EXPECT_FALSE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 0);
}

TEST(TestAttributeCollector, CollectPendingKeyPathScalar)
{
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address",
        object_builder_da::map({{"first", object_builder_da::map({{"second", expected}})}})}});
    object_store store;

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
    EXPECT_TRUE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);
    EXPECT_TRUE(collector.has_pending_attributes());

    store.insert(std::move(input));
    collector.collect_pending(store);
    attributes = collector.get_available_attributes_and_reset();
    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableKeyPathInvalidValue)
{
    auto input = object_builder_da::map(
        {{"input_address", object_builder_da::map({{"first",
                               object_builder_da::map({{"second", object_builder_da::map()}})}})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    std::vector<std::variant<std::string, int64_t>> key_path{"first", "second"};
    EXPECT_FALSE(
        collector.collect(store, get_target_index("input_address"), key_path, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 0);
}

TEST(TestAttributeCollector, CollectDuplicateScalar)
{
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address", expected}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    EXPECT_FALSE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableScalarFromSingleValueArray)
{
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address", object_builder_da::array({expected})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectAvailableScalarFromMultiValueArray)
{
    std::string_view expected = "value0";
    auto input = object_builder_da::map(
        {{"input_address", object_builder_da::array({expected, "value1", "value2"})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectInvalidObjectFromArray)
{
    auto input = object_builder_da::map(
        {{"input_address", object_builder_da::array({object_builder_da::map()})}});

    object_store store;
    store.insert(std::move(input));

    attribute_collector collector;
    EXPECT_FALSE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    auto attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 0);
}

TEST(TestAttributeCollector, CollectUnavailableScalar)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    EXPECT_TRUE(collector.has_pending_attributes());

    collector.collect_pending(store);
    EXPECT_TRUE(collector.has_pending_attributes());

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address", expected}});

    store.insert(std::move(input));
    collector.collect_pending(store);
    EXPECT_FALSE(collector.has_pending_attributes());

    attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectUnavailableScalarFromSingleValueArray)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    EXPECT_TRUE(collector.has_pending_attributes());

    collector.collect_pending(store);
    EXPECT_TRUE(collector.has_pending_attributes());

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    std::string_view expected = "value";
    auto input = object_builder_da::map({{"input_address", object_builder_da::array({expected})}});

    store.insert(std::move(input));
    collector.collect_pending(store);
    EXPECT_FALSE(collector.has_pending_attributes());

    attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectUnavailableScalarFromMultiValueArray)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    EXPECT_TRUE(collector.has_pending_attributes());

    collector.collect_pending(store);
    EXPECT_TRUE(collector.has_pending_attributes());

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    std::string_view expected = "value0";
    auto input = object_builder_da::map(
        {{"input_address", object_builder_da::array({expected, "value1", "value2"})}});

    store.insert(std::move(input));
    collector.collect_pending(store);
    EXPECT_FALSE(collector.has_pending_attributes());

    attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectUnavailableKeyPathFromWithinArrayPositiveIndex)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    std::vector<std::variant<std::string, int64_t>> kp{0};
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), kp, "output_address"));
    EXPECT_TRUE(collector.has_pending_attributes());

    collector.collect_pending(store);
    EXPECT_TRUE(collector.has_pending_attributes());

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    std::string_view expected = "value0";
    auto input = object_builder_da::map(
        {{"input_address", object_builder_da::array({expected, "value1", "value2"})}});

    store.insert(std::move(input));
    collector.collect_pending(store);
    EXPECT_FALSE(collector.has_pending_attributes());

    attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectUnavailableKeyPathFromWithinArrayNegativeIndex)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    std::vector<std::variant<std::string, int64_t>> kp{-3};
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), kp, "output_address"));
    EXPECT_TRUE(collector.has_pending_attributes());

    collector.collect_pending(store);
    EXPECT_TRUE(collector.has_pending_attributes());

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    std::string_view expected = "value0";
    auto input = object_builder_da::map(
        {{"input_address", object_builder_da::array({expected, "value1", "value2"})}});

    store.insert(std::move(input));
    collector.collect_pending(store);
    EXPECT_FALSE(collector.has_pending_attributes());

    attributes = collector.get_available_attributes_and_reset();

    EXPECT_FALSE(collector.has_pending_attributes());

    EXPECT_EQ(attributes.size(), 1);

    const auto obtained = attributes.at(0);
    EXPECT_TRUE(obtained.is_string());
    EXPECT_STRV(obtained.as<std::string_view>(), expected);
}

TEST(TestAttributeCollector, CollectUnavailableInvalidObject)
{
    object_store store;
    attribute_collector collector;

    // The attribute should be in the pending queue
    EXPECT_TRUE(collector.collect(store, get_target_index("input_address"), {}, "output_address"));
    EXPECT_TRUE(collector.has_pending_attributes());

    collector.collect_pending(store);
    EXPECT_TRUE(collector.has_pending_attributes());

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    // After adding the attribute, collect_pending should extract, copy and return
    // the expected attribute
    auto input = object_builder_da::map({{"input_address", object_builder_da::array()}});

    store.insert(std::move(input));
    collector.collect_pending(store);
    EXPECT_FALSE(collector.has_pending_attributes());

    attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);
}

TEST(TestAttributeCollector, CollectMultipleUnavailableScalars)
{
    object_store store;
    attribute_collector collector;

    {
        // The attribute should be in the pending queue
        EXPECT_TRUE(
            collector.collect(store, get_target_index("input_address_0"), {}, "output_address_0"));
        EXPECT_TRUE(collector.has_pending_attributes());

        // Nothing to be collected
        collector.collect_pending(store);
        EXPECT_TRUE(collector.has_pending_attributes());

        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 0);
    }

    {
        // The attribute should be in the pending queue
        EXPECT_TRUE(
            collector.collect(store, get_target_index("input_address_1"), {}, "output_address_1"));
        EXPECT_TRUE(collector.has_pending_attributes());

        // Nothing to be collected
        collector.collect_pending(store);
        EXPECT_TRUE(collector.has_pending_attributes());

        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 0);
    }

    {
        // After adding the attribute, collect_pending should extract, copy and return
        // the expected attribute
        std::string_view expected = "value";
        auto input = object_builder_da::map({{"input_address_0", expected}});

        store.insert(std::move(input));

        EXPECT_TRUE(
            collector.collect(store, get_target_index("input_address_2"), {}, "output_address_2"));

        collector.collect_pending(store);
        EXPECT_TRUE(collector.has_pending_attributes());

        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 1);

        const auto obtained = attributes.at(0);
        EXPECT_TRUE(obtained.is_string());
        EXPECT_STRV(obtained.as<std::string_view>(), expected);
    }

    {
        // After adding the attribute, collect_pending should extract, copy and return
        // the expected attribute

        std::string_view expected = "value";
        auto input = object_builder_da::map({{"input_address_2", expected}});
        store.insert(std::move(input));

        collector.collect_pending(store);
        EXPECT_TRUE(collector.has_pending_attributes());

        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 1);

        const auto obtained = attributes.at(0);
        EXPECT_TRUE(obtained.is_string());
        EXPECT_STRV(obtained.as<std::string_view>(), expected);
    }

    {
        // After adding the attribute, collect_pending should extract, copy and return
        // the expected attribute

        std::string_view expected = "value";
        auto input = object_builder_da::map({{"input_address_1", expected}});

        store.insert(std::move(input));

        collector.collect_pending(store);
        EXPECT_FALSE(collector.has_pending_attributes());

        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 1);

        const auto obtained = attributes.at(0);
        EXPECT_TRUE(obtained.is_string());
        EXPECT_STRV(obtained.as<std::string_view>(), expected);
    }
}

} // namespace
