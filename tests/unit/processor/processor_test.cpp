// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "exception.hpp"
#include "matcher/equals.hpp"
#include "processor/base.hpp"

#include <gmock/gmock.h>

#include "common/gtest_utils.hpp"

using ::testing::_;
using ::testing::ByMove;
using ::testing::Return;

using namespace ddwaf;
using namespace std::literals;

namespace {

namespace mock {
class processor : public ddwaf::structured_processor<processor> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    processor(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    MOCK_METHOD((owned_object), eval_impl,
        (const unary_argument<object_view> &, processor_cache &,
            nonnull_ptr<memory::memory_resource>, ddwaf::timer &),
        (const));
};

} // namespace mock

TEST(TestProcessor, SingleMappingOutputNoEvalUnconditional)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({{"input_address", "input_string"}});
    object_store store;
    store.insert(input_map);

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 1);
    const auto [obtained_key, obtained_value] = object_view{attributes}.at(0);
    EXPECT_STRV(obtained_key.as<std::string_view>(), "output_address");
    EXPECT_STRV(obtained_value.as<std::string_view>(), "output_string");
}

TEST(TestProcessor, MultiMappingOutputNoEvalUnconditional)
{
    auto *alloc = memory::get_default_resource();

    owned_object first_output = owned_object::make_string("first_output_string");
    owned_object second_output = owned_object::make_string("second_output_string");

    auto input_map = object_builder::map(
        {{"input_address", "first_input_string"}, {"input_address.second", "second_input_string"}});

    object_store store;
    store.insert(input_map);

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}},
        {.inputs = {{{{.index = get_target_index("input_address.second"),
             .name = "input_address.second",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address.second"),
                .name = "output_address.second",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object(std::move(first_output)))))
        .WillOnce(Return(ByMove(owned_object(std::move(second_output)))));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 2);
    {
        const auto [obtained_key, obtained_value] = object_view{attributes}.at(0);
        EXPECT_STRV(obtained_key.as<std::string_view>(), "output_address");
        EXPECT_STRV(obtained_value.as<std::string_view>(), "first_output_string");
    }

    {
        const auto [obtained_key, obtained_value] = object_view{attributes}.at(1);
        EXPECT_STRV(obtained_key.as<std::string_view>(), "output_address.second");
        EXPECT_STRV(obtained_value.as<std::string_view>(), "second_output_string");
    }
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalTrue)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({{"input_address", "input_string"}, {"enabled?", true}});

    object_store store;
    store.insert(input_map);

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("enabled?");
    builder.end_condition<matcher::equals<bool>>(true);

    mock::processor proc{"id", builder.build(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 1);
    const auto [obtained_key, obtained_value] = object_view{attributes}.at(0);
    EXPECT_STRV(obtained_key.as<std::string_view>(), "output_address");
    EXPECT_STRV(obtained_value.as<std::string_view>(), "output_string");
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalCached)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({{"enabled?", true}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("enabled?");
    builder.end_condition<matcher::equals<bool>>(true);

    mock::processor proc{"id", builder.build(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    input_map = object_builder::map({
        {"input_address", "input_string"},
    });

    store.insert(std::move(input_map));

    proc.eval(store, collector, cache, alloc, deadline);
    attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 1);

    const auto [obtained_key, obtained_value] = object_view{attributes}.at(0);
    EXPECT_STRV(obtained_key.as<std::string_view>(), "output_address");
    EXPECT_STRV(obtained_value.as<std::string_view>(), "output_string");
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalFalse)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({{"input_address", "input_string"}, {"enabled?", false}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("enabled?");
    builder.end_condition<matcher::equals<bool>>(true);

    mock::processor proc{"id", builder.build(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);
}

TEST(TestProcessor, SingleMappingNoOutputEvalUnconditional)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({
        {"input_address", "input_string"},
    });

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));

    processor_cache cache;
    timer deadline{2s};

    owned_object attributes;

    {
        auto obtained = store.get_target("output_address");
        EXPECT_FALSE(obtained.has_value());
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    {
        auto obtained = store.get_target("output_address");
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalTrue)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({{"input_address", "input_string"}, {"enabled?", true}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("enabled?");
    builder.end_condition<matcher::equals<bool>>(true);

    mock::processor proc{"id", builder.build(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));
    processor_cache cache;

    timer deadline{2s};

    owned_object attributes;

    EXPECT_FALSE(store.get_target("output_address").has_value());

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    {
        auto obtained = store.get_target("output_address");
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalFalse)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({{"input_address", "input_string"}, {"enabled?", false}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("enabled?");
    builder.end_condition<matcher::equals<bool>>(true);

    mock::processor proc{"id", builder.build(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};

    owned_object attributes;

    EXPECT_FALSE(store.get_target("output_address").has_value());
    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    EXPECT_FALSE(store.get_target("output_address").has_value());
}

TEST(TestProcessor, MultiMappingNoOutputEvalUnconditional)
{
    auto *alloc = memory::get_default_resource();

    owned_object first_output = owned_object::make_string("first_output_string");
    owned_object second_output = owned_object::make_string("second_output_string");

    auto input_map = object_builder::map(
        {{"input_address", "first_input_string"}, {"input_address.second", "second_input_string"}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}},
        {.inputs = {{{{.index = get_target_index("input_address.second"),
             .name = "input_address.second",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address.second"),
                .name = "output_address.second",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object(std::move(first_output)))))
        .WillOnce(Return(ByMove(owned_object(std::move(second_output)))));

    processor_cache cache;
    timer deadline{2s};
    owned_object attributes;

    EXPECT_FALSE(store.get_target("output_address").has_value());
    EXPECT_FALSE(store.get_target("output_address.second").has_value());

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    {
        auto obtained = store.get_target("output_address");
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "first_output_string");
    }

    {
        auto obtained = store.get_target("output_address.second");
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "second_output_string");
    }
}

TEST(TestProcessor, SingleMappingOutputEvalUnconditional)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({
        {"input_address", "input_string"},
    });

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));

    processor_cache cache;
    timer deadline{2s};

    {
        auto obtained = store.get_target("output_address");
        EXPECT_FALSE(obtained.has_value());
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    {
        auto obtained = store.get_target("output_address");
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }

    {
        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 1);
        const auto [obtained_key, obtained_value] = object_view{attributes}.at(0);
        EXPECT_STRV(obtained_key.as<std::string_view>(), "output_address");
        EXPECT_STRV(obtained_value.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, OutputAlreadyAvailableInStore)
{
    auto *alloc = memory::get_default_resource();

    auto input_map = object_builder::map(
        {{"input_address", "input_string"}, {"output_address", owned_object::make_null()}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _)).Times(0);

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);
}

TEST(TestProcessor, OutputAlreadyGenerated)
{
    auto *alloc = memory::get_default_resource();

    auto input_map = object_builder::map({
        {"input_address", "input_string"},
    });

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _)).Times(1);

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);
    proc.eval(store, collector, cache, alloc, deadline);
}

TEST(TestProcessor, EvalAlreadyAvailableInStore)
{
    auto *alloc = memory::get_default_resource();

    auto input_map = object_builder::map(
        {{"input_address", "input_string"}, {"output_address", owned_object::make_null()}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _)).Times(0);

    processor_cache cache;
    timer deadline{2s};
    owned_object attributes;

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);
}

TEST(TestProcessor, OutputEvalWithoutattributesMap)
{
    auto *alloc = memory::get_default_resource();

    owned_object output = owned_object::make_string("output_string");

    auto input_map = object_builder::map({
        {"input_address", "input_string"},
    });

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _))
        .WillOnce(Return(ByMove(owned_object{std::move(output)})));

    processor_cache cache;
    timer deadline{2s};

    owned_object attributes;

    {
        auto obtained = store.get_target("output_address");
        EXPECT_FALSE(obtained.has_value());
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, alloc, deadline);

    {
        auto obtained = store.get_target("output_address");
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, Timeout)
{
    auto *alloc = memory::get_default_resource();

    object_store store;

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address"),
             .name = "input_address",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address"),
                .name = "output_address",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _, _)).Times(0);

    processor_cache cache;
    timer deadline{0s};
    owned_object attributes;

    attribute_collector collector;
    EXPECT_THROW(proc.eval(store, collector, cache, alloc, deadline), ddwaf::timeout_exception);
}

} // namespace
