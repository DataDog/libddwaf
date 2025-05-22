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

    MOCK_METHOD((std::pair<owned_object, object_store::attribute>), eval_impl,
        (const unary_argument<object_view> &, processor_cache &, ddwaf::timer &), (const));
};

} // namespace mock

TEST(TestProcessor, SingleMappingOutputNoEvalUnconditional)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map = owned_object::make_map({{"input_address", "input_string"}});
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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 1);
    const auto *obtained = attributes.at(0).ptr();
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");
}

TEST(TestProcessor, MultiMappingOutputNoEvalUnconditional)
{
    owned_object first_output = owned_object::make_string("first_output_string");
    owned_object second_output = owned_object::make_string("second_output_string");

    auto input_map = owned_object::make_map({{"input_address.first", "first_input_string"},
        {"input_address.second", "second_input_string"}});

    object_store store;
    store.insert(input_map);

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address.first"),
             .name = "input_address.first",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address.first"),
                .name = "output_address.first",
                .key_path = {}}},
        {.inputs = {{{{.index = get_target_index("input_address.second"),
             .name = "input_address.second",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address.second"),
                .name = "output_address.second",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>(
            std::move(first_output), object_store::attribute::none))))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>(
            std::move(second_output), object_store::attribute::none))));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 2);
    {
        const auto *obtained = attributes.at(0).ptr();
        EXPECT_STREQ(obtained->parameterName, "output_address.first");
        EXPECT_STREQ(obtained->stringValue, "first_output_string");
    }

    {
        const auto *obtained = attributes.at(1).ptr();
        EXPECT_STREQ(obtained->parameterName, "output_address.second");
        EXPECT_STREQ(obtained->stringValue, "second_output_string");
    }
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalTrue)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map =
        owned_object::make_map({{"input_address", "input_string"}, {"enabled?", true}});

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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 1);
    const auto *obtained = attributes.at(0).ptr();
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalCached)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map = owned_object::make_map({{"enabled?", true}});

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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);

    input_map = owned_object::make_map({
        {"input_address", "input_string"},
    });

    store.insert(std::move(input_map));

    proc.eval(store, collector, cache, deadline);
    attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 1);

    const auto *obtained = attributes.at(0).ptr();
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalFalse)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map =
        owned_object::make_map({{"input_address", "input_string"}, {"enabled?", false}});

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
    proc.eval(store, collector, cache, deadline);

    auto attributes = collector.get_available_attributes_and_reset();
    EXPECT_EQ(attributes.size(), 0);
}

TEST(TestProcessor, SingleMappingNoOutputEvalUnconditional)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map = owned_object::make_map({
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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    processor_cache cache;
    timer deadline{2s};

    owned_object attributes;

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_FALSE(obtained.has_value());
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalTrue)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map =
        owned_object::make_map({{"input_address", "input_string"}, {"enabled?", true}});

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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));
    processor_cache cache;

    timer deadline{2s};

    owned_object attributes;

    EXPECT_FALSE(store.get_target("output_address").first.has_value());

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalFalse)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map =
        owned_object::make_map({{"input_address", "input_string"}, {"enabled?", false}});

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

    EXPECT_FALSE(store.get_target("output_address").first.has_value());
    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    EXPECT_FALSE(store.get_target("output_address").first.has_value());
}

TEST(TestProcessor, MultiMappingNoOutputEvalUnconditional)
{
    owned_object first_output = owned_object::make_string("first_output_string");
    owned_object second_output = owned_object::make_string("second_output_string");

    auto input_map = owned_object::make_map({{"input_address.first", "first_input_string"},
        {"input_address.second", "second_input_string"}});

    object_store store;
    store.insert(std::move(input_map));

    std::vector<processor_mapping> mappings{
        {.inputs = {{{{.index = get_target_index("input_address.first"),
             .name = "input_address.first",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address.first"),
                .name = "output_address.first",
                .key_path = {}}},
        {.inputs = {{{{.index = get_target_index("input_address.second"),
             .name = "input_address.second",
             .key_path = {}}}}},
            .output = {.index = get_target_index("output_address.second"),
                .name = "output_address.second",
                .key_path = {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>(
            std::move(first_output), object_store::attribute::none))))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>(
            std::move(second_output), object_store::attribute::none))));

    processor_cache cache;
    timer deadline{2s};
    owned_object attributes;

    EXPECT_FALSE(store.get_target("output_address.first").first.has_value());
    EXPECT_FALSE(store.get_target("output_address.second").first.has_value());

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    {
        auto obtained = store.get_target("output_address.first").first;
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "first_output_string");
    }

    {
        auto obtained = store.get_target("output_address.second").first;
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "second_output_string");
    }
}

TEST(TestProcessor, SingleMappingOutputEvalUnconditional)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map = owned_object::make_map({
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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    processor_cache cache;
    timer deadline{2s};

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_FALSE(obtained.has_value());
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }

    {
        auto attributes = collector.get_available_attributes_and_reset();
        EXPECT_EQ(attributes.size(), 1);
        const auto *obtained = attributes.at(0).ptr();
        EXPECT_STREQ(obtained->parameterName, "output_address");
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }
}

TEST(TestProcessor, OutputAlreadyAvailableInStore)
{
    auto input_map =
        owned_object::make_map({{"input_address", "input_string"}, {"output_address", nullptr}});

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

    EXPECT_CALL(proc, eval_impl(_, _, _)).Times(0);

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);
}

TEST(TestProcessor, OutputAlreadyGenerated)
{
    auto input_map = owned_object::make_map({
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

    EXPECT_CALL(proc, eval_impl(_, _, _)).Times(1);

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);
    proc.eval(store, collector, cache, deadline);
}

TEST(TestProcessor, EvalAlreadyAvailableInStore)
{
    auto input_map =
        owned_object::make_map({{"input_address", "input_string"}, {"output_address", nullptr}});

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

    EXPECT_CALL(proc, eval_impl(_, _, _)).Times(0);

    processor_cache cache;
    timer deadline{2s};
    owned_object attributes;

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);
}

TEST(TestProcessor, OutputEvalWithoutattributesMap)
{
    owned_object output = owned_object::make_string("output_string");

    auto input_map = owned_object::make_map({
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

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    processor_cache cache;
    timer deadline{2s};

    owned_object attributes;

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_FALSE(obtained.has_value());
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, deadline);

    {
        auto obtained = store.get_target("output_address").first;
        EXPECT_TRUE(obtained.has_value());
        EXPECT_STRV(obtained.as<std::string_view>(), "output_string");
    }
}

TEST(TestProcessor, Timeout)
{
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

    EXPECT_CALL(proc, eval_impl(_, _, _)).Times(0);

    processor_cache cache;
    timer deadline{0s};
    owned_object attributes;

    attribute_collector collector;
    EXPECT_THROW(proc.eval(store, collector, cache, deadline), ddwaf::timeout_exception);
}

} // namespace
