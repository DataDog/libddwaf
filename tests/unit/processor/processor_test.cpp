// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "attribute_collector.hpp"
#include "exception.hpp"
#include "matcher/equals.hpp"
#include "processor/base.hpp"

#include <gmock/gmock.h>

#include "common/gtest_utils.hpp"

using ::testing::_;
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

    MOCK_METHOD((std::pair<ddwaf_object, object_store::attribute>), eval_impl,
        (const unary_argument<const ddwaf_object *> &, processor_cache &, ddwaf::timer &), (const));
};

} // namespace mock

TEST(TestProcessor, SingleMappingOutputNoEvalUnconditional)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

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
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>{
            output, object_store::attribute::none}));

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    auto output_map = collector.get_available_attributes_and_reset();
    EXPECT_EQ(ddwaf_object_size(&output_map), 1);
    const auto *obtained = ddwaf_object_get_index(&output_map, 0);
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");

    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, MultiMappingOutputNoEvalUnconditional)
{
    ddwaf_object first_output;
    ddwaf_object second_output;
    ddwaf_object_string(&first_output, "first_output_string");
    ddwaf_object_string(&second_output, "second_output_string");

    ddwaf_object first_input;
    ddwaf_object second_input;
    ddwaf_object_string(&first_input, "first_input_string");
    ddwaf_object_string(&second_input, "second_input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address.first", &first_input);
    ddwaf_object_map_add(&input_map, "input_address.second", &second_input);

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
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>(
            first_output, object_store::attribute::none)))
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>(
            second_output, object_store::attribute::none)));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    auto output_map = collector.get_available_attributes_and_reset();
    EXPECT_EQ(ddwaf_object_size(&output_map), 2);
    {
        const auto *obtained = ddwaf_object_get_index(&output_map, 0);
        EXPECT_STREQ(obtained->parameterName, "output_address.first");
        EXPECT_STREQ(obtained->stringValue, "first_output_string");
    }

    {
        const auto *obtained = ddwaf_object_get_index(&output_map, 1);
        EXPECT_STREQ(obtained->parameterName, "output_address.second");
        EXPECT_STREQ(obtained->stringValue, "second_output_string");
    }

    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalTrue)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, true));

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
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>{
            output, object_store::attribute::none}));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    auto output_map = collector.get_available_attributes_and_reset();
    EXPECT_EQ(ddwaf_object_size(&output_map), 1);
    const auto *obtained = ddwaf_object_get_index(&output_map, 0);
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");

    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalCached)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object tmp;
    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, true));

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
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>{
            output, object_store::attribute::none}));

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    auto output_map = collector.get_available_attributes_and_reset();
    EXPECT_EQ(ddwaf_object_size(&output_map), 0);

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    store.insert(input_map);

    proc.eval(store, collector, cache, {}, deadline);

    output_map = collector.get_available_attributes_and_reset();
    EXPECT_EQ(ddwaf_object_size(&output_map), 1);

    const auto *obtained = ddwaf_object_get_index(&output_map, 0);
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");

    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, SingleMappingOutputNoEvalConditionalFalse)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, false));

    object_store store;
    store.insert(input_map);

    std::vector<processor_mapping> mappings{
        {{{{{get_target_index("input_address"), "input_address", {}}}}},
            {get_target_index("output_address"), "output_address", {}}}};

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
    proc.eval(store, collector, cache, {}, deadline);

    auto output_map = collector.get_available_attributes_and_reset();
    EXPECT_EQ(ddwaf_object_size(&output_map), 0);

    ddwaf_object_free(&output_map);
    ddwaf_object_free(&output);
}

TEST(TestProcessor, SingleMappingNoOutputEvalUnconditional)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

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
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>{
            output, object_store::attribute::none}));

    processor_cache cache;
    timer deadline{2s};

    {
        auto *obtained = store.get_target(get_target_index("output_address")).first;
        EXPECT_EQ(obtained, nullptr);
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address")).first;
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalTrue)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, true));

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

    mock::processor proc{"id", builder.build(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>{
            output, object_store::attribute::none}));
    processor_cache cache;

    timer deadline{2s};

    EXPECT_EQ(store.get_target(get_target_index("output_address")).first, nullptr);

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address")).first;
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalFalse)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, false));

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

    mock::processor proc{"id", builder.build(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};

    EXPECT_EQ(store.get_target(get_target_index("output_address")).first, nullptr);

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    EXPECT_EQ(store.get_target(get_target_index("output_address")).first, nullptr);

    ddwaf_object_free(&output);
}

TEST(TestProcessor, MultiMappingNoOutputEvalUnconditional)
{
    ddwaf_object first_output;
    ddwaf_object second_output;
    ddwaf_object_string(&first_output, "first_output_string");
    ddwaf_object_string(&second_output, "second_output_string");

    ddwaf_object first_input;
    ddwaf_object second_input;
    ddwaf_object_string(&first_input, "first_input_string");
    ddwaf_object_string(&second_input, "second_input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address.first", &first_input);
    ddwaf_object_map_add(&input_map, "input_address.second", &second_input);

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

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _))
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>(
            first_output, object_store::attribute::none)))
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>(
            second_output, object_store::attribute::none)));

    processor_cache cache;
    timer deadline{2s};

    EXPECT_EQ(store.get_target(get_target_index("output_address.first")).first, nullptr);
    EXPECT_EQ(store.get_target(get_target_index("output_address.second")).first, nullptr);

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address.first")).first;
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "first_output_string");
    }

    {
        auto *obtained = store.get_target(get_target_index("output_address.second")).first;
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "second_output_string");
    }
}

TEST(TestProcessor, SingleMappingOutputEvalUnconditional)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

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
        .WillOnce(Return(std::pair<ddwaf_object, object_store::attribute>{
            output, object_store::attribute::none}));

    processor_cache cache;
    timer deadline{2s};

    {
        auto *obtained = store.get_target(get_target_index("output_address")).first;
        EXPECT_EQ(obtained, nullptr);
    }

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);
    auto output_map = collector.get_available_attributes_and_reset();

    {
        auto *obtained = store.get_target(get_target_index("output_address")).first;
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }

    {
        EXPECT_EQ(ddwaf_object_size(&output_map), 1);
        const auto *obtained = ddwaf_object_get_index(&output_map, 0);
        EXPECT_STREQ(obtained->parameterName, "output_address");
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }
    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, OutputAlreadyAvailableInStore)
{
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "output_address", ddwaf_object_null(&input));

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
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _)).Times(0);

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);
}

TEST(TestProcessor, OutputAlreadyGenerated)
{
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

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
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    EXPECT_CALL(proc, eval_impl(_, _, _)).Times(1);

    processor_cache cache;
    timer deadline{2s};

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);
    proc.eval(store, collector, cache, {}, deadline);
}

TEST(TestProcessor, EvalAlreadyAvailableInStore)
{
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "output_address", ddwaf_object_null(&input));

    object_store store;
    store.insert(input_map);

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

    attribute_collector collector;
    proc.eval(store, collector, cache, {}, deadline);
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

    attribute_collector collector;
    EXPECT_THROW(proc.eval(store, collector, cache, {}, deadline), ddwaf::timeout_exception);
}

} // namespace
