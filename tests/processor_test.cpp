// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "generator/base.hpp"
#include "matcher/equals.hpp"
#include "processor.hpp"

#include <gmock/gmock.h>

using ::testing::_;
using ::testing::Return;

using namespace ddwaf;
using namespace std::literals;

namespace {

namespace mock {
class generator : public ddwaf::generator::base {
public:
    MOCK_METHOD(
        ddwaf_object, generate, (const ddwaf_object *input, ddwaf::timer &deadline), (override));
};

} // namespace mock

TEST(TestProcessor, SingleMappingOutputNoEvalUnconditional)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).WillOnce(Return(output));

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);

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

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _))
        .WillOnce(Return(first_output))
        .WillOnce(Return(second_output));

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

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address.first"), get_target_index("output_address.first"),
            "output_address.first"},
        {get_target_index("input_address.second"), get_target_index("output_address.second"),
            "output_address.second"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);

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

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).WillOnce(Return(output));

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, true));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    expression_builder builder(1);
    builder.start_condition<matcher::equals<bool>>(true);
    builder.add_target("enabled?");

    processor proc{"id", std::move(gen), builder.build(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);

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

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).WillOnce(Return(output));

    ddwaf_object tmp;
    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, true));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    expression_builder builder(1);
    builder.start_condition<matcher::equals<bool>>(true);
    builder.add_target("enabled?");

    processor proc{"id", std::move(gen), builder.build(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);
    EXPECT_EQ(ddwaf_object_size(&output_map), 0);

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    store.insert(input_map);

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);
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

    auto gen = std::make_unique<mock::generator>();

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, false));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    expression_builder builder(1);
    builder.start_condition<matcher::equals<bool>>(true);
    builder.add_target("enabled?");

    processor proc{"id", std::move(gen), builder.build(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);

    ddwaf_object_free(&output_map);
    ddwaf_object_free(&output);
}

TEST(TestProcessor, SingleMappingNoOutputEvalUnconditional)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).WillOnce(Return(output));

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor::cache_type cache;
    timer deadline{2s};

    optional_ref<ddwaf_object> derived{std::nullopt};

    {
        auto *obtained = store.get_target(get_target_index("output_address"));
        EXPECT_EQ(obtained, nullptr);
    }

    proc.eval(store, derived, cache, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address"));
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalTrue)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).WillOnce(Return(output));

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, true));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    expression_builder builder(1);
    builder.start_condition<matcher::equals<bool>>(true);
    builder.add_target("enabled?");

    processor proc{"id", std::move(gen), builder.build(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor::cache_type cache;
    timer deadline{2s};

    optional_ref<ddwaf_object> derived{std::nullopt};

    EXPECT_EQ(store.get_target(get_target_index("output_address")), nullptr);

    proc.eval(store, derived, cache, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address"));
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "output_string");
    }
}

TEST(TestProcessor, SingleMappingNoOutputEvalConditionalFalse)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    auto gen = std::make_unique<mock::generator>();

    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "enabled?", ddwaf_object_bool(&tmp, false));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    expression_builder builder(1);
    builder.start_condition<matcher::equals<bool>>(true);
    builder.add_target("enabled?");

    processor proc{"id", std::move(gen), builder.build(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor::cache_type cache;
    timer deadline{2s};

    optional_ref<ddwaf_object> derived{std::nullopt};

    EXPECT_EQ(store.get_target(get_target_index("output_address")), nullptr);
    proc.eval(store, derived, cache, deadline);

    EXPECT_EQ(store.get_target(get_target_index("output_address")), nullptr);

    ddwaf_object_free(&output);
}

TEST(TestProcessor, MultiMappingNoOutputEvalUnconditional)
{
    ddwaf_object first_output;
    ddwaf_object second_output;
    ddwaf_object_string(&first_output, "first_output_string");
    ddwaf_object_string(&second_output, "second_output_string");

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _))
        .WillOnce(Return(first_output))
        .WillOnce(Return(second_output));

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

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address.first"), get_target_index("output_address.first"),
            "output_address.first"},
        {get_target_index("input_address.second"), get_target_index("output_address.second"),
            "output_address.second"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{std::nullopt};

    EXPECT_EQ(store.get_target(get_target_index("output_address.first")), nullptr);
    EXPECT_EQ(store.get_target(get_target_index("output_address.second")), nullptr);

    proc.eval(store, derived, cache, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address.first"));
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "first_output_string");
    }

    {
        auto *obtained = store.get_target(get_target_index("output_address.second"));
        EXPECT_NE(obtained, nullptr);
        EXPECT_STREQ(obtained->stringValue, "second_output_string");
    }
}

TEST(TestProcessor, SingleMappingOutputEvalUnconditional)
{
    ddwaf_object output;
    ddwaf_object_string(&output, "output_string");

    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).WillOnce(Return(output));

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), true, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};

    optional_ref<ddwaf_object> derived{output_map};

    {
        auto *obtained = store.get_target(get_target_index("output_address"));
        EXPECT_EQ(obtained, nullptr);
        EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    }

    proc.eval(store, derived, cache, deadline);

    {
        auto *obtained = store.get_target(get_target_index("output_address"));
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
    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).Times(0);

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "output_address", ddwaf_object_null(&input));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);

    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, OutputAlreadyGenerated)
{
    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).Times(1);

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    ddwaf_object output_map;
    ddwaf_object_map(&output_map);

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{output_map};

    EXPECT_EQ(ddwaf_object_size(&output_map), 0);
    proc.eval(store, derived, cache, deadline);
    proc.eval(store, derived, cache, deadline);

    ddwaf_object_free(&output_map);
}

TEST(TestProcessor, EvalAlreadyAvailableInStore)
{
    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).Times(0);

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);
    ddwaf_object_map_add(&input_map, "output_address", ddwaf_object_null(&input));

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), true, false};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{};

    proc.eval(store, derived, cache, deadline);
}

TEST(TestProcessor, OutputWithoutDerivedMap)
{
    auto gen = std::make_unique<mock::generator>();
    EXPECT_CALL(*gen, generate(_, _)).Times(0);

    ddwaf_object input;
    ddwaf_object_string(&input, "input_string");

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "input_address", &input);

    object_store store;
    store.insert(input_map);

    std::vector<processor::target_mapping> mappings{
        {get_target_index("input_address"), get_target_index("output_address"), "output_address"}};

    processor proc{
        "id", std::move(gen), std::make_shared<expression>(), std::move(mappings), false, true};
    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor::cache_type cache;
    timer deadline{2s};
    optional_ref<ddwaf_object> derived{};

    proc.eval(store, derived, cache, deadline);
}

} // namespace
