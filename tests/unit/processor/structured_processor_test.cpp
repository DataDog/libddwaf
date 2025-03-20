// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "exception.hpp"
#include "matcher/equals.hpp"
#include "object_view.hpp"
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
    static constexpr std::array<std::string_view, 3> param_names{"unary", "optional", "variadic"};

    processor(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    MOCK_METHOD((std::pair<owned_object, object_store::attribute>), eval_impl,
        (const unary_argument<object_view> &unary,
            const optional_argument<std::string_view> &optional,
            const variadic_argument<uint64_t> &variadic, processor_cache &, ddwaf::timer &),
        (const));
};

} // namespace mock

TEST(TestStructuredProcessor, AllParametersAvailable)
{
    owned_object output = owned_object::make_string("output_string");

    ddwaf_object tmp;

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "unary_address", ddwaf_object_string(&tmp, "unary_string"));
    ddwaf_object_map_add(
        &input_map, "optional_address", ddwaf_object_string(&tmp, "optional_string"));
    ddwaf_object_map_add(&input_map, "variadic_address_1", ddwaf_object_unsigned(&tmp, 1));
    ddwaf_object_map_add(&input_map, "variadic_address_2", ddwaf_object_unsigned(&tmp, 1));

    object_store store;
    store.insert(owned_object{input_map});

    std::vector<processor_mapping> mappings{
        {{{{{get_target_index("unary_address"), "unary_address", {}}}},
             {{{get_target_index("optional_address"), "optional_address", {}}}},
             {{{get_target_index("variadic_address_1"), "variadic_address_1", {}},
                 {get_target_index("variadic_address_2"), "variadic_address_2", {}}}}},
            {get_target_index("output_address"), "output_address", {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};

    EXPECT_CALL(proc, eval_impl(_, _, _, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};
    auto derived = owned_object::make_map();

    EXPECT_EQ(derived.size(), 0);
    proc.eval(store, derived, cache, deadline);

    EXPECT_EQ(derived.size(), 1);
    const auto *obtained = derived.at(0).ptr();
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");
}

TEST(TestStructuredProcessor, OptionalParametersNotAvailable)
{
    owned_object output = owned_object::make_string("output_string");

    ddwaf_object tmp;

    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "unary_address", ddwaf_object_string(&tmp, "unary_string"));
    ddwaf_object_map_add(&input_map, "variadic_address_1", ddwaf_object_unsigned(&tmp, 1));
    ddwaf_object_map_add(&input_map, "variadic_address_2", ddwaf_object_unsigned(&tmp, 1));

    object_store store;
    store.insert(owned_object{input_map});

    std::vector<processor_mapping> mappings{
        {{{{{get_target_index("unary_address"), "unary_address", {}}}},
             {{{get_target_index("optional_address"), "optional_address", {}}}},
             {{{get_target_index("variadic_address_1"), "variadic_address_1", {}},
                 {get_target_index("variadic_address_2"), "variadic_address_2", {}}}}},
            {get_target_index("output_address"), "output_address", {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};

    EXPECT_CALL(proc, eval_impl(_, _, _, _, _))
        .WillOnce(Return(ByMove(std::pair<owned_object, object_store::attribute>{
            std::move(output), object_store::attribute::none})));

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};
    auto derived = owned_object::make_map();

    EXPECT_EQ(derived.size(), 0);
    proc.eval(store, derived, cache, deadline);

    EXPECT_EQ(derived.size(), 1);
    const auto *obtained = derived.at(0).ptr();
    EXPECT_STREQ(obtained->parameterName, "output_address");
    EXPECT_STREQ(obtained->stringValue, "output_string");
}

TEST(TestStructuredProcessor, RequiredParameterNotAvailable)
{
    ddwaf_object tmp;
    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(
        &input_map, "optional_address", ddwaf_object_string(&tmp, "optional_string"));
    ddwaf_object_map_add(&input_map, "variadic_address_1", ddwaf_object_unsigned(&tmp, 1));
    ddwaf_object_map_add(&input_map, "variadic_address_2", ddwaf_object_unsigned(&tmp, 1));

    object_store store;
    store.insert(owned_object{input_map});

    std::vector<processor_mapping> mappings{
        {{{{{get_target_index("unary_address"), "unary_address", {}}}},
             {{{get_target_index("optional_address"), "optional_address", {}}}},
             {{{get_target_index("variadic_address_1"), "variadic_address_1", {}},
                 {get_target_index("variadic_address_2"), "variadic_address_2", {}}}}},
            {get_target_index("output_address"), "output_address", {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};

    EXPECT_CALL(proc, eval_impl(_, _, _, _, _)).Times(0);

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};
    auto derived = owned_object::make_map();

    EXPECT_EQ(derived.size(), 0);
    proc.eval(store, derived, cache, deadline);
    EXPECT_EQ(derived.size(), 0);
}

TEST(TestStructuredProcessor, NoVariadocParametersAvailable)
{
    ddwaf_object tmp;
    ddwaf_object input_map;
    ddwaf_object_map(&input_map);
    ddwaf_object_map_add(&input_map, "unary_address", ddwaf_object_string(&tmp, "unary_string"));
    ddwaf_object_map_add(
        &input_map, "optional_address", ddwaf_object_string(&tmp, "optional_string"));

    object_store store;
    store.insert(owned_object{input_map});

    std::vector<processor_mapping> mappings{
        {{{{{get_target_index("unary_address"), "unary_address", {}}}},
             {{{get_target_index("optional_address"), "optional_address", {}}}},
             {{{get_target_index("variadic_address_1"), "variadic_address_1", {}},
                 {get_target_index("variadic_address_2"), "variadic_address_2", {}}}}},
            {get_target_index("output_address"), "output_address", {}}}};

    mock::processor proc{"id", std::make_shared<expression>(), std::move(mappings), false, true};

    EXPECT_CALL(proc, eval_impl(_, _, _, _, _)).Times(0);

    EXPECT_STREQ(proc.get_id().c_str(), "id");

    processor_cache cache;
    timer deadline{2s};
    auto derived = owned_object::make_map();

    EXPECT_EQ(derived.size(), 0);
    proc.eval(store, derived, cache, deadline);
    EXPECT_EQ(derived.size(), 0);
}

} // namespace
