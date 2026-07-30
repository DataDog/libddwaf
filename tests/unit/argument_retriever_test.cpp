// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "argument_retriever.hpp"
#include "condition/base.hpp"
#include "processor/base.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

// Targets which provide their own transformers
static_assert(has_transformers<condition_target>);

// Targets without transformers
static_assert(!has_transformers<processor_target>);

struct wrong_transformer_type {
    std::vector<int> transformers;
};
static_assert(!has_transformers<wrong_transformer_type>);

struct wrong_transformer_name {
    std::vector<transformer_id> transformer;
};
static_assert(!has_transformers<wrong_transformer_name>);

TEST(TestArgumentRetriever, UnaryArgumentWithTransformers)
{
    auto root = object_builder_da::map({{"input", "value"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    const condition_target target{.name = "input",
        .index = get_target_index("input"),
        .key_path = {},
        .transformers = {transformer_id::lowercase, transformer_id::url_decode}};

    auto arg = argument_retriever<unary_argument<std::string_view>>::retrieve(store, {}, target);
    ASSERT_TRUE(arg.has_value());

    EXPECT_STRV(arg->address, "input");
    EXPECT_STRV(arg->value, "value");
    ASSERT_EQ(arg->transformers.size(), 2);
    EXPECT_EQ(arg->transformers[0], transformer_id::lowercase);
    EXPECT_EQ(arg->transformers[1], transformer_id::url_decode);
}

TEST(TestArgumentRetriever, UnaryArgumentWithoutTransformers)
{
    auto root = object_builder_da::map({{"input", "value"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    const condition_target target{.name = "input", .index = get_target_index("input")};

    auto arg = argument_retriever<unary_argument<std::string_view>>::retrieve(store, {}, target);
    ASSERT_TRUE(arg.has_value());

    EXPECT_STRV(arg->address, "input");
    EXPECT_STRV(arg->value, "value");
    EXPECT_TRUE(arg->transformers.empty());
}

// Targets which don't provide transformers must yield an empty span
TEST(TestArgumentRetriever, UnaryArgumentTargetWithoutTransformerSupport)
{
    auto root = object_builder_da::map({{"input", "value"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    const processor_target target{
        .index = get_target_index("input"), .name = "input", .key_path = {}};

    auto arg = argument_retriever<unary_argument<std::string_view>>::retrieve(store, {}, target);
    ASSERT_TRUE(arg.has_value());

    EXPECT_STRV(arg->address, "input");
    EXPECT_STRV(arg->value, "value");
    EXPECT_TRUE(arg->transformers.empty());
}

TEST(TestArgumentRetriever, OptionalArgumentWithTransformers)
{
    auto root = object_builder_da::map({{"input", "value"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    const condition_target target{.name = "input",
        .index = get_target_index("input"),
        .key_path = {},
        .transformers = {transformer_id::lowercase}};

    auto arg = argument_retriever<optional_argument<std::string_view>>::retrieve(store, {}, target);
    ASSERT_TRUE(arg.has_value());

    ASSERT_EQ(arg->transformers.size(), 1);
    EXPECT_EQ(arg->transformers[0], transformer_id::lowercase);
}

// Each target of a variadic argument keeps its own set of transformers
TEST(TestArgumentRetriever, VariadicArgumentWithTransformers)
{
    auto root =
        object_builder_da::map({{"input", "value"}, {"other", "value"}, {"another", "value"}});

    object_store store;
    store.insert_and_apply(std::move(root));

    const std::vector<condition_target> targets{
        {.name = "input",
            .index = get_target_index("input"),
            .key_path = {},
            .transformers = {transformer_id::lowercase}},
        {.name = "other", .index = get_target_index("other")},
        {.name = "another",
            .index = get_target_index("another"),
            .key_path = {},
            .transformers = {transformer_id::url_decode, transformer_id::base64_decode}},
    };

    auto args =
        argument_retriever<variadic_argument<std::string_view>>::retrieve(store, {}, targets);
    ASSERT_EQ(args.size(), 3);

    EXPECT_STRV(args[0].address, "input");
    ASSERT_EQ(args[0].transformers.size(), 1);
    EXPECT_EQ(args[0].transformers[0], transformer_id::lowercase);

    EXPECT_STRV(args[1].address, "other");
    EXPECT_TRUE(args[1].transformers.empty());

    EXPECT_STRV(args[2].address, "another");
    ASSERT_EQ(args[2].transformers.size(), 2);
    EXPECT_EQ(args[2].transformers[0], transformer_id::url_decode);
    EXPECT_EQ(args[2].transformers[1], transformer_id::base64_decode);
}

} // namespace
