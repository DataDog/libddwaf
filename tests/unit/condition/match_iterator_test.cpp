// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "condition/match_iterator.hpp"
#include "transformer/base.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestMatchIterator, InvalidIterator)
{
    owned_object object = owned_object{};

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, NoMatch)
{
    owned_object object = test::ddwaf_object_da::make_string("no match");

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, {}, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, SingleMatch)
{
    owned_object object = test::ddwaf_object_da::make_string("resource");

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, {}, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "resource");
    EXPECT_EQ(index, 12);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, MultipleMatches)
{
    owned_object object = test::ddwaf_object_da::make_string("resource");

    std::string resource = "resource resource resource resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, {}, exclude);

    for (std::size_t i = 0; i < 4; ++i) {
        EXPECT_TRUE((bool)it);
        auto [param, index] = *it;
        EXPECT_STRV(param, "resource");
        EXPECT_EQ(index, i * 9);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, OverlappingMatches)
{
    owned_object object = test::ddwaf_object_da::make_string("ee");

    std::string resource = "eeeeeeeeee";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, {}, exclude);
    EXPECT_TRUE((bool)it);

    for (std::size_t i = 0; i < 9; ++i) {
        auto [param, index] = *it;
        EXPECT_STRV(param, "ee");
        EXPECT_EQ(index, i);

        auto path = it.get_current_path();
        EXPECT_EQ(path.size(), 0);

        ++it;
    }

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, NoMatchWithoutTransformer)
{
    owned_object object = test::ddwaf_object_da::make_string("%72esource");

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, {}, exclude);
    EXPECT_FALSE((bool)it);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, SingleMatchWithTransformer)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = test::ddwaf_object_da::make_string("%72esource");

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "resource");
    EXPECT_EQ(index, 12);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, MultipleTransformers)
{
    const std::vector<transformer_id> transformers{
        transformer_id::url_decode, transformer_id::lowercase};

    owned_object object = test::ddwaf_object_da::make_string("%52ESOURCE");

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "resource");
    EXPECT_EQ(index, 12);

    EXPECT_FALSE(++it);
}

// When none of the transformers modify the parameter, the original value must
// still be used for matching
TEST(TestMatchIterator, UnmodifiedByTransformer)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = test::ddwaf_object_da::make_string("resource");

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "resource");
    EXPECT_EQ(index, 12);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, MultipleMatchesWithTransformer)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = test::ddwaf_object_da::make_string("%72esource");

    std::string resource = "resource resource resource resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);

    for (std::size_t i = 0; i < 4; ++i) {
        EXPECT_TRUE((bool)it);
        auto [param, index] = *it;
        EXPECT_STRV(param, "resource");
        EXPECT_EQ(index, i * 9);

        ++it;
    }

    EXPECT_FALSE(++it);
}

// Each parameter must be transformed independently, regardless of whether the
// previous one was modified by the transformers or not
TEST(TestMatchIterator, MultipleParametersWithTransformer)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = object_builder_da::array(
        {"unrelated", "%72esource", "no match here", "resource", "%6eothing"});

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);

    for (std::size_t i = 0; i < 2; ++i) {
        EXPECT_TRUE((bool)it);
        auto [param, index] = *it;
        EXPECT_STRV(param, "resource");
        EXPECT_EQ(index, 12);

        auto path = it.get_current_path();
        ASSERT_EQ(path.size(), 1);
        EXPECT_EQ(std::get<int64_t>(path[0]), i == 0 ? 1 : 3);

        ++it;
    }

    EXPECT_FALSE((bool)it);
}

// The default iterator is a kv_iterator, so keys must also be transformed
TEST(TestMatchIterator, TransformedKey)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = object_builder_da::map({{"%72esource", "unrelated"}});

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "resource");
    EXPECT_EQ(index, 12);

    EXPECT_FALSE(++it);
}

// The minimum length requirement is evaluated on the value which is actually
// looked up within the resource, i.e. the transformed one when the transformers
// modify the parameter and the original one otherwise
TEST(TestMatchIterator, MinLengthAppliedToMatchedValue)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    {
        // The parameter is left untouched by the transformers and is too short
        owned_object object = test::ddwaf_object_da::make_string("res");

        std::string resource = "this is the resource";
        object_set_ref exclude;
        ddwaf::match_iterator<5> it(resource, object, transformers, exclude);
        EXPECT_FALSE((bool)it);
    }

    {
        // The transformed value is too short and the original one, which is
        // present within the resource, must not be evaluated instead
        owned_object object = test::ddwaf_object_da::make_string("%72%65%73");

        std::string resource = "this is the %72%65%73ource";
        object_set_ref exclude;
        ddwaf::match_iterator<5> it(resource, object, transformers, exclude);
        EXPECT_FALSE((bool)it);

        EXPECT_FALSE(++it);
    }

    {
        // The transformed value satisfies the minimum length
        owned_object object = test::ddwaf_object_da::make_string("%72esource");

        std::string resource = "this is the resource";
        object_set_ref exclude;
        ddwaf::match_iterator<5> it(resource, object, transformers, exclude);
        EXPECT_TRUE((bool)it);

        auto [param, index] = *it;
        EXPECT_STRV(param, "resource");
        EXPECT_EQ(index, 12);
    }
}

// A parameter shorter than the minimum length can still be matched if the
// transformers make it long enough
TEST(TestMatchIterator, MinLengthReachedAfterTransform)
{
    const std::vector<transformer_id> transformers{transformer_id::base64_encode};

    owned_object object = test::ddwaf_object_da::make_string("ab");

    // base64("ab")
    std::string resource = "this is the YWI= resource";
    object_set_ref exclude;
    ddwaf::match_iterator<4> it(resource, object, transformers, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "YWI=");
    EXPECT_EQ(index, 12);
}

// The transformed parameter replaces the original one, rather than being
// evaluated in addition to it, so a parameter which is present verbatim within
// the resource is no longer found once a transformer modifies it
TEST(TestMatchIterator, OnlyTransformedParameterEvaluated)
{
    const std::vector<transformer_id> transformers{transformer_id::lowercase};

    owned_object object = test::ddwaf_object_da::make_string("RESOURCE");

    std::string resource = "this is the RESOURCE";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);
    EXPECT_FALSE((bool)it);

    EXPECT_FALSE(++it);
}

// A parameter which is reduced to an empty string by the transformers must not
// be considered a match, as std::string_view::find always succeeds on an empty
// needle
TEST(TestMatchIterator, EmptyTransformedParameter)
{
    const std::vector<transformer_id> transformers{transformer_id::remove_nulls};

    const std::string nulls("\0\0\0", 3);
    owned_object object = test::ddwaf_object_da::make_string(nulls);

    std::string resource = "this is the resource";
    object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, transformers, exclude);
    EXPECT_FALSE((bool)it);

    EXPECT_FALSE(++it);
}

} // namespace
