// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "condition/transforming_iterator.hpp"
#include "transformer/base.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestTransformingIterator, NoTransformers)
{
    owned_object object = object_builder_da::array({"value"});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, {}, exclude, deadline);
    ASSERT_TRUE((bool)it);

    EXPECT_STRV((*it).as<std::string_view>(), "value");
    EXPECT_FALSE(++it);
}

TEST(TestTransformingIterator, TransformedValue)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = object_builder_da::array({"%72esource"});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, transformers, exclude, deadline);
    ASSERT_TRUE((bool)it);

    EXPECT_STRV((*it).as<std::string_view>(), "resource");
    EXPECT_FALSE(++it);
}

// When none of the transformers modify the value, the original one is yielded
TEST(TestTransformingIterator, UnmodifiedValue)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = object_builder_da::array({"resource"});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, transformers, exclude, deadline);
    ASSERT_TRUE((bool)it);

    EXPECT_STRV((*it).as<std::string_view>(), "resource");
    EXPECT_FALSE(++it);
}

// Non-string objects are skipped, including the keys of their parent map
TEST(TestTransformingIterator, NonStringValuesSkipped)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = object_builder_da::array({22, "%72esource", 4.2, true});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, transformers, exclude, deadline);
    ASSERT_TRUE((bool)it);

    EXPECT_STRV((*it).as<std::string_view>(), "resource");
    EXPECT_FALSE(++it);
}

// A transformer may reduce a value to an empty string with no underlying
// buffer; the yielded object must still expose a valid pointer, as the rest of
// the codebase assumes string objects are never null
TEST(TestTransformingIterator, EmptyTransformedValue)
{
    const std::vector<transformer_id> transformers{transformer_id::remove_comments};

    owned_object object = object_builder_da::array({"#"});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, transformers, exclude, deadline);
    ASSERT_TRUE((bool)it);

    auto value = (*it).as<std::string_view>();
    EXPECT_EQ(value.size(), 0);
    EXPECT_NE(value.data(), nullptr);

    // The yielded object must be usable by anything expecting a string object
    EXPECT_NO_THROW(cow_string{value});

    EXPECT_FALSE(++it);
}

// The iterator skips objects internally, so it must evaluate the deadline
// itself rather than relying on the caller doing so per yielded value
TEST(TestTransformingIterator, TimeoutWhileSkippingNonStrings)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    auto object = object_builder_da::array();
    for (unsigned i = 0; i < 1024; ++i) { object.emplace_back(owned_object::make_signed(i)); }

    object_set_ref exclude;
    ddwaf::timer deadline{0s};
    EXPECT_THROW((transforming_iterator<kv_iterator>{object, transformers, exclude, deadline}),
        ddwaf::timeout_exception);
}

// current_value() and operator* must expose the same value, the latter simply
// wrapping it in a string object
TEST(TestTransformingIterator, CurrentValueMatchesObject)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object = object_builder_da::array({"%72esource", "unmodified", "#"});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, transformers, exclude, deadline);

    for (const auto *expected : {"resource", "unmodified", "#"}) {
        ASSERT_TRUE((bool)it);
        EXPECT_STRV(it.current_value(), expected);
        EXPECT_STRV((*it).as<std::string_view>(), expected);
        ++it;
    }

    EXPECT_FALSE((bool)it);
}

// Note: operator++ performs the same check, but the deadline can't be expired
// deterministically half-way through an iteration, as base_timer consults the
// clock on its very first call. The detector-level regression test in
// lfi_detector_test.cpp covers the skip loop as a whole.

TEST(TestTransformingIterator, KeyPath)
{
    const std::vector<transformer_id> transformers{transformer_id::url_decode};

    owned_object object =
        object_builder_da::map({{"key", object_builder_da::array({"%72esource"})}});

    object_set_ref exclude;
    ddwaf::timer deadline{2s};
    transforming_iterator<kv_iterator> it(object, transformers, exclude, deadline);
    ASSERT_TRUE((bool)it);

    // The first value yielded by the kv_iterator is the key itself
    EXPECT_STRV((*it).as<std::string_view>(), "key");
    EXPECT_TRUE(++it);

    EXPECT_STRV((*it).as<std::string_view>(), "resource");
    auto path = it.get_current_path();
    ASSERT_EQ(path.size(), 2);
    EXPECT_STRV(std::get<std::string_view>(path[0]), "key");
    EXPECT_EQ(std::get<int64_t>(path[1]), 0);

    EXPECT_FALSE(++it);
}

} // namespace
