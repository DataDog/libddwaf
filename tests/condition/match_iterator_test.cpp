// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "condition/match_iterator.hpp"

using namespace ddwaf;

namespace {

TEST(TestMatchIterator, InvalidIterator)
{
    ddwaf_object object;
    ddwaf_object_invalid(&object);

    std::string resource = "this is the resource";
    exclusion::object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);
}

TEST(TestMatchIterator, NoMatch)
{
    ddwaf_object object;
    ddwaf_object_string(&object, "no match");

    std::string resource = "this is the resource";
    exclusion::object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, exclude);
    EXPECT_FALSE((bool)it);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestMatchIterator, SingleMatch)
{
    ddwaf_object object;
    ddwaf_object_string(&object, "resource");

    std::string resource = "this is the resource";
    exclusion::object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, exclude);
    EXPECT_TRUE((bool)it);

    auto [param, index] = *it;
    EXPECT_STRV(param, "resource");
    EXPECT_EQ(index, 12);

    auto path = it.get_current_path();
    EXPECT_EQ(path.size(), 0);

    EXPECT_FALSE(++it);

    ddwaf_object_free(&object);
}

TEST(TestMatchIterator, MultipleMatches)
{
    ddwaf_object object;
    ddwaf_object_string(&object, "resource");

    std::string resource = "resource resource resource resource";
    exclusion::object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, exclude);

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

    ddwaf_object_free(&object);
}

TEST(TestMatchIterator, OverlappingMatches)
{
    ddwaf_object object;
    ddwaf_object_string(&object, "ee");

    std::string resource = "eeeeeeeeee";
    exclusion::object_set_ref exclude;
    ddwaf::match_iterator it(resource, object, exclude);
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

    ddwaf_object_free(&object);
}

} // namespace
