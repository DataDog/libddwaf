// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/remove_nulls.hpp"
#include "transformer_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestRemoveNulls, NameAndID)
{
    EXPECT_STREQ(transformer::remove_nulls::name().data(), "remove_nulls");
    EXPECT_EQ(transformer::remove_nulls::id(), transformer_id::remove_nulls);
}

TEST(TestRemoveNulls, EmptyString) { EXPECT_NO_TRANSFORM(remove_nulls, ""); }

TEST(TestRemoveNulls, ValidTransform)
{
    EXPECT_TRANSFORM(remove_nulls, "r\0", "r");
    EXPECT_TRANSFORM(remove_nulls, "re\0", "re");
    EXPECT_TRANSFORM(remove_nulls, "\0re", "re");
    EXPECT_TRANSFORM(remove_nulls, "r\0e", "re");
    EXPECT_TRANSFORM(remove_nulls, "removenulls\0", "removenulls");
    EXPECT_TRANSFORM(remove_nulls, "remove\0nulls", "removenulls");
    EXPECT_TRANSFORM(remove_nulls, "\0removenulls", "removenulls");
}

TEST(TestRemoveNulls, InvalidTransform)
{
    EXPECT_NO_TRANSFORM(remove_nulls, "r");
    EXPECT_NO_TRANSFORM(remove_nulls, "rs");
    EXPECT_NO_TRANSFORM(remove_nulls, "remove_nulls");
    EXPECT_NO_TRANSFORM(remove_nulls, "remove_nulls but it doesn't matter");
}

} // namespace
