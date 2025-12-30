// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/is_sqli.hpp"
#include "object.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::matcher;

namespace {

TEST(TestIsSQLi, TestBasic)
{
    is_sqli matcher;
    EXPECT_STRV(matcher.to_string(), "");
    EXPECT_STRV(matcher.name(), "is_sqli");

    owned_object param = test::ddwaf_object_da::make_string("'OR 1=1/*");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "s&1c");
}

TEST(TestIsSQLi, TestMatch)
{
    is_sqli matcher;

    auto match = {"1, -sin(1)) UNION SELECT 1"};

    for (const auto *pattern : match) {
        owned_object param = test::ddwaf_object_da::make_string(pattern);
        EXPECT_TRUE(matcher.match(param).first);
    }
}

TEST(TestIsSQLi, TestNoMatch)
{
    is_sqli matcher;

    auto no_match = {"*", "00119007249934829312950000808000953OR-240128165430155"};

    for (const auto *pattern : no_match) {
        owned_object param = test::ddwaf_object_da::make_string(pattern);
        EXPECT_FALSE(matcher.match(param).first);
    }
}

TEST(TestIsSQLi, TestInvalidInput)
{
    is_sqli matcher;

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

} // namespace
