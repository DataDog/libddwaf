// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/is_sqli.hpp"
#include "object_view.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;

namespace {

TEST(TestIsSQLi, TestBasic)
{
    is_sqli matcher;
    EXPECT_STREQ(matcher.to_string().data(), "");
    EXPECT_STREQ(matcher.name().data(), "is_sqli");

    ddwaf_object param;
    ddwaf_object_string(&param, "'OR 1=1/*");

    auto [res, highlight] = matcher.match(ddwaf::object_view{param});
    EXPECT_TRUE(res);
    EXPECT_STREQ(highlight.c_str(), "s&1c");

    ddwaf_object_free(&param);
}

TEST(TestIsSQLi, TestMatch)
{
    is_sqli matcher;

    auto match = {"1, -sin(1)) UNION SELECT 1"};

    for (const auto *pattern : match) {
        ddwaf_object param;
        ddwaf_object_string(&param, pattern);
        EXPECT_TRUE(matcher.match(ddwaf::object_view{param}).first);
        ddwaf_object_free(&param);
    }
}

TEST(TestIsSQLi, TestNoMatch)
{
    is_sqli matcher;

    auto no_match = {"*", "00119007249934829312950000808000953OR-240128165430155"};

    for (const auto *pattern : no_match) {
        ddwaf_object param;
        ddwaf_object_string(&param, pattern);
        EXPECT_FALSE(matcher.match(ddwaf::object_view{param}).first);
        ddwaf_object_free(&param);
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
