// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher/is_xss.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf::matcher;

namespace {
TEST(TestIsXSS, TestBasic)
{
    is_xss matcher;
    EXPECT_STR(matcher.to_string(), "");
    EXPECT_STR(matcher.name(), "is_xss");

    ddwaf_object param;
    ddwaf_object_string(&param, "<script>alert(1);</script>");

    auto [res, highlight] = matcher.match(param);
    EXPECT_TRUE(res);
    EXPECT_STR(highlight, "");

    ddwaf_object_free(&param);
}

TEST(TestIsXSS, TestNoMatch)
{
    is_xss matcher;

    ddwaf_object param;
    ddwaf_object_string(&param, "non-xss");

    EXPECT_FALSE(matcher.match(param).first);

    ddwaf_object_free(&param);
}

TEST(TestIsXSS, TestInvalidInput)
{
    is_xss matcher;

    EXPECT_FALSE(matcher.match(std::string_view{nullptr, 0}).first);
    // NOLINTNEXTLINE(bugprone-string-constructor)
    EXPECT_FALSE(matcher.match(std::string_view{"*", 0}).first);
}

} // namespace
