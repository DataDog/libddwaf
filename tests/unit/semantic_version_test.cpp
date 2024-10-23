// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string_view>
#include <tuple>
#include <vector>

#include "semver.hpp"

#include "common/gtest/utils.hpp"

using namespace ddwaf;

namespace {

TEST(TestVersion, Parsing)
{
    std::vector<std::tuple<std::string_view, unsigned, unsigned, unsigned, unsigned>> samples{
        {"1.2.3", 1, 2, 3, 1002003},
        {"1.2.33", 1, 2, 33, 1002033},
        {"1.2.333", 1, 2, 333, 1002333},
        {"1.22.3", 1, 22, 3, 1022003},
        {"1.22.33", 1, 22, 33, 1022033},
        {"1.22.333", 1, 22, 333, 1022333},
        {"1.222.3", 1, 222, 3, 1222003},
        {"1.222.33", 1, 222, 33, 1222033},
        {"1.222.333", 1, 222, 333, 1222333},

        {"11.2.3", 11, 2, 3, 11002003},
        {"11.2.33", 11, 2, 33, 11002033},
        {"11.2.333", 11, 2, 333, 11002333},
        {"11.22.3", 11, 22, 3, 11022003},
        {"11.22.33", 11, 22, 33, 11022033},
        {"11.22.333", 11, 22, 333, 11022333},
        {"11.222.3", 11, 222, 3, 11222003},
        {"11.222.33", 11, 222, 33, 11222033},
        {"11.222.333", 11, 222, 333, 11222333},

        {"111.2.3", 111, 2, 3, 111002003},
        {"111.2.33", 111, 2, 33, 111002033},
        {"111.2.333", 111, 2, 333, 111002333},
        {"111.22.3", 111, 22, 3, 111022003},
        {"111.22.33", 111, 22, 33, 111022033},
        {"111.22.333", 111, 22, 333, 111022333},
        {"111.222.3", 111, 222, 3, 111222003},
        {"111.222.33", 111, 222, 33, 111222033},
        {"111.222.333", 111, 222, 333, 111222333},

        {"1.2.3-alpha", 1, 2, 3, 1002003},
        {"111.222.333-beta", 111, 222, 333, 111222333},
    };

    for (auto [str, major, minor, patch, number] : samples) {
        semantic_version v{str};

        EXPECT_EQ(v.major(), major);
        EXPECT_EQ(v.minor(), minor);
        EXPECT_EQ(v.patch(), patch);

        EXPECT_EQ(v.number(), number);
        EXPECT_STREQ(v.cstring(), str.data());
    }
}

TEST(TestVersion, LowerThan)
{
    std::vector<std::string_view> samples{"1.2.3", "1.2.33", "1.2.333", "1.22.3", "1.22.33",
        "1.22.333", "1.222.3", "1.222.33", "1.222.333", "11.2.3", "11.2.33", "11.2.333", "11.22.3",
        "11.22.33", "11.22.333", "11.222.3", "11.222.33", "11.222.333", "111.2.3", "111.2.33",
        "111.2.333", "111.22.3", "111.22.33", "111.22.333", "111.222.3", "111.222.33",
        "111.222.333"};

    for (std::size_t i = 0; i < samples.size(); ++i) {
        auto lower = samples[i];
        for (std::size_t j = i + 1; j < samples.size(); ++j) {
            auto higher = samples[j];
            EXPECT_LT(semantic_version{lower}, semantic_version{higher});
        }
    }
}

TEST(TestVersion, LowerEqual)
{
    std::vector<std::string_view> samples{"1.2.3", "1.2.33", "1.2.333", "1.22.3", "1.22.33",
        "1.22.333", "1.222.3", "1.222.33", "1.222.333", "11.2.3", "11.2.33", "11.2.333", "11.22.3",
        "11.22.33", "11.22.333", "11.222.3", "11.222.33", "11.222.333", "111.2.3", "111.2.33",
        "111.2.333", "111.22.3", "111.22.33", "111.22.333", "111.222.3", "111.222.33",
        "111.222.333"};

    for (std::size_t i = 0; i < samples.size(); ++i) {
        auto lower = samples[i];
        for (std::size_t j = i; j < samples.size(); ++j) {
            auto higher = samples[j];
            EXPECT_LE(semantic_version{lower}, semantic_version{higher});
        }
    }
}

TEST(TestVersion, GreaterThan)
{
    std::vector<std::string_view> samples{"1.2.3", "1.2.33", "1.2.333", "1.22.3", "1.22.33",
        "1.22.333", "1.222.3", "1.222.33", "1.222.333", "11.2.3", "11.2.33", "11.2.333", "11.22.3",
        "11.22.33", "11.22.333", "11.222.3", "11.222.33", "11.222.333", "111.2.3", "111.2.33",
        "111.2.333", "111.22.3", "111.22.33", "111.22.333", "111.222.3", "111.222.33",
        "111.222.333"};

    for (std::size_t i = 0; i < samples.size(); ++i) {
        auto lower = samples[i];
        for (std::size_t j = i + 1; j < samples.size(); ++j) {
            auto higher = samples[j];
            EXPECT_GT(semantic_version{higher}, semantic_version{lower});
        }
    }
}

TEST(TestVersion, GreaterEqual)
{
    std::vector<std::string_view> samples{"1.2.3", "1.2.33", "1.2.333", "1.22.3", "1.22.33",
        "1.22.333", "1.222.3", "1.222.33", "1.222.333", "11.2.3", "11.2.33", "11.2.333", "11.22.3",
        "11.22.33", "11.22.333", "11.222.3", "11.222.33", "11.222.333", "111.2.3", "111.2.33",
        "111.2.333", "111.22.3", "111.22.33", "111.22.333", "111.222.3", "111.222.33",
        "111.222.333"};

    for (std::size_t i = 0; i < samples.size(); ++i) {
        auto lower = samples[i];
        for (std::size_t j = i; j < samples.size(); ++j) {
            auto higher = samples[j];
            EXPECT_GE(semantic_version{higher}, semantic_version{lower});
        }
    }
}

TEST(TestVersion, Equality)
{
    std::vector<std::string_view> samples{"1.2.3", "1.2.33", "1.2.333", "1.22.3", "1.22.33",
        "1.22.333", "1.222.3", "1.222.33", "1.222.333", "11.2.3", "11.2.33", "11.2.333", "11.22.3",
        "11.22.33", "11.22.333", "11.222.3", "11.222.33", "11.222.333", "111.2.3", "111.2.33",
        "111.2.333", "111.22.3", "111.22.33", "111.22.333", "111.222.3", "111.222.33",
        "111.222.333"};

    for (auto str : samples) { EXPECT_EQ(semantic_version{str}, semantic_version{str}); }
}

TEST(TestVersion, InvalidVersion)
{
    EXPECT_THROW(semantic_version{"a.b.c"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.b.c"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.2.c"}, std::invalid_argument);

    EXPECT_THROW(semantic_version{"1a.b.c"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.2b.c"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.2.3c"}, std::invalid_argument);

    EXPECT_THROW(semantic_version{"1"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.2"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.2.3.4"}, std::invalid_argument);
}

TEST(TestVersion, OutOfRange)
{
    EXPECT_THROW(semantic_version{"1.2.3333"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.2222.3"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1111.2.3"}, std::invalid_argument);

    EXPECT_THROW(semantic_version{"1000.1.1"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.1000.1"}, std::invalid_argument);
    EXPECT_THROW(semantic_version{"1.1.1000"}, std::invalid_argument);
}

} // namespace
