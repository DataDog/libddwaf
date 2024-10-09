// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <string_view>
#include <tuple>
#include <vector>

#include "version.hpp"

#include "test_utils.hpp"

using namespace ddwaf;

namespace {

TEST(Version, Parsing)
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

TEST(Version, LowerThan) { EXPECT_LT(semantic_version{"1.2.3"}, semantic_version{"1.2.33"}); }

TEST(Version, Equality) { EXPECT_EQ(semantic_version{"1.2.3"}, semantic_version{"1.2.3"}); }

} // namespace
