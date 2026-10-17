// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <random>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "condition/match_iterator.hpp"
#include "condition/substring_filter.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

// Makes the filter build its bitmap, by testing as many needles as it lets
// through unfiltered (only texts of at least two bytes have a bitmap)
void build_filter(substring_filter &filter)
{
    for (unsigned i = 0; i < substring_filter::unfiltered_needles; ++i) {
        std::ignore = filter.may_contain("xx");
    }
}

TEST(TestSubstringFilter, NeedleLongerThanText)
{
    substring_filter filter{"text"};
    EXPECT_FALSE(filter.may_contain("texts"));
    EXPECT_FALSE(filter.may_contain("other text"));

    substring_filter empty_filter{""};
    EXPECT_FALSE(empty_filter.may_contain("a"));
    EXPECT_TRUE(empty_filter.may_contain(""));
}

TEST(TestSubstringFilter, UnfilteredNeedles)
{
    substring_filter filter{"select * from table"};
    for (unsigned i = 0; i < substring_filter::unfiltered_needles; ++i) {
        EXPECT_TRUE(filter.may_contain("zzz"));
    }
    // The bitmap has now been built
    EXPECT_FALSE(filter.may_contain("zzz"));
    EXPECT_TRUE(filter.may_contain("from"));
}

TEST(TestSubstringFilter, ShortNeedles)
{
    substring_filter filter{"abcdef"};
    build_filter(filter);

    // Needles without pairs can't be filtered
    EXPECT_TRUE(filter.may_contain(""));
    EXPECT_TRUE(filter.may_contain("z"));

    EXPECT_TRUE(filter.may_contain("ab"));
    EXPECT_TRUE(filter.may_contain("ef"));
    EXPECT_FALSE(filter.may_contain("ba"));
    EXPECT_FALSE(filter.may_contain("zz"));
}

TEST(TestSubstringFilter, RejectsNeedlesWithAbsentPairs)
{
    substring_filter filter{"SELECT * FROM users WHERE id = '1234' LIMIT 1"};
    build_filter(filter);

    EXPECT_TRUE(filter.may_contain("users"));
    EXPECT_TRUE(filter.may_contain("1234"));
    EXPECT_TRUE(filter.may_contain("WHERE id"));

    // Absent first, last or interior pairs
    EXPECT_FALSE(filter.may_contain("qqsers"));
    EXPECT_FALSE(filter.may_contain("userqq"));
    EXPECT_FALSE(filter.may_contain("WHERE qq = '1234'"));
    // The filter is case-sensitive, as the search is
    EXPECT_FALSE(filter.may_contain("select"));
}

TEST(TestSubstringFilter, BinaryContent)
{
    const std::string text{"\x00\xff\x80\x7f\x00\x01"sv};
    substring_filter filter{text};
    build_filter(filter);

    EXPECT_TRUE(filter.may_contain("\x00\xff\x80"sv));
    EXPECT_TRUE(filter.may_contain("\x7f\x00\x01"sv));
    EXPECT_FALSE(filter.may_contain("\xff\x00"sv));
}

// Every substring of the text, and every needle actually found within it,
// must be let through by the filter
TEST(TestSubstringFilter, NoFalseNegatives)
{
    std::mt19937 rng{42}; // NOLINT(cert-msc32-c,cert-msc51-cpp)

    for (std::size_t alphabet : {2, 4, 26, 256}) {
        std::uniform_int_distribution<int> byte_dist(0, static_cast<int>(alphabet) - 1);
        std::uniform_int_distribution<std::size_t> len_dist(0, 300);

        for (unsigned round = 0; round < 50; ++round) {
            std::string text(len_dist(rng), '\0');
            for (auto &c : text) { c = static_cast<char>('a' + byte_dist(rng)); }

            substring_filter filter{text};
            build_filter(filter);

            for (std::size_t i = 0; i < text.size(); i += 3) {
                for (std::size_t len = 0; i + len <= text.size(); len += 1 + (len / 4)) {
                    EXPECT_TRUE(filter.may_contain(std::string_view{text}.substr(i, len)));
                }
            }

            std::uniform_int_distribution<std::size_t> needle_len_dist(2, 12);
            for (unsigned n = 0; n < 200; ++n) {
                std::string needle(needle_len_dist(rng), '\0');
                for (auto &c : needle) { c = static_cast<char>('a' + byte_dist(rng)); }
                if (text.find(needle) != std::string::npos) {
                    EXPECT_TRUE(filter.may_contain(needle));
                }
            }
        }
    }
}

// The values and indices yielded by a match_iterator with a filter must be
// the same as those yielded without
TEST(TestSubstringFilter, MatchIteratorEquivalence)
{
    const std::string resource =
        "SELECT * FROM wp_posts WHERE post_name = 'hello-world' AND post_type = 'post' "
        "AND post_status = 'publish' ORDER BY post_date DESC LIMIT 10";

    auto object = object_builder_da::map();
    for (unsigned i = 0; i < 40; ++i) {
        object.emplace("key" + std::to_string(i), "value" + std::to_string(i));
    }
    object.emplace("post_name", "hello-world");
    auto nested = object.emplace("nested", object_builder_da::array());
    nested.emplace_back("post");
    nested.emplace_back("DESC LIMIT");
    nested.emplace_back("unrelated value");
    for (unsigned i = 0; i < 40; ++i) { nested.emplace_back("other" + std::to_string(i)); }
    nested.emplace_back("publish");

    using result_type =
        std::tuple<std::string, std::size_t, std::vector<std::variant<std::string_view, int64_t>>>;

    const auto collect = [&](substring_filter *filter) {
        std::vector<result_type> results;
        object_set_ref exclude;
        ddwaf::timer deadline{2s};
        match_iterator<3> it(resource, object, {}, exclude, deadline, filter);
        for (; it; ++it) {
            auto [value, index] = *it;
            results.emplace_back(std::string{value}, index, it.get_current_path());
        }
        return results;
    };

    substring_filter filter{resource};
    auto expected = collect(nullptr);
    auto obtained = collect(&filter);

    EXPECT_EQ(expected.size(), 10);
    EXPECT_EQ(expected, obtained);
}

} // namespace
