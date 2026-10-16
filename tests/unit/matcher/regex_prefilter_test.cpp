// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iostream>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include "matcher/literal_scanner.hpp"
#include "matcher/prefilter_cache.hpp"
#include "matcher/regex_prefilter.hpp"
#include "re2/re2.h"
#include "transformer/base.hpp"

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::matcher;

namespace {

std::unique_ptr<re2::RE2> try_compile(std::string_view pattern, bool case_sensitive = true)
{
    re2::RE2::Options options;
    options.set_log_errors(false);
    options.set_case_sensitive(case_sensitive);
    return std::make_unique<re2::RE2>(pattern, options);
}

std::unique_ptr<re2::RE2> compile(std::string_view pattern, bool case_sensitive = true)
{
    auto re = try_compile(pattern, case_sensitive);
    EXPECT_TRUE(re->ok()) << pattern;
    return re;
}

std::string prefilter_of(std::string_view pattern, bool case_sensitive = true)
{
    auto re = compile(pattern, case_sensitive);
    auto prefilter = regex_prefilter::from_regex(*re);
    return prefilter ? prefilter->to_string() : std::string{"<none>"};
}

// Whether the prefilter (evaluated as during an evaluation) lets the input
// through, which it must do whenever the regular expression matches.
bool prefilter_passes(const regex_prefilter &prefilter, const literal_scanner &scanner,
    std::string_view input, literal_scanner::scratch &scratch)
{
    std::vector<uint64_t> found;
    auto res = scanner.scan(input, scratch, found);
    if (res.unfiltered) {
        return true;
    }
    if ((res.mask & prefilter.atom_mask()) == 0) {
        EXPECT_FALSE(prefilter.may_match(found));
        return false;
    }
    return prefilter.may_match(found);
}

TEST(TestRegexPrefilter, Extraction)
{
    EXPECT_STR(prefilter_of("union.*?select.*?from"), R"(("union" & "select" & "from"))");
    EXPECT_STR(prefilter_of("<(?:script|iframe)"), R"(("<iframe" | "<script"))");
    EXPECT_STR(prefilter_of("abc(?:def|ghi)"), R"(("abcdef" | "abcghi"))");
    EXPECT_STR(prefilter_of("[ab]cde"), R"(("acde" | "bcde"))");
    EXPECT_STR(prefilter_of("hello|world"), R"(("hello" | "world"))");
    EXPECT_STR(prefilter_of("foo(bar)?baz"), R"(("foobarbaz" | "foobaz"))");
    EXPECT_STR(prefilter_of("foo(?:bar|.*x)baz"), R"(("foo" & "baz"))");
    EXPECT_STR(
        prefilter_of("foo(?:bar|q+uvwxyz)baz"), R"(("foobarbaz" | ("foo" & "uvwxyz" & "baz")))");
    EXPECT_STR(prefilter_of("(?:execut|write?|read)able"),
        R"(("executable" | "readable" | "writable" | "writeable"))");
    EXPECT_STR(prefilter_of("abc(?:x)*"), R"("abc")");
    EXPECT_STR(prefilter_of("abc+def"), R"("def")");
    EXPECT_STR(prefilter_of("x{3}abc"), R"("abc")");
    EXPECT_STR(prefilter_of("(?:abc){2,}"), R"("abc")");
    EXPECT_STR(prefilter_of("^404$"), R"("404")");
    EXPECT_STR(prefilter_of(R"(\bptst\.io\b)"), R"("ptst.io")");
    EXPECT_STR(
        prefilter_of("(?:foo|bar)(?:baz|qux)"), R"(("barbaz" | "barqux" | "foobaz" | "fooqux"))");

    // Atoms are lowercase, whatever the case sensitivity
    EXPECT_STR(prefilter_of("SeLeCt"), R"("select")");
    EXPECT_STR(prefilter_of("SeLeCt", false), R"("select")");
    EXPECT_STR(prefilter_of("(?i)ptsk"), R"("ptsk")");

    // Non-ASCII characters are wildcards
    EXPECT_STR(prefilter_of("abc\u00E9def"), R"(("abc" & "def"))");
    EXPECT_STR(prefilter_of("\u00E9+abc"), R"("abc")");
    EXPECT_STR(prefilter_of("(?i)\u01C5abc"), R"("abc")");

    // Nothing usable
    EXPECT_STR(prefilter_of(R"(\d+)"), "<none>");
    EXPECT_STR(prefilter_of("(?:a|b)c"), "<none>");
    EXPECT_STR(prefilter_of("ab+cd"), "<none>");
    EXPECT_STR(prefilter_of("abc|d"), "<none>");
    EXPECT_STR(prefilter_of("(?:abc)?"), "<none>");
    EXPECT_STR(prefilter_of("(?:abc)*"), "<none>");
    EXPECT_STR(prefilter_of("[a-z]{5}"), "<none>");
    EXPECT_STR(prefilter_of("[^a]bcd"), R"("bcd")");
    EXPECT_STR(prefilter_of(""), "<none>");
}

TEST(TestRegexPrefilter, Evaluation)
{
    auto re = compile("(?:union|intersect).*?select.*?from", false);
    auto prefilter = regex_prefilter::from_regex(*re);
    ASSERT_NE(prefilter, nullptr);

    std::vector<const regex_prefilter *> prefilters{prefilter.get()};
    auto scanner = literal_scanner::build(prefilters);
    ASSERT_TRUE(scanner->covers(*prefilter));

    literal_scanner::scratch scratch;
    EXPECT_TRUE(prefilter_passes(*prefilter, *scanner, "1 UNION SELECT a FROM b", scratch));
    EXPECT_TRUE(prefilter_passes(*prefilter, *scanner, "fromselectintersect", scratch));
    EXPECT_FALSE(prefilter_passes(*prefilter, *scanner, "1 UNION SELECT a", scratch));
    EXPECT_FALSE(prefilter_passes(*prefilter, *scanner, "select from", scratch));
    EXPECT_FALSE(prefilter_passes(*prefilter, *scanner, "", scratch));
    EXPECT_FALSE(prefilter_passes(*prefilter, *scanner, "un", scratch));
}

TEST(TestRegexPrefilter, ScannerFindsOverlappingAtoms)
{
    auto re = compile("abcd.*bcde.*cdef");
    auto prefilter = regex_prefilter::from_regex(*re);
    ASSERT_NE(prefilter, nullptr);
    EXPECT_STR(prefilter->to_string(), R"(("abcd" & "bcde" & "cdef"))");

    std::vector<const regex_prefilter *> prefilters{prefilter.get()};
    auto scanner = literal_scanner::build(prefilters);

    literal_scanner::scratch scratch;
    std::vector<uint64_t> found;
    auto res = scanner->scan("xxABCDEFxx", scratch, found);
    EXPECT_FALSE(res.unfiltered);
    EXPECT_EQ(found.size(), 3);
    EXPECT_TRUE(prefilter->may_match(found));

    found.clear();
    scanner->scan("abcdef", scratch, found);
    EXPECT_EQ(found.size(), 3);

    found.clear();
    scanner->scan("abcde", scratch, found);
    EXPECT_EQ(found.size(), 2);
    EXPECT_FALSE(prefilter->may_match(found));

    // Repeated occurrences are reported once
    found.clear();
    scanner->scan("abcdabcdabcd", scratch, found);
    EXPECT_EQ(found.size(), 1);
}

TEST(TestRegexPrefilter, ScannerMatchesNaiveSearch)
{
    // Atoms of three to six characters over a small alphabet, searched for
    // in random strings of every length (exercising both the word-at-a-time
    // and the byte-at-a-time paths, and atoms at the very end)
    std::mt19937_64 rng{7};
    const std::string alphabet = "abcAB";
    auto random_string = [&](std::size_t length) {
        std::string str;
        for (std::size_t i = 0; i < length; ++i) {
            str.push_back(alphabet[rng() % alphabet.size()]);
        }
        return str;
    };

    for (int round = 0; round < 50; ++round) {
        std::string pattern;
        std::vector<std::string> atoms;
        for (int i = 0; i < 6; ++i) {
            auto atom = random_string(3 + (rng() % 4));
            for (auto &c : atom) { c = static_cast<char>(std::tolower(c)); }
            atoms.emplace_back(atom);
            pattern += (pattern.empty() ? "" : "|") + atom;
        }
        auto re = compile(pattern);
        auto prefilter = regex_prefilter::from_regex(*re);
        ASSERT_NE(prefilter, nullptr) << pattern;
        std::vector<const regex_prefilter *> prefilters{prefilter.get()};
        auto scanner = literal_scanner::build(prefilters);
        literal_scanner::scratch scratch;

        for (std::size_t length = 0; length < 40; ++length) {
            for (int j = 0; j < 20; ++j) {
                auto input = random_string(length);
                std::string lowered = input;
                for (auto &c : lowered) { c = static_cast<char>(std::tolower(c)); }

                std::vector<uint64_t> expected;
                for (const auto &atom : prefilter->atoms()) {
                    if (lowered.find(atom) != std::string::npos) {
                        expected.push_back(regex_prefilter::hash_atom(atom));
                    }
                }
                std::sort(expected.begin(), expected.end());

                std::vector<uint64_t> found;
                scanner->scan(input, scratch, found);
                EXPECT_EQ(found, expected) << "pattern: " << pattern << " input: " << input;
            }
        }
    }
}

TEST(TestRegexPrefilter, CaseFoldingToAscii)
{
    // U+212A KELVIN SIGN and U+017F LATIN SMALL LETTER LONG S match 'k' and
    // 's' case-insensitively; inputs containing them are not filtered.
    for (const auto *pattern : {"(?i)kelvin", "(?i)class", "\u212Aelvin", "cla\u017Fs"}) {
        auto re = compile(pattern);
        auto prefilter = regex_prefilter::from_regex(*re);
        ASSERT_NE(prefilter, nullptr) << pattern;

        std::vector<const regex_prefilter *> prefilters{prefilter.get()};
        auto scanner = literal_scanner::build(prefilters);
        literal_scanner::scratch scratch;

        for (const auto *input : {"\u212Aelvin", "cla\u017Fs", "\u212A", "\u017F"}) {
            std::vector<uint64_t> found;
            auto res = scanner->scan(input, scratch, found);
            EXPECT_TRUE(res.unfiltered) << input;
            if (re2::RE2::PartialMatch(input, *re)) {
                EXPECT_TRUE(prefilter_passes(*prefilter, *scanner, input, scratch));
            }
        }
    }

    EXPECT_TRUE(re2::RE2::PartialMatch("\u212Aelvin", *compile("(?i)kelvin")));
    EXPECT_TRUE(re2::RE2::PartialMatch("cla\u017Fs", *compile("(?i)class")));
}

TEST(TestRegexPrefilter, ScannerCoverage)
{
    auto re1 = compile("first_atom");
    auto re2 = compile("second_atom");
    auto pf1 = regex_prefilter::from_regex(*re1);
    auto pf2 = regex_prefilter::from_regex(*re2);
    ASSERT_NE(pf1, nullptr);
    ASSERT_NE(pf2, nullptr);

    std::vector<const regex_prefilter *> prefilters{pf1.get()};
    auto scanner = literal_scanner::build(prefilters);
    EXPECT_TRUE(scanner->covers(*pf1));
    EXPECT_FALSE(scanner->covers(*pf2));

    {
        prefilter_scope scope{scanner.get()};
        auto *cache = prefilter_cache::current();
        ASSERT_NE(cache, nullptr);
        EXPECT_TRUE(cache->supports(*pf1));
        EXPECT_FALSE(cache->supports(*pf2));
        // Memoised
        EXPECT_TRUE(cache->supports(*pf1));
        EXPECT_FALSE(cache->supports(*pf2));

        // Nested scopes disable prefiltering
        {
            prefilter_scope nested{scanner.get()};
            EXPECT_EQ(prefilter_cache::current(), nullptr);
        }
        EXPECT_EQ(prefilter_cache::current(), cache);
    }
    EXPECT_EQ(prefilter_cache::current(), nullptr);

    {
        prefilter_scope scope{nullptr};
        EXPECT_EQ(prefilter_cache::current(), nullptr);
    }
}

TEST(TestRegexPrefilter, CacheWithTransformers)
{
    auto re = compile("<script", false);
    auto prefilter = regex_prefilter::from_regex(*re);
    ASSERT_NE(prefilter, nullptr);
    std::vector<const regex_prefilter *> prefilters{prefilter.get()};
    auto scanner = literal_scanner::build(prefilters);

    prefilter_scope scope{scanner.get()};
    auto *cache = prefilter_cache::current();
    ASSERT_NE(cache, nullptr);

    auto encoded = test::ddwaf_object_da::make_string("%3CSCRIPT%3E");
    auto plain = test::ddwaf_object_da::make_string("<SCRIPT>");
    auto benign = test::ddwaf_object_da::make_string("hello world");

    const std::vector<transformer_id> none;
    const std::vector<transformer_id> lowercase{transformer_id::lowercase};
    const std::vector<transformer_id> decode{transformer_id::url_decode};
    const std::vector<transformer_id> decode_lowercase{
        transformer_id::url_decode, transformer_id::lowercase};

    for (int i = 0; i < 2; ++i) {
        // The second iteration is served from the cache
        std::optional<cow_string> transformed;
        bool transformed_valid = false;

        EXPECT_FALSE(cache->may_match(
            *prefilter, object_view{encoded}, none, transformed, transformed_valid));
        EXPECT_FALSE(transformed_valid);

        EXPECT_FALSE(cache->may_match(
            *prefilter, object_view{encoded}, lowercase, transformed, transformed_valid));
        // A final lowercase doesn't change the atoms present: not transformed
        EXPECT_FALSE(transformed_valid);

        EXPECT_TRUE(cache->may_match(
            *prefilter, object_view{plain}, lowercase, transformed, transformed_valid));
        EXPECT_FALSE(transformed_valid);

        transformed.reset();
        transformed_valid = false;
        EXPECT_TRUE(cache->may_match(
            *prefilter, object_view{encoded}, decode, transformed, transformed_valid));
        if (i == 0) {
            ASSERT_TRUE(transformed_valid);
            ASSERT_TRUE(transformed.has_value());
            EXPECT_STR(static_cast<std::string_view>(*transformed), "<SCRIPT>");
        } else {
            EXPECT_FALSE(transformed_valid);
        }

        transformed.reset();
        transformed_valid = false;
        EXPECT_TRUE(cache->may_match(
            *prefilter, object_view{encoded}, decode_lowercase, transformed, transformed_valid));
        // Only the decoding was performed, not the whole transformation
        EXPECT_FALSE(transformed_valid);

        transformed.reset();
        transformed_valid = false;
        EXPECT_FALSE(cache->may_match(
            *prefilter, object_view{benign}, decode, transformed, transformed_valid));
        if (i == 0) {
            // Unchanged by the transformation
            EXPECT_TRUE(transformed_valid);
            EXPECT_FALSE(transformed.has_value());
        }
    }
}

// Exposes the size of the buffer of scan results, which must not grow with the
// number of lookups of strings which can't be cached.
class inspectable_prefilter_cache : public prefilter_cache {
public:
    using prefilter_cache::reset;
    [[nodiscard]] std::size_t scan_results_size() const { return found_.size(); }
};

TEST(TestRegexPrefilter, UncachedScansDontAccumulate)
{
    auto re = compile("union.*select", false);
    auto prefilter = regex_prefilter::from_regex(*re);
    ASSERT_NE(prefilter, nullptr);
    std::vector<const regex_prefilter *> prefilters{prefilter.get()};
    auto scanner = literal_scanner::build(prefilters);

    inspectable_prefilter_cache cache;
    cache.reset(scanner.get());

    // More distinct strings than the cache holds, all of them containing the
    // atoms of the prefilter
    constexpr std::size_t count = 20000;
    std::vector<owned_object> strings;
    strings.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        strings.emplace_back(
            test::ddwaf_object_da::make_string("union select " + std::to_string(i)));
    }

    const std::vector<transformer_id> none;
    const std::vector<transformer_id> decode{transformer_id::url_decode};
    auto may_match = [&](const owned_object &str, const std::vector<transformer_id> &chain) {
        std::optional<cow_string> transformed;
        bool transformed_valid = false;
        return cache.may_match(*prefilter, object_view{str}, chain, transformed, transformed_valid);
    };

    for (const auto &str : strings) {
        EXPECT_TRUE(may_match(str, none));
        EXPECT_TRUE(may_match(str, decode));
    }
    const auto size = cache.scan_results_size();

    // Lookups of the strings which didn't fit in the cache, as when several
    // regular expressions are applied to them, scan them again but mustn't
    // retain their results.
    for (int rep = 0; rep < 10; ++rep) {
        for (std::size_t i = count - 1000; i < count; ++i) {
            EXPECT_TRUE(may_match(strings[i], none));
            EXPECT_TRUE(may_match(strings[i], decode));
        }
    }
    EXPECT_EQ(cache.scan_results_size(), size);
}

// Generates random regular expressions and inputs over a small alphabet, and
// checks that the prefilter never rejects an input which the expression
// matches.
class random_regex_generator {
public:
    explicit random_regex_generator(uint64_t seed) : rng_(seed) {}

    std::string regex(unsigned depth = 0)
    {
        std::string out;
        const auto n = 1 + pick(depth > 2 ? 3 : 5);
        for (unsigned i = 0; i < n; ++i) { out += term(depth); }
        return out;
    }

    std::string input()
    {
        static const std::vector<std::string> pieces{"a", "b", "k", "s", "A", "B", "K", "S", "a",
            "b", "k", "s", "ab", "ka", "sk", "abk", "\u212A", "\u017F", "\u00E9", "\u00C9", " ",
            ".", "\n"};
        std::string out;
        const auto n = pick(14);
        for (unsigned i = 0; i < n; ++i) { out += pieces[pick(pieces.size())]; }
        return out;
    }

    bool coin() { return pick(2) == 0; }

protected:
    unsigned pick(std::size_t n) { return static_cast<unsigned>(rng_() % n); }

    std::string atom()
    {
        static const std::vector<std::string> atoms{"a", "b", "k", "s", "A", "K", "S", "a", "b",
            "k", "s", "ab", "abk", "ka", ".", "[ab]", "[aK]", "[^a]", "[a-c]", "\\.", "\u212A",
            "\u017F", "\u00E9", "[\u00E9a]", "\\b", "^", "$", "\\s", "\\w", "(?i:k)", "(?i:s)",
            "(?i:ab)", "[kK]", "[sS]", "[ks]", "\\x{212A}"};
        return atoms[pick(atoms.size())];
    }

    std::string term(unsigned depth)
    {
        std::string base;
        if (depth < 3 && pick(4) == 0) {
            base = "(?:" + regex(depth + 1);
            const auto alternatives = pick(3);
            for (unsigned i = 0; i < alternatives; ++i) { base += "|" + regex(depth + 1); }
            base += ")";
        } else {
            base = atom();
        }

        static const std::vector<std::string> suffixes{
            "", "", "", "", "", "*", "+", "?", "{2}", "{0,2}", "{1,3}"};
        const auto &suffix = suffixes[pick(suffixes.size())];
        if (!suffix.empty() && (base == "^" || base == "$" || base == "\\b")) {
            return base;
        }
        return base + suffix;
    }

    std::mt19937_64 rng_;
};

TEST(TestRegexPrefilter, RandomisedExactness)
{
    random_regex_generator gen{42};
    literal_scanner::scratch scratch;

    std::size_t with_prefilter = 0;
    std::size_t matches = 0;
    std::size_t rejected = 0;
    for (int i = 0; i < 20000; ++i) {
        const bool case_sensitive = gen.coin();
        auto pattern = gen.regex();
        auto re = try_compile(pattern, case_sensitive);
        if (!re->ok()) {
            continue;
        }

        auto prefilter = regex_prefilter::from_regex(*re);
        if (!prefilter) {
            continue;
        }
        ++with_prefilter;

        std::vector<const regex_prefilter *> prefilters{prefilter.get()};
        auto scanner = literal_scanner::build(prefilters);

        for (int j = 0; j < 200; ++j) {
            auto input = gen.input();
            const bool passes = prefilter_passes(*prefilter, *scanner, input, scratch);
            if (re2::RE2::PartialMatch(input, *re)) {
                ++matches;
                EXPECT_TRUE(passes)
                    << "regex: " << pattern << " (case sensitive: " << case_sensitive
                    << ") input: " << input << " prefilter: " << prefilter->to_string();
            } else if (!passes) {
                ++rejected;
            }
        }
    }

    // Make sure the test is meaningful
    EXPECT_GT(with_prefilter, 500);
    EXPECT_GT(matches, 5000);
    EXPECT_GT(rejected, 5000);
    std::cout << "regexes with a prefilter: " << with_prefilter << ", matches: " << matches
              << ", rejected non-matches: " << rejected << '\n';
}

} // namespace
