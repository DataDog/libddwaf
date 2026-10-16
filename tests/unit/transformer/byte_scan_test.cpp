// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#  include <sys/mman.h>
#  include <unistd.h>
#endif

#include "cow_string.hpp"
#include "transformer/byte_scan.hpp"
#include "transformer/compress_whitespace.hpp"
#include "transformer/lowercase.hpp"
#include "transformer/normalize_path.hpp"
#include "transformer/remove_comments.hpp"
#include "transformer/remove_nulls.hpp"
#include "transformer/shell_unescape.hpp"
#include "transformer/unicode_normalize.hpp"
#include "transformer/url_decode.hpp"
#include "utf8.hpp"
#include "utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::transformer;

// NOLINTBEGIN(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,readability-function-cognitive-complexity)
namespace {

// The transformers as they were before their scans were vectorised: the
// fast paths must produce exactly the same results
namespace reference {

bool remove_nulls(cow_string &str)
{
    std::size_t read = 0;
    for (; read < str.length() && str.at(read) != '\0'; ++read) {}
    if (read == str.length()) {
        return false;
    }
    std::size_t write = read;
    for (; read < str.length(); ++read) {
        auto c = str.at(read);
        str[write] = c;
        write += static_cast<std::size_t>(!(c == 0));
    }
    str.truncate(write);
    return true;
}

bool lowercase(cow_string &str)
{
    std::size_t pos = 0;
    for (; pos < str.length() && (str.at(pos) < 'A' || str.at(pos) > 'Z'); ++pos) {}
    if (pos == str.length()) {
        return false;
    }
    for (; pos < str.length(); ++pos) { str[pos] = ddwaf::tolower(str.at(pos)); }
    return true;
}

bool compress_whitespace(cow_string &str)
{
    std::size_t read = 1;
    for (; read < str.length() && (str.at(read) != ' ' || str.at(read - 1) != ' '); ++read) {}
    if (read >= str.length()) {
        return false;
    }
    std::size_t write = read;
    while (read < str.length()) {
        if (str.at(read) == ' ' && str.at(read - 1) == ' ') {
            // NOLINTNEXTLINE(bugprone-inc-dec-in-conditions)
            while (++read < str.length() && str.at(read) == ' ') {}
            if (read == str.length()) {
                break;
            }
        }
        str[write++] = str.at(read++);
    }
    str.truncate(write);
    return true;
}

bool url_decode_common(cow_string &str, bool read_iis)
{
    std::size_t read = 0;
    for (; read < str.length() && str.at(read) != '+'; ++read) {
        if (read + 2 < str.length() && str.at(read) == '%' && ddwaf::isxdigit(str.at(read + 1)) &&
            ddwaf::isxdigit(str.at(read + 2))) {
            break;
        }
        if (read_iis && read + 5 < str.length() && str.at(read) == '%' &&
            (str.at(read + 1) | 0x20) == 'u' && ddwaf::isxdigit(str.at(read + 2)) &&
            ddwaf::isxdigit(str.at(read + 3)) && ddwaf::isxdigit(str.at(read + 4)) &&
            ddwaf::isxdigit(str.at(read + 5))) {
            break;
        }
    }
    if (read >= str.length()) {
        return false;
    }
    std::size_t write = read;
    while (read < str.length()) {
        if (str.at(read) == '+') {
            str[write++] = ' ';
            read += 1;
        } else if (str.at(read) == '%') {
            if (read + 2 < str.length() && ddwaf::isxdigit(str.at(read + 1)) &&
                ddwaf::isxdigit(str.at(read + 2))) {
                const uint8_t highBits = from_hex(str.at(read + 1));
                const uint8_t lowBits = from_hex(str.at(read + 2));
                str[write++] = static_cast<char>(highBits << 4U | lowBits);
                read += 3;
            } else if (read_iis && read + 5 < str.length() && (str.at(read + 1) | 0x20) == 'u' &&
                       ddwaf::isxdigit(str.at(read + 2)) && ddwaf::isxdigit(str.at(read + 3)) &&
                       ddwaf::isxdigit(str.at(read + 4)) && ddwaf::isxdigit(str.at(read + 5))) {
                const auto codepoint =
                    (uint16_t)(from_hex(str.at(read + 2)) << 12U |
                               from_hex(str.at(read + 3)) << 8U | from_hex(str.at(read + 4)) << 4U |
                               from_hex(str.at(read + 5)));
                read += 6;
                if (codepoint <= 0x7f) {
                    str[write++] = static_cast<char>(codepoint);
                } else {
                    write += ddwaf::utf8::write_codepoint(codepoint, &str[write], read - write);
                }
            } else {
                str[write++] = str.at(read++);
            }
        } else {
            str[write++] = str.at(read++);
        }
    }
    str.truncate(write);
    return true;
}

bool url_decode(cow_string &str) { return url_decode_common(str, false); }

bool url_decode_iis(cow_string &str)
{
    bool output = false;
    while (url_decode_common(str, true)) { output = true; }
    return output;
}

bool shell_unescape(cow_string &str)
{
    uint64_t read = 0;
    bool transform_required = false;
    for (; read < str.length(); read += 1) {
        const char c = str.at(read);
        if (read + 1 < str.length()) {
            const char next = str.at(read + 1);
            if (c == ',' || c == ';' ||
                ((ddwaf::isspace(c)) && ((ddwaf::isspace(next)) || next == ',' || next == ';' ||
                                         next == '(' || next == '/'))) {
                transform_required = true;
                break;
            }
        }
        if (c == '\\' || c == '"' || c == '\'' || c == '^' || ddwaf::isupper(c)) {
            transform_required = true;
            break;
        }
    }
    if (!transform_required) {
        return false;
    }
    uint64_t write = read;
    for (; read < str.length(); read += 1) {
        const char c = str.at(read);
        if (c == '\\' || c == '"' || c == '\'' || c == '^') {
            continue;
        }
        if ((ddwaf::isspace(c)) || c == ',' || c == ';') {
            if (read + 1 < str.length()) {
                auto next = str.at(read + 1);
                if (ddwaf::isspace(next) || next == ',' || next == ';' || next == '(' ||
                    next == '/') {
                    continue;
                }
            }
            str[write++] = ' ';
        } else {
            str[write++] = ddwaf::tolower(str.at(read));
        }
    }
    if (write < str.length()) {
        str.truncate(write);
    }
    return true;
}

bool remove_comments(cow_string &str)
{
    enum class comment_type : uint8_t { unknown, html, c, eol } type = comment_type::unknown;
    bool comment_found = false;
    std::size_t read = 0;
    std::size_t write = 0;
    while (read < str.length()) {
        type = comment_type::unknown;
        while (read < str.length()) {
            if (str.at(read) == '<' && read + 3 < str.length() && str.at(read + 1) == '!' &&
                str.at(read + 2) == '-' && str.at(read + 3) == '-') {
                read += 4;
                type = comment_type::html;
                break;
            }
            if (str.at(read) == '-' && read + 1 < str.length() && str.at(read + 1) == '-') {
                type = comment_type::eol;
                break;
            }
            if (str.at(read) == '#') {
                type = comment_type::eol;
                break;
            }
            if (str.at(read) == '/' && read + 1 < str.length()) {
                if (str.at(read + 1) == '*') {
                    read += 2;
                    type = comment_type::c;
                    break;
                }
                if (str.at(read + 1) == '/') {
                    type = comment_type::eol;
                    break;
                }
            }
            if (comment_found) {
                str[write] = str.at(read);
            }
            ++write;
            ++read;
        }
        if (type == comment_type::unknown || type == comment_type::eol) {
            break;
        }
        comment_found = true;
        while (read < str.length()) {
            std::pair<bool, std::size_t> result;
            // NOLINTNEXTLINE(bugprone-assignment-in-if-condition)
            if (type == comment_type::html && (result = str.find('-', read)).first) {
                read = result.second;
                if (read + 2 < str.length() && str.at(read + 1) == '-' && str.at(read + 2) == '>') {
                    read += 3;
                    break;
                }
                ++read;
                // NOLINTNEXTLINE(bugprone-assignment-in-if-condition)
            } else if (type == comment_type::c && (result = str.find('*', read)).first) {
                read = result.second;
                if (read + 1 < str.length() && str.at(read + 1) == '/') {
                    read += 2;
                    break;
                }
                ++read;
            } else {
                read = str.length();
                break;
            }
        }
    }
    if (!comment_found && type == comment_type::unknown) {
        return false;
    }
    str.truncate(write);
    return true;
}

bool normalize_path(cow_string &str)
{
    bool modified = false;
    std::size_t read = 0;
    std::size_t write = 0;
    while (read < str.length()) {
        if (str.at(read) != '.' || (read + 1 != str.length() && str.at(read + 1) != '/')) {
            if (str.copy_char(read++, write++)) {
                modified = true;
            }
            continue;
        }
        if (read == 0 || str.at(read - 1) == '/') {
            read += 2;
        } else if (read > 1 && str.at(read - 1) == '.' && str.at(read - 2) == '/') {
            write -= std::min(write, static_cast<std::size_t>(3));
            while (write != 0 && str[write] != '/') { write -= 1; }
            str[write++] = '/';
            read += 2;
            modified = true;
        } else {
            if (str.copy_char(read++, write++)) {
                modified = true;
            }
        }
    }
    if (!modified) {
        return false;
    }
    str.truncate(write);
    return true;
}

bool normalize_path_win(cow_string &str)
{
    bool normalized = false;
    for (std::size_t pos = 0; pos < str.length(); ++pos) {
        if (str.at(pos) == '\\') {
            normalized = true;
            str[pos] = '/';
        }
    }
    auto res = normalize_path(str);
    return res || normalized;
}

bool unicode_normalize_needed(std::string_view str)
{
    uint32_t codepoint;
    uint64_t position = 0;
    while ((codepoint = utf8::fetch_next_codepoint(str.data(), position, str.length())) !=
           utf8::UTF8_EOF) {
        if (codepoint == utf8::UTF8_INVALID || codepoint < 0x80) {
            continue;
        }
        int32_t decomposed_codepoint = 0;
        const size_t decomposed_length =
            utf8::normalize_codepoint(codepoint, &decomposed_codepoint, 1);
        if (decomposed_length != 1 || codepoint != static_cast<uint32_t>(decomposed_codepoint)) {
            return true;
        }
    }
    return false;
}

bool unicode_normalize(cow_string &str)
{
    return unicode_normalize_needed(static_cast<std::string_view>(str)) &&
           utf8::normalize_string(str);
}

} // namespace reference

using transform_fn = std::function<bool(cow_string &)>;

struct transformer_pair {
    std::string_view name;
    transform_fn current;
    transform_fn reference;
    // Characters the transformer looks for, which random strings are made of
    std::string_view alphabet;
};

bool with_base(const transform_fn &fn, cow_string &str)
{
    // What base<T>::transform adds to the reference implementations
    return str.length() > 0 && fn(str);
}

std::vector<transformer_pair> transformer_pairs()
{
    return {
        {"remove_nulls", remove_nulls::transform, reference::remove_nulls,
         std::string_view{"\0ab \0\0", 7}},
        {"lowercase", lowercase::transform, reference::lowercase, "aAzZ@[`{ \x80\xc1"},
        {"compress_whitespace", compress_whitespace::transform, reference::compress_whitespace,
         "   a\t"},
        {"url_decode", url_decode::transform, reference::url_decode, "%%+0aFgu2b5c%"},
        {"url_decode_iis", url_decode_iis::transform, reference::url_decode_iis, "%%+0aFUu255%c"},
        {"shell_unescape", shell_unescape::transform, reference::shell_unescape,
         "a ,;(/\\\"'^Zz\t\n\v\f\r\x08\x0e@["},
        {"remove_comments", remove_comments::transform, reference::remove_comments, "<!-->#/*a\n"},
        {"normalize_path", normalize_path::transform, reference::normalize_path, "./a./\\"},
        {"normalize_path_win", normalize_path_win::transform, reference::normalize_path_win,
         "./a./\\"},
        {"unicode_normalize", unicode_normalize::transform, reference::unicode_normalize,
         "aA\xc3\xa9\xcc\x81\xef\xbc\xa1\xe2\x84\xaa\x80\xff\xc3"},
    };
}

std::string random_string(std::mt19937_64 &rng, std::string_view alphabet, std::size_t length)
{
    std::string str(length, '\0');
    for (auto &c : str) {
        const auto r = rng();
        // Mostly the transformer's alphabet, sometimes any byte
        if ((r & 0xF) == 0) {
            c = static_cast<char>(r >> 8);
        } else {
            c = alphabet[(r >> 8) % alphabet.size()];
        }
    }
    return str;
}

void compare(const transformer_pair &pair, std::string_view input)
{
    // Exact allocations, so that a read past the end is caught by ASan
    std::vector<char> buffer_current(input.begin(), input.end());
    std::vector<char> buffer_reference(input.begin(), input.end());

    cow_string current{std::string_view{buffer_current.data(), buffer_current.size()}};
    cow_string reference{std::string_view{buffer_reference.data(), buffer_reference.size()}};

    if (input.empty()) {
        // cow_string rejects null pointers
        return;
    }

    const bool res_current = pair.current(current);
    const bool res_reference = with_base(pair.reference, reference);

    ASSERT_EQ(res_current, res_reference) << pair.name << " on " << testing::PrintToString(input);
    ASSERT_EQ(static_cast<std::string_view>(current), static_cast<std::string_view>(reference))
        << pair.name << " on " << testing::PrintToString(input);
    ASSERT_EQ(current.modified(), reference.modified())
        << pair.name << " on " << testing::PrintToString(input);
    // The input is never modified in place
    ASSERT_EQ(std::string_view(buffer_current.data(), buffer_current.size()), input);

    // A string that a previous transformer has already copied is transformed
    // in place
    cow_string copied_current{std::string_view{buffer_current.data(), buffer_current.size()}};
    cow_string copied_reference{std::string_view{buffer_reference.data(), buffer_reference.size()}};
    (void)copied_current.modifiable_data();
    (void)copied_reference.modifiable_data();

    ASSERT_EQ(pair.current(copied_current), with_base(pair.reference, copied_reference))
        << pair.name << " on a copy of " << testing::PrintToString(input);
    ASSERT_EQ(static_cast<std::string_view>(copied_current),
              static_cast<std::string_view>(copied_reference))
        << pair.name << " on a copy of " << testing::PrintToString(input);
}

struct is_x {
    template <typename T> static auto match(T c) { return byte_scan::eq(c, 'x'); }
};
struct is_high {
    template <typename T> static auto match(T c)
    { return byte_scan::in_range(c, static_cast<char>(0xF0), static_cast<char>(0xFF)); }
};
struct is_digit_or_x {
    template <typename T> static auto match(T c)
    { return byte_scan::in_range(c, '0', '9') | byte_scan::eq(c, 'x'); }
};

struct x_then_y_or_last_x {
    template <typename T> static auto match(T c, T next)
    { return (byte_scan::eq(c, 'x') & byte_scan::eq(next, 'y')) | byte_scan::eq(c, 'z'); }
    static bool match_last(char c) { return c == 'x'; }
};

TEST(TestByteScan, FindFirstMatchesNaive)
{
    std::mt19937_64 rng{42};
    for (std::size_t length = 0; length < 70; ++length) {
        for (int iteration = 0; iteration < 50; ++iteration) {
            std::string str(length, 'a');
            for (auto &c : str) {
                const auto r = rng() % 40;
                c = r == 0 ? 'x' : (r == 1 ? '5' : (r == 2 ? static_cast<char>(0xF5) : 'a'));
            }
            std::vector<char> buffer(str.begin(), str.end());
            for (std::size_t start = 0; start <= length; ++start) {
                auto naive = [&](auto pred) {
                    std::size_t i = start;
                    while (i < length && !pred(str[i])) { ++i; }
                    return i;
                };
                EXPECT_EQ((byte_scan::find_first<is_x>(buffer.data(), length, start)),
                          naive([](char c) { return c == 'x'; }));
                EXPECT_EQ((byte_scan::find_first<is_high>(buffer.data(), length, start)),
                          naive([](char c) { return static_cast<uint8_t>(c) >= 0xF0; }));
                EXPECT_EQ((byte_scan::find_first<is_digit_or_x>(buffer.data(), length, start)),
                          naive([](char c) { return (c >= '0' && c <= '9') || c == 'x'; }));
            }
        }
    }
}

TEST(TestByteScan, FindFirstPairMatchesNaive)
{
    std::mt19937_64 rng{43};
    for (std::size_t length = 0; length < 70; ++length) {
        for (int iteration = 0; iteration < 50; ++iteration) {
            std::string str(length, 'a');
            for (auto &c : str) {
                const auto r = rng() % 16;
                c = r < 3 ? 'x' : (r < 6 ? 'y' : (r == 6 && (rng() % 4) == 0 ? 'z' : 'a'));
            }
            std::vector<char> buffer(str.begin(), str.end());
            for (std::size_t start = 0; start <= length; ++start) {
                std::size_t expected = start;
                for (; expected < length; ++expected) {
                    if (expected + 1 < length) {
                        if ((str[expected] == 'x' && str[expected + 1] == 'y') ||
                            str[expected] == 'z') {
                            break;
                        }
                    } else if (str[expected] == 'x') {
                        break;
                    }
                }
                EXPECT_EQ(
                    (byte_scan::find_first_pair<x_then_y_or_last_x>(buffer.data(), length, start)),
                    expected);
            }
        }
    }
}

TEST(TestByteScan, TransformersMatchReference)
{
    std::mt19937_64 rng{44};
    for (const auto &pair : transformer_pairs()) {
        for (std::size_t length = 1; length < 100; ++length) {
            for (int iteration = 0; iteration < 200; ++iteration) {
                compare(pair, random_string(rng, pair.alphabet, length));
            }
        }
        for (int iteration = 0; iteration < 200; ++iteration) {
            compare(pair, random_string(rng, pair.alphabet, 100 + (rng() % 400)));
        }
    }
}

TEST(TestByteScan, TransformersMatchReferenceOnMostlyPlainInputs)
{
    // Long stretches of letters, with the transformer's characters here and
    // there, as in text
    std::mt19937_64 rng{46};
    for (const auto &pair : transformer_pairs()) {
        for (int iteration = 0; iteration < 3000; ++iteration) {
            const std::size_t length = 1 + (rng() % 300);
            const auto density = 2 + (rng() % 40);
            std::string str = random_string(rng, pair.alphabet, length);
            for (auto &c : str) {
                const auto r = rng();
                if (r % density != 0) {
                    c = "abcXYZ q"[(r >> 32) % 8];
                }
            }
            compare(pair, str);
        }
    }
}

TEST(TestByteScan, TransformersMatchReferenceOnSparseInputs)
{
    // Long runs without anything to transform, then a single interesting
    // character at every position
    for (const auto &pair : transformer_pairs()) {
        for (std::size_t length = 1; length < 70; ++length) {
            for (std::size_t pos = 0; pos < length; ++pos) {
                for (char c : pair.alphabet) {
                    std::string str(length, 'a');
                    str[pos] = c;
                    compare(pair, str);
                    if (pos + 1 < length && length < 40) {
                        for (char d : pair.alphabet) {
                            str[pos + 1] = d;
                            compare(pair, str);
                        }
                    }
                }
            }
        }
    }
}

#if !defined(_WIN32)
TEST(TestByteScan, NoReadPastTheEnd)
{
    // Strings that end right before an inaccessible page
    const auto page = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    void *mapping =
        mmap(nullptr, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mapping, MAP_FAILED);
    char *guard = static_cast<char *>(mapping) + page;
    ASSERT_EQ(mprotect(guard, page, PROT_NONE), 0);

    std::mt19937_64 rng{45};
    for (const auto &pair : transformer_pairs()) {
        for (std::size_t length = 1; length < 80; ++length) {
            for (int iteration = 0; iteration < 20; ++iteration) {
                // Nothing to transform, so that every byte is scanned
                char *begin = guard - length;
                std::fill_n(begin, length, 'a');
                cow_string str{std::string_view{begin, length}};
                pair.current(str);

                auto random = random_string(rng, pair.alphabet, length);
                std::copy(random.begin(), random.end(), begin);
                cow_string other{std::string_view{begin, length}};
                pair.current(other);
            }
        }
    }

    munmap(mapping, 2 * page);
}
#endif

} // namespace
// NOLINTEND(cppcoreguidelines-avoid-magic-numbers,readability-magic-numbers,readability-function-cognitive-complexity)
