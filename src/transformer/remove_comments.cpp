// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>
#include <utility>

#include "transformer/common/cow_string.hpp"
#include "transformer/remove_comments.hpp"

namespace ddwaf::transformer {

bool remove_comments::transform_impl(cow_string &str)
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
                // Don't bother updating the read index since we'll exit anyway
                type = comment_type::eol; // SQL comment
                break;
            }

            if (str.at(read) == '#') {
                // Don't bother updating the read index since we'll exit anyway
                type = comment_type::eol; // Shell comment
                break;
            }

            if (str.at(read) == '/' && read + 1 < str.length()) {
                if (str.at(read + 1) == '*') {
                    read += 2;
                    type = comment_type::c;
                    break;
                }

                if (str.at(read + 1) == '/') {
                    // Don't bother updating the read index since we'll exit anyway
                    type = comment_type::eol; // C/C++ end of line comment
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
                // If we reach this point we have found no comment terminator
                // so we set read to str.length() in order to exit.
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

} // namespace ddwaf::transformer
