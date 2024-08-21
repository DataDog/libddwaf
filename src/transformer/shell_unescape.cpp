// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "transformer/common/cow_string.hpp"
#include "transformer/shell_unescape.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {
/*
 * Reimplementing the cmdLine ModSecurity operator.
 * It is documented as follow:
 *
 * The cmdLine transformation function avoids this problem by manipulating the variable contend
 in the following ways:
 * 1. deleting all backslashes [\]
 * 2. deleting all double quotes ["]
 * 3. deleting all single quotes [']
 * 4. deleting all carets [^]
 * 5. deleting spaces before a slash [/]
 * 6. deleting spaces before an open parentesis [(]
 * 7. replacing all commas [,] and semicolon [;] into a space
 * 8. replacing all multiple spaces (including tab, newline, etc.) into one space
 * 9. transform all characters to lowercase
 */

bool shell_unescape::transform_impl(cow_string &str)
{
    uint64_t read = 0;

    bool transform_required = false;
    // Fast forward, also implement readOnly
    for (; read < str.length(); read += 1) {
        const char c = str.at(read);

        // Multi char sequences
        if (read + 1 < str.length()) {
            const char next = str.at(read + 1);

            // Character we need to trandform (7) or multiple spaces/space equivalent
            // characters? (5, 6 and 8)
            if (c == ',' || c == ';' ||
                ((ddwaf::isspace(c)) && ((ddwaf::isspace(next)) || next == ',' || next == ';' ||
                                            next == '(' || next == '/'))) {
                transform_required = true;
                break;
            }
        }

        // Remove 1, 2, 3 and 4, and detect 9
        if (c == '\\' || c == '"' || c == '\'' || c == '^' || ddwaf::isupper(c)) {
            transform_required = true;
            break;
        }
    }

    if (!transform_required) {
        return false;
    }

    uint64_t write = read;
    // Actually perform the update
    for (; read < str.length(); read += 1) {
        const char c = str.at(read);

        // Remove 1, 2, 3 and 4
        if (c == '\\' || c == '"' || c == '\'' || c == '^') {
            continue;
        }
        if ((ddwaf::isspace(c)) || c == ',' || c == ';') {
            // We're doing all the space trimming here:
            //  We only copy the last space (or space terminator) character

            // First, we get rid of the case where we're on the last char: we will need to
            // write a space no matter what then
            if (read + 1 < str.length()) {
                // Then, we find if the next char is space equivalent (7, 8) or a space
                // terminator (5, 6)
                auto next = str.at(read + 1);
                if (ddwaf::isspace(next) || next == ',' || next == ';' || next == '(' ||
                    next == '/') {
                    // We drop this character, the next iteration will take care of it
                    continue;
                }
            }

            // Otherwise, we write this last space!
            str[write++] = ' ';
        } else {
            // Handle upper case character
            str[write++] = ddwaf::tolower(str.at(read));
        }
    }

    if (write < str.length()) {
        str.truncate(write);
    }

    return true;
}

} // namespace ddwaf::transformer
