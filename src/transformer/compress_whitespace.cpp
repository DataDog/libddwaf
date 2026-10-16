// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>

#include "cow_string.hpp"
#include "transformer/byte_scan.hpp"
#include "transformer/compress_whitespace.hpp"

namespace ddwaf::transformer {

namespace {

struct is_double_space {
    template <typename T> static auto match(T c, T next)
    { return byte_scan::eq(c, ' ') & byte_scan::eq(next, ' '); }
    static bool match_last(char /*c*/) { return false; }
};

} // namespace

bool compress_whitespace::transform_impl(cow_string &str)
{
    // First look for the first two consecutives space char, read is the
    // position of the second one
    std::size_t read = byte_scan::find_first_pair<is_double_space>(str.data(), str.length()) + 1;

    //  If we're checking whether we need to do change, finding such a chain mean we need to
    //  do so (we return true if we need to update)
    if (read >= str.length()) {
        return false;
    }

    //  If we're mutating the string, then we have the starting offset
    std::size_t write = read;
    while (read < str.length()) {
        // When we find two consecutive spaces, we skip over them
        //  We check with read - 1 to make sure at least one space is commited
        if (str.at(read) == ' ' && str.at(read - 1) == ' ') {
            // Skip ahead
            // NOLINTNEXTLINE(bugprone-inc-dec-in-conditions)
            while (++read < str.length() && str.at(read) == ' ') {}

            // Should we run the end of the loop?
            if (read == str.length()) {
                break;
            }
        }

        str[write++] = str.at(read++);
    }

    str.truncate(write);

    return true;
}

} // namespace ddwaf::transformer
