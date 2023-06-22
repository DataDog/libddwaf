// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <transformer/compress_whitespace.hpp>

namespace ddwaf::transformer {

bool compress_whitespace::transform(lazy_string &str)
{
    // First loop looking for the first two consecutives space char
    uint64_t read = 1;
    for (; read < str.length() && (str.at(read) != ' ' || str.at(read - 1) != ' '); ++read) {}

    //  If we're checking whether we need to do change, finding such a chain mean we need to
    //  do so (we return true if we need to update)
    if (read >= str.length()) {
        return false;
    }

    //  If we're mutating the string, then we have the starting offset
    uint64_t write = read;
    while (read < str.length()) {
        // When we find two consecutive spaces, we skip over them
        //  We check with read - 1 to make sure at least one space is commited
        if (str.at(read) == ' ' && str.at(read - 1) == ' ') {
            // Skip ahead
            while (++read < str.length() && str.at(read) == ' ') {}

            // Should we run the end of the loop?
            if (read == str.length()) {
                break;
            }
        }

        str[write++] = str.at(read++);
    }

    str.finalize(write);

    return true;
}

} // namespace ddwaf::transformer
