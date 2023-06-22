// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <transformer/remove_nulls.hpp>

namespace ddwaf::transformer {

bool remove_nulls::transform_impl(lazy_string &str)
{
    // First loop looking for the first null char
    uint64_t read = 0;
    for (; read < str.length() && str.at(read) != '\0'; ++read) {}

    //  If we're checking whether we need to do change, finding such a char mean we need to
    //  do so (we return true if we need to update)
    if (read == str.length()) {
        return false;
    }

    //  If we're mutating the string, then we have the starting offset
    uint64_t write = read;
    for (; read < str.length(); ++read) {
        auto c = str.at(read);
        if (c == 0) {
            continue;
        }
        str[write++] = c;
    }

    str.finalize(write);

    return true;
}

} // namespace ddwaf::transformer
