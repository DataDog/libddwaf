// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>

#include "cow_string.hpp"
#include "transformer/remove_nulls.hpp"

namespace ddwaf::transformer {

bool remove_nulls::transform_impl(cow_string &str)
{
    // First loop looking for the first null char
    std::size_t read = 0;
    for (; read < str.length() && str.at(read) != '\0'; ++read) {}

    //  If we're checking whether we need to do change, finding such a char mean we need to
    //  do so (we return true if we need to update)
    if (read == str.length()) {
        return false;
    }

    //  If we're mutating the string, then we have the starting offset
    std::size_t write = read;
    for (; read < str.length(); ++read) {
        auto c = str.at(read);
        str[write] = c;
        write += static_cast<std::size_t>(!(c == 0));
    }

    str.truncate(write);

    return true;
}

} // namespace ddwaf::transformer
