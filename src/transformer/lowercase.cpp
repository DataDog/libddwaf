// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <transformer/lowercase.hpp>

namespace ddwaf::transformer {

bool lowercase::transform_impl(lazy_string &str) {
    size_t pos = 0;

    // First loop looking for the first non-lowercase char
    for (; pos < str.length() && (str.at(pos) < 'A' || str.at(pos) > 'Z'); ++pos) {}

    //  If we're checking whether we need to do change, finding such a char mean we need to
    //  do so (we return true if we need to update)
    if (pos == str.length()) {
        return false;
    }

    //  If we're mutating the string, then we have the starting offset
    for (; pos < str.length(); ++pos) {
        auto c = str.at(pos);
        if (c >= 'A' && c <= 'Z') {
            str[pos] += 'a' - 'A';
        }
    }

    return true;
}

} // namespace ddwaf::transformer
