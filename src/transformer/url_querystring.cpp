// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/url_querystring.hpp"
#include "transformer/common/cow_string.hpp"
#include <cstddef>

namespace ddwaf::transformer {

bool url_querystring::transform_impl(cow_string &str)
{
    size_t read = 0;

    // Find the end of the path, i.e either the end of the URL, the begining of the query
    // string or the fragment
    for (; read < str.length() && str.at(read) != '?' && str.at(read) != '#'; ++read) {}

    if (read < str.length() && str.at(read) == '?') {
        // If we had a query string, skip past the `?`
        read += 1;
    }

    // Copy until the end of the query string
    size_t write = 0;
    while (read < str.length() && str.at(read) != '#') { str[write++] = str.at(read++); }

    str.truncate(write);

    return true;
}

} // namespace ddwaf::transformer
