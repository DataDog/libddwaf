// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/url_basename.hpp"
#include "transformer/common/cow_string.hpp"
#include <cstddef>

namespace ddwaf::transformer {

bool url_basename::transform_impl(cow_string &str)
{
    size_t path_end = 0;
    size_t last_slash = 0;

    // Look for the end of the path, and tag the slashes along the way
    while (path_end < str.length() && str.at(path_end) != '?' && str.at(path_end) != '#') {
        if (str.at(path_end) == '/') {
            last_slash = path_end;
        }

        path_end += 1;
    }

    if (last_slash == 0 && str.at(0) != '/' && path_end == str.length()) {
        return false;
    }

    // Find the character after the /. We need to be careful when no slash are present
    size_t read = (last_slash != 0 || str.at(0) == '/') ? last_slash + 1 : last_slash;
    size_t write = 0;
    // Copy between the last slash and the end of the path
    while (read < path_end) { str[write++] = str.at(read++); }

    str.truncate(write);

    return true;
}

} // namespace ddwaf::transformer
