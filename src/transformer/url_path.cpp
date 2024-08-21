// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/url_path.hpp"
#include "transformer/common/cow_string.hpp"
#include <cstddef>

namespace ddwaf::transformer {

bool url_path::transform_impl(cow_string &str)
{
    size_t pos = 0;
    for (; pos < str.length() && str.at(pos) != '?' && str.at(pos) != '#'; ++pos) {}

    if (pos == str.length()) {
        return false;
    }

    str.truncate(pos);

    return true;
}

} // namespace ddwaf::transformer
