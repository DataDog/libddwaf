// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <cstring>
#include <ddwaf.h>
#include <string_view>

#include "transformer/common/cow_string.hpp"

namespace ddwaf {

enum class transformer_id : uint8_t {
    lowercase,
    remove_nulls,
    compress_whitespace,
    normalize_path,
    normalize_path_win,
    url_decode,
    url_decode_iis,
    css_decode,
    js_decode,
    html_entity_decode,
    base64_decode,
    base64_encode,
    shell_unescape,
    url_basename,
    url_path,
    url_querystring,
    remove_comments,
    unicode_normalize
};

namespace transformer {

template <typename T> class base {
public:
    static bool transform(cow_string &str)
    {
        if (str.length() == 0 || !T::needs_transform(static_cast<std::string_view>(str))) {
            return false;
        }

        return T::transform_impl(str);
    }
};

} // namespace transformer
} // namespace ddwaf
