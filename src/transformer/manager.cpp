// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/manager.hpp"
#include "ddwaf.h"
#include "transformer/compress_whitespace.hpp"
#include "transformer/lowercase.hpp"
#include "transformer/normalize_path.hpp"
#include "transformer/remove_comments.hpp"
#include "transformer/remove_nulls.hpp"
#include "transformer/unicode_normalize.hpp"
#include "transformer/url_decode.hpp"

namespace ddwaf::transformer {

bool call_transformer(transformer_id id, lazy_string &str)
{
    switch (id) {
    case transformer_id::lowercase:
        return lowercase::transform(str);
    case transformer_id::remove_nulls:
        return remove_nulls::transform(str);
    case transformer_id::compress_whitespace:
        return compress_whitespace::transform(str);
    case transformer_id::normalize_path:
        return normalize_path::transform(str);
    case transformer_id::normalize_path_win:
        return normalize_path_win::transform(str);
    case transformer_id::unicode_normalize:
        return unicode_normalize::transform(str);
    case transformer_id::remove_comments:
        return remove_comments::transform(str);
    case transformer_id::url_decode:
        return url_decode::transform(str);
    case transformer_id::url_decode_iis:
        return url_decode_iis::transform(str);
    case transformer_id::css_decode:
    case transformer_id::js_decode:
    case transformer_id::html_entity_decode:
    case transformer_id::base64_decode:
    case transformer_id::base64_decode_rfc2045:
    case transformer_id::base64_encode:
    case transformer_id::shell_unescape:
    case transformer_id::url_basename:
    case transformer_id::url_path:
    case transformer_id::url_querystring:
    default:
        break;
    }

    return false;
}

bool manager::transform(const ddwaf_object &source, ddwaf_object &destination,
    const std::vector<transformer_id> &transformers)
{
    if (source.type != DDWAF_OBJ_STRING || source.stringValue == nullptr) {
        return false;
    }

    bool transformed = false;
    lazy_string str({source.stringValue, static_cast<std::size_t>(source.nbEntries)});
    for (auto transformer : transformers) {
        auto res = call_transformer(transformer, str);
        transformed = transformed || res;
    }

    if (!transformed || !str.modified()) {
        return false;
    }

    // Note that this object might contain a string which is greater in
    // capacity than the length specified
    ddwaf_object_stringl_nc(&destination, str.data(), str.length());

    return true;
}

} // namespace ddwaf::transformer
