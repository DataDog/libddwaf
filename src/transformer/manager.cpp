// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <span>
#include <string_view>

#include "object.hpp"
#include "transformer/base.hpp"
#include "transformer/base64_decode.hpp"
#include "transformer/base64_encode.hpp"
#include "transformer/common/cow_string.hpp"
#include "transformer/compress_whitespace.hpp"
#include "transformer/css_decode.hpp"
#include "transformer/html_entity_decode.hpp"
#include "transformer/js_decode.hpp"
#include "transformer/lowercase.hpp"
#include "transformer/manager.hpp"
#include "transformer/normalize_path.hpp"
#include "transformer/remove_comments.hpp"
#include "transformer/remove_nulls.hpp"
#include "transformer/shell_unescape.hpp"
#include "transformer/unicode_normalize.hpp"
#include "transformer/url_basename.hpp"
#include "transformer/url_decode.hpp"
#include "transformer/url_path.hpp"
#include "transformer/url_querystring.hpp"

namespace ddwaf::transformer {

namespace {

bool call_transformer(transformer_id id, cow_string &str)
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
    case transformer_id::url_basename:
        return url_basename::transform(str);
    case transformer_id::url_path:
        return url_path::transform(str);
    case transformer_id::url_querystring:
        return url_querystring::transform(str);
    case transformer_id::shell_unescape:
        return shell_unescape::transform(str);
    case transformer_id::css_decode:
        return css_decode::transform(str);
    case transformer_id::js_decode:
        return js_decode::transform(str);
    case transformer_id::html_entity_decode:
        return html_entity_decode::transform(str);
    case transformer_id::base64_decode:
        return base64_decode::transform(str);
    case transformer_id::base64_encode:
        return base64_encode::transform(str);
    }

    return false;
}

} // namespace

bool manager::transform(object_view source, owned_object &destination,
    const std::span<const transformer_id> &transformers)
{
    if (!source.is_string() || source.empty()) {
        return false;
    }

    bool transformed = false;
    cow_string str(source.as<std::string_view>());
    for (auto transformer : transformers) {
        auto res = call_transformer(transformer, str);
        transformed = transformed || res;
    }

    if (!transformed) {
        return false;
    }

    // Note that this object might contain a string which is greater in
    // capacity than the length specified
    auto [buffer, length] = str.move();

    // The memory returned by str.move() is now owned by destination, however
    // clang-tidy believes it has been leaked as it can't track the fact that
    // it has changed ownership.
    // NOLINTNEXTLINE(clang-analyzer-unix.Malloc)
    destination = owned_object::make_string_nocopy(buffer, length);
    return true;
}

} // namespace ddwaf::transformer
