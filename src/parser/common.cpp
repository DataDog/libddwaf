// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "parameter.hpp"
#include "parser/common.hpp"
#include "parser/specification.hpp"
#include "transformer/base.hpp"

namespace ddwaf::parser {

std::optional<transformer_id> transformer_from_string(std::string_view str)
{
    static const std::unordered_map<std::string_view, transformer_id> transformer_mapping{
        {"lowercase", transformer_id::lowercase},
        {"remove_nulls", transformer_id::remove_nulls},
        {"compress_whitespace", transformer_id::compress_whitespace},
        {"normalize_path", transformer_id::normalize_path},
        {"normalize_path_win", transformer_id::normalize_path_win},
        {"url_decode", transformer_id::url_decode},
        {"url_decode_iis", transformer_id::url_decode_iis},
        {"css_decode", transformer_id::css_decode},
        {"js_decode", transformer_id::js_decode},
        {"html_entity_decode", transformer_id::html_entity_decode},
        {"base64_decode", transformer_id::base64_decode},
        {"base64_encode", transformer_id::base64_encode},
        {"shell_unescape", transformer_id::shell_unescape},
        {"url_basename", transformer_id::url_basename},
        {"url_path", transformer_id::url_path},
        {"url_querystring", transformer_id::url_querystring},
        {"remove_comments", transformer_id::remove_comments},
        {"unicode_normalize", transformer_id::unicode_normalize},

        // Aliases
        {"removeNulls", transformer_id::remove_nulls},
        {"compressWhiteSpace", transformer_id::compress_whitespace},
        {"normalizePath", transformer_id::normalize_path},
        {"normalizePathWin", transformer_id::normalize_path_win},
        {"urlDecode", transformer_id::url_decode},
        {"urlDecodeUni", transformer_id::url_decode_iis},
        {"cssDecode", transformer_id::css_decode},
        {"jsDecode", transformer_id::js_decode},
        {"htmlEntityDecode", transformer_id::html_entity_decode},
        {"base64Decode", transformer_id::base64_decode},
        {"base64Encode", transformer_id::base64_encode},
        {"cmdLine", transformer_id::shell_unescape},
        {"_sqr_basename", transformer_id::url_basename},
        {"_sqr_filename", transformer_id::url_path},
        {"_sqr_querystring", transformer_id::url_querystring},
        {"removeComments", transformer_id::remove_comments},
    };

    auto it = transformer_mapping.find(str);
    if (it != transformer_mapping.end()) {
        return {it->second};
    }

    return std::nullopt;
}

reference_spec parse_reference(const parameter::map &target)
{
    auto ref_id = at<std::string>(target, "rule_id", {});
    if (!ref_id.empty()) {
        return {reference_type::id, std::move(ref_id), {}};
    }

    ref_id = at<std::string>(target, "id", {});
    if (!ref_id.empty()) {
        return {reference_type::id, std::move(ref_id), {}};
    }

    auto tag_map = at<parameter::map>(target, "tags", {});
    if (!tag_map.empty()) {
        std::unordered_map<std::string, std::string> tags;
        for (auto &[key, value] : tag_map) { tags.emplace(key, value); }

        return {reference_type::tags, {}, std::move(tags)};
    }

    return {reference_type::none, {}, {}};
}

} // namespace ddwaf::parser
