// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "processor/uri_parse.hpp"

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "ddwaf.h"
#include "object_store.hpp"
#include "processor/base.hpp"
#include "uri_utils.hpp"
#include "utils.hpp"

#include <string_view>
#include <unordered_map>
#include <utility>

using namespace std::literals;

namespace ddwaf {

namespace {

ddwaf_object string_view_to_object(std::string_view str)
{
    ddwaf_object obj;
    if (!str.empty()) {
        ddwaf_object_stringl(&obj, str.data(), str.size());
    } else {
        ddwaf_object_string(&obj, "");
    }
    return obj;
}

ddwaf_object split_query_parameters(const uri_decomposed &decomposed)
{
    // This map is used to track if there are multiple instances of the same key, the
    // value will either be a:
    //   - A boolean if it's a flag
    //   - A string if there's only one value
    //   - An array if there are multiple values
    std::unordered_map<std::string_view, ddwaf_object> query_keys;
    auto query_remaining = decomposed.query;
    while (!query_remaining.empty()) {
        // Get the next query parameter
        std::string_view parameter;
        auto separator_pos = query_remaining.find_first_of('&');
        if (separator_pos != std::string_view::npos) {
            parameter = query_remaining.substr(0, separator_pos);
            query_remaining = query_remaining.substr(separator_pos + 1);
        } else {
            parameter = query_remaining;
            query_remaining = {};
        }

        std::string_view key;
        ddwaf_object value;

        // Check if it's in the key=value format
        //  - key= is considered an empty string value
        //  - key is considered a flag
        auto assignment_pos = parameter.find_first_of('=');
        if (assignment_pos == std::string_view::npos) {
            key = parameter;

            // Ignore empty keys
            if (key.empty()) {
                continue;
            }

            // We can consider this a modifier rather than a kv pair
            ddwaf_object_bool(&value, true);
        } else {
            key = parameter.substr(0, assignment_pos);
            // Ignore empty keys
            if (key.empty()) {
                continue;
            }

            auto value_str = parameter.substr(assignment_pos + 1);
            ddwaf_object_stringl(&value, value_str.data(), value_str.size());
        }

        // Check if the key has the array suffix ([]) and strip it, if the suffix
        // contains an index ([index]), we just consider it a separate key
        if (key.ends_with("[]")) {
            key.remove_suffix(sizeof("[]") - 1);
        }

        auto it = query_keys.find(key);
        if (it == query_keys.end()) {
            query_keys.emplace(key, value);
        } else {
            // Duplicate! We need to create an array or add to it
            if (it->second.type != DDWAF_OBJ_ARRAY) {
                ddwaf_object array;
                ddwaf_object_array(&array);
                ddwaf_object_array_add(&array, &it->second);
                it->second = array;
            }

            ddwaf_object_array_add(&it->second, &value);
        }
    }

    ddwaf_object query;
    ddwaf_object_map(&query);
    for (auto &[key, value] : query_keys) {
        ddwaf_object_map_addl(&query, key.data(), key.size(), &value);
    }

    return query;
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> uri_parse_processor::eval_impl(
    const unary_argument<std::string_view> &input, processor_cache & /*cache*/,
    ddwaf::timer & /*deadline*/) const
{
    const object_store::attribute attr =
        input.ephemeral ? object_store::attribute::ephemeral : object_store::attribute::none;

    auto decomposed = uri_parse(input.value);
    if (!decomposed.has_value()) {
        return {};
    }

    ddwaf_object scheme = string_view_to_object(decomposed->scheme);
    ddwaf_object userinfo = string_view_to_object(decomposed->authority.userinfo);
    ddwaf_object host = string_view_to_object(decomposed->authority.host);

    ddwaf_object port;
    ddwaf_object_unsigned(&port, decomposed->authority.port);

    ddwaf_object path = string_view_to_object(decomposed->path);
    ddwaf_object query = split_query_parameters(*decomposed);
    ddwaf_object fragment = string_view_to_object(decomposed->fragment);

    ddwaf_object output;
    ddwaf_object_map(&output);
    ddwaf_object_map_addl(&output, STRL("scheme"), &scheme);
    ddwaf_object_map_addl(&output, STRL("userinfo"), &userinfo);
    ddwaf_object_map_addl(&output, STRL("host"), &host);
    ddwaf_object_map_addl(&output, STRL("port"), &port);
    ddwaf_object_map_addl(&output, STRL("path"), &path);
    ddwaf_object_map_addl(&output, STRL("query"), &query);
    ddwaf_object_map_addl(&output, STRL("fragment"), &fragment);

    return {output, attr};
}

} // namespace ddwaf
