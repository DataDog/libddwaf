// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "processor/uri_parse.hpp"

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "uri_utils.hpp"

#include <string_view>
#include <unordered_map>
#include <utility>

using namespace std::literals;

namespace ddwaf {

namespace {

owned_object split_query_parameters(
    const uri_decomposed &decomposed, nonnull_ptr<memory::memory_resource> alloc)
{
    // This map is used to track if there are multiple instances of the same key, the
    // value will either be a:
    //   - A boolean if it's a flag
    //   - A string if there's only one value
    //   - An array if there are multiple values
    std::unordered_map<std::string_view, owned_object> query_keys;
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
        owned_object value;

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
            value = owned_object::make_boolean(true);
        } else {
            key = parameter.substr(0, assignment_pos);
            // Ignore empty keys
            if (key.empty()) {
                continue;
            }

            value = owned_object::make_string(parameter.substr(assignment_pos + 1), alloc);
        }

        // Check if the key has the array suffix ([]) and strip it, if the suffix
        // contains an index ([index]), we just consider it a separate key
        if (key.ends_with("[]")) {
            key.remove_suffix(sizeof("[]") - 1);
        }

        auto it = query_keys.find(key);
        if (it == query_keys.end()) {
            query_keys.emplace(key, std::move(value));
        } else {
            // Duplicate! We need to create an array or add to it
            if (!it->second.is_array()) {
                auto array = owned_object::make_array(2, alloc);
                array.emplace_back(std::move(it->second));
                it->second = std::move(array);
            }

            it->second.emplace_back(std::move(value));
        }
    }

    auto query = owned_object::make_map(query_keys.size(), alloc);
    for (auto &[key, value] : query_keys) { query.emplace(key, std::move(value)); }

    return query;
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
owned_object uri_parse_processor::eval_impl(const unary_argument<std::string_view> &input,
    processor_cache & /*cache*/, nonnull_ptr<memory::memory_resource> alloc,
    ddwaf::timer & /*deadline*/) const
{
    auto decomposed = uri_parse(input.value);
    if (!decomposed.has_value()) {
        return {};
    }

    auto output = owned_object::make_map(7, alloc);
    output.emplace("scheme", decomposed->scheme);
    output.emplace("userinfo", decomposed->authority.userinfo);
    output.emplace("host", decomposed->authority.host);
    output.emplace("port", decomposed->authority.port);
    output.emplace("path", decomposed->path);
    output.emplace("query", split_query_parameters(*decomposed, alloc));
    output.emplace("fragment", decomposed->fragment);

    return output;
}

} // namespace ddwaf
