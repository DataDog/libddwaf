// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "processor/jwt_decode.hpp"

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "cow_string.hpp"
#include "json_utils.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "transformer/base64_decode.hpp"
#include "utils.hpp"

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

using namespace std::literals;

namespace ddwaf {

namespace {

struct exploded_jwt {
    std::string_view header;
    std::string_view payload;
    std::string_view signature;
};

std::pair<bool, exploded_jwt> split_token(std::string_view source)
{
    constexpr char delim = '.';

    exploded_jwt parts;
    std::size_t end = source.find(delim);
    if (end == std::string_view::npos || end == source.size() - 1) {
        // We expect at least one more delimiter, so this can't be at the end
        // and the delimiter must exist
        return {false, {}};
    }

    parts.header = source.substr(0, end);
    source.remove_prefix(end + 1);

    end = source.find(delim);
    if (end == std::string_view::npos) {
        // This delimiter must exist, but it can be at the end
        return {false, {}};
    }
    parts.payload = source.substr(0, end);

    if (end != source.size() - 1) {
        // If we have a signature, extract it
        parts.signature = source.substr(end + 1);
    }

    return {true, parts};
}

owned_object decode_and_parse(std::string_view source, nonnull_ptr<memory::memory_resource> alloc)
{
    cow_string cstr{source};
    if (!transformer::base64url_decode::transform(cstr)) {
        return {};
    }

    return json_to_object(static_cast<std::string_view>(cstr), alloc);
}

std::string_view find_token(object_view root, std::span<const std::string> key_path)
{
    object_view object = root;
    if (!key_path.empty()) {
        object = root.find_key_path(key_path);
        if (!object.has_value()) {
            return {};
        }
    }

    if (object.is_array() && !object.empty()) {
        // If the object is an array (which can happen due to serialisation)
        // take only the first element. Otherwise, the next if statement will
        // already take care of bailing out.
        object = object.at_value(0);
    }

    if (!object.is_string() || object.empty()) {
        return {};
    }

    return object.as<std::string_view>();
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<owned_object, evaluation_scope> jwt_decode::eval_impl(
    const unary_argument<object_view> &input, processor_cache & /*cache*/,
    nonnull_ptr<memory::memory_resource> alloc, ddwaf::timer & /*deadline*/) const
{
    std::string_view token = find_token(input.value, input.key_path);
    if (token.empty()) {
        return {};
    }

    static const std::string_view prefix = "Bearer";
    if (!token.starts_with(prefix)) {
        // Unlikely to be a JWT
        return {};
    }

    // Remove prefix and spaces
    token.remove_prefix(prefix.size());

    std::size_t spaces = 0;
    while (spaces < token.size() && ddwaf::isspace(token[spaces])) { ++spaces; }

    token.remove_prefix(spaces);

    // Split jwt
    auto [valid, jwt] = split_token(token);
    if (!valid) {
        // Not a valid JWT
        return {};
    }

    // Decode header and payload and generate output
    auto output = object_builder::map({{"header", decode_and_parse(jwt.header, alloc)},
        {"payload", decode_and_parse(jwt.payload, alloc)},
        {"signature", object_builder::map({{"available", !jwt.signature.empty()}}, alloc)}});

    return {std::move(output), input.scope};
}

} // namespace ddwaf
