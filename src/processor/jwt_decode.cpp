// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "processor/jwt_decode.hpp"

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "ddwaf.h"
#include "iterator.hpp"
#include "object_store.hpp"
#include "processor/base.hpp"
#include "transformer/base64_decode.hpp"
#include "transformer/common/cow_string.hpp"
#include "utils.hpp"

#include <cstddef>
#include <deque>
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
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

ddwaf_object json_to_object(std::string_view json)
{
    // Safety limit, potentially not necessary as if we can decode and parse
    // we should have a manageable json structure as other limits are already
    // in place.
    constexpr std::size_t max_depth = 20;

    auto to_object = [](const rapidjson::Value &doc) -> ddwaf_object {
        ddwaf_object object;
        if (doc.IsBool()) {
            ddwaf_object_bool(&object, doc.GetBool());
        } else if (doc.IsInt64()) {
            ddwaf_object_signed(&object, doc.GetInt64());
        } else if (doc.IsUint64()) {
            ddwaf_object_unsigned(&object, doc.GetUint64());
        } else if (doc.IsDouble()) {
            ddwaf_object_float(&object, doc.GetDouble());
        } else if (doc.IsString()) {
            const std::string_view str = doc.GetString();
            ddwaf_object_stringl(&object, str.data(), str.size());
        } else if (doc.IsNull()) {
            ddwaf_object_null(&object);
        } else if (doc.IsObject()) {
            ddwaf_object_map(&object);
        } else if (doc.IsArray()) {
            ddwaf_object_array(&object);
        } else {
            ddwaf_object_invalid(&object);
        }
        return object;
    };

    rapidjson::Document doc;
    const rapidjson::ParseResult result = doc.Parse(json.data(), json.size());
    if (result.IsError()) {
        return {};
    }

    std::deque<std::tuple<rapidjson::Value *, ddwaf_object *, std::size_t>> stack;
    auto object = to_object(doc);
    if (doc.IsArray() || doc.IsObject()) {
        stack.emplace_back(&doc, &object, 0);
    }

    while (!stack.empty()) {
        bool container_found = false;

        auto &[source, destination, idx] = stack.back();
        if (source->IsArray()) {
            for (; idx < source->Size(); ++idx) {
                auto &value = (*source)[idx];

                auto value_object = to_object(value);
                ddwaf_object_array_add(destination, &value_object);

                if ((value.IsObject() || value.IsArray()) && stack.size() < max_depth) {
                    container_found = true;
                    stack.emplace_back(&value, &destination->array[idx++], 0);
                    break;
                }
            }
        } else if (source->IsObject()) {
            using DifferenceType = rapidjson::Value::MemberIterator::DifferenceType;
            auto it = source->MemberBegin() + static_cast<DifferenceType>(idx);
            for (; it != source->MemberEnd(); ++idx, ++it) {
                auto value_object = to_object(it->value);

                const std::string_view key_sv = it->name.GetString();
                ddwaf_object_map_addl(destination, key_sv.data(), key_sv.length(), &value_object);

                if ((it->value.IsObject() || it->value.IsArray()) && stack.size() < max_depth) {
                    container_found = true;
                    stack.emplace_back(&(it->value), &destination->array[idx++], 0);
                    break;
                }
            }
        }

        if (!container_found) {
            stack.pop_back();
        }
    }

    return object;
}

ddwaf_object decode_and_parse(std::string_view source)
{
    cow_string cstr{source};
    if (!transformer::base64url_decode::transform(cstr)) {
        return {};
    }

    return json_to_object(static_cast<std::string_view>(cstr));
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> jwt_decode::eval_impl(
    const unary_argument<const ddwaf_object *> &input, processor_cache & /*cache*/,
    ddwaf::timer & /*deadline*/) const
{
    const object_store::attribute attr =
        input.ephemeral ? object_store::attribute::ephemeral : object_store::attribute::none;

    const object::value_iterator it{input.value, input.key_path, {}};

    const auto *object = *it;
    if (object == nullptr || object->type != DDWAF_OBJ_STRING || object->nbEntries == 0 ||
        object->stringValue == nullptr) {
        return {};
    }

    std::string_view token{object->stringValue, static_cast<std::size_t>(object->nbEntries)};

    static const std::string_view prefix = "Bearer";
    if (!token.starts_with(prefix)) {
        // Unlikely to be a JWT
        return {};
    }

    // Remove prefix and spaces
    token.remove_prefix(prefix.size());

    std::size_t spaces = 0;
    while (!token.empty() && ddwaf::isspace(token[spaces])) { ++spaces; }

    token.remove_prefix(spaces);

    // Split jwt
    auto [valid, jwt] = split_token(token);
    if (!valid) {
        // Not a valid JWT
        return {};
    }

    // Decode header and payload
    auto header = decode_and_parse(jwt.header);
    auto payload = decode_and_parse(jwt.payload);

    // Generate output
    ddwaf_object output;
    ddwaf_object_map(&output);
    ddwaf_object_map_addl(&output, STRL("header"), &header);
    ddwaf_object_map_addl(&output, STRL("payload"), &payload);

    ddwaf_object signature_map;
    ddwaf_object_map(&signature_map);

    ddwaf_object signature_available;
    ddwaf_object_bool(&signature_available, !jwt.signature.empty());

    ddwaf_object_map_addl(&signature_map, STRL("available"), &signature_available);

    ddwaf_object_map_addl(&output, STRL("signature"), &signature_map);

    return {output, attr};
}

} // namespace ddwaf
