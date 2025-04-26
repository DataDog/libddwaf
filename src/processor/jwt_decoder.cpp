// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "processor/jwt_decoder.hpp"

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "ddwaf.h"
#include "iterator.hpp"
#include "object_store.hpp"
#include "processor/base.hpp"
#include "transformer/base64_decode.hpp"
#include "transformer/common/cow_string.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <string_view>
#include <utility>

using namespace std::literals;

namespace ddwaf {

namespace {

std::array<std::string_view, 3> split_token(std::string_view source, char delim)
{
    std::array<std::string_view, 3> parts{};
    for (std::size_t i = 0; i < 3 && !source.empty(); ++i) {
        auto end = source.find_first_of(delim);
        parts[i] = source.substr(0, end);
        source = source.substr(end + 1);
    }
    return parts;
}

ddwaf_object json_to_object(std::string_view json)
{
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
    const rapidjson::ParseResult result = doc.Parse(json.data());
    if (result.IsError()) {
        return {};
    }

    std::deque<std::pair<rapidjson::Value *, ddwaf_object *>> queue;
    auto object = to_object(doc);
    if (doc.IsArray() || doc.IsObject()) {
        queue.emplace_back(&doc, &object);
    }

    while (!queue.empty()) {
        auto &[source, destination] = queue.front();
        if (source->IsArray()) {
            for (auto &value : source->GetArray()) {
                auto value_object = to_object(value);
                ddwaf_object_array_add(destination, &value_object);
            }

            std::size_t i = 0;
            for (auto &value : source->GetArray()) {
                if (value.IsArray() || value.IsObject()) {
                    queue.emplace_back(&value, &destination->array[i++]);
                }
            }
        } else if (source->IsObject()) {
            for (auto &[key, value] : source->GetObject()) {
                auto value_object = to_object(value);

                const std::string_view key_sv = key.GetString();
                ddwaf_object_map_addl(destination, key_sv.data(), key_sv.length(), &value_object);
            }

            std::size_t i = 0;
            for (auto &[_, value] : source->GetObject()) {
                if (value.IsArray() || value.IsObject()) {
                    queue.emplace_back(&value, &destination->array[i++]);
                }
            }
        }

        queue.pop_front();
    }

    return object;
}

ddwaf_object decode_and_parse(std::string_view source)
{
    cow_string cstr{source};
    if (!transformer::base64_decode::transform(cstr)) {
        return {};
    }

    return json_to_object(static_cast<std::string_view>(cstr));
}

} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> jwt_decoder::eval_impl(
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

    const std::string_view token{object->stringValue, static_cast<std::size_t>(object->nbEntries)};

    // Split jwt
    auto [header_base64, payload_base64, signature] = split_token(token, '.');

    // Decode header and payload
    auto header = decode_and_parse(header_base64);
    auto payload = decode_and_parse(payload_base64);

    // Generate output
    ddwaf_object output;
    ddwaf_object_map(&output);
    ddwaf_object_map_addl(&output, "header", sizeof("header") - 1, &header);
    ddwaf_object_map_addl(&output, "payload", sizeof("payload") - 1, &payload);

    ddwaf_object signature_available;
    ddwaf_object_bool(&signature_available, !signature.empty());
    ddwaf_object_map_addl(&output, "signature", sizeof("signature") - 1, &signature_available);

    return {output, attr};
}

} // namespace ddwaf
