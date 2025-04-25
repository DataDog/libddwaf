// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include "processor/jwt_decoder.hpp"

#include "transformer/base64_decode.hpp"

#include <rapidjson/prettywriter.h>
#include <rapidjson/schema.h>

using namespace std::literals;

namespace ddwaf {

template <std::size_t N> std::array<std::string_view, N> split(std::string_view source, char delim)
{
    std::array<std::string_view, N> parts{};
    std::size_t i = 0;
    for (; i < (N - 1) && !source.empty(); ++i) {
        auto end = source.find_first_of(delim);
        if (end == std::string_view::npos) {
            break;
        }

        parts[i] = source.substr(0, end);
        source = source.substr(end + 1);
    }
    parts[i] = source;

    return parts;
}

template <typename T>
// NOLINTNEXTLINE(misc-no-recursion)
void json_to_object_helper(ddwaf_object *object, T &doc)
    requires std::is_same_v<rapidjson::Document, T> || std::is_same_v<rapidjson::Value, T>
{
    switch (doc.GetType()) {
    case rapidjson::kFalseType:
        ddwaf_object_bool(object, false);
        break;
    case rapidjson::kTrueType:
        ddwaf_object_bool(object, true);
        break;
    case rapidjson::kObjectType: {
        ddwaf_object_map(object);
        for (auto &kv : doc.GetObject()) {
            ddwaf_object element;
            json_to_object_helper(&element, kv.value);

            const std::string_view key = kv.name.GetString();
            ddwaf_object_map_addl(object, key.data(), key.length(), &element);
        }
        break;
    }
    case rapidjson::kArrayType: {
        ddwaf_object_array(object);
        for (auto &v : doc.GetArray()) {
            ddwaf_object element;
            json_to_object_helper(&element, v);

            ddwaf_object_array_add(object, &element);
        }
        break;
    }
    case rapidjson::kStringType: {
        const std::string_view str = doc.GetString();
        ddwaf_object_stringl(object, str.data(), str.size());
        break;
    }
    case rapidjson::kNumberType: {
        if (doc.IsInt64()) {
            ddwaf_object_signed(object, doc.GetInt64());
        } else if (doc.IsUint64()) {
            ddwaf_object_unsigned(object, doc.GetUint64());
        } else if (doc.IsDouble()) {
            ddwaf_object_float(object, doc.GetDouble());
        }
        break;
    }
    case rapidjson::kNullType:
        ddwaf_object_null(object);
        break;
    default:
        ddwaf_object_invalid(object);
        break;
    }
}

ddwaf_object json_to_object(std::string_view json)
{
    ddwaf_object output;
    ddwaf_object_invalid(&output);

    rapidjson::Document doc;
    try {
        const rapidjson::ParseResult result = doc.Parse(json.data());
        if (!result.IsError()) {
            json_to_object_helper(&output, doc);
        }
    } catch (...) {}

    return output;
}

ddwaf_object decode_and_parse(std::string_view source)
{
    cow_string cstr{source};
    if (!transformer::base64_decode::transform(cstr)) {
        return {};
    }

    return json_to_object(static_cast<std::string_view>(cstr));
}

std::pair<ddwaf_object, object_store::attribute> jwt_decoder::eval_impl(
    const unary_argument<std::string_view> &input, processor_cache & /*cache*/,
    ddwaf::timer & /*deadline*/) const
{
    if (input.value.empty()) {
        return {};
    }

    const object_store::attribute attr =
        input.ephemeral ? object_store::attribute::ephemeral : object_store::attribute::none;

    // Split jwt
    auto [header_base64, payload_base64, signature] = split<3>(input.value, '.');

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
