// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <rapidjson/document.h>
#include <rapidjson/error/error.h>
#include <string_view>
#include <tuple>
#include <vector>

#include "ddwaf.h"
#include "json_utils.hpp"
#include "utils.hpp"

namespace ddwaf {

ddwaf_object json_to_object(std::string_view json)
{
    // Safety limit, potentially not necessary as if we can decode and parse
    // we should have a manageable json structure as other limits are already
    // in place.
    constexpr std::size_t max_depth = object_limits::default_max_container_depth;

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

    // This could be replaced with an std::array and an index
    std::vector<std::tuple<rapidjson::Value *, ddwaf_object *, std::size_t>> stack;
    stack.reserve(max_depth);

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

} // namespace ddwaf
