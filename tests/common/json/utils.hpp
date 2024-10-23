// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <optional>
#include <rapidjson/prettywriter.h>
#include <rapidjson/schema.h>
#include <unordered_map>
#include <vector>

#include "ddwaf.h"

namespace ddwaf::test {

std::string object_to_json(const ddwaf_object &obj);
rapidjson::Document object_to_rapidjson(const ddwaf_object &obj);
std::unordered_map<std::string_view, std::string_view> object_to_map(const ddwaf_object &obj);

} // namespace ddwaf::test

class schema_validator {
public:
    explicit schema_validator(const std::string &path);
    std::optional<std::string> validate(const char *events);
    std::optional<std::string> validate(rapidjson::Document &doc);

protected:
    rapidjson::Document schema_doc_;
    std::unique_ptr<rapidjson::SchemaDocument> schema_;
    std::unique_ptr<rapidjson::SchemaValidator> validator_;
};

ddwaf_object read_json_file(std::string_view filename, std::string_view base = "./");
ddwaf_object json_to_object(const std::string &json);

template <typename T>
// NOLINTNEXTLINE(misc-no-recursion)
bool json_equals(const T &lhs, const T &rhs)
    requires std::is_same_v<rapidjson::Document, T> || std::is_same_v<rapidjson::Value, T>
{
    if (lhs.GetType() != rhs.GetType()) {
        return false;
    }

    switch (lhs.GetType()) {
    case rapidjson::kObjectType: {
        if (lhs.MemberCount() != rhs.MemberCount()) {
            return false;
        }

        std::vector<bool> seen(lhs.MemberCount(), false);
        for (const auto &lkv : lhs.GetObject()) {
            bool found = false;
            const std::string_view lkey = lkv.name.GetString();
            for (auto it = rhs.MemberBegin(); it != rhs.MemberEnd(); ++it) {
                auto i = it - rhs.MemberBegin();
                if (seen[i]) {
                    continue;
                }

                const auto &rkv = *it;
                const std::string_view rkey = rkv.name.GetString();
                if (lkey != rkey) {
                    continue;
                }

                if (json_equals(lkv.value, rkv.value)) {
                    seen[i] = found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }
    case rapidjson::kArrayType: {
        if (lhs.Size() != rhs.Size()) {
            return false;
        }

        std::vector<bool> seen(lhs.Size(), false);
        for (const auto &v : lhs.GetArray()) {
            bool found = false;
            for (unsigned i = 0; i < rhs.Size(); ++i) {
                if (!seen[i] && json_equals(v, rhs[i])) {
                    seen[i] = found = true;
                    break;
                }
            }
            if (!found) {
                return false;
            }
        }
        return true;
    }
    case rapidjson::kStringType: {
        std::string_view lstr = lhs.GetString();
        std::string_view rstr = rhs.GetString();
        return lstr == rstr;
    }
    case rapidjson::kNumberType: {
        if (lhs.IsInt()) {
            return rhs.IsInt() && lhs.GetInt() == rhs.GetInt();
        }
        if (lhs.IsUint()) {
            return rhs.IsUint() && lhs.GetUint() == rhs.GetUint();
        }

        if (lhs.IsInt64()) {
            return rhs.IsInt64() && lhs.GetInt64() == rhs.GetInt64();
        }
        if (lhs.IsUint64()) {
            return rhs.IsUint64() && lhs.GetUint64() == rhs.GetUint64();
        }

        if (lhs.IsDouble()) {
            return rhs.IsDouble() && std::abs(lhs.GetDouble() - rhs.GetDouble()) < 0.01;
        }
        break;
    }
    case rapidjson::kTrueType:
    case rapidjson::kFalseType:
    case rapidjson::kNullType:
    default:
        return true;
    }
    return false;
}
