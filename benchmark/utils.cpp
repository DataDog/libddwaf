// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <fstream>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <string>

#include "ddwaf.h"
#include "utils.hpp"

namespace ddwaf::benchmark::utils {

namespace {
class string_buffer {
public:
    using Ch = char;

protected:
    static constexpr std::size_t default_capacity = 1024;

public:
    string_buffer() { buffer_.reserve(default_capacity); }

    void Put(Ch c) { buffer_.push_back(c); }
    void PutUnsafe(Ch c) { Put(c); }
    void Flush() {}
    void Clear() { buffer_.clear(); }
    void ShrinkToFit() { buffer_.shrink_to_fit(); }
    void Reserve(size_t count) { buffer_.reserve(count); }

    [[nodiscard]] const Ch *GetString() const { return buffer_.c_str(); }
    [[nodiscard]] size_t GetSize() const { return buffer_.size(); }

    [[nodiscard]] size_t GetLength() const { return GetSize(); }

    std::string &get_string_ref() { return buffer_; }

protected:
    std::string buffer_;
};

template <typename T>
// NOLINTNEXTLINE(misc-no-recursion, google-runtime-references)
void object_to_json_helper(
    const ddwaf_object &obj, T &output, rapidjson::Document::AllocatorType &alloc)
{
    switch (obj.type) {
    case DDWAF_OBJ_BOOL:
        output.SetBool(obj.boolean);
        break;
    case DDWAF_OBJ_SIGNED:
        output.SetInt64(obj.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        output.SetUint64(obj.uintValue);
        break;
    case DDWAF_OBJ_FLOAT:
        output.SetDouble(obj.f64);
        break;
    case DDWAF_OBJ_STRING: {
        auto sv = std::string_view(obj.stringValue, obj.nbEntries);
        output.SetString(sv.data(), sv.size(), alloc);
    } break;
    case DDWAF_OBJ_MAP:
        output.SetObject();
        for (unsigned i = 0; i < obj.nbEntries; i++) {
            rapidjson::Value key;
            rapidjson::Value value;

            auto child = obj.array[i];
            object_to_json_helper(child, value, alloc);

            key.SetString(child.parameterName, child.parameterNameLength, alloc);
            output.AddMember(key, value, alloc);
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output.SetArray();
        for (unsigned i = 0; i < obj.nbEntries; i++) {
            rapidjson::Value value;
            auto child = obj.array[i];
            object_to_json_helper(child, value, alloc);
            output.PushBack(value, alloc);
        }
        break;
    case DDWAF_OBJ_NULL:
    case DDWAF_OBJ_INVALID:
        output.SetNull();
        break;
    };
}

} // namespace

std::string object_to_string(const ddwaf_object &obj) noexcept
{
    rapidjson::Document document;
    rapidjson::Document::AllocatorType &alloc = document.GetAllocator();

    object_to_json_helper(obj, document, alloc);

    string_buffer buffer;
    rapidjson::Writer<decltype(buffer)> writer(buffer);

    if (document.Accept(writer)) {
        return std::move(buffer.get_string_ref());
    }

    return {};
}

// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object object_dup(const ddwaf_object &o) noexcept
{
    ddwaf_object copy;
    switch (o.type) {
    case DDWAF_OBJ_INVALID:
        ddwaf_object_invalid(&copy);
        break;
    case DDWAF_OBJ_NULL:
        ddwaf_object_null(&copy);
        break;
    case DDWAF_OBJ_BOOL:
        ddwaf_object_bool(&copy, o.boolean);
        break;
    case DDWAF_OBJ_SIGNED:
        ddwaf_object_signed(&copy, o.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        ddwaf_object_unsigned(&copy, o.uintValue);
        break;
    case DDWAF_OBJ_FLOAT:
        ddwaf_object_float(&copy, o.f64);
        break;
    case DDWAF_OBJ_STRING:
        ddwaf_object_stringl(&copy, o.stringValue, o.nbEntries);
        break;
    case DDWAF_OBJ_ARRAY:
        ddwaf_object_array(&copy);
        for (decltype(o.nbEntries) i = 0; i < o.nbEntries; i++) {
            ddwaf_object child_copy = object_dup(o.array[i]);
            ddwaf_object_array_add(&copy, &child_copy);
        }
        break;
    case DDWAF_OBJ_MAP:
        ddwaf_object_map(&copy);
        for (decltype(o.nbEntries) i = 0; i < o.nbEntries; i++) {
            ddwaf_object child_copy = object_dup(o.array[i]);
            ddwaf_object_map_addl(
                &copy, o.array[i].parameterName, o.array[i].parameterNameLength, &child_copy);
        }
        break;
    }
    return copy;
}

std::string read_file(const fs::path &filename)
{
    std::ifstream file(filename.c_str(), std::ios::in);
    if (!file) {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.seekg(0, std::ios::end);
    buffer.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(buffer.data(), static_cast<int64_t>(buffer.size()));
    file.close();
    return buffer;
}

std::map<std::string_view, std::string_view> parse_args(const std::vector<std::string> &args)
{
    std::map<std::string_view, std::string_view> parsed_args;

    for (std::size_t i = 1; i < args.size(); i++) {
        std::string_view arg = args[i];
        if (arg.substr(0, 2) != "--") {
            continue;
        }

        auto assignment = arg.find('=');
        if (assignment != std::string::npos) {
            std::string_view opt_name = arg.substr(2, assignment - 2);
            parsed_args[opt_name] = arg.substr(assignment + 1);
        } else {
            std::string_view opt_name = arg.substr(2);
            parsed_args[opt_name] = {};

            if ((i + 1) < args.size()) {
                std::string_view value = args[i + 1];
                if (value.substr(0, 2) != "--") {
                    parsed_args[opt_name] = value;
                }
            }
        }
    }

    return parsed_args;
}

} // namespace ddwaf::benchmark::utils
