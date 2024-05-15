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
        output.SetBool(obj.via.b8);
        break;
    case DDWAF_OBJ_SIGNED:
        output.SetInt64(obj.via.i64);
        break;
    case DDWAF_OBJ_UNSIGNED:
        output.SetUint64(obj.via.u64);
        break;
    case DDWAF_OBJ_FLOAT:
        output.SetDouble(obj.via.f64);
        break;
    case DDWAF_OBJ_STRING: {
        auto sv = std::string_view(obj.via.str, obj.length);
        output.SetString(sv.data(), sv.size(), alloc);
    } break;
    case DDWAF_OBJ_SMALL_STRING: {
        auto sv = std::string_view(obj.via.sstr, obj.length);
        output.SetString(sv.data(), sv.size(), alloc);
    } break;
    case DDWAF_OBJ_CONST_STRING: {
        auto sv = std::string_view(obj.via.cstr, obj.length);
        output.SetString(sv.data(), sv.size(), alloc);
    } break;
    case DDWAF_OBJ_MAP:
        output.SetObject();
        for (unsigned i = 0; i < obj.size; i++) {
            rapidjson::Value key;
            rapidjson::Value value;

            auto child = obj.via.map[i];
            object_to_json_helper(child.val, value, alloc);
            object_to_json_helper(child.key, key, alloc);

            output.AddMember(key, value, alloc);
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output.SetArray();
        for (unsigned i = 0; i < obj.size; i++) {
            rapidjson::Value value;
            auto child = obj.via.array[i];
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
        ddwaf_object_set_invalid(&copy);
        break;
    case DDWAF_OBJ_NULL:
        ddwaf_object_set_null(&copy);
        break;
    case DDWAF_OBJ_BOOL:
        ddwaf_object_set_bool(&copy, o.via.b8);
        break;
    case DDWAF_OBJ_SIGNED:
        ddwaf_object_set_signed(&copy, o.via.i64);
        break;
    case DDWAF_OBJ_UNSIGNED:
        ddwaf_object_set_unsigned(&copy, o.via.u64);
        break;
    case DDWAF_OBJ_FLOAT:
        ddwaf_object_set_float(&copy, o.via.f64);
        break;
    case DDWAF_OBJ_STRING:
        ddwaf_object_set_string(&copy, o.via.str, o.size, nullptr);
        break;
    case DDWAF_OBJ_SMALL_STRING:
        ddwaf_object_set_string(&copy, o.via.sstr, o.size, nullptr);
        break;
    case DDWAF_OBJ_CONST_STRING:
        ddwaf_object_set_const_string(&copy, o.via.cstr, o.size);
        break;
    case DDWAF_OBJ_ARRAY:
        ddwaf_object_set_array(&copy, o.size, nullptr);
        for (decltype(o.size) i = 0; i < o.size; i++) {
            auto *slot = ddwaf_object_insert(&copy);
            *slot = object_dup(o.via.array[i]);
        }
        break;
    case DDWAF_OBJ_MAP:
        ddwaf_object_set_map(&copy, o.size, nullptr);
        for (decltype(o.size) i = 0; i < o.size; i++) {
            copy.via.map[i].val = object_dup(o.via.map[i].val);
            copy.via.map[i].key = object_dup(o.via.map[i].key);
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
