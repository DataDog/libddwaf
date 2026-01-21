// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <rapidjson/document.h>
#include <rapidjson/error/en.h>
#include <rapidjson/writer.h>
#include <string_view>
#include <utility>
#include <yaml-cpp/yaml.h>

#include "ddwaf.h"
#include "utils.hpp"

using namespace std::literals;

namespace YAML {

namespace {

// NOLINTNEXTLINE(misc-no-recursion)
void node_to_ddwaf_object(ddwaf_object *root, const Node &node)
{
    auto *alloc = ddwaf_get_default_allocator();
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object_set_array(root, node.size(), alloc);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto *child = ddwaf_object_insert(root, alloc);
            node_to_ddwaf_object(child, *it);
        }
        return;
    }
    case NodeType::Map: {
        ddwaf_object_set_map(root, node.size(), alloc);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            auto *child = ddwaf_object_insert_key(root, key.data(), key.size(), alloc);
            node_to_ddwaf_object(child, it->second);
        }
        return;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();

        if (node.Tag() == "?") {
            try {
                ddwaf_object_set_unsigned(root, node.as<uint64_t>());
                return;
            } catch (...) {}

            try {
                ddwaf_object_set_signed(root, node.as<int64_t>());
                return;
            } catch (...) {}

            try {
                ddwaf_object_set_float(root, node.as<double>());
                return;
            } catch (...) {}

            try {
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    ddwaf_object_set_bool(root, node.as<bool>());
                    return;
                }
            } catch (...) {}
        }

        ddwaf_object_set_string(root, value.data(), value.size(), alloc);
        return;
    }
    case NodeType::Null: {
        ddwaf_object_set_null(root);
        return;
    }
    case NodeType::Undefined: {
        ddwaf_object_set_invalid(root);
        return;
    }
    }

    throw parsing_error("Invalid YAML node type");
}

} // namespace

ddwaf_object as_if<ddwaf_object, void>::operator()() const {
    ddwaf_object object;
    node_to_ddwaf_object(&object, node);
    return object;
}

} // namespace YAML

namespace {
// NOLINTNEXTLINE(misc-no-recursion)
void object_to_yaml_helper(const ddwaf_object &obj, YAML::Node &output)
{
    switch (obj.type) {
    case DDWAF_OBJ_BOOL:
        output = ddwaf_object_get_bool(&obj);
        break;
    case DDWAF_OBJ_SIGNED:
        output = ddwaf_object_get_signed(&obj);
        break;
    case DDWAF_OBJ_UNSIGNED:
        output = ddwaf_object_get_unsigned(&obj);
        break;
    case DDWAF_OBJ_FLOAT:
        output = ddwaf_object_get_float(&obj);
        break;
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_SMALL_STRING:
    case DDWAF_OBJ_LITERAL_STRING:
        output = std::string{ddwaf_object_get_string(&obj, nullptr), ddwaf_object_get_length(&obj)};
        break;
    case DDWAF_OBJ_MAP:
        output = YAML::Load("{}");
        for (unsigned i = 0; i < obj.via.map.size; i++) {
            const auto *child = ddwaf_object_at_key(&obj, i);
            std::string key{ddwaf_object_get_string(child, nullptr), ddwaf_object_get_length(child)};

            YAML::Node value;
            object_to_yaml_helper(*ddwaf_object_at_value(&obj, i), value);
            output[key] = value;
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output = YAML::Load("[]");
        for (unsigned i = 0; i < obj.via.array.size; i++) {
            auto child = obj.via.array.ptr[i];

            YAML::Node value;
            object_to_yaml_helper(child, value);
            output.push_back(value);
        }
        break;
    case DDWAF_OBJ_INVALID:
    case DDWAF_OBJ_NULL:
        output = YAML::Null;
    };
}

} // namespace

YAML::Node object_to_yaml(const ddwaf_object &obj)
{
    YAML::Node root;
    object_to_yaml_helper(obj, root);
    return root;
}

template <typename T>
// NOLINTNEXTLINE(misc-no-recursion)
void json_to_object_helper(ddwaf_object *object, T &doc)
    requires std::is_same_v<rapidjson::Document, T> || std::is_same_v<rapidjson::Value, T>
{
    auto *alloc = ddwaf_get_default_allocator();
    switch (doc.GetType()) {
    case rapidjson::kFalseType:
        ddwaf_object_set_bool(object, false);
        break;
    case rapidjson::kTrueType:
        ddwaf_object_set_bool(object, true);
        break;
    case rapidjson::kObjectType: {
        ddwaf_object_set_map(object, doc.MemberCount(), alloc);
        for (auto &kv : doc.GetObject()) {
            const std::string_view key = kv.name.GetString();
            auto *element = ddwaf_object_insert_key(object, key.data(), key.length(), alloc);

            json_to_object_helper(element, kv.value);
        }
        break;
    }
    case rapidjson::kArrayType: {
        ddwaf_object_set_array(object, doc.Size(), alloc);
        for (auto &v : doc.GetArray()) {
            auto *element = ddwaf_object_insert(object, alloc);
            json_to_object_helper(element, v);
        }
        break;
    }
    case rapidjson::kStringType: {
        const std::string_view str = doc.GetString();
        ddwaf_object_set_string(object, str.data(), str.size(), alloc);
        break;
    }
    case rapidjson::kNumberType: {
        if (doc.IsInt64()) {
            ddwaf_object_set_signed(object, doc.GetInt64());
        } else if (doc.IsUint64()) {
            ddwaf_object_set_unsigned(object, doc.GetUint64());
        } else if (doc.IsDouble()) {
            ddwaf_object_set_float(object, doc.GetDouble());
        }
        break;
    }
    case rapidjson::kNullType:
        ddwaf_object_set_null(object);
        break;
    default:
        ddwaf_object_set_invalid(object);
        break;
    }
}

ddwaf_object json_to_object(const std::string &json)
{
    rapidjson::Document doc;
    rapidjson::ParseResult const result = doc.Parse(json.data());
    if (result.IsError()) {
        throw std::runtime_error(
            "invalid json object: "s + rapidjson::GetParseError_En(result.Code()));
    }

    ddwaf_object output{};
    json_to_object_helper(&output, doc);
    return output;
}

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
        output.SetBool(ddwaf_object_get_bool(&obj));
        break;
    case DDWAF_OBJ_SIGNED:
        output.SetInt64(ddwaf_object_get_signed(&obj));
        break;
    case DDWAF_OBJ_UNSIGNED:
        output.SetUint64(ddwaf_object_get_unsigned(&obj));
        break;
    case DDWAF_OBJ_FLOAT:
        output.SetDouble(ddwaf_object_get_float(&obj));
        break;
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_SMALL_STRING:
    case DDWAF_OBJ_LITERAL_STRING: {
        output.SetString(
            ddwaf_object_get_string(&obj, nullptr), ddwaf_object_get_length(&obj), alloc);
    } break;
    case DDWAF_OBJ_MAP:
        output.SetObject();
        for (unsigned i = 0; i < obj.via.map.size; i++) {
            rapidjson::Value key;
            rapidjson::Value value;

            auto child = obj.via.map.ptr[i];
            object_to_json_helper(child.val, value, alloc);
            const auto *child_key = ddwaf_object_at_key(&obj, i);
            key.SetString(ddwaf_object_get_string(child_key, nullptr),
                ddwaf_object_get_length(child_key), alloc);

            output.AddMember(key, value, alloc);
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output.SetArray();
        for (unsigned i = 0; i < obj.via.array.size; i++) {
            rapidjson::Value value;
            auto child = obj.via.array.ptr[i];
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

std::string object_to_json(const ddwaf_object &obj)
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


const char* level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level)
    {
        case DDWAF_LOG_TRACE:
            return "trace";
        case DDWAF_LOG_DEBUG:
            return "debug";
        case DDWAF_LOG_ERROR:
            return "error";
        case DDWAF_LOG_WARN:
            return "warn";
        case DDWAF_LOG_INFO:
            return "info";
        case DDWAF_LOG_OFF:
            break;
    }

    return "off";
}

void log_cb(DDWAF_LOG_LEVEL level,
            const char* function, const char* file, unsigned line,
            const char* message, uint64_t  /*length*/)
{
    std::cout << "[" << level_to_str(level)
              << "][" << file
              << ":" << function
              << ":" << line
              << "]: " << message
              << '\n';
}

std::string read_file(std::string_view filename)
{
    std::ifstream rule_file(filename.data(), std::ios::in);
    if (!rule_file)
    {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    rule_file.seekg(0, std::ios::end);
    buffer.resize(rule_file.tellg());
    rule_file.seekg(0, std::ios::beg);

    rule_file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    rule_file.close();
    return buffer;
}


