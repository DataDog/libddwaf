// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/json_utils.hpp"
#include "log.hpp"

#include <fstream>

using namespace std::literals;

namespace ddwaf::test {

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
    switch (ddwaf_object_type(&obj)) {
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
        output.SetString(ddwaf_object_get_string(&obj, nullptr), ddwaf_object_length(&obj), alloc);
    } break;
    case DDWAF_OBJ_MAP:
        output.SetObject();
        for (unsigned i = 0; i < obj.via.map.size; i++) {
            rapidjson::Value key;
            rapidjson::Value value;

            object_to_json_helper(*ddwaf_object_at_value(&obj, i), value, alloc);

            const auto *child_key = ddwaf_object_at_key(&obj, i);
            key.SetString(
                ddwaf_object_get_string(child_key, nullptr), ddwaf_object_length(child_key), alloc);
            output.AddMember(key, value, alloc);
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output.SetArray();
        for (unsigned i = 0; i < obj.via.array.size; i++) {
            rapidjson::Value value;
            const auto *child = ddwaf_object_at_value(&obj, i);
            object_to_json_helper(*child, value, alloc);
            output.PushBack(value, alloc);
        }
        break;
    case DDWAF_OBJ_NULL:
    case DDWAF_OBJ_INVALID:
    default:
        output.SetNull();
        break;
    };
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
            ddwaf_object element{};
            json_to_object_helper(&element, kv.value);

            const std::string_view key = kv.name.GetString();
            ddwaf_object_map_addl(object, key.data(), key.length(), &element);
        }
        break;
    }
    case rapidjson::kArrayType: {
        ddwaf_object_array(object);
        for (auto &v : doc.GetArray()) {
            ddwaf_object element{};
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

rapidjson::Document object_to_rapidjson(const ddwaf_object &obj)
{
    rapidjson::Document document;
    rapidjson::Document::AllocatorType &alloc = document.GetAllocator();

    object_to_json_helper(obj, document, alloc);

    return document;
}

boost::unordered_flat_map<std::string_view, std::string_view> object_to_map(const ddwaf_object &obj)
{
    boost::unordered_flat_map<std::string_view, std::string_view> map;
    for (unsigned i = 0; i < obj.via.map.size; ++i) {
        const auto *key = ddwaf_object_at_key(&obj, i);
        const auto *value = ddwaf_object_at_value(&obj, i);

        map.emplace(
            std::string_view{ddwaf_object_get_string(key, nullptr), ddwaf_object_length(key)},
            std::string_view{ddwaf_object_get_string(value, nullptr), ddwaf_object_length(value)});
    }
    return map;
}

} // namespace ddwaf::test

ddwaf_object json_to_object(const std::string &json)
{
    rapidjson::Document doc;
    const rapidjson::ParseResult result = doc.Parse(json.data());
    if (result.IsError()) {
        throw std::runtime_error(
            "invalid json object: "s + rapidjson::GetParseError_En(result.Code()));
    }

    ddwaf_object output{};
    ddwaf::test::json_to_object_helper(&output, doc);
    return output;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
ddwaf_object read_json_file(std::string_view filename, std::string_view base)
{
    std::string base_dir{base};
    if (*base_dir.end() != '/') {
        base_dir += '/';
    }

    auto file_path = base_dir + "ruleset/" + std::string{filename};

    DDWAF_DEBUG("Opening %s", file_path.c_str());

    std::ifstream file(file_path.c_str(), std::ios::in);
    if (!file) {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize length = file.gcount();
    file.clear();
    buffer.resize(length, '\0');
    file.seekg(0, std::ios::beg);

    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    file.close();

    return json_to_object(buffer);
}

schema_validator::schema_validator(const std::string &path)
{
    std::ifstream rule_file(path, std::ios::in);
    if (!rule_file) {
        throw std::system_error(errno, std::generic_category());
    }

    std::string buffer;
    rule_file.seekg(0, std::ios::end);
    buffer.resize(rule_file.tellg());
    rule_file.seekg(0, std::ios::beg);

    rule_file.read(buffer.data(), buffer.size());
    rule_file.close();

    if (schema_doc_.Parse(buffer).HasParseError()) {
        throw std::runtime_error("failed to parse schema");
    }

    schema_ = std::make_unique<rapidjson::SchemaDocument>(schema_doc_);
    validator_ = std::make_unique<rapidjson::SchemaValidator>(*schema_);
}

std::optional<std::string> schema_validator::validate(const char *events)
{
    validator_->Reset();

    rapidjson::Document doc;
    doc.Parse(events);
    if (doc.HasParseError()) {
        return std::to_string(doc.GetErrorOffset()) + ": " +
               rapidjson::GetParseError_En(doc.GetParseError());
    }

    if (!doc.Accept(*validator_)) {

        rapidjson::StringBuffer sb;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> w(sb);
        validator_->GetError().Accept(w);

        return sb.GetString();
    }

    return std::nullopt;
}

std::optional<std::string> schema_validator::validate(rapidjson::Document &doc)
{
    validator_->Reset();

    if (!doc.Accept(*validator_)) {

        rapidjson::StringBuffer sb;
        rapidjson::PrettyWriter<rapidjson::StringBuffer> w(sb);
        validator_->GetError().Accept(w);

        return sb.GetString();
    }

    return std::nullopt;
}
