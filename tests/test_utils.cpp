// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test_utils.hpp"
#include "ddwaf.h"
#include "log.hpp"
#include <fstream>
#include <memory>
#include <string_view>

using namespace std::literals;

namespace ddwaf::test {

bool operator==(const event::match::argument &lhs, const event::match::argument &rhs)
{
    return lhs.address == rhs.address && lhs.name == rhs.name && lhs.value == rhs.value &&
           lhs.path == rhs.path;
}

bool operator==(const event::match &lhs, const event::match &rhs)
{
    return lhs.op == rhs.op && lhs.op_value == rhs.op_value && lhs.args == rhs.args &&
           lhs.highlight == rhs.highlight;
}

bool operator==(const event &lhs, const event &rhs)
{
    return lhs.id == rhs.id && lhs.name == rhs.name && lhs.tags == rhs.tags &&
           lhs.actions == rhs.actions && lhs.matches == rhs.matches &&
           lhs.stack_id.empty() == rhs.stack_id.empty();
}

namespace {

struct indent {
    indent(unsigned size) : size_(size) {}
    unsigned size_;
};

std::ostream &operator<<(std::ostream &os, const indent &offset)
{
    for (unsigned i = 0; i < offset.size_; i++) { os << ' '; }
    return os;
}

} // namespace

std::ostream &operator<<(std::ostream &os, const event::match &m)
{
    // using indent = ddwaf::test::indent;

    os << indent(4) << "{\n"
       << indent(8) << "operator: " << m.op << ",\n"
       << indent(8) << "operator_value: " << m.op_value << ",\n";

    os << indent(8) << "parameters: {\n";

    for (const auto &arg : m.args) {
        os << indent(12) << arg.name << ": {\n"
           << indent(16) << "address: " << arg.address << ",\n"
           << indent(16) << "path: [";

        bool start = true;
        for (const auto &p : arg.path) {
            if (!start) {
                os << ", ";
            } else {
                start = false;
            }
            os << p;
        }

        os << "],\n" << indent(16) << "value: " << arg.value << ",\n" << indent(12) << "}\n";
    }

    os << indent(8) << "highlight: " << m.highlight << "\n" << indent(4) << "}\n";

    return os;
}

std::ostream &operator<<(std::ostream &os, const event &e)
{
    // using indent = ddwaf::test::indent;

    os << "{\n"
       << indent(4) << "id: " << e.id << ",\n"
       << indent(4) << "name: " << e.name << ",\n"
       << indent(4) << "stack_id: " << e.stack_id << ",\n"
       << indent(4) << "tags: {";
    {
        bool start = true;
        for (const auto &[key, val] : e.tags) {
            if (!start) {
                os << ", ";
            } else {
                start = false;
            }
            os << '\n' << indent(8) << key << ": " << val;
        }
    }
    os << '\n' << indent(4) << "},\n" << indent(4) << "actions: [";
    {
        bool start = true;
        for (const auto &a : e.actions) {
            if (!start) {
                os << ", ";
            } else {
                start = false;
            }
            os << a;
        }
    }
    os << "],\n" << indent(4) << "matches: [\n";

    for (const auto &m : e.matches) {
        os << indent(8) << "{\n"
           << indent(12) << "operator: " << m.op << ",\n"
           << indent(12) << "operator_value: " << m.op_value << ",\n";

        os << indent(12) << "parameters: {\n";

        for (const auto &arg : m.args) {
            os << indent(16) << arg.name << ": {\n"
               << indent(20) << "address: " << arg.address << ",\n"
               << indent(20) << "path: [";

            bool start = true;
            for (const auto &p : arg.path) {
                if (!start) {
                    os << ", ";
                } else {
                    start = false;
                }
                os << p;
            }

            os << "],\n" << indent(20) << "value: " << arg.value << ",\n" << indent(16) << "}\n";
        }

        os << indent(12) << "highlight: " << m.highlight << "\n" << indent(8) << "}\n";
    }

    os << indent(4) << "]\n}\n";

    return os;
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

//} // namespace ddwaf::test
void PrintTo(const ddwaf_object &actions, ::std::ostream *os)
{
    *os << "[";
    for (unsigned i = 0; i < ddwaf_object_size(&actions); i++) {
        if (i > 0) {
            *os << ", ";
        }
        const auto *object = ddwaf_object_get_index(actions.array, i);
        if (ddwaf_object_type(object) == DDWAF_OBJ_STRING) {
            *os << ddwaf_object_get_string(object, nullptr);
        }
    }
    *os << "]";
}

void PrintTo(const std::list<ddwaf::test::event> &events, ::std::ostream *os)
{
    for (const auto &e : events) { *os << e; }
}

void PrintTo(const std::list<ddwaf::test::event::match> &matches, ::std::ostream *os)
{
    for (const auto &m : matches) { *os << m; }
}

} // namespace ddwaf::test

std::ostream &operator<<(std::ostream &os, const ddwaf::test::action_map &actions)
{
    using indent = ddwaf::test::indent;
    os << "{\n";
    bool start = true;
    for (const auto &[action, parameters] : actions) {
        if (!start) {
            os << ",\n";
        } else {
            start = false;
        }

        os << indent(4) << action << ": {\n";

        bool param_start = true;
        for (const auto &[k, v] : parameters) {
            if (!param_start) {
                os << ",\n";
            } else {
                param_start = false;
            }

            os << indent(8) << k << ": " << v;
        }

        os << "\n" << indent(4) << "}";
    }

    os << "\n}";

    return os;
}

void PrintTo(const ddwaf::test::action_map &actions, ::std::ostream *os) { *os << actions; }

namespace YAML {
using event = ddwaf::test::event;
using match = ddwaf::test::event::match;
using action_map = ddwaf::test::action_map;

template <class T> T as(const YAML::Node &node, const std::string &key)
{
    auto value = node[key];
    if (!value) {
        return {};
    }

    try {
        return value.as<T>();
    } catch (...) {
        throw parsing_error("failed to parse " + key);
    }
}

template <class T> T as(const YAML::Node &node, unsigned key)
{
    auto value = node[key];
    if (!value) {
        return {};
    }

    try {
        return value.as<T>();
    } catch (...) {
        throw parsing_error("failed to parse " + std::to_string(key));
    }
}

match as_if<match, void>::operator()() const
{
    if (node.Type() != NodeType::Map) {
        throw parsing_error("match should be a map");
    }

    match m;

    m.op = as<std::string>(node, "operator");
    m.op_value = as<std::string>(node, "operator_value");

    auto parameters = node["parameters"][0];
    if (!parameters || parameters.Type() != NodeType::Map) {
        throw parsing_error("parameter should be a map");
    }

    if (parameters["address"].IsDefined()) {
        m.args.emplace_back(match::argument{"input", as<std::string>(parameters, "value"),
            as<std::string>(parameters, "address"),
            as<std::vector<std::string>>(parameters, "key_path")});
    } else {
        for (auto it = parameters.begin(); it != parameters.end(); ++it) {
            if (it->second.IsMap()) {
                m.args.emplace_back(match::argument{it->first.as<std::string>(),
                    as<std::string>(it->second, "value"), as<std::string>(it->second, "address"),
                    as<std::vector<std::string>>(it->second, "key_path")});
            }
        }
    }

    auto highlight = parameters["highlight"];
    if (!highlight || highlight.Type() != NodeType::Sequence) {
        throw parsing_error("parameter should be a sequence");
    }

    m.highlight = as<std::string>(highlight, 0);

    return m;
}

event as_if<event, void>::operator()() const
{
    if (node.Type() != YAML::NodeType::Map) {
        throw parsing_error("event should be a map");
    }

    auto rule = node["rule"];
    if (!rule || rule.Type() != YAML::NodeType::Map) {
        throw parsing_error("rule should be a map");
    }

    event e;
    auto id = rule["id"];
    e.id = as<std::string>(rule, "id");
    e.name = as<std::string>(rule, "name");
    e.tags = as<std::map<std::string, std::string>>(rule, "tags");
    e.actions = as<std::vector<std::string>>(rule, "on_match");
    e.matches = as<std::vector<match>>(node, "rule_matches");
    e.stack_id = as<std::string>(node, "stack_id");

    return e;
}

namespace {
ddwaf_object node_to_arg(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object arg = DDWAF_OBJECT_ARRAY;
        for (auto it = node.begin(); it != node.end(); ++it) {
            ddwaf_object child = node_to_arg(*it);
            ddwaf_object_array_add(&arg, &child);
        }
        return arg;
    }
    case NodeType::Map: {
        ddwaf_object arg = DDWAF_OBJECT_MAP;
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            ddwaf_object child = node_to_arg(it->second);
            ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
        }
        return arg;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();
        ddwaf_object arg;
        ddwaf_object_stringl(&arg, value.c_str(), value.size());
        return arg;
    }
    case NodeType::Null:
    case NodeType::Undefined:
        ddwaf_object arg = DDWAF_OBJECT_MAP;
        return arg;
    }

    throw parsing_error("Invalid YAML node type");
}

} // namespace

as_if<ddwaf_object, void>::as_if(const Node &node_) : node(node_) {}
ddwaf_object as_if<ddwaf_object, void>::operator()() const { return node_to_arg(node); }

action_map as_if<action_map, void>::operator()() const
{
    if (node.Type() != YAML::NodeType::Map) {
        throw parsing_error("action map should be a map");
    }

    action_map actions;
    for (YAML::const_iterator it = node.begin(); it != node.end(); ++it) {
        auto key = it->first.as<std::string>();
        auto parameters = it->second.as<std::map<std::string, std::string>>();

        actions.emplace(key, parameters);
    }

    return actions;
}

} // namespace YAML

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

::testing::AssertionResult ValidateSchema(const std::string &result)
{
    static schema_validator schema("../schema/events.json");
    auto error = schema.validate(result.c_str());
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

::testing::AssertionResult ValidateSchemaSchema(rapidjson::Document &doc)
{
    static schema_validator schema("../schema/types.json");
    auto error = schema.validate(doc);
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

WafResultActionMatcher::WafResultActionMatcher(
    std::map<std::string, std::map<std::string, std::string>> &&v)
    : expected_(std::move(v))
{}

bool WafResultActionMatcher::MatchAndExplain(
    const ddwaf::test::action_map &obtained, ::testing::MatchResultListener * /*unused*/) const
{
    return obtained == expected_;
}

bool WafResultDataMatcher::MatchAndExplain(
    std::list<ddwaf::test::event> events, ::testing::MatchResultListener * /*unused*/) const
{
    if (events.size() != expected_events_.size()) {
        return false;
    }

    for (const auto &expected : expected_events_) {
        bool found = false;
        for (auto it = events.begin(); it != events.end(); ++it) {
            auto &obtained = *it;
            if (obtained == expected) {
                events.erase(it);
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }

    return events.empty();
}

bool MatchMatcher::MatchAndExplain(
    std::list<ddwaf::test::event::match> matches, ::testing::MatchResultListener * /*unused*/) const
{
    if (matches.size() != expected_matches_.size()) {
        return false;
    }

    for (const auto &expected : expected_matches_) {
        bool found = false;
        for (auto it = matches.begin(); it != matches.end(); ++it) {
            auto &obtained = *it;
            if (obtained == expected) {
                matches.erase(it);
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }

    return matches.empty();
}

std::list<ddwaf::test::event::match> from_matches(
    const std::vector<ddwaf::condition_match> &matches)
{
    std::list<ddwaf::test::event::match> match_list;

    for (const auto &m : matches) {
        ddwaf::test::event::match new_match;
        if (!m.highlights.empty()) {
            new_match.highlight = m.highlights[0];
        }
        new_match.op = m.operator_name;
        new_match.op_value = m.operator_value;
        for (const auto &arg : m.args) {
            new_match.args.emplace_back(ddwaf::test::event::match::argument{
                std::string{arg.name}, arg.resolved, std::string{arg.address}, arg.key_path});
        }

        match_list.emplace_back(std::move(new_match));
    }

    return match_list;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
ddwaf_object read_file(std::string_view filename, std::string_view base)
{
    std::string base_dir{base};
    if (*base_dir.end() != '/') {
        base_dir += '/';
    }

    auto file_path = base_dir + "yaml/" + std::string{filename};

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

    return yaml_to_object(buffer);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameter)
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

ddwaf_object json_to_object(const std::string &json)
{
    rapidjson::Document doc;
    const rapidjson::ParseResult result = doc.Parse(json.data());
    if (result.IsError()) {
        throw std::runtime_error(
            "invalid json object: "s + rapidjson::GetParseError_En(result.Code()));
    }

    ddwaf_object output;
    json_to_object_helper(&output, doc);
    return output;
}
