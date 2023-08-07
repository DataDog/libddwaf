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

using namespace std::literals;

namespace ddwaf::test {

bool operator==(const event::match &lhs, const event::match &rhs)
{
    return lhs.op == rhs.op && lhs.op_value == rhs.op_value && lhs.address == rhs.address &&
           lhs.path == rhs.path && lhs.value == rhs.value && lhs.highlight == rhs.highlight;
}

bool operator==(const event &lhs, const event &rhs)
{
    return lhs.id == rhs.id && lhs.name == rhs.name && lhs.tags == rhs.tags &&
           lhs.actions == rhs.actions && lhs.matches == rhs.matches;
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
    os << indent(4) << "{\n"
       << indent(8) << "operator: " << m.op << ",\n"
       << indent(8) << "operator_value: " << m.op_value << ",\n"
       << indent(8) << "address: " << m.address << ",\n"
       << indent(8) << "path: [";

    bool start = true;
    for (const auto &p : m.path) {
        if (!start) {
            os << ", ";
        } else {
            start = false;
        }
        os << p;
    }

    os << "],\n"
       << indent(8) << "value: " << m.value << ",\n"
       << indent(8) << "highlight: " << m.highlight << "\n"
       << indent(4) << "}\n";

    return os;
}

std::ostream &operator<<(std::ostream &os, const event &e)
{
    os << "{\n"
       << indent(4) << "id: " << e.id << ",\n"
       << indent(4) << "name: " << e.name << ",\n"
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
        os << indent(8) << "{\n";

        os << indent(12) << "operator: " << m.op << ",\n"
           << indent(12) << "operator_value: " << m.op_value << ",\n"
           << indent(12) << "address: " << m.address << ",\n"
           << indent(12) << "path: [";

        bool start = true;
        for (const auto &p : m.path) {
            if (!start) {
                os << ", ";
            } else {
                start = false;
            }
            os << p;
        }

        os << "],\n"
           << indent(12) << "value: " << m.value << ",\n"
           << indent(12) << "highlight: " << m.highlight << "\n"
           << indent(8) << "}\n";
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
    case DDWAF_OBJ_BOOL: {
        std::string_view value = "false"sv;
        if (obj.boolean) {
            value = "true"sv;
        }
        output.SetString(value.data(), value.size(), alloc);
    } break;
    case DDWAF_OBJ_SIGNED:
        output.SetInt64(obj.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        output.SetUint64(obj.uintValue);
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
    case DDWAF_OBJ_INVALID:
        throw std::runtime_error("invalid parameter in structure");
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

} // namespace ddwaf::test

namespace YAML {
using event = ddwaf::test::event;
using match = ddwaf::test::event::match;

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

    m.address = as<std::string>(parameters, "address");
    m.path = as<std::vector<std::string>>(parameters, "key_path");
    m.value = as<std::string>(parameters, "value");

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

} // namespace YAML

event_schema_validator::event_schema_validator()
{
    std::ifstream rule_file("../schema/events.json", std::ios::in);
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

std::optional<std::string> event_schema_validator::validate(const char *events)
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

::testing::AssertionResult ValidateSchema(const std::string &result)
{
    static event_schema_validator schema;
    auto error = schema.validate(result.c_str());
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

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

WafResultActionMatcher::WafResultActionMatcher(std::vector<std::string_view> &&values)
    : expected_(std::move(values))
{
    std::sort(expected_.begin(), expected_.end());
    expected_as_string_ = "[";
    for (auto &value : expected_) {
        if (expected_as_string_.size() > 1) {
            expected_as_string_ += ", ";
        }

        expected_as_string_ += value;
    }

    expected_as_string_ += "]";
}

bool WafResultActionMatcher::MatchAndExplain(
    const ddwaf_object &actions, ::testing::MatchResultListener *) const
{
    size_t actions_size = ddwaf_object_size(&actions);
    if (actions_size != expected_.size()) {
        return false;
    }

    std::vector<std::string_view> obtained;
    obtained.reserve(actions_size);
    for (unsigned i = 0; i < actions_size; i++) {
        const auto *object = ddwaf_object_get_index(&actions, i);
        if (ddwaf_object_type(object) == DDWAF_OBJ_STRING) {
            obtained.emplace_back(ddwaf_object_get_string(object, nullptr));
        }
    }
    std::sort(obtained.begin(), obtained.end());

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
    const ddwaf::memory::vector<ddwaf::event::match> &matches)
{
    std::list<ddwaf::test::event::match> match_list;

    for (const auto &m : matches) {
        ddwaf::test::event::match new_match;
        new_match.value = m.resolved;
        new_match.highlight = m.matched;
        new_match.op = m.operator_name;
        new_match.op_value = m.operator_value;
        new_match.address = m.address;
        for (const auto &k : m.key_path) { new_match.path.emplace_back(k); }

        match_list.emplace_back(std::move(new_match));
    }

    return match_list;
}

size_t getFileSize(const char *filename)
{
    struct stat st;
    size_t output = 0;

    if (stat(filename, &st) == 0 && st.st_size > 0)
        output = (uint64_t)st.st_size;

    return output;
}

ddwaf_object readFile(std::string_view filename, std::string_view base)
{
    const static char path_sep =
#ifdef _WIN32
        '\\';
#else
        '/';
#endif

    std::string base_dir{base};
    if (*base_dir.end() != path_sep) {
        base_dir += path_sep;
    }

    auto fullFileName = base_dir + "yaml" + path_sep + std::string{filename};

    DDWAF_DEBUG("Opening %s", fullFileName.c_str());
    auto fileSize = getFileSize(fullFileName.c_str());
    if (fileSize == 0) {
        DDWAF_ERROR("No such file or size 0 (wrong dir?): %s", fullFileName.c_str());
        return DDWAF_OBJECT_INVALID;
    }

    char *buffer = (char *)malloc(fileSize + 1);
    if (buffer == nullptr)
        return DDWAF_OBJECT_INVALID;

    FILE *file = fopen(fullFileName.c_str(), "rb");
    if (file == nullptr) {
        DDWAF_ERROR("Failed opening for reading: %s", fullFileName.c_str());
        free(buffer);
        return DDWAF_OBJECT_INVALID;
    }

    if (fread((void *)buffer, fileSize, 1, file) != 1) {
        free(buffer);
        fclose(file);
        return DDWAF_OBJECT_INVALID;
    }

    fclose(file);
    buffer[fileSize] = 0;

    auto config = readRule(buffer);
    free(buffer);
    return config;
}

ddwaf_object readRule(const char *rule)
{
    YAML::Node doc = YAML::Load(rule);
    return doc.as<ddwaf_object>();
}
