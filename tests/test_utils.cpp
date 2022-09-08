// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test_utils.hpp"
#include <fstream>
#include <memory>

namespace ddwaf::test {

bool operator==(const event::match &lhs, const event::match &rhs) {
    return lhs.op == rhs.op && lhs.op_value == rhs.op_value &&
        lhs.address == rhs.address && lhs.path == rhs.path &&
        lhs.value == rhs.value && lhs.highlight == rhs.highlight;
}

bool operator==(const event &lhs, const event &rhs) {
    return lhs.id == rhs.id && lhs.name == rhs.name && lhs.type == rhs.type &&
        lhs.category == rhs.category && lhs.actions == rhs.actions &&
        lhs.matches == rhs.matches;
}

namespace {

struct indent {
    indent(unsigned size): size_(size) {}
    unsigned size_;
};

std::ostream& operator<<(std::ostream& os, const indent& offset)
{
    for (unsigned i = 0; i < offset.size_; i++) { os << ' '; }
    return os;
}

}

std::ostream& operator<<(std::ostream& os, const event& e)
{
    os << "{\n"
       << indent(4) << "id: " << e.id << ",\n"
       << indent(4) << "name: " << e.name << ",\n"
       << indent(4) << "type: " << e.type << ",\n"
       << indent(4) << "category: " << e.category << ",\n"
       << indent(4) << "actions: [";
    bool start = true;
    for (auto a : e.actions) {
        if (!start) { os << ", "; } else { start = false; }
        os  << a;
    }
    os << "],\n"
       << indent(4) << "matches: [\n";

    for (auto m : e.matches) {
        os << indent(8) <<"{\n";

        os << indent(12) << "operator: "  << m.op << ",\n"
           << indent(12) << "operator_value:" << m.op_value << ",\n"
           << indent(12) << "address: " <<  m.address << ",\n"
           << indent(12) << "path: [";

        bool start = true;
        for (auto p : m.path) {
            if (!start) { os << ", "; } else { start = false; }
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

}

namespace YAML
{
using event = ddwaf::test::event;
using match = ddwaf::test::event::match;

template <class T>
T as(const YAML::Node &node, const std::string &key)
{
    auto value = node[key];
    if (!value) { return {}; }

    try {
        return value.as<T>();
    } catch (...) {
        throw parsing_error("failed to parse " + key);
    }
}

template <class T>
T as(const YAML::Node &node, unsigned key)
{
    auto value = node[key];
    if (!value) { return {}; }

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

    auto tags = rule["tags"];
    if (!tags || tags.Type() != YAML::NodeType::Map) {
        throw parsing_error("tags should be a map");
    }

    e.type = as<std::string>(tags, "type");
    e.category = as<std::string>(tags, "category");
    e.actions = as<std::vector<std::string>>(rule, "on_match");
    e.matches = as<std::vector<match>>(node, "rule_matches");

    return e;
}

namespace {
ddwaf_object node_to_arg(const Node& node)
{
    switch (node.Type())
    {
        case NodeType::Sequence:
        {
            ddwaf_object arg = DDWAF_OBJECT_ARRAY;
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                ddwaf_object child = node_to_arg(*it);
                ddwaf_object_array_add(&arg, &child);
            }
            return arg;
        }
        case NodeType::Map:
        {
            ddwaf_object arg = DDWAF_OBJECT_MAP;
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                std::string key    = it->first.as<std::string>();
                ddwaf_object child = node_to_arg(it->second);
                ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
            }
            return arg;
        }
        case NodeType::Scalar:
        {
            const std::string& value = node.Scalar();
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
}

as_if<ddwaf_object, void>::as_if(const Node& node_) : node(node_) {}
ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    return node_to_arg(node);
}

}

event_schema_validator::event_schema_validator()
{
    std::ifstream rule_file("../schema/appsec-event-1.1.0.json", std::ios::in);
    if (!rule_file)
    {
        throw std::system_error(errno, std::generic_category());
    }

    std::string buffer;
    rule_file.seekg(0, std::ios::end);
    buffer.resize(rule_file.tellg());
    rule_file.seekg(0, std::ios::beg);

    rule_file.read(&buffer[0], buffer.size());
    rule_file.close();

    if (schema_doc_.Parse(buffer).HasParseError()) {
        throw std::runtime_error("failed to parse schema");
    }

    schema_   = std::make_unique<rapidjson::SchemaDocument>(schema_doc_);
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

::testing::AssertionResult ValidateSchema(const ddwaf_result &result) {

    if (result.data == nullptr) {
        return ::testing::AssertionFailure() << " invalid data";
    }

    static event_schema_validator schema;
    auto error = schema.validate(result.data);
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

void PrintTo(const ddwaf_result_actions &actions, ::std::ostream *os)
{
    *os << "[";
    for (unsigned i = 0; i < actions.size; i++) {
        if (i > 0) { *os << ", "; }
        *os << actions.array[i];
    }
    *os << "]";
}

void PrintTo(const ddwaf_result &result, ::std::ostream *os)
{
    YAML::Node doc = YAML::Load(result.data);
    auto events = doc.as<std::vector<ddwaf::test::event>>();
    for (auto e : events) {
        *os << e;
    }
}

WafResultActionMatcher::WafResultActionMatcher(std::vector<std::string_view> &&values):
    expected_(std::move(values))
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

bool WafResultActionMatcher::MatchAndExplain(const ddwaf_result_actions &actions,
  ::testing::MatchResultListener*) const {
    if (actions.size != expected_.size()) { return false; }

    std::vector<std::string_view> obtained;
    obtained.reserve(actions.size);
    for (unsigned i = 0; i < actions.size; i++) {
        obtained.emplace_back(actions.array[i]);
    }
    std::sort(obtained.begin(), obtained.end());

    return obtained == expected_;
}

bool WafResultDataMatcher::MatchAndExplain(const ddwaf_result &result,
  ::testing::MatchResultListener*) const {
    if (result.data == nullptr) { return false; }

    YAML::Node doc = YAML::Load(result.data);
    auto events = doc.as<std::list<ddwaf::test::event>>();

    if (events.size() != expected_events_.size()) { return false; }

    for (auto expected : expected_events_) {
        bool found = false;
        for (auto it = events.begin() ; it != events.end() ; ++it) {
            auto &obtained = *it;
            if (obtained == expected) {
                events.erase(it);
                found = true;
                break;
            }
        }
        if (!found) { return false; }
    }

    if (!events.empty()) { return false; }

    return true;
}

size_t getFileSize(const char* filename)
{
    struct stat st;
    size_t output = 0;

    if (stat(filename, &st) == 0 && st.st_size > 0)
        output = (uint64_t) st.st_size;

    return output;
}

ddwaf_object readFile(const char* filename)
{
    const static char path_sep =
#ifdef _WIN32
    '\\';
#else
    '/';
#endif

    auto fullFileName = string { "yaml" } + path_sep + filename;

    auto fileSize = getFileSize(fullFileName.c_str());
    if (fileSize == 0)
    {
        DDWAF_ERROR("No such file or size 0 (wrong dir?): %s", fullFileName.c_str());
        return DDWAF_OBJECT_INVALID;
    }

    char* buffer = (char*) malloc(fileSize + 1);
    if (buffer == nullptr)
        return DDWAF_OBJECT_INVALID;

    FILE* file = fopen(fullFileName.c_str(), "rb");
    if (file == nullptr)
    {
        DDWAF_ERROR("Failed opening for reading: %s", fullFileName.c_str());
        free(buffer);
        return DDWAF_OBJECT_INVALID;
    }

    if (fread((void*) buffer, fileSize, 1, file) != 1)
    {
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

ddwaf_object readRule(const char* rule)
{
    YAML::Node doc = YAML::Load(rule);
    return doc.as<ddwaf_object>();
}
