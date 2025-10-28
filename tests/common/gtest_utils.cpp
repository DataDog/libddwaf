// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "common/base_path.hpp"
#include "common/json_utils.hpp"
#include "common/yaml_utils.hpp"
#include "condition/base.hpp"

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
           lhs.stack_id.empty() == rhs.stack_id.empty() &&
           lhs.block_id.empty() == rhs.block_id.empty();
}

namespace {

struct indent {
    explicit indent(unsigned size) : size_(size) {}
    unsigned size_;
};

std::ostream &operator<<(std::ostream &os, const ddwaf::dynamic_string &str)
{
    return os << std::string_view{str};
}

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
       << indent(4) << "block_id: " << e.block_id << ",\n"
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

            if (std::holds_alternative<std::string>(v)) {
                os << indent(8) << k << ": " << std::get<std::string>(v);
            } else if (std::holds_alternative<int64_t>(v)) {
                os << indent(8) << k << ": " << std::get<int64_t>(v);
            } else if (std::holds_alternative<uint64_t>(v)) {
                os << indent(8) << k << ": " << std::get<uint64_t>(v);
            } else if (std::holds_alternative<double>(v)) {
                os << indent(8) << k << ": " << std::get<double>(v);
            } else if (std::holds_alternative<bool>(v)) {
                os << indent(8) << k << ": " << std::boolalpha << std::get<bool>(v);
            }
        }

        os << "\n" << indent(4) << "}";
    }

    os << "\n}";

    return os;
}

void PrintTo(const ddwaf::test::action_map &actions, ::std::ostream *os) { *os << actions; }

::testing::AssertionResult ValidateEventSchema(const std::string &result)
{
    static schema_validator schema(ddwaf::test::test_directory + "/../schema/events.json");
    auto error = schema.validate(result.c_str());
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

::testing::AssertionResult ValidateSchemaSchema(rapidjson::Document &doc)
{
    static schema_validator schema(ddwaf::test::test_directory + "/../schema/schema.json");
    auto error = schema.validate(doc);
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

::testing::AssertionResult ValidateDiagnosticsSchema(const ddwaf_object &diagnostics)
{
    static schema_validator schema(ddwaf::test::test_directory + "/../schema/diagnostics.json");
    auto doc = ddwaf::test::object_to_rapidjson(diagnostics);
    auto error = schema.validate(doc);
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

::testing::AssertionResult ValidateActionsSchema(const std::string &result)
{
    static schema_validator schema(ddwaf::test::test_directory + "/../schema/actions.json");
    auto error = schema.validate(result.c_str());
    if (error) {
        return ::testing::AssertionFailure() << *error;
    }

    return ::testing::AssertionSuccess();
}

WafResultActionMatcher::WafResultActionMatcher(
    std::map<std::string, std::map<std::string, ddwaf::test::scalar_type>> &&v)
    : expected_(std::move(v))
{}

bool WafResultActionMatcher::MatchAndExplain(
    const ddwaf::test::action_map &obtained, ::testing::MatchResultListener * /*unused*/) const
{
    if (expected_.size() != obtained.size()) {
        return false;
    }

    for (auto [expected_type, expected_params] : expected_) {
        const auto &it = obtained.find(expected_type);
        if (it == obtained.end()) {
            return false;
        }

        auto obtained_params = it->second;

        if (expected_params.contains("stack_id")) {
            if (!obtained_params.contains("stack_id")) {
                return false;
            }
            expected_params.erase("stack_id");
            obtained_params.erase("stack_id");
        }

        if (expected_params.contains("security_response_id")) {
            if (!obtained_params.contains("security_response_id")) {
                return false;
            }
            expected_params.erase("security_response_id");
            obtained_params.erase("security_response_id");
        }

        if (expected_params != obtained_params) {
            return false;
        }
    }
    return true;
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
    e.block_id = as<std::string>(node, "security_response_id");

    return e;
}
std::map<std::string, ddwaf::test::scalar_type>
as_if<std::map<std::string, ddwaf::test::scalar_type>, void>::operator()() const
{
    std::map<std::string, ddwaf::test::scalar_type> parameters;

    for (auto it = node.begin(); it != node.end(); ++it) {
        auto key = it->first.as<std::string>();

        const std::string &value = it->second.Scalar();
        if (it->second.Tag() == "?") {
            try {
                parameters.emplace(std::move(key), it->second.as<uint64_t>());
                continue;
            } catch (...) {}

            try {
                parameters.emplace(std::move(key), it->second.as<int64_t>());
                continue;
            } catch (...) {}

            try {
                parameters.emplace(std::move(key), it->second.as<double>());
                continue;
            } catch (...) {}

            try {
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    parameters.emplace(std::move(key), it->second.as<bool>());
                }
                continue;
            } catch (...) {}
        }

        parameters.emplace(std::move(key), value);
    }

    return parameters;
}

action_map as_if<action_map, void>::operator()() const
{
    if (node.Type() != YAML::NodeType::Map) {
        throw parsing_error("action map should be a map");
    }

    action_map actions;
    for (YAML::const_iterator it = node.begin(); it != node.end(); ++it) {
        auto key = it->first.as<std::string>();
        auto parameters = it->second.as<std::map<std::string, ddwaf::test::scalar_type>>();
        actions.emplace(key, parameters);
    }

    return actions;
}
} // namespace YAML
