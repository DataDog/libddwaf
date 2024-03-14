// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <map>
#include <utility>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/schema.h>

#include <yaml-cpp/yaml.h>

#include "condition/scalar_condition.hpp"
#include "context_allocator.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "ruleset.hpp"
#include "test.hpp"
#include "utils.hpp"

namespace ddwaf::test {
struct event {
    struct match {
        struct argument {
            std::string name{"input"};
            std::string value{};
            std::string address{};
            std::vector<std::string> path{};
        };
        std::string op{};
        std::string op_value{};
        std::string highlight{};
        std::vector<argument> args;
    };

    std::string id;
    std::string name;
    std::map<std::string, std::string> tags{{"type", ""}, {"category", ""}};
    std::vector<std::string> actions{};
    std::vector<match> matches;
};

bool operator==(const event::match::argument &lhs, const event::match::argument &rhs);
bool operator==(const event::match &lhs, const event::match &rhs);
bool operator==(const event &lhs, const event &rhs);

std::ostream &operator<<(std::ostream &os, const event &e);
std::ostream &operator<<(std::ostream &os, const event::match &m);

std::string object_to_json(const ddwaf_object &obj);
rapidjson::Document object_to_rapidjson(const ddwaf_object &obj);

class expression_builder {
public:
    explicit expression_builder(std::size_t num_conditions) { conditions_.reserve(num_conditions); }

    void start_condition() { arguments_.clear(); }

    template <typename T, typename... Args>
    void end_condition(Args... args)
        requires std::is_base_of_v<matcher::base, T>
    {
        conditions_.emplace_back(
            std::make_unique<scalar_condition>(std::make_unique<T>(std::forward<Args>(args)...),
                std::string{}, std::move(arguments_)));
    }

    template <typename T>
    void end_condition(std::string data_id)
        requires std::is_base_of_v<matcher::base, T>
    {
        conditions_.emplace_back(std::make_unique<scalar_condition>(
            std::move(arguments_), std::move(data_id), std::make_unique<T>()));
    }

    template <typename T>
    void end_condition()
        requires std::is_base_of_v<base_condition, T>
    {
        conditions_.emplace_back(std::make_unique<T>(std::move(arguments_)));
    }

    void add_argument() { arguments_.emplace_back(); }

    void add_target(const std::string &name, std::vector<std::string> key_path = {},
        std::vector<transformer_id> transformers = {}, data_source source = data_source::values)
    {
        auto &argument = arguments_.back();
        argument.targets.emplace_back(target_definition{
            name, get_target_index(name), std::move(key_path), std::move(transformers), source});
    }

    std::shared_ptr<expression> build()
    {
        return std::make_shared<expression>(std::move(conditions_));
    }

protected:
    std::vector<parameter_definition> arguments_{};
    std::vector<std::unique_ptr<base_condition>> conditions_{};
};

inline std::shared_ptr<ddwaf::ruleset> get_default_ruleset()
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();
    ruleset->actions = std::make_shared<ddwaf::action_mapper>();
    return ruleset;
}

} // namespace ddwaf::test

namespace YAML {

class parsing_error : public std::exception {
public:
    explicit parsing_error(std::string what) : what_(std::move(what)) {}
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

protected:
    const std::string what_;
};

template <> struct as_if<ddwaf_object, void> {
    explicit as_if(const Node &node_);
    ddwaf_object operator()() const;
    const Node &node;
};

template <> struct as_if<ddwaf::test::event::match, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    ddwaf::test::event::match operator()() const;
    const Node &node;
};

template <> struct as_if<ddwaf::test::event, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    ddwaf::test::event operator()() const;
    const Node &node;
};

} // namespace YAML

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

// Note that naming conventions (and Pascal case) are kept for functions and
// classes involved in anything GTest related.

::testing::AssertionResult ValidateSchema(const std::string &result);
::testing::AssertionResult ValidateSchemaSchema(rapidjson::Document &doc);

// Required by gtest to pretty print relevant types
void PrintTo(const ddwaf_object &actions, ::std::ostream *os);
void PrintTo(const std::list<ddwaf::test::event> &events, ::std::ostream *os);
void PrintTo(const std::list<ddwaf::test::event::match> &matches, ::std::ostream *os);

class WafResultActionMatcher {
public:
    explicit WafResultActionMatcher(std::vector<std::string_view> &&values);
    bool MatchAndExplain(const ddwaf_object &actions, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const { *os << expected_as_string_; }

    void DescribeNegationTo(::std::ostream *os) const { *os << expected_as_string_; }

private:
    std::string expected_as_string_{};
    std::vector<std::string_view> expected_;
};

class WafResultDataMatcher {
public:
    explicit WafResultDataMatcher(std::vector<ddwaf::test::event> expected_events)
        : expected_events_(std::move(expected_events))
    {}

    bool MatchAndExplain(std::list<ddwaf::test::event>, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_events_) { *os << expected; }
    }

    void DescribeNegationTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_events_) { *os << expected; }
    }

protected:
    std::vector<ddwaf::test::event> expected_events_;
};

class MatchMatcher {
public:
    explicit MatchMatcher(std::vector<ddwaf::test::event::match> expected_matches)
        : expected_matches_(std::move(expected_matches))
    {}

    bool MatchAndExplain(
        std::list<ddwaf::test::event::match>, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_matches_) { *os << expected; }
    }

    void DescribeNegationTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_matches_) { *os << expected; }
    }

protected:
    std::vector<ddwaf::test::event::match> expected_matches_;
};

inline ::testing::PolymorphicMatcher<WafResultActionMatcher> WithActions(
    std::vector<std::string_view> &&values)
{
    return ::testing::MakePolymorphicMatcher(WafResultActionMatcher(std::move(values)));
}

inline ::testing::PolymorphicMatcher<WafResultDataMatcher> WithEvents(
    std::vector<ddwaf::test::event> &&expected)
{
    return ::testing::MakePolymorphicMatcher(WafResultDataMatcher(std::move(expected)));
}

inline ::testing::PolymorphicMatcher<MatchMatcher> WithMatches(
    std::vector<ddwaf::test::event::match> &&expected)
{
    return ::testing::MakePolymorphicMatcher(MatchMatcher(std::move(expected)));
}

std::list<ddwaf::test::event::match> from_matches(
    const std::vector<ddwaf::condition_match> &matches);

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define EXPECT_EVENTS(result, ...)                                                                 \
    {                                                                                              \
        auto data = ddwaf::test::object_to_json(result.events);                                    \
        EXPECT_TRUE(ValidateSchema(data));                                                         \
        YAML::Node doc = YAML::Load(data.c_str());                                                 \
        auto events = doc.as<std::list<ddwaf::test::event>>();                                     \
        EXPECT_THAT(events, WithEvents({__VA_ARGS__}));                                            \
    }

#define EXPECT_MATCHES(matches, ...) EXPECT_THAT(from_matches(matches), WithMatches({__VA_ARGS__}));

#define EXPECT_SCHEMA_EQ(obtained, expected)                                                       \
    {                                                                                              \
        auto obtained_doc = test::object_to_rapidjson(obtained);                                   \
        EXPECT_TRUE(ValidateSchemaSchema(obtained_doc));                                           \
        rapidjson::Document expected_doc;                                                          \
        expected_doc.Parse(expected);                                                              \
        EXPECT_FALSE(expected_doc.HasParseError());                                                \
        EXPECT_TRUE(json_equals(obtained_doc, expected_doc)) << test::object_to_json(obtained);    \
    }
// NOLINTEND(cppcoreguidelines-macro-usage)

ddwaf_object read_file(std::string_view filename, std::string_view base = "./");
ddwaf_object read_json_file(std::string_view filename, std::string_view base = "./");

inline ddwaf_object yaml_to_object(const std::string &yaml)
{
    return YAML::Load(yaml).as<ddwaf_object>();
}

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
