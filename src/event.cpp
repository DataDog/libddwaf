// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <event.hpp>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <rule.hpp>
#include <unordered_set>

namespace ddwaf {

namespace {

char *to_cstr(std::string_view input)
{
    const std::size_t size = input.size();
    // NOLINTNEXTLINE
    char *str = static_cast<char *>(malloc(size + 1));
    memcpy(str, input.data(), size);
    str[size] = '\0';
    return str;
}

char *to_cstr(rapidjson::StringBuffer &buffer)
{
    return to_cstr(std::string_view{buffer.GetString(), buffer.GetSize()});
}

rapidjson::GenericStringRef<char> StringRef(std::string_view str)
{
    return {str.data(), static_cast<rapidjson::SizeType>(str.size())};
}

bool redact_match(const ddwaf::obfuscator &obfuscator, const event::match &match)
{
    for (const auto &key : match.key_path) {
        if (obfuscator.is_sensitive_key(key)) {
            return true;
        }
    }

    return obfuscator.is_sensitive_value(match.resolved) ||
           obfuscator.is_sensitive_value(match.matched);
}

void serialize_match(rapidjson::Value &output, rapidjson::Document::AllocatorType &allocator,
    const event::match &match, bool redact)
{
    auto redaction_msg = StringRef(ddwaf::obfuscator::redaction_msg);

    rapidjson::Value parameters;
    rapidjson::Value param;
    rapidjson::Value key_path;
    rapidjson::Value highlight;

    key_path.SetArray();
    for (const auto &key : match.key_path) { key_path.PushBack(StringRef(key), allocator); }

    highlight.SetArray();
    if (!match.matched.empty()) {
        highlight.PushBack(redact ? redaction_msg : StringRef(match.matched), allocator);
    }

    param.SetObject();
    param.AddMember("address", StringRef(match.address), allocator);
    param.AddMember("key_path", key_path, allocator);
    param.AddMember("value", redact ? redaction_msg : StringRef(match.resolved), allocator);
    param.AddMember("highlight", highlight, allocator);

    parameters.SetArray();
    parameters.PushBack(param, allocator);

    output.AddMember("operator", StringRef(match.operator_name), allocator);
    output.AddMember("operator_value", StringRef(match.operator_value), allocator);
    output.AddMember("parameters", parameters, allocator);
}

} // namespace

void event_serializer::serialize(const memory::vector<event> &events, ddwaf_result &output) const
{
    rapidjson::Document doc;
    auto &allocator = doc.GetAllocator();

    output.data = nullptr;
    output.actions = {nullptr, 0};

    doc.SetArray();
    std::unordered_set<std::string_view> all_actions;
    for (const auto &event : events) {
        rapidjson::Value map;
        rapidjson::Value rule;
        rapidjson::Value tags;
        rapidjson::Value match_array;
        rapidjson::Value on_match;

        tags.SetObject();
        rule.SetObject();

        if (event.rule != nullptr) {
            for (const auto &[key, value] : event.rule->get_tags()) {
                tags.AddMember(StringRef(key), StringRef(value), allocator);
            }

            rule.AddMember("id", StringRef(event.rule->get_id()), allocator);
            rule.AddMember("name", StringRef(event.rule->get_name()), allocator);

            const auto &actions = event.rule->get_actions();
            if (!actions.empty()) {
                on_match.SetArray();
                for (const auto &action : actions) {
                    all_actions.emplace(action);
                    on_match.PushBack(StringRef(action), allocator);
                }
                rule.AddMember("on_match", on_match, allocator);
            }
        } else {
            // This will only be used for testing
            tags.AddMember("type", "", allocator);
            tags.AddMember("category", "", allocator);
            rule.AddMember("id", "", allocator);
            rule.AddMember("name", "", allocator);
        }

        rule.AddMember("tags", tags, allocator);

        match_array.SetArray();
        for (const auto &match : event.matches) {
            rapidjson::Value output;
            output.SetObject();

            const bool redact = redact_match(obfuscator_, match);
            serialize_match(output, allocator, match, redact);

            match_array.PushBack(output, allocator);
        }

        map.SetObject();
        map.AddMember("rule", rule, allocator);
        map.AddMember("rule_matches", match_array, allocator);

        doc.PushBack(map, allocator);
    }

    if (!events.empty()) {
        rapidjson::StringBuffer buffer;
        buffer.Clear();

        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        if (doc.Accept(writer)) {
            output.data = to_cstr(buffer);
        }

        if (!all_actions.empty()) {
            // NOLINTNEXTLINE
            output.actions.array =
                static_cast<char **>(malloc(sizeof(char *) * all_actions.size()));
            output.actions.size = all_actions.size();

            std::size_t index = 0;
            for (const auto &action : all_actions) {
                output.actions.array[index++] = to_cstr(action);
            }
        }
    }
}

} // namespace ddwaf
