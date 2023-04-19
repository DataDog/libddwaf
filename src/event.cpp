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


ddwaf_object* to_object(std::string_view str) {
    static ddwaf_object tmp;
    return ddwaf_object_stringl(&tmp, str.data(), str.size());
}

} // namespace

void event_serializer::serialize(const memory::vector<event> &events, ddwaf_result &output) const
{
    rapidjson::Document doc;
    auto &allocator = doc.GetAllocator();

    output.actions = {nullptr, 0};
    ddwaf_object_array(&output.events);

    std::unordered_set<std::string_view> all_actions;
    for (const auto &event : events) {
        ddwaf_object root_map;
        ddwaf_object rule_map;
        ddwaf_object tags_map;
        ddwaf_object match_array;

        ddwaf_object_map(&root_map);
        ddwaf_object_map(&rule_map);
        ddwaf_object_map(&tags_map);
        ddwaf_object_array(&match_array);

        if (event.rule != nullptr) {
            for (const auto &[key, value] : event.rule->get_tags()) {
                ddwaf_object_map_addl(&tags_map, key.c_str(), key.size(), to_object(value));
            }

            ddwaf_object_map_add(&rule_map, "id", to_object(event.rule->get_id()));
            ddwaf_object_map_add(&rule_map, "name", to_object(event.rule->get_name()));

            const auto &actions = event.rule->get_actions();
            if (!actions.empty()) {
                ddwaf_object actions_array;
                ddwaf_object_array(&actions_array);
                for (const auto &action : actions) {
                    all_actions.emplace(action);
                    ddwaf_object_array_add(&actions_array, to_object(action));
                }
                ddwaf_object_map_add(&rule_map, "on_match", &actions_array);
            }
        } else {
            // This will only be used for testing
            ddwaf_object_map_add(&rule_map, "id", to_object({}));
            ddwaf_object_map_add(&rule_map, "name", to_object({}));
            ddwaf_object_map_add(&tags_map, "type", to_object({}));
            ddwaf_object_map_add(&tags_map, "category", to_object({}));
        }
        ddwaf_object_map_add(&rule_map, "tags", &tags_map);

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
