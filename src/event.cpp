// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <event.hpp>
#include <log.hpp>
#include <rapidjson/document.h>
#include <rapidjson/prettywriter.h>
#include <unordered_set>

namespace ddwaf
{

namespace
{

char *to_cstr(std::string_view input) {
    std::size_t size = input.size();
    char *str = static_cast<char*>(malloc(size + 1));
    memcpy(str, input.data(), size);
    str[size] = '\0';
    return str;
}

char *to_cstr(rapidjson::StringBuffer &buffer) {
    return to_cstr(std::string_view{buffer.GetString(), buffer.GetSize()});
}

rapidjson::GenericStringRef<char> StringRef(std::string_view str) {
    return rapidjson::GenericStringRef<char>(
            str.data(), static_cast<rapidjson::SizeType>(str.size()));
}

void serialize_match(rapidjson::Value &output,
        rapidjson::Document::AllocatorType &allocator,
        event::match &match, const ddwaf::obfuscator &obfuscator)
{
    auto redaction_msg = StringRef(ddwaf::obfuscator::redaction_msg);

    output.AddMember("operator", StringRef(match.operator_name), allocator);
    output.AddMember("operator_value", StringRef(match.operator_value), allocator);

    rapidjson::Value parameters, param, key_path;
    parameters.SetArray();

    param.SetObject();
    param.AddMember("address", StringRef(match.source), allocator);

    key_path.SetArray();
    bool redact = false;
    for (const auto &key: match.key_path)
    {
        redact = redact || obfuscator.is_sensitive_key(key);

        rapidjson::Value jsonKey;
        jsonKey.SetString(key, allocator);
        key_path.PushBack(jsonKey, allocator);
    }
    param.AddMember("key_path", key_path, allocator);

    rapidjson::Value highlight, matched;
    highlight.SetArray();

    redact = redact ||
             obfuscator.is_sensitive_value(match.resolved) ||
             obfuscator.is_sensitive_value(match.matched);

    if (redact) {
        param.AddMember("value", redaction_msg, allocator);
        if (!match.matched.empty()) {
            matched.SetString(redaction_msg, allocator);
            highlight.PushBack(matched, allocator);
        }
    } else {
        param.AddMember("value", match.resolved, allocator);
        if (!match.matched.empty()) {
            matched.SetString(match.matched, allocator);
            highlight.PushBack(matched, allocator);
        }
    }

    param.AddMember("highlight", highlight, allocator);
    parameters.PushBack(param, allocator);

    // This field is required by the obfuscator and shouldn't be renamed
    output.AddMember("parameters", parameters, allocator);
}

}

void event_serializer::serialize(ddwaf_result &output)
{
    rapidjson::Document doc;
    auto &allocator = doc.GetAllocator();

    output.data = nullptr;
    output.actions = {nullptr, 0};

    std::unordered_set<std::string_view> actions;

    doc.SetArray();
    DDWAF_DEBUG("SERIALIZING");
    for (auto &event : events_) {
        rapidjson::Value map, rule, tags, match_array;

        tags.SetObject();
        tags.AddMember("type", StringRef(event.type), allocator);
        tags.AddMember("category", StringRef(event.category), allocator);

        DDWAF_DEBUG("EVENT %s, %s", event.id.data(), event.name.data());
        rule.SetObject();
        rule.AddMember("id", StringRef(event.id), allocator);
        rule.AddMember("name", StringRef(event.name), allocator);
        rule.AddMember("tags", tags, allocator);

        match_array.SetArray();
        for (auto &match: event.matches) {
            rapidjson::Value output;
            output.SetObject();
            serialize_match(output, allocator, match, obfuscator_);
            match_array.PushBack(output, allocator);
        }

        map.SetObject();
        map.AddMember("rule", rule, allocator);
        map.AddMember("rule_matches", match_array, allocator);

        for (std::string_view action: event.actions) {
            actions.emplace(action);
        }

        doc.PushBack(map, allocator);
    }

    if (!events_.empty()) {
        rapidjson::StringBuffer buffer;
        buffer.Clear();

        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        if (doc.Accept(writer)) {
            output.data = to_cstr(buffer);
        }

        if (!actions.empty()) {
            output.actions.array = static_cast<char**>(malloc(sizeof(char *) * actions.size()));
            output.actions.size = actions.size();

            std::size_t index = 0;
            for (const auto &action : actions) {
                output.actions.array[index++] = to_cstr(action);
            }
        }
    }
}

}
