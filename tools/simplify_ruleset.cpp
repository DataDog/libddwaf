// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/prettywriter.h>
#include <re2/re2.h>
#include <re2/regexp.h>
#include <string>
#include <yaml-cpp/node/parse.h>

#include "common/utils.hpp"

std::optional<std::string> simplify_regex(const std::string &str) {
    re2::RE2 regex(str);

    auto *regexp = regex.Regexp();
    auto simplified = regexp->ToString();
    if (simplified != str) {
        return simplified;
    }

    return std::nullopt;
}

void simplify_condition(auto &condition, auto &allocator)
{
    std::string_view op = condition["operator"].GetString();
    if (op != "match_regex") {
        return;
    }

    auto &parameters = condition["parameters"];
    auto &regex = parameters["regex"];
    std::string regex_str = regex.GetString();

    auto simplified_regex = simplify_regex(regex_str);
    if (simplified_regex.has_value()) {
        regex.SetString(simplified_regex.value(), allocator);
    }
}

int main(int argc, char *argv[])
{
    int retval = EXIT_SUCCESS;

    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <json/yaml file>\n";
        return EXIT_FAILURE;
    }

    rapidjson::Document doc;
    doc.Parse(read_file(argv[1]));

    auto &alloc = doc.GetAllocator();

    if (doc.HasMember("rules")) {
        auto &rules = doc["rules"];
        for (auto &rule : rules.GetArray()) {
            auto &conditions = rule["conditions"];
            for (auto &condition : conditions.GetArray()) {
                simplify_condition(condition, alloc);
            }
        }
    }

    if (doc.HasMember("scanners")) {
        auto &scanners = doc["scanners"];
        for (auto &scanner : scanners.GetArray()) {
            auto value_it = scanner.FindMember("value");
            if (value_it != scanner.MemberEnd()) {
                auto &value = value_it->value;
                simplify_condition(value, alloc);
            }

            auto key_it = scanner.FindMember("key");
            if (key_it != scanner.MemberEnd()) {
                auto &key = key_it->value;
                simplify_condition(key, alloc);
            }
        }
    }

    rapidjson::StringBuffer buffer;
    buffer.Clear();

    rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
    writer.SetIndent(' ', 2);
    doc.Accept(writer);

    std::cout << buffer.GetString();

    return retval;
}
