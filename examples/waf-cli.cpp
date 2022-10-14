// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <yaml-cpp/yaml.h>

#include "ddwaf.h"
#include "log.hpp"
#include <fstream>
#include <iostream>
#include <ctime>

#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"
#include "rapidjson/error/en.h"

using namespace rapidjson;


#define LONG_TIME 1000000

std::string read_file(const std::string_view& filename)
{
    std::ifstream rule_file(filename.data(), std::ios::in);
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
    return buffer;
}


namespace YAML
{

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() { return what_.c_str(); }

protected:
    const std::string what_;
};

ddwaf_object node_to_arg(const Node& node)
{
    switch (node.Type())
    {
        case NodeType::Sequence:
        {
            ddwaf_object arg;
            ddwaf_object_array(&arg);
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                ddwaf_object child = node_to_arg(*it);
                ddwaf_object_array_add(&arg, &child);
            }
            return arg;
        }
        case NodeType::Map:
        {
            ddwaf_object arg;
            ddwaf_object_map(&arg);
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
            ddwaf_object arg;
            ddwaf_object_invalid(&arg);
            return arg;
    }

    throw parsing_error("Invalid YAML node type");
}

template <>
struct as_if<ddwaf_object, void>
{
    explicit as_if(const Node& node_) : node(node_) {}
    ddwaf_object operator()() const { return node_to_arg(node); }
    const Node& node;
};

}

const char* level_to_str(DDWAF_LOG_LEVEL level)
{
    switch (level)
    {
        case DDWAF_LOG_TRACE:
            return "trace";
        case DDWAF_LOG_DEBUG:
            return "debug";
        case DDWAF_LOG_ERROR:
            return "error";
        case DDWAF_LOG_WARN:
            return "warn";
        case DDWAF_LOG_INFO:
            return "info";
        case DDWAF_LOG_OFF:
            break;
    }

    return "off";
}

void log_cb(DDWAF_LOG_LEVEL level,
            const char* function, const char* file, unsigned line,
            const char* message, uint64_t)
{
    printf("[%s][%s:%s:%u]: %s\n", level_to_str(level), file, function, line, message);
}

std::string read_rule_file(const std::string_view& filename)
{
    std::ifstream rule_file(filename.data(), std::ios::in);
    if (!rule_file)
    {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    rule_file.seekg(0, std::ios::end);
    buffer.resize(rule_file.tellg());
    rule_file.seekg(0, std::ios::beg);

    rule_file.read(&buffer[0], buffer.size());
    rule_file.close();
    return buffer;
}


void process_attack(ddwaf_context *context, std::string attack, std::string org_id, int run_id) {

    // std::cout << org_id << "; " << attack << std::endl;

    ddwaf_result ret = {0};
    // ddwaf_object input = YAML::Load(argv[2]).as<ddwaf_object>();
    YAML::Emitter out;
    out << YAML::BeginMap;
    out << YAML::Key << "server.request.query";
    out << YAML::Value << attack;
    out << YAML::EndMap;
    ddwaf_object input = YAML::Load(out.c_str()).as<ddwaf_object>();
    ddwaf_run(*context, &input, &ret, LONG_TIME);
    if (ret.data) {
        auto result = YAML::Load(ret.data);
        for (unsigned i = 0; i < result.size(); i++) {
            auto rule = result[i]["rule"];
            auto match = result[i]["rule_matches"][0]["parameters"][0];
            std::cout << org_id << "; " << rule["id"] << "; ";
            std::cout  << run_id << "; " << match["value"] << std::endl;
        }
    }
    ddwaf_result_free(&ret);
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <json/yaml rule file> <yaml input>" << std::endl;
        std::cerr << std::endl;
        std::cerr << "    " << argv[0] << "appsec-event-rules/build/recommended.json \"<script>alert(0)\"" << std::endl;
        std::cerr << std::endl;
        std::cerr << "   JSON file format: {\"org_id\": [array of attacks]" << std::endl;
        std::cerr << "   Example: {\"1000201\": [\"<script>alert()\", \"' OR 1=1-- \"]}" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << "   The address used as attack provenance is \"server.request.query\"" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << "   In order to run every rule against an attack, each rule has to have a different type." << std::endl;
        std::cerr << "   the rule file has to be changed in such a way, for instance in VIM:" << std::endl;
        std::cerr << "   :let i=1 | g/^ *\"type\": \"/s//\\='\"type\": \"'.i/ | let i=i+1l;" << std::endl;
        std::cerr << "" << std::endl;
        std::cerr << std::endl;

        return EXIT_FAILURE;
    }

    std::string rule_str = read_rule_file(argv[1]);
    YAML::Node doc       = YAML::Load(rule_str);

    ddwaf_object rule   = doc.as<ddwaf_object>();

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        std::cerr << "Error initializing ddwaf (check rules)\n";
        exit(EXIT_FAILURE);
    }


    auto inputJson = read_file(argv[2]);
    Document d;
    rapidjson::ParseResult result = d.Parse(inputJson);
    if (!result)
    {
        std::cerr << "Failed to parse input json: " 
                  << rapidjson::GetParseError_En(result.Code())
                  << result.Offset() << std::endl;
        return EXIT_FAILURE;
    }

    int run_id = 0;
    for (auto& m : d.GetObject()) {
        std::string org_id = m.name.GetString();
        for (auto& a : m.value.GetArray()) {

            std::string attack = a.GetString();

            ddwaf_context context = ddwaf_context_init(handle);
            if (context == nullptr) {
                std::cerr << "Error initializing ddwaf context\n";
                ddwaf_destroy(handle);
                exit(EXIT_FAILURE);
            }

            process_attack(&context, attack, org_id, ++run_id);

            ddwaf_context_destroy(context);
        }
    }


    ddwaf_destroy(handle);
}

