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

#define LONG_TIME 1000000

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

#define DEFAULT_VALUE_REGEX "(?i)(p(ass)?w(or)?d|pass(_?phrase)?|secret|(api_?|private_?|public_?|access_?|secret_?)key(_?id)?|token|consumer_?(id|key|secret)|sign(ed|ature)?|auth(entication|orization)?)|(\\s*=[^;]|\"\\s*:\\s*\"[^\"]+\")|bearer\\s+[a-z0-9\\._\\-]+|token:[a-z0-9]{13}|gh[opsu]_[0-9a-zA-Z]{36}|ey[I-L][\\w=-]+\\.ey[I-L][\\w=-]+(\\.[\\w.+\\/=-]+)?|[\\-]{5}BEGIN[a-z\\s]+PRIVATE\\sKEY[\\-]{5}[^\\-]+[\\-]{5}END[a-z\\s]+PRIVATE\\sKEY|ssh-rsa\\s*[a-z0-9\\/\\.+]{100,}"

int main(int argc, char* argv[])
{
    ddwaf_set_log_cb(log_cb, DDWAF_LOG_OFF);

    if (argc < 2) {
        DDWAF_ERROR("Usage: %s <json/yaml file>", argv[0]);
        return EXIT_FAILURE;
    }

    std::string rule_str = read_rule_file(argv[1]);
    YAML::Node doc       = YAML::Load(rule_str);

    ddwaf_object rule   = doc.as<ddwaf_object>(); //= convert_yaml_to_args(doc);
    ddwaf_ruleset_info info;

    ddwaf_config config{{0, 0, 0}, {nullptr, DEFAULT_VALUE_REGEX}, ddwaf_object_free};
    ddwaf_handle handle = ddwaf_init(&rule, &config, &info);

    ddwaf_ruleset_info_free(&info);
    ddwaf_object_free(&rule);
    if (handle == nullptr) {
        exit(EXIT_FAILURE);
    }

    ddwaf_context context = ddwaf_context_init(handle);
    if (handle == nullptr) {
        ddwaf_destroy(handle);
        exit(EXIT_FAILURE);
    }

    ddwaf_result ret;

    ddwaf_object tmp;
    ddwaf_object useragent;
    ddwaf_object_map(&useragent);
    ddwaf_object_map_add(&useragent, "user_agent", ddwaf_object_string(&tmp, "Arachni/v1"));

    ddwaf_object root;
    ddwaf_object query_array;
    ddwaf_object_array(&query_array);
    ddwaf_object_array_add(&query_array, ddwaf_object_string(&tmp, "not a nice payload"));
    ddwaf_object_array_add(&query_array, ddwaf_object_string(&tmp, "fake honeypot"));
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "headers", &useragent);
    ddwaf_object_map_add(&root, "query", &query_array);

    auto code = ddwaf_run(context, &root, &ret, LONG_TIME);
    if (code == DDWAF_MATCH && ret.data != nullptr) {
        std::cout << ret.data << '\n';
    }
    ddwaf_result_free(&ret);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
