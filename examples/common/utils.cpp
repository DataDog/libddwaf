// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <limits>
#include <string_view>
#include <utility>
#include <yaml-cpp/yaml.h>

#include "ddwaf.h"
#include "utils.hpp"

namespace YAML {

namespace {
// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object yaml_to_object(const Node& node)
{
    switch (node.Type())
    {
        case NodeType::Sequence:
        {
            ddwaf_object arg;
            ddwaf_object_array(&arg);
            for (auto it = node.begin(); it != node.end(); ++it)
            {
                ddwaf_object child = yaml_to_object(*it);
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
                ddwaf_object child = yaml_to_object(it->second);
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

} // namespace

ddwaf_object as_if<ddwaf_object, void>::operator()() const {
    return yaml_to_object(node); 
}

} // namespace YAML

namespace {
// NOLINTNEXTLINE(misc-no-recursion)
void object_to_yaml_helper(const ddwaf_object &obj, YAML::Node &output)
{
    switch (obj.type) {
    case DDWAF_OBJ_BOOL:
        output = obj.boolean ? "true" : "false";
        break;
    case DDWAF_OBJ_SIGNED:
        output = obj.intValue;
        break;
    case DDWAF_OBJ_UNSIGNED:
        output = obj.uintValue;
        break;
    case DDWAF_OBJ_STRING:
        output = std::string{obj.stringValue, obj.nbEntries};
        break;
    case DDWAF_OBJ_MAP:
        output = YAML::Load("{}");
        for (unsigned i = 0; i < obj.nbEntries; i++) {
            auto child = obj.array[i];
            std::string key{child.parameterName, child.parameterNameLength};

            YAML::Node value;
            object_to_yaml_helper(child, value);
            output[key] = value;
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output = YAML::Load("[]");
        for (unsigned i = 0; i < obj.nbEntries; i++) {
            auto child = obj.array[i];

            YAML::Node value;
            object_to_yaml_helper(child, value);
            output.push_back(value);
        }
        break;
    case DDWAF_OBJ_INVALID:
        throw std::runtime_error("invalid parameter in structure");
    };
}

} // namespace

YAML::Node object_to_yaml(const ddwaf_object &obj)
{
    YAML::Node root;
    object_to_yaml_helper(obj, root);
    return root;
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
            const char* message, uint64_t  /*length*/)
{
    std::cout << "[" << level_to_str(level)
              << "][" << file
              << ":" << function
              << ":" << line
              << "]: " << message
              << '\n';
}

std::string read_file(std::string_view filename)
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

    rule_file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    rule_file.close();
    return buffer;
}

