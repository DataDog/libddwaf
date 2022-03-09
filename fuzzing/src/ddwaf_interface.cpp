// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf_interface.hpp"
#include "helpers.hpp"
#include <cstdlib>
#include <ddwaf.h>
#include <stdexcept>
#include <yaml-cpp/yaml.h>

#define DDWAF_OBJECT_INVALID                    \
    {                                           \
        NULL, 0, { NULL }, 0, DDWAF_OBJ_INVALID \
    }
#define DDWAF_OBJECT_MAP                    \
    {                                       \
        NULL, 0, { NULL }, 0, DDWAF_OBJ_MAP \
    }
#define DDWAF_OBJECT_ARRAY                    \
    {                                         \
        NULL, 0, { NULL }, 0, DDWAF_OBJ_ARRAY \
    }
#define DDWAF_OBJECT_SIGNED_FORCE(value)                      \
    {                                                         \
        NULL, 0, { (const char*) value }, 0, DDWAF_OBJ_SIGNED \
    }
#define DDWAF_OBJECT_UNSIGNED_FORCE(value)                      \
    {                                                           \
        NULL, 0, { (const char*) value }, 0, DDWAF_OBJ_UNSIGNED \
    }
#define DDWAF_OBJECT_STRING_PTR(string, length)       \
    {                                                 \
        NULL, 0, { string }, length, DDWAF_OBJ_STRING \
    }

namespace YAML
{

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() const noexcept { return what_.c_str(); }

protected:
    const std::string what_;
};

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
        {
            ddwaf_object arg;
            ddwaf_object_invalid(&arg);
            return arg;
        }
    }

    throw parsing_error("Invalid YAML node type");
}

template <>
as_if<ddwaf_object, void>::as_if(const Node& node_) : node(node_) {}

template <>
ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    return node_to_arg(node);
}
}

ddwaf_object file_to_object(const char* filename)
{
    size_t size;
    const char* ruleset = read_file_content(filename, &size);
    // return will not be NULL
    YAML::Node doc = YAML::Load(ruleset);

    ddwaf_object object = doc.as<ddwaf_object>();

    free((void*) ruleset);

    return object;
}

ddwaf_handle init_waf()
{
    ddwaf_object rule   = file_to_object("sample_rules.yml");
    ddwaf_handle handle = ddwaf_init(&rule, NULL, NULL);
    ddwaf_object_free(&rule);
    return handle;
}

void run_waf(ddwaf_handle handle, ddwaf_object args, size_t timeLeftInUs)
{
    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    if (context == NULL)
    {
        __builtin_trap();
    }

    ddwaf_result res;
    auto code = ddwaf_run(context, &args, nullptr, &res, timeLeftInUs);

    // TODO split input in several ddwaf_object, and call ddwaf_run on the same context

    if (code == DDWAF_ERR_INTERNAL)
    {
        __builtin_trap();
    }

    ddwaf_result_free(&res);
    ddwaf_context_destroy(context);
}
