// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include "yaml_helpers.hpp"

namespace YAML
{

namespace 
{
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
            ddwaf_object_array(&arg);
            //ddwaf_object_invalid(&arg);
            return arg;
    }

    throw parsing_error("Invalid YAML node type");
}
}

ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    return node_to_arg(node);
}

YAML::Emitter& operator << (YAML::Emitter& out, const ddwaf_object& o)
{
    out.SetMapFormat(YAML::Flow);
    out.SetSeqFormat(YAML::Flow);
    out.SetStringFormat(YAML::DoubleQuoted);

    switch (o.type) {
    case DDWAF_OBJ_SIGNED:
        out << o.intValue;
        break;
    case DDWAF_OBJ_UNSIGNED:
        out << o.uintValue;
        break;
    case DDWAF_OBJ_STRING:
        out << o.stringValue;
        break;
    case DDWAF_OBJ_ARRAY:
        out << YAML::BeginSeq;
        for (decltype(o.nbEntries) i = 0; i < o.nbEntries; i++) {
            out << o.array[i];
        }
        out << YAML::EndSeq;
        break;
    case DDWAF_OBJ_MAP:
        out << YAML::BeginMap;
        for (decltype(o.nbEntries) i = 0; i < o.nbEntries; i++) {
            out << YAML::Key << o.array[i].parameterName;
            out << YAML::Value << o.array[i];
        }
        out << YAML::EndMap;
        break;
    }

    return out;
}

}
