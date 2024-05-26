// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "yaml_helpers.hpp"
#include <yaml-cpp/null.h>

namespace YAML {

namespace {

// NOLINTNEXTLINE(misc-no-recursion)
void node_to_arg(const Node &node, ddwaf_object *arg)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object_set_array(arg, node.size(), nullptr);
        for (auto it = node.begin(); it != node.end(); ++it) {
            ddwaf_object *child = ddwaf_object_insert(arg);
            node_to_arg(*it, child);
        }
        break;
    }
    case NodeType::Map: {
        ddwaf_object_set_map(arg, node.size(), nullptr);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            auto *child = ddwaf_object_insert_key(arg, key.c_str(), key.size(), nullptr);
            node_to_arg(it->second, child);
        }
        break;
    }
    case NodeType::Scalar: {
        if (node.Tag() == "?") {
            try {
                ddwaf_object_set_unsigned(arg, node.as<uint64_t>());
                break;
            } catch (...) {}

            try {
                ddwaf_object_set_signed(arg, node.as<int64_t>());
                break;
            } catch (...) {}

            try {
                ddwaf_object_set_float(arg, node.as<double>());
                break;
            } catch (...) {}

            try {
                ddwaf_object_set_bool(arg, node.as<bool>());
                break;
            } catch (...) {}
        }

        const std::string &value = node.Scalar();
        ddwaf_object_set_string(arg, value.c_str(), value.size(), nullptr);
        break;
    }
    case NodeType::Null:
        ddwaf_object_set_null(arg);
        break;
    case NodeType::Undefined:
        ddwaf_object_set_invalid(arg);
        break;
    default:
        throw parsing_error("Invalid YAML node type");
    }
}

} // namespace

ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    ddwaf_object arg;
    node_to_arg(node, &arg);
    return arg;
}

// NOLINTNEXTLINE(misc-no-recursion)
YAML::Emitter &operator<<(YAML::Emitter &out, const ddwaf_object &o)
{
    out.SetMapFormat(YAML::Flow);
    out.SetSeqFormat(YAML::Flow);
    out.SetStringFormat(YAML::DoubleQuoted);

    switch (o.type) {
    case DDWAF_OBJ_BOOL:
        out << o.via.b8;
        break;
    case DDWAF_OBJ_SIGNED:
        out << o.via.i64;
        break;
    case DDWAF_OBJ_UNSIGNED:
        out << o.via.u64;
        break;
    case DDWAF_OBJ_FLOAT:
        out << o.via.f64;
        break;
    case DDWAF_OBJ_STRING:
        out << o.via.str;
        break;
    case DDWAF_OBJ_CONST_STRING:
        out << o.via.cstr;
        break;
    case DDWAF_OBJ_SMALL_STRING:
        out << o.via.sstr;
        break;
    case DDWAF_OBJ_ARRAY:
        out << YAML::BeginSeq;
        for (decltype(o.size) i = 0; i < o.size; i++) { out << o.via.array[i]; }
        out << YAML::EndSeq;
        break;
    case DDWAF_OBJ_MAP:
        out << YAML::BeginMap;
        for (decltype(o.size) i = 0; i < o.size; i++) {
            out << YAML::Key << o.via.map[i].key;
            out << YAML::Value << o.via.map[i].val;
            ;
        }
        out << YAML::EndMap;
        break;
    case DDWAF_OBJ_INVALID:
    case DDWAF_OBJ_NULL:
        out << YAML::Null;
        break;
    }

    return out;
}

} // namespace YAML
