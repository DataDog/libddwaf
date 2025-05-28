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
ddwaf_object node_to_arg(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object arg{};
        ddwaf_object_array(&arg);
        for (auto it = node.begin(); it != node.end(); ++it) {
            ddwaf_object child = node_to_arg(*it);
            ddwaf_object_array_add(&arg, &child);
        }
        return arg;
    }
    case NodeType::Map: {
        ddwaf_object arg{};
        ddwaf_object_map(&arg);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            ddwaf_object child = node_to_arg(it->second);
            ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
        }
        return arg;
    }
    case NodeType::Scalar: {
        ddwaf_object arg{};
        if (node.Tag() == "?") {
            try {
                ddwaf_object_unsigned(&arg, node.as<uint64_t>());
                return arg;
            } catch (...) {}

            try {
                ddwaf_object_signed(&arg, node.as<int64_t>());
                return arg;
            } catch (...) {}

            try {
                ddwaf_object_float(&arg, node.as<double>());
                return arg;
            } catch (...) {}

            try {
                ddwaf_object_bool(&arg, node.as<bool>());
                return arg;
            } catch (...) {}
        }

        const std::string &value = node.Scalar();
        ddwaf_object_stringl(&arg, value.c_str(), value.size());
        return arg;
    }
    case NodeType::Null:
    case NodeType::Undefined:
        ddwaf_object arg{};
        ddwaf_object_invalid(&arg);
        return arg;
    }

    throw parsing_error("Invalid YAML node type");
}
} // namespace

ddwaf_object as_if<ddwaf_object, void>::operator()() const { return node_to_arg(node); }

// NOLINTNEXTLINE(misc-no-recursion)
YAML::Emitter &operator<<(YAML::Emitter &out, const ddwaf_object &o)
{
    out.SetMapFormat(YAML::Flow);
    out.SetSeqFormat(YAML::Flow);
    out.SetStringFormat(YAML::DoubleQuoted);

    switch (o.type) {
    case DDWAF_OBJ_BOOL:
        out << o.via.b8.val;
        break;
    case DDWAF_OBJ_SIGNED:
        out << o.via.i64.val;
        break;
    case DDWAF_OBJ_UNSIGNED:
        out << o.via.u64.val;
        break;
    case DDWAF_OBJ_FLOAT:
        out << o.via.f64.val;
        break;
    case DDWAF_OBJ_STRING:
        out << std::string{o.via.str.ptr, o.via.str.size};
        break;
    case DDWAF_OBJ_ARRAY:
        out << YAML::BeginSeq;
        for (decltype(o.via.array.size) i = 0; i < o.via.array.size; i++) {
            out << o.via.array.ptr[i];
        }
        out << YAML::EndSeq;
        break;
    case DDWAF_OBJ_MAP:
        out << YAML::BeginMap;
        for (decltype(o.via.map.size) i = 0; i < o.via.map.size; i++) {
            auto kv = o.via.map.ptr[i];
            out << YAML::Key << std::string{kv.key.via.str.ptr, kv.key.via.str.size};
            out << YAML::Value << kv.val;
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
