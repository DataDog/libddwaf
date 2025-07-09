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
void node_to_ddwaf_object(ddwaf_object *root, const Node &node)
{
    auto *alloc = ddwaf_get_default_allocator();
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object_set_array(root, node.size(), alloc);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto *child = ddwaf_object_insert(root, alloc);
            node_to_ddwaf_object(child, *it);
        }
        return;
    }
    case NodeType::Map: {
        ddwaf_object_set_map(root, node.size(), alloc);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            auto *child = ddwaf_object_insert_key(root, key.data(), key.size(), alloc);
            node_to_ddwaf_object(child, it->second);
        }
        return;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();

        if (node.Tag() == "?") {
            try {
                ddwaf_object_set_unsigned(root, node.as<uint64_t>());
                return;
            } catch (...) {}

            try {
                ddwaf_object_set_signed(root, node.as<int64_t>());
                return;
            } catch (...) {}

            try {
                ddwaf_object_set_float(root, node.as<double>());
                return;
            } catch (...) {}

            try {
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    ddwaf_object_set_bool(root, node.as<bool>());
                    return;
                }
            } catch (...) {}
        }

        ddwaf_object_set_string(root, value.data(), value.size(), alloc);
        return;
    }
    case NodeType::Null: {
        ddwaf_object_set_null(root);
        return;
    }
    case NodeType::Undefined: {
        ddwaf_object_set_invalid(root);
        return;
    }
    }

    throw parsing_error("Invalid YAML node type");
}

} // namespace

ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    ddwaf_object object;
    node_to_ddwaf_object(&object, node);
    return object;
}

// NOLINTNEXTLINE(misc-no-recursion)
YAML::Emitter &operator<<(YAML::Emitter &out, const ddwaf_object &o)
{
    out.SetMapFormat(YAML::Flow);
    out.SetSeqFormat(YAML::Flow);
    out.SetStringFormat(YAML::DoubleQuoted);

    switch (o.type) {
    case DDWAF_OBJ_BOOL:
        out << ddwaf_object_get_bool(&o);
        break;
    case DDWAF_OBJ_SIGNED:
        out << ddwaf_object_get_signed(&o);
        break;
    case DDWAF_OBJ_UNSIGNED:
        out << ddwaf_object_get_unsigned(&o);
        break;
    case DDWAF_OBJ_FLOAT:
        out << ddwaf_object_get_float(&o);
        break;
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_SMALL_STRING:
    case DDWAF_OBJ_LITERAL_STRING:
        out << std::string{ddwaf_object_get_string(&o, nullptr), ddwaf_object_get_length(&o)};
        break;
    case DDWAF_OBJ_ARRAY:
        out << YAML::BeginSeq;
        for (std::size_t i = 0; i < ddwaf_object_get_size(&o); i++) {
            out << *ddwaf_object_at_value(&o, i);
        }
        out << YAML::EndSeq;
        break;
    case DDWAF_OBJ_MAP:
        out << YAML::BeginMap;
        for (std::size_t i = 0; i < ddwaf_object_get_size(&o); i++) {
            out << YAML::Key << *ddwaf_object_at_key(&o, i);
            out << YAML::Value << *ddwaf_object_at_value(&o, i);
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
