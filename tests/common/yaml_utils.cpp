// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/yaml_utils.hpp"
#include "log.hpp"

#include <fstream>

using namespace ddwaf;

namespace YAML {

template <class T> T as(const YAML::Node &node, const std::string &key)
{
    auto value = node[key];
    if (!value) {
        return {};
    }

    try {
        return value.as<T>();
    } catch (...) {
        throw parsing_error("failed to parse " + key);
    }
}

template <class T> T as(const YAML::Node &node, unsigned key)
{
    auto value = node[key];
    if (!value) {
        return {};
    }

    try {
        return value.as<T>();
    } catch (...) {
        throw parsing_error("failed to parse " + std::to_string(key));
    }
}

namespace {

// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object node_to_ddwaf_object(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object arg;
        ddwaf_object_array(&arg);
        for (auto it = node.begin(); it != node.end(); ++it) {
            ddwaf_object child = node_to_ddwaf_object(*it);
            ddwaf_object_array_add(&arg, &child);
        }
        return arg;
    }
    case NodeType::Map: {
        ddwaf_object arg;
        ddwaf_object_map(&arg);
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            ddwaf_object child = node_to_ddwaf_object(it->second);
            ddwaf_object_map_addl(&arg, key.c_str(), key.size(), &child);
        }
        return arg;
    }
    case NodeType::Scalar: {
        ddwaf_object arg;
        const std::string &value = node.Scalar();

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
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    ddwaf_object_bool(&arg, node.as<bool>());
                    return arg;
                }
            } catch (...) {}
        }

        ddwaf_object_stringl(&arg, value.c_str(), value.size());
        return arg;
    }
    case NodeType::Null: {
        ddwaf_object arg;
        ddwaf_object_null(&arg);
        return arg;
    }
    case NodeType::Undefined: {
        ddwaf_object arg;
        ddwaf_object_invalid(&arg);
        return arg;
    }
    }

    throw parsing_error("Invalid YAML node type");
}

// NOLINTNEXTLINE(misc-no-recursion)
owned_object node_to_owned_object(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        auto parent = owned_object::make_array();
        for (auto it = node.begin(); it != node.end(); ++it) {
            parent.emplace_back(node_to_owned_object(*it));
        }
        return parent;
    }
    case NodeType::Map: {
        auto parent = owned_object::make_map();
        for (auto it = node.begin(); it != node.end(); ++it) {
            parent.emplace(it->first.as<std::string>(), node_to_owned_object(it->second));
        }
        return parent;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();
        if (node.Tag() == "?") {
            try {
                return owned_object{node.as<uint64_t>()};
            } catch (...) {} // NOLINT(bugprone-empty-catch)

            try {
                return owned_object{node.as<int64_t>()};
            } catch (...) {} // NOLINT(bugprone-empty-catch)

            try {
                return owned_object{node.as<double>()};
            } catch (...) {} // NOLINT(bugprone-empty-catch)

            try {
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    return owned_object{node.as<bool>()};
                }
            } catch (...) {} // NOLINT(bugprone-empty-catch)
        }

        return owned_object{value};
    }
    case NodeType::Null:
        return owned_object::make_null();
    case NodeType::Undefined:
        return {};
    }

    throw parsing_error("Invalid YAML node type");
}
} // namespace

as_if<ddwaf_object, void>::as_if(const Node &node_) : node(node_) {}
ddwaf_object as_if<ddwaf_object, void>::operator()() const { return node_to_ddwaf_object(node); }

as_if<owned_object, void>::as_if(const Node &node_) : node(node_) {}
owned_object as_if<owned_object, void>::operator()() const { return node_to_owned_object(node); }

} // namespace YAML
