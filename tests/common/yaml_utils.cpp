// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/yaml_utils.hpp"
#include "common/ddwaf_object_da.hpp"
#include "ddwaf.h"
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

// NOLINTNEXTLINE(misc-no-recursion)
owned_object node_to_owned_object(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        auto parent = test::ddwaf_object_da::make_array();
        for (auto it = node.begin(); it != node.end(); ++it) {
            parent.emplace_back(node_to_owned_object(*it));
        }
        return parent;
    }
    case NodeType::Map: {
        auto parent = test::ddwaf_object_da::make_map();
        for (auto it = node.begin(); it != node.end(); ++it) {
            parent.emplace(it->first.as<std::string>(), node_to_owned_object(it->second));
        }
        return parent;
    }
    case NodeType::Scalar: {
        const std::string &value = node.Scalar();
        if (node.Tag() == "?") {
            try {
                return test::ddwaf_object_da::make_unsigned(node.as<uint64_t>());
            } catch (...) {} // NOLINT(bugprone-empty-catch)

            try {
                return test::ddwaf_object_da::make_signed(node.as<int64_t>());
            } catch (...) {} // NOLINT(bugprone-empty-catch)

            try {
                return test::ddwaf_object_da::make_float(node.as<double>());
            } catch (...) {} // NOLINT(bugprone-empty-catch)

            try {
                if (!value.empty() && value[0] != 'Y' && value[0] != 'y' && value[0] != 'n' &&
                    value[0] != 'N') {
                    // Skip the yes / no variants of boolean
                    return test::ddwaf_object_da::make_boolean(node.as<bool>());
                }
            } catch (...) {} // NOLINT(bugprone-empty-catch)
        }

        return test::ddwaf_object_da::make_string(value);
    }
    case NodeType::Null:
        return owned_object::make_null();
    case NodeType::Undefined:
        return owned_object{};
    }

    throw parsing_error("Invalid YAML node type");
}
} // namespace

as_if<ddwaf_object, void>::as_if(const Node &node_) : node(node_) {}
ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    ddwaf_object object;
    node_to_ddwaf_object(&object, node);
    return object;
}

as_if<owned_object, void>::as_if(const Node &node_) : node(node_) {}
owned_object as_if<owned_object, void>::operator()() const { return node_to_owned_object(node); }

} // namespace YAML
