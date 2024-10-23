// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/yaml/utils.hpp"
#include "log.hpp"

#include <fstream>

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
ddwaf_object node_to_arg(const Node &node)
{
    switch (node.Type()) {
    case NodeType::Sequence: {
        ddwaf_object arg = DDWAF_OBJECT_ARRAY;
        for (auto it = node.begin(); it != node.end(); ++it) {
            ddwaf_object child = node_to_arg(*it);
            ddwaf_object_array_add(&arg, &child);
        }
        return arg;
    }
    case NodeType::Map: {
        ddwaf_object arg = DDWAF_OBJECT_MAP;
        for (auto it = node.begin(); it != node.end(); ++it) {
            auto key = it->first.as<std::string>();
            ddwaf_object child = node_to_arg(it->second);
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
    case NodeType::Null:
    case NodeType::Undefined:
        ddwaf_object arg = DDWAF_OBJECT_MAP;
        return arg;
    }

    throw parsing_error("Invalid YAML node type");
}

} // namespace

as_if<ddwaf_object, void>::as_if(const Node &node_) : node(node_) {}
ddwaf_object as_if<ddwaf_object, void>::operator()() const { return node_to_arg(node); }

} // namespace YAML

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
ddwaf_object read_file(std::string_view filename, std::string_view base)
{
    std::string base_dir{base};
    if (*base_dir.end() != '/') {
        base_dir += '/';
    }

    auto file_path = base_dir + "yaml/" + std::string{filename};

    DDWAF_DEBUG("Opening {}", file_path.c_str());

    std::ifstream file(file_path.c_str(), std::ios::in);
    if (!file) {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.ignore(std::numeric_limits<std::streamsize>::max());
    std::streamsize length = file.gcount();
    file.clear();
    buffer.resize(length, '\0');
    file.seekg(0, std::ios::beg);

    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    file.close();

    return yaml_to_object(buffer);
}


