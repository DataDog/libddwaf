// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2021 Datadog, Inc.

#include "utils.hpp"
#include <iostream>
#include <unistd.h>

using namespace std::literals;

namespace YAML {

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

ddwaf_object as_if<ddwaf_object, void>::operator()() const
{
    ddwaf_object arg;
    node_to_arg(node, &arg);
    return arg;
}
} // namespace YAML

std::string read_file(std::string_view filename)
{
    std::ifstream file(filename.data(), std::ios::in);
    if (!file) {
        throw std::system_error(errno, std::generic_category());
    }

    // Create a buffer equal to the file size
    std::string buffer;
    file.seekg(0, std::ios::end);
    buffer.resize(file.tellg());
    file.seekg(0, std::ios::beg);

    file.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    file.close();
    return buffer;
}

