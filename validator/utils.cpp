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

ddwaf_object as_if<ddwaf_object, void>::operator()() const { return node_to_arg(node); }

std::set<std::string> as_if<std::set<std::string>, void>::operator()() const
{

    if (node.Type() != NodeType::Sequence) {
        throw parsing_error("Invalid node type, expected sequence");
    }

    std::set<std::string> set;
    for (auto it = node.begin(); it != node.end(); ++it) { set.emplace(it->as<std::string>()); }

    return set;
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

namespace term {

bool has_colour() { return isatty(fileno(stdout)) != 0; }

} // namespace term

std::ostream &operator<<(std::ostream &os, term::colour c)
{
    // Attempt to verify if ostream is cout
    if (os.rdbuf() != std::cout.rdbuf() || !term::has_colour()) {
        return os;
    }

    os << "\033[" << static_cast<std::underlying_type<term::colour>::type>(c) << "m";
    return os;
}

std::ostream &operator<<(std::ostream &os, const std::set<std::string> &set)
{
    os << "[";
    for (const auto &str : set) {
        os << str;
        if (str != *set.rbegin()) {
            os << ", ";
        }
    }
    os << "]";
    return os;
}

// NOLINTNEXTLINE(misc-no-recursion)
void object_to_yaml_helper(const ddwaf_object &obj, YAML::Node &output)
{
    switch (obj.type) {
    case DDWAF_OBJ_BOOL:
        output = ddwaf_object_get_bool(&obj);
        break;
    case DDWAF_OBJ_SIGNED:
        output = ddwaf_object_get_signed(&obj);
        break;
    case DDWAF_OBJ_UNSIGNED:
        output = ddwaf_object_get_unsigned(&obj);
        break;
    case DDWAF_OBJ_FLOAT:
        output = ddwaf_object_get_float(&obj);
        break;
    case DDWAF_OBJ_STRING:
    case DDWAF_OBJ_SMALL_STRING:
    case DDWAF_OBJ_LARGE_STRING:
    case DDWAF_OBJ_CONST_STRING:
        output = std::string{ddwaf_object_get_string(&obj, nullptr), ddwaf_object_length(&obj)};
        break;
    case DDWAF_OBJ_MAP:
        output = YAML::Load("{}");
        for (unsigned i = 0; i < obj.via.map.size; i++) {
            const auto *child_key = ddwaf_object_at_key(&obj, i);
            std::string key{
                ddwaf_object_get_string(child_key, nullptr), ddwaf_object_length(child_key)};

            YAML::Node value;
            object_to_yaml_helper(*ddwaf_object_at_value(&obj, i), value);
            output[key] = value;
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output = YAML::Load("[]");
        for (unsigned i = 0; i < obj.via.array.size; i++) {
            const auto *child = ddwaf_object_at_value(&obj, i);

            YAML::Node value;
            object_to_yaml_helper(*child, value);
            output.push_back(value);
        }
        break;
    case DDWAF_OBJ_INVALID:
    case DDWAF_OBJ_NULL:
        output = YAML::Null;
    };
}

YAML::Node object_to_yaml(const ddwaf_object &obj)
{
    YAML::Node root;
    object_to_yaml_helper(obj, root);
    return root;
}
