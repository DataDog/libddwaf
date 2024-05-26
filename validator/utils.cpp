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
        output = obj.via.b8;
        break;
    case DDWAF_OBJ_SIGNED:
        output = obj.via.i64;
        break;
    case DDWAF_OBJ_UNSIGNED:
        output = obj.via.u64;
        break;
    case DDWAF_OBJ_FLOAT:
        output = obj.via.f64;
        break;
    case DDWAF_OBJ_STRING:
        output = std::string{obj.via.str, obj.length};
        break;
    case DDWAF_OBJ_SMALL_STRING:
        output = std::string{obj.via.sstr, obj.length};
        break;
    case DDWAF_OBJ_CONST_STRING:
        output = std::string{obj.via.cstr, obj.length};
        break;
    case DDWAF_OBJ_MAP:
        output = YAML::Load("{}");
        for (unsigned i = 0; i < obj.size; i++) {
            auto child = obj.via.map[i];
            std::string key{
                ddwaf_object_get_string(&child.key), ddwaf_object_get_length(&child.key)};

            YAML::Node value;
            object_to_yaml_helper(child.val, value);
            output[key] = value;
        }
        break;
    case DDWAF_OBJ_ARRAY:
        output = YAML::Load("[]");
        for (unsigned i = 0; i < obj.size; i++) {
            auto child = obj.via.array[i];

            YAML::Node value;
            object_to_yaml_helper(child, value);
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
