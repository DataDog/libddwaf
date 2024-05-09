// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <variant>

#include "exception.hpp"
#include "generator/extract_schema.hpp"
#include "log.hpp"

namespace ddwaf::generator {
namespace schema {

struct node_record;
struct node_array;

using node_record_ptr = std::unique_ptr<node_record>;
using node_array_ptr = std::unique_ptr<node_array>;

enum class scalar_type : uint8_t { null = 1, boolean = 2, integer = 4, string = 8, real = 16 };

struct node_scalar {
    scalar_type type{scalar_type::null};
    std::unordered_map<std::string, std::string> tags{};
    mutable std::size_t hash{0};
};

using base_node = std::variant<std::monostate, node_scalar, node_array_ptr, node_record_ptr>;

struct node_hash {
    constexpr std::size_t operator()(const std::monostate & /*node*/) const noexcept
    {
        return 0x9e3779b9;
    }
    std::size_t operator()(const node_scalar &node) const noexcept;
    std::size_t operator()(const node_array_ptr &node) const noexcept;
    std::size_t operator()(const node_record_ptr &node) const noexcept;
    std::size_t operator()(const base_node &node) const noexcept;
};

struct node_equal {
    constexpr bool operator()(const std::monostate & /*lhs*/, const std::monostate & /*rhs*/) const
    {
        return true;
    }
    bool operator()(const node_scalar &lhs, const node_scalar &rhs) const;
    bool operator()(const node_array_ptr &lhs, const node_array_ptr &rhs) const;
    bool operator()(const node_record_ptr &lhs, const node_record_ptr &rhs) const;
    template <typename T, typename U>
    constexpr bool operator()(const T & /*lhs*/, const U & /*rhs*/) const
        requires(!std::is_same_v<T, U>)
    {
        return false;
    }
    bool operator()(const base_node &lhs, const base_node &rhs) const;
};

struct node_record {
    std::size_t hash{0};
    bool truncated{false};
    std::unordered_map<std::string_view, base_node> children;
};

struct node_array {
    std::size_t hash{0};
    bool truncated{false};
    std::size_t length{0};
    std::unordered_set<base_node, node_hash, node_equal> children;
};

std::size_t node_hash::operator()(const base_node &node) const noexcept
{
    return std::visit(node_hash{}, node);
}

std::size_t node_hash::operator()(const node_scalar &node) const noexcept
{
    // Accept the risk of collision with the hash value 0
    if (node.hash == 0) {
        using underlying_type = std::underlying_type_t<scalar_type>;
        auto value = std::hash<underlying_type>{}(static_cast<underlying_type>(node.type));
        for (const auto &[k, v] : node.tags) {
            value ^= std::hash<std::string_view>{}(k) ^ std::hash<std::string_view>{}(v);
        }
        node.hash = value;
    }
    return node.hash;
}

std::size_t node_hash::operator()(const node_array_ptr &node) const noexcept
{
    if (node->hash == 0) {
        std::size_t value =
            std::hash<bool>{}(node->truncated) ^ std::hash<std::size_t>{}(node->length);
        for (const auto &child : node->children) { value ^= std::visit(node_hash{}, child); }
        node->hash = value;
    }
    return node->hash;
}

std::size_t node_hash::operator()(const node_record_ptr &node) const noexcept
{
    if (node->hash == 0) {
        std::size_t value = std::hash<bool>{}(node->truncated);
        for (const auto &[key, child] : node->children) {
            value ^= std::hash<std::string_view>{}(key) ^ std::visit(node_hash{}, child);
        }
        node->hash = value;
    }
    return node->hash;
}

bool node_equal::operator()(const node_scalar &lhs, const node_scalar &rhs) const
{
    return lhs.type == rhs.type && lhs.tags == rhs.tags;
}

bool node_equal::operator()(const node_array_ptr &lhs, const node_array_ptr &rhs) const
{
    if (lhs->length != rhs->length || lhs->children.size() != rhs->children.size() ||
        lhs->truncated != rhs->truncated) {
        return false;
    }

    // NOLINTNEXTLINE(readability-use-anyofallof)
    for (const auto &node : lhs->children) {
        if (rhs->children.find(node) == rhs->children.end()) {
            return false;
        }
    }
    return true;
}

bool node_equal::operator()(const node_record_ptr &lhs, const node_record_ptr &rhs) const
{
    if (lhs->children.size() != rhs->children.size() || lhs->truncated != rhs->truncated) {
        return false;
    }

    for (const auto &[k, v] : lhs->children) {
        auto it = rhs->children.find(k);
        if (it == rhs->children.end()) {
            return false;
        }

        if (!std::visit(node_equal{}, v, it->second)) {
            return false;
        }
    }
    return true;
}

bool node_equal::operator()(const base_node &lhs, const base_node &rhs) const
{
    return std::visit(node_equal{}, lhs, rhs);
}

struct node_serialize {
    owned_object operator()(const std::monostate & /*node*/) const noexcept;
    owned_object operator()(const node_scalar &node) const noexcept;
    owned_object operator()(const node_array_ptr &node) const noexcept;
    owned_object operator()(const node_record_ptr &node) const noexcept;
};

owned_object node_serialize::operator()(const std::monostate & /*node*/) const noexcept
{
    static constexpr unsigned unknown_type = 0;

    owned_object array = owned_object::make_array(1);
    array.emplace_back(owned_object::make_unsigned(unknown_type));
    return array;
}

owned_object node_serialize::operator()(const node_scalar &node) const noexcept
{
    auto array = owned_object::make_array(!node.tags.empty() ? 2 : 1);
    array.emplace_back(
        owned_object::make_unsigned(static_cast<std::underlying_type_t<scalar_type>>(node.type)));

    if (!node.tags.empty()) {
        auto meta = array.emplace_back(owned_object::make_map(node.tags.size()));
        for (auto [key, value] : node.tags) { meta.emplace(key, owned_object::make_string(value)); }
    }

    return array;
}

// NOLINTNEXTLINE(misc-no-recursion)
owned_object node_serialize::operator()(const node_array_ptr &node) const noexcept
{
    owned_object array = owned_object::make_array(2);
    auto types = array.emplace_back(owned_object::make_array(node->children.size()));
    for (const auto &child : node->children) {
        types.emplace_back(std::visit(node_serialize{}, child));
    }

    auto meta = array.emplace_back(owned_object::make_map(node->truncated ? 2 : 1));
    meta.emplace("len", owned_object::make_unsigned(node->length));
    if (node->truncated) {
        meta.emplace("truncated", owned_object::make_boolean(true));
    }
    return array;
}

// NOLINTNEXTLINE(misc-no-recursion)
owned_object node_serialize::operator()(const node_record_ptr &node) const noexcept
{
    owned_object array = owned_object::make_array(node->truncated ? 2 : 1);
    auto map = array.emplace_back(owned_object::make_map(node->children.size()));

    for (const auto &[key, child] : node->children) {
        map.emplace(key, std::visit(node_serialize{}, child));
    }

    if (node->truncated) {
        auto meta = array.emplace_back(owned_object::make_map(1));
        meta.emplace("truncated", owned_object::make_boolean(true));
    }

    return array;
}

owned_object serialize(const base_node &node) { return std::visit(node_serialize{}, node); }

// NOLINTNEXTLINE(misc-no-recursion)
base_node generate_helper(object_view object, object_view key,
    const std::set<const scanner *> &scanners, std::size_t depth, ddwaf::timer &deadline)
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    switch (object.type()) {
    case object_type::null:
        return node_scalar{scalar_type::null};
    case object_type::float64:
        return node_scalar{scalar_type::real};
    case object_type::boolean:
        return node_scalar{scalar_type::boolean};
    case object_type::string:
    case object_type::const_string:
    case object_type::small_string:
        for (const auto *scanner : scanners) {
            if (scanner->eval(key, object)) {
                return node_scalar{scalar_type::string, scanner->get_tags()};
            }
        }
        return node_scalar{scalar_type::string};
    case object_type::int64:
    case object_type::uint64:
        return node_scalar{scalar_type::integer};
    case object_type::map: {
        auto size = object.size();
        node_record_ptr record = std::make_unique<node_record>();
        if (size > extract_schema::max_record_nodes) {
            record->truncated = true;
            size = extract_schema::max_record_nodes;
        }
        record->children.reserve(size);
        for (std::size_t i = 0; i < size && depth > 1; i++) {
            auto [child_key, child_value] = object.at_unchecked(i);
            auto schema = generate_helper(child_value, child_key, scanners, depth - 1, deadline);
            record->children.emplace(key, std::move(schema));
        }
        return record;
    }
    case object_type::array: {
        auto size = object.size();
        node_array_ptr array = std::make_unique<node_array>();
        array->length = size;
        if (size > extract_schema::max_array_nodes) {
            array->truncated = true;
            size = extract_schema::max_array_nodes;
        }
        array->children.reserve(size);
        for (std::size_t i = 0; i < size && depth > 1; i++) {
            auto [_, child_value] = object.at_unchecked(i);
            auto schema = generate_helper(child_value, key, scanners, depth - 1, deadline);
            array->children.emplace(std::move(schema));
        }
        return array;
    }
    case object_type::invalid:
    default:
        break;
    }
    return {};
}

owned_object generate(
    object_view object, const std::set<const scanner *> &scanners, ddwaf::timer &deadline)
{
    return serialize(
        generate_helper(object, {}, scanners, extract_schema::max_container_depth, deadline));
}

} // namespace schema

owned_object extract_schema::generate(
    object_view input, const std::set<const scanner *> &scanners, ddwaf::timer &deadline)
{
    if (input == nullptr) {
        return {};
    }

    return schema::generate(input, scanners, deadline);
}

} // namespace ddwaf::generator
