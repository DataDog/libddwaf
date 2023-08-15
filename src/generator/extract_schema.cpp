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

#include "generator/extract_schema.hpp"

namespace ddwaf::generator {
namespace schema {

struct node_record;
struct node_array;
struct node_scalar;

using node = std::variant<std::monostate, node_scalar, node_array, node_record>;
using node_ptr = std::unique_ptr<node>;

struct node_hash {
    constexpr std::size_t operator()(const std::monostate & /*node*/) const noexcept
    {
        return 0x9e3779b9;
    }
    std::size_t operator()(const node_scalar &node) const noexcept;
    std::size_t operator()(const node_array &node) const noexcept;
    std::size_t operator()(const node_record &node) const noexcept;
    std::size_t operator()(const node_ptr &node) const noexcept;
};

struct node_equal {
    constexpr bool operator()(const std::monostate & /*lhs*/, const std::monostate & /*rhs*/) const
    {
        return true;
    }
    bool operator()(const node_scalar &lhs, const node_scalar &rhs) const;
    bool operator()(const node_array &lhs, const node_array &rhs) const;
    bool operator()(const node_record &lhs, const node_record &rhs) const;
    template <typename T, typename U>
    constexpr bool operator()(const T & /*lhs*/, const U & /*rhs*/) const
        requires(!std::is_same_v<T, U>)
    {
        return false;
    }
    bool operator()(const node_ptr &lhs, const node_ptr &rhs) const;
};

struct node_record {
    bool truncated{false};
    std::map<std::string_view, node_ptr> children{};
};

struct node_array {
    bool truncated{false};
    std::size_t length{0};
    std::unordered_set<node_ptr, node_hash, node_equal> children{};
};

enum class scalar_type : uint8_t { null = 1, boolean = 2, integer = 4, string = 8, real = 16 };

struct node_scalar {
    scalar_type type{scalar_type::null};
    std::map<std::string_view, std::string_view> tags{};
};

std::size_t node_hash::operator()(const node_ptr &node) const noexcept
{
    return std::visit(node_hash{}, *node);
}

std::size_t node_hash::operator()(const node_scalar &node) const noexcept
{
    using underlying_type = typename std::underlying_type<scalar_type>::type;
    auto value = std::hash<underlying_type>{}(static_cast<underlying_type>(node.type));
    for (const auto &[k, v] : node.tags) {
        value ^= std::hash<std::string_view>{}(k) ^ std::hash<std::string_view>{}(v);
    }
    return value;
}

std::size_t node_hash::operator()(const node_array &node) const noexcept
{
    std::size_t value = std::hash<bool>{}(node.truncated) ^ std::hash<std::size_t>{}(node.length);
    for (const auto &child : node.children) { value ^= std::visit(node_hash{}, *child); }
    return value;
}

std::size_t node_hash::operator()(const node_record &node) const noexcept
{
    std::size_t value = std::hash<bool>{}(node.truncated);
    for (const auto &[key, child] : node.children) {
        value ^= std::hash<std::string_view>{}(key) ^ std::visit(node_hash{}, *child);
    }
    return value;
}

bool node_equal::operator()(const node_scalar &lhs, const node_scalar &rhs) const
{
    return lhs.type == rhs.type && lhs.tags == rhs.tags;
}

bool node_equal::operator()(const node_array &lhs, const node_array &rhs) const
{
    if (lhs.length != rhs.length || lhs.children.size() != rhs.children.size() ||
        lhs.truncated != rhs.truncated) {
        return false;
    }

    // NOLINTNEXTLINE(readability-use-anyofallof)
    for (const auto &node : lhs.children) {
        if (rhs.children.find(node) == rhs.children.end()) {
            return false;
        }
    }
    return true;
}

bool node_equal::operator()(const node_record &lhs, const node_record &rhs) const
{
    if (lhs.children.size() != rhs.children.size() || lhs.truncated != rhs.truncated) {
        return false;
    }

    auto lhs_it = lhs.children.begin();
    auto lhs_end = lhs.children.end();

    auto rhs_it = rhs.children.begin();
    auto rhs_end = rhs.children.end();

    for (; lhs_it != lhs_end && rhs_it != rhs_end; ++lhs_it, ++rhs_it) {
        if (rhs_it->first != lhs_it->first) {
            return false;
        }
        if (!std::visit(node_equal{}, *lhs_it->second, *rhs_it->second)) {
            return false;
        }
    }

    return true;
}

bool node_equal::operator()(const node_ptr &lhs, const node_ptr &rhs) const
{
    return std::visit(node_equal{}, *lhs, *rhs);
}

// NOLINTNEXTLINE(misc-no-recursion)
node_ptr generate(const ddwaf_object *object, std::size_t depth)
{
    if (depth == 0) {
        return nullptr;
    }

    auto length = static_cast<std::size_t>(object->nbEntries);
    switch (object->type) {
    case DDWAF_OBJ_NULL:
        return std::make_unique<node>(node_scalar{scalar_type::null});
    case DDWAF_OBJ_FLOAT:
        return std::make_unique<node>(node_scalar{scalar_type::real});
    case DDWAF_OBJ_BOOL:
        return std::make_unique<node>(node_scalar{scalar_type::boolean});
    case DDWAF_OBJ_STRING:
        return std::make_unique<node>(node_scalar{scalar_type::string});
    case DDWAF_OBJ_SIGNED:
    case DDWAF_OBJ_UNSIGNED:
        return std::make_unique<node>(node_scalar{scalar_type::integer});
    case DDWAF_OBJ_MAP: {
        node_record record{};
        if (length > extract_schema::max_record_nodes) {
            record.truncated = true;
            length = extract_schema::max_record_nodes;
        }
        for (std::size_t i = 0; i < length; i++) {
            const auto *child = &object->array[i];
            if (child->parameterName == nullptr) {
                continue;
            }

            auto schema = generate(child, depth - 1);
            if (schema == nullptr) {
                continue;
            }

            std::string_view key{
                child->parameterName, static_cast<std::size_t>(child->parameterNameLength)};
            record.children.emplace(key, std::move(schema));
        }
        return std::make_unique<node>(std::move(record));
    }
    case DDWAF_OBJ_ARRAY: {
        node_array array{};
        array.length = length;
        if (length > extract_schema::max_array_nodes) {
            array.truncated = true;
            length = extract_schema::max_array_nodes;
        }
        for (std::size_t i = 0; i < length; i++) {
            const auto *child = &object->array[i];
            auto schema = generate(child, depth - 1);
            if (schema == nullptr) {
                continue;
            }
            array.children.emplace(std::move(schema));
        }
        return std::make_unique<node>(std::move(array));
    }
    case DDWAF_OBJ_INVALID:
        break;
    }

    return std::make_unique<node>();
}

struct node_serialize {
    ddwaf_object operator()(const std::monostate & /*node*/) const noexcept;
    ddwaf_object operator()(const node_scalar &node) const noexcept;
    ddwaf_object operator()(const node_array &node) const noexcept;
    ddwaf_object operator()(const node_record &node) const noexcept;
};

ddwaf_object node_serialize::operator()(const std::monostate & /*node*/) const noexcept
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_unsigned(&tmp, 0));
    return array;
}

ddwaf_object node_serialize::operator()(const node_scalar &node) const noexcept
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object_array_add(
        &array, ddwaf_object_unsigned(
                    &tmp, static_cast<std::underlying_type<scalar_type>::type>(node.type)));

    if (!node.tags.empty()) {
        ddwaf_object meta;
        ddwaf_object_map(&meta);

        for (auto [key, value] : node.tags) {
            ddwaf_object_map_addl(&meta, key.data(), key.size(),
                ddwaf_object_stringl(&tmp, value.data(), value.size()));
        }

        ddwaf_object_array_add(&array, &meta);
    }

    return array;
}

// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object node_serialize::operator()(const node_array &node) const noexcept
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object types;
    ddwaf_object_array(&types);

    for (const auto &child : node.children) {
        auto res = std::visit(node_serialize{}, *child);
        ddwaf_object_array_add(&types, &res);
    }
    ddwaf_object_array_add(&array, &types);

    ddwaf_object meta;
    ddwaf_object_map(&meta);
    ddwaf_object_map_add(&meta, "len", ddwaf_object_unsigned(&tmp, node.length));
    if (node.truncated) {
        ddwaf_object_map_add(&meta, "truncated", ddwaf_object_bool(&tmp, true));
    }
    ddwaf_object_array_add(&array, &meta);

    return array;
}

// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object node_serialize::operator()(const node_record &node) const noexcept
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object map;
    ddwaf_object_map(&map);
    for (const auto &[key, child] : node.children) {
        auto res = std::visit(node_serialize{}, *child);
        ddwaf_object_map_addl(&map, key.data(), key.size(), &res);
    }
    ddwaf_object_array_add(&array, &map);

    if (node.truncated) {
        ddwaf_object meta;
        ddwaf_object_map(&meta);
        ddwaf_object_map_add(&meta, "truncated", ddwaf_object_bool(&tmp, true));
        ddwaf_object_array_add(&array, &meta);
    }

    return array;
}

ddwaf_object serialize(const node &root) { return std::visit(node_serialize{}, root); }

} // namespace schema

ddwaf_object extract_schema::generate(const ddwaf_object *input)
{
    if (input == nullptr) {
        return {};
    }

    auto schema = schema::generate(input, max_container_depth);
    if (schema == nullptr) {
        return {};
    }

    return serialize(*schema);
}

} // namespace ddwaf::generator
