// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "config.hpp"
#include "ddwaf.h"
#include <iostream>
#include <map>
#include <unordered_set>

#include <generator/extract_schema.hpp>
#include <utils.hpp>

namespace ddwaf::generator {
namespace {

enum class schema_node_type { unknown, scalar, array, record };

struct schema_node {
    explicit schema_node(schema_node_type type_) : type(type_) {}
    schema_node(const schema_node &) = delete;
    schema_node(schema_node &&oth) noexcept = default;
    schema_node &operator=(const schema_node &) = delete;
    schema_node &operator=(schema_node &&oth) noexcept = default;
    virtual ~schema_node() = default;

    [[nodiscard]] virtual std::size_t hash() const = 0;

    schema_node_type type{schema_node_type::unknown};
};

struct schema_record : schema_node {
    schema_record() : schema_node(schema_node_type::record) {}
    schema_record(const schema_record &) = delete;
    schema_record(schema_record &&oth) noexcept = default;
    schema_record &operator=(const schema_record &) = delete;
    schema_record &operator=(schema_record &&oth) noexcept = default;
    ~schema_record() override
    {
        for (auto [key, node] : children) { delete node; }
    }

    [[nodiscard]] std::size_t hash() const override
    {
        std::size_t value = 0;
        for (auto [key, node] : children) { value ^= node->hash(); }
        return value;
    }

    bool truncated{false};
    std::map<std::string_view, schema_node *> children{};
};

struct schema_array : schema_node {
    schema_array() : schema_node(schema_node_type::array) {}
    schema_array(const schema_array &) = delete;
    schema_array(schema_array &&oth) noexcept = default;
    schema_array &operator=(const schema_array &) = delete;
    schema_array &operator=(schema_array &&oth) noexcept = default;
    ~schema_array() override
    {
        for (auto *node : children) { delete node; }
    }

    [[nodiscard]] std::size_t hash() const override
    {
        std::size_t value = 0;
        for (auto *node : children) { value ^= node->hash(); }
        return value;
    }

    bool truncated{false};
    std::size_t length{0};
    std::vector<schema_node *> children{};
};

enum class schema_scalar_type : uint8_t {
    unknown = 0,
    null = 1,
    boolean = 2,
    integer = 4,
    string = 8,
    real = 16
};

struct schema_scalar : schema_node {
    schema_scalar(schema_scalar_type type_, std::string_view class_)
        : schema_node(schema_node_type::scalar), scalar_type(type_), value_class(class_)
    {}
    schema_scalar(const schema_scalar &) = delete;
    schema_scalar(schema_scalar &&oth) noexcept = default;
    schema_scalar &operator=(const schema_scalar &) = delete;
    schema_scalar &operator=(schema_scalar &&oth) noexcept = default;
    ~schema_scalar() override = default;

    [[nodiscard]] std::size_t hash() const override
    {
        using underlying_type = typename std::underlying_type<schema_scalar_type>::type;
        return std::hash<underlying_type>{}(static_cast<underlying_type>(type));
    }

    schema_scalar_type scalar_type;
    std::string_view value_class{};
};

struct node_hash {
    std::size_t operator()(const schema_node *node) const noexcept
    {
        if (node == nullptr) {
            return 0;
        }
        return node->hash();
    }
};

struct node_equal {
    constexpr bool operator()(const schema_node *lhs, const schema_node *rhs) const
    {
        if (lhs->type != rhs->type) {
            return false;
        }

        switch (lhs->type) {
        case schema_node_type::array:
        case schema_node_type::record:
            break;
        case schema_node_type::scalar: {
            const auto *rhs_scalar = dynamic_cast<const schema_scalar *>(rhs);
            const auto *lhs_scalar = dynamic_cast<const schema_scalar *>(lhs);
            return rhs_scalar->scalar_type == lhs_scalar->scalar_type;
        }
        case schema_node_type::unknown:
            return rhs->type == schema_node_type::unknown;
        }

        return false;
    }
};

schema_node *compute_schema(const ddwaf_object *object, object_limits &limits)
{
    switch (object->type) {
    case DDWAF_OBJ_BOOL:
        return new schema_scalar{schema_scalar_type::boolean, {}};
    case DDWAF_OBJ_STRING:
        // TODO: Infer type
        return new schema_scalar{schema_scalar_type::string, {}};
    case DDWAF_OBJ_SIGNED:
    case DDWAF_OBJ_UNSIGNED:
        return new schema_scalar{schema_scalar_type::integer, {}};
    case DDWAF_OBJ_MAP: {
        auto *node = new schema_record{};
        auto length = static_cast<std::size_t>(object->nbEntries);
        if (length > limits.max_container_size) {
            node->truncated = true;
            length = limits.max_container_size;
        }
        for (std::size_t i = 0; i < length; i++) {
            const auto *child = &object->array[i];
            std::string_view key{child->parameterName, child->parameterNameLength};
            node->children.emplace(key, compute_schema(child, limits));
        }
        return node;
    }
    case DDWAF_OBJ_ARRAY: {
        std::unordered_set<schema_node *, node_hash, node_equal> subtypes;
        auto *node = new schema_array{};
        node->length = object->nbEntries;
        auto length = static_cast<std::size_t>(object->nbEntries);
        if (length > limits.max_container_size) {
            node->truncated = true;
            length = limits.max_container_size;
        }
        for (std::size_t i = 0; i < length; i++) {
            const auto *child = &object->array[i];
            auto *schema = compute_schema(child, limits);
            auto [it, res] = subtypes.emplace(schema);
            if (res) {
                node->children.emplace_back(schema);
            } else {
                delete schema;
            }
        }
        return node;
    }
    case DDWAF_OBJ_INVALID:
        break;
    }

    return new schema_scalar{schema_scalar_type::unknown, {}};
}

ddwaf_object serialize(schema_node &node);

ddwaf_object serialize(schema_scalar &node)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object_array_add(
        &array, ddwaf_object_unsigned_force(&tmp,
                    static_cast<std::underlying_type<schema_scalar_type>::type>(node.scalar_type)));

    if (!node.value_class.empty()) {
        ddwaf_object meta;
        ddwaf_object_map(&meta);
        ddwaf_object_map_add(&meta, "class",
            ddwaf_object_stringl(&tmp, node.value_class.data(), node.value_class.size()));
        ddwaf_object_array_add(&array, &meta);
    }

    return array;
}

ddwaf_object serialize(schema_array &node)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object types;
    ddwaf_object_array(&types);

    for (auto *child : node.children) {
        auto res = serialize(*child);
        ddwaf_object_array_add(&types, &res);
    }
    ddwaf_object_array_add(&array, &types);

    ddwaf_object meta;
    ddwaf_object_map(&meta);
    ddwaf_object_map_add(&meta, "len", ddwaf_object_unsigned_force(&tmp, node.length));
    if (node.truncated) {
        ddwaf_object_map_add(&meta, "truncated", ddwaf_object_bool(&tmp, true));
    }
    ddwaf_object_array_add(&array, &meta);

    return array;
}

ddwaf_object serialize(schema_record &node)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object map;
    ddwaf_object_map(&map);
    for (auto [key, child] : node.children) {
        auto res = serialize(*child);
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

ddwaf_object serialize(schema_node &node)
{
    switch (node.type) {
    case schema_node_type::scalar:
        return serialize(dynamic_cast<schema_scalar &>(node));
    case schema_node_type::array:
        return serialize(dynamic_cast<schema_array &>(node));
    case schema_node_type::record:
        return serialize(dynamic_cast<schema_record &>(node));
    default:
        break;
    }

    return {};
}

} // namespace

ddwaf_object extract_schema::generate(const ddwaf_object *input)
{
    if (input == nullptr) {
        return {};
    }

    object_limits limits;
    std::shared_ptr<schema_node> schema{compute_schema(input, limits)};
    if (schema == nullptr) {
        return {};
    }

    return serialize(*schema);
}

} // namespace ddwaf::generator
