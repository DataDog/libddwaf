// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <iostream>
#include <map>
#include <unordered_set>

#include "generator/extract_schema.hpp"

namespace ddwaf::generator {
namespace {

template <typename T> bool compare_containers(T &lhs, T &rhs)
{
    if (lhs.size() != rhs.size()) {
        return false;
    }

    for (auto l_it = lhs.begin(), r_it = rhs.begin(); l_it != lhs.end() && r_it != rhs.end();
         ++l_it, ++r_it) {
        if (l_it != r_it) {
            return false;
        }
    }
    return true;
}

enum class schema_node_type { unknown, scalar, array, record };

struct schema_node {
    using ptr = std::unique_ptr<schema_node>;
    explicit schema_node(schema_node_type type_) : type(type_) {}
    schema_node(const schema_node &) = delete;
    schema_node(schema_node &&oth) noexcept = default;
    schema_node &operator=(const schema_node &) = delete;
    schema_node &operator=(schema_node &&oth) noexcept = default;
    virtual ~schema_node() = default;

    [[nodiscard]] virtual std::size_t hash() const = 0;

    schema_node_type type{schema_node_type::unknown};
};

struct node_hash {
    std::size_t operator()(const schema_node::ptr &node) const noexcept
    {
        return node == nullptr ? 0 : node->hash();
    }
};

struct node_equal {
    bool operator()(const schema_node::ptr &lhs, const schema_node::ptr &rhs) const;
};

struct schema_record : schema_node {
    schema_record() : schema_node(schema_node_type::record) {}
    schema_record(const schema_record &) = delete;
    schema_record(schema_record &&oth) noexcept = default;
    schema_record &operator=(const schema_record &) = delete;
    schema_record &operator=(schema_record &&oth) noexcept = default;
    ~schema_record() override = default;

    [[nodiscard]] std::size_t hash() const override
    {
        std::size_t value = 0;
        for (const auto &[key, node] : children) { value ^= node->hash(); }
        return value;
    }

    bool truncated{false};
    std::map<std::string_view, schema_node::ptr> children{};
};

struct schema_array : schema_node {
    schema_array() : schema_node(schema_node_type::array) {}
    schema_array(const schema_array &) = delete;
    schema_array(schema_array &&oth) noexcept = default;
    schema_array &operator=(const schema_array &) = delete;
    schema_array &operator=(schema_array &&oth) noexcept = default;
    ~schema_array() override = default;

    [[nodiscard]] std::size_t hash() const override
    {
        std::size_t value = 0;
        for (const auto &node : children) { value ^= node->hash(); }
        return value;
    }

    bool truncated{false};
    std::size_t length{0};
    std::unordered_set<schema_node::ptr, node_hash, node_equal> children{};
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
    explicit schema_scalar(
        schema_scalar_type type_, std::map<std::string_view, std::string_view> tags_ = {})
        : schema_node(schema_node_type::scalar), type(type_), tags(std::move(tags_))
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

    schema_scalar_type type;
    std::map<std::string_view, std::string_view> tags{};
};

// NOLINTNEXTLINE(misc-no-recursion)
bool node_equal::operator()(const schema_node::ptr &lhs, const schema_node::ptr &rhs) const
{
    if (lhs->type != rhs->type) {
        return false;
    }

    switch (lhs->type) {
    case schema_node_type::array: {
        const auto &rhs_array = dynamic_cast<const schema_array &>(*rhs);
        const auto &lhs_array = dynamic_cast<const schema_array &>(*lhs);

        if (lhs_array.length != rhs_array.length ||
            lhs_array.children.size() != rhs_array.children.size() ||
            lhs_array.truncated != rhs_array.truncated) {
            return false;
        }

        auto lhs_it = lhs_array.children.begin();
        auto lhs_end = lhs_array.children.end();

        auto rhs_it = rhs_array.children.begin();
        auto rhs_end = rhs_array.children.end();

        for (; lhs_it != lhs_end && rhs_it != rhs_end; ++lhs_it, ++rhs_it) {
            if (!operator()(*lhs_it, *rhs_it)) {
                return false;
            }
        }
        return true;
    }
    case schema_node_type::record: {
        const auto &rhs_record = dynamic_cast<const schema_record &>(*rhs);
        const auto &lhs_record = dynamic_cast<const schema_record &>(*lhs);
        return compare_containers(lhs_record.children, rhs_record.children);

        if (lhs_record.children.size() != rhs_record.children.size() ||
            lhs_record.truncated != rhs_record.truncated) {
            return false;
        }

        auto lhs_it = lhs_record.children.begin();
        auto lhs_end = lhs_record.children.end();

        auto rhs_it = rhs_record.children.begin();
        auto rhs_end = rhs_record.children.end();

        for (; lhs_it != lhs_end && rhs_it != rhs_end; ++lhs_it, ++rhs_it) {
            if (rhs_it->first != lhs_it->first) {
                return false;
            }
            if (!operator()(lhs_it->second, rhs_it->second)) {
                return false;
            }
        }
        return true;
    }
    case schema_node_type::scalar: {
        const auto &rhs_scalar = dynamic_cast<const schema_scalar &>(*rhs);
        const auto &lhs_scalar = dynamic_cast<const schema_scalar &>(*lhs);
        return lhs_scalar.type == rhs_scalar.type && lhs_scalar.tags == rhs_scalar.tags;
    }
    case schema_node_type::unknown:
        return true;
    }

    return false;
}

class schema_generator {
public:
    explicit schema_generator(const object_limits &limits) : limits_(limits) {}

    schema_node::ptr generate(const ddwaf_object *object, std::size_t depth);

protected:
    const object_limits &limits_;
};

// NOLINTNEXTLINE(misc-no-recursion)
schema_node::ptr schema_generator::generate(const ddwaf_object *object, std::size_t depth)
{
    if (depth == 0) {
        return nullptr;
    }

    auto length = static_cast<std::size_t>(object->nbEntries);
    switch (object->type) {
    case DDWAF_OBJ_NULL:
        return std::make_unique<schema_scalar>(schema_scalar_type::null);
    case DDWAF_OBJ_FLOAT:
        return std::make_unique<schema_scalar>(schema_scalar_type::real);
    case DDWAF_OBJ_BOOL:
        return std::make_unique<schema_scalar>(schema_scalar_type::boolean);
    case DDWAF_OBJ_STRING:
        return std::make_unique<schema_scalar>(schema_scalar_type::string);
    case DDWAF_OBJ_SIGNED:
    case DDWAF_OBJ_UNSIGNED:
        return std::make_unique<schema_scalar>(schema_scalar_type::integer);
    case DDWAF_OBJ_MAP: {
        auto node = std::make_unique<schema_record>();
        if (length > limits_.max_container_size) {
            node->truncated = true;
            length = limits_.max_container_size;
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
            node->children.emplace(key, std::move(schema));
        }
        return node;
    }
    case DDWAF_OBJ_ARRAY: {
        auto node = std::make_unique<schema_array>();
        node->length = length;
        if (length > limits_.max_container_size) {
            node->truncated = true;
            length = limits_.max_container_size;
        }
        for (std::size_t i = 0; i < length; i++) {
            const auto *child = &object->array[i];
            auto schema = generate(child, depth - 1);
            if (schema == nullptr) {
                continue;
            }
            node->children.emplace(std::move(schema));
        }
        return node;
    }
    case DDWAF_OBJ_INVALID:
        break;
    }

    return std::make_unique<schema_scalar>(schema_scalar_type::unknown);
}

ddwaf_object serialize(const schema_node &node);

ddwaf_object serialize(const schema_scalar &node)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object_array_add(
        &array, ddwaf_object_unsigned(
                    &tmp, static_cast<std::underlying_type<schema_scalar_type>::type>(node.type)));

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
ddwaf_object serialize(const schema_array &node)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object types;
    ddwaf_object_array(&types);

    for (const auto &child : node.children) {
        auto res = serialize(*child);
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
ddwaf_object serialize(const schema_record &node)
{
    ddwaf_object tmp;
    ddwaf_object array;
    ddwaf_object_array(&array);

    ddwaf_object map;
    ddwaf_object_map(&map);
    for (const auto &[key, child] : node.children) {
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

// NOLINTNEXTLINE(misc-no-recursion)
ddwaf_object serialize(const schema_node &node)
{
    switch (node.type) {
    case schema_node_type::scalar:
        return serialize(dynamic_cast<const schema_scalar &>(node));
    case schema_node_type::array:
        return serialize(dynamic_cast<const schema_array &>(node));
    case schema_node_type::record:
        return serialize(dynamic_cast<const schema_record &>(node));
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

    schema_generator gen(limits_);
    std::shared_ptr<schema_node> schema{gen.generate(input, limits_.max_container_depth)};
    if (schema == nullptr) {
        return {};
    }

    return serialize(*schema);
}

} // namespace ddwaf::generator
