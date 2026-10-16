// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <memory_resource>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>

#include "arena_resource.hpp"
#include "argument_retriever.hpp"
#include "clock.hpp"
#include "exception.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "object_type.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "processor/extract_schema.hpp"
#include "scanner.hpp"

namespace ddwaf {
namespace schema {

// The schema tree is a temporary built and serialised within a single
// evaluation, so all of its nodes and containers are allocated from an arena
// local to that evaluation and released at once, without running destructors.
// Records and arrays are therefore referred to by plain pointers.
struct node_record;
struct node_array;

using node_record_ptr = node_record *;
using node_array_ptr = node_array *;
using node_allocator = std::pmr::polymorphic_allocator<>;
using scanner_tags = std::unordered_map<std::string, std::string>;

enum class scalar_type : uint8_t { null = 1, boolean = 2, integer = 4, string = 8, real = 16 };

struct node_scalar {
    scalar_type type{scalar_type::null};
    // Owned by the processor (see extract_schema::scanner_entry)
    const scanner_tags *tags{nullptr};
    mutable std::size_t hash{0};

    [[nodiscard]] bool has_tags() const { return tags != nullptr && !tags->empty(); }
};

using base_node = std::variant<std::monostate, node_scalar, node_array_ptr, node_record_ptr>;

struct node_hash {
    constexpr std::size_t operator()(const std::monostate & /*node*/) const { return 0x9e3779b9; }
    std::size_t operator()(const node_scalar &node) const;
    std::size_t operator()(const node_array_ptr &node) const;
    std::size_t operator()(const node_record_ptr &node) const;
    std::size_t operator()(const base_node &node) const;
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
    explicit node_record(node_allocator alloc) : children(alloc) {}

    std::size_t hash{0};
    bool truncated{false};
    std::pmr::unordered_map<std::string_view, base_node> children;
};

struct node_array {
    explicit node_array(node_allocator alloc) : children(alloc) {}

    std::size_t hash{0};
    bool truncated{false};
    std::size_t length{0};
    std::pmr::unordered_set<base_node, node_hash, node_equal> children;
};

std::size_t node_hash::operator()(const base_node &node) const
{
    return std::visit(node_hash{}, node);
}

std::size_t node_hash::operator()(const node_scalar &node) const
{
    // Accept the risk of collision with the hash value 0
    if (node.hash == 0) {
        using underlying_type = std::underlying_type_t<scalar_type>;
        auto value = std::hash<underlying_type>{}(static_cast<underlying_type>(node.type));
        if (node.tags != nullptr) {
            for (const auto &[k, v] : *node.tags) {
                value ^= std::hash<std::string_view>{}(k) ^ std::hash<std::string_view>{}(v);
            }
        }
        node.hash = value;
    }
    return node.hash;
}

// NOLINTNEXTLINE(misc-no-recursion)
std::size_t node_hash::operator()(const node_array_ptr &node) const
{
    if (node->hash == 0) {
        std::size_t value =
            std::hash<bool>{}(node->truncated) ^ std::hash<std::size_t>{}(node->length);

        // NOLINTNEXTLINE(misc-no-recursion)
        for (const auto &child : node->children) { value ^= std::visit(node_hash{}, child); }
        node->hash = value;
    }
    return node->hash;
}

// NOLINTNEXTLINE(misc-no-recursion)
std::size_t node_hash::operator()(const node_record_ptr &node) const
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
    if (lhs.type != rhs.type) {
        return false;
    }

    if (!lhs.has_tags() || !rhs.has_tags()) {
        return lhs.has_tags() == rhs.has_tags();
    }

    return lhs.tags == rhs.tags || *lhs.tags == *rhs.tags;
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
    owned_object operator()(const std::monostate & /*node*/) const;
    owned_object operator()(const node_scalar &node) const;
    owned_object operator()(const node_array_ptr &node) const;
    owned_object operator()(const node_record_ptr &node) const;

    nonnull_ptr<memory::memory_resource> alloc{memory::get_default_resource()};
};

owned_object node_serialize::operator()(const std::monostate & /*node*/) const
{
    static constexpr unsigned unknown_type = 0;

    auto array = owned_object::make_array(1, alloc);
    array.emplace_back(unknown_type);

    return array;
}

owned_object node_serialize::operator()(const node_scalar &node) const
{
    auto array = owned_object::make_array(node.has_tags() ? 2 : 1, alloc);
    array.emplace_back(static_cast<std::underlying_type_t<scalar_type>>(node.type));

    if (node.has_tags()) {
        auto meta = array.emplace_back(owned_object::make_map(node.tags->size(), alloc));
        for (const auto &[key, value] : *node.tags) { meta.emplace(key, value); }
    }

    return array;
}

// NOLINTNEXTLINE(misc-no-recursion)
owned_object node_serialize::operator()(const node_array_ptr &node) const
{
    auto array = owned_object::make_array(2, alloc);
    auto types = array.emplace_back(owned_object::make_array(node->children.size(), alloc));

    for (const auto &child : node->children) {
        auto res = std::visit(node_serialize{alloc}, child);
        types.emplace_back(std::move(res));
    }

    if (node->truncated) {
        array.emplace_back(object_builder::map(
            {{"len", static_cast<uint64_t>(node->length)}, {"truncated", true}}, alloc));
    } else {
        array.emplace_back(
            object_builder::map({{"len", static_cast<uint64_t>(node->length)}}, alloc));
    }

    return array;
}

// NOLINTNEXTLINE(misc-no-recursion)
owned_object node_serialize::operator()(const node_record_ptr &node) const
{
    owned_object array = owned_object::make_array(2, alloc);

    auto map = array.emplace_back(owned_object::make_map(node->children.size(), alloc));
    for (const auto &[key, child] : node->children) {
        auto res = std::visit(node_serialize{alloc}, child);
        map.emplace(key, std::move(res));
    }

    if (node->truncated) {
        array.emplace_back(object_builder::map({{"truncated", true}}, alloc));
    }

    return array;
}

namespace {
// NOLINTNEXTLINE(misc-no-recursion)
owned_object serialize(const base_node &node, nonnull_ptr<memory::memory_resource> alloc)
{
    return std::visit(node_serialize{alloc}, node);
}

using scanner_span = std::span<const extract_schema::scanner_entry>;

// NOLINTNEXTLINE(misc-no-recursion)
base_node generate_helper(object_view object, std::string_view key, scanner_span scanners,
    std::size_t depth, node_allocator node_alloc, ddwaf::timer &deadline)
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    switch (object.type()) {
    case object_type::null:
        return node_scalar{.type = scalar_type::null};
    case object_type::float64:
        return node_scalar{.type = scalar_type::real};
    case object_type::boolean:
        return node_scalar{.type = scalar_type::boolean};
    case object_type::string:
    case object_type::small_string:
    case object_type::literal_string:
        for (const auto &entry : scanners) {
            if (entry.instance->eval(key, object)) {
                return node_scalar{.type = scalar_type::string, .tags = &entry.tags};
            }
        }
        return node_scalar{.type = scalar_type::string};
    case object_type::int64:
    case object_type::uint64:
        return node_scalar{.type = scalar_type::integer};
    case object_type::map:
    case object_type::large_map: {
        auto length = object.size();
        node_record_ptr record = node_alloc.new_object<node_record>(node_alloc);
        if (length > extract_schema::max_record_nodes) {
            record->truncated = true;
            length = extract_schema::max_record_nodes;
        }
        record->children.reserve(length);
        for (std::size_t i = 0; i < length && depth > 1; i++) {
            const auto child = object.at_value(i);
            const auto key = object.at_key(i).as<std::string_view>();
            if (key.empty() || key.data() == nullptr) {
                continue;
            }

            auto schema = generate_helper(child, key, scanners, depth - 1, node_alloc, deadline);
            record->children.emplace(key, schema);
        }
        return record;
    }
    case object_type::array:
    case object_type::large_array: {
        auto length = object.size();
        node_array_ptr array = node_alloc.new_object<node_array>(node_alloc);
        array->length = length;
        if (length > extract_schema::max_array_nodes) {
            array->truncated = true;
            length = extract_schema::max_array_nodes;
        }
        array->children.reserve(length);
        for (std::size_t i = 0; i < length && depth > 1; i++) {
            const auto child = object.at_value(i);
            auto schema = generate_helper(child, key, scanners, depth - 1, node_alloc, deadline);
            array->children.emplace(schema);
        }
        return array;
    }
    case object_type::invalid:
    default:
        break;
    }
    return {};
}

owned_object generate(object_view object, scanner_span scanners,
    nonnull_ptr<memory::memory_resource> alloc, ddwaf::timer &deadline)
{
    // Only the serialised schema outlives this function; the arena returns
    // its blocks to the thread's block cache, so most schemas are built
    // without calling the system allocator.
    static constexpr std::size_t initial_arena_size = 4096;
    memory::arena_resource arena{initial_arena_size};

    static_assert(std::is_trivially_destructible_v<base_node>);
    const auto root = generate_helper(object, {}, scanners, extract_schema::max_container_depth,
        node_allocator{&arena}, deadline);
    return serialize(root, alloc);
}

} // namespace

} // namespace schema

owned_object extract_schema::eval_impl(const unary_argument<object_view> &input,
    processor_cache & /*cache*/, nonnull_ptr<memory::memory_resource> alloc,
    ddwaf::timer &deadline) const
{
    if (!input.value.has_value()) {
        return owned_object{};
    }

    return {schema::generate(input.value, scanners_, alloc, deadline)};
}

} // namespace ddwaf
