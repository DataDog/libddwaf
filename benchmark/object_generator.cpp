// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <ddwaf.h>
#include <deque>
#include <memory_resource>
#include <vector>
#include <yaml-cpp/node/node.h>

#include "object_generator.hpp"
#include "random.hpp"

namespace ddwaf::benchmark {
namespace {

char *generate_random_string(std::size_t length)
{
    static const auto &charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"\0!";

    // NOLINTNEXTLINE
    // TODO Should we have a no-copy string
    auto *alloc = std::pmr::new_delete_resource();
    char *str = static_cast<char *>(alloc->allocate(length, alignof(char)));
    for (std::size_t i = 0; i < length; i++) {
        str[i] = charset[random::get() % (sizeof(charset) - 2)];
    }

    return str;
}

void generate_string_object(ddwaf_object &o, std::size_t length)
{
    char *str = generate_random_string(length);
    ddwaf_object_set_const_string(&o, str, length);
    o.type = DDWAF_OBJ_STRING;
}

void generate_container(ddwaf_object &o)
{
    if (random::get_bool()) {
        ddwaf_object_set_array(&o, 4, nullptr);
    } else {
        ddwaf_object_set_map(&o, 4, nullptr);
    }
}

struct level_nodes {
    unsigned intermediate{0};
    unsigned terminal{0};
};

void generate_node_distribution(std::vector<level_nodes> &slots, unsigned nodes, auto getter)
{
    for (unsigned i = 0; nodes > 0; i = (i + 1) % slots.size()) {
        auto extra_nodes = random::get(nodes + 1);
        getter(slots[i]) += extra_nodes;
        nodes -= extra_nodes;
    }
}

std::vector<level_nodes> generate_vertical_distribution(
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    unsigned depth, unsigned intermediate, unsigned terminal)
{
    std::vector<level_nodes> levels{depth, {1, 0}};
    levels.back().intermediate = 0;
    intermediate -= intermediate < depth ? 0 : (depth - 1);

    // Distribute the remaining intermediate nodes
    generate_node_distribution(
        levels, intermediate, [](auto &node) -> unsigned & { return node.intermediate; });
    generate_node_distribution(
        levels, terminal, [](auto &node) -> unsigned & { return node.terminal; });

    return levels;
}

std::vector<level_nodes> generate_horizontal_distribution(
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    unsigned nodes, unsigned intermediate, unsigned terminal)
{
    std::vector<level_nodes> slots{nodes, level_nodes{}};

    // Distribute intermediate nodes, this doesn't apply to the last level
    generate_node_distribution(
        slots, intermediate, [](auto &node) -> unsigned & { return node.intermediate; });
    generate_node_distribution(
        slots, terminal, [](auto &node) -> unsigned & { return node.terminal; });

    return slots;
}

struct queue_node {
    ddwaf_object *object;
    unsigned level;
    unsigned intermediate;
    unsigned terminal;
};

void generate_objects(ddwaf_object &root, const object_specification &s)
{
    auto levels =
        generate_vertical_distribution(s.depth, s.intermediate_nodes - 1, s.terminal_nodes);

    std::deque<queue_node> object_queue;
    generate_container(root);
    object_queue.emplace_back(&root, 0, levels[0].intermediate, levels[0].terminal);

    for (; !object_queue.empty(); object_queue.pop_front()) {
        auto &[object, level, intermediate, terminal] = object_queue.front();
        unsigned intermediate_nodes_in_current = intermediate;

        while ((terminal + intermediate) > 0) {
            ddwaf_object next;

            if ((random::get_bool() && terminal > 0) || intermediate == 0) {
                generate_string_object(next, s.string_length);
                --terminal;
            } else {
                generate_container(next);
                --intermediate;
            }

            if (object->type == DDWAF_OBJ_MAP) {
                auto *str = generate_random_string(s.key_length);
                auto *slot = ddwaf_object_insert_key_nocopy(object, str, s.key_length);
                *slot = next;
            } else {
                auto slot = ddwaf_object_insert(object);
                *slot = next;
            }
        }

        if (s.depth > (level + 1) && intermediate_nodes_in_current > 0) {
            auto [next_intermediate, next_terminal] = levels[level + 1];
            auto next_level = generate_horizontal_distribution(
                intermediate_nodes_in_current, next_intermediate, next_terminal);

            for (unsigned i = 0, j = 0; i < object->size; ++i) {
                auto *child =
                    const_cast<ddwaf_object *>(ddwaf_object_get_index(object, i, nullptr));
                if (child->type == DDWAF_OBJ_MAP || child->type == DDWAF_OBJ_ARRAY) {
                    object_queue.emplace_back(
                        child, level + 1, next_level[j].intermediate, next_level[j].terminal);
                    ++j;
                }
            }
        }
    }
}

} // namespace

std::vector<ddwaf_object> object_generator::operator()(unsigned n, object_specification spec) const
{
    std::vector<ddwaf_object> objects;
    while (n-- > 0) {
        ddwaf_object root;
        ddwaf_object_set_map(&root, 4, nullptr);

        for (const auto addr : addresses_) {
            ddwaf_object value;
            if (spec.depth == 0) {
                generate_string_object(value, spec.string_length);
            } else {
                generate_objects(value, spec);
            }

            auto *slot = ddwaf_object_insert_key(&root, addr.data(), addr.size(), nullptr);
            *slot = value;
        }
        objects.emplace_back(root);
    }
    return objects;
}

} // namespace ddwaf::benchmark
