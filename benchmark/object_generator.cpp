// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <ddwaf.h>
#include <deque>
#include <iostream>
#include <string>
#include <vector>
#include <yaml-cpp/node/node.h>

#include "object_generator.hpp"
#include "random.hpp"
#include "utils.hpp"
#include "yaml_helpers.hpp"

namespace ddwaf::benchmark {
namespace {

char *generate_random_string(std::size_t length)
{
    static const auto &charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"\0!";

    // NOLINTNEXTLINE
    char *str = (char *)malloc(length + 1);
    for (std::size_t i = 0; i < length; i++) {
        str[i] = charset[random::get() % (sizeof(charset) - 2)];
    }
    str[length] = '\0';

    return str;
}

void generate_string_object(ddwaf_object &o, std::size_t length)
{
    char *str = generate_random_string(length);
    ddwaf_object_stringl_nc(&o, str, length);
}

void generate_container(ddwaf_object &o)
{
    if (random::get_bool()) {
        ddwaf_object_array(&o);
    } else {
        ddwaf_object_map(&o);
    }
}

struct level_nodes {
    unsigned intermediate{0};
    unsigned terminal{0};
};

std::vector<level_nodes> generate_vertical_distribution(
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    unsigned depth, unsigned intermediate, unsigned terminal)
{
    if (depth == 0) {
        return {};
    }

    std::vector<level_nodes> levels;
    levels.resize(depth);

    if (intermediate > 0) {
        // Ensure each level has at least an intermediate node, except the last
        for (unsigned i = 0; i < (depth - 1); ++i) { levels[i].intermediate += 1; }
        intermediate -= (depth - 1);
    }

    while (intermediate > 0) {
        // Distribute the remaining intermediate nodes
        for (unsigned i = 0; intermediate > 0 && i < depth; ++i) {
            auto extra_nodes = random::get(intermediate + 1);
            levels[i].intermediate += extra_nodes;
            intermediate -= extra_nodes;
        }
    }

    while (terminal > 0) {
        for (unsigned i = 0; terminal > 0 && i < depth; ++i) {
            auto extra_nodes = random::get(terminal + 1);
            levels[i].terminal += extra_nodes;
            terminal -= extra_nodes;
        }
    }

    return levels;
}

std::vector<level_nodes> generate_horizontal_distribution(
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    unsigned nodes, unsigned intermediate, unsigned terminal)
{
    if (nodes == 0) {
        return {};
    }

    std::vector<level_nodes> slots;
    slots.resize(nodes);

    // Distribute intermediate nodes, this doesn't apply to the last level
    while (intermediate > 0) {
        for (unsigned i = 0; intermediate > 0 && i < nodes; ++i) {
            auto extra_nodes = 1 + random::get(intermediate);
            slots[i].intermediate += extra_nodes;
            intermediate -= extra_nodes;
        }
    }

    while (terminal > 0) {
        for (unsigned i = 0; terminal > 0 && i < nodes; ++i) {
            auto extra_nodes = random::get(terminal + 1);
            slots[i].terminal += extra_nodes;
            terminal -= extra_nodes;
        }
    }

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
    generate_container(root);

    auto levels =
        generate_vertical_distribution(s.depth, s.intermediate_nodes - 1, s.terminal_nodes);

    std::deque<queue_node> object_queue;
    generate_container(root);
    object_queue.emplace_back(&root, 0, levels[0].intermediate, levels[0].terminal);

    for (; !object_queue.empty(); object_queue.pop_front()) {
        auto &node = object_queue.front();
        unsigned intermediate_nodes_in_current = 0;

        while ((node.terminal + node.intermediate) > 0) {
            ddwaf_object next;

            bool build_terminal = random::get_bool() ? node.terminal > 0 : node.intermediate == 0;

            if (build_terminal) {
                generate_string_object(next, s.string_length);
                --node.terminal;
            } else {
                generate_container(next);
                --node.intermediate;
                ++intermediate_nodes_in_current;
            }

            if (node.object->type == DDWAF_OBJ_MAP) {
                auto *str = generate_random_string(s.key_length);
                ddwaf_object_map_addl_nc(node.object, str, s.key_length, &next);
            } else {
                ddwaf_object_array_add(node.object, &next);
            }
        }

        if (s.depth > (node.level + 1) && intermediate_nodes_in_current > 0) {
            auto [next_intermediate, next_terminal] = levels[node.level + 1];
            auto next_level = generate_horizontal_distribution(
                intermediate_nodes_in_current, next_intermediate, next_terminal);

            for (unsigned i = 0, j = 0; i < node.object->nbEntries; ++i) {
                auto type = node.object->array[i].type;
                if (type == DDWAF_OBJ_MAP || type == DDWAF_OBJ_ARRAY) {
                    object_queue.emplace_back(&node.object->array[i], node.level + 1,
                        next_level[j].intermediate, next_level[j].terminal);
                    ++j;
                }
            }
        }
    }
}

} // namespace

ddwaf_object object_generator::operator()(object_specification spec) const
{
    if (spec.depth > spec.intermediate_nodes) {
        spec.intermediate_nodes = spec.depth;
    }

    if (spec.depth == 0) {
        spec.intermediate_nodes = 0;
    }

    ddwaf_object root;
    ddwaf_object_map(&root);

    for (const auto addr : addresses_) {
        ddwaf_object value;
        if (spec.depth == 0) {
            generate_string_object(value, spec.string_length);
        } else {
            generate_objects(value, spec);
        }

        ddwaf_object_map_add(&root, addr.data(), &value);
    }

    return root;
}

} // namespace ddwaf::benchmark
