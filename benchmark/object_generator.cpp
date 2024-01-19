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

#include "random.hpp"
#include "utils.hpp"
#include "yaml_helpers.hpp"

namespace utils = ddwaf::benchmark::utils;
using rnd = ddwaf::benchmark::random;

namespace {

// Global settings
constexpr unsigned default_terminal_nodes = 100;
constexpr unsigned default_intermediate_nodes = 500;
constexpr unsigned default_depth = 10;
constexpr unsigned default_string_length = 4096;
constexpr unsigned default_key_length = 128;

unsigned obj_terminal_nodes{default_terminal_nodes};
unsigned obj_intermediate_nodes{default_intermediate_nodes};
unsigned obj_depth{default_depth};
unsigned obj_string_length{default_string_length};
unsigned obj_key_length{default_key_length};

char *generate_random_string(std::size_t length)
{
    static const auto &charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"\0!";

    // NOLINTNEXTLINE
    char *str = (char *)malloc(length + 1);
    for (std::size_t i = 0; i < length; i++) {
        str[i] = charset[rnd::get() % (sizeof(charset) - 2)];
    }
    str[length] = '\0';

    return str;
}

void generate_string_object(ddwaf_object &o)
{
    char *str = generate_random_string(obj_string_length);
    ddwaf_object_stringl_nc(&o, str, obj_string_length);
}

void generate_container(ddwaf_object &o)
{
    if (rnd::get_bool()) {
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

    while (intermediate > 0) {
        // Ensure each level has at least an intermediate node, except the last
        for (unsigned i = 0; i < (depth - 1); ++i) { levels[i].intermediate += 1; }
        intermediate -= (depth - 1);

        // Distribute the remaining intermediate nodes
        for (unsigned i = 0; intermediate > 0 && i < depth; ++i) {
            auto extra_nodes = rnd::get(intermediate);
            levels[i].intermediate += extra_nodes;
            intermediate -= extra_nodes;
        }
    }

    while (terminal > 0) {
        for (unsigned i = 0; terminal > 0 && i < depth; ++i) {
            auto extra_nodes = rnd::get(terminal + 1);
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
            auto extra_nodes = 1 + rnd::get(intermediate);
            slots[i].intermediate += extra_nodes;
            intermediate -= extra_nodes;
        }
    }

    while (terminal > 0) {
        for (unsigned i = 0; terminal > 0 && i < nodes; ++i) {
            auto extra_nodes = rnd::get(terminal + 1);
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

void generate_objects(ddwaf_object &root)
{
    generate_container(root);

    auto levels =
        generate_vertical_distribution(obj_depth, obj_intermediate_nodes - 1, obj_terminal_nodes);

    std::deque<queue_node> object_queue;
    generate_container(root);
    object_queue.emplace_back(&root, 0, levels[0].intermediate, levels[0].terminal);

    for (; !object_queue.empty(); object_queue.pop_front()) {
        auto &node = object_queue.front();
        unsigned intermediate_nodes_in_current = 0;

        while ((node.terminal + node.intermediate) > 0) {
            ddwaf_object next;

            bool build_terminal = rnd::get_bool() ? node.terminal > 0 : node.intermediate == 0;

            if (build_terminal) {
                generate_string_object(next);
                --node.terminal;
            } else {
                generate_container(next);
                --node.intermediate;
                ++intermediate_nodes_in_current;
            }

            if (node.object->type == DDWAF_OBJ_MAP) {
                auto *str = generate_random_string(obj_key_length);
                ddwaf_object_map_addl_nc(node.object, str, obj_key_length, &next);
            } else {
                ddwaf_object_array_add(node.object, &next);
            }
        }

        if (obj_depth > (node.level + 1) && intermediate_nodes_in_current > 0) {
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

ddwaf_object generate_root_object(const std::vector<std::string_view> &addresses)
{
    ddwaf_object root;
    ddwaf_object_map(&root);

    for (const auto addr : addresses) {
        ddwaf_object value;
        if (obj_depth == 0) {
            generate_string_object(value);
        } else {
            generate_objects(value);
        }

        ddwaf_object_map_add(&root, addr.data(), &value);
    }

    return root;
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void print_help_and_exit(std::string_view name, std::string_view error = {})
{
    std::cerr << "Usage: " << name << " [OPTION]...\n"
              << "    --terminal_nodes VALUE      Number of terminal nodes per object\n"
              << "    --intermediate_nodes VALUE  Number of intermediate containers per object\n"
              << "    --depth VALUE               Depth of each object\n"
              << "    --seed VALUE                Seed for RNG\n"
              << "    --string_length VALUE       Size of terminal string nodes\n"
              << "    --key_length VALUE          Size of map keys\n";

    if (!error.empty()) {
        std::cerr << "\nError: " << error << "\n";
        utils::exit_failure();
    }
    utils::exit_success();
}

void generate_settings(const std::vector<std::string> &args)
{
    auto opts = utils::parse_args(args);

    if (opts.contains("help")) {
        print_help_and_exit(args[0]);
    }

    if (opts.contains("terminal_nodes")) {
        obj_terminal_nodes = utils::from_string<unsigned>(opts["terminal_nodes"]);
    }

    if (opts.contains("intermediate_nodes")) {
        obj_intermediate_nodes = utils::from_string<unsigned>(opts["intermediate_nodes"]);
    }

    if (opts.contains("depth")) {
        obj_depth = utils::from_string<unsigned>(opts["depth"]);
    }

    if (opts.contains("string_length")) {
        obj_string_length = utils::from_string<unsigned>(opts["string_length"]);
    }

    if (opts.contains("key_length")) {
        obj_key_length = utils::from_string<unsigned>(opts["key_length"]);
    }

    if (opts.contains("seed")) {
        auto seed = utils::from_string<unsigned>(opts["seed"]);
        rnd::seed(seed);
    }

    if (obj_depth > obj_intermediate_nodes) {
        obj_intermediate_nodes = obj_depth;
    }

    if (obj_depth == 0) {
        obj_intermediate_nodes = 0;
    }
}

} // namespace
  //
int main(int argc, char *argv[])
{
    std::vector<std::string_view> default_addresses{"graphql.server.all_resolvers",
        "graphql.server.resolver", "grpc.server.request.message", "grpc.server.request.metadata",
        "http.client_ip", "server.request.body", "server.request.cookies",
        "server.request.headers.no_cookies", "server.request.headers.user-agent",
        "server.request.path_params", "server.request.query", "server.request.uri.raw",
        "server.response.body", "server.response.headers.no_cookies", "server.response.status",
        "usr.id", "waf.context.duration", "waf.context.events.length", "waf.context.processor",
        "waf.context.processor.extract-schema"};

    std::vector<std::string> args(argv, argv + argc);
    generate_settings(args);

    auto obj = generate_root_object(default_addresses);
    std::cout << utils::object_to_string(obj) << std::endl;

    return EXIT_SUCCESS;
}
