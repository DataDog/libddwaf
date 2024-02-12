// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <array>
#include <ddwaf.h>
#include <deque>
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

void generate_ip_object(ddwaf_object &o)
{
    std::stringstream ss;
    auto b = random::get_n<uint8_t, 4>();
    ss << b[0] << "." << b[1] << "." << b[2] << "." << b[3];
    ddwaf_object_string(&o, ss.str().c_str());
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
    generate_container(root);

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
                ddwaf_object_map_addl_nc(object, str, s.key_length, &next);
            } else {
                ddwaf_object_array_add(object, &next);
            }
        }

        if (s.depth > (level + 1) && intermediate_nodes_in_current > 0) {
            auto [next_intermediate, next_terminal] = levels[level + 1];
            auto next_level = generate_horizontal_distribution(
                intermediate_nodes_in_current, next_intermediate, next_terminal);

            for (unsigned i = 0, j = 0; i < object->nbEntries; ++i) {
                auto type = object->array[i].type;
                if (type == DDWAF_OBJ_MAP || type == DDWAF_OBJ_ARRAY) {
                    object_queue.emplace_back(&object->array[i], level + 1,
                        next_level[j].intermediate, next_level[j].terminal);
                    ++j;
                }
            }
        }
    }
}

enum class object_type : uint8_t { none, string, ip, boolean, any };

object_type address_to_object_type(std::string_view addr)
{
    static std::unordered_map<std::string_view, object_type> address_types{
        {"graphql.server.all_resolvers", object_type::any},
        {"graphql.server.resolver", object_type::any},
        {"grpc.server.request.message", object_type::any},
        {"grpc.server.request.metadata", object_type::any},
        {"http.client_ip", object_type::ip},
        {"server.request.body", object_type::any},
        {"server.request.cookies", object_type::any},
        {"server.request.headers.no_cookies", object_type::any},
        {"server.request.headers.no_cookies", object_type::any},
        {"server.request.path_params", object_type::any},
        {"server.request.query", object_type::any},
        {"server.request.uri.raw", object_type::string},
        {"server.response.body", object_type::any},
        {"server.response.headers.no_cookies", object_type::any},
        {"server.response.status", object_type::string},
        {"usr.id", object_type::string},
        {"waf.context.processor", object_type::boolean},
        {"server.io.fs.file", object_type::string},
    };
    auto it = address_types.find(addr);
    return it == address_types.end() ? object_type::none : it->second;
}

} // namespace

std::vector<ddwaf_object> object_generator::operator()(unsigned n, object_specification spec) const
{
    std::vector<ddwaf_object> objects;
    while (n-- > 0) {
        ddwaf_object root;
        ddwaf_object_map(&root);

        for (const auto addr : addresses_) {
            auto type = address_to_object_type(addr);

            ddwaf_object value;
            switch (type) {
            case object_type::string:
                generate_string_object(value, spec.string_length);
                break;
            case object_type::ip:
                generate_ip_object(value);
                break;
            case object_type::boolean:
                ddwaf_object_bool(&value, random::get_bool());
                break;
            case object_type::none:
                ddwaf_object_null(&value);
                break;
            case object_type::any:
            default:
                if (spec.depth == 0) {
                    generate_string_object(value, spec.string_length);
                } else {
                    generate_objects(value, spec);
                }
                break;
            }

            ddwaf_object_map_add(&root, addr.data(), &value);
        }
        objects.emplace_back(root);
    }
    return objects;
}

} // namespace ddwaf::benchmark
