// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <iostream>
#include <yaml-cpp/yaml.h>

#include "object_generator.hpp"
#include "random.hpp"
#include "utils.hpp"
#include "yaml_helpers.hpp"

namespace ddwaf::benchmark {

namespace {

using settings = object_generator::settings;

void generate_object(
    ddwaf_object &o, const settings &l, std::size_t depth = 0);

char *generate_random_string(const settings &l, std::size_t *length)
{
    static const auto &charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"!";

    // NOLINTNEXTLINE
    char *str = (char *)malloc(l.string_length + 1);
    for (std::size_t i = 0; i < l.string_length; i++) {
        str[i] = charset[random::get() % (sizeof(charset) - 2)];
    }
    str[l.string_length] = '\0';
    *length = l.string_length;

    return str;
}

void generate_string_object(ddwaf_object &o, const settings &l)
{
    std::size_t length = 0;
    char *str = generate_random_string(l, &length);
    ddwaf_object_stringl_nc(&o, str, length);
}

// NOLINTNEXTLINE(misc-no-recursion)
void generate_map_object(
    ddwaf_object &o, const settings &l, std::size_t depth)

{
    ddwaf_object_map(&o);

    for (std::size_t i = 0; i < l.container_size; i++) {
        std::size_t length = 0;
        char *key = generate_random_string(l, &length);

        ddwaf_object value;
        generate_object(value, l, depth + 1);
        ddwaf_object_map_addl_nc(&o, key, length, &value);
    }
}

// NOLINTNEXTLINE(misc-no-recursion)
void generate_array_object(
    ddwaf_object &o, const settings &l, std::size_t depth)
{
    ddwaf_object_array(&o);

    for (std::size_t i = 0; i < l.container_size; i++) {
        ddwaf_object value;
        generate_object(value, l, depth + 1);
        ddwaf_object_array_add(&o, &value);
    }
}

// NOLINTNEXTLINE(misc-no-recursion)
void generate_object(
    ddwaf_object &o, const settings &l, std::size_t depth)
{
    if (depth >= l.container_depth) {
        generate_string_object(o, l);
        return;
    }

    if (depth < l.container_depth) {
        if (random::get_bool()) {
            generate_map_object(o, l, depth);
        } else {
            generate_array_object(o, l, depth);
        }
        return;
    }

    // Decide type (map, array, string)
    switch (random::get() % 3) {
    case 0: // String
        generate_string_object(o, l);
        break;
    case 1: // Map
        generate_map_object(o, l, depth);
        break;
    case 2: // Array
        generate_array_object(o, l, depth);
        break;
    }
}

} // namespace

object_generator::object_generator(
    const std::vector<std::string_view> &addresses, const YAML::Node &spec)
{
    for (auto addr : addresses) { addresses_[addr] = {}; }

    const YAML::Node &test_vectors = spec["vectors"];
    if (!test_vectors) {
        return;
    }

    for (auto it = test_vectors.begin(); it != test_vectors.end(); ++it) {
        auto key = it->first.as<std::string>();
        auto &current_values = addresses_[key];

        auto array = it->second;
        for (auto value_it = array.begin(); value_it != array.end(); ++value_it) {
            auto vector = value_it->as<ddwaf_object>();
            objects_.push_back(vector);
            current_values.push_back(vector);
        }
    }
}

object_generator::~object_generator()
{
    for (auto &obj : objects_) { ddwaf_object_free(&obj); }
}

std::vector<ddwaf_object> object_generator::operator()(
    const object_generator::settings &l, size_t n) const
{
    std::vector<ddwaf_object> output(n);

    while (n-- > 0) {
        ddwaf_object &root = output[n];
        ddwaf_object_map(&root);

        for (const auto &[addr, valid_values] : addresses_) {
            ddwaf_object value;

            generator_type type = l.type;
            if (type == generator_type::valid) {
                if (valid_values.empty()) {
                    continue;
                }

                std::size_t index = random::get() % valid_values.size();
                value = utils::object_dup(valid_values[index]);
            } else {
                generate_object(value, l);
            }

            ddwaf_object_map_add(&root, addr.data(), &value);
        }
    }

    if (output.empty() && l.type == generator_type::valid) {
        throw std::runtime_error("No valid values available");
    }

    return output;
}

} // namespace ddwaf::benchmark
