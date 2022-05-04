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

void generate_object(ddwaf_object &o, const settings &l,
    std::size_t &max_elements, std::size_t depth = 0);

char *generate_random_string(const settings &l, std::size_t *length)
{
    static auto &charset =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    //"`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"!";

    std::size_t numchars =
        l.string_length.min + random::get() % l.string_length.range();

    char *str = (char *)malloc(numchars + 1);
    for (std::size_t i = 0; i < numchars; i++) {
        str[i] = charset[random::get() % (sizeof(charset) - 2)];
    }
    str[numchars] = '\0';
    *length = numchars;

    return str;
}

void generate_string_object(ddwaf_object &o, const settings &l)
{
    std::size_t length = 0;
    char *str = generate_random_string(l, &length);
    ddwaf_object_stringl_nc(&o, str, length);
}

void generate_map_object(ddwaf_object &o, const settings &l,
    std::size_t &max_elements, std::size_t depth)

{
    ddwaf_object_map(&o);

    std::size_t n =
        l.container_size.min + random::get() % l.container_size.range();

    n = std::min(n, max_elements);

    for (std::size_t i = 0; i < n; i++) {
        std::size_t length = 0;
        char *key = generate_random_string(l, &length);

        ddwaf_object value;
        generate_object(value, l, max_elements, depth + 1);
        ddwaf_object_map_addl_nc(&o, key, length, &value);
    }
}

void generate_array_object(ddwaf_object &o, const settings &l,
    std::size_t &max_elements, std::size_t depth)
{
    ddwaf_object_array(&o);

    std::size_t n =
        l.container_size.min + random::get() % l.container_size.range();

    n = std::min(n, max_elements);

    for (std::size_t i = 0; i < n; i++) {
        ddwaf_object value;
        generate_object(value, l, max_elements, depth + 1);
        ddwaf_object_array_add(&o, &value);
    }
}

void generate_object(ddwaf_object &o, const settings &l,
    std::size_t &max_elements, std::size_t depth)
{
    if (max_elements > 0) {
        max_elements--;
    }

    if (depth >= l.container_depth.max) {
        generate_string_object(o, l);
        return;
    }

    if (depth < l.container_depth.min) {
        if (random::get() % 2) {
            generate_map_object(o, l, max_elements, depth);
        } else {
            generate_array_object(o, l, max_elements, depth);
        }
        return;
    }

    // Decide type (map, array, string)
    switch (random::get() % 3) {
    case 0: // String
        generate_string_object(o, l);
        break;
    case 1: // Map
        generate_map_object(o, l, max_elements, depth);
        break;
    case 2: // Array
        generate_array_object(o, l, max_elements, depth);
        break;
    }
}

} // namespace

void object_generator::parse_rule(const fs::path &rule_path)
{
    std::string rule_str = utils::read_file(rule_path);
    YAML::Node doc = YAML::Load(rule_str);

    const YAML::Node &conditions = doc["conditions"];
    for (auto it = conditions.begin(); it != conditions.end(); ++it) {
        const YAML::Node &condition = *it;
        const YAML::Node &parameters = condition["parameters"];
        const YAML::Node &op = condition["operator"];

        std::vector<ddwaf_object> cond_values;
        if (op.as<std::string>() == "phrase_match") {
            const YAML::Node &list = parameters["list"];
            cond_values = list.as<std::vector<ddwaf_object>>();
            objects_.insert(
                objects_.end(), cond_values.begin(), cond_values.end());
        } else {
            continue;
        }

        const YAML::Node &inputs = parameters["inputs"];
        for (auto addr = inputs.begin(); addr != inputs.end(); ++addr) {
            auto key = (*addr)["address"].as<std::string>();
            auto &current_values = addresses_[key];
            current_values.insert(
                current_values.end(), cond_values.begin(), cond_values.end());
        }
    }

    const YAML::Node &test_vectors = doc["test_vectors"];
    if (!test_vectors) {
        return;
    }

    const YAML::Node &matches = test_vectors["matches"];
    if (!matches) {
        return;
    }

    for (auto it = matches.begin(); it != matches.end(); ++it) {
        auto first_entry = it->begin();
        auto key = first_entry->first.as<std::string>();
        auto vector = first_entry->second.as<ddwaf_object>();

        objects_.push_back(vector);

        auto &current_values = addresses_[key];
        current_values.push_back(vector);
    }
}

object_generator::object_generator(
    const std::vector<std::string_view> &addresses, const fs::path &rules_dir)
{
    if (!fs::is_directory(rules_dir)) {
        throw std::invalid_argument(
            std::string(rules_dir) + " should be a directory");
    }

    for (auto addr : addresses) { addresses_[addr] = {}; }

    for (auto const &entry : fs::directory_iterator{rules_dir}) {
        if (!entry.is_regular_file()) {
            continue;
        }

        const auto entry_path = entry.path();
        if (entry_path.extension() != ".yaml") {
            continue;
        }

        try {
            parse_rule(entry_path);
        } catch (const std::exception &e) {
            std::cerr << entry_path << std::endl;
            std::cerr << e.what() << std::endl;
            break;
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

    while (n--) {
        ddwaf_object &root = output[n];
        ddwaf_object_map(&root);

        for (auto &[addr, valid_values] : addresses_) {
            ddwaf_object value;

            std::size_t max_elements = l.max_elements / addresses_.size();
            if (max_elements == 0) {
                max_elements = 1;
            }

            generator_type type = l.type;
            if (valid_values.empty()) {
                type = generator_type::random;
            } else {
                if (type == generator_type::mixed) {
                    type = static_cast<generator_type>(random::get() % 2);
                }
            }

            if (type == generator_type::random) {
                generate_object(value, l, max_elements);
            } else {
                std::size_t index = random::get() % valid_values.size();
                value = utils::object_dup(valid_values[index]);
            }

            ddwaf_object_map_add(&root, addr.data(), &value);
        }
    }

    return output;
}

} // namespace ddwaf::benchmark
