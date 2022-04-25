// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#include <iostream>

#include "object_generator.hpp"
#include "random.hpp"

namespace ddwaf::benchmark
{

object_generator::object_generator(limits l,
    std::vector<std::string_view> &&addresses):
    limits_(l), addresses_(std::move(addresses)) {}

ddwaf_object object_generator::operator()() const
{
    ddwaf_object root;
    ddwaf_object_map(&root);

    for (auto &addr : addresses_) {
        ddwaf_object value;
        generate_object(value);

        ddwaf_object_map_add(&root, addr.data(), &value);
    }

    return root;
}

char* object_generator::generate_random_string(std::size_t *length) const
{
    static auto& charset = 
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "`¬|\\|,<.>/?;:'@#~[{]}=+-_)(*&^%$£\"!";

    static std::uniform_int_distribution<std::string::size_type> udist(0,
        sizeof(charset) - 2);

    std::size_t numchars = limits_.string_length.min +
        random::get() % limits_.string_length.range();

    char *str = (char *)malloc(numchars + 1);
    for (std::size_t i = 0; i < numchars; i++) {
        str[i] =  charset[udist(random::get_rng())];
    }
    str[numchars] = '\0';
    *length = numchars;

    return str;
}

void object_generator::generate_string_object(ddwaf_object &o) const
{
    std::size_t length = 0;
    char * str = generate_random_string(&length);
    ddwaf_object_stringl_nc(&o, str, length);
}

void object_generator::generate_map_object(ddwaf_object &o, std::size_t depth) const
{
    ddwaf_object_map(&o);
    std::size_t n = limits_.container_size.min +
        random::get() % limits_.container_size.range();

    for (std::size_t i = 0; i < n; i++) {
        std::size_t length = 0;
        char *key = generate_random_string(&length);

        ddwaf_object value;
        generate_object(value, depth + 1);
        ddwaf_object_map_addl_nc(&o, key, length, &value);
    }
}

void object_generator::generate_array_object(ddwaf_object &o, std::size_t depth) const
{
    ddwaf_object_array(&o);
    std::size_t n = limits_.container_size.min +
        random::get() % limits_.container_size.range();

    for (std::size_t i = 0; i < n; i++) {
        ddwaf_object value;
        generate_object(value, depth + 1);
        ddwaf_object_array_add(&o, &value);
    }
}

void object_generator::generate_object(ddwaf_object &o, std::size_t depth) const
{
    if (depth >= limits_.container_depth.max) {
        generate_string_object(o);
        return;
    }

    // Decide type (map, array, string)
    switch (random::get() % 3) {
    case 0: // String
        generate_string_object(o);
        break;
    case 1: // Map
        generate_map_object(o, depth);
        break;
    case 2: // Array
        generate_array_object(o, depth);
        break;
    }
}

}
