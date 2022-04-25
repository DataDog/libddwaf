// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include <ddwaf.h>

namespace ddwaf::benchmark
{

class object_generator
{
public:
    struct limits
    {
        using limit_type = struct {
            std::size_t min, max;
            std::size_t range() const { return max - min; }
        };

        limit_type container_depth{0, 20};
        limit_type container_size{0, 256};
        limit_type string_length{0, 4096};
        std::size_t max_nodes{4096};
    };

    object_generator() = default;
    object_generator(limits l, std::vector<std::string_view> &&addresses);

    object_generator(const object_generator&) = default;
    object_generator& operator=(const object_generator&) = default;

    object_generator(object_generator&&) = default;
    object_generator& operator=(object_generator&&) = default;

    ddwaf_object operator()() const;

protected:
    char* generate_random_string(std::size_t *length) const;
    void generate_string_object(ddwaf_object &o) const ;
    void generate_map_object(ddwaf_object &o, std::size_t depth) const;
    void generate_array_object(ddwaf_object &o, std::size_t depth) const;
    void generate_object(ddwaf_object &o, std::size_t depth = 1) const;

protected:
    limits limits_;
    std::vector<std::string_view> addresses_;
};


}
