// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <ddwaf.h>
#include <yaml-cpp/node/node.h>

namespace ddwaf::benchmark {

struct object_specification {
    static constexpr unsigned default_terminal_nodes = 100;
    static constexpr unsigned default_intermediate_nodes = 200;
    static constexpr unsigned default_depth = 10;
    static constexpr unsigned default_string_length = 2048;
    static constexpr unsigned default_key_length = 128;

    unsigned terminal_nodes{default_terminal_nodes};
    unsigned intermediate_nodes{default_intermediate_nodes};
    unsigned depth{default_depth};
    unsigned string_length{default_string_length};
    unsigned key_length{default_key_length};
};

class object_generator {
public:
    explicit object_generator(std::vector<std::string_view> addresses)
        : addresses_(std::move(addresses))
    {}

    ~object_generator() = default;

    object_generator(const object_generator &) = default;
    object_generator &operator=(const object_generator &) = default;

    object_generator(object_generator &&) = default;
    object_generator &operator=(object_generator &&) = default;

    ddwaf_object operator()(object_specification spec = {}) const;

protected:
    std::vector<std::string_view> addresses_;
};

} // namespace ddwaf::benchmark
