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
#include <vector>

#include <ddwaf.h>
#include <yaml-cpp/node/node.h>

namespace ddwaf::benchmark {

class object_generator {
public:
    enum class generator_type : unsigned {
        valid = 1,
        random = 2,
    };

    object_generator() = default;
    object_generator(const std::vector<std::string_view> &addresses, const YAML::Node &spec);

    ~object_generator();

    object_generator(const object_generator &) = default;
    object_generator &operator=(const object_generator &) = default;

    object_generator(object_generator &&) = default;
    object_generator &operator=(object_generator &&) = default;

    std::vector<ddwaf_object> operator()(generator_type type, size_t n) const;

protected:
    std::unordered_map<std::string_view, std::vector<ddwaf_object>> addresses_;

    // Objects generated from the ruleset will be stored here and freed on
    // destruction. This ensures that addresses can have multiple copies.
    std::vector<ddwaf_object> objects_;
};

} // namespace ddwaf::benchmark
