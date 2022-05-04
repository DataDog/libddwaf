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

namespace fs = std::filesystem;

namespace ddwaf::benchmark {

class object_generator {
public:
    enum class generator_type : unsigned {
        valid = 1,
        random = 2,
        mixed = valid | random,
    };

    struct settings {
        using limit_type = struct {
            std::size_t min, max;
            std::size_t range() const { return max - min; }
        };

        limit_type container_depth{0, 20};
        limit_type container_size{0, 256};
        limit_type string_length{0, 4096};
        std::size_t max_elements{4096};
        generator_type type{generator_type::random};
    };

    object_generator() = default;
    object_generator(const std::vector<std::string_view> &addresses,
        const fs::path &rules_dir);

    ~object_generator();

    object_generator(const object_generator &) = default;
    object_generator &operator=(const object_generator &) = default;

    object_generator(object_generator &&) = default;
    object_generator &operator=(object_generator &&) = default;

    std::vector<ddwaf_object> operator()(const settings &l, size_t n) const;

protected:
    void parse_rule(const fs::path &rule_path);
    std::unordered_map<std::string_view, std::vector<ddwaf_object>> addresses_;

    // Objects generated from the ruleset will be stored here and freed on
    // destruction. This ensures that addresses can have multiple copies.
    std::vector<ddwaf_object> objects_;
};

} // namespace ddwaf::benchmark
