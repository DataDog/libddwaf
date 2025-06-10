// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <boost/unordered/unordered_flat_map.hpp>
#include <memory>
#include <string>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "dynamic_string.hpp"
#include "exclusion/common.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"

namespace ddwaf {

enum class data_source : uint8_t { values, keys, object };

struct condition_match {
    struct argument {
        std::string_view name;
        dynamic_string resolved;
        std::string_view address{};
        std::vector<std::string> key_path{};
    };

    std::vector<argument> args;
    std::vector<dynamic_string> highlights;
    std::string_view operator_name;
    std::string_view operator_value;
    bool ephemeral{false};
};

struct condition_cache {
    // Stores the pointer to the object of the i-th target of the condition,
    // used in the previous evaluation, if said object is non-ephemeral. This
    // ensures that the evaluation of the condition can be skipped for the same
    // object in the future.
    memory::vector<object_view> targets;
    std::optional<condition_match> match;
};

// Provides the specification of a specific operator parameter. Note that the
// type of the parameter is inferred at compile type.
struct parameter_specification {
    std::string_view name;
    bool variadic{false};
    bool optional{false};
};

// Provides the definition of an individual address(target) to parameter mapping.
// Each target must satisfy the associated parameter specification.
struct condition_target {
    std::string name;
    target_index index{};
    std::vector<std::string> key_path{};
    std::vector<transformer_id> transformers{};
    data_source source{data_source::values};
};

// Provides the list of targets mapped to the given condition parameter. If the
// parameter is non-variadic, only one mapping should be present.
struct condition_parameter {
    std::vector<condition_target> targets;
};

class base_condition {
public:
    base_condition() = default;
    virtual ~base_condition() = default;
    base_condition(const base_condition &) = default;
    base_condition &operator=(const base_condition &) = default;
    base_condition(base_condition &&) = default;
    base_condition &operator=(base_condition &&) = default;

    virtual eval_result eval(condition_cache &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
        ddwaf::timer &deadline) const = 0;

    virtual void get_addresses(
        boost::unordered_flat_map<target_index, std::string> &addresses) const = 0;
};

} // namespace ddwaf
