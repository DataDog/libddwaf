// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/base.hpp"
#include "utils.hpp"

namespace ddwaf {

enum class data_source : uint8_t { values, keys, object };

struct condition_cache {
    // The targets cache mirrors the array of targets for the given condition.
    // Each element in this array caches the pointer of the last non-ephemeral
    // object evaluated by the target in the same index within the condition.
    memory::vector<const ddwaf_object *> targets;
    event::match match;
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
struct target_definition {
    std::string name;
    target_index root{};
    std::vector<std::string> key_path{};
    std::vector<transformer_id> transformers{};
    data_source source{data_source::values};
};

// Provides the definition of a parameter, which essentially consists of all the
// mappings available for it. If the parameter is non-variadic, only one mapping
// should be present.
struct parameter_definition {
    std::vector<target_definition> targets;
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
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline) const = 0;

    virtual void get_addresses(std::unordered_map<target_index, std::string> &addresses) const = 0;
};

} // namespace ddwaf
