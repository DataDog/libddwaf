// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <unordered_map>

#include "rule.hpp"

namespace ddwaf {

class global_context {
public:
    using local_cache_type = std::unordered_map<base_rule*, expression::cache_type>;

    global_context() = default;
    global_context(const global_context &) = delete;
    global_context &operator=(const global_context &) = delete;
    global_context(global_context &&) = default;
    global_context &operator=(global_context &&) = delete;
    ~global_context() = default;

    void eval(std::vector<event> &events, const object_store &store,
        local_cache_type &lcache, ddwaf::timer &deadline) const;

protected:
    using global_cache_variants = std::variant<threshold_rule::global_cache_type, indexed_threshold_rule::global_cache_type>;

    std::vector<std::shared_ptr<base_rule>> rules_;
    std::unordered_map<base_rule*, global_cache_variants> rule_cache_{};
};

}
