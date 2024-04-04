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
    using cache_type = std::unordered_map<base_threshold_rule *, base_threshold_rule::cache_type>;

    explicit global_context(std::vector<std::unique_ptr<base_threshold_rule>> rules)
        : rules_(std::move(rules))
    {}
    global_context(const global_context &) = delete;
    global_context &operator=(const global_context &) = delete;
    global_context(global_context &&) = default;
    global_context &operator=(global_context &&) = delete;
    ~global_context() = default;

    void eval(std::vector<event> &events, const object_store &store, cache_type &lcache,
        ddwaf::timer &deadline);

protected:
    std::vector<std::unique_ptr<base_threshold_rule>> rules_;
};

} // namespace ddwaf
