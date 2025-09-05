// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "condition/base.hpp"
#include "context_allocator.hpp"
#include "exclusion/common.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "utils.hpp"

namespace ddwaf {

class expression {
public:
    struct cache_type {
        bool result{false};
        evaluation_scope scope;
        memory::vector<condition_cache> conditions;
    };

    expression() = default;

    explicit expression(std::vector<std::unique_ptr<base_condition>> &&conditions)
        : conditions_(std::move(conditions))
    {}

    eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
        evaluation_scope scope, ddwaf::timer &deadline) const;

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        for (const auto &cond : conditions_) { cond->get_addresses(addresses); }
    }

    static std::vector<condition_match> get_matches(cache_type &cache, evaluation_scope scope = {})
    {
        std::vector<condition_match> matches;
        matches.reserve(cache.conditions.size());
        for (auto &cond_cache : cache.conditions) {
            if (cond_cache.match.has_value() &&
                cond_cache.match->scope.has_higher_precedence_or_is_equal_to(scope)) {
                matches.emplace_back(cond_cache.match.value());
            }
        }
        return matches;
    }

    static bool get_result(cache_type &cache, evaluation_scope scope)
    {
        return cache.scope.has_higher_precedence_or_is_equal_to(scope) && cache.result;
    }

    [[nodiscard]] bool empty() const { return conditions_.empty(); }
    [[nodiscard]] std::size_t size() const { return conditions_.size(); }

protected:
    std::vector<std::unique_ptr<base_condition>> conditions_;
};

} // namespace ddwaf
