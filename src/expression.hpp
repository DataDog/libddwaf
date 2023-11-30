// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "clock.hpp"
#include "condition/base.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf {

class expression {
public:
    struct cache_type {
        bool result{false};
        memory::vector<condition::cache_type> conditions;
    };

    expression() = default;

    explicit expression(std::vector<std::unique_ptr<condition::base>> &&conditions,
        ddwaf::object_limits limits = {})
        : limits_(limits), conditions_(std::move(conditions))
    {}

    eval_result eval(cache_type &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const;

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        for (const auto &cond : conditions_) { cond->get_addresses(addresses); }
    }

    static std::vector<event::match> get_matches(cache_type &cache)
    {
        std::vector<event::match> matches;
        matches.reserve(cache.conditions.size());
        for (auto &cond_cache : cache.conditions) {
            auto &match = cond_cache.match;
            if (match.has_value()) {
                if (match->ephemeral) {
                    matches.emplace_back(std::move(match.value()));
                } else {
                    matches.emplace_back(match.value());
                }
            }
        }
        return matches;
    }

    static bool get_result(cache_type &cache) { return cache.result; }

    [[nodiscard]] bool empty() const { return conditions_.empty(); }
    [[nodiscard]] std::size_t size() const { return conditions_.size(); }

protected:
    ddwaf::object_limits limits_;
    std::vector<std::unique_ptr<condition::base>> conditions_;
};

} // namespace ddwaf
