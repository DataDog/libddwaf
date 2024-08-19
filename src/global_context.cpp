// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "global_context.hpp"
#include "rule/rule.hpp"

namespace ddwaf {
void global_context::eval(std::vector<event> &events, const object_store &store, cache_type &cache,
    ddwaf::timer &deadline)
{
    auto timepoint = monotonic_clock::now();

    DDWAF_DEBUG("Evaluating global rules");
    for (const auto &rule : rules_) {
        auto cache_it = cache.find(rule.get());
        if (cache_it == cache.end()) {
            auto [new_it, res] = cache.emplace(rule.get(), base_threshold_rule::cache_type{});
            if (!res) {
                continue;
            }
            cache_it = new_it;
        }
        DDWAF_DEBUG("Evaluating rule {}", rule->get_id());
        auto opt_evt = rule->eval(store, cache_it->second, timepoint, deadline);
        if (opt_evt.has_value()) {
            events.emplace_back(std::move(opt_evt.value()));
        }
    }
}

} // namespace ddwaf
