// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <array>
#include <cstddef>
#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include "builder/module_builder.hpp"
#include "module.hpp"
#include "module_category.hpp"
#include "rule.hpp"

namespace ddwaf {

rule_module rule_module_builder::build()
{
    const auto &sort_fn = [this](const auto *left, const auto *right) {
        const auto lverdict = left->get_verdict();
        const auto rverdict = right->get_verdict();
        const auto lsource = left->get_source();
        const auto rsource = right->get_source();
        std::string_view const lkey = grouping_key_fn_(left);
        std::string_view const rkey = grouping_key_fn_(right);
        return lverdict > rverdict ||
               (lverdict == rverdict && (source_precedence_fn_(lsource, rsource) ||
                                            (lsource == rsource && lkey < rkey)));
    };

    // Sort first
    std::sort(rules_.begin(), rules_.end(), sort_fn);

    // Generate collections by grouping based on the grouping key
    std::string_view prev_key;
    for (std::size_t i = 0; i < rules_.size(); ++i) {
        const auto *rule = rules_[i];
        auto cur_key = grouping_key_fn_(rule);
        if (cur_key != prev_key) {
            if (!collections_.empty()) {
                collections_.back().end = i;
            }
            collections_.emplace_back(cur_key, rule->get_verdict(), i, i + 1);
            prev_key = cur_key;
        }
    }

    if (!collections_.empty()) {
        collections_.back().end = rules_.size();
    }

    return rule_module{std::move(rules_), std::move(collections_)};
}

std::array<rule_module, rule_module_count> rule_module_set_builder::build(
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    const std::vector<std::shared_ptr<core_rule>> &base,
    const std::vector<std::shared_ptr<core_rule>> &user)
{
    std::array<rule_module, rule_module_count> all_modules;

    const auto inserter = [this](const auto &rules) {
        for (const auto &rule : rules) {
            auto &builder = builders_[static_cast<std::size_t>(rule->get_module())];
            builder.insert(rule.get());
        }
    };

    inserter(base);
    inserter(user);

    for (std::size_t i = 0; i < builders_.size(); ++i) { all_modules[i] = builders_[i].build(); }

    return all_modules;
}

} // namespace ddwaf
