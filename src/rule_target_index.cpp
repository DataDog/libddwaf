// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "module.hpp"
#include "module_category.hpp"
#include "rule_target_index.hpp"
#include "target_address.hpp"

namespace ddwaf {

namespace {

// Rules are added in module and position order, so a rule can only belong
// to the last set of the list, if any.
void add_rule(std::vector<rule_target_index::rule_set> &sets, rule_target_index::rule_set rule)
{
    if (!sets.empty() && sets.back().module == rule.module && sets.back().word == rule.word) {
        sets.back().mask |= rule.mask;
    } else {
        sets.emplace_back(rule);
    }
}

// Identifies the rules of a module and their order
std::size_t fingerprint(const rule_module &module)
{
    constexpr std::size_t prime = 1099511628211ULL;
    const auto rules = module.get_rules();
    std::size_t value = rules.size();
    for (const auto *rule : rules) { value = (value * prime) ^ std::bit_cast<uintptr_t>(rule); }
    return value;
}

} // namespace

rule_target_index::rule_target_index(const std::array<rule_module, rule_module_count> &modules)
{
    constexpr auto word_bits = rule_module_cache::pending_word_bits;

    std::map<target_index, std::vector<rule_set>> rules_by_target;
    std::unordered_map<target_index, std::string> addresses;
    for (std::size_t m = 0; m < modules.size(); ++m) {
        layout_[m] = fingerprint(modules[m]);

        const auto rules = modules[m].get_rules();
        for (std::size_t i = 0; i < rules.size(); ++i) {
            const rule_set rule{.module = static_cast<uint32_t>(m),
                .word = static_cast<uint32_t>(i / word_bits),
                .mask = uint64_t{1} << (i % word_bits)};

            if (!rules[i]->has_conditions()) {
                add_rule(unconditional_, rule);
            }

            // This includes the targets used for attributes, which have no
            // bearing on the outcome of the rule, so that a target is indexed
            // if, and only if, it's one of the ruleset's rule addresses.
            addresses.clear();
            rules[i]->get_addresses(addresses);
            for (const auto &[target, name] : addresses) {
                add_rule(rules_by_target[target], rule);
            }
        }
    }

    if (rules_by_target.empty()) {
        return;
    }

    // Keep the load factor at or below 50%, so that probing remains short and
    // there is always at least one empty slot to end it.
    const auto capacity = std::bit_ceil(rules_by_target.size() * 2);
    slots_.resize(capacity);
    slot_mask_ = capacity - 1;

    for (const auto &[target, sets] : rules_by_target) {
        auto &slot = slots_[probe(target)];
        slot = {.target = target,
            .begin = static_cast<uint32_t>(rule_sets_.size()),
            .end = static_cast<uint32_t>(rule_sets_.size() + sets.size())};
        rule_sets_.insert(rule_sets_.end(), sets.begin(), sets.end());
    }
}

bool rule_target_index::is_valid_for(
    const std::array<rule_module, rule_module_count> &modules) const
{
    for (std::size_t m = 0; m < modules.size(); ++m) {
        if (layout_[m] != fingerprint(modules[m])) {
            return false;
        }
    }
    return true;
}

} // namespace ddwaf
