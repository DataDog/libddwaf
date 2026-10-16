// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "module.hpp"
#include "module_category.hpp"
#include "rule.hpp"
#include "target_address.hpp"

namespace ddwaf {

// Maps each target to the rules which reference it, so that the evaluation
// engine can flag as pending only the rules which may produce a different
// outcome after a target is updated (see rule_module_cache::pending), rather
// than evaluating every rule each time.
//
// Rules are referred to in groups of up to 64 rules from the same module,
// matching a single word of the module's pending bitset.
class rule_target_index {
public:
    struct rule_set {
        uint32_t module;
        uint32_t word;
        uint64_t mask;

        bool operator==(const rule_set &) const = default;
    };

    rule_target_index() = default;
    explicit rule_target_index(const std::array<rule_module, rule_module_count> &modules);

    // Returns the rules referencing the target, the result is empty if, and
    // only if, the target isn't referenced by any rule.
    [[nodiscard]] std::span<const rule_set> find(target_index target) const
    {
        if (slots_.empty()) {
            return {};
        }

        const auto &slot = slots_[probe(target)];
        return {rule_sets_.data() + slot.begin, rule_sets_.data() + slot.end};
    }

    // Rules which have to be evaluated every time, as their outcome doesn't
    // depend on any target (i.e. rules without conditions).
    [[nodiscard]] std::span<const rule_set> unconditional_rules() const { return unconditional_; }

    // Whether the index applies to the given modules, i.e. whether they contain
    // the same rules in the same order as those the index was built from. Rules
    // are identified by address, so the index must not outlive its rules.
    [[nodiscard]] bool is_valid_for(
        const std::array<rule_module, rule_module_count> &modules) const;

protected:
    // Open addressing table with linear probing, keyed by the target index
    // (which is already a hash), a slot with begin == end is empty.
    struct slot {
        target_index target{0};
        uint32_t begin{0};
        uint32_t end{0};
    };

    // Returns the slot of the target, or the empty slot where it would be inserted
    [[nodiscard]] std::size_t probe(target_index target) const
    {
        auto i = target & slot_mask_;
        while (slots_[i].begin != slots_[i].end && slots_[i].target != target) {
            i = (i + 1) & slot_mask_;
        }
        return i;
    }

    std::vector<slot> slots_;
    std::size_t slot_mask_{0};
    std::vector<rule_set> rule_sets_;
    std::vector<rule_set> unconditional_;
    // Fingerprint of the rules of each module the index was built from
    std::array<std::size_t, rule_module_count> layout_{};
};

} // namespace ddwaf
