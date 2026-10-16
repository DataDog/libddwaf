// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "clock.hpp"
#include "context_allocator.hpp"
#include "exclusion/common.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace ddwaf {

struct rule_collection_cache {
    core_rule::verdict_type type{core_rule::verdict_type::none};
};

struct rule_module_cache {
    // Number of rules represented by each word of the pending bitset
    static constexpr std::size_t pending_word_bits = 64;

    memory::vector<core_rule::cache_type> rules;
    memory::unordered_map<std::string_view, rule_collection_cache> collections;
    // Bitset with one bit per rule, in module order, flagging the rules which
    // need to be evaluated: initially all of them, then only those referencing
    // a target updated since their last evaluation. Evaluating a rule again on
    // the same targets can't produce a different outcome, as condition caches
    // and exclusions only accumulate. A bit is cleared once the evaluation of
    // its rule completes, so a rule interrupted by a timeout, or left behind
    // by an earlier match or block, remains pending.
    memory::vector<uint64_t> pending;
};

class rule_module {
public:
    using verdict_type = core_rule::verdict_type;
    using cache_type = rule_module_cache;
    using iterator = std::vector<core_rule *>::iterator;
    using const_iterator = std::vector<core_rule *>::const_iterator;

    enum class expiration_policy : uint8_t {
        expiring,
        non_expiring,
    };

    rule_module() = default;
    ~rule_module() = default;
    rule_module(const rule_module &) = default;
    rule_module(rule_module &&) noexcept = default;
    rule_module &operator=(const rule_module &) = default;
    rule_module &operator=(rule_module &&) noexcept = default;

    void init_cache(cache_type &cache) const
    {
        cache.rules.resize(rules_.size());
        cache.collections.reserve(collections_.size());

        // Every rule of a new cache must be evaluated at least once, whereas a
        // cache inherited from a context (i.e. by a subcontext) is left as is.
        constexpr auto word_bits = cache_type::pending_word_bits;
        const auto words = (rules_.size() + word_bits - 1) / word_bits;
        if (cache.pending.size() != words) {
            cache.pending.assign(words, ~uint64_t{0});
            if (const auto remainder = rules_.size() % word_bits; remainder != 0) {
                cache.pending.back() = (uint64_t{1} << remainder) - 1;
            }
        }
    }

    [[nodiscard]] bool may_expire() const { return policy_ == expiration_policy::expiring; }

    // Rules in evaluation order, the position of each rule corresponds to its
    // bit in the pending bitset of the cache
    [[nodiscard]] std::span<const core_rule *const> get_rules() const { return rules_; }

    // Evaluates the rules flagged in the pending bitset of the cache, in order
    verdict_type eval(std::vector<rule_result> &results, object_store &store, cache_type &cache,
        const exclusion_policy &exclusion, const matcher_mapper &dynamic_matchers,
        ddwaf::timer &deadline) const;

protected:
    verdict_type eval_with_collections(std::vector<rule_result> &results, object_store &store,
        cache_type &cache, const exclusion_policy &exclusion,
        const matcher_mapper &dynamic_matchers, ddwaf::timer &deadline) const;

    ddwaf::timer &get_deadline(ddwaf::timer &deadline) const;

    struct rule_collection {
        std::string_view name;
        verdict_type type;
        std::size_t begin;
        std::size_t end;
    };

    explicit rule_module(std::vector<const core_rule *> &&rules,
        std::vector<rule_collection> &&collections,
        expiration_policy policy = expiration_policy::expiring)
        : rules_(std::move(rules)), collections_(std::move(collections)), policy_(policy)
    {}

    std::vector<const core_rule *> rules_;
    std::vector<rule_collection> collections_;
    expiration_policy policy_{expiration_policy::expiring};

    friend class rule_module_builder;
};

} // namespace ddwaf
