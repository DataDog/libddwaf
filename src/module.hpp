// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "rule.hpp"

#include <vector>

namespace ddwaf {

struct rule_collection_cache {
    core_rule::verdict_type type{core_rule::verdict_type::none};
    evaluation_scope scope;
};

struct rule_module_cache {
    memory::vector<core_rule::cache_type> rules;
    memory::unordered_map<std::string_view, rule_collection_cache> collections;
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
    }

    [[nodiscard]] bool may_expire() const { return policy_ == expiration_policy::expiring; }

    verdict_type eval(std::vector<rule_result> &results, object_store &store, cache_type &cache,
        const exclusion::exclusion_policy &exclusion, const matcher_mapper &dynamic_matchers,
        ddwaf::timer &deadline) const;

    static void invalidate_subcontext_cache(cache_type &cache)
    {
        for (auto &rule_cache : cache.rules) { core_rule::invalidate_subcontext_cache(rule_cache); }
        for (auto &[_, collection_cache] : cache.collections) {
            if (collection_cache.scope.is_subcontext()) {
                collection_cache = {};
            }
        }
    }

protected:
    verdict_type eval_with_collections(std::vector<rule_result> &results, object_store &store,
        cache_type &cache, const exclusion::exclusion_policy &exclusion,
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
