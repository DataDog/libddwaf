// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "context_allocator.hpp"
#include "event.hpp"
#include "rule.hpp"

#include <vector>

// Modules:
//   - Network-ACL:
//      - Order:
//          blocking
//          non-blocking
//      - Short-circuit: rule match
//      - No timing
//   - Authentication-ACL:
//      - Order:
//          blocking
//          non-blocking
//      - Short-circuit: rule match
//      - No timing
//   - Custom-ACL:
//      - Order:
//          blocking user rules
//          blocking datadog rules
//          non-blocking user
//          non-blocking datadog rules
//      - Short-circuit: rule match
//      - Timed
//   - Configuration:
//      - Order:
//          blocking user rules
//          blocking datadog rules
//          non-blocking user
//          non-blocking datadog rules
//      - Short-circuit: rule match
//      - Timed
//   - Business logic:
//      - Order:
//          blocking user rules
//          blocking datadog rules
//          non-blocking user
//          non-blocking datadog rules
//      - Short-circuit: rule match
//      - Timed
//   - RASP:
//      - Order:
//          blocking datadog rules
//          blocking user rules
//          non-blocking datadog rules
//          non-blocking user
//      - Short-circuit: rule match
//      - Timed
//   - WAF:
//      - Order:
//          blocking datadog rules
//          blocking user rules
//          non-blocking datadog rules
//          non-blocking user
//      - Short-circuit: rule match, but only rules of the same type (collections)
//      - Timed

namespace ddwaf {

struct rule_collection_cache {
    action_type type{action_type::none};
    bool ephemeral{false};
};

struct module_cache {
    memory::unordered_map<std::string_view, rule_collection_cache> collections;
    memory::vector<core_rule::cache_type> rules;

    //[[nodiscard]] bool empty() const { return collections.empty(); }
};

class base_module {
public:
    base_module() = default;
    virtual ~base_module() = default;
    base_module(const base_module &) = default;
    base_module(base_module &&) noexcept = default;
    base_module &operator=(const base_module &) = default;
    base_module &operator=(base_module &&) noexcept = default;

    virtual void init_cache(module_cache &cache) const = 0;

    virtual void eval(std::vector<event> &events, object_store &store, module_cache &cache,
        const exclusion::context_policy &exclusion,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const = 0;
};

class rule_module : public base_module {
public:
    using cache_type = module_cache;
    using iterator = std::vector<core_rule *>::iterator;
    using const_iterator = std::vector<core_rule *>::const_iterator;

    rule_module() = default;
    ~rule_module() override = default;
    rule_module(const rule_module &) = default;
    rule_module(rule_module &&) noexcept = default;
    rule_module &operator=(const rule_module &) = default;
    rule_module &operator=(rule_module &&) noexcept = default;

    void init_cache(module_cache &cache) const override { cache.rules.resize(rules_.size()); }

    void eval(std::vector<event> &events, object_store &store, module_cache &cache,
        const exclusion::context_policy &exclusion,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const override;

protected:
    explicit rule_module(std::vector<core_rule *> &&rules) : rules_(std::move(rules)) {}

    std::vector<core_rule *> rules_;

    template <typename T, typename PrecedenceOrder> friend class module_builder;
};

class rule_collection_module : public base_module {
public:
    using cache_type = module_cache;
    using iterator = std::vector<core_rule *>::iterator;
    using const_iterator = std::vector<core_rule *>::const_iterator;

    rule_collection_module() = default;
    ~rule_collection_module() override = default;
    rule_collection_module(const rule_collection_module &) = default;
    rule_collection_module(rule_collection_module &&) noexcept = default;
    rule_collection_module &operator=(const rule_collection_module &) = default;
    rule_collection_module &operator=(rule_collection_module &&) noexcept = default;

    void init_cache(module_cache &cache) const override { cache.rules.resize(rules_.size()); }

    void eval(std::vector<event> &events, object_store &store, module_cache &cache,
        const exclusion::context_policy &exclusion,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const override;

protected:
    struct rule_collection {
        std::string_view name;
        std::vector<core_rule *> rules;
    };

    explicit rule_collection_module(std::vector<core_rule *> &&rules) : rules_(std::move(rules)) {}

    std::vector<core_rule *> rules_;

    template <typename T, typename PrecedenceOrder> friend class module_builder;
};

} // namespace ddwaf
