// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include "clock.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule.hpp"
#include "target_address.hpp"

namespace ddwaf {

class rule_filter {
public:
    struct excluded_set {
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
        const std::unordered_set<const core_rule *> &rules;
        filter_mode mode{filter_mode::none};
        std::string_view action;
    };

    using cache_type = expression::cache_type;

    rule_filter(std::string id, std::shared_ptr<expression> expr,
        std::set<const core_rule *> rule_targets, filter_mode mode = filter_mode::bypass,
        std::string action = {});
    rule_filter(const rule_filter &) = delete;
    rule_filter &operator=(const rule_filter &) = delete;
    rule_filter(rule_filter &&) = default;
    rule_filter &operator=(rule_filter &&) = default;
    ~rule_filter() = default;

    std::optional<excluded_set> match(const object_store &store, cache_type &cache,
        const matcher_mapper &dynamic_matchers, timer &deadline) const;

    std::string_view get_id() const { return id_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        expr_->get_addresses(addresses);
    }

    std::string_view get_action() const { return action_; }

protected:
    std::string id_;
    std::shared_ptr<expression> expr_;
    std::unordered_set<const core_rule *> rule_targets_;
    filter_mode mode_;
    std::string action_;
};

} // namespace ddwaf
