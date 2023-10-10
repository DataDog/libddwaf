// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>
#include <stack>
#include <vector>

#include <clock.hpp>
#include <object_store.hpp>
#include <rule.hpp>

namespace ddwaf::exclusion {

enum class filter_mode { bypass, monitor };

class rule_filter {
public:
    struct excluded_set {
        const std::unordered_set<rule *> &rules;
        bool ephemeral{false};
    };

    using cache_type = expression::cache_type;

    rule_filter(std::string id, std::shared_ptr<expression> expr, std::set<rule *> rule_targets,
        filter_mode mode = filter_mode::bypass);
    rule_filter(const rule_filter &) = delete;
    rule_filter &operator=(const rule_filter &) = delete;
    rule_filter(rule_filter &&) = default;
    rule_filter &operator=(rule_filter &&) = default;
    virtual ~rule_filter() = default;

    virtual std::optional<excluded_set> match(
        const object_store &store, cache_type &cache, ddwaf::timer &deadline) const;

    std::string_view get_id() const { return id_; }
    filter_mode get_mode() const { return mode_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        expr_->get_addresses(addresses);
    }

protected:
    std::string id_;
    std::shared_ptr<expression> expr_;
    std::unordered_set<rule *> rule_targets_;
    filter_mode mode_;
};

} // namespace ddwaf::exclusion
