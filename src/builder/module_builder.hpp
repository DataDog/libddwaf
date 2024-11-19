// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "module.hpp"
#include "rule.hpp"

namespace ddwaf {

struct user_rule_precedence {
    bool operator()(const core_rule *left, const core_rule *right) const
    {
        const auto left_mode = left->get_blocking_mode();
        const auto right_mode = right->get_blocking_mode();

        const auto left_source = left->get_source();
        const auto right_source = right->get_source();

        return (left_mode > right_mode) || (left_mode == right_mode && left_source > right_source);
    }
};

struct base_rule_precedence {
    bool operator()(const core_rule *left, const core_rule *right) const
    {
        const auto left_mode = left->get_blocking_mode();
        const auto right_mode = right->get_blocking_mode();

        const auto left_source = left->get_source();
        const auto right_source = right->get_source();

        return (left_mode > right_mode) || (left_mode == right_mode && left_source < right_source);
    }
};

struct rule_collection_precedence {
    bool operator()(const core_rule *left, const core_rule *right) const
    {
        const auto left_type = left->get_type();
        const auto right_type = right->get_type();

        const auto type_cmp = left_type.compare(right_type);

        const auto left_mode = left->get_blocking_mode();
        const auto right_mode = right->get_blocking_mode();

        return type_cmp < 0 ||
               (type_cmp == 0 &&
                   (left_mode > right_mode ||
                       (left_mode == right_mode && left->get_source() > right->get_source())));
    }
};

template <typename T, typename PrecedenceOrder> class module_builder {
public:
    void insert(core_rule *rule) { rules_.emplace_back(rule); }

    T build()
    {
        std::sort(rules_.begin(), rules_.end(), PrecedenceOrder{});
        return T{std::move(rules_)};
    }

protected:
    std::vector<core_rule *> rules_;
};

} // namespace ddwaf
