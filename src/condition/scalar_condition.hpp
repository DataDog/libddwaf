// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"

namespace ddwaf {

class scalar_condition : public base_condition {
public:
    scalar_condition(std::unique_ptr<matcher::base> &&matcher, std::string data_id,
        std::vector<condition_parameter> args)
        : matcher_(std::move(matcher)), data_id_(std::move(data_id))
    {
        if (args.size() > 1) {
            throw std::invalid_argument("Matcher initialised with more than one argument");
        }

        if (args.empty()) {
            throw std::invalid_argument("Matcher initialised without arguments");
        }

        targets_ = std::move(args[0].targets);
    }

    eval_result eval(condition_cache &cache, const object_store &store,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline) const override;

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const override
    {
        for (const auto &target : targets_) { addresses.emplace(target.index, target.name); }
    }

    static constexpr auto arguments()
    {
        return std::array<parameter_specification, 1>{{{"inputs", true, false}}};
    }

protected:
    [[nodiscard]] const matcher::base *get_matcher(
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers)
        const;

    std::unique_ptr<matcher::base> matcher_;
    std::string data_id_;
    std::vector<condition_target> targets_;
};

} // namespace ddwaf
