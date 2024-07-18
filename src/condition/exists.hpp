// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/structured_condition.hpp"

namespace ddwaf {

class exists_condition : public base_impl<exists_condition> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    explicit exists_condition(
        std::vector<condition_parameter> args, const object_limits &limits = {})
        : base_impl<exists_condition>(std::move(args), limits)
    {}

protected:
    [[nodiscard]] eval_result eval_impl(const variadic_argument<const ddwaf_object *> &inputs,
        condition_cache &cache, const exclusion::object_set_ref & /*objects_excluded*/,
        ddwaf::timer & /*deadline*/) const
    {
        if (inputs.empty()) {
            return {false, false};
        }
        // We only care about the first input
        auto input = inputs.front();
        cache.match = {{{{"input", {}, input.address, {}}}, {}, "exists", {}, input.ephemeral}};
        return {true, input.ephemeral};
    }

    friend class base_impl<exists_condition>;
};

} // namespace ddwaf
