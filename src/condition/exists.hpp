// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/structured_condition.hpp"
#include "exception.hpp"
#include "iterator.hpp"

namespace ddwaf {

class exists_condition : public base_impl<exists_condition> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    explicit exists_condition(std::vector<condition_parameter> args)
        : base_impl<exists_condition>(std::move(args))
    {}

protected:
    [[nodiscard]] eval_result eval_impl(const variadic_argument<optional_object_view> &inputs,
        condition_cache &cache, const exclusion::object_set_ref &objects_excluded,
        const object_limits &limits, ddwaf::timer &deadline) const;

    friend class base_impl<exists_condition>;
};

class exists_negated_condition : public base_impl<exists_negated_condition> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    explicit exists_negated_condition(std::vector<condition_parameter> args)
        : base_impl<exists_negated_condition>(std::move(args))
    {}

protected:
    [[nodiscard]] eval_result eval_impl(const unary_argument<optional_object_view> &input,
        condition_cache &cache, const exclusion::object_set_ref &objects_excluded,
        const object_limits &limits, ddwaf::timer & /*deadline*/) const;

    friend class base_impl<exists_negated_condition>;
};

} // namespace ddwaf
