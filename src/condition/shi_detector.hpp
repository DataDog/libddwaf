// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/structured_condition.hpp"

namespace ddwaf {

class shi_detector : public base_impl<shi_detector> {
public:
    static constexpr unsigned version = 1;
    static constexpr std::array<std::string_view, 2> param_names{"resource", "params"};

    explicit shi_detector(std::vector<condition_parameter> args);

protected:
    [[nodiscard]] bool eval_impl(const unary_argument<object_view> &resource,
        const variadic_argument<object_view> &params, condition_cache &cache,
        const object_set_ref &objects_excluded, ddwaf::timer &deadline) const;

    [[nodiscard]] static bool eval_string(const unary_argument<object_view> &resource,
        const variadic_argument<object_view> &params, condition_cache &cache,
        const object_set_ref &objects_excluded, ddwaf::timer &deadline);

    [[nodiscard]] static bool eval_array(const unary_argument<object_view> &resource,
        const variadic_argument<object_view> &params, condition_cache &cache,
        const object_set_ref &objects_excluded, ddwaf::timer &deadline);

    friend class base_impl<shi_detector>;
};

} // namespace ddwaf
