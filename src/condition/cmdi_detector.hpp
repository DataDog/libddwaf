// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/structured_condition.hpp"
#include "exclusion/common.hpp"
#include "object.hpp"
#include <array>
#include <string_view>
#include <vector>

namespace ddwaf {

class cmdi_detector : public base_impl<cmdi_detector> {
public:
    static constexpr unsigned version = 1;
    static constexpr std::array<std::string_view, 2> param_names{"resource", "params"};

    explicit cmdi_detector(std::vector<condition_parameter> args);

protected:
    [[nodiscard]] bool eval_impl(const unary_argument<object_view> &resource,
        const variadic_argument<object_view> &params, condition_cache &cache,
        const object_set_ref &objects_excluded, ddwaf::timer &deadline) const;

    friend class base_impl<cmdi_detector>;
};

} // namespace ddwaf
