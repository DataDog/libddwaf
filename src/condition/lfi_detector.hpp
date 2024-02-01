// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"

namespace ddwaf::condition {

class lfi_detector : public base_impl<lfi_detector> {
public:
    using param_types =
        std::tuple<unary_argument<std::string_view>, variadic_argument<const ddwaf_object *>>;
    static constexpr std::array<std::string_view, 2> param_names{"resource", "params"};

    explicit lfi_detector(std::vector<argument_definition> args)
        : base_impl<lfi_detector>(std::move(args))
    {}

protected:
    [[nodiscard]] eval_result eval_impl(const unary_argument<std::string_view> &path,
        const variadic_argument<const ddwaf_object *> &params,
        std::reference_wrapper<cache_type> cache, std::reference_wrapper<timer> deadline) const;

    friend class base_impl<lfi_detector>;
};

} // namespace ddwaf::condition
