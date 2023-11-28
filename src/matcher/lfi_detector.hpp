// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <type_traits>
#include <unordered_map>

#include "matcher/base.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

class lfi_detector : public structured_base_impl<lfi_detector> {
public:
    lfi_detector() = default;
    ~lfi_detector() override = default;
    lfi_detector(const lfi_detector &) = delete;
    lfi_detector(lfi_detector &&) noexcept = default;
    lfi_detector &operator=(const lfi_detector &) = delete;
    lfi_detector &operator=(lfi_detector &&) noexcept = default;

protected:
    static constexpr std::string_view name_impl() { return "lfi_detector"; }
    static constexpr std::string_view to_string_impl() { return ""; }

    static constexpr unsigned arity_impl() { return 2; }
    static constexpr std::vector<std::string_view> arguments_impl() { return {"path", "query"}; }

    [[nodiscard]] static std::tuple<bool, std::string, std::size_t> match_impl(
        const std::vector<optional_ref<const ddwaf_object>> &args);

    friend class structured_base_impl<lfi_detector>;
};

} // namespace ddwaf::matcher
