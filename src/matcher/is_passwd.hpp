// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string_view>
#include <string_checker.h>

#include "matcher/base.hpp"

namespace ddwaf::matcher {

class is_passwd : public base_impl<is_passwd> {
public:
    is_passwd() = default;
    ~is_passwd() override = default;
    is_passwd(const is_passwd &) = default;
    is_passwd(is_passwd &&) noexcept = default;
    is_passwd &operator=(const is_passwd &) = default;
    is_passwd &operator=(is_passwd &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "is_passwd"; }

    static constexpr DDWAF_OBJ_TYPE supported_type_impl()
    {
        return DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view obtained) const
    {
        return {check_string(obtained.data()), std::string{obtained}} ;
    }

    friend class base_impl<is_passwd>;
};

} // namespace ddwaf::matcher
