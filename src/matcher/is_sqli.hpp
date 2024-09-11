// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <libinjection.h>

#include "matcher/base.hpp"

namespace ddwaf::matcher {

class is_sqli : public base_impl<is_sqli> {
public:
    is_sqli() = default;
    ~is_sqli() override = default;
    is_sqli(const is_sqli &) = delete;
    is_sqli(is_sqli &&) noexcept = default;
    is_sqli &operator=(const is_sqli &) = delete;
    is_sqli &operator=(is_sqli &&) noexcept = default;

protected:
    static constexpr unsigned fingerprint_length = 16;

    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "is_sqli"; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_STRING;
    }

    static std::pair<bool, std::string> match_impl(std::string_view pattern);

    friend class base_impl<is_sqli>;
};

} // namespace ddwaf::matcher
