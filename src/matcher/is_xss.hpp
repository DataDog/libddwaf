// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <libinjection.h>
#include <matcher/base.hpp>

namespace ddwaf::matcher {

class is_xss : public base_impl<is_xss> {
public:
    is_xss() = default;
    ~is_xss() override = default;
    is_xss(const is_xss &) = delete;
    is_xss(is_xss &&) noexcept = default;
    is_xss &operator=(const is_xss &) = delete;
    is_xss &operator=(is_xss &&) noexcept = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "is_xss"; }
    static constexpr DDWAF_OBJ_TYPE supported_type_impl() { return DDWAF_OBJ_STRING; }

    static std::pair<bool, std::string> match_impl(std::string_view pattern);

    friend class base_impl<is_xss>;
};

} // namespace ddwaf::matcher
