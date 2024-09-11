// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <re2/re2.h>

#include "matcher/base.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

class regex_match : public base_impl<regex_match> {
public:
    static constexpr std::string_view matcher_name = "match_regex";

    regex_match(const std::string &regex_str, std::size_t minLength, bool case_sensitive);
    ~regex_match() override = default;
    regex_match(const regex_match &) = delete;
    regex_match(regex_match &&) noexcept = default;
    regex_match &operator=(const regex_match &) = delete;
    regex_match &operator=(regex_match &&) noexcept = default;

protected:
    [[nodiscard]] std::string_view to_string_impl() const { return regex->pattern(); }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view pattern) const;

    static constexpr int max_match_count = 16;
    std::unique_ptr<re2::RE2> regex{nullptr};
    std::size_t min_length;

    friend class base_impl<regex_match>;
};

} // namespace ddwaf::matcher
