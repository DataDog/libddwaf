// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <memory>
#include <re2/re2.h>
#include <string>
#include <string_view>
#include <utility>

#include "checksum/base.hpp"
#include "dynamic_string.hpp"
#include "matcher/base.hpp"
#include "object_type.hpp"

namespace ddwaf::matcher {

class regex_match_with_checksum : public base_impl<regex_match_with_checksum> {
public:
    static constexpr std::string_view matcher_name = "match_regex_with_checksum";
    static constexpr std::string_view negated_matcher_name = "!match_regex_with_checksum";

    regex_match_with_checksum(const std::string &regex_str, std::size_t minLength,
        bool case_sensitive, std::unique_ptr<base_checksum> &&algo);
    ~regex_match_with_checksum() override = default;
    regex_match_with_checksum(const regex_match_with_checksum &) = delete;
    regex_match_with_checksum(regex_match_with_checksum &&) noexcept = default;
    regex_match_with_checksum &operator=(const regex_match_with_checksum &) = delete;
    regex_match_with_checksum &operator=(regex_match_with_checksum &&) noexcept = default;

protected:
    [[nodiscard]] std::string_view to_string_impl() const { return regex->pattern(); }
    static constexpr bool is_supported_type_impl(object_type type)
    {
        return (type & object_type::string) != 0;
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(std::string_view pattern) const;

    std::unique_ptr<re2::RE2> regex{nullptr};
    std::size_t min_length;

    std::unique_ptr<base_checksum> algo_;

    friend class base_impl<regex_match_with_checksum>;
};

} // namespace ddwaf::matcher
