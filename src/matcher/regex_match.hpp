// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <re2/re2.h>
#include <string>
#include <string_view>
#include <utility>

#include "dynamic_string.hpp"
#include "matcher/base.hpp"
#include "matcher/regex_prefilter.hpp"
#include "object_type.hpp"

namespace ddwaf::matcher {

class regex_match : public base_impl<regex_match> {
public:
    static constexpr std::string_view matcher_name = "match_regex";
    static constexpr std::string_view negated_matcher_name = "!match_regex";

    regex_match(const std::string &regex_str, std::size_t minLength, bool case_sensitive);
    ~regex_match() override = default;
    regex_match(const regex_match &) = delete;
    regex_match(regex_match &&other) noexcept = delete;
    regex_match &operator=(const regex_match &) = delete;
    regex_match &operator=(regex_match &&other) noexcept = delete;

    [[nodiscard]] const regex_prefilter *get_prefilter() const override
    {
        return prefilter_built_.load(std::memory_order_acquire) ? prefilter_.get() : nullptr;
    }
    const regex_prefilter *build_prefilter() const override;

protected:
    [[nodiscard]] std::string_view to_string_impl() const { return regex->pattern(); }
    static constexpr bool is_supported_type_impl(object_type type)
    {
        return (type & object_type::string) != 0;
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(std::string_view pattern) const;

    std::shared_ptr<const re2::RE2> regex{nullptr};
    std::size_t min_length;
    // Set once by build_prefilter, and published by prefilter_built_
    mutable std::unique_ptr<regex_prefilter> prefilter_;
    mutable std::atomic<bool> prefilter_built_{false};
    mutable std::mutex prefilter_mutex_;

    friend class base_impl<regex_match>;
};

} // namespace ddwaf::matcher
