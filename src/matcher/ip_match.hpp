// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ip_utils.hpp>
#include <matcher/base.hpp>
#include <memory>
#include <radixlib.h>

namespace ddwaf::matcher {

class ip_match : public base_impl<ip_match> {
public:
    using rule_data_type = std::vector<std::pair<std::string_view, uint64_t>>;

    ip_match() = default;
    explicit ip_match(const std::vector<std::string_view> &ip_list);
    explicit ip_match(const rule_data_type &ip_list);
    ~ip_match() override = default;
    ip_match(const ip_match &) = delete;
    ip_match(ip_match &&) = default;
    ip_match &operator=(const ip_match &) = delete;
    ip_match &operator=(ip_match &&) = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "ip_match"; }
    static constexpr DDWAF_OBJ_TYPE supported_type_impl() { return DDWAF_OBJ_STRING; }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view str) const;

    static constexpr unsigned radix_tree_bits = 128; // IPv6
    std::unique_ptr<radix_tree_t, decltype(&radix_free)> rtree_{nullptr, nullptr};

    friend class base_impl<ip_match>;
};

} // namespace ddwaf::matcher
