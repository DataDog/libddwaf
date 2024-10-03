// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <radixlib.h>
#include <vector>

#include "ip_utils.hpp"
#include "matcher/base.hpp"

namespace ddwaf::matcher {

class ip_match : public base_impl<ip_match> {
public:
    using data_type = std::vector<std::pair<std::string_view, uint64_t>>;

    static constexpr std::string_view matcher_name = "ip_match";
    static constexpr std::string_view negated_matcher_name = "!ip_match";

    ip_match() = default;
    explicit ip_match(const std::vector<std::string_view> &ip_list);
    template <std::size_t N>
    explicit ip_match(const std::array<std::string_view, N> &ip_list)
        : rtree_(radix_new(radix_tree_bits), radix_free)
    {
        if (!rtree_) {
            throw std::runtime_error("failed to instantiate radix tree");
        }

        init_tree(ip_list);
    }

    explicit ip_match(const data_type &ip_list);
    ~ip_match() override = default;
    ip_match(const ip_match &) = delete;
    ip_match(ip_match &&) = default;
    ip_match &operator=(const ip_match &) = delete;
    ip_match &operator=(ip_match &&) = default;

    [[nodiscard]] bool match_ip(const ipaddr &ip) const;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(DDWAF_OBJ_TYPE type)
    {
        return type == DDWAF_OBJ_STRING;
    }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view str) const;

    template <typename T> void init_tree(const T &ip_list)
    {
        for (auto str : ip_list) {
            // Parse and populate each IP/network
            ipaddr ip{};
            if (ddwaf::parse_cidr(str, ip)) {
                prefix_t prefix;
                // NOLINTNEXTLINE(hicpp-no-array-decay,cppcoreguidelines-pro-bounds-array-to-pointer-decay)
                radix_prefix_init(FAMILY_IPv6, ip.data, ip.mask, &prefix);
                radix_put_if_absent(rtree_.get(), &prefix, 0);
            }
        }
    }

    static constexpr unsigned radix_tree_bits = 128; // IPv6
    std::unique_ptr<radix_tree_t, decltype(&radix_free)> rtree_{nullptr, nullptr};

    friend class base_impl<ip_match>;
};

} // namespace ddwaf::matcher
