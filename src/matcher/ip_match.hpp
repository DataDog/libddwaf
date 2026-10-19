// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "dynamic_string.hpp"
#include "expiring_string_list.hpp"
#include "indexed_multivector.hpp"
#include "ip_radix_tree.hpp"
#include "ip_utils.hpp"
#include "matcher/base.hpp"
#include "object_type.hpp"

namespace ddwaf::matcher {

class ip_match : public base_impl<ip_match> {
public:
    using data_type = std::vector<std::pair<std::string, uint64_t>>;

    static constexpr std::string_view matcher_name = "ip_match";
    static constexpr std::string_view negated_matcher_name = "!ip_match";

    ip_match() = default;
    // A list of IPs or CIDR networks which never expire, as given in a rule
    // ("list" parameter) or by the SSRF detector, parsed with parse_cidr
    explicit ip_match(const std::vector<std::string_view> &ip_list);
    template <std::size_t N>
    explicit ip_match(const std::array<std::string_view, N> &ip_list)
        : tree_(build_tree(ip_list, parse_cidr))
    {}

    // Rules or exclusion data (ip_with_expiration): (IP or network,
    // expiration) pairs, parsed with parse_network
    explicit ip_match(
        const indexed_multivector<std::string, std::pair<std::string, uint64_t>> &ip_list);
    explicit ip_match(const indexed_multivector<std::string, expiring_string_list::value_type,
        expiring_string_list> &ip_list);
    explicit ip_match(const data_type &ip_list);
    ~ip_match() override = default;
    ip_match(const ip_match &) = delete;
    ip_match(ip_match &&) = default;
    ip_match &operator=(const ip_match &) = delete;
    ip_match &operator=(ip_match &&) = default;

    [[nodiscard]] bool match_ip(const ipaddr &ip) const;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr bool is_supported_type_impl(object_type type)
    {
        return (type & object_type::string) != 0;
    }

    [[nodiscard]] std::pair<bool, dynamic_string> match_impl(std::string_view str) const;

    // Builds the tree from a list of IPs or CIDR networks, either as plain
    // strings (which never expire) or as (string, expiration) pairs. Entries
    // which can't be parsed are ignored.
    template <typename T, typename Parser>
    static ip_radix_tree build_tree(const T &ip_list, Parser &&parse)
    {
        ip_radix_tree::builder builder;
        builder.reserve(ip_list.size());
        for (const auto &item : ip_list) {
            std::string_view str;
            uint64_t expiration = 0;
            if constexpr (std::is_convertible_v<decltype(item), std::string_view>) {
                str = item;
            } else {
                str = item.first;
                expiration = item.second;
            }

            ipaddr ip{};
            if (parse(str, ip)) {
                builder.insert(ip, expiration);
            }
        }
        return builder.build();
    }

    ip_radix_tree tree_;

    friend class base_impl<ip_match>;
};

} // namespace ddwaf::matcher
