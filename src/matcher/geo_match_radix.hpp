// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <radixlib.h>
#include <unordered_set>
#include <vector>

#include "ip_utils.hpp"
#include "matcher/base.hpp"

namespace ddwaf::matcher {

class geo_match_radix : public base_impl<geo_match_radix> {
public:
    geo_match_radix() = default;
    geo_match_radix(std::unordered_set<std::string_view> countries,
        const std::vector<std::pair<std::string_view, std::string_view>> &ip_list);

    ~geo_match_radix() override = default;
    geo_match_radix(const geo_match_radix &) = delete;
    geo_match_radix(geo_match_radix &&) = default;
    geo_match_radix &operator=(const geo_match_radix &) = delete;
    geo_match_radix &operator=(geo_match_radix &&) = default;

    [[nodiscard]] bool match_ip(const ipaddr &ip) const;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "geo_match_radix"; }
    static constexpr DDWAF_OBJ_TYPE supported_type_impl() { return DDWAF_OBJ_STRING; }

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
    std::unordered_set<uint8_t> countries_{};

    friend class base_impl<geo_match_radix>;
};

} // namespace ddwaf::matcher
