// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/structured_condition.hpp"
#include "exclusion/common.hpp"
#include "matcher/ip_match.hpp"
#include "utils.hpp"
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace ddwaf {

struct ssrf_opts {
    bool authority_inspection{true};
    bool path_inspection{false};
    bool query_inspection{false};
    bool forbid_full_url_injection{false};
    bool enforce_policy_without_injection{false};
};

class ssrf_detector : public base_impl<ssrf_detector> {
public:
    static constexpr std::array<std::string_view, 10> default_forbidden_ips{"169.254.0.0/16",
        "127.0.0.1/32", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "::1/128",
        "fc00::/7", "fe80::/10", "2001:db8:1234:1a00::/56"};

    static constexpr std::array<std::string_view, 8> default_forbidden_domains{"metadata.google",
        "burpcollaborator.net", ".local", ".internal", "ram.aliyuncs.com", "ifconfig.pro",
        "localhost", "localtest.me"};

    static constexpr std::array<std::string_view, 4> default_allowed_schemes{
        "https", "http", "ftps", "ftp"};

    static constexpr unsigned version = 3;
    static constexpr std::array<std::string_view, 2> param_names{"resource", "params"};

    explicit ssrf_detector(std::vector<condition_parameter> args);
    ssrf_detector(std::vector<condition_parameter> args, const ssrf_opts &opts,
        std::vector<std::string> &&allowed_schemes, std::vector<std::string> &&forbidden_domains,
        const std::vector<std::string_view> &forbidden_ips);

    // Setters for testing
    void set_opts(const ssrf_opts &opts) { opts_ = opts; }

    void set_allowed_schemes(std::vector<std::string> &&allowed_schemes)
    {
        allowed_schemes_strings_ = std::move(allowed_schemes);
        allowed_schemes_ = {allowed_schemes_strings_.begin(), allowed_schemes_strings_.end()};
    }

    void set_forbidden_domains(std::vector<std::string> &&forbidden_domains)
    {
        forbidden_domains_ = std::move(forbidden_domains);
    }

    void set_forbidden_ips(const std::vector<std::string_view> &forbidden_ips)
    {
        forbidden_ip_matcher_ = std::make_unique<matcher::ip_match>(forbidden_ips);
    }

protected:
    [[nodiscard]] eval_result eval_impl(const unary_argument<std::string_view> &uri,
        const variadic_argument<object_view> &params, condition_cache &cache,
        const object_set_ref &objects_excluded, ddwaf::timer &deadline) const;

    ssrf_opts opts_;
    std::unique_ptr<matcher::ip_match> forbidden_ip_matcher_;
    std::vector<std::string> allowed_schemes_strings_;
    std::unordered_set<std::string_view> allowed_schemes_;
    std::vector<std::string> forbidden_domains_;

    friend class base_impl<ssrf_detector>;
};

} // namespace ddwaf
