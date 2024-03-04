// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/ssrf_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "uri_utils.hpp"
#include "utils.hpp"
#include <iostream>

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr std::array<std::string_view, 10> dangerous_ips{"169.254.0.0/16", "127.0.0.1/32",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7",
    "fe80::/10", "2001:db8:1234:1a00::/56"};

constexpr const std::array<std::string_view, 10> dangerous_domains{
    "metadata.google", "burpcollaborator.net", ".local", ".internal", "ram.aliyuncs.com",
    "ifconfig.pro", "localhost", "fuf.me", "localtest.me", "ulh.us" // Legacy domains
};

constexpr const std::array<std::string_view, 4> authorised_schemes{"https", "http", "ftps", "ftp"};

constexpr const auto &npos = std::string_view::npos;

using ssrf_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

bool detect_parameter_injection(
    const uri_decomposed &uri, std::string_view param, std::size_t param_index)
{
    const auto path_end = uri.path_index + uri.path.size();

    // REST parameter injection will involve introducing a / to the URL, however, such
    // slashes are allowed after the ? or the #. Check if the slash is within the parameters.
    if (auto slash_index = param.find('/'); slash_index != npos) {
        slash_index += param_index;
        if (slash_index < path_end) {
            // The path is partially under control of the user, this might be intentional
            // so lets check for a possible LFI
            auto relative_dir_index = param.find("..");
            while (relative_dir_index != npos) {
                auto dir_index = relative_dir_index + param_index;
                if (dir_index < path_end && (dir_index + 2) < uri.raw.size() &&
                    uri.raw[dir_index - 1] == '/' && uri.raw[dir_index + 2] == '/') {
                    return true;
                }
                relative_dir_index = param.find("..", relative_dir_index + 2);
            }
        }
    }

    // The application giving total control to the user after a given point.
    // At this point, if it starts in the path, assume it's intentional
    if ((uri.query.empty() && uri.fragment.empty()) ||
        (param_index < path_end && (param_index + param.size()) == uri.raw.size())) {
        return false;
    }

    const auto query_index = param.find('?');
    if (uri.query_index != npos && query_index != npos &&
        (param_index + query_index + 1) == uri.query_index) {
        // We had some cases where this was expected behavior
        // We identify them by checking whether the next character is a '&'
        auto after_param = uri.raw.substr(param_index + param.length());
        if (!after_param.empty() && after_param[0] == '&') {
            return false;
        }

        // We can also find them if it is followed by a parameter (abc=42)
        for (std::size_t i = 0; i < after_param.size(); ++i) {
            const auto c = after_param[i];
            if (c == '=' && i > 0) {
                return false;
            }

            if (!ddwaf::isalnum(c) && c != '_') {
                break;
            }
        }

        return true;
    }

    // Check if the parameter interfered with what comes after the ?

    // The parameter stop before the ? or start after #, so it can't be interfering with what come
    // after. We can stop processing this heuristic
    const auto param_end = param_index + param.size() - 1;
    if (uri.query_index > param_end ||
        (uri.fragment_index != npos && uri.fragment_index < param_index)) {
        return false;
    }

    // We compute the substring of the parameter that come after the ?
    auto query_param =
        uri.query_index <= param_index ? param : param.substr(uri.query_index - param_index);
    return query_param.find('&') != npos;
}

ssrf_result ssrf_impl(const uri_decomposed &uri, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    const std::unique_ptr<matcher::ip_match> &dangerous_ip_matcher,
    const std::unordered_set<std::string_view> &authorised_scheme_set, ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 4;

    std::string_view dangerous_domain = {};
    for (const auto domain : dangerous_domains) {
        if (uri.authority.host.ends_with(domain)) {
            dangerous_domain = domain;
        }
    }

    std::optional<ssrf_result> parameter_injection;

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &object = *(*it);
        if (object.type != DDWAF_OBJ_STRING || object.nbEntries < min_str_len) {
            continue;
        }

        std::string_view param{object.stringValue, static_cast<std::size_t>(object.nbEntries)};
        auto param_index = uri.raw.find(param);
        if (param_index == npos) {
            // Seemingly no injection
            continue;
        }

        // Verify if the injected param intereferes with the authority
        // Note that if there is no authority, this condition will never be true
        // as uri.authority.param_index will be npos (size_t::max)
        if (param_index >= uri.authority.index && param_index < uri.scheme_and_authority.size()) {
            // Verify if the host was fully modified by the injected param
            if ((param_index + param.size() - 1) > uri.scheme_and_authority.size()) {
                return {{std::string(param), it.get_current_path()}};
            }

            // If the IP is injected, we want to make sure it's fully under the attacker's control
            // Otherwise, that's likely a false positive (bla=169.2&... in the URL match the IP
            // 169.254.169.254)
            bool host_fully_injected =
                param_index <= uri.authority.host_index &&
                param_index + param.size() >= uri.authority.host_index + uri.authority.host.size();

            if (uri.authority.host_ip.has_value()) {
                auto res = dangerous_ip_matcher->match_ip(uri.authority.host_ip.value());
                if (res && host_fully_injected) {
                    return {{std::string(param), it.get_current_path()}};
                }
            }

            if (!dangerous_domain.empty() && param == dangerous_domain) {
                return {{std::string(param), it.get_current_path()}};
            }
        }

        if (param_index == 0 && !authorised_scheme_set.contains(uri.scheme)) {
            return {{std::string(param), it.get_current_path()}};
        }

        if (!parameter_injection.has_value() &&
            detect_parameter_injection(uri, param, param_index)) {
            parameter_injection = {{std::string(param), it.get_current_path()}};
        }
    }

    if (parameter_injection.has_value()) {
        return parameter_injection.value();
    }

    return {};
}

} // namespace

ssrf_detector::ssrf_detector(std::vector<parameter_definition> args, const object_limits &limits)
    : base_impl<ssrf_detector>(std::move(args), limits),
      dangerous_ip_matcher_(std::make_unique<matcher::ip_match>(dangerous_ips)),
      authorised_schemes_(authorised_schemes.begin(), authorised_schemes.end())
{}

eval_result ssrf_detector::eval_impl(const unary_argument<std::string_view> &uri,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    auto decomposed = uri_parse(uri.value);
    if (!decomposed.has_value()) {
        return {};
    }

    for (const auto &param : params) {
        auto res = ssrf_impl(*decomposed, *param.value, objects_excluded, limits_,
            dangerous_ip_matcher_, authorised_schemes_, deadline);
        if (res.has_value()) {
            std::vector<std::string> uri_kp{uri.key_path.begin(), uri.key_path.end()};
            bool ephemeral = uri.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();
            cache.match =
                condition_match{{{"resource"sv, std::string{uri.value}, uri.address, uri_kp},
                                    {"params"sv, highlight, param.address, param_kp}},
                    {std::move(highlight)}, "ssrf_detector", {}, ephemeral};

            return {true, uri.ephemeral || param.ephemeral};
        }
    }

    return {};
}

} // namespace ddwaf
