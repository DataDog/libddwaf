// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/match_iterator.hpp"
#include "condition/ssrf_detector.hpp"
#include "condition/structured_condition.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "ip_utils.hpp"
#include "log.hpp"
#include "matcher/ip_match.hpp"
#include "uri_utils.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr const auto &npos = std::string_view::npos;

using ssrf_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

bool detect_parameter_injection(const ssrf_opts &opts, const uri_decomposed &uri,
    std::string_view param, std::size_t param_index)
{
    const auto param_end = param_index + param.size();

    // Check if the application is giving full control of the path to the user
    // either fully or after a forward-slash.
    if (opts.path_inspection && !uri.path.empty()) {
        const auto path_end = uri.path_index + uri.path.size();

        //  scheme://userinfo@host:port/path?query#fragment
        //                             ─────
        if (uri.path.size() == param.size()) {
            return false;
        }
        //  scheme://userinfo@host:port/path?query#fragment
        //                              ────
        if (uri.path[0] == '/' && param_index == uri.path_index + 1 &&
            param.size() == uri.path.size() - 1) {
            return false;
        }

        // If part of the path has been injected and said injection contains a
        // %2f, flag it as suspicious
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //                            <─────>
        if (param_index < path_end && param_end > uri.path_index &&
            (param.find("%2f") != npos || param.find("%2F") != npos || param.find("%5c") != npos ||
                param.find("%5C") != npos)) {
            return true;
        }

        // REST parameter injection will involve introducing a / to the URL, however, such
        // slashes are allowed after the ? or the #. Check if the slash is within the path
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //                             ─────
        if (auto slash_index = param.find('/'); slash_index != npos) {
            slash_index += param_index;
            if (slash_index < path_end) {
                // The path is partially under control of the user, this might be intentional
                // so lets check for a possible LFI
                auto relative_dir_index = param.find("..");
                while (relative_dir_index != npos) {

                    // We found '..', check if it's enclosed by '/'
                    auto dir_index = relative_dir_index + param_index;
                    if (dir_index < path_end && (dir_index + 2) < uri.raw.size() &&
                        uri.raw[dir_index - 1] == '/' && uri.raw[dir_index + 2] == '/') {
                        return true;
                    }
                    relative_dir_index = param.find("..", relative_dir_index + 2);
                }
            }
        }

        // If everything after a certain point before the end of the path has been
        // injected, assume it's intentional
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //                             <───────────────────
        if (param_index < path_end && param_end == uri.raw.size()) {
            return false;
        }
    }

    if (opts.query_inspection && !uri.query.empty()) {
        // Check if the query string was injected
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //                                 <─────
        const auto param_query_index = param.find('?');
        if (uri.query_index != npos && param_query_index != npos &&
            (param_index + param_query_index + 1) == uri.query_index) {
            // We had some cases where this was expected behavior, to make sure
            // we check whether the next character is a '&'
            auto after_param = uri.raw.substr(param_index + param.length());
            return after_param.empty() || after_param[0] != '&';
        }

        // Check if the parameter interfered with what comes after the ?
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //                                   ─────
        //
        // The parameter ends before the ? or starts after #, so it can't be
        // interfering with the query parameters, we can stop here.
        const auto query_end = uri.query_index + uri.query.size();
        if ((param_end <= uri.query_index - 1) || param_index >= query_end) {
            return false;
        }

        // Check if more than one parameter was injected
        return param.find('&') != npos;
    }

    // We only need to check for parameter injections in either the path
    // or the query string, so if these are empty we can skip the checks
    return false;
}

bool is_forbidden_uri(const uri_decomposed &uri, const matcher::ip_match &forbidden_ip_matcher,
    const std::unordered_set<std::string_view> &allowed_scheme_set,
    const std::vector<std::string> &forbidden_domains)
{
    const auto is_forbidden_domain = [&](std::string_view host) {
        for (const auto &domain : forbidden_domains) {
            if (host.ends_with(domain)) {
                return true;
            }
        }
        return false;
    };

    const auto is_forbidden_ip = [&](const std::optional<ipaddr> &ip) {
        return ip.has_value() && forbidden_ip_matcher.match_ip(ip.value());
    };

    return !allowed_scheme_set.contains(uri.scheme) || is_forbidden_domain(uri.authority.host) ||
           is_forbidden_ip(uri.authority.host_ip);
}

ssrf_result ssrf_impl(const uri_decomposed &uri, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    const ssrf_opts &opts, const matcher::ip_match &forbidden_ip_matcher,
    const std::unordered_set<std::string_view> &allowed_scheme_set,
    const std::vector<std::string> &forbidden_domains, ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 4;

    std::string_view forbidden_domain = {};
    if (!opts.enforce_policy_without_injection) {
        for (const auto &domain : forbidden_domains) {
            if (uri.authority.host.ends_with(domain)) {
                forbidden_domain = domain;
                break;
            }
        }
    }

    std::optional<ssrf_result> parameter_injection;

    match_iterator<min_str_len> it{uri.raw, &params, objects_excluded, limits};
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto [param, param_index] = *it;

        if (uri.raw == param) {
            if (opts.forbid_full_url_injection) {
                return {{std::string(param), it.get_current_path()}};
            }
            return {};
        }

        // Verify if the injected param intereferes with the authority:
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //           ──────────────────
        //
        // Note that if there is no authority, this condition will never be true
        // as uri.authority.param_index will be npos (size_t::max)
        if (opts.authority_inspection && param_index >= uri.authority.index &&
            param_index < uri.scheme_and_authority.size()) {
            // Verify if the host was fully modified by the injected param
            //
            //  scheme://userinfo@host:port/path?query#fragment
            //           ───────────────────>
            //
            // Note that we require the injection to extend beyond the authority
            // to avoid false positives caused by the introduction of a single '/'
            if ((param_index + param.size() - 1) > uri.scheme_and_authority.size()) {
                return {{std::string(param), it.get_current_path()}};
            }

            // If the entire host has been injected, and it's an IP, check if its
            // present in the list of known dangeorus IPs
            //
            //  scheme://userinfo@host:port/path?query#fragment
            //                   <────>
            const bool host_fully_injected =
                param_index <= uri.authority.host_index &&
                param_index + param.size() >= uri.authority.host_index + uri.authority.host.size();

            if (host_fully_injected && uri.authority.host_ip.has_value() &&
                forbidden_ip_matcher.match_ip(uri.authority.host_ip.value())) {
                return {{std::string(param), it.get_current_path()}};
            }

            // Otherwise, check if the domain is also a known forbidden one injected
            // by the parameter itself
            if (!forbidden_domain.empty() && param.find(forbidden_domain) != npos) {
                return {{std::string(param), it.get_current_path()}};
            }
        }

        // If the injection includes the scheme and beyond, check if the
        // potentially injected scheme is still a valid one
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //  ───────>
        if (!uri.scheme.empty() && param_index == 0 && param.size() > uri.scheme.size() &&
            !allowed_scheme_set.contains(uri.scheme)) {
            return {{std::string(param), it.get_current_path()}};
        }

        // Finally, since we haven't found an injection on the scheme + authority
        // section of the URL, we verify if the parameter has been injected in the
        // path or query.
        //
        //  scheme://userinfo@host:port/path?query#fragment
        //                             ───────────
        //
        // However we don't report an event yet as there could be a legitimate injection.
        if (!parameter_injection.has_value() &&
            detect_parameter_injection(opts, uri, param, param_index)) {
            parameter_injection = {{std::string(param), it.get_current_path()}};
        }
    }

    // At this stage, no injection has been found on scheme + authority, so we
    // report the parameter injection if one has been detected
    if (parameter_injection.has_value()) {
        return parameter_injection.value();
    }

    return {};
}

} // namespace

ssrf_detector::ssrf_detector(std::vector<condition_parameter> args)
    : base_impl<ssrf_detector>(std::move(args)),
      forbidden_ip_matcher_(std::make_unique<matcher::ip_match>(default_forbidden_ips)),
      allowed_schemes_(default_allowed_schemes.begin(), default_allowed_schemes.end()),
      forbidden_domains_(default_forbidden_domains.begin(), default_forbidden_domains.end())
{}

ssrf_detector::ssrf_detector(std::vector<condition_parameter> args, const ssrf_opts &opts,
    std::vector<std::string> &&allowed_schemes, std::vector<std::string> &&forbidden_domains,
    const std::vector<std::string_view> &forbidden_ips)
    : base_impl<ssrf_detector>(std::move(args)), opts_(opts),
      forbidden_ip_matcher_(std::make_unique<matcher::ip_match>(forbidden_ips)),
      allowed_schemes_strings_(std::move(allowed_schemes)),
      allowed_schemes_(allowed_schemes_strings_.begin(), allowed_schemes_strings_.end()),
      forbidden_domains_(std::move(forbidden_domains))
{}

eval_result ssrf_detector::eval_impl(const unary_argument<std::string_view> &uri,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline) const
{
    auto decomposed = uri_parse(uri.value);
    if (!decomposed.has_value()) {
        return {};
    }

    if (opts_.enforce_policy_without_injection &&
        is_forbidden_uri(
            *decomposed, *forbidden_ip_matcher_, allowed_schemes_, forbidden_domains_)) {
        const std::vector<std::string> uri_kp{uri.key_path.begin(), uri.key_path.end()};

        DDWAF_TRACE("Resource {} matched policy", uri.value);

        cache.match = condition_match{
            .args = {{.name = "resource"sv,
                         .resolved = std::string{uri.value},
                         .address = uri.address,
                         .key_path = uri_kp},
                {.name = "params"sv, .resolved = {}, .address = {}, .key_path = {}}},
            .highlights = {decomposed->scheme_and_authority},
            .operator_name = "ssrf_detector",
            .operator_value = {},
            .ephemeral = uri.ephemeral};

        return {.outcome = true, .ephemeral = uri.ephemeral};
    }

    for (const auto &param : params) {
        auto res = ssrf_impl(*decomposed, *param.value, objects_excluded, limits, opts_,
            *forbidden_ip_matcher_, allowed_schemes_, forbidden_domains_, deadline);
        if (res.has_value()) {
            const std::vector<std::string> uri_kp{uri.key_path.begin(), uri.key_path.end()};
            const bool ephemeral = uri.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{.args = {{.name = "resource"sv,
                                                       .resolved = std::string{uri.value},
                                                       .address = uri.address,
                                                       .key_path = uri_kp},
                                              {.name = "params"sv,
                                                  .resolved = highlight,
                                                  .address = param.address,
                                                  .key_path = param_kp}},
                .highlights = {std::move(highlight)},
                .operator_name = "ssrf_detector",
                .operator_value = {},
                .ephemeral = ephemeral};

            return {.outcome = true, .ephemeral = ephemeral};
        }
    }

    return {};
}

} // namespace ddwaf
