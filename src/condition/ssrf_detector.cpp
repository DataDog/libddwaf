// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/ssrf_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "platform.hpp"
#include "uri_utils.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr std::array<std::string_view, 10> dangerous_ips{"169.254.0.0/16", "127.0.0.1/32",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7",
    "fe80::/10", "2001:db8:1234:1a00::/56"};

using ssrf_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

ssrf_result ssrf_impl(const uri_scheme_and_authority &uri, const ddwaf_object &params,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    const std::unique_ptr<matcher::ip_match> &dangerous_ip_matcher, ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 4;

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING && param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        auto index = uri.original.find(value);
        if (index == std::string_view::npos) {
            // Seemingly no injection
            continue;
        }

        // Verify if the injected value intereferes with the authority
        if (index < uri.raw.size() && (index + value.size()) > (uri.scheme.size() + 3)) {
            if (uri.authority.malformed) {
                // There is a known injection and the authority is malformed, so
                // we return an event here. There is a small chance this isn't the
                // relevant injection.
                return {{std::string(value), it.get_current_path()}};
            }

            // Verify if the host was modified by the injected value
            if ((index + value.size()) > uri.raw.size()) {
                // TODO Add extra FP checks
                if ((index + value.size() - 1) > uri.raw.size()) {
                    return {{std::string(value), it.get_current_path()}};
                }
            }

            // If the IP is injected, we want to make sure it's fully under the attacker's control
            //	Otherwise, that's likely a false positive (bla=169.2&... in the URL match the IP
            // 169.254.169.254)
            bool host_fully_injected =
                index <= uri.authority.host_index &&
                index + value.size() >= uri.authority.host_index + uri.authority.host.size();

            auto [res, match] = dangerous_ip_matcher->match(uri.authority.host);

            if (res && host_fully_injected) {
                return {{std::string(value), it.get_current_path()}};
            }
        }
    }

    return {};
}

} // namespace

ssrf_detector::ssrf_detector(std::vector<parameter_definition> args, const object_limits &limits)
    : base_impl<ssrf_detector>(std::move(args), limits),
      dangerous_ip_matcher_(std::make_unique<matcher::ip_match>(dangerous_ips))
{}

eval_result ssrf_detector::eval_impl(const unary_argument<std::string_view> &uri,
    const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    auto decomposed = uri_parse_scheme_and_authority(uri.value);
    if (!decomposed.has_value()) {
        return {};
    }

    for (const auto &param : params) {
        auto res = ssrf_impl(
            *decomposed, *param.value, objects_excluded, limits_, dangerous_ip_matcher_, deadline);
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
