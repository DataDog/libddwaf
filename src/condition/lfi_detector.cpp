// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "condition/lfi_detector.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "object.hpp"
#include "platform.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr const auto &npos = std::string_view::npos;

using lfi_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

bool find_directory_escape(std::string_view value, std::string_view sep)
{
    std::size_t start = 0;
    unsigned part_count = 0;
    bool part_seen = false;
    while (start < value.size()) {
        const std::size_t end = value.find_first_of(sep, start);

        if (end == start) {
            // Ignore zero-sized strings
            start = end + 1;
            continue;
        }

        ++part_count;

        std::string_view part;
        if (end != npos) {
            part = value.substr(start, end - start);
            start = end + 1;
        } else {
            part = value.substr(start);
            start = value.size();
        }

        part_seen = part_seen || part == "..";
        if (part_count > 1 && part_seen) {
            return true;
        }
    }

    return false;
}

// TODO: https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#dos-device-paths
bool lfi_impl_windows(std::string_view path, std::string_view param)
{
    static constexpr std::size_t min_str_len = 2;

    if (param.size() < min_str_len || !path.ends_with(param)) {
        return false;
    }

    const bool is_absolute = param[0] == '/' || param[0] == '\\' ||
                             (param.size() >= 3 && (ddwaf::isalpha(param[0]) && param[1] == ':' &&
                                                       (param[2] == '/' || param[2] == '\\')));
    return (is_absolute && param == path) || find_directory_escape(param, "/\\");
}

bool lfi_impl_unix(std::string_view path, std::string_view param)
{
    static constexpr std::size_t min_str_len = 5;

    if (param.size() < min_str_len || param.find('/') == npos || !path.ends_with(param)) {
        return false;
    }

    return (param[0] == '/' && param == path) || find_directory_escape(param, "/");
}

lfi_result lfi_impl(std::string_view path, object_view params,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline)
{
    auto *lfi_fn = &lfi_impl_unix;
    if (system_platform::current() == platform::windows) {
        lfi_fn = &lfi_impl_windows;
    }

    kv_iterator it(params, {}, objects_excluded);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto param = *it;
        if (!param.is_string()) {
            continue;
        }

        const auto value = param.as<std::string_view>();
        if (lfi_fn(path, value)) {
            return {{std::string(value), it.get_current_path()}};
        }
    }

    return {};
}
} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
eval_result lfi_detector::eval_impl(const unary_argument<std::string_view> &path,
    const variadic_argument<object_view> &params, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    for (const auto &param : params) {
        auto res = lfi_impl(path.value, param.value, objects_excluded, deadline);
        if (res.has_value()) {
            const std::vector<std::string> path_kp{path.key_path.begin(), path.key_path.end()};

            const evaluation_scope scope = resolve_scope(path, param);

            auto &[highlight, param_kp] = res.value();

            DDWAF_TRACE("Target {} matched parameter value {}", param.address, highlight);

            cache.match = condition_match{.args = {{.name = "resource"sv,
                                                       .resolved = path.value,
                                                       .address = path.address,
                                                       .key_path = path_kp},
                                              {.name = "params"sv,
                                                  .resolved = highlight,
                                                  .address = param.address,
                                                  .key_path = param_kp}},
                .highlights = {highlight},
                .operator_name = "lfi_detector",
                .operator_value = {},
                .scope = scope};

            return eval_result::match(scope);
        }
    }

    return {};
}

} // namespace ddwaf
